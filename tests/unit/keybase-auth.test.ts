/**
 * Unit tests for the Keybase PDPKA authentication flow.
 *
 * Two test groups:
 *
 *  1. **Mocked flow** (always runs in CI): verifies the salt → deriveKeys →
 *     pdpka → login → me.json pipeline against a stubbed fetch. Asserts that
 *     the right calls are made in the right order and that the wire format
 *     matches what Keybase expects.
 *
 *  2. **Live integration flow** (only runs when `INTEGRATION=true` AND
 *     `KEYBASE_TEST_USERNAME` / `KEYBASE_TEST_PASS` are set): performs a
 *     real end-to-end login against keybase.io and asserts that the returned
 *     private key is parseable. Skipped by default to avoid rate limits.
 *
 * In GitHub Actions, the integration tests run in a separate job that has
 * access to the `KEYBASE_TEST_USERNAME` and `KEYBASE_TEST_PASS` secrets —
 * see `.github/workflows/unit-tests.yml`.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  deriveKeysFromPassword,
  generatePdpkaSignatures,
  getSalt,
  loginAndFetchMe,
  loginWithPassword,
  type SaltResponse,
} from "@/lib/pgp/keybase-auth";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a fake Keybase salt response. */
function fakeSalt(overrides: Partial<SaltResponse> = {}): SaltResponse {
  return {
    salt: "0123456789abcdef0123456789abcdef",
    csrf_token: "fake-csrf-token",
    login_session: "fake-login-session",
    pwh_version: 3,
    uid: "fake-uid",
    ...overrides,
  };
}

/** Replace global fetch with a stub that returns the given responses in order. */
function stubFetch(
  ...responses: Array<
    | Response
    | { json: () => Promise<unknown>; ok: boolean; status: number; headers: Map<string, string> }
  >
) {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const queue = [...responses];
  const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: typeof url === "string" ? url : url.toString(), init });
    const next = queue.shift();
    if (!next) throw new Error("fetch called more times than expected");
    if (next instanceof Response) return next;
    return {
      ok: next.ok,
      status: next.status,
      json: next.json,
      headers: {
        get: (name: string) => next.headers.get(name) ?? null,
      },
    } as unknown as Response;
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock };
}

// ---------------------------------------------------------------------------
// Mocked flow tests — always run
// ---------------------------------------------------------------------------

describe("keybase-auth (mocked)", () => {
  beforeEach(() => {
    vi.stubGlobal("crypto", globalThis.crypto);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  describe("getSalt", () => {
    it("POSTs to the proxy and returns the parsed salt response", async () => {
      const { calls } = stubFetch({
        ok: true,
        status: 200,
        json: async () => fakeSalt(),
        headers: new Map(),
      });

      const result = await getSalt("alice", "/api/keybase/getsalt");

      expect(result.salt).toBe("0123456789abcdef0123456789abcdef");
      expect(result.csrf_token).toBe("fake-csrf-token");
      expect(result.pwh_version).toBe(3);
      expect(calls).toHaveLength(1);
      expect(calls[0].init?.method).toBe("POST");
      const body = JSON.parse(calls[0].init?.body as string);
      expect(body.username).toBe("alice");
    });

    it("lowercases and trims the username before sending", async () => {
      const { calls } = stubFetch({
        ok: true,
        status: 200,
        json: async () => fakeSalt(),
        headers: new Map(),
      });

      await getSalt("  AlIcE  ", "/api/keybase/getsalt");
      const body = JSON.parse(calls[0].init?.body as string);
      expect(body.username).toBe("alice");
    });

    it("throws when the proxy returns an error", async () => {
      stubFetch({
        ok: false,
        status: 400,
        json: async () => ({ error: "Invalid username" }),
        headers: new Map(),
      });
      await expect(getSalt("alice", "/api/keybase/getsalt")).rejects.toThrow("Invalid username");
    });
  });

  describe("deriveKeysFromPassword", () => {
    it("produces 32-byte pwh and eddsaSeed from a password + salt", async () => {
      const keys = await deriveKeysFromPassword(
        "correct horse battery staple",
        "0123456789abcdef0123456789abcdef",
      );
      expect(keys.pwh).toBeInstanceOf(Uint8Array);
      expect(keys.pwh.length).toBe(32);
      expect(keys.eddsaSeed).toBeInstanceOf(Uint8Array);
      expect(keys.eddsaSeed.length).toBe(32);
      expect(keys.pwhHex).toMatch(/^[0-9a-f]{64}$/);
    });

    it("is deterministic — same password + salt always produces the same pwh", async () => {
      const a = await deriveKeysFromPassword("password", "abcd1234abcd1234abcd1234abcd1234");
      const b = await deriveKeysFromPassword("password", "abcd1234abcd1234abcd1234abcd1234");
      expect(a.pwhHex).toBe(b.pwhHex);
    });

    it("changes when the password changes", async () => {
      const a = await deriveKeysFromPassword("password1", "abcd1234abcd1234abcd1234abcd1234");
      const b = await deriveKeysFromPassword("password2", "abcd1234abcd1234abcd1234abcd1234");
      expect(a.pwhHex).not.toBe(b.pwhHex);
    });

    it("changes when the salt changes", async () => {
      const a = await deriveKeysFromPassword("password", "abcd1234abcd1234abcd1234abcd1234");
      const b = await deriveKeysFromPassword("password", "1234abcd1234abcd1234abcd1234abcd");
      expect(a.pwhHex).not.toBe(b.pwhHex);
    });
  });

  describe("generatePdpkaSignatures", () => {
    it("produces two distinct armored PGP signatures (pdpka4 + pdpka5)", async () => {
      const keys = await deriveKeysFromPassword("password", "abcd1234abcd1234abcd1234abcd1234");
      const sigs = await generatePdpkaSignatures(
        keys.pwh,
        keys.eddsaSeed,
        "alice",
        "fake-uid",
        "fake-login-session",
      );
      expect(sigs.pdpka4).toBeTruthy();
      expect(sigs.pdpka5).toBeTruthy();
      expect(sigs.pdpka4).not.toBe(sigs.pdpka5);
      // keybase-proofs returns base64-encoded binary signatures (the field
      // is named `armored` but it's actually base64). Verify they decode
      // cleanly to a non-empty byte buffer.
      for (const sig of [sigs.pdpka4, sigs.pdpka5]) {
        expect(sig.length).toBeGreaterThan(50);
        const decoded = Buffer.from(sig, "base64");
        expect(decoded.length).toBeGreaterThan(50);
      }
    });
  });

  describe("loginAndFetchMe", () => {
    it("POSTs pdpka4 + pdpka5 to the login proxy and returns the me response", async () => {
      const { calls } = stubFetch({
        ok: true,
        status: 200,
        json: async () => ({
          username: "alice",
          uid: "fake-uid",
          picture_url: null,
          full_name: null,
          private_key_bundle: null,
          primary_key_fingerprint: "ABCDEF0123456789",
        }),
        headers: new Map(),
      });

      const result = await loginAndFetchMe(
        "alice",
        "pdpka4-armored",
        "pdpka5-armored",
        "csrf-token",
        "login-session",
        "/api/keybase/login",
      );

      expect(result.username).toBe("alice");
      expect(result.private_key_bundle).toBeNull();
      expect(result.primary_key_fingerprint).toBe("ABCDEF0123456789");
      expect(calls).toHaveLength(1);
      expect(calls[0].init?.method).toBe("POST");
      const body = JSON.parse(calls[0].init?.body as string);
      expect(body).toMatchObject({
        username: "alice",
        pdpka4: "pdpka4-armored",
        pdpka5: "pdpka5-armored",
        csrf_token: "csrf-token",
        login_session: "login-session",
      });
    });

    it("throws when the proxy returns an error", async () => {
      stubFetch({
        ok: false,
        status: 401,
        json: async () => ({ error: "BAD_LOGIN_PASSWORD" }),
        headers: new Map(),
      });
      await expect(
        loginAndFetchMe("alice", "pdpka4", "pdpka5", "csrf", "session", "/api/keybase/login"),
      ).rejects.toThrow("BAD_LOGIN_PASSWORD");
    });
  });

  describe("loginWithPassword (end-to-end with mocked fetch)", () => {
    it("runs the full salt → derive → sign → login → me pipeline and returns the username", async () => {
      // Mock fetch for both the getsalt proxy call AND the login proxy call.
      const { calls } = stubFetch(
        // getsalt response
        {
          ok: true,
          status: 200,
          json: async () => fakeSalt(),
          headers: new Map(),
        },
        // login response — note private_key_bundle is null so the function
        // will throw "no private key bundle". That's fine for this test —
        // we just want to verify the pipeline got that far.
        {
          ok: true,
          status: 200,
          json: async () => ({
            username: "alice",
            uid: "fake-uid",
            private_key_bundle: null,
            primary_key_fingerprint: "ABC",
          }),
          headers: new Map(),
        },
      );

      // The function should throw because private_key_bundle is null,
      // but that proves the pipeline got all the way to step 5.
      await expect(
        loginWithPassword("alice", "password", {
          getsaltUrl: "/api/keybase/getsalt",
          loginUrl: "/api/keybase/login",
        }),
      ).rejects.toThrow(/no private key bundle/i);

      // Verify both proxy endpoints were hit
      expect(calls).toHaveLength(2);
      expect(calls[0].url).toBe("/api/keybase/getsalt");
      expect(calls[1].url).toBe("/api/keybase/login");
    });
  });
});

// ---------------------------------------------------------------------------
// Live integration tests — only run when INTEGRATION=true AND credentials
// are available. Skipped by default to avoid hitting Keybase from CI on
// every commit.
// ---------------------------------------------------------------------------

const INTEGRATION = process.env.INTEGRATION === "true";
const hasCreds = !!(process.env.KEYBASE_TEST_USERNAME && process.env.KEYBASE_TEST_PASS);

const describeIntegration = INTEGRATION && hasCreds ? describe : describe.skip;

describeIntegration("keybase-auth (live integration)", () => {
  it(
    "logs in to the real Keybase API and returns a parseable private key",
    { timeout: 60_000 },
    async () => {
      const username = process.env.KEYBASE_TEST_USERNAME!;
      const password = process.env.KEYBASE_TEST_PASS!;

      const { me, privateKey } = await loginWithPassword(username, password, {
        getsaltUrl: "https://keybase.io/_/api/1.0/getsalt.json",
        loginUrl: "https://keybase.io/_/api/1.0/login.json",
      });

      // Sanity-check the response.
      expect(me.username.toLowerCase()).toBe(username.toLowerCase());
      expect(me.private_key_bundle).toBeTruthy();
      expect(privateKey.isPrivate()).toBe(true);

      // The key should be decryptable — try to armor it back out.
      const armored = privateKey.armor();
      expect(armored).toContain("BEGIN PGP PRIVATE KEY BLOCK");
    },
  );
});
