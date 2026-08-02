import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Route } from "./+types/home";
import type * as OpenPGP from "openpgp";
import {
  fetchKeyByKeyIDClient,
  fetchKeyFromOpenPGP_orgClient,
  lookupKeybaseUsersClient,
  searchAllKeyserversClient,
  type KeybaseKeyByIDResult,
  type KeySearchResult,
} from "~/lib/keybase";
// keybase-auth is dynamically imported inside KeybaseLoginForm to keep
// kbpgp/keybase-proofs out of the initial client bundle.
import {
  decryptAndAutoVerify,
  detectArmoredFormat,
  encryptAndSign,
  formatFingerprint,
  generateKeyPair,
  readKey,
  signMessage,
  unlockPrivateKey,
  validateArmoredKey,
  verifyAutoDetectWithKeyFetch,
  type AnyKeyInfo,
  type GeneratedKeyPair,
} from "~/lib/pgp";

export function meta(_: Route.MetaArgs) {
  return [
    { title: "Encryptor · PGP for Keybase" },
    {
      name: "description",
      content:
        "Encrypt + sign PGP messages to multiple recipients, decrypt while verifying the signer, and sign plain text. Pulls PGP keys from Keybase.",
    },
  ];
}

export async function loader(_: Route.LoaderArgs) {
  return Response.json({
    keybaseProxy: "/api/keybase",
    autocompleteProxy: "/api/keybase/autocomplete",
    searchAllProxy: "/api/keybase/search-all",
    fetchkeyProxy: "/api/keybase/fetchkey",
    fetchkeyOpgProxy: "/api/keybase/fetchkey-opg",
    getsaltProxy: "/api/keybase/getsalt",
    loginProxy: "/api/keybase/login",
  });
}

type Tab = "encrypt" | "decrypt" | "sign" | "verify";

/**
 * Fetch public keys for signature verification from BOTH Keybase and
 * keys.openpgp.org, merging the results.
 *
 * Keybase is tried first because it returns the owning username. If a key
 * isn't found on Keybase, we fall back to keys.openpgp.org (which doesn't
 * have usernames but still allows signature verification).
 *
 * Results are deduplicated by fingerprint.
 */
async function fetchKeysFromAllSources(
  keyIDs: string[],
  keybaseProxy: string,
  opgProxy: string,
): Promise<KeybaseKeyByIDResult[]> {
  // Try Keybase first.
  const keybaseResults = await fetchKeyByKeyIDClient(keyIDs, keybaseProxy).catch(
    () => [],
  );

  // Find key IDs that Keybase didn't resolve.
  const foundKeyIDs = new Set(
    keybaseResults.flatMap((k) => k.allKeyIDs ?? [k.keyID]),
  );
  const missingKeyIDs = keyIDs.filter((id) => {
    const upper = id.toUpperCase();
    return !foundKeyIDs.has(upper) && !foundKeyIDs.has(upper.toLowerCase());
  });

  // Try keys.openpgp.org for the missing ones.
  const opgResults =
    missingKeyIDs.length > 0
      ? await fetchKeyFromOpenPGP_orgClient(missingKeyIDs, opgProxy).catch(
          () => [],
        )
      : [];

  // Merge and deduplicate by fingerprint.
  const seen = new Set<string>();
  const merged: KeybaseKeyByIDResult[] = [];
  for (const k of [...keybaseResults, ...opgResults]) {
    const fp = k.fingerprint.toUpperCase();
    if (!seen.has(fp)) {
      seen.add(fp);
      merged.push(k);
    }
  }
  return merged;
}

interface Recipient {
  source: "keybase" | "local";
  username?: string;
  label: string;
  armored: string;
  fingerprint: string;
  keyID: string;
  algorithm: string;
  expiresAt: number | null;
}

interface PrivateKeyConfig {
  source: "keybase" | "manual" | "generated";
  label: string;
  username?: string;
  /** For manual/generated sources: the ENCRYPTED armored private key.
   *  For keybase source: not used (the key is fetched on demand). */
  encryptedArmored?: string;
  /** Key metadata for display (fingerprint, key ID, algorithm). */
  info: AnyKeyInfo;
}

const LS_KEY = "encryptor.config.v1";
const LS_INCLUDE_SELF = "encryptor.include-self.v1";

/** Default value for the "include me as recipient" checkbox.
 *  Returns true unless the user has explicitly disabled it. */
function loadIncludeSelfDefault(): boolean {
  try {
    const v = localStorage.getItem(LS_INCLUDE_SELF);
    if (v === "false") return false;
    return true;
  } catch {
    return true;
  }
}

export default function Home({ loaderData }: Route.ComponentProps) {
  const proxies = loaderData as {
    keybaseProxy: string;
    autocompleteProxy: string;
    searchAllProxy: string;
    fetchkeyProxy: string;
    fetchkeyOpgProxy: string;
    getsaltProxy: string;
    loginProxy: string;
  };

  const [tab, setTab] = useState<Tab>("encrypt");
  const [recipients, setRecipients] = useState<Recipient[]>([]);
  const [privateKey, setPrivateKey] = useState<PrivateKeyConfig | null>(null);
  const [configOpen, setConfigOpen] = useState(false);
  const [includeSelf, setIncludeSelf] = useState<boolean>(loadIncludeSelfDefault);

  const handleSetIncludeSelf = useCallback((next: boolean) => {
    setIncludeSelf(next);
    try {
      localStorage.setItem(LS_INCLUDE_SELF, next ? "true" : "false");
    } catch {
      // ignore
    }
  }, []);

  // Hydrate persisted config. Only metadata + encrypted key are stored —
  // NEVER the decrypted private key or the passphrase.
  useEffect(() => {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as PrivateKeyConfig;
        if (parsed?.info && (parsed.source === "keybase" || parsed.encryptedArmored)) {
          setPrivateKey(parsed);
        }
      }
    } catch {
      // ignore
    }
  }, []);

  const handleSetPrivateKey = useCallback((next: PrivateKeyConfig | null) => {
    setPrivateKey(next);
    try {
      if (next) {
        localStorage.setItem(LS_KEY, JSON.stringify(next));
      } else {
        localStorage.removeItem(LS_KEY);
      }
    } catch {
      // ignore
    }
  }, []);

  // --- On-demand key decryption (Keybase-style) ---
  // When a tab needs the decrypted private key, it calls requestDecryptedKey().
  // This shows a passphrase prompt. The decrypted key exists only in the
  // promise resolver's scope and is cleared after the operation completes.
  const [keyRequest, setKeyRequest] = useState<{
    resolve: (key: OpenPGP.PrivateKey) => void;
    reject: (err: Error) => void;
  } | null>(null);

  const requestDecryptedKey = useCallback((): Promise<OpenPGP.PrivateKey> => {
    return new Promise((resolve, reject) => {
      setKeyRequest({ resolve, reject });
    });
  }, []);

  return (
    <div className="min-h-screen flex flex-col bg-white text-neutral-900">
      <Header
        onConfigure={() => setConfigOpen(true)}
        privateKey={privateKey}
      />

      <main className="flex-1 w-full max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-6 lg:py-8">
        <Tabs value={tab} onChange={setTab} />

        <div className="mt-6">
          {tab === "encrypt" && (
            <EncryptTab
              recipients={recipients}
              setRecipients={setRecipients}
              privateKey={privateKey}
              proxies={proxies}
              includeSelf={includeSelf}
              setIncludeSelf={handleSetIncludeSelf}
              requestDecryptedKey={requestDecryptedKey}
            />
          )}
          {tab === "decrypt" && (
            <DecryptTab
              privateKey={privateKey}
              proxies={proxies}
              requestDecryptedKey={requestDecryptedKey}
            />
          )}
          {tab === "sign" && (
            <SignTab
              privateKey={privateKey}
              requestDecryptedKey={requestDecryptedKey}
            />
          )}
          {tab === "verify" && <VerifyTab proxies={proxies} />}
        </div>
      </main>

      <Footer />

      {configOpen && (
        <ConfigureModal
          onClose={() => setConfigOpen(false)}
          privateKey={privateKey}
          onSave={(next) => {
            handleSetPrivateKey(next);
            setConfigOpen(false);
          }}
          onClear={() => {
            handleSetPrivateKey(null);
            setConfigOpen(false);
          }}
          proxies={proxies}
        />
      )}

      {keyRequest && privateKey && (
        <PassphrasePrompt
          config={privateKey}
          proxies={proxies}
          onResolve={(key) => {
            keyRequest.resolve(key);
            setKeyRequest(null);
          }}
          onCancel={(err) => {
            keyRequest.reject(err);
            setKeyRequest(null);
          }}
          onKeyUpdated={(updatedConfig) => {
            handleSetPrivateKey(updatedConfig);
          }}
        />
      )}
    </div>
  );
}

/* ---------------------------------- Header --------------------------------- */

function Header({
  onConfigure,
  privateKey,
}: {
  onConfigure: () => void;
  privateKey: PrivateKeyConfig | null;
}) {
  return (
    <header className="border-b border-neutral-200 bg-white sticky top-0 z-10">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="size-7 rounded-md bg-[#0055dc] text-white font-bold grid place-items-center text-xs">
            E
          </div>
          <span className="text-base font-semibold tracking-tight">Encryptor</span>
        </div>
        <button
          onClick={onConfigure}
          className="inline-flex items-center gap-2 rounded-md border border-neutral-300 bg-white px-3 py-1.5 text-sm font-medium text-neutral-700 hover:border-[#0055dc] hover:text-[#0055dc] transition-colors"
        >
          <KeyIcon />
          {privateKey ? (
            <span>
              {privateKey.source === "keybase"
                ? `@${privateKey.username}`
                : privateKey.label}
            </span>
          ) : (
            <span>Configure private key</span>
          )}
        </button>
      </div>
    </header>
  );
}

function KeyIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
    </svg>
  );
}

function Footer() {
  return (
    <footer className="mt-auto border-t border-neutral-200 bg-white">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-3 text-[11px] text-neutral-500">
        All crypto runs in your browser. Keys and plaintext never touch our
        servers — only Keybase username lookups are proxied.
      </div>
    </footer>
  );
}

/* ----------------------------------- Tabs ---------------------------------- */

function Tabs({ value, onChange }: { value: Tab; onChange: (t: Tab) => void }) {
  const tabs: { id: Tab; label: string }[] = [
    { id: "encrypt", label: "Encrypt" },
    { id: "decrypt", label: "Decrypt" },
    { id: "sign", label: "Sign" },
    { id: "verify", label: "Verify" },
  ];
  return (
    <nav
      className="flex border-b border-neutral-200"
      role="tablist"
      aria-label="Mode"
    >
      {tabs.map((t) => {
        const active = t.id === value;
        return (
          <button
            key={t.id}
            role="tab"
            aria-selected={active}
            onClick={() => onChange(t.id)}
            className={`px-5 py-2.5 -mb-px border-b-2 text-sm font-medium transition-colors ${
              active
                ? "border-[#0055dc] text-[#0055dc]"
                : "border-transparent text-neutral-500 hover:text-neutral-800 hover:border-neutral-300"
            }`}
          >
            {t.label}
          </button>
        );
      })}
    </nav>
  );
}

/* --------------------------------- Encrypt --------------------------------- */

interface EncryptTabProps {
  recipients: Recipient[];
  setRecipients: React.Dispatch<React.SetStateAction<Recipient[]>>;
  privateKey: PrivateKeyConfig | null;
  proxies: {
    keybaseProxy: string;
    autocompleteProxy: string;
    searchAllProxy: string;
    fetchkeyProxy: string;
    fetchkeyOpgProxy: string;
    getsaltProxy: string;
    loginProxy: string;
  };
  includeSelf: boolean;
  setIncludeSelf: (v: boolean) => void;
  requestDecryptedKey: () => Promise<OpenPGP.PrivateKey>;
}

function EncryptTab({
  recipients,
  setRecipients,
  privateKey,
  proxies,
  includeSelf,
  setIncludeSelf,
  requestDecryptedKey,
}: EncryptTabProps) {
  const [plaintext, setPlaintext] = useState("");
  const [output, setOutput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nukeConfirmed, setNukeConfirmed] = useState(false);

  // Derive the user's own public key from the configured private key.
  // Shown as a recipient chip when "Include me" is checked.
  const selfRecipient = useMemo<Recipient | null>(() => {
    if (!privateKey) return null;
    const info = privateKey.info;
    return {
      source: "local",
      label:
        privateKey.source === "keybase"
          ? `@${privateKey.username} (you)`
          : `${privateKey.label} (you)`,
      armored: "", // not needed — we'll inject it directly in handleEncrypt
      fingerprint: info.fingerprint,
      keyID: info.keyID,
      algorithm: info.algorithm,
      expiresAt: info.expirationTime?.getTime() ?? null,
    };
  }, [privateKey]);

  const handleEncrypt = useCallback(async () => {
    setError(null);
    setOutput("");
    setNukeConfirmed(false);
    if (!plaintext.trim()) {
      setError("Enter the message to encrypt.");
      return;
    }
    if (!privateKey) {
      setError("Configure your private key first (top-right button) to sign the encrypted message.");
      return;
    }

    setBusy(true);
    try {
      // Request the decrypted key — this shows the passphrase prompt.
      // The decrypted key exists only in this local variable and is
      // cleared when the function returns.
      const decryptedKey = await requestDecryptedKey();

      // Build the recipient key list. If "include me" is checked, derive
      // the public key from the decrypted private key.
      const recipientKeys: string[] = [...recipients.map((r) => r.armored)];
      if (includeSelf) {
        try {
          const pubArmored = decryptedKey.toPublic().armor();
          recipientKeys.push(pubArmored);
        } catch {
          // skip self-inclusion on error
        }
      }

      // Pass the PrivateKey object directly to avoid re-armoring +
      // re-parsing, which can lose key material for Keybase P3SKB keys.
      const armored = await encryptAndSign({
        plaintext,
        recipientPublicKeys: recipientKeys,
        signerPrivateKey: decryptedKey,
      });
      setOutput(armored);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [plaintext, recipients, privateKey, includeSelf, requestDecryptedKey]);

  return (
    <section className="space-y-4">
      <RecipientPicker
        recipients={recipients}
        setRecipients={setRecipients}
        autocompleteProxy={proxies.autocompleteProxy}
        searchAllProxy={proxies.searchAllProxy}
        keybaseProxy={proxies.keybaseProxy}
        includeSelf={includeSelf}
        setIncludeSelf={setIncludeSelf}
        selfRecipient={selfRecipient}
      />

      <div>
        <Label>Message</Label>
        <Textarea
          value={plaintext}
          onChange={setPlaintext}
          placeholder="Type the message you want to encrypt + sign."
          rows={8}
          disabled={!!output}
        />
      </div>

      {error && <ErrorBanner message={error} />}

      {!output && (
        <div className="flex gap-2">
          <Button onClick={handleEncrypt} disabled={busy} variant="primary">
            {busy ? "Encrypting…" : "Encrypt & sign"}
          </Button>
        </div>
      )}

      {output && (
        <OutputBlock
          title="Encrypted + signed message"
          output={output}
          nukeLabel="Nuke plaintext"
          nukeConfirmed={nukeConfirmed}
          onNuke={() => {
            setPlaintext("");
            setNukeConfirmed(true);
          }}
          onReset={() => {
            setOutput("");
            setPlaintext("");
            setNukeConfirmed(false);
            setError(null);
          }}
        />
      )}
    </section>
  );
}

/* ----------------------- Recipient picker w/ autocomplete ------------------- */

function RecipientPicker({
  recipients,
  setRecipients,
  autocompleteProxy,
  searchAllProxy,
  keybaseProxy,
  includeSelf,
  setIncludeSelf,
  selfRecipient,
}: {
  recipients: Recipient[];
  setRecipients: React.Dispatch<React.SetStateAction<Recipient[]>>;
  autocompleteProxy: string;
  searchAllProxy: string;
  keybaseProxy: string;
  includeSelf: boolean;
  setIncludeSelf: (v: boolean) => void;
  selfRecipient: Recipient | null;
}) {
  const [input, setInput] = useState("");
  const [suggestions, setSuggestions] = useState<KeySearchResult[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [busy, setBusy] = useState(false);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Debounced multi-source search
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    const q = input.trim();
    if (q.length < 1) {
      setSuggestions([]);
      return;
    }
    debounceRef.current = setTimeout(async () => {
      setBusy(true);
      try {
        const results = await searchAllKeyserversClient(q, searchAllProxy);
        setSuggestions(results);
        setShowSuggestions(true);
      } catch {
        setSuggestions([]);
      } finally {
        setBusy(false);
      }
    }, 250);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [input, searchAllProxy]);

  // Click-outside to close suggestions
  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (
        containerRef.current &&
        !containerRef.current.contains(e.target as Node)
      ) {
        setShowSuggestions(false);
      }
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  const addRecipient = useCallback(
    async (result: KeySearchResult) => {
      setError(null);
      setAdding(true);
      try {
        if (result.source === "keybase" && result.username) {
          // Fetch the full public key from Keybase
          const r = await lookupKeybaseUsersClient(
            [result.username],
            keybaseProxy,
          );
          if (r.found.length === 0) {
            setError(`No Keybase key found for @${result.username}.`);
            return;
          }
          const k = r.found[0];
          if (recipients.some((p) => p.fingerprint === k.fingerprint)) {
            setInput("");
            setSuggestions([]);
            setShowSuggestions(false);
            return;
          }
          setRecipients((prev) => [
            ...prev,
            {
              source: "keybase",
              username: k.username,
              label: `@${k.username}`,
              armored: k.armored,
              fingerprint: k.fingerprint,
              keyID: k.keyID,
              algorithm: k.algorithm,
              expiresAt: k.expiresAt,
            },
          ]);
        } else if (result.fingerprint) {
          // Fetch the key from keys.openpgp.org or Ubuntu keyserver
          const fetched = await fetchKeysFromAllSources(
            [result.fingerprint],
            "/api/keybase/fetchkey",
            "/api/keybase/fetchkey-opg",
          );
          if (fetched.length === 0) {
            setError(`Could not fetch key ${result.keyID || result.fingerprint}.`);
            return;
          }
          const k = fetched[0];
          if (recipients.some((p) => p.fingerprint === k.fingerprint)) {
            setInput("");
            setSuggestions([]);
            setShowSuggestions(false);
            return;
          }
          setRecipients((prev) => [
            ...prev,
            {
              source: "local",
              label: result.fullName
                ? `${result.fullName} <${result.email}>`
                : result.label,
              armored: k.armored,
              fingerprint: k.fingerprint,
              keyID: k.keyID,
              algorithm: "Unknown",
              expiresAt: null,
            },
          ]);
        } else {
          setError("No key fingerprint available for this result.");
        }
        setInput("");
        setSuggestions([]);
        setShowSuggestions(false);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setAdding(false);
      }
    },
    [recipients, setRecipients, keybaseProxy],
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter" && suggestions.length > 0) {
        e.preventDefault();
        addRecipient(suggestions[0]);
      } else if (e.key === "Escape") {
        setShowSuggestions(false);
      }
    },
    [suggestions, addRecipient],
  );

  const sourceColors: Record<string, string> = {
    keybase: "bg-[#0055dc]/10 text-[#0055dc]",
    ubuntu: "bg-orange-100 text-orange-700",
    "openpgp.org": "bg-green-100 text-green-700",
    mailvelope: "bg-purple-100 text-purple-700",
  };

  return (
    <div>
      <Label>Recipients</Label>

      {/* Include-me checkbox (only shown when a private key is configured) */}
      {selfRecipient && (
        <label className="mb-2 flex items-center gap-2 text-xs text-neutral-700 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={includeSelf}
            onChange={(e) => setIncludeSelf(e.target.checked)}
            className="size-3.5 accent-[#0055dc]"
          />
          <span>
            Include me as a recipient{" "}
            <span className="text-neutral-400">
              (encrypts a copy to myself — stays {includeSelf ? "on" : "off"} for next time)
            </span>
          </span>
        </label>
      )}

      {/* Recipients list — show self chip first when included */}
      {(recipients.length > 0 || (includeSelf && selfRecipient)) && (
        <ul className="mb-2 flex flex-wrap gap-1.5">
          {includeSelf && selfRecipient && (
            <li
              className="inline-flex items-center gap-1.5 rounded-full border border-[#0055dc]/30 bg-[#0055dc]/5 pl-2.5 pr-1.5 py-1 text-xs"
              title={`${selfRecipient.label}\n${formatFingerprint(selfRecipient.fingerprint)}`}
            >
              <span className="font-medium text-[#0055dc]">
                {selfRecipient.label}
              </span>
              <span className="text-[10px] text-[#0055dc]/70">auto</span>
            </li>
          )}
          {recipients.map((r) => (
            <li
              key={r.fingerprint}
              className="inline-flex items-center gap-1.5 rounded-full border border-neutral-300 bg-white pl-2.5 pr-1.5 py-1 text-xs"
              title={`${r.label}\n${formatFingerprint(r.fingerprint)}`}
            >
              <span className="font-medium text-[#0055dc]">{r.label}</span>
              <button
                type="button"
                onClick={() =>
                  setRecipients((prev) =>
                    prev.filter((p) => p.fingerprint !== r.fingerprint),
                  )
                }
                className="ml-1 rounded-full text-neutral-400 hover:text-neutral-700"
                aria-label={`Remove ${r.label}`}
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}

      {/* Input + autocomplete dropdown */}
      <div className="relative" ref={containerRef}>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          onFocus={() => suggestions.length > 0 && setShowSuggestions(true)}
          placeholder={
            recipients.length === 0
              ? "Search by name, email, or Keybase username…"
              : "Add another recipient…"
          }
          className="w-full rounded-md border border-neutral-300 bg-white px-3 py-2 text-sm placeholder:text-neutral-400 focus:outline-none focus:ring-2 focus:ring-[#0055dc]/30 focus:border-[#0055dc]"
          disabled={adding}
        />
        {busy && (
          <div className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] text-neutral-400">
            …
          </div>
        )}

        {/* Suggestions dropdown - BELOW the input */}
        {showSuggestions && suggestions.length > 0 && (
          <ul className="absolute z-20 left-0 right-0 mt-1 max-h-64 overflow-auto rounded-md border border-neutral-200 bg-white shadow-lg">
            {suggestions.map((s, i) => {
              const alreadyAdded = recipients.some(
                (p) =>
                  (s.username && p.username === s.username) ||
                  (s.fingerprint && p.fingerprint === s.fingerprint),
              );
              return (
                <li key={`${s.source}-${s.label}-${i}`}>
                  <button
                    type="button"
                    onClick={() => addRecipient(s)}
                    disabled={alreadyAdded}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 text-left text-sm hover:bg-neutral-50 ${
                      alreadyAdded ? "opacity-50 cursor-not-allowed" : ""
                    }`}
                  >
                    {s.pictureUrl ? (
                      <img
                        src={s.pictureUrl}
                        alt=""
                        className="size-6 rounded-full object-cover"
                      />
                    ) : (
                      <div className="size-6 rounded-full bg-neutral-200 grid place-items-center text-[10px] text-neutral-600 font-medium">
                        {(s.username || s.fullName || s.label)
                          .slice(0, 2)
                          .toUpperCase()}
                      </div>
                    )}
                    <div className="min-w-0 flex-1">
                      <div className="font-medium text-neutral-900 truncate">
                        {s.label}
                      </div>
                      {s.fullName && s.username && (
                        <div className="text-[11px] text-neutral-500 truncate">
                          {s.fullName}
                        </div>
                      )}
                      {s.email && !s.username && (
                        <div className="text-[11px] text-neutral-500 truncate">
                          {s.email}
                        </div>
                      )}
                    </div>
                    <span
                      className={`shrink-0 rounded-full px-1.5 py-0.5 text-[9px] font-medium ${sourceColors[s.source] || "bg-neutral-100 text-neutral-500"}`}
                    >
                      {s.source}
                    </span>
                    {alreadyAdded && (
                      <span className="text-[10px] text-neutral-400">added</span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {error && <p className="mt-1.5 text-[11px] text-red-600">{error}</p>}

      <p className="mt-1.5 text-[11px] text-neutral-500">
        Searches Keybase, Ubuntu keyserver, and keys.openpgp.org. Type a name,
        email, or Keybase username.
      </p>

      <ManualRecipientAdd
        onAdd={(r) =>
          setRecipients((prev) =>
            prev.some((p) => p.fingerprint === r.fingerprint)
              ? prev
              : [...prev, r],
          )
        }
      />
    </div>
  );
}

function ManualRecipientAdd({
  onAdd,
}: {
  onAdd: (r: Recipient) => void;
}) {
  const [open, setOpen] = useState(false);
  const [armored, setArmored] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleAdd = useCallback(async () => {
    setError(null);
    if (!armored.trim()) {
      setError("Paste an armored public key.");
      return;
    }
    setBusy(true);
    try {
      const v = await validateArmoredKey(armored.trim());
      if (!v.ok || !v.info) {
        setError(v.error ?? "Invalid public key.");
        return;
      }
      if ("isPrivate" in v.info && v.info.isPrivate) {
        setError("That's a private key. Paste a public key for recipients.");
        return;
      }
      onAdd({
        source: "local",
        label:
          v.info.userIDs[0]?.name ||
          v.info.userIDs[0]?.email ||
          "Pasted key",
        armored: armored.trim(),
        fingerprint: v.info.fingerprint,
        keyID: v.info.keyID,
        algorithm: v.info.algorithm,
        expiresAt: v.info.expirationTime?.getTime() ?? null,
      });
      setArmored("");
      setOpen(false);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [armored, onAdd]);

  return (
    <div className="mt-2">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="text-[11px] text-[#0055dc] hover:underline"
      >
        {open ? "Hide manual paste" : "+ Paste a public key manually"}
      </button>
      {open && (
        <div className="mt-1.5 space-y-2">
          <Textarea
            value={armored}
            onChange={setArmored}
            placeholder={"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----"}
            rows={5}
          />
          {error && <ErrorBanner message={error} />}
          <Button onClick={handleAdd} disabled={busy} variant="default">
            {busy ? "Validating…" : "Add public key"}
          </Button>
        </div>
      )}
    </div>
  );
}

/* --------------------------------- Decrypt --------------------------------- */

function DecryptTab({
  privateKey,
  proxies,
  requestDecryptedKey,
}: {
  privateKey: PrivateKeyConfig | null;
  proxies: { fetchkeyProxy: string; fetchkeyOpgProxy: string };
  requestDecryptedKey: () => Promise<OpenPGP.PrivateKey>;
}) {
  const [armored, setArmored] = useState("");
  const [output, setOutput] = useState<{
    plaintext: string;
    signatures: Array<{
      keyID: string;
      fingerprint?: string;
      username?: string;
      verified: "valid" | "invalid" | "unknown";
      error?: string;
    }>;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nukeConfirmed, setNukeConfirmed] = useState(false);

  const handleDecrypt = useCallback(async () => {
    setError(null);
    setOutput(null);
    setNukeConfirmed(false);
    if (!armored.trim()) {
      setError("Paste the encrypted PGP message.");
      return;
    }
    if (!privateKey) {
      setError("Configure your private key first (top-right button).");
      return;
    }
    setBusy(true);
    try {
      // Request the decrypted key — shows passphrase prompt.
      // The key exists only in this local variable and is cleared after.
      const decryptedKey = await requestDecryptedKey();

      // Pass the PrivateKey object directly to avoid re-armoring +
      // re-parsing, which can lose key material for Keybase P3SKB keys.
      const result = await decryptAndAutoVerify(
        {
          armoredMessage: armored,
          decryptionPrivateKey: decryptedKey,
          verificationPublicKeys: [],
        },
        async (keyIDs) => {
          const fetched = await fetchKeysFromAllSources(
            keyIDs,
            proxies.fetchkeyProxy,
            proxies.fetchkeyOpgProxy,
          );
          return fetched.map((f) => ({
            armored: f.armored,
            keyID: f.keyID,
            fingerprint: f.fingerprint,
            username: f.username,
            allKeyIDs: f.allKeyIDs,
          }));
        },
      );
      setOutput(result);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [armored, privateKey, proxies.fetchkeyProxy, proxies.fetchkeyOpgProxy, requestDecryptedKey]);

  return (
    <section className="space-y-4">
      <div>
        <Label>Encrypted message</Label>
        <Textarea
          value={armored}
          onChange={setArmored}
          placeholder={"-----BEGIN PGP MESSAGE-----\n...\n-----END PGP MESSAGE-----"}
          rows={10}
          disabled={!!output}
        />
      </div>

      {error && <ErrorBanner message={error} />}

      {!output && (
        <div className="flex gap-2">
          <Button onClick={handleDecrypt} disabled={busy} variant="primary">
            {busy ? "Decrypting…" : "Decrypt"}
          </Button>
        </div>
      )}

      {output && (
        <div className="space-y-4">
          {output.signatures.length > 0 && (
            <SignerBadges signatures={output.signatures} />
          )}
          <OutputBlock
            title="Decrypted message"
            output={output.plaintext}
            nukeLabel="Nuke encrypted input"
            nukeConfirmed={nukeConfirmed}
            onNuke={() => {
              setArmored("");
              setNukeConfirmed(true);
            }}
            onReset={() => {
              setOutput(null);
              setArmored("");
              setNukeConfirmed(false);
              setError(null);
            }}
          />
        </div>
      )}
    </section>
  );
}

function SignerBadges({
  signatures,
}: {
  signatures: Array<{
    keyID: string;
    fingerprint?: string;
    username?: string;
    verified: "valid" | "invalid" | "unknown";
    error?: string;
  }>;
}) {
  return (
    <div className="rounded-md border border-neutral-200 bg-neutral-50 px-3 py-2.5">
      <div className="text-[11px] font-medium uppercase tracking-wide text-neutral-500 mb-1.5">
        Signed by
      </div>
      <ul className="space-y-1.5">
        {signatures.map((s, i) => {
          const color =
            s.verified === "valid"
              ? "text-emerald-700 bg-emerald-50 border-emerald-200"
              : s.verified === "invalid"
                ? "text-red-700 bg-red-50 border-red-200"
                : "text-neutral-700 bg-neutral-100 border-neutral-200";
          const label =
            s.verified === "valid"
              ? "verified"
              : s.verified === "invalid"
                ? "invalid signature"
                : "unknown signer";
          return (
            <li key={i} className="flex items-center gap-2 text-sm">
              <span className="font-medium text-[#0055dc]">
                {s.username ? `@${s.username}` : "Unknown key"}
              </span>
              <span
                className={`inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-medium ${color}`}
              >
                {label}
              </span>
              <span className="text-[11px] text-neutral-500 font-mono ml-auto">
                {s.keyID}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/* ----------------------------------- Sign ---------------------------------- */

function SignTab({
  privateKey,
  requestDecryptedKey,
}: {
  privateKey: PrivateKeyConfig | null;
  requestDecryptedKey: () => Promise<OpenPGP.PrivateKey>;
}) {
  const [plaintext, setPlaintext] = useState("");
  const [detached, setDetached] = useState(false);
  const [output, setOutput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nukeConfirmed, setNukeConfirmed] = useState(false);

  const handleSign = useCallback(async () => {
    setError(null);
    setOutput("");
    setNukeConfirmed(false);
    if (!plaintext.trim()) {
      setError("Enter the text to sign.");
      return;
    }
    if (!privateKey) {
      setError("Configure your private key first (top-right button).");
      return;
    }
    setBusy(true);
    try {
      // Request the decrypted key — shows passphrase prompt.
      // The key exists only in this local variable and is cleared after.
      const decryptedKey = await requestDecryptedKey();

      // Pass the PrivateKey object directly to avoid re-armoring +
      // re-parsing, which can lose key material for Keybase P3SKB keys.
      const signed = await signMessage({
        plaintext,
        privateKey: decryptedKey,
        detached,
      });
      setOutput(signed);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [plaintext, privateKey, detached, requestDecryptedKey]);

  return (
    <section className="space-y-4">
      <div>
        <Label>Plain text to sign</Label>
        <Textarea
          value={plaintext}
          onChange={setPlaintext}
          placeholder="Paste the text you want to sign."
          rows={8}
          disabled={!!output}
        />
      </div>

      <div className="flex gap-5 text-sm">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="radio"
            checked={!detached}
            onChange={() => setDetached(false)}
            className="accent-[#0055dc]"
          />
          <span>Cleartext signed</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="radio"
            checked={detached}
            onChange={() => setDetached(true)}
            className="accent-[#0055dc]"
          />
          <span>Detached signature</span>
        </label>
      </div>

      {error && <ErrorBanner message={error} />}

      {!output && (
        <div className="flex gap-2">
          <Button onClick={handleSign} disabled={busy} variant="primary">
            {busy ? "Signing…" : "Sign message"}
          </Button>
        </div>
      )}

      {output && (
        <OutputBlock
          title={detached ? "Detached signature" : "Cleartext signed message"}
          output={output}
          nukeLabel="Nuke plaintext"
          nukeConfirmed={nukeConfirmed}
          onNuke={() => {
            setPlaintext("");
            setNukeConfirmed(true);
          }}
          onReset={() => {
            setOutput("");
            setPlaintext("");
            setNukeConfirmed(false);
            setError(null);
          }}
        />
      )}
    </section>
  );
}

/* ---------------------------------- Verify --------------------------------- */

function VerifyTab({
  proxies,
}: {
  proxies: { fetchkeyProxy: string; fetchkeyOpgProxy: string };
}) {
  const [armored, setArmored] = useState("");
  const [plaintext, setPlaintext] = useState("");
  const [detected, setDetected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{
    verified: "valid" | "invalid" | "unknown";
    signatures: Array<{
      keyID: string;
      fingerprint?: string;
      username?: string;
      verified: "valid" | "invalid" | "unknown";
      error?: string;
    }>;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Auto-detect format on input change
  useEffect(() => {
    if (!armored.trim()) {
      setDetected(null);
      return;
    }
    const f = detectArmoredFormat(armored);
    setDetected(f);
  }, [armored]);

  const handleVerify = useCallback(async () => {
    setError(null);
    setResult(null);
    if (!armored.trim()) {
      setError("Paste a signature or cleartext-signed message to verify.");
      return;
    }
    setBusy(true);
    try {
      const res = await verifyAutoDetectWithKeyFetch(
        armored,
        plaintext || undefined,
        async (keyIDs) => {
          const fetched = await fetchKeysFromAllSources(
            keyIDs,
            proxies.fetchkeyProxy,
            proxies.fetchkeyOpgProxy,
          );
          return fetched.map((f) => ({
            armored: f.armored,
            keyID: f.keyID,
            fingerprint: f.fingerprint,
            username: f.username,
            allKeyIDs: f.allKeyIDs,
          }));
        },
      );
      setResult(res);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [armored, plaintext, proxies.fetchkeyProxy, proxies.fetchkeyOpgProxy]);

  const showPlaintextField = detected === "detached-signature";

  return (
    <section className="space-y-4">
      <div>
        <Label>Signature or signed message</Label>
        <Textarea
          value={armored}
          onChange={setArmored}
          placeholder={
            "Paste a cleartext-signed message (-----BEGIN PGP SIGNED MESSAGE-----)\n" +
            "or a detached signature (-----BEGIN PGP SIGNATURE-----)."
          }
          rows={8}
        />
        {detected && (
          <p className="mt-1.5 text-[11px] text-neutral-500">
            Detected format:{" "}
            <span className="font-medium text-neutral-700">{detected}</span>
            {detected === "encrypted-message" && (
              <span className="ml-1">
                — switch to the Decrypt tab to decrypt and verify.
              </span>
            )}
          </p>
        )}
        <p className="mt-1.5 text-[11px] text-neutral-500">
          The signer's public key is fetched automatically from Keybase by the
          signature's key ID.
        </p>
      </div>

      {showPlaintextField && (
        <div>
          <Label>Original plaintext (required for detached signatures)</Label>
          <Textarea
            value={plaintext}
            onChange={setPlaintext}
            placeholder="Paste the plaintext that was signed."
            rows={6}
          />
        </div>
      )}

      {error && <ErrorBanner message={error} />}

      <div className="flex gap-2">
        <Button onClick={handleVerify} disabled={busy} variant="primary">
          {busy ? "Verifying…" : "Verify"}
        </Button>
        {(result || error) && (
          <Button
            onClick={() => {
              setArmored("");
              setPlaintext("");
              setResult(null);
              setError(null);
              setDetected(null);
            }}
            variant="ghost"
          >
            Reset
          </Button>
        )}
      </div>

      {result && (
        <div className="rounded-md border border-neutral-200 bg-neutral-50 px-4 py-3">
          <div className="text-sm font-medium mb-2">
            {result.verified === "valid" ? (
              <span className="text-emerald-700">✓ Signature is valid</span>
            ) : result.verified === "invalid" ? (
              <span className="text-red-700">✗ Signature is invalid</span>
            ) : (
              <span className="text-neutral-700">
                ? Signature could not be verified
              </span>
            )}
          </div>
          {result.signatures.length > 0 && (
            <ul className="space-y-1.5 text-xs">
              {result.signatures.map((s, i) => {
                const color =
                  s.verified === "valid"
                    ? "text-emerald-700"
                    : s.verified === "invalid"
                      ? "text-red-700"
                      : "text-neutral-600";
                const label =
                  s.verified === "valid"
                    ? "verified"
                    : s.verified === "invalid"
                      ? "invalid signature"
                      : "unknown signer";
                return (
                  <li key={i} className="flex items-center gap-2">
                    <span className="font-medium text-[#0055dc]">
                      {s.username ? `@${s.username}` : "Unknown key"}
                    </span>
                    <span className={`font-medium ${color}`}>{label}</span>
                    <span className="text-[11px] text-neutral-500 font-mono ml-auto">
                      {s.keyID}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}

/* --------------------------- Output + nuke block --------------------------- */

function OutputBlock({
  title,
  output,
  nukeLabel,
  nukeConfirmed,
  onNuke,
  onReset,
}: {
  title: string;
  output: string;
  nukeLabel: string;
  nukeConfirmed: boolean;
  onNuke: () => void;
  onReset: () => void;
}) {
  return (
    <div className="space-y-3">
      <div>
        <Label>{title}</Label>
        <Textarea value={output} readOnly rows={12} />
        <div className="mt-2 flex justify-end">
          <CopyButton text={output} />
        </div>
      </div>

      <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2.5">
        {!nukeConfirmed ? (
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs text-amber-800">
              Your input is still in memory. Nuke it now to make sure only the
              output remains.
            </p>
            <button
              onClick={onNuke}
              className="shrink-0 rounded-md bg-amber-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-amber-700"
            >
              {nukeLabel}
            </button>
          </div>
        ) : (
          <p className="text-xs text-emerald-700">
            ✓ Input nuked. Only the output remains in memory.
          </p>
        )}
      </div>

      <div className="flex gap-2">
        <Button onClick={onReset} variant="ghost">
          Start over
        </Button>
      </div>
    </div>
  );
}

/* ---------------------------- Configure modal ------------------------------ */

interface ConfigureModalProps {
  onClose: () => void;
  privateKey: PrivateKeyConfig | null;
  onSave: (next: PrivateKeyConfig) => void;
  onClear: () => void;
  proxies: {
    getsaltProxy: string;
    loginProxy: string;
  };
}

/* --------------------------- Passphrase Prompt ----------------------------- */

function PassphrasePrompt({
  config,
  proxies,
  onResolve,
  onCancel,
  onKeyUpdated,
}: {
  config: PrivateKeyConfig;
  proxies: { getsaltProxy: string; loginProxy: string };
  onResolve: (key: OpenPGP.PrivateKey) => void;
  onCancel: (err: Error) => void;
  onKeyUpdated?: (config: PrivateKeyConfig) => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState("");
  const [error, setError] = useState<string | null>(null);

  const isKeybase = config.source === "keybase";
  const promptLabel = isKeybase ? "Keybase password" : "Passphrase";
  const promptPlaceholder = isKeybase
    ? "Your Keybase account password"
    : "Passphrase for the private key";

  const handleSubmit = useCallback(async () => {
    setError(null);
    if (!passphrase) {
      setError(`Enter your ${promptLabel.toLowerCase()}.`);
      return;
    }
    setBusy(true);
    try {
      if (isKeybase) {
        setStage("Loading crypto libraries…");
        const { loginWithPassword } = await import("~/lib/keybase-auth");
        setStage("Fetching salt + deriving keys…");
        await new Promise((r) => setTimeout(r, 50));
        setStage("Generating PDPKA signatures…");
        await new Promise((r) => setTimeout(r, 50));
        setStage("Logging in to Keybase…");
        const { me, privateKey: decrypted } = await loginWithPassword(
          config.username!,
          passphrase,
          {
            getsaltUrl: proxies.getsaltProxy,
            loginUrl: proxies.loginProxy,
          },
        );
        setStage("Decrypting private key…");

        const armored = decrypted.armor();
        const info = await validateArmoredKey(armored);
        if (info.ok && info.info && onKeyUpdated) {
          const oldInfo = config.info;
          const newInfo = info.info;
          if (
            oldInfo.fingerprint !== newInfo.fingerprint ||
            oldInfo.keyID !== newInfo.keyID
          ) {
            onKeyUpdated({ ...config, info: newInfo });
          }
        }
        onResolve(decrypted);
      } else {
        if (!config.encryptedArmored) {
          throw new Error("No encrypted key found in configuration.");
        }
        setStage("Decrypting private key…");
        const key = await readKey(config.encryptedArmored);
        if (!key.isPrivate()) {
          throw new Error("Stored key is not a private key.");
        }
        const decrypted = await unlockPrivateKey(
          key as OpenPGP.PrivateKey,
          passphrase,
        );
        onResolve(decrypted);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
      setStage("");
    }
  }, [passphrase, isKeybase, config, proxies, onResolve, onKeyUpdated, promptLabel]);

  const handleCancel = useCallback(() => {
    onCancel(new Error("Cancelled by user"));
  }, [onCancel]);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/40 p-4 sm:p-8 overflow-auto">
      <div className="w-full max-w-md rounded-lg bg-white shadow-xl my-8">
        <div className="flex items-center justify-between border-b border-neutral-200 px-5 py-3">
          <h2 className="text-base font-semibold">
            {isKeybase ? "Enter Keybase password" : "Enter passphrase"}
          </h2>
          <button
            onClick={handleCancel}
            className="text-neutral-400 hover:text-neutral-700 text-xl leading-none"
            aria-label="Close"
          >
            ×
          </button>
        </div>
        <div className="px-5 py-4">
          <p className="text-xs text-neutral-500 mb-3">
            {isKeybase
              ? "Your password is used to re-fetch and decrypt your private key from Keybase. It is never stored — only kept in RAM for this operation."
              : "Your passphrase decrypts the private key in memory. It is never stored and is cleared immediately after the operation."}
          </p>
          <div className="space-y-2">
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !busy) handleSubmit();
                if (e.key === "Escape") handleCancel();
              }}
              placeholder={promptPlaceholder}
              autoFocus
              autoComplete="off"
              className="w-full rounded-md border border-neutral-300 bg-white px-3 py-2 text-sm placeholder:text-neutral-400 focus:outline-none focus:ring-2 focus:ring-[#0055dc]/30 focus:border-[#0055dc]"
              disabled={busy}
            />
            {error && <ErrorBanner message={error} />}
            {busy && stage && (
              <p className="text-[11px] text-neutral-500">{stage}</p>
            )}
            <div className="flex gap-2 pt-1">
              <Button onClick={handleSubmit} disabled={busy} variant="primary" full>
                {busy ? "Working…" : "Decrypt & continue"}
              </Button>
              <Button onClick={handleCancel} disabled={busy} variant="ghost">
                Cancel
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ConfigureModal({
  onClose,
  privateKey,
  onSave,
  onClear,
  proxies,
}: ConfigureModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/40 p-4 sm:p-8 overflow-auto">
      <div className="w-full max-w-lg rounded-lg bg-white shadow-xl my-8">
        <div className="flex items-center justify-between border-b border-neutral-200 px-5 py-3">
          <h2 className="text-base font-semibold">Configure your private key</h2>
          <button
            onClick={onClose}
            className="text-neutral-400 hover:text-neutral-700 text-xl leading-none"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="px-5 py-4 max-h-[80vh] overflow-y-auto">
          {privateKey && (
            <div className="mb-4 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2.5">
              <div className="text-xs font-medium text-emerald-800 mb-1">
                Currently configured
              </div>
              <div className="text-sm text-emerald-900">
                {privateKey.source === "keybase"
                  ? `@${privateKey.username} (via Keybase login)`
                  : privateKey.label}
              </div>
              {privateKey.info && (
                <div className="text-[11px] font-mono text-emerald-700 mt-1 break-all">
                  {formatFingerprint(privateKey.info.fingerprint)}
                </div>
              )}
              <button
                onClick={onClear}
                className="mt-2 text-[11px] text-red-600 hover:underline"
              >
                Clear / log out
              </button>
            </div>
          )}

          <KeybaseLoginForm
            proxies={proxies}
            onLoaded={(cfg) => onSave(cfg)}
          />

          <hr className="my-4 border-neutral-200" />

          <ManualKeyForm onLoaded={(cfg) => onSave(cfg)} />

          <hr className="my-4 border-neutral-200" />

          <GenerateKeyForm onLoaded={(cfg) => onSave(cfg)} />
        </div>
      </div>
    </div>
  );
}

function KeybaseLoginForm({
  proxies,
  onLoaded,
}: {
  proxies: { getsaltProxy: string; loginProxy: string };
  onLoaded: (cfg: PrivateKeyConfig) => void;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  const handleLogin = useCallback(async () => {
    setError(null);
    if (!username.trim() || !password) {
      setError("Enter your Keybase username and password.");
      return;
    }
    setBusy(true);
    try {
      setStage("Loading crypto libraries…");
      // Dynamically import keybase-auth (which in turn dynamically imports
      // kbpgp + keybase-proofs) only when the user actually clicks login.
      // This keeps the initial page bundle small and prevents OOM crashes
      // during Turbopack compilation.
      const { loginWithPassword } = await import("~/lib/keybase-auth");

      setStage("Fetching salt + deriving keys…");
      // Yield to the browser so the stage label can paint before the
      // synchronous scrypt + PDPKA signing work blocks the main thread.
      await new Promise((r) => setTimeout(r, 50));

      setStage("Generating PDPKA signatures…");
      await new Promise((r) => setTimeout(r, 50));

      setStage("Logging in to Keybase…");
      const { me, privateKey: decrypted } = await loginWithPassword(
        username,
        password,
        {
          getsaltUrl: proxies.getsaltProxy,
          loginUrl: proxies.loginProxy,
        },
      );

      if (!me.private_key_bundle) {
        throw new Error(
          "Your Keybase account has no private key bundle. Generate one in the Keybase app first.",
        );
      }

      setStage("Decrypting private key…");
      const armored = decrypted.armor();
      const info = await validateArmoredKey(armored);
      if (!info.ok || !info.info) {
        throw new Error(info.error ?? "Decrypted key could not be parsed.");
      }

      // Store ONLY the username + metadata. The decrypted key is NOT stored.
      // At operation time, the password will be re-requested and the key
      // re-fetched from Keybase's me.json API.
      onLoaded({
        source: "keybase",
        label: `@${me.username}`,
        username: me.username,
        info: info.info,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
      setStage("");
    }
  }, [username, password, proxies, onLoaded]);

  return (
    <div>
      <div className="text-sm font-semibold text-neutral-900 mb-1">
        Log in with Keybase
      </div>
      <p className="text-[11px] text-neutral-500 mb-3">
        Your password is used to derive the PGP passphrase via scrypt and never
        leaves your browser. We fetch your private key bundle from{" "}
        <code className="text-neutral-700">keybase.io/_/api/1.0/me.json</code>{" "}
        and decrypt it locally.
      </p>
      <div className="space-y-2">
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Keybase username"
          autoComplete="username"
          className="w-full rounded-md border border-neutral-300 bg-white px-3 py-2 text-sm placeholder:text-neutral-400 focus:outline-none focus:ring-2 focus:ring-[#0055dc]/30 focus:border-[#0055dc]"
          disabled={busy}
        />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
          autoComplete="current-password"
          className="w-full rounded-md border border-neutral-300 bg-white px-3 py-2 text-sm placeholder:text-neutral-400 focus:outline-none focus:ring-2 focus:ring-[#0055dc]/30 focus:border-[#0055dc]"
          disabled={busy}
        />
        {error && <ErrorBanner message={error} />}
        {busy && stage && (
          <p className="text-[11px] text-neutral-500">{stage}</p>
        )}
        <Button onClick={handleLogin} disabled={busy} variant="primary" full>
          {busy ? "Working…" : "Log in & load private key"}
        </Button>
      </div>
    </div>
  );
}

function ManualKeyForm({
  onLoaded,
}: {
  onLoaded: (cfg: PrivateKeyConfig) => void;
}) {
  const [armored, setArmored] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLoad = useCallback(async () => {
    setError(null);
    if (!armored.trim()) {
      setError("Paste your armored private key.");
      return;
    }
    setBusy(true);
    try {
      const v = await validateArmoredKey(armored.trim());
      if (!v.ok || !v.info) {
        setError(v.error ?? "Invalid key.");
        return;
      }
      if (!("isPrivate" in v.info) || !v.info.isPrivate) {
        setError("That's a public key. Paste a private key.");
        return;
      }
      // Store ONLY the ENCRYPTED armored key. The passphrase is NOT stored.
      onLoaded({
        source: "manual",
        label:
          v.info.userIDs[0]?.name ||
          v.info.userIDs[0]?.email ||
          "Pasted private key",
        encryptedArmored: armored.trim(),
        info: v.info,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [armored, passphrase, onLoaded]);

  return (
    <div>
      <div className="text-sm font-semibold text-neutral-900 mb-1">
        Paste a private key
      </div>
      <p className="text-[11px] text-neutral-500 mb-3">
        Use this if you already have an armored PGP private key block.
      </p>
      <div className="space-y-2">
        <Textarea
          value={armored}
          onChange={setArmored}
          placeholder={"-----BEGIN PGP PRIVATE KEY BLOCK-----\n...\n-----END PGP PRIVATE KEY BLOCK-----"}
          rows={5}
        />
        <input
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          placeholder="Passphrase (if encrypted)"
          autoComplete="off"
          className="w-full rounded-md border border-neutral-300 bg-white px-3 py-2 text-sm placeholder:text-neutral-400 focus:outline-none focus:ring-2 focus:ring-[#0055dc]/30 focus:border-[#0055dc]"
        />
        {error && <ErrorBanner message={error} />}
        <Button onClick={handleLoad} disabled={busy} variant="default" full>
          {busy ? "Loading…" : "Load private key"}
        </Button>
      </div>
    </div>
  );
}

function GenerateKeyForm({
  onLoaded,
}: {
  onLoaded: (cfg: PrivateKeyConfig) => void;
}) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [pass, setPass] = useState("");
  const [type, setType] = useState<"ecc" | "rsa">("ecc");
  const [curve, setCurve] = useState("ed25519Legacy");
  const [bits, setBits] = useState<2048 | 3072 | 4096>(4096);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = useCallback(async () => {
    setError(null);
    setBusy(true);
    try {
      const kp: GeneratedKeyPair = await generateKeyPair({
        name: name || undefined,
        email: email || undefined,
        passphrase: pass || undefined,
        type,
        curve: type === "ecc" ? (curve as never) : undefined,
        rsaBits: type === "rsa" ? bits : undefined,
        expirationSeconds: 0,
      });
      const label =
        name || email || (type === "ecc" ? "ECC key" : "RSA key");
      // Store ONLY the ENCRYPTED armored private key. The passphrase is
      // NOT stored — it will be re-requested at operation time.
      onLoaded({
        source: "generated",
        label,
        encryptedArmored: kp.privateKey,
        info: kp.info,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [name, email, pass, type, curve, bits, onLoaded]);

  return (
    <details className="group">
      <summary className="cursor-pointer text-sm font-semibold text-neutral-900 select-none">
        Generate a new local key{" "}
        <span className="text-[11px] text-neutral-500 font-normal">
          (advanced)
        </span>
      </summary>
      <div className="mt-3 space-y-2">
        <div className="grid grid-cols-2 gap-2">
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Full name"
            className="rounded-md border border-neutral-300 bg-white px-2 py-1.5 text-xs"
          />
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="email@example.com"
            className="rounded-md border border-neutral-300 bg-white px-2 py-1.5 text-xs"
          />
        </div>
        <input
          type="password"
          value={pass}
          onChange={(e) => setPass(e.target.value)}
          placeholder="Passphrase (optional)"
          autoComplete="off"
          className="w-full rounded-md border border-neutral-300 bg-white px-2 py-1.5 text-xs"
        />
        <div className="grid grid-cols-2 gap-2 text-[11px]">
          <select
            value={type}
            onChange={(e) => setType(e.target.value as "ecc" | "rsa")}
            className="rounded-md border border-neutral-300 bg-white px-2 py-1.5"
          >
            <option value="ecc">ECC (recommended)</option>
            <option value="rsa">RSA</option>
          </select>
          {type === "ecc" ? (
            <select
              value={curve}
              onChange={(e) => setCurve(e.target.value)}
              className="rounded-md border border-neutral-300 bg-white px-2 py-1.5"
            >
              <option value="ed25519Legacy">ed25519</option>
              <option value="nistP256">NIST P-256</option>
              <option value="nistP384">NIST P-384</option>
              <option value="nistP521">NIST P-521</option>
              <option value="secp256k1">secp256k1</option>
            </select>
          ) : (
            <select
              value={bits}
              onChange={(e) =>
                setBits(Number(e.target.value) as 2048 | 3072 | 4096)
              }
              className="rounded-md border border-neutral-300 bg-white px-2 py-1.5"
            >
              <option value={2048}>2048</option>
              <option value={3072}>3072</option>
              <option value={4096}>4096</option>
            </select>
          )}
        </div>
        {error && <ErrorBanner message={error} />}
        <Button onClick={handleGenerate} disabled={busy} variant="default" full>
          {busy ? "Generating…" : "Generate key pair"}
        </Button>
      </div>
    </details>
  );
}

/* --------------------------------- Sub-UI ---------------------------------- */

function Label({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-xs font-medium uppercase tracking-wide text-neutral-500 mb-1.5">
      {children}
    </label>
  );
}

function Textarea({
  value,
  onChange,
  placeholder,
  rows,
  readOnly,
  disabled,
}: {
  value: string;
  onChange?: (v: string) => void;
  placeholder?: string;
  rows?: number;
  readOnly?: boolean;
  disabled?: boolean;
}) {
  return (
    <textarea
      value={value}
      onChange={onChange ? (e) => onChange(e.target.value) : undefined}
      placeholder={placeholder}
      rows={rows ?? 6}
      readOnly={readOnly}
      disabled={disabled}
      spellCheck={false}
      className={`w-full rounded-md border border-neutral-300 bg-white px-3 py-2 text-xs leading-relaxed placeholder:text-neutral-400 focus:outline-none focus:ring-2 focus:ring-[#0055dc]/30 focus:border-[#0055dc] ${
        readOnly ? "bg-neutral-50" : ""
      } ${disabled ? "opacity-60" : ""}`}
    />
  );
}

function Button({
  children,
  onClick,
  disabled,
  variant = "default",
  full,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "primary" | "ghost" | "default";
  full?: boolean;
}) {
  const base =
    "inline-flex items-center justify-center gap-1.5 rounded-md px-4 py-2 text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed";
  const variants: Record<string, string> = {
    primary: "bg-[#0055dc] text-white hover:bg-[#0044b8]",
    ghost: "bg-transparent text-neutral-700 hover:bg-neutral-100",
    default: "bg-white text-neutral-700 border border-neutral-300 hover:bg-neutral-50",
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`${base} ${variants[variant]} ${full ? "w-full" : ""}`}
    >
      {children}
    </button>
  );
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">
      {message}
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          // ignore
        }
      }}
      className="text-[11px] rounded px-2 py-1 bg-white border border-neutral-300 hover:bg-neutral-50 text-neutral-700"
    >
      {copied ? "Copied!" : "Copy"}
    </button>
  );
}
