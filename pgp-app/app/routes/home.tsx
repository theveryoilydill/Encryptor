import { useCallback, useEffect, useState } from "react";
import type { Route } from "./+types/home";
import { lookupKeybaseUsersClient, type KeybasePublicKey } from "~/lib/keybase";
import {
  decryptAndVerify,
  encryptAndSign,
  formatFingerprint,
  generateKeyPair,
  signMessage,
  validateArmoredKey,
  verifyMessage,
  type AnyKeyInfo,
  type DecryptAndVerifyResult,
  type GeneratedKeyPair,
} from "~/lib/pgp";

export function meta(_: Route.MetaArgs) {
  return [
    { title: "PGP · Keybase · Cloudflare" },
    {
      name: "description",
      content:
        "Encrypt + sign PGP messages to multiple recipients, decrypt while verifying the signer, and sign plain text. Pulls PGP keys from Keybase.",
    },
  ];
}

export async function loader(_: Route.LoaderArgs) {
  // The Keybase proxy URL is the same origin in production (Cloudflare Worker).
  return Response.json({ keybaseProxy: "/api/keybase" });
}

type Tab = "encrypt" | "decrypt" | "sign" | "verify";

interface LocalKey {
  id: string;
  label: string;
  armored: string;
  isPrivate: boolean;
  info?: AnyKeyInfo;
  createdAt: number;
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

const LOCAL_STORAGE_KEY = "pgp-app.local-keys.v1";

export default function Home({ loaderData }: Route.ComponentProps) {
  const { keybaseProxy } = loaderData as { keybaseProxy: string };

  const [tab, setTab] = useState<Tab>("encrypt");

  // Shared state: list of resolved recipient public keys (used by Encrypt tab)
  const [recipients, setRecipients] = useState<Recipient[]>([]);

  // Shared state: signer's private key (used by Encrypt + Sign, Sign, and as fallback for Decrypt)
  const [myPrivateKey, setMyPrivateKey] = useState("");
  const [myPrivateKeyPass, setMyPrivateKeyPass] = useState("");
  const [myPrivateKeyInfo, setMyPrivateKeyInfo] = useState<AnyKeyInfo | null>(null);
  const [myPrivateKeyError, setMyPrivateKeyError] = useState<string | null>(null);

  // Local keys collection
  const [localKeys, setLocalKeys] = useState<LocalKey[]>([]);
  const [showLocalKeys, setShowLocalKeys] = useState(false);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(LOCAL_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw) as LocalKey[];
        if (Array.isArray(parsed)) setLocalKeys(parsed);
      }
    } catch {
      // ignore
    }
  }, []);

  const persistLocalKeys = useCallback((next: LocalKey[]) => {
    setLocalKeys(next);
    try {
      localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(next));
    } catch {
      // ignore quota errors
    }
  }, []);

  const validateMyPrivateKey = useCallback(async () => {
    setMyPrivateKeyError(null);
    if (!myPrivateKey.trim()) {
      setMyPrivateKeyInfo(null);
      return;
    }
    const result = await validateArmoredKey(myPrivateKey.trim());
    if (!result.ok) {
      setMyPrivateKeyInfo(null);
      setMyPrivateKeyError(result.error ?? "Invalid private key.");
      return;
    }
    if (result.info && "isPrivate" in result.info && result.info.isPrivate) {
      setMyPrivateKeyInfo(result.info);
    } else {
      setMyPrivateKeyInfo(null);
      setMyPrivateKeyError(
        "The key you pasted is a public key. A private key is required for signing and decryption.",
      );
    }
  }, [myPrivateKey]);

  useEffect(() => {
    let cancelled = false;
    const t = setTimeout(async () => {
      await validateMyPrivateKey();
      if (cancelled) return;
    }, 400);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [myPrivateKey, validateMyPrivateKey]);

  return (
    <div className="min-h-screen flex flex-col">
      <Header />

      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 lg:py-10 grid grid-cols-1 lg:grid-cols-[1fr_360px] gap-6 lg:gap-8">
        <div className="min-w-0 space-y-6">
          <Tabs value={tab} onChange={setTab} />

          {tab === "encrypt" && (
            <EncryptSignPanel
              recipients={recipients}
              setRecipients={setRecipients}
              myPrivateKey={myPrivateKey}
              myPrivateKeyPass={myPrivateKeyPass}
              myPrivateKeyInfo={myPrivateKeyInfo}
              myPrivateKeyError={myPrivateKeyError}
              localKeys={localKeys}
              keybaseProxy={keybaseProxy}
            />
          )}
          {tab === "decrypt" && (
            <DecryptVerifyPanel
              myPrivateKey={myPrivateKey}
              myPrivateKeyPass={myPrivateKeyPass}
              myPrivateKeyInfo={myPrivateKeyInfo}
              myPrivateKeyError={myPrivateKeyError}
              localKeys={localKeys}
              keybaseProxy={keybaseProxy}
            />
          )}
          {tab === "sign" && (
            <SignPanel
              myPrivateKey={myPrivateKey}
              myPrivateKeyPass={myPrivateKeyPass}
              myPrivateKeyInfo={myPrivateKeyInfo}
              myPrivateKeyError={myPrivateKeyError}
              localKeys={localKeys}
            />
          )}
          {tab === "verify" && (
            <VerifyPanel localKeys={localKeys} keybaseProxy={keybaseProxy} />
          )}
        </div>

        <aside className="space-y-6">
          <KeybaseSidebar
            keybaseProxy={keybaseProxy}
            recipients={recipients}
            setRecipients={setRecipients}
          />

          <MyPrivateKeyCard
            myPrivateKey={myPrivateKey}
            setMyPrivateKey={setMyPrivateKey}
            myPrivateKeyPass={myPrivateKeyPass}
            setMyPrivateKeyPass={setMyPrivateKeyPass}
            myPrivateKeyInfo={myPrivateKeyInfo}
            myPrivateKeyError={myPrivateKeyError}
            localKeys={localKeys}
            onLoadLocalKey={(armored) => setMyPrivateKey(armored)}
          />

          <LocalKeysCard
            localKeys={localKeys}
            setLocalKeys={persistLocalKeys}
            showLocalKeys={showLocalKeys}
            setShowLocalKeys={setShowLocalKeys}
            onLoadAsSigner={(armored) => setMyPrivateKey(armored)}
            onAddAsRecipient={(r) =>
              setRecipients((prev) =>
                prev.some((p) => p.fingerprint === r.fingerprint)
                  ? prev
                  : [...prev, r],
              )
            }
          />
        </aside>
      </main>

      <Footer />
    </div>
  );
}

/* ---------------------------------- Header --------------------------------- */

function Header() {
  return (
    <header className="border-b border-neutral-800 bg-neutral-950/80 backdrop-blur sticky top-0 z-10">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="size-8 rounded-md bg-amber-500 text-neutral-950 font-bold grid place-items-center text-sm">
            PGP
          </div>
          <div className="flex flex-col leading-tight">
            <span className="text-sm font-semibold">PGP for Keybase</span>
            <span className="text-[11px] text-neutral-500">
              Encrypt · Sign · Decrypt · Verify · Cloudflare Workers
            </span>
          </div>
        </div>
        <a
          href="https://keybase.io"
          target="_blank"
          rel="noreferrer noopener"
          className="text-xs text-neutral-400 hover:text-amber-400 transition-colors"
        >
          keybase.io ↗
        </a>
      </div>
    </header>
  );
}

function Footer() {
  return (
    <footer className="mt-auto border-t border-neutral-800 bg-neutral-950">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 text-[11px] text-neutral-500 flex flex-wrap items-center justify-between gap-2">
        <span>
          Built with React Router v8 · openpgp.js · deploys to Cloudflare Workers.
        </span>
        <span>
          All crypto runs in your browser. Keys and messages never touch our
          servers except for Keybase lookups (proxied server-side).
        </span>
      </div>
    </footer>
  );
}

/* ----------------------------------- Tabs ---------------------------------- */

function Tabs({ value, onChange }: { value: Tab; onChange: (t: Tab) => void }) {
  const tabs: { id: Tab; label: string; hint: string }[] = [
    { id: "encrypt", label: "Encrypt & Sign", hint: "To multiple recipients" },
    { id: "decrypt", label: "Decrypt & Verify", hint: "Verify the signer" },
    { id: "sign", label: "Sign", hint: "Plain-text signature" },
    { id: "verify", label: "Verify", hint: "Check a signature" },
  ];
  return (
    <nav
      className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-1 grid grid-cols-2 sm:grid-cols-4 gap-1"
      role="tablist"
    >
      {tabs.map((t) => {
        const active = t.id === value;
        return (
          <button
            key={t.id}
            role="tab"
            aria-selected={active}
            onClick={() => onChange(t.id)}
            className={`rounded-md px-3 py-2 text-left transition-colors ${
              active
                ? "bg-amber-500 text-neutral-950"
                : "text-neutral-300 hover:bg-neutral-800 hover:text-white"
            }`}
          >
            <div className="text-sm font-semibold">{t.label}</div>
            <div
              className={`text-[11px] ${active ? "text-neutral-800" : "text-neutral-500"}`}
            >
              {t.hint}
            </div>
          </button>
        );
      })}
    </nav>
  );
}

/* ------------------------------ Encrypt & Sign ----------------------------- */

interface EncryptSignPanelProps {
  recipients: Recipient[];
  setRecipients: React.Dispatch<React.SetStateAction<Recipient[]>>;
  myPrivateKey: string;
  myPrivateKeyPass: string;
  myPrivateKeyInfo: AnyKeyInfo | null;
  myPrivateKeyError: string | null;
  localKeys: LocalKey[];
  keybaseProxy: string;
}

function EncryptSignPanel({
  recipients,
  setRecipients,
  myPrivateKey,
  myPrivateKeyPass,
  myPrivateKeyInfo,
  myPrivateKeyError,
  localKeys,
  keybaseProxy,
}: EncryptSignPanelProps) {
  const [plaintext, setPlaintext] = useState("");
  const [output, setOutput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showAddRecipient, setShowAddRecipient] = useState(false);

  const handleEncrypt = useCallback(async () => {
    setError(null);
    setOutput("");
    if (!plaintext.trim()) {
      setError("Please enter the plaintext message to encrypt.");
      return;
    }
    if (recipients.length === 0) {
      setError("Please add at least one recipient (Keybase username or pasted public key).");
      return;
    }
    if (!myPrivateKey.trim()) {
      setError(
        "Please provide your private key in the sidebar to sign the encrypted message.",
      );
      return;
    }
    setBusy(true);
    try {
      const armored = await encryptAndSign({
        plaintext,
        recipientPublicKeys: recipients.map((r) => r.armored),
        signerPrivateKey: myPrivateKey,
        signerPassphrase: myPrivateKeyPass || undefined,
      });
      setOutput(armored);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [plaintext, recipients, myPrivateKey, myPrivateKeyPass]);

  return (
    <section className="space-y-4">
      <Card>
        <CardHeader
          title="Encrypt & sign message"
          subtitle="The message is encrypted to every recipient AND signed with your private key."
        />
        <div className="space-y-4">
          <Field label="Recipients">
            <RecipientList
              recipients={recipients}
              onRemove={(fp) =>
                setRecipients((prev) => prev.filter((r) => r.fingerprint !== fp))
              }
            />
            <button
              onClick={() => setShowAddRecipient((v) => !v)}
              className="mt-2 text-xs text-amber-400 hover:text-amber-300"
            >
              {showAddRecipient ? "Hide manual paste" : "+ Paste a public key manually"}
            </button>
            {showAddRecipient && (
              <ManualRecipientForm
                onAdd={(r) =>
                  setRecipients((prev) =>
                    prev.some((p) => p.fingerprint === r.fingerprint)
                      ? prev
                      : [...prev, r],
                  )
                }
              />
            )}
            <p className="mt-2 text-[11px] text-neutral-500">
              Tip: add recipients from the Keybase panel on the right by typing
              their usernames.
            </p>
          </Field>

          <Field label="Plaintext message">
            <Textarea
              value={plaintext}
              onChange={setPlaintext}
              placeholder="Type the message you want to encrypt + sign."
              rows={8}
            />
          </Field>

          <SignerStatus
            info={myPrivateKeyInfo}
            error={myPrivateKeyError}
            hasKey={!!myPrivateKey.trim()}
            localKeys={localKeys}
          />

          {error && <ErrorBanner message={error} />}

          <div className="flex flex-wrap gap-2">
            <Button
              onClick={handleEncrypt}
              disabled={busy}
              variant="primary"
            >
              {busy ? "Encrypting…" : "Encrypt & sign"}
            </Button>
            <Button
              onClick={() => {
                setPlaintext("");
                setOutput("");
                setError(null);
              }}
              variant="ghost"
            >
              Clear
            </Button>
          </div>
        </div>
      </Card>

      {output && (
        <Card>
          <CardHeader
            title="Encrypted + signed message"
            subtitle="Send this ASCII-armored block to your recipients."
          />
          <Textarea value={output} readOnly rows={14} />
          <div className="mt-2 flex justify-end">
            <CopyButton text={output} />
          </div>
        </Card>
      )}
    </section>
  );
}

/* ------------------------------ Decrypt & Verify --------------------------- */

interface DecryptVerifyPanelProps {
  myPrivateKey: string;
  myPrivateKeyPass: string;
  myPrivateKeyInfo: AnyKeyInfo | null;
  myPrivateKeyError: string | null;
  localKeys: LocalKey[];
  keybaseProxy: string;
}

function DecryptVerifyPanel({
  myPrivateKey,
  myPrivateKeyPass,
  myPrivateKeyInfo,
  myPrivateKeyError,
  localKeys,
  keybaseProxy,
}: DecryptVerifyPanelProps) {
  const [armored, setArmored] = useState("");
  const [signerUsernames, setSignerUsernames] = useState("");
  const [signerPubKeys, setSignerPubKeys] = useState<{ label: string; armored: string }[]>([]);
  const [result, setResult] = useState<DecryptAndVerifyResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fetchingKeys, setFetchingKeys] = useState(false);

  const handleFetchSignerKeys = useCallback(async () => {
    setError(null);
    const names = signerUsernames
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (names.length === 0) {
      setError("Enter one or more Keybase usernames for the expected signers.");
      return;
    }
    setFetchingKeys(true);
    try {
      const r = await lookupKeybaseUsersClient(names, keybaseProxy);
      if (r.found.length === 0) {
        setError("No Keybase public keys found for the given usernames.");
      } else {
        setSignerPubKeys(
          r.found.map((k) => ({
            label: `@${k.username}`,
            armored: k.armored,
          })),
        );
      }
      if (r.missing.length > 0) {
        setError(
          (prev) =>
            (prev ? prev + " " : "") +
            `No key found for: ${r.missing.join(", ")}.`,
        );
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setFetchingKeys(false);
    }
  }, [signerUsernames, keybaseProxy]);

  const handleDecrypt = useCallback(async () => {
    setError(null);
    setResult(null);
    if (!armored.trim()) {
      setError("Paste the encrypted PGP message first.");
      return;
    }
    if (!myPrivateKey.trim()) {
      setError("Provide your private key in the sidebar to decrypt.");
      return;
    }
    if (signerPubKeys.length === 0) {
      setError(
        "Provide at least one signer public key (Keybase username or paste) to verify the signature.",
      );
      return;
    }
    setBusy(true);
    try {
      const res = await decryptAndVerify({
        armoredMessage: armored,
        decryptionPrivateKey: myPrivateKey,
        decryptionPassphrase: myPrivateKeyPass || undefined,
        verificationPublicKeys: signerPubKeys.map((k) => k.armored),
      });
      setResult(res);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [armored, myPrivateKey, myPrivateKeyPass, signerPubKeys]);

  return (
    <section className="space-y-4">
      <Card>
        <CardHeader
          title="Decrypt & verify signature"
          subtitle="Decrypt the message with your private key and verify the signer's signature."
        />
        <div className="space-y-4">
          <Field label="Encrypted PGP message">
            <Textarea
              value={armored}
              onChange={setArmored}
              placeholder="-----BEGIN PGP MESSAGE-----&#10;...&#10;-----END PGP MESSAGE-----"
              rows={10}
            />
          </Field>

          <Field label="Expected signer (Keybase usernames)">
            <div className="flex gap-2">
              <input
                type="text"
                value={signerUsernames}
                onChange={(e) => setSignerUsernames(e.target.value)}
                placeholder="alice, bob, chris"
                className="flex-1 rounded-md border border-neutral-800 bg-neutral-900 px-3 py-2 text-sm placeholder:text-neutral-600 focus:outline-none focus:ring-1 focus:ring-amber-500"
              />
              <Button
                onClick={handleFetchSignerKeys}
                disabled={fetchingKeys}
                variant="ghost"
              >
                {fetchingKeys ? "Fetching…" : "Fetch signer keys"}
              </Button>
            </div>
            {signerPubKeys.length > 0 && (
              <ul className="mt-2 text-[11px] text-neutral-400 list-disc list-inside">
                {signerPubKeys.map((k, i) => (
                  <li key={i}>{k.label} · loaded for verification</li>
                ))}
              </ul>
            )}
            <p className="mt-1 text-[11px] text-neutral-500">
              Without the signer's public key, the message can still be
              decrypted but the signature cannot be verified.
            </p>
          </Field>

          <SignerStatus
            info={myPrivateKeyInfo}
            error={myPrivateKeyError}
            hasKey={!!myPrivateKey.trim()}
            localKeys={localKeys}
            isPrivateForDecryption
          />

          {error && <ErrorBanner message={error} />}

          <div className="flex flex-wrap gap-2">
            <Button onClick={handleDecrypt} disabled={busy} variant="primary">
              {busy ? "Decrypting…" : "Decrypt & verify"}
            </Button>
            <Button
              onClick={() => {
                setArmored("");
                setResult(null);
                setError(null);
              }}
              variant="ghost"
            >
              Clear
            </Button>
          </div>
        </div>
      </Card>

      {result && (
        <Card>
          <CardHeader
            title="Decrypted message"
            subtitle="The decrypted plaintext and signature verification result."
          />
          <Textarea value={result.plaintext} readOnly rows={10} />
          <div className="mt-3">
            <SignatureTable signatures={result.signatures} />
          </div>
        </Card>
      )}
    </section>
  );
}

/* ----------------------------------- Sign ---------------------------------- */

interface SignPanelProps {
  myPrivateKey: string;
  myPrivateKeyPass: string;
  myPrivateKeyInfo: AnyKeyInfo | null;
  myPrivateKeyError: string | null;
  localKeys: LocalKey[];
}

function SignPanel({
  myPrivateKey,
  myPrivateKeyPass,
  myPrivateKeyInfo,
  myPrivateKeyError,
  localKeys,
}: SignPanelProps) {
  const [plaintext, setPlaintext] = useState("");
  const [detached, setDetached] = useState(false);
  const [output, setOutput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSign = useCallback(async () => {
    setError(null);
    setOutput("");
    if (!plaintext.trim()) {
      setError("Enter the text you want to sign.");
      return;
    }
    if (!myPrivateKey.trim()) {
      setError("Provide your private key in the sidebar to sign.");
      return;
    }
    setBusy(true);
    try {
      const signed = await signMessage({
        plaintext,
        privateKey: myPrivateKey,
        passphrase: myPrivateKeyPass || undefined,
        detached,
      });
      setOutput(signed);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [plaintext, myPrivateKey, myPrivateKeyPass, detached]);

  return (
    <section className="space-y-4">
      <Card>
        <CardHeader
          title="Sign plain text"
          subtitle="Create a detached PGP signature or a cleartext-signed message."
        />
        <div className="space-y-4">
          <Field label="Plain text to sign">
            <Textarea
              value={plaintext}
              onChange={setPlaintext}
              placeholder="Paste the text you want to sign."
              rows={8}
            />
          </Field>

          <Field label="Signature format">
            <div className="flex gap-4 text-sm">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  checked={!detached}
                  onChange={() => setDetached(false)}
                  className="accent-amber-500"
                />
                <span>
                  <span className="font-medium">Cleartext signed</span>{" "}
                  <span className="text-neutral-500">(inline, human-readable)</span>
                </span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  checked={detached}
                  onChange={() => setDetached(true)}
                  className="accent-amber-500"
                />
                <span>
                  <span className="font-medium">Detached</span>{" "}
                  <span className="text-neutral-500">(separate signature block)</span>
                </span>
              </label>
            </div>
          </Field>

          <SignerStatus
            info={myPrivateKeyInfo}
            error={myPrivateKeyError}
            hasKey={!!myPrivateKey.trim()}
            localKeys={localKeys}
          />

          {error && <ErrorBanner message={error} />}

          <div className="flex flex-wrap gap-2">
            <Button onClick={handleSign} disabled={busy} variant="primary">
              {busy ? "Signing…" : "Sign message"}
            </Button>
            <Button
              onClick={() => {
                setPlaintext("");
                setOutput("");
                setError(null);
              }}
              variant="ghost"
            >
              Clear
            </Button>
          </div>
        </div>
      </Card>

      {output && (
        <Card>
          <CardHeader
            title={detached ? "Detached signature" : "Cleartext signed message"}
            subtitle="Share this with anyone who has your public key."
          />
          <Textarea value={output} readOnly rows={12} />
          <div className="mt-2 flex justify-end">
            <CopyButton text={output} />
          </div>
        </Card>
      )}
    </section>
  );
}

/* ---------------------------------- Verify --------------------------------- */

interface VerifyPanelProps {
  localKeys: LocalKey[];
  keybaseProxy: string;
}

function VerifyPanel({ localKeys, keybaseProxy }: VerifyPanelProps) {
  const [signerUsernames, setSignerUsernames] = useState("");
  const [pubKeys, setPubKeys] = useState<{ label: string; armored: string }[]>([]);
  const [armored, setArmored] = useState("");
  const [plaintext, setPlaintext] = useState("");
  const [detached, setDetached] = useState(false);
  const [result, setResult] = useState<{
    verified: "valid" | "invalid" | "unknown";
    signatures: { keyID: string; fingerprint?: string; verified: string; error?: string }[];
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [fetchingKeys, setFetchingKeys] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFetchKeys = useCallback(async () => {
    setError(null);
    const names = signerUsernames
      .split(/[\s,;]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (names.length === 0) {
      setError("Enter at least one Keybase username.");
      return;
    }
    setFetchingKeys(true);
    try {
      const r = await lookupKeybaseUsersClient(names, keybaseProxy);
      if (r.found.length === 0) {
        setError("No Keybase public keys found for the given usernames.");
      } else {
        setPubKeys(
          r.found.map((k) => ({ label: `@${k.username}`, armored: k.armored })),
        );
      }
      if (r.missing.length > 0) {
        setError(
          (prev) =>
            (prev ? prev + " " : "") +
            `No key found for: ${r.missing.join(", ")}.`,
        );
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setFetchingKeys(false);
    }
  }, [signerUsernames, keybaseProxy]);

  const handleVerify = useCallback(async () => {
    setError(null);
    setResult(null);
    if (!armored.trim()) {
      setError("Paste the signature (or cleartext-signed message) to verify.");
      return;
    }
    if (pubKeys.length === 0) {
      setError("Provide at least one signer public key (Keybase username).");
      return;
    }
    if (detached && !plaintext.trim()) {
      setError("For detached signatures, paste the original plaintext too.");
      return;
    }
    setBusy(true);
    try {
      const res = await verifyMessage({
        plaintext,
        armoredSignature: armored,
        publicKeys: pubKeys.map((k) => k.armored),
        detached,
      });
      setResult(res);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [armored, plaintext, detached, pubKeys]);

  return (
    <section className="space-y-4">
      <Card>
        <CardHeader
          title="Verify a signature"
          subtitle="Check that a signed message or detached signature was produced by the claimed Keybase identity."
        />
        <div className="space-y-4">
          <Field label="Signer Keybase usernames">
            <div className="flex gap-2">
              <input
                type="text"
                value={signerUsernames}
                onChange={(e) => setSignerUsernames(e.target.value)}
                placeholder="alice, bob"
                className="flex-1 rounded-md border border-neutral-800 bg-neutral-900 px-3 py-2 text-sm placeholder:text-neutral-600 focus:outline-none focus:ring-1 focus:ring-amber-500"
              />
              <Button
                onClick={handleFetchKeys}
                disabled={fetchingKeys}
                variant="ghost"
              >
                {fetchingKeys ? "Fetching…" : "Fetch keys"}
              </Button>
            </div>
            {pubKeys.length > 0 && (
              <ul className="mt-2 text-[11px] text-neutral-400 list-disc list-inside">
                {pubKeys.map((k, i) => (
                  <li key={i}>{k.label} · loaded</li>
                ))}
              </ul>
            )}
          </Field>

          <Field label="Signature format">
            <div className="flex gap-4 text-sm">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  checked={!detached}
                  onChange={() => setDetached(false)}
                  className="accent-amber-500"
                />
                <span>
                  <span className="font-medium">Cleartext signed</span>{" "}
                  <span className="text-neutral-500">(single block)</span>
                </span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  checked={detached}
                  onChange={() => setDetached(true)}
                  className="accent-amber-500"
                />
                <span>
                  <span className="font-medium">Detached</span>{" "}
                  <span className="text-neutral-500">(signature + original text)</span>
                </span>
              </label>
            </div>
          </Field>

          {detached && (
            <Field label="Original plaintext">
              <Textarea
                value={plaintext}
                onChange={setPlaintext}
                placeholder="Paste the original plaintext that was signed."
                rows={6}
              />
            </Field>
          )}

          <Field label={detached ? "Detached signature" : "Cleartext signed message"}>
            <Textarea
              value={armored}
              onChange={setArmored}
              placeholder={
                detached
                  ? "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----"
                  : "-----BEGIN PGP SIGNED MESSAGE-----\n...\n-----END PGP SIGNATURE-----"
              }
              rows={10}
            />
          </Field>

          {error && <ErrorBanner message={error} />}

          <div className="flex flex-wrap gap-2">
            <Button onClick={handleVerify} disabled={busy} variant="primary">
              {busy ? "Verifying…" : "Verify signature"}
            </Button>
            <Button
              onClick={() => {
                setArmored("");
                setPlaintext("");
                setResult(null);
                setError(null);
              }}
              variant="ghost"
            >
              Clear
            </Button>
          </div>
        </div>
      </Card>

      {result && (
        <Card>
          <CardHeader
            title="Verification result"
            subtitle={
              result.verified === "valid"
                ? "Signature is valid ✓"
                : result.verified === "invalid"
                  ? "Signature is invalid ✗"
                  : "Signature could not be verified (unknown signer key)"
            }
          />
          <SignatureTable signatures={result.signatures} />
        </Card>
      )}
    </section>
  );
}

/* ------------------------------- Keybase sidebar --------------------------- */

interface KeybaseSidebarProps {
  keybaseProxy: string;
  recipients: Recipient[];
  setRecipients: React.Dispatch<React.SetStateAction<Recipient[]>>;
}

function KeybaseSidebar({
  keybaseProxy,
  recipients,
  setRecipients,
}: KeybaseSidebarProps) {
  const [usernames, setUsernames] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<KeybasePublicKey[]>([]);
  const [missing, setMissing] = useState<string[]>([]);
  const [lastQuery, setLastQuery] = useState<string>("");

  const handleFetch = useCallback(async () => {
    setError(null);
    const names = usernames
      .split(/[\s,;\n]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (names.length === 0) {
      setError("Enter at least one Keybase username.");
      return;
    }
    setBusy(true);
    try {
      const r = await lookupKeybaseUsersClient(names, keybaseProxy);
      setResults(r.found);
      setMissing(r.missing);
      setLastQuery(names.join(", "));
      if (r.found.length === 0 && r.missing.length === 0) {
        setError("Keybase returned no results.");
      }
    } catch (e) {
      setError((e as Error).message);
      setResults([]);
      setMissing([]);
    } finally {
      setBusy(false);
    }
  }, [usernames, keybaseProxy]);

  const addRecipient = useCallback(
    (k: KeybasePublicKey) => {
      setRecipients((prev) => {
        if (prev.some((p) => p.fingerprint === k.fingerprint)) return prev;
        return [
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
        ];
      });
    },
    [setRecipients],
  );

  return (
    <Card>
      <CardHeader
        title="Keybase public keys"
        subtitle="Look up any Keybase user's public key by username."
        accent
      />
      <div className="space-y-3">
        <Field label="Usernames">
          <Textarea
            value={usernames}
            onChange={setUsernames}
            placeholder={"alice\nbob\nchris"}
            rows={3}
          />
          <p className="mt-1 text-[11px] text-neutral-500">
            Comma, space, or newline-separated. Keybase usernames only.
          </p>
        </Field>

        <Button onClick={handleFetch} disabled={busy} variant="primary" full>
          {busy ? "Looking up…" : "Look up public keys"}
        </Button>

        {error && <ErrorBanner message={error} />}

        {missing.length > 0 && (
          <div className="rounded-md border border-amber-700/40 bg-amber-950/30 p-2 text-[11px] text-amber-300">
            No public key found for: {missing.join(", ")}
          </div>
        )}

        {results.length > 0 && (
          <ul className="space-y-2 max-h-[28rem] overflow-y-auto pr-1">
            {results.map((k) => {
              const isAdded = recipients.some(
                (p) => p.fingerprint === k.fingerprint,
              );
              return (
                <li
                  key={k.fingerprint}
                  className="rounded-md border border-neutral-800 bg-neutral-900/60 p-3 space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-amber-400 text-sm">
                      @{k.username}
                    </span>
                    <button
                      onClick={() => addRecipient(k)}
                      disabled={isAdded}
                      className={`text-[11px] rounded px-2 py-0.5 ${
                        isAdded
                          ? "bg-neutral-800 text-neutral-500 cursor-not-allowed"
                          : "bg-amber-500 text-neutral-950 hover:bg-amber-400"
                      }`}
                    >
                      {isAdded ? "Added" : "+ Add recipient"}
                    </button>
                  </div>
                  <KeyMeta
                    fingerprint={k.fingerprint}
                    keyID={k.keyID}
                    algorithm={k.algorithm}
                    bits={k.bits}
                    curve={k.curve}
                    createdAt={k.createdAt}
                    expiresAt={k.expiresAt}
                  />
                  <details className="text-[11px] text-neutral-400">
                    <summary className="cursor-pointer hover:text-neutral-200">
                      Show armored public key
                    </summary>
                    <pre className="mt-1 max-h-40 overflow-auto rounded bg-neutral-950 p-2 whitespace-pre-wrap break-all">
                      {k.armored}
                    </pre>
                  </details>
                </li>
              );
            })}
          </ul>
        )}

        {results.length === 0 && !busy && !error && lastQuery === "" && (
          <p className="text-[11px] text-neutral-500">
            Example: try <code className="text-neutral-300">chris</code>,{" "}
            <code className="text-neutral-300">max</code>, or{" "}
            <code className="text-neutral-300">malgorithms</code> — these are
            well-known Keybase team accounts.
          </p>
        )}
      </div>
    </Card>
  );
}

/* --------------------------- My private key card --------------------------- */

interface MyPrivateKeyCardProps {
  myPrivateKey: string;
  setMyPrivateKey: (v: string) => void;
  myPrivateKeyPass: string;
  setMyPrivateKeyPass: (v: string) => void;
  myPrivateKeyInfo: AnyKeyInfo | null;
  myPrivateKeyError: string | null;
  localKeys: LocalKey[];
  onLoadLocalKey: (armored: string) => void;
}

function MyPrivateKeyCard({
  myPrivateKey,
  setMyPrivateKey,
  myPrivateKeyPass,
  setMyPrivateKeyPass,
  myPrivateKeyInfo,
  myPrivateKeyError,
  localKeys,
  onLoadLocalKey,
}: MyPrivateKeyCardProps) {
  const [showKey, setShowKey] = useState(false);
  return (
    <Card>
      <CardHeader
        title="Your private key"
        subtitle="Used for signing and decryption. Stays in your browser."
        accent
      />
      <div className="space-y-3">
        <Field label="Armored private key">
          <Textarea
            value={myPrivateKey}
            onChange={setMyPrivateKey}
            placeholder={"-----BEGIN PGP PRIVATE KEY BLOCK-----\n...\n-----END PGP PRIVATE KEY BLOCK-----"}
            rows={6}
            hidden={!showKey}
            onToggleHide={() => setShowKey((v) => !v)}
          />
          {localKeys.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {localKeys
                .filter((k) => k.isPrivate)
                .map((k) => (
                  <button
                    key={k.id}
                    onClick={() => onLoadLocalKey(k.armored)}
                    className="text-[11px] rounded px-2 py-0.5 bg-neutral-800 hover:bg-neutral-700 text-neutral-300"
                    title={k.info?.fingerprint}
                  >
                    Load "{k.label}"
                  </button>
                ))}
            </div>
          )}
        </Field>

        <Field label="Passphrase (optional)">
          <input
            type="password"
            value={myPrivateKeyPass}
            onChange={(e) => setMyPrivateKeyPass(e.target.value)}
            placeholder="If your private key is encrypted"
            className="w-full rounded-md border border-neutral-800 bg-neutral-900 px-3 py-2 text-sm placeholder:text-neutral-600 focus:outline-none focus:ring-1 focus:ring-amber-500"
          />
        </Field>

        {myPrivateKeyInfo && (
          <div className="rounded-md border border-emerald-700/40 bg-emerald-950/30 p-3 space-y-1.5">
            <div className="text-xs font-semibold text-emerald-400">
              ✓ Private key loaded
            </div>
            <KeyMeta
              fingerprint={myPrivateKeyInfo.fingerprint}
              keyID={myPrivateKeyInfo.keyID}
              algorithm={myPrivateKeyInfo.algorithm}
              bits={myPrivateKeyInfo.bitSize}
              curve={myPrivateKeyInfo.curve}
              createdAt={myPrivateKeyInfo.creationTime.getTime()}
              expiresAt={myPrivateKeyInfo.expirationTime?.getTime() ?? null}
            />
            <div className="text-[11px] text-neutral-400">
              {myPrivateKeyInfo.userIDs.map((u, i) => (
                <div key={i}>
                  {u.name && <span className="text-neutral-300">{u.name}</span>}
                  {u.email && <span className="text-neutral-500"> &lt;{u.email}&gt;</span>}
                </div>
              ))}
            </div>
          </div>
        )}

        {myPrivateKeyError && <ErrorBanner message={myPrivateKeyError} />}
      </div>
    </Card>
  );
}

/* ------------------------------ Local keys card ---------------------------- */

interface LocalKeysCardProps {
  localKeys: LocalKey[];
  setLocalKeys: (next: LocalKey[]) => void;
  showLocalKeys: boolean;
  setShowLocalKeys: (v: boolean) => void;
  onLoadAsSigner: (armored: string) => void;
  onAddAsRecipient: (r: Recipient) => void;
}

function LocalKeysCard({
  localKeys,
  setLocalKeys,
  showLocalKeys,
  setShowLocalKeys,
  onLoadAsSigner,
  onAddAsRecipient,
}: LocalKeysCardProps) {
  return (
    <Card>
      <button
        onClick={() => setShowLocalKeys(!showLocalKeys)}
        className="w-full flex items-center justify-between text-left"
      >
        <div>
          <div className="text-sm font-semibold text-neutral-200">
            Local keys (advanced)
          </div>
          <div className="text-[11px] text-neutral-500">
            Generate or paste keys you don't want to fetch from Keybase. Stored
            in your browser's localStorage.
          </div>
        </div>
        <span className="text-neutral-500 text-sm">
          {showLocalKeys ? "−" : "+"}
        </span>
      </button>

      {showLocalKeys && (
        <div className="mt-4 space-y-4">
          <GenerateKeyForm
            onGenerated={(kp) => {
              const priv: LocalKey = {
                id: crypto.randomUUID(),
                label: kp.info.userIDs[0]?.name ||
                  kp.info.userIDs[0]?.email ||
                  "Generated key",
                armored: kp.privateKey,
                isPrivate: true,
                info: kp.info,
                createdAt: Date.now(),
              };
              const pub: LocalKey = {
                id: crypto.randomUUID(),
                label: `${priv.label} (public)`,
                armored: kp.publicKey,
                isPrivate: false,
                // For a public-key-only entry we strip the private-only fields.
                info: {
                  armored: kp.info.armored,
                  fingerprint: kp.info.fingerprint,
                  keyID: kp.info.keyID,
                  userIDs: kp.info.userIDs,
                  creationTime: kp.info.creationTime,
                  expirationTime: kp.info.expirationTime,
                  algorithm: kp.info.algorithm,
                  bitSize: kp.info.bitSize,
                  curve: kp.info.curve,
                  isRevoked: kp.info.isRevoked,
                },
                createdAt: Date.now(),
              };
              setLocalKeys([...localKeys, priv, pub]);
            }}
          />

          <ImportKeyForm
            onImport={(label, armored, info, isPrivate) => {
              const k: LocalKey = {
                id: crypto.randomUUID(),
                label,
                armored,
                isPrivate,
                info,
                createdAt: Date.now(),
              };
              setLocalKeys([...localKeys, k]);
            }}
          />

          {localKeys.length > 0 && (
            <ul className="space-y-2 max-h-72 overflow-y-auto pr-1">
              {localKeys.map((k) => (
                <li
                  key={k.id}
                  className="rounded-md border border-neutral-800 bg-neutral-900/60 p-3 space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium text-neutral-200 truncate">
                      {k.label}
                    </span>
                    <span
                      className={`text-[10px] rounded px-1.5 py-0.5 ${
                        k.isPrivate
                          ? "bg-amber-950/60 text-amber-300 border border-amber-700/40"
                          : "bg-neutral-800 text-neutral-400 border border-neutral-700"
                      }`}
                    >
                      {k.isPrivate ? "private" : "public"}
                    </span>
                  </div>
                  {k.info && (
                    <KeyMeta
                      fingerprint={k.info.fingerprint}
                      keyID={k.info.keyID}
                      algorithm={k.info.algorithm}
                      bits={k.info.bitSize}
                      curve={k.info.curve}
                      createdAt={k.info.creationTime.getTime()}
                      expiresAt={k.info.expirationTime?.getTime() ?? null}
                    />
                  )}
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {k.isPrivate ? (
                      <button
                        onClick={() => onLoadAsSigner(k.armored)}
                        className="text-[11px] rounded px-2 py-0.5 bg-amber-500 text-neutral-950 hover:bg-amber-400"
                      >
                        Use as signer
                      </button>
                    ) : (
                      <button
                        onClick={() =>
                          k.info &&
                          onAddAsRecipient({
                            source: "local",
                            label: k.label,
                            armored: k.armored,
                            fingerprint: k.info.fingerprint,
                            keyID: k.info.keyID,
                            algorithm: k.info.algorithm,
                            expiresAt: k.info.expirationTime?.getTime() ?? null,
                          })
                        }
                        className="text-[11px] rounded px-2 py-0.5 bg-amber-500 text-neutral-950 hover:bg-amber-400"
                      >
                        Add as recipient
                      </button>
                    )}
                    <button
                      onClick={() => {
                        navigator.clipboard?.writeText(k.armored);
                      }}
                      className="text-[11px] rounded px-2 py-0.5 bg-neutral-800 hover:bg-neutral-700 text-neutral-300"
                    >
                      Copy
                    </button>
                    <button
                      onClick={() =>
                        setLocalKeys(localKeys.filter((x) => x.id !== k.id))
                      }
                      className="text-[11px] rounded px-2 py-0.5 bg-neutral-800 hover:bg-red-900 text-neutral-400 hover:text-red-300"
                    >
                      Delete
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}

          <p className="text-[10px] text-neutral-600">
            Local keys are stored only in this browser. Clearing site data will
            remove them permanently — export any keys you want to keep.
          </p>
        </div>
      )}
    </Card>
  );
}

/* --------------------------------- Sub-UI ---------------------------------- */

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-neutral-800 bg-neutral-900/40 p-4 sm:p-5 backdrop-blur">
      {children}
    </div>
  );
}

function CardHeader({
  title,
  subtitle,
  accent,
}: {
  title: string;
  subtitle?: string;
  accent?: boolean;
}) {
  return (
    <div className="mb-4">
      <h2
        className={`text-base font-semibold ${accent ? "text-amber-400" : "text-neutral-100"}`}
      >
        {title}
      </h2>
      {subtitle && (
        <p className="text-[12px] text-neutral-500 mt-0.5">{subtitle}</p>
      )}
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <label className="block text-xs font-medium text-neutral-400 uppercase tracking-wide">
        {label}
      </label>
      {children}
    </div>
  );
}

function Textarea({
  value,
  onChange,
  placeholder,
  rows,
  readOnly,
  hidden,
  onToggleHide,
}: {
  value: string;
  onChange?: (v: string) => void;
  placeholder?: string;
  rows?: number;
  readOnly?: boolean;
  hidden?: boolean;
  onToggleHide?: () => void;
}) {
  return (
    <div className="relative">
      <textarea
        value={value}
        onChange={onChange ? (e) => onChange(e.target.value) : undefined}
        placeholder={placeholder}
        rows={rows ?? 6}
        readOnly={readOnly}
        spellCheck={false}
        className={`w-full rounded-md border border-neutral-800 bg-neutral-950 px-3 py-2 text-xs leading-relaxed placeholder:text-neutral-600 focus:outline-none focus:ring-1 focus:ring-amber-500 ${
          hidden ? "text-transparent [caret-color:white] selection:bg-amber-500/40" : ""
        }`}
        style={hidden ? { WebkitTextSecurity: "disc" } as React.CSSProperties : undefined}
      />
      {onToggleHide && (
        <button
          type="button"
          onClick={onToggleHide}
          className="absolute top-2 right-2 text-[10px] text-neutral-400 hover:text-amber-400 bg-neutral-900/80 px-1.5 py-0.5 rounded"
        >
          {hidden ? "Show" : "Hide"}
        </button>
      )}
    </div>
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
    primary: "bg-amber-500 text-neutral-950 hover:bg-amber-400",
    ghost: "bg-transparent text-neutral-300 hover:bg-neutral-800",
    default: "bg-neutral-800 text-neutral-200 hover:bg-neutral-700",
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
    <div className="rounded-md border border-red-800/60 bg-red-950/40 px-3 py-2 text-xs text-red-300">
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
      className="text-[11px] rounded px-2 py-1 bg-neutral-800 hover:bg-neutral-700 text-neutral-300"
    >
      {copied ? "Copied!" : "Copy to clipboard"}
    </button>
  );
}

function KeyMeta({
  fingerprint,
  keyID,
  algorithm,
  bits,
  curve,
  createdAt,
  expiresAt,
}: {
  fingerprint: string;
  keyID: string;
  algorithm: string;
  bits?: number;
  curve?: string;
  createdAt: number;
  expiresAt: number | null;
}) {
  const expired = expiresAt !== null && expiresAt < Date.now();
  return (
    <div className="space-y-0.5 text-[11px] text-neutral-400 font-mono">
      <div>
        <span className="text-neutral-600">FP: </span>
        {formatFingerprint(fingerprint)}
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-0.5">
        <span>
          <span className="text-neutral-600">KeyID: </span>
          {keyID}
        </span>
        <span>
          <span className="text-neutral-600">Algo: </span>
          {algorithm}
          {bits ? ` ${bits}` : ""}
          {curve ? ` (${curve})` : ""}
        </span>
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-0.5">
        <span>
          <span className="text-neutral-600">Created: </span>
          {new Date(createdAt).toLocaleDateString()}
        </span>
        <span>
          <span className="text-neutral-600">Expires: </span>
          {expiresAt ? (
            <span className={expired ? "text-red-400" : ""}>
              {new Date(expiresAt).toLocaleDateString()}
              {expired ? " (expired)" : ""}
            </span>
          ) : (
            "never"
          )}
        </span>
      </div>
    </div>
  );
}

function RecipientList({
  recipients,
  onRemove,
}: {
  recipients: Recipient[];
  onRemove: (fingerprint: string) => void;
}) {
  if (recipients.length === 0) {
    return (
      <div className="rounded-md border border-dashed border-neutral-800 px-3 py-4 text-center text-xs text-neutral-500">
        No recipients yet. Add some from the Keybase panel on the right.
      </div>
    );
  }
  return (
    <ul className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
      {recipients.map((r) => (
        <li
          key={r.fingerprint}
          className="flex items-start justify-between gap-2 rounded-md border border-neutral-800 bg-neutral-900/60 px-2.5 py-1.5"
        >
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-amber-400 truncate">
                {r.label}
              </span>
              <span className="text-[10px] uppercase tracking-wide text-neutral-500">
                {r.source}
              </span>
            </div>
            <div className="text-[10px] text-neutral-500 font-mono truncate">
              {formatFingerprint(r.fingerprint)}
            </div>
          </div>
          <button
            onClick={() => onRemove(r.fingerprint)}
            className="text-[11px] text-neutral-500 hover:text-red-400"
            aria-label="Remove recipient"
          >
            ✕
          </button>
        </li>
      ))}
    </ul>
  );
}

function ManualRecipientForm({
  onAdd,
}: {
  onAdd: (r: Recipient) => void;
}) {
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
        setError(
          "You pasted a private key. Only public keys can be used as recipients.",
        );
        return;
      }
      onAdd({
        source: "local",
        label: v.info.userIDs[0]?.name ||
          v.info.userIDs[0]?.email ||
          "Pasted key",
        armored: armored.trim(),
        fingerprint: v.info.fingerprint,
        keyID: v.info.keyID,
        algorithm: v.info.algorithm,
        expiresAt: v.info.expirationTime?.getTime() ?? null,
      });
      setArmored("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [armored, onAdd]);

  return (
    <div className="mt-2 space-y-2">
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
  );
}

function SignerStatus({
  info,
  error,
  hasKey,
  localKeys,
  isPrivateForDecryption,
}: {
  info: AnyKeyInfo | null;
  error: string | null;
  hasKey: boolean;
  localKeys: LocalKey[];
  isPrivateForDecryption?: boolean;
}) {
  if (!hasKey) {
    return (
      <div className="rounded-md border border-neutral-700/50 bg-neutral-900/60 px-3 py-2 text-xs text-neutral-400">
        {isPrivateForDecryption
          ? "Provide your private key in the sidebar to decrypt."
          : "Provide your private key in the sidebar to sign."}
        {localKeys.filter((k) => k.isPrivate).length > 0 && (
          <> You have local private keys available in the sidebar.</>
        )}
      </div>
    );
  }
  if (info) {
    return (
      <div className="rounded-md border border-emerald-700/40 bg-emerald-950/30 px-3 py-2 text-xs text-emerald-300">
        ✓ Signing as: {info.userIDs[0]?.name || info.userIDs[0]?.email || "unknown"}
        <span className="text-neutral-500 ml-2 font-mono">
          {info.keyID}
        </span>
      </div>
    );
  }
  if (error) {
    return <ErrorBanner message={error} />;
  }
  return null;
}

function SignatureTable({
  signatures,
}: {
  signatures: { keyID: string; fingerprint?: string; verified: string; error?: string }[];
}) {
  if (signatures.length === 0) {
    return (
      <p className="text-xs text-neutral-500">
        No signature information was present in the message.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto rounded-md border border-neutral-800">
      <table className="w-full text-xs">
        <thead className="bg-neutral-900/80 text-neutral-400">
          <tr>
            <th className="text-left px-3 py-1.5 font-medium">Status</th>
            <th className="text-left px-3 py-1.5 font-medium">Key ID</th>
            <th className="text-left px-3 py-1.5 font-medium">Fingerprint</th>
            <th className="text-left px-3 py-1.5 font-medium">Notes</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-neutral-800">
          {signatures.map((s, i) => {
            const color =
              s.verified === "valid"
                ? "text-emerald-400"
                : s.verified === "invalid"
                  ? "text-red-400"
                  : "text-neutral-400";
            const label =
              s.verified === "valid"
                ? "✓ Valid"
                : s.verified === "invalid"
                  ? "✗ Invalid"
                  : "? Unknown";
            return (
              <tr key={i} className="bg-neutral-950/40">
                <td className={`px-3 py-1.5 font-medium ${color}`}>{label}</td>
                <td className="px-3 py-1.5 font-mono text-neutral-300">
                  {s.keyID || "—"}
                </td>
                <td className="px-3 py-1.5 font-mono text-neutral-400 text-[10px] break-all">
                  {s.fingerprint ? formatFingerprint(s.fingerprint) : "—"}
                </td>
                <td className="px-3 py-1.5 text-neutral-500">
                  {s.error ?? (s.verified === "unknown"
                    ? "Signer key not in verification set"
                    : "")}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function GenerateKeyForm({
  onGenerated,
}: {
  onGenerated: (kp: GeneratedKeyPair) => void;
}) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [pass, setPass] = useState("");
  const [type, setType] = useState<"ecc" | "rsa">("ecc");
  const [curve, setCurve] = useState<string>("ed25519");
  const [bits, setBits] = useState<2048 | 3072 | 4096>(4096);
  const [expiryDays, setExpiryDays] = useState<number>(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = useCallback(async () => {
    setError(null);
    setBusy(true);
    try {
      const kp = await generateKeyPair({
        name: name || undefined,
        email: email || undefined,
        passphrase: pass || undefined,
        type,
        curve: type === "ecc" ? (curve as never) : undefined,
        rsaBits: type === "rsa" ? bits : undefined,
        expirationSeconds: expiryDays > 0 ? expiryDays * 86400 : 0,
      });
      onGenerated(kp);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [name, email, pass, type, curve, bits, expiryDays, onGenerated]);

  return (
    <div className="space-y-2 rounded-md border border-neutral-800 bg-neutral-950/40 p-3">
      <div className="text-xs font-semibold text-neutral-300">
        Generate a new local key pair
      </div>
      <div className="grid grid-cols-2 gap-2">
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Full name"
          className="rounded-md border border-neutral-800 bg-neutral-900 px-2 py-1.5 text-xs"
        />
        <input
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="email@example.com"
          className="rounded-md border border-neutral-800 bg-neutral-900 px-2 py-1.5 text-xs"
        />
      </div>
      <input
        type="password"
        value={pass}
        onChange={(e) => setPass(e.target.value)}
        placeholder="Passphrase (optional, recommended)"
        className="w-full rounded-md border border-neutral-800 bg-neutral-900 px-2 py-1.5 text-xs"
      />
      <div className="grid grid-cols-2 gap-2 text-[11px]">
        <label className="flex flex-col gap-1">
          <span className="text-neutral-500">Type</span>
          <select
            value={type}
            onChange={(e) => setType(e.target.value as "ecc" | "rsa")}
            className="rounded-md border border-neutral-800 bg-neutral-900 px-2 py-1.5"
          >
            <option value="ecc">ECC (recommended)</option>
            <option value="rsa">RSA</option>
          </select>
        </label>
        {type === "ecc" ? (
          <label className="flex flex-col gap-1">
            <span className="text-neutral-500">Curve</span>
            <select
              value={curve}
              onChange={(e) => setCurve(e.target.value)}
              className="rounded-md border border-neutral-800 bg-neutral-900 px-2 py-1.5"
            >
              <option value="ed25519Legacy">ed25519 (default)</option>
              <option value="nistP256">NIST P-256</option>
              <option value="nistP384">NIST P-384</option>
              <option value="nistP521">NIST P-521</option>
              <option value="secp256k1">secp256k1</option>
            </select>
          </label>
        ) : (
          <label className="flex flex-col gap-1">
            <span className="text-neutral-500">Bits</span>
            <select
              value={bits}
              onChange={(e) =>
                setBits(Number(e.target.value) as 2048 | 3072 | 4096)
              }
              className="rounded-md border border-neutral-800 bg-neutral-900 px-2 py-1.5"
            >
              <option value={2048}>2048</option>
              <option value={3072}>3072</option>
              <option value={4096}>4096</option>
            </select>
          </label>
        )}
        <label className="flex flex-col gap-1 col-span-2">
          <span className="text-neutral-500">
            Expiration (days, 0 = never)
          </span>
          <input
            type="number"
            min={0}
            value={expiryDays}
            onChange={(e) => setExpiryDays(Number(e.target.value))}
            className="rounded-md border border-neutral-800 bg-neutral-900 px-2 py-1.5 text-xs"
          />
        </label>
      </div>
      {error && <ErrorBanner message={error} />}
      <Button onClick={handleGenerate} disabled={busy} variant="default" full>
        {busy ? "Generating…" : "Generate key pair"}
      </Button>
    </div>
  );
}

function ImportKeyForm({
  onImport,
}: {
  onImport: (
    label: string,
    armored: string,
    info: AnyKeyInfo,
    isPrivate: boolean,
  ) => void;
}) {
  const [label, setLabel] = useState("");
  const [armored, setArmored] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleImport = useCallback(async () => {
    setError(null);
    if (!armored.trim()) {
      setError("Paste an armored key.");
      return;
    }
    setBusy(true);
    try {
      const v = await validateArmoredKey(armored.trim());
      if (!v.ok || !v.info) {
        setError(v.error ?? "Invalid key.");
        return;
      }
      const isPrivate = "isPrivate" in v.info && v.info.isPrivate;
      onImport(
        label.trim() ||
          v.info.userIDs[0]?.name ||
          v.info.userIDs[0]?.email ||
          (isPrivate ? "Imported private key" : "Imported public key"),
        armored.trim(),
        v.info,
        isPrivate,
      );
      setArmored("");
      setLabel("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [armored, label, onImport]);

  return (
    <div className="space-y-2 rounded-md border border-neutral-800 bg-neutral-950/40 p-3">
      <div className="text-xs font-semibold text-neutral-300">
        Import an existing key
      </div>
      <input
        type="text"
        value={label}
        onChange={(e) => setLabel(e.target.value)}
        placeholder="Label (optional)"
        className="w-full rounded-md border border-neutral-800 bg-neutral-900 px-2 py-1.5 text-xs"
      />
      <Textarea
        value={armored}
        onChange={setArmored}
        placeholder={"-----BEGIN PGP PRIVATE KEY BLOCK-----\n... or PUBLIC KEY BLOCK ..."}
        rows={5}
      />
      {error && <ErrorBanner message={error} />}
      <Button onClick={handleImport} disabled={busy} variant="default" full>
        {busy ? "Validating…" : "Import key"}
      </Button>
    </div>
  );
}
