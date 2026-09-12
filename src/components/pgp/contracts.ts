/**
 * Shared contracts between PGP UI components (DRY).
 *
 * Every component in src/components/pgp builds against these types so that
 * parallel work streams compose without drift.
 */
import type { AnyKeyInfo } from "@/lib/pgp/pgp";
import type { EnvelopeFile } from "@/lib/pgp/envelope";
import type { KeySearchResult } from "@/lib/pgp/keybase";

/** Proxied Keybase/keys.openpgp.org endpoints on our own origin. */
export const PROXIES = {
  keybaseProxy: "/api/keybase",
  autocompleteProxy: "/api/keybase/autocomplete",
  searchAllProxy: "/api/keybase/search-all",
  fetchkeyProxy: "/api/keybase/fetchkey",
  fetchkeyOpgProxy: "/api/keybase/fetchkey-opg",
  getsaltProxy: "/api/keybase/getsalt",
  loginProxy: "/api/keybase/login",
} as const;

export type Tab = "encrypt" | "decrypt" | "sign" | "verify";

export interface Recipient {
  source: "keybase" | "local";
  username?: string;
  label: string;
  armored: string;
  fingerprint: string;
  keyID: string;
  algorithm: string;
  expiresAt: number | null;
}

export interface PrivateKeyConfig {
  source: "keybase" | "manual" | "generated";
  label: string;
  username?: string;
  /** For manual/generated sources: the ENCRYPTED armored private key.
   *  For keybase source: not used (the key is fetched on demand). */
  encryptedArmored?: string;
  /** Key metadata for display (fingerprint, key ID, algorithm). */
  info: AnyKeyInfo;
}

/** Rich signer info extracted from a verified signature. */
export interface SignatureInfo {
  keyID: string;
  fingerprint?: string;
  username?: string;
  verified: "valid" | "invalid" | "unknown";
  error?: string;
  name?: string;
  email?: string;
  comment?: string;
  userID?: string;
  allUserIDs?: string[];
  timestampIso?: string;
  /** True when the signature was verified against the user's own locally-
   *  configured key (the signer is "you"). */
  self?: boolean;
  /** Expiration of the signer's key as epoch-ms, when real data is
   *  available (R9: only locally-resolved verification records carry it —
   *  remote keyserver lookups don't return expiration, and it is never
   *  fabricated). null = the key is known to never expire; undefined =
   *  unknown. Drives the "Expired"/"Expires in N days" pill. */
  expiresAt?: number | null;
}

/** Shape returned by decryptAndAutoVerify / verifyAutoDetectWithKeyFetch. */
export interface VerificationResult {
  verified: "valid" | "invalid" | "unknown";
  signatures: SignatureInfo[];
}

/** Awaiting resolution of the private key at operation time. */
export interface KeyRequestState {
  resolve: (key: OpenPGP.PrivateKey) => void;
  reject: (reason?: Error) => void;
}

/** Public key record used for verification fetch callbacks. */
export interface VerificationKeyRecord {
  armored: string;
  keyID: string;
  fingerprint: string;
  username?: string;
  allKeyIDs?: string[];
  /** True when the record was resolved from the user's own locally-
   *  configured key rather than a remote keyserver. */
  self?: boolean;
  /** Expiration of the record's key as epoch-ms, when real data is
   *  available (R9: populated on the local-match path from the key already
   *  in hand; remote lookups leave it absent — never fabricated). */
  expiresAt?: number | null;
}

export type KeySearchResultType = KeySearchResult;

export type EnvelopeFileType = EnvelopeFile;
