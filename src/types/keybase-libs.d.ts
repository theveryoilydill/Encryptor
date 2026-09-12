/**
 * Minimal ambient type declarations for the CommonJS libraries we use for the
 * Keybase PDPKA login flow. These are not complete — they only describe the
 * surface area we touch.
 */

declare module "kbpgp" {
  export namespace kb {
    class KeyManager {
      static generate(
        opts: { seed: Uint8Array | Buffer; split?: boolean },
        cb: (err: Error | null, km: KeyManager) => void,
      ): void;
      make_sig_eng(): SigEng;
      export_public(opts: unknown, cb: (err: Error | null, kid: string) => void): void;
      get_pgp_fingerprint(): string;
    }
    interface SigEng {
      box: unknown;
      unbox: unknown;
    }
  }
}

declare module "keybase-proofs" {
  export class Auth {
    constructor(opts: {
      sig_eng: unknown;
      host: string;
      user: { local: Record<string, string> };
      nonce: Uint8Array | Buffer;
      session: string;
    });
    generate(
      cb: (err: Error | null, sig: { armored: string }) => void,
      opts?: { dohash?: boolean },
    ): void;
  }
}

declare module "keybase-proofs/lib/auth.js" {
  export class Auth {
    constructor(opts: {
      sig_eng: unknown;
      host: string;
      user: { local: Record<string, string> };
      nonce: Uint8Array | Buffer;
      session: string;
    });
    generate(
      cb: (err: Error | null, sig: { armored: string }) => void,
      opts?: { dohash?: boolean },
    ): void;
  }
}

declare module "triplesec" {
  export class Buffer {
    constructor(data: string, encoding: string);
    static from(data: string, encoding: string): Buffer;
    toString(encoding: string): string;
    slice(start: number, end?: number): Buffer;
    length: number;
  }
  export class Encryptor {
    constructor(opts: { key: Buffer; version?: number });
    set_key(key: Buffer): void;
    resalt(
      opts: {
        salt: Buffer;
        extra_keymaterial?: number;
        progress_hook?: (p: number) => void;
      },
      cb: (err: Error | null, keys: { extra: Buffer }) => void,
    ): void;
  }
  export function scrypt(opts: unknown, cb: (err: Error | null, result: unknown) => void): void;
}

/**
 * Ambient OpenPGP namespace so existing call sites can reference
 * `OpenPGP.PrivateKey` / `OpenPGP.PublicKey` / `OpenPGP.Key` as types
 * without an explicit `import * as OpenPGP from "openpgp"` at the top of
 * every file. The actual runtime values still come from the real openpgp
 * module imported by `@/lib/pgp/pgp`.
 */
declare namespace OpenPGP {
  type PrivateKey = import("openpgp").PrivateKey;
  type PublicKey = import("openpgp").PublicKey;
  type Key = import("openpgp").Key;
  type KeyID = import("openpgp").KeyID;
  type Signature = import("openpgp").Signature;
  type CleartextMessage = import("openpgp").CleartextMessage;
  type Message<T extends string | Uint8Array = string | Uint8Array> = import("openpgp").Message<T>;
}
