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
    constructor(opts: { key: Buffer });
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
