-- Encryptor key registry — encrypted private key escrow (0003)
-- # Mr. AI Acting on s183173's Behalf
--
-- Adds OPTIONAL encrypted private key escrow to the registry. The
-- encrypted_private column stores an ASCII-armored private key whose
-- secret packets are ALL passphrase-encrypted (enforced server-side in
-- src/lib/registry/keys.ts — any decrypted packet is rejected before it
-- can reach the database, so this column never holds usable key bytes).
-- Security of the escrow rests on the owner's passphrase strength and
-- OpenPGP's iterated S2K, exactly like an offline .asc backup.

ALTER TABLE registry_keys ADD COLUMN encrypted_private TEXT;
ALTER TABLE registry_keys ADD COLUMN private_updated_at INTEGER;
