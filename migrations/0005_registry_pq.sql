-- Encryptor key registry — quantum-seal public keys (0005)
-- # Mr. AI Acting on s183173's Behalf
--
-- Adds the OPTIONAL public half of the owner's ML-KEM-768 (FIPS 203)
-- quantum-seal pair. The secret half never leaves the owner's device; the
-- public half only ever ENCAPSULATES (seals) archive copies to this key.
-- Stored as base64 of the raw 1184-byte public key, validated server-side
-- on publish (src/lib/registry/keys.ts parsePqSealPk). NULL = the owner has
-- not published a quantum-seal pair (or published before this feature).

ALTER TABLE registry_keys ADD COLUMN pq_seal_pk TEXT;
