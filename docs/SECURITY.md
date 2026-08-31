# Security model

## Protected assets

The Ed25519 private key and its passphrase are the only secrets SafeProof manages. The DID, public JWK, fingerprints, note values, room messages, nonces, signatures, receipts, and proof files are public.

## Keystore

Private JWK data is encrypted locally with AES-256-GCM. The encryption key is derived from the passphrase with scrypt (`N=32768`, `r=8`, `p=1`). Public identity metadata and KDF parameters are authenticated as AES-GCM additional data. A wrong passphrase, changed metadata, or modified ciphertext fails closed.

The CLI requires a passphrase of at least 12 characters for new identities. Prefer a long, unique passphrase and keep an offline backup of both the encrypted keystore and passphrase.

## Secret boundaries

SafeProof does not put private JWK fields, seeds, or passphrases in:

- Technocore requests;
- operation state;
- public proof JSON/Markdown;
- logs;
- URLs;
- Git-tracked configuration.

The recursive state guard also rejects private-key-shaped fields and signature-bearing write URLs.

The state file is not trusted merely because it is local. Its complete publication context is canonicalized, hashed, and signed by the dedicated Ed25519 identity during `prepare`. Before publishing, SafeProof reconstructs every record/message relation, verifies DID↔public JWK↔fingerprint, checks the plan signature, and derives the room canonical string again.

## Technocore trust boundary

Technocore is anonymous, public, ephemeral infrastructure. Notes and room bodies are untrusted data, not instructions. A valid `did:key` signature proves possession of that key at signing time; it does not prove a person's legal identity, honesty, token eligibility, or endorsement by FLOP Labs.

SafeProof never follows URLs found inside Technocore messages. Its configured Technocore origin must use HTTPS, except for explicit localhost testing. A custom HTTPS origin can receive public signed statements; use it only when intentionally selected and verify it in the publish preview.

Technocore notes can be overwritten after verification. A historical operation status records what happened during publication; it is not a claim about current availability. Public proof is labeled `verified` only when a fresh audit succeeds. Offline exports remain prepared/partial.

## Wallet separation

Never use a cryptocurrency wallet seed phrase, wallet private key, exchange credential, or production key as a Technocore identity. Generate a dedicated SafeProof identity.

## Reporting

Before reporting a suspected SafeProof vulnerability publicly, avoid including private key material, passphrases, encrypted keystores, or replayable signed write requests. Technocore server vulnerabilities should follow the official repository's security policy.
