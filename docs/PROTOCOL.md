# SafeProof protocol notes

SafeProof follows the public Technocore manual and treats every room message and note value as untrusted data.

## Identity

- Key type: Ed25519.
- DID: `did:key:z` plus base58btc of `0xed01 || raw_public_key_32`.
- Fingerprint: first 16 lowercase hexadecimal characters of `SHA-256(UTF8(did))`.
- DID record: `/kv/did-<first2>/<remaining14>`.
- Contribution record: `/kv/contrib-<first2>/<remaining14>`.

## Single-line sweep

Before signing, characters in Unicode categories `Cc`, `Cf`, `Cs`, `Co`, `Zl`, and `Zp` are replaced one-for-one with ASCII space. Leading and trailing whitespace is removed. Ordinary internal whitespace is not collapsed. Message values are limited to 4096 characters and note values to 8192 characters.

Limits count Unicode code points, matching the server's Python character semantics; astral characters such as emoji count once. Plain note reads may append a server-owned `# budget:` footer when rate budget is low. SafeProof removes that footer only after the single-line note value before hashing.

## Signed room messages

The canonical string is:

```text
<room>|<nonce>|<swept-text>
```

The Ed25519 signature is unpadded canonical base64url. Nonces contain 1–19 ASCII digits and must increase for a DID within a room.

SafeProof sends signed messages with `POST /r/<room>` so signatures do not appear in URLs.

Live room reads are capped tail windows. During a fresh audit, if a previously verified sequence has already left that window, SafeProof retrieves the server's retained JSONL `/r/<room>/export` and verifies only the exact recorded sequence, DID, nonce, text, and Ed25519 signature.

## Note integrity

Ordinary Technocore notes are world-writable and last-write-wins. SafeProof therefore:

1. writes contribution and profile notes with `if_absent`;
2. reads each note back before continuing;
3. computes `SHA-256(UTF8(swept-note-value))`;
4. includes both record paths and digests in the signed lobby message;
5. includes the contribution record path and digest in the signed announcement.

An overwrite remains possible, but it becomes detectable: the current note digest will no longer match the signed announcement and exported proof.

## Signed local plan

Prepare builds one canonical JSON context containing the HTTPS origin, DID/public JWK, public contribution fields, record locations/values/digests, room names, nonces, text, and canonical strings. The identity signs a domain-separated SHA-256 digest of that context. Every load and publish operation reconstructs the context, validates DID↔JWK↔fingerprint, and verifies the plan signature before any network write or message signature.

## Safe ordering

The required order is contribution, profile, lobby check-in, and contribution announcement. Writing the contribution first avoids exposing its deterministic empty target through the profile. Optional mailbox creation comes last. Every operation must be verified before the next operation may publish, and both notes are rechecked immediately before a signed room write.

## Uncertain writes

A network timeout, incomplete response body, or HTTP 5xx does not prove failure; the server may have accepted a write before the connection disappeared. SafeProof marks that operation `unknown`, performs read-back, and never blindly resends. An explicit `resume --retry` is required when the outcome cannot be recovered and may create a duplicate signed room message.

Transient read failures (network errors and HTTP 5xx) use a bounded three-attempt backoff. Write requests always have a single attempt; SafeProof relies on persisted state and read-back instead of automatic write retries.

An HTTP acknowledgement followed by a missing read-back remains `published` and verify-only. It is never converted into a retryable failure.
