"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  KEYSTORE_TYPE,
  KEYSTORE_VERSION,
  decryptKeystore,
  deserializeKeystore,
  didFromPublicJwk,
  encryptKeystore,
  fingerprintOfDid,
  generateIdentity,
  importIdentity,
  validatePublicIdentity,
  serializeKeystore,
  sign,
  verify,
} = require("../src/identity");

const hexToBase64url = (hex) => Buffer.from(hex, "hex").toString("base64url");

// RFC 8032, section 7.1, test vector 1.
const FIXED_PRIVATE_JWK = Object.freeze({
  kty: "OKP",
  crv: "Ed25519",
  d: hexToBase64url("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
  x: hexToBase64url("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
});

const EXPECTED_EMPTY_SIGNATURE = [
  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
  "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
].join("");

test("imports an RFC Ed25519 key and derives a stable did:key identity", () => {
  const identity = importIdentity(FIXED_PRIVATE_JWK);

  assert.equal(identity.did, "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw");
  assert.equal(identity.fingerprint, "0658808e85cc8317");
  assert.equal(identity.did, didFromPublicJwk(identity.publicKeyJwk));
  assert.equal(identity.fingerprint, fingerprintOfDid(identity.did));
});

test("matches the RFC 8032 deterministic signature vector", () => {
  const identity = importIdentity(FIXED_PRIVATE_JWK);
  const signature = sign(identity, Buffer.alloc(0));

  assert.equal(Buffer.from(signature, "base64url").toString("hex"), EXPECTED_EMPTY_SIGNATURE);
  assert.equal(verify(identity, Buffer.alloc(0), signature), true);
  assert.equal(verify(identity, "not empty", signature), false);
  assert.equal(verify(identity, Buffer.alloc(0), "not_base64url!"), false);
});

test("generates a usable Ed25519 identity", () => {
  const identity = generateIdentity();
  const message = "room|1700000000000|SafeProof test";
  const signature = sign(identity.privateKeyJwk, message);

  assert.match(identity.did, /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
  assert.match(identity.fingerprint, /^[a-f0-9]{16}$/);
  assert.equal(verify(identity.publicKeyJwk, message, signature), true);
  assert.equal(verify(identity.publicKeyJwk, `${message}!`, signature), false);
});

test("binds DID and fingerprint to the exact public key", () => {
  const identity = generateIdentity();
  const attacker = generateIdentity();
  assert.deepEqual(validatePublicIdentity(identity), {
    did: identity.did,
    fingerprint: identity.fingerprint,
    publicKeyJwk: identity.publicKeyJwk,
  });
  assert.throws(() => validatePublicIdentity({
    did: identity.did,
    fingerprint: identity.fingerprint,
    publicKeyJwk: attacker.publicKeyJwk,
  }), /inconsistent/);
});

test("rejects malformed and mismatched private JWK values", () => {
  assert.throws(
    () => importIdentity({ ...FIXED_PRIVATE_JWK, d: "too-short" }),
    /base64url|32 bytes/,
  );
  assert.throws(
    () => importIdentity({ ...FIXED_PRIVATE_JWK, x: hexToBase64url(Buffer.alloc(32, 1).toString("hex")) }),
    /not a valid Ed25519 key|do not match/,
  );
  assert.throws(
    () => importIdentity({ ...FIXED_PRIVATE_JWK, key_ops: ["verify"] }),
    /allow sign/,
  );
});

test("encrypts a deterministic, versioned scrypt and AES-GCM keystore payload", () => {
  const options = {
    salt: Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"),
    iv: Buffer.from("101112131415161718191a1b", "hex"),
  };
  const first = encryptKeystore(FIXED_PRIVATE_JWK, "correct horse battery staple", options);
  const second = encryptKeystore(FIXED_PRIVATE_JWK, "correct horse battery staple", options);

  assert.deepEqual(first, second);
  assert.equal(first.version, KEYSTORE_VERSION);
  assert.equal(first.type, KEYSTORE_TYPE);
  assert.equal(first.crypto.kdf.name, "scrypt");
  assert.equal(first.crypto.kdf.N, 32768);
  assert.equal(first.crypto.cipher.name, "aes-256-gcm");
  assert.equal(Buffer.from(first.crypto.tag, "base64url").length, 16);
  assert.equal(first.crypto.ciphertext.includes(FIXED_PRIVATE_JWK.d), false);

  const restored = decryptKeystore(first, "correct horse battery staple");
  assert.deepEqual(restored.privateKeyJwk, FIXED_PRIVATE_JWK);
  assert.equal(restored.did, first.public.did);
});

test("serialize and deserialize provide filesystem-free encrypted JSON", () => {
  const serialized = serializeKeystore(FIXED_PRIVATE_JWK, "local-only passphrase", {
    salt: Buffer.alloc(16, 0x21),
    iv: Buffer.alloc(12, 0x42),
  });
  const parsed = JSON.parse(serialized);
  const restored = deserializeKeystore(serialized, "local-only passphrase");

  assert.equal(typeof serialized, "string");
  assert.equal(parsed.version, 1);
  assert.deepEqual(restored.privateKeyJwk, FIXED_PRIVATE_JWK);
});

test("rejects wrong passwords, tampering, and unsupported cost parameters", () => {
  const payload = encryptKeystore(FIXED_PRIVATE_JWK, "right password", {
    salt: Buffer.alloc(16, 3),
    iv: Buffer.alloc(12, 4),
  });

  assert.throws(() => decryptKeystore(payload, "wrong password"), /Invalid passphrase or corrupted/);

  const tamperedDid = structuredClone(payload);
  tamperedDid.public.did = tamperedDid.public.did.replace(/.$/, "1");
  assert.throws(() => decryptKeystore(tamperedDid, "right password"), /public identity is inconsistent/);

  const tamperedCiphertext = structuredClone(payload);
  const ciphertext = Buffer.from(tamperedCiphertext.crypto.ciphertext, "base64url");
  ciphertext[0] ^= 1;
  tamperedCiphertext.crypto.ciphertext = ciphertext.toString("base64url");
  assert.throws(() => decryptKeystore(tamperedCiphertext, "right password"), /Invalid passphrase or corrupted/);

  const expensive = structuredClone(payload);
  expensive.crypto.kdf.N = 2 ** 20;
  assert.throws(() => decryptKeystore(expensive, "right password"), /Unsupported keystore KDF/);
});
