"use strict";

const crypto = require("node:crypto");

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const DID_KEY_PREFIX = Buffer.from([0xed, 0x01]);
const KEYSTORE_TYPE = "safeproof-ed25519-keystore";
const KEYSTORE_VERSION = 1;
const SCRYPT_PARAMS = Object.freeze({ N: 32768, r: 8, p: 1, dkLen: 32 });
const SCRYPT_MAXMEM = 64 * 1024 * 1024;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const MAX_KEYSTORE_LENGTH = 64 * 1024;
const SELF_TEST_MESSAGE = Buffer.from("safeproof-ed25519-self-test-v1", "utf8");

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

function decodeBase64url(value, label, expectedLength) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} must be unpadded base64url.`);
  }

  const decoded = Buffer.from(value, "base64url");
  if (base64url(decoded) !== value) {
    throw new Error(`${label} must use canonical unpadded base64url.`);
  }
  if (expectedLength !== undefined && decoded.length !== expectedLength) {
    throw new Error(`${label} must decode to ${expectedLength} bytes.`);
  }
  return decoded;
}

function base58btcEncode(input) {
  const bytes = Buffer.from(input);
  let number = BigInt(`0x${bytes.toString("hex") || "0"}`);
  let encoded = "";

  while (number > 0n) {
    encoded = BASE58_ALPHABET[Number(number % 58n)] + encoded;
    number /= 58n;
  }

  for (const byte of bytes) {
    if (byte !== 0) break;
    encoded = BASE58_ALPHABET[0] + encoded;
  }

  return encoded || BASE58_ALPHABET[0];
}

function validatePublicJwk(value) {
  const jwk = value && value.publicKeyJwk ? value.publicKeyJwk : value;
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) {
    throw new Error("Public key must be an Ed25519 JWK object.");
  }
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new Error("Public key must use kty OKP and curve Ed25519.");
  }
  if (jwk.alg !== undefined && jwk.alg !== "Ed25519" && jwk.alg !== "EdDSA") {
    throw new Error("Public key JWK has an unsupported algorithm.");
  }
  if (jwk.use !== undefined && jwk.use !== "sig") {
    throw new Error("Public key JWK must be a signing key.");
  }
  if (jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops) || !jwk.key_ops.includes("verify"))) {
    throw new Error("Public key JWK key_ops must allow verify.");
  }

  decodeBase64url(jwk.x, "Public key x", 32);
  return { kty: "OKP", crv: "Ed25519", x: jwk.x };
}

function validatePrivateJwk(value) {
  const jwk = value && value.privateKeyJwk ? value.privateKeyJwk : value;
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) {
    throw new Error("Private key must be an Ed25519 JWK object.");
  }
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new Error("Private key must use kty OKP and curve Ed25519.");
  }
  if (jwk.alg !== undefined && jwk.alg !== "Ed25519" && jwk.alg !== "EdDSA") {
    throw new Error("Private key JWK has an unsupported algorithm.");
  }
  if (jwk.use !== undefined && jwk.use !== "sig") {
    throw new Error("Private key JWK must be a signing key.");
  }
  if (jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops) || !jwk.key_ops.includes("sign"))) {
    throw new Error("Private key JWK key_ops must allow sign.");
  }

  decodeBase64url(jwk.x, "Private key x", 32);
  decodeBase64url(jwk.d, "Private key d", 32);
  return { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d };
}

function didFromPublicJwk(value) {
  const publicKeyJwk = validatePublicJwk(value);
  const rawPublicKey = decodeBase64url(publicKeyJwk.x, "Public key x", 32);
  return `did:key:z${base58btcEncode(Buffer.concat([DID_KEY_PREFIX, rawPublicKey]))}`;
}

function fingerprintOfDid(did) {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) {
    throw new Error("DID must be a did:key value.");
  }
  return crypto.createHash("sha256").update(did, "utf8").digest("hex").slice(0, 16);
}

function validatePublicIdentity(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Identity must be an object.");
  }
  const publicKeyJwk = validatePublicJwk(value.publicKeyJwk);
  const did = didFromPublicJwk(publicKeyJwk);
  const fingerprint = fingerprintOfDid(did);
  if (value.did !== did || value.fingerprint !== fingerprint) {
    throw new Error("DID, fingerprint, and public key are inconsistent.");
  }
  return { did, fingerprint, publicKeyJwk };
}

function identityFromPrivateJwk(value) {
  const privateKeyJwk = validatePrivateJwk(value);
  let privateKey;
  let derivedPublicJwk;

  try {
    privateKey = crypto.createPrivateKey({ key: privateKeyJwk, format: "jwk" });
    derivedPublicJwk = crypto.createPublicKey(privateKey).export({ format: "jwk" });
  } catch {
    throw new Error("Private key JWK is not a valid Ed25519 key.");
  }

  const suppliedX = decodeBase64url(privateKeyJwk.x, "Private key x", 32);
  const derivedX = decodeBase64url(derivedPublicJwk.x, "Derived public key x", 32);
  if (!crypto.timingSafeEqual(suppliedX, derivedX)) {
    throw new Error("Private key JWK x and d values do not match.");
  }

  const publicKeyJwk = validatePublicJwk(derivedPublicJwk);
  const publicKey = crypto.createPublicKey({ key: publicKeyJwk, format: "jwk" });
  const selfTestSignature = crypto.sign(null, SELF_TEST_MESSAGE, privateKey);
  if (!crypto.verify(null, SELF_TEST_MESSAGE, publicKey, selfTestSignature)) {
    throw new Error("Ed25519 key self-test failed.");
  }

  const did = didFromPublicJwk(publicKeyJwk);
  return {
    did,
    fingerprint: fingerprintOfDid(did),
    publicKeyJwk,
    privateKeyJwk,
  };
}

function generateIdentity() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  return identityFromPrivateJwk(privateKey.export({ format: "jwk" }));
}

function importIdentity(privateKeyJwk) {
  return identityFromPrivateJwk(privateKeyJwk);
}

function messageBytes(message) {
  if (typeof message === "string") return Buffer.from(message, "utf8");
  if (Buffer.isBuffer(message) || ArrayBuffer.isView(message)) return Buffer.from(message);
  if (message instanceof ArrayBuffer) return Buffer.from(message);
  throw new TypeError("Message must be a string, Buffer, ArrayBuffer, or typed array.");
}

function sign(privateKey, message) {
  const privateKeyJwk = validatePrivateJwk(privateKey);
  const keyObject = crypto.createPrivateKey({ key: privateKeyJwk, format: "jwk" });
  return base64url(crypto.sign(null, messageBytes(message), keyObject));
}

function verify(publicKey, message, signature) {
  const publicKeyJwk = validatePublicJwk(publicKey);
  let signatureBytes;
  try {
    signatureBytes = decodeBase64url(signature, "Signature", 64);
  } catch {
    return false;
  }

  const keyObject = crypto.createPublicKey({ key: publicKeyJwk, format: "jwk" });
  return crypto.verify(null, messageBytes(message), keyObject, signatureBytes);
}

function requirePassphrase(passphrase) {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("Passphrase must be a non-empty string.");
  }
  return Buffer.from(passphrase, "utf8");
}

function optionBytes(value, label, length) {
  if (value === undefined) return crypto.randomBytes(length);
  const bytes = Buffer.from(value);
  if (bytes.length !== length) throw new Error(`${label} must be ${length} bytes.`);
  return bytes;
}

function publicMetadata(identity) {
  return {
    did: identity.did,
    fingerprint: identity.fingerprint,
    publicKeyJwk: identity.publicKeyJwk,
  };
}

function authenticatedHeader(payload) {
  return Buffer.from(JSON.stringify({
    version: payload.version,
    type: payload.type,
    public: {
      did: payload.public.did,
      fingerprint: payload.public.fingerprint,
      publicKeyJwk: {
        kty: payload.public.publicKeyJwk.kty,
        crv: payload.public.publicKeyJwk.crv,
        x: payload.public.publicKeyJwk.x,
      },
    },
    crypto: {
      kdf: {
        name: payload.crypto.kdf.name,
        salt: payload.crypto.kdf.salt,
        N: payload.crypto.kdf.N,
        r: payload.crypto.kdf.r,
        p: payload.crypto.kdf.p,
        dkLen: payload.crypto.kdf.dkLen,
      },
      cipher: {
        name: payload.crypto.cipher.name,
        iv: payload.crypto.cipher.iv,
      },
    },
  }), "utf8");
}

function encryptKeystore(privateKey, passphrase, options = {}) {
  const identity = identityFromPrivateJwk(privateKey);
  const salt = optionBytes(options.salt, "Scrypt salt", SALT_LENGTH);
  const iv = optionBytes(options.iv, "AES-GCM IV", IV_LENGTH);
  const passphraseBytes = requirePassphrase(passphrase);
  const derivedKey = crypto.scryptSync(passphraseBytes, salt, SCRYPT_PARAMS.dkLen, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
    maxmem: SCRYPT_MAXMEM,
  });
  const plaintext = Buffer.from(JSON.stringify({ privateKeyJwk: identity.privateKeyJwk }), "utf8");

  const payload = {
    version: KEYSTORE_VERSION,
    type: KEYSTORE_TYPE,
    public: publicMetadata(identity),
    crypto: {
      kdf: {
        name: "scrypt",
        salt: base64url(salt),
        N: SCRYPT_PARAMS.N,
        r: SCRYPT_PARAMS.r,
        p: SCRYPT_PARAMS.p,
        dkLen: SCRYPT_PARAMS.dkLen,
      },
      cipher: {
        name: "aes-256-gcm",
        iv: base64url(iv),
      },
      ciphertext: "",
      tag: "",
    },
  };

  try {
    const cipher = crypto.createCipheriv("aes-256-gcm", derivedKey, iv, { authTagLength: TAG_LENGTH });
    cipher.setAAD(authenticatedHeader(payload));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    payload.crypto.ciphertext = base64url(ciphertext);
    payload.crypto.tag = base64url(cipher.getAuthTag());
    return payload;
  } finally {
    passphraseBytes.fill(0);
    derivedKey.fill(0);
    plaintext.fill(0);
  }
}

function parseKeystore(payload) {
  let parsed = payload;
  if (typeof payload === "string") {
    if (Buffer.byteLength(payload, "utf8") > MAX_KEYSTORE_LENGTH) {
      throw new Error("Keystore payload is too large.");
    }
    try {
      parsed = JSON.parse(payload);
    } catch {
      throw new Error("Keystore is not valid JSON.");
    }
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Keystore must be a JSON object.");
  }
  if (parsed.version !== KEYSTORE_VERSION || parsed.type !== KEYSTORE_TYPE) {
    throw new Error("Unsupported keystore type or version.");
  }
  if (!parsed.public || !parsed.crypto || !parsed.crypto.kdf || !parsed.crypto.cipher) {
    throw new Error("Keystore payload is incomplete.");
  }

  const kdf = parsed.crypto.kdf;
  const cipher = parsed.crypto.cipher;
  if (
    kdf.name !== "scrypt" ||
    kdf.N !== SCRYPT_PARAMS.N ||
    kdf.r !== SCRYPT_PARAMS.r ||
    kdf.p !== SCRYPT_PARAMS.p ||
    kdf.dkLen !== SCRYPT_PARAMS.dkLen
  ) {
    throw new Error("Unsupported keystore KDF parameters.");
  }
  if (cipher.name !== "aes-256-gcm") {
    throw new Error("Unsupported keystore cipher.");
  }
  if (
    typeof parsed.crypto.ciphertext !== "string" ||
    parsed.crypto.ciphertext.length > MAX_KEYSTORE_LENGTH
  ) {
    throw new Error("Keystore ciphertext is invalid or too large.");
  }

  const publicKeyJwk = validatePublicJwk(parsed.public.publicKeyJwk);
  const expectedDid = didFromPublicJwk(publicKeyJwk);
  if (parsed.public.did !== expectedDid || parsed.public.fingerprint !== fingerprintOfDid(expectedDid)) {
    throw new Error("Keystore public identity is inconsistent.");
  }

  decodeBase64url(kdf.salt, "Scrypt salt", SALT_LENGTH);
  decodeBase64url(cipher.iv, "AES-GCM IV", IV_LENGTH);
  decodeBase64url(parsed.crypto.ciphertext, "Ciphertext");
  decodeBase64url(parsed.crypto.tag, "Authentication tag", TAG_LENGTH);
  return parsed;
}

function decryptKeystore(payload, passphrase) {
  const parsed = parseKeystore(payload);
  const passphraseBytes = requirePassphrase(passphrase);
  const salt = decodeBase64url(parsed.crypto.kdf.salt, "Scrypt salt", SALT_LENGTH);
  const iv = decodeBase64url(parsed.crypto.cipher.iv, "AES-GCM IV", IV_LENGTH);
  const tag = decodeBase64url(parsed.crypto.tag, "Authentication tag", TAG_LENGTH);
  const ciphertext = decodeBase64url(parsed.crypto.ciphertext, "Ciphertext");
  const derivedKey = crypto.scryptSync(passphraseBytes, salt, SCRYPT_PARAMS.dkLen, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
    maxmem: SCRYPT_MAXMEM,
  });
  let plaintext;

  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", derivedKey, iv, { authTagLength: TAG_LENGTH });
    decipher.setAAD(authenticatedHeader(parsed));
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error("Invalid passphrase or corrupted keystore.");
  } finally {
    passphraseBytes.fill(0);
    derivedKey.fill(0);
  }

  try {
    if (plaintext.length > MAX_KEYSTORE_LENGTH) throw new Error("Decrypted keystore is too large.");
    const secret = JSON.parse(plaintext.toString("utf8"));
    const identity = identityFromPrivateJwk(secret.privateKeyJwk);
    if (
      identity.did !== parsed.public.did ||
      identity.fingerprint !== parsed.public.fingerprint ||
      identity.publicKeyJwk.x !== parsed.public.publicKeyJwk.x
    ) {
      throw new Error("Decrypted key does not match the keystore identity.");
    }
    return identity;
  } catch (error) {
    if (error.message === "Decrypted key does not match the keystore identity.") throw error;
    throw new Error("Keystore contains invalid private key data.");
  } finally {
    plaintext.fill(0);
  }
}

function serializeKeystore(privateKey, passphrase, options) {
  return `${JSON.stringify(encryptKeystore(privateKey, passphrase, options), null, 2)}\n`;
}

function deserializeKeystore(serialized, passphrase) {
  return decryptKeystore(serialized, passphrase);
}

module.exports = {
  KEYSTORE_TYPE,
  KEYSTORE_VERSION,
  decryptKeystore,
  deserializeKeystore,
  didFromPublicJwk,
  encryptKeystore,
  fingerprintOfDid,
  generateIdentity,
  importIdentity,
  serializeKeystore,
  sign,
  validatePrivateJwk,
  validatePublicIdentity,
  validatePublicJwk,
  verify,
};
