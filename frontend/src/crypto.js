// Client-side E2EE primitives. The server never sees private keys or
// plaintext. Both curves are P-256 because it's the one curve Web Crypto
// supports natively, with no flags, across every major browser.
//
// This is an MVP key-exchange (ECDH + AES-GCM), not a full Double
// Ratchet: messages aren't forward-secret across a session. Upgrading to
// a proper ratchet is tracked as follow-up work.

const IDENTITY_ALG = { name: "ECDSA", namedCurve: "P-256" };
const EXCHANGE_ALG = { name: "ECDH", namedCurve: "P-256" };

export async function generateIdentityKeyPair() {
  return crypto.subtle.generateKey(IDENTITY_ALG, true, ["sign", "verify"]);
}

export async function generateExchangeKeyPair() {
  return crypto.subtle.generateKey(EXCHANGE_ALG, true, ["deriveKey", "deriveBits"]);
}

export async function exportPublicKey(key) {
  const spki = await crypto.subtle.exportKey("spki", key);
  return toBase64Url(spki);
}

export async function importExchangePublicKey(b64url) {
  return crypto.subtle.importKey("spki", fromBase64Url(b64url), EXCHANGE_ALG, true, []);
}

// Must byte-for-byte match the backend's registration_payload() in
// auth.py -- this is what /register requires a valid identity_pub
// signature over, proving the caller controls the identity_pub it's
// publishing an exchange_pub for.
export function registrationPayload(identityPub, exchangePub, handle) {
  return `${identityPub}|${exchangePub}|${handle || ""}`;
}

export async function signChallenge(privateKey, challenge) {
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(challenge),
  );
  return toBase64Url(signature);
}

export async function deriveSharedKey(privateKey, publicKey) {
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: publicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptMessage(sharedKey, plaintext) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    sharedKey,
    new TextEncoder().encode(plaintext),
  );
  return { ciphertext: toBase64Url(ciphertext), nonce: toBase64Url(nonce) };
}

export async function decryptMessage(sharedKey, ciphertextB64, nonceB64) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64Url(nonceB64) },
    sharedKey,
    fromBase64Url(ciphertextB64),
  );
  return new TextDecoder().decode(plaintext);
}

// Short decimal fingerprint of a single public key, e.g. for display next
// to a contact's name. Not a security boundary on its own, see
// safetyNumber() for the mutual comparison that actually verifies a session.
export async function fingerprint(pubkeyB64url) {
  const digest = await crypto.subtle.digest("SHA-256", fromBase64Url(pubkeyB64url));
  return groupedDigits(digest, 4);
}

// A mutual, order-independent "safety number" for a pair of identity keys:
// an MVP stand-in for Signal-style SAS comparison. Both sides computing this
// over the same two keys and reading matching digits out-of-band (in person,
// on a call) rules out a relay-side machine-in-the-middle substituting keys.
export async function safetyNumber(pubkeyA, pubkeyB) {
  const [first, second] = [pubkeyA, pubkeyB].sort();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${first}|${second}`));
  return groupedDigits(digest, 6);
}

// Identity backup/restore: the only way an identity survives losing this
// browser's IndexedDB, or moves to another device. Private keys are
// exported as JWK, encrypted with a passphrase-derived AES-GCM key
// (PBKDF2-SHA256), and returned as a small JSON-serializable object the
// caller can save to a file. Losing the passphrase makes the backup
// useless; there is no recovery path around it by design, a recoverable
// passphrase would just be a weaker password on the account.
const BACKUP_PBKDF2_ITERATIONS = 250000;

export async function exportIdentityBackup(identity, passphrase) {
  const [identityPrivateJwk, exchangePrivateJwk] = await Promise.all([
    crypto.subtle.exportKey("jwk", identity.identityKeyPair.privateKey),
    crypto.subtle.exportKey("jwk", identity.exchangeKeyPair.privateKey),
  ]);
  const payload = new TextEncoder().encode(JSON.stringify({ identityPrivateJwk, exchangePrivateJwk }));

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveBackupKey(passphrase, salt, BACKUP_PBKDF2_ITERATIONS);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);

  return {
    version: 1,
    kdf: "PBKDF2-SHA256",
    iterations: BACKUP_PBKDF2_ITERATIONS,
    salt: toBase64Url(salt),
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext),
  };
}

export async function importIdentityBackup(backup, passphrase) {
  const salt = new Uint8Array(fromBase64Url(backup.salt));
  const iv = new Uint8Array(fromBase64Url(backup.iv));
  const key = await deriveBackupKey(passphrase, salt, backup.iterations);

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, fromBase64Url(backup.ciphertext));
  } catch {
    throw new Error("Incorrect passphrase, or the backup file is corrupted.");
  }

  const payload = JSON.parse(new TextDecoder().decode(plaintext));
  const [identityKeyPair, exchangeKeyPair] = await Promise.all([
    importKeyPairFromPrivateJwk(payload.identityPrivateJwk, IDENTITY_ALG, ["sign"]),
    importKeyPairFromPrivateJwk(payload.exchangePrivateJwk, EXCHANGE_ALG, ["deriveKey", "deriveBits"]),
  ]);

  const identityPub = await exportPublicKey(identityKeyPair.publicKey);
  const exchangePub = await exportPublicKey(exchangeKeyPair.publicKey);
  return { identityKeyPair, exchangeKeyPair, identityPub, exchangePub, fp: await fingerprint(identityPub) };
}

async function deriveBackupKey(passphrase, salt, iterations) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// A private JWK already carries the public coordinates (x, y) alongside the
// private scalar (d), so the public half of the pair can be reconstructed
// without a second export/import round trip.
async function importKeyPairFromPrivateJwk(privateJwk, alg, privateKeyUsages) {
  const privateKey = await crypto.subtle.importKey("jwk", privateJwk, alg, true, privateKeyUsages);
  // key_ops on the source JWK reflects the private key's own usages (e.g.
  // ["sign"]) and must not carry over: importKey rejects a JWK whose
  // embedded key_ops disagrees with the usages array being requested here.
  const { d: _d, key_ops: _keyOps, ...publicJwk } = privateJwk;
  const publicKeyUsages = alg.name === "ECDSA" ? ["verify"] : [];
  const publicKey = await crypto.subtle.importKey("jwk", publicJwk, alg, true, publicKeyUsages);
  return { privateKey, publicKey };
}

// Paper key: a high-entropy, server-independent recovery credential. Unlike
// the passphrase backup above (which needs the user to also keep the
// downloaded file), a paper key needs nothing but the string itself:
// restoring on a new device re-derives where the encrypted backup lives
// (recoveryIdForPaperKey) and fetches it from the relay. It's randomly
// generated, not user-chosen, precisely so it doesn't need file management:
// ~121 bits of entropy from an unambiguous alphabet (no 0/O/1/I) makes it
// both brute-force-resistant and legible to copy onto paper by hand.
const PAPER_KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function generatePaperKey(groups = 6, groupLength = 4) {
  const bytes = crypto.getRandomValues(new Uint8Array(groups * groupLength));
  const chars = Array.from(bytes, (b) => PAPER_KEY_ALPHABET[b % PAPER_KEY_ALPHABET.length]);
  const parts = [];
  for (let i = 0; i < groups; i++) {
    parts.push(chars.slice(i * groupLength, (i + 1) * groupLength).join(""));
  }
  return parts.join("-");
}

// Deterministic, one-way: the server only ever sees this hash, never the
// paper key it was derived from, it can't be reversed to find the key that
// unlocks the backup it points at.
export async function recoveryIdForPaperKey(paperKey) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`pubkeycc-recovery-v1:${paperKey}`));
  return toBase64Url(digest);
}

function groupedDigits(digestBuffer, groups) {
  const bytes = new Uint8Array(digestBuffer);
  const chunks = [];
  for (let i = 0; i < groups; i++) {
    const value = (bytes[i * 2] << 8) | bytes[i * 2 + 1];
    chunks.push(String(value % 100000).padStart(5, "0"));
  }
  return chunks.join(" ");
}

export function toBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(b64url) {
  const padded = b64url.replace(/-/g, "+").replace(/_/g, "/").padEnd(
    b64url.length + ((4 - (b64url.length % 4)) % 4),
    "=",
  );
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
