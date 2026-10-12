// lib/clientCrypto.ts
//
// All client-side PKI key handling for BhoomiRakshak. The server never
// sees or stores a usable private key — every Landowner/Village Officer/
// Registrar generates their own RSA-2048 key pair here, in the browser,
// and the private key only ever exists in memory as a CryptoKey, for as
// long as a single sign operation takes.
//
// Algorithm: RSASSA-PKCS1-v1_5, 2048-bit modulus, SHA-256 — the Web Crypto
// name for exactly the "RSA-SHA256" scheme Node's crypto.sign/verify use
// server-side (lib/signing.ts, lib/ca.ts), so a signature produced here
// verifies there with no translation step.
//
// Storage: the private key is wrapped with AES-256-GCM, whose key is
// derived from the user's password via PBKDF2-SHA256 (600,000 iterations,
// a random salt). Only the wrapped blob (ciphertext + salt + iv) — never
// the password, never the raw key — goes to the server, which returns it
// at login so the browser can unwrap it again. Wrong password -> GCM's
// authentication tag fails to verify -> decrypt throws, with nothing
// partially decrypted to leak.

const RSA_ALGORITHM = {
  name: "RSASSA-PKCS1-v1_5",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
} as const;

const PBKDF2_ITERATIONS = 600_000;
const AES_KEY_LENGTH = 256;

function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  // Chunked to stay well under the argument-count limits some engines
  // place on String.fromCharCode(...spread) for very large arrays; a
  // 2048-bit RSA key's DER encoding is a few KB at most, but this is cheap
  // insurance either way.
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

function base64ToBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Generates a fresh RSA-2048 key pair. Extractable, because the private
 * key must be exported once (to wrap it) immediately after generation —
 * it is never extractable again after that point (see unwrapPrivateKey). */
export async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(RSA_ALGORITHM, true, ["sign", "verify"]) as Promise<CryptoKeyPair>;
}

/** Exports a public key as SPKI PEM — the same format Node's
 * crypto.generateKeyPairSync({publicKeyEncoding:{type:"spki",format:"pem"}})
 * produces server-side, so the two are interchangeable. */
export async function exportPublicKeySpkiPem(publicKey: CryptoKey): Promise<string> {
  const der = await crypto.subtle.exportKey("spki", publicKey);
  const base64 = bufferToBase64(der);
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

/** SHA-256 of the exact PEM string's UTF-8 bytes — must match
 * lib/ca.ts's `crypto.createHash("sha256").update(user.publicKey, "utf8")`,
 * which hashes the public key string exactly as received, not the raw DER. */
export async function fingerprintOfPem(pem: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pem));
  return bufferToHex(digest);
}

export interface WrappedKeyBlob {
  ciphertext: string; // base64
  salt: string; // base64
  iv: string; // base64
}

async function deriveWrappingKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    passwordKey,
    { name: "AES-GCM", length: AES_KEY_LENGTH },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Exports the private key (PKCS#8), encrypts it with AES-256-GCM under a
 * key derived from `password`, and returns only the wrapped blob — the raw
 * exported key bytes are not retained after this call returns. */
export async function wrapPrivateKey(
  privateKey: CryptoKey,
  password: string,
): Promise<WrappedKeyBlob> {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await deriveWrappingKey(password, salt);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrappingKey, pkcs8);

  return {
    ciphertext: bufferToBase64(ciphertext),
    salt: bufferToBase64(salt.buffer),
    iv: bufferToBase64(iv.buffer),
  };
}

export class WrongPasswordError extends Error {
  constructor() {
    super("Incorrect password — could not unlock your signing key.");
    this.name = "WrongPasswordError";
  }
}

/** Unwraps a stored key blob into a NON-extractable signing-only CryptoKey.
 * A wrong password makes AES-GCM's authentication tag fail to verify,
 * which throws here — there is no partial/garbage key to accidentally use. */
export async function unwrapPrivateKey(
  wrapped: WrappedKeyBlob,
  password: string,
): Promise<CryptoKey> {
  const salt = new Uint8Array(base64ToBuffer(wrapped.salt));
  const iv = new Uint8Array(base64ToBuffer(wrapped.iv));
  const wrappingKey = await deriveWrappingKey(password, salt);

  let pkcs8: ArrayBuffer;
  try {
    pkcs8 = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      wrappingKey,
      base64ToBuffer(wrapped.ciphertext),
    );
  } catch {
    throw new WrongPasswordError();
  }

  return crypto.subtle.importKey("pkcs8", pkcs8, RSA_ALGORITHM, false, ["sign"]);
}

/** Signs the exact UTF-8 bytes of `canonicalPayload` — no re-serialization,
 * no re-canonicalization. Used both for the prepare -> sign -> submit flow
 * (the server sends back the exact string it wants signed) and for the
 * registration proof (built from canonicalStringify() directly, see
 * lib/canonicalize.ts). */
export async function signCanonicalString(
  privateKey: CryptoKey,
  canonicalPayload: string,
): Promise<string> {
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    privateKey,
    new TextEncoder().encode(canonicalPayload),
  );
  return bufferToBase64(signature);
}
