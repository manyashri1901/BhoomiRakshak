// lib/x509Keys.ts
//
// WebCrypto RSA key-pair plumbing shared by lib/ca.ts — @peculiar/x509
// signs and verifies using WebCrypto CryptoKey objects, not Node's
// crypto.generateKeyPairSync()/crypto.sign() PEM-string API the rest of
// this codebase otherwise uses. This file is the one place that bridges
// "generate/load an RSA key pair" into the shape @peculiar/x509 needs,
// mirroring the exact PEM-encoding approach frontend/src/lib/clientCrypto.ts
// already uses in the browser (same algorithm, same PKCS#8/SPKI framing),
// so a key pair generated here and one generated there are byte-for-byte
// interchangeable in format.
//
// Also registers the WebCrypto provider @peculiar/x509 uses on Node — see
// setX509CryptoProvider() — which must run before any other @peculiar/x509
// call in the process; lib/ca.ts imports this module first for that reason.

import "reflect-metadata";
import { webcrypto } from "node:crypto";
import * as x509 from "@peculiar/x509";

// @peculiar/x509 defaults to looking for a global `crypto.subtle`; on Node
// that object exists but isn't automatically wired in as x509's provider,
// so every process using this library must set it once, before any
// signing/verification call. Idempotent — safe to import this module from
// multiple places.
x509.cryptoProvider.set(webcrypto as unknown as Crypto);

export const RSA_SIGNING_ALGORITHM = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
} as const;

function bufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

function pemToDer(pem: string): ArrayBuffer {
  const base64 = pem.replace(/-----BEGIN [^-]+-----/, "").replace(/-----END [^-]+-----/, "").replace(/\s+/g, "");
  const buf = Buffer.from(base64, "base64");
  // Buffer.from(string, "base64") is small enough (an RSA-2048 key is well
  // under Node's 4KB pooling threshold) to come back as a VIEW into a
  // shared ~8KB pool slab, not its own allocation — buf.buffer is that
  // whole slab, not just this key's bytes, and buf.byteOffset is only 0
  // for the first key decoded from the pool. Returning buf.buffer directly
  // hands WebCrypto's DER parser someone else's bytes before the key's own
  // header (or trailing zeros), which importKey() rejects as malformed
  // ASN.1 ("header too long") — reproduces consistently once more than one
  // small Buffer has been decoded in the process. Slicing to this buffer's
  // own byteOffset/byteLength returns only its actual bytes.
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

function derToPem(der: ArrayBuffer, label: "PUBLIC KEY" | "PRIVATE KEY"): string {
  const base64 = bufferToBase64(der);
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

export interface RsaKeyPairPem {
  publicKey: string; // SPKI PEM
  privateKey: string; // PKCS#8 PEM
}

/** Generates a fresh RSA-2048 WebCrypto key pair and returns it both as
 * CryptoKeys (for immediate signing use) and as PEM (for persistence). */
export async function generateRsaKeyPairPem(): Promise<{ keyPair: CryptoKeyPair; pem: RsaKeyPairPem }> {
  const keyPair = (await webcrypto.subtle.generateKey(RSA_SIGNING_ALGORITHM, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const [publicDer, privateDer] = await Promise.all([
    webcrypto.subtle.exportKey("spki", keyPair.publicKey),
    webcrypto.subtle.exportKey("pkcs8", keyPair.privateKey),
  ]);
  return {
    keyPair,
    pem: {
      publicKey: derToPem(publicDer, "PUBLIC KEY"),
      privateKey: derToPem(privateDer, "PRIVATE KEY"),
    },
  };
}

/** Imports a PKCS#8 PEM private key as a signing CryptoKey. `extractable`
 * defaults to false — true only for the root key, which first-run may
 * need to re-export once more if regenerating is ever required. */
export async function importPrivateKeyPem(pem: string, extractable = false): Promise<CryptoKey> {
  return webcrypto.subtle.importKey("pkcs8", pemToDer(pem), RSA_SIGNING_ALGORITHM, extractable, ["sign"]);
}

/** Imports a SPKI PEM public key as a verify-only CryptoKey. */
export async function importPublicKeyPem(pem: string): Promise<CryptoKey> {
  return webcrypto.subtle.importKey("spki", pemToDer(pem), RSA_SIGNING_ALGORITHM, true, ["verify"]);
}
