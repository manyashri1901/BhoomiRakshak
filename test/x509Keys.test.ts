// test/x509Keys.test.ts
//
// Regression coverage for the "header too long" / Invalid keyData bug in
// lib/x509Keys.ts's pemToDer(): Buffer.from(base64String, "base64") is
// small enough (an RSA-2048 key is well under Node's ~4KB pool threshold)
// to come back as a VIEW into a shared pool slab rather than its own
// allocation, so `.buffer` alone is only correct for the very first such
// Buffer decoded in the process — every subsequent one has a nonzero
// byteOffset, and handing WebCrypto the whole slab instead of the slice
// means its DER parser starts reading someone else's bytes. This file
// proves the full generate -> export PEM -> persist -> read back -> import
// -> sign/verify round trip for every shape that round trip actually takes
// in this codebase: a file on disk, a *_BASE64 env var, CRLF line endings
// (Windows), and a PEM with no trailing newline — plus the root CA key
// specifically and an issuing CERTIFICATE (not a key) loaded the same way.

import "dotenv/config";
// Must precede the "@peculiar/x509" import below: its tsyringe dependency
// requires this polyfill at load time, not just before first use.
import "reflect-metadata";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { webcrypto } from "node:crypto";
import * as x509 from "@peculiar/x509";
import {
  RSA_SIGNING_ALGORITHM,
  generateRsaKeyPairPem,
  importPrivateKeyPem,
  importPublicKeyPem,
} from "../lib/x509Keys.ts";
import { ensureIssuingCA } from "../lib/ca.ts";

const SIGN_VERIFY_ALGORITHM = { name: "RSASSA-PKCS1-v1_5" };

async function signAndVerifyRoundTrip(privateKey: CryptoKey, publicKey: CryptoKey) {
  const message = Buffer.from("x509Keys round-trip test payload", "utf8");
  const signature = await webcrypto.subtle.sign(SIGN_VERIFY_ALGORITHM, privateKey, message);
  return webcrypto.subtle.verify(SIGN_VERIFY_ALGORITHM, publicKey, signature, message);
}

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "bhoomirakshak-x509keys-test-"));
}

test("generateRsaKeyPairPem -> write to a temp file -> read back -> importPrivateKeyPem -> sign/verify", async () => {
  const { keyPair, pem } = await generateRsaKeyPairPem();

  const dir = makeTempDir();
  const keyPath = path.join(dir, "private.pem");
  fs.writeFileSync(keyPath, pem.privateKey);
  const readBack = fs.readFileSync(keyPath, "utf8");

  const importedPrivateKey = await importPrivateKeyPem(readBack);
  const verified = await signAndVerifyRoundTrip(importedPrivateKey, keyPair.publicKey);
  assert.equal(verified, true);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("generateRsaKeyPairPem -> base64 (as a *_BASE64 env var would carry it) -> decode -> importPrivateKeyPem -> sign/verify", async () => {
  const { keyPair, pem } = await generateRsaKeyPairPem();

  const envStyleBase64 = Buffer.from(pem.privateKey, "utf8").toString("base64");
  const decoded = Buffer.from(envStyleBase64, "base64").toString("utf8");
  assert.equal(decoded, pem.privateKey);

  const importedPrivateKey = await importPrivateKeyPem(decoded);
  const verified = await signAndVerifyRoundTrip(importedPrivateKey, keyPair.publicKey);
  assert.equal(verified, true);
});

test("importPrivateKeyPem tolerates CRLF line endings (Windows-edited key file)", async () => {
  const { keyPair, pem } = await generateRsaKeyPairPem();
  const crlfPem = pem.privateKey.replace(/\n/g, "\r\n");

  const importedPrivateKey = await importPrivateKeyPem(crlfPem);
  const verified = await signAndVerifyRoundTrip(importedPrivateKey, keyPair.publicKey);
  assert.equal(verified, true);
});

test("importPrivateKeyPem tolerates a PEM with no trailing newline", async () => {
  const { keyPair, pem } = await generateRsaKeyPairPem();
  const noTrailingNewline = pem.privateKey.replace(/\n+$/, "");
  assert.ok(!noTrailingNewline.endsWith("\n"));

  const importedPrivateKey = await importPrivateKeyPem(noTrailingNewline);
  const verified = await signAndVerifyRoundTrip(importedPrivateKey, keyPair.publicKey);
  assert.equal(verified, true);
});

test("importPublicKeyPem round trip verifies a signature made by the matching private key", async () => {
  const { keyPair, pem } = await generateRsaKeyPairPem();
  const importedPublicKey = await importPublicKeyPem(pem.publicKey);

  const verified = await signAndVerifyRoundTrip(keyPair.privateKey, importedPublicKey);
  assert.equal(verified, true);
});

test("importPrivateKeyPem succeeds even after several other small base64 buffers were already decoded in this process (the exact pool-allocation condition that reproduced the original bug)", async () => {
  // Buffer.from(smallBase64String, "base64") is pool-allocated: byteOffset
  // is 0 only for the first such decode in the process. Deliberately
  // decode a few throwaway ones first so this test only passes if
  // pemToDer() correctly slices to its own buffer's range rather than
  // returning the whole shared pool slab.
  for (let i = 0; i < 5; i += 1) {
    Buffer.from("aGVsbG8gd29ybGQ=", "base64");
  }

  const { keyPair, pem } = await generateRsaKeyPairPem();
  const importedPrivateKey = await importPrivateKeyPem(pem.privateKey);
  const verified = await signAndVerifyRoundTrip(importedPrivateKey, keyPair.publicKey);
  assert.equal(verified, true);
});

test("root CA key: a self-signed root-style certificate's private key survives the same file round trip and can still sign", async () => {
  const { keyPair, pem } = await generateRsaKeyPairPem();

  const dir = makeTempDir();
  const keyPath = path.join(dir, "root-ca-private.pem");
  fs.writeFileSync(keyPath, pem.privateKey, { mode: 0o600 });

  const reloadedRootPrivateKey = await importPrivateKeyPem(fs.readFileSync(keyPath, "utf8"), true);

  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + 24 * 60 * 60 * 1000);
  const rootCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=Test Root CA Round Trip",
    notBefore,
    notAfter,
    signingAlgorithm: RSA_SIGNING_ALGORITHM,
    keys: { privateKey: reloadedRootPrivateKey, publicKey: keyPair.publicKey },
  });

  const selfVerified = await rootCert.verify({ publicKey: keyPair.publicKey, signatureOnly: true });
  assert.equal(selfVerified, true);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("issuing CERT load: the real Issuing CA certificate round-trips through base64 (as ISSUING_CA_CERT_BASE64 would carry it) and parses back to the same subject", async () => {
  const { issuingCert } = await ensureIssuingCA();

  const envStyleBase64 = Buffer.from(issuingCert.toString("pem"), "utf8").toString("base64");
  const decoded = Buffer.from(envStyleBase64, "base64").toString("utf8");

  const reparsed = new x509.X509Certificate(decoded);
  assert.equal(reparsed.subject, issuingCert.subject);
  assert.equal(reparsed.serialNumber, issuingCert.serialNumber);
});
