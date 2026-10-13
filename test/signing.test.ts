// test/signing.test.ts
//
// verifySignature / verifySignatureOverCanonicalString: true for a genuine
// signature, false for a tampered payload or the wrong key. Pure crypto —
// no database, no server.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { verifySignature, verifySignatureOverCanonicalString } from "../lib/signing.ts";

function generateKeyPair() {
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

test("verifySignature: true for a genuine signature over the exact payload", () => {
  const { publicKey, privateKey } = generateKeyPair();
  const payload = { landRecordId: "lr_1", documentHash: "a".repeat(64) };
  const canonical = JSON.stringify({ documentHash: payload.documentHash, landRecordId: payload.landRecordId });
  const signatureValue = crypto.sign("RSA-SHA256", Buffer.from(canonical, "utf8"), privateKey).toString("base64");
  assert.equal(verifySignature(publicKey, payload, signatureValue), true);
});

test("verifySignature: false when the payload is tampered after signing", () => {
  const { publicKey, privateKey } = generateKeyPair();
  const payload = { landRecordId: "lr_1", documentHash: "a".repeat(64) };
  const canonical = JSON.stringify({ documentHash: payload.documentHash, landRecordId: payload.landRecordId });
  const signatureValue = crypto.sign("RSA-SHA256", Buffer.from(canonical, "utf8"), privateKey).toString("base64");

  const tamperedPayload = { ...payload, documentHash: "b".repeat(64) };
  assert.equal(verifySignature(publicKey, tamperedPayload, signatureValue), false);
});

test("verifySignature: false when verified against the wrong public key", () => {
  const signer = generateKeyPair();
  const attacker = generateKeyPair();
  const payload = { landRecordId: "lr_1" };
  const canonical = JSON.stringify(payload);
  const signatureValue = crypto.sign("RSA-SHA256", Buffer.from(canonical, "utf8"), signer.privateKey).toString("base64");

  assert.equal(verifySignature(attacker.publicKey, payload, signatureValue), false);
});

test("verifySignature: never throws on a malformed signature, returns false", () => {
  const { publicKey } = generateKeyPair();
  assert.equal(verifySignature(publicKey, { a: 1 }, "not-valid-base64!!"), false);
});

test("verifySignatureOverCanonicalString: verifies an already-canonical string directly", () => {
  const { publicKey, privateKey } = generateKeyPair();
  const canonical = '{"a":1,"b":2}';
  const signatureValue = crypto.sign("RSA-SHA256", Buffer.from(canonical, "utf8"), privateKey).toString("base64");

  assert.equal(verifySignatureOverCanonicalString(publicKey, canonical, signatureValue), true);
  assert.equal(verifySignatureOverCanonicalString(publicKey, canonical + " ", signatureValue), false);
});
