// test/timestamp.test.ts
//
// Deterministic unit tests for lib/timestamp.ts's verifyAnchor() — no
// network calls (unlike scripts/test-timestamp-live.ts, which exercises a
// real TSA). Builds its own in-process "fake TSA" with pkijs: a self-signed
// test certificate carrying the timeStamping EKU, used to sign real CMS
// SignedData / TSTInfo tokens by hand, the same shapes a genuine TSA
// response contains. Every test here only exercises steps 1-6 of
// verifyAnchor() (tokenParses / messageImprint / cmsSignature /
// tsaCertificate / nonce / genTime) — it never asserts on the overall
// `status` or on steps 7-8 (entryIntact/chainIntact), which need a real
// AuditLog row and are covered instead by
// scripts/test-audit-anchor-tamper.ts against the real database.
//
// "Trusted" and "untrusted" below refer only to whether this file put that
// test certificate's own PEM into TSA_CA_CERT_BASE64 before the test ran —
// lib/timestamp.ts's trustedRootCertificates() reads that env var fresh on
// every call, so this file can set it once at import time and never has to
// juggle it per test.

import "dotenv/config";
// Must precede the "@peculiar/x509" import below: its tsyringe dependency
// requires this polyfill at load time, not just before first use.
import "reflect-metadata";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { webcrypto } from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import * as x509 from "@peculiar/x509";
import { RSA_SIGNING_ALGORITHM } from "../lib/x509Keys.ts";
import { verifyAnchor, type AnchorCheckStep } from "../lib/timestamp.ts";

const TIMESTAMPING_EKU_OID = "1.3.6.1.5.5.7.3.8";
const SHA256_OID = "2.16.840.1.101.3.4.2.1";

function pemToPkijsCert(pem: string): pkijs.Certificate {
  const base64 = pem.replace(/-----BEGIN CERTIFICATE-----/, "").replace(/-----END CERTIFICATE-----/, "").replace(/\s+/g, "");
  const der = Buffer.from(base64, "base64");
  const asn1 = asn1js.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
  return new pkijs.Certificate({ schema: asn1.result });
}

interface TestTsa {
  keys: CryptoKeyPair;
  certPem: string;
  rootCertPem: string;
}

// A real root -> leaf pair, not a single self-signed cert: pkijs's
// CertificateChainValidationEngine requires the trust anchor itself to be
// a distinct CA:true certificate — a CA:false self-signed leaf used
// directly as its own "trusted root" does not build a valid path, even
// though it's a perfectly fine signer for the CMS signature itself. This
// mirrors the shape a real public TSA's own chain has (leaf -> intermediate
// -> root) with one fewer tier, since one is all this needs.
async function makeTestTsa(options?: { withoutEku?: boolean }): Promise<TestTsa> {
  const rootKeys = (await webcrypto.subtle.generateKey(RSA_SIGNING_ALGORITHM, true, ["sign", "verify"])) as CryptoKeyPair;
  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + 24 * 60 * 60 * 1000);
  const rootCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: crypto.randomBytes(8).toString("hex"),
    name: "CN=Test Root CA",
    notBefore,
    notAfter,
    signingAlgorithm: RSA_SIGNING_ALGORITHM,
    keys: rootKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(rootKeys.publicKey),
    ],
  });

  const tsaKeys = (await webcrypto.subtle.generateKey(RSA_SIGNING_ALGORITHM, true, ["sign", "verify"])) as CryptoKeyPair;
  const extensions = [
    new x509.BasicConstraintsExtension(false),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature),
    await x509.SubjectKeyIdentifierExtension.create(tsaKeys.publicKey),
    await x509.AuthorityKeyIdentifierExtension.create(rootKeys.publicKey),
  ];
  if (!options?.withoutEku) {
    extensions.push(new x509.ExtendedKeyUsageExtension([TIMESTAMPING_EKU_OID]));
  }
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: crypto.randomBytes(8).toString("hex"),
    subject: "CN=Test TSA",
    issuer: rootCert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: RSA_SIGNING_ALGORITHM,
    publicKey: tsaKeys.publicKey,
    signingKey: rootKeys.privateKey,
    extensions,
  });
  return { keys: tsaKeys, certPem: cert.toString("pem"), rootCertPem: rootCert.toString("pem") };
}

// One fixed, "trusted" test TSA for most tests below (its ROOT is in
// TSA_CA_CERT_BASE64 for this whole process) and one "no EKU" variant —
// built once at module load since generating RSA keys isn't free and
// nothing about these certs varies per test.
const trustedTsa = await makeTestTsa();
const noEkuTsa = await makeTestTsa({ withoutEku: true });
// A second, equally well-formed TSA whose ROOT is deliberately NEVER added
// to TSA_CA_CERT_BASE64 — covers "untrusted root".
const untrustedTsa = await makeTestTsa();

process.env.TSA_CA_CERT_BASE64 = Buffer.from(trustedTsa.rootCertPem + "\n" + noEkuTsa.rootCertPem, "utf8").toString(
  "base64",
);

interface BuildTokenOptions {
  tsa: TestTsa;
  messageImprintSource: Buffer; // what hashedMessage is computed over
  nonceBytes: Uint8Array;
  genTime?: Date;
  corruptSignature?: boolean;
}

async function buildFakeToken(options: BuildTokenOptions): Promise<Buffer> {
  const messageImprint = await pkijs.MessageImprint.create("SHA-256", options.messageImprintSource);
  const pkijsCert = pemToPkijsCert(options.tsa.certPem);

  const tstInfo = new pkijs.TSTInfo({
    version: 1,
    policy: "1.2.3.4.5.6",
    messageImprint,
    serialNumber: new asn1js.Integer({ value: 1 }),
    genTime: options.genTime ?? new Date(),
    nonce: new asn1js.Integer({
      valueHex: options.nonceBytes.buffer.slice(options.nonceBytes.byteOffset, options.nonceBytes.byteOffset + options.nonceBytes.byteLength),
    }),
  });

  // Two-step construct-then-assign, not a one-shot constructor param: pkijs's
  // EncapsulatedContentInfo constructor, when handed `eContent` directly,
  // unconditionally rewraps a primitive OCTET STRING into a CONSTRUCTED one
  // (its BER chunking path for content over 65536 bytes — triggered here
  // regardless of size). A constructed OCTET STRING's own .valueBlock.
  // valueHexView is not the raw TSTInfo DER verifyAnchor() expects when it
  // later reads this same field — assigning the property after construction
  // skips that constructor-only branch entirely, matching the plain,
  // primitive shape a real TSA response actually contains.
  const encapContentInfo = new pkijs.EncapsulatedContentInfo({ eContentType: pkijs.id_eContentType_TSTInfo });
  encapContentInfo.eContent = new asn1js.OctetString({ valueHex: tstInfo.toSchema().toBER(false) });

  const signedData = new pkijs.SignedData({
    version: 1,
    encapContentInfo,
    signerInfos: [
      new pkijs.SignerInfo({
        sid: new pkijs.IssuerAndSerialNumber({ issuer: pkijsCert.issuer, serialNumber: pkijsCert.serialNumber }),
      }),
    ],
    certificates: [pkijsCert],
  });

  await signedData.sign(options.tsa.keys.privateKey, 0, "SHA-256");

  if (options.corruptSignature) {
    const sig = signedData.signerInfos[0].signature;
    const bytes = new Uint8Array(sig.valueBlock.valueHexView);
    bytes[0] ^= 0xff;
    sig.valueBlock.valueHexView.set(bytes);
  }

  const contentInfo = new pkijs.ContentInfo({
    contentType: pkijs.ContentInfo.SIGNED_DATA,
    content: signedData.toSchema(true),
  });
  return Buffer.from(contentInfo.toSchema().toBER(false));
}

function fakeAnchorRow(tokenDer: Buffer, headHash: string, nonceHex: string, tsaUrl: string) {
  return {
    id: "test-anchor-id",
    headLogId: "test-head-log-id-does-not-exist",
    headHash,
    tsaUrl,
    tokenBase64: tokenDer.toString("base64"),
    genTime: new Date(),
    tsaSerial: "01",
    policyOid: "1.2.3.4.5.6",
    nonce: nonceHex,
    createdAt: new Date(),
  } as Parameters<typeof verifyAnchor>[0];
}

function stepsById(steps: AnchorCheckStep[]) {
  return new Map(steps.map((s) => [s.id, s]));
}

test("verifyAnchor: a genuinely valid token passes every live check (steps 1-6)", async () => {
  const headHash = crypto.createHash("sha256").update("genuine audit head").digest("hex");
  const nonceBytes = crypto.randomBytes(8);
  nonceBytes[0] &= 0x7f;
  const nonceHex = nonceBytes.toString("hex");

  const tokenDer = await buildFakeToken({
    tsa: trustedTsa,
    messageImprintSource: Buffer.from(headHash, "hex"),
    nonceBytes,
  });
  const result = await verifyAnchor(fakeAnchorRow(tokenDer, headHash, nonceHex, "https://test-tsa.example"));
  const steps = stepsById(result.steps);

  assert.equal(steps.get("tokenParses")?.pass, true);
  assert.equal(steps.get("messageImprint")?.pass, true);
  assert.equal(steps.get("cmsSignature")?.pass, true);
  assert.equal(steps.get("tsaCertificate")?.pass, true);
  assert.equal(steps.get("nonce")?.pass, true);
  assert.equal(steps.get("genTime")?.pass, true);
});

test("verifyAnchor: wrong messageImprint fails only that step — signature, EKU, nonce, genTime are unaffected", async () => {
  const headHash = crypto.createHash("sha256").update("genuine audit head 2").digest("hex");
  const nonceBytes = crypto.randomBytes(8);
  nonceBytes[0] &= 0x7f;
  const nonceHex = nonceBytes.toString("hex");

  // Genuinely signed by the real test TSA key — just attests to a
  // DIFFERENT value than this anchor's own stored headHash.
  const tokenDer = await buildFakeToken({
    tsa: trustedTsa,
    messageImprintSource: Buffer.from("a completely different value"),
    nonceBytes,
  });
  const result = await verifyAnchor(fakeAnchorRow(tokenDer, headHash, nonceHex, "https://test-tsa.example"));
  const steps = stepsById(result.steps);

  assert.equal(steps.get("messageImprint")?.pass, false);
  assert.equal(steps.get("cmsSignature")?.pass, true);
  assert.equal(steps.get("tsaCertificate")?.pass, true);
  assert.equal(steps.get("nonce")?.pass, true);
});

test("verifyAnchor: a tampered CMS signature fails only that step — messageImprint is unaffected", async () => {
  const headHash = crypto.createHash("sha256").update("genuine audit head 3").digest("hex");
  const nonceBytes = crypto.randomBytes(8);
  nonceBytes[0] &= 0x7f;
  const nonceHex = nonceBytes.toString("hex");

  const tokenDer = await buildFakeToken({
    tsa: trustedTsa,
    messageImprintSource: Buffer.from(headHash, "hex"),
    nonceBytes,
    corruptSignature: true,
  });
  const result = await verifyAnchor(fakeAnchorRow(tokenDer, headHash, nonceHex, "https://test-tsa.example"));
  const steps = stepsById(result.steps);

  assert.equal(steps.get("messageImprint")?.pass, true);
  assert.equal(steps.get("cmsSignature")?.pass, false);
});

test("verifyAnchor: wrong nonce fails only that step", async () => {
  const headHash = crypto.createHash("sha256").update("genuine audit head 4").digest("hex");
  const sentNonceBytes = crypto.randomBytes(8);
  sentNonceBytes[0] &= 0x7f;
  const recordedNonceHex = crypto.randomBytes(8).toString("hex"); // deliberately NOT what was sent

  const tokenDer = await buildFakeToken({
    tsa: trustedTsa,
    messageImprintSource: Buffer.from(headHash, "hex"),
    nonceBytes: sentNonceBytes,
  });
  const result = await verifyAnchor(fakeAnchorRow(tokenDer, headHash, recordedNonceHex, "https://test-tsa.example"));
  const steps = stepsById(result.steps);

  assert.equal(steps.get("nonce")?.pass, false);
  assert.equal(steps.get("cmsSignature")?.pass, true);
  assert.equal(steps.get("messageImprint")?.pass, true);
});

test("verifyAnchor: a certificate without the timeStamping EKU fails tsaCertificate specifically, naming the EKU", async () => {
  const headHash = crypto.createHash("sha256").update("genuine audit head 5").digest("hex");
  const nonceBytes = crypto.randomBytes(8);
  nonceBytes[0] &= 0x7f;
  const nonceHex = nonceBytes.toString("hex");

  const tokenDer = await buildFakeToken({
    tsa: noEkuTsa,
    messageImprintSource: Buffer.from(headHash, "hex"),
    nonceBytes,
  });
  const result = await verifyAnchor(fakeAnchorRow(tokenDer, headHash, nonceHex, "https://test-tsa.example"));
  const steps = stepsById(result.steps);

  assert.equal(steps.get("tsaCertificate")?.pass, false);
  assert.match(steps.get("tsaCertificate")?.detail ?? "", /timeStamping/i);
  assert.equal(steps.get("cmsSignature")?.pass, true, "the signature itself is genuine — only the certificate's authorization is wrong");
});

test("verifyAnchor: a certificate chaining to an untrusted root fails tsaCertificate — signature still verifies", async () => {
  const headHash = crypto.createHash("sha256").update("genuine audit head 6").digest("hex");
  const nonceBytes = crypto.randomBytes(8);
  nonceBytes[0] &= 0x7f;
  const nonceHex = nonceBytes.toString("hex");

  const tokenDer = await buildFakeToken({
    tsa: untrustedTsa, // never added to TSA_CA_CERT_BASE64 above
    messageImprintSource: Buffer.from(headHash, "hex"),
    nonceBytes,
  });
  const result = await verifyAnchor(fakeAnchorRow(tokenDer, headHash, nonceHex, "https://test-tsa.example"));
  const steps = stepsById(result.steps);

  assert.equal(steps.get("tsaCertificate")?.pass, false);
  assert.equal(steps.get("cmsSignature")?.pass, true);
});

test("verifyAnchor: messageImprint uses the SHA-256 algorithm OID, matching lib/timestamp.ts's own design", async () => {
  const headHash = crypto.createHash("sha256").update("genuine audit head 7").digest("hex");
  const nonceBytes = crypto.randomBytes(8);
  nonceBytes[0] &= 0x7f;

  const tokenDer = await buildFakeToken({ tsa: trustedTsa, messageImprintSource: Buffer.from(headHash, "hex"), nonceBytes });
  const contentInfo = pkijs.ContentInfo.fromBER(tokenDer.buffer.slice(tokenDer.byteOffset, tokenDer.byteOffset + tokenDer.byteLength));
  const signedData = new pkijs.SignedData({ schema: contentInfo.content });
  const tstInfo = new pkijs.TSTInfo({ schema: asn1js.fromBER(signedData.encapContentInfo.eContent!.valueBlock.valueHexView).result });
  assert.equal(tstInfo.messageImprint.hashAlgorithm.algorithmId, SHA256_OID);
});
