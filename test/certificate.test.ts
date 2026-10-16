// test/certificate.test.ts
//
// verifyCertificate(): valid for a freshly issued X.509 certificate,
// invalid after revocation, invalid once past its notAfter, invalid when
// tampered, invalid when issued by an unknown CA. DB-backed (there is no
// mock Prisma layer in this project) — each test creates its own user, and
// per the lesson in scripts/test-ca.ts's header, none of them are deleted
// afterward: AuditLog.actorUserId is `onDelete: Restrict` specifically so
// a user referenced by the audit trail (issueCertificate logs
// CERTIFICATE_ISSUED) can't be deleted without breaking that guarantee.

import "dotenv/config";
// Must precede the "@peculiar/x509" import below: its tsyringe dependency
// requires this polyfill at load time, not just before first use.
import "reflect-metadata";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { webcrypto } from "node:crypto";
import * as x509 from "@peculiar/x509";
import { prisma } from "../lib/prisma.ts";
import {
  generateUserKeyPair,
  issueCertificate,
  verifyCertificate,
  revokeCertificate,
  getSignedCRL,
  ensureIssuingCA,
} from "../lib/ca.ts";
import { RSA_SIGNING_ALGORITHM } from "../lib/x509Keys.ts";

async function makeTestUser(label: string) {
  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  return prisma.user.create({
    data: {
      name: `Unit Test ${label}`,
      email: `unit-test-${label.toLowerCase().replace(/\s+/g, "-")}-${stamp}@example.com`,
      passwordHash: "unit-test-not-a-real-hash",
      role: "LANDOWNER",
      publicKey: "placeholder-until-keypair-generated",
    },
  });
}

async function issueForTestUser(label: string) {
  const user = await makeTestUser(label);
  const { publicKey } = generateUserKeyPair();
  await prisma.user.update({ where: { id: user.id }, data: { publicKey } });
  const certificate = await issueCertificate({ id: user.id, name: user.name, role: user.role, publicKey });
  return { user, certificate };
}

function randomSerialHex(): string {
  const bytes = crypto.randomBytes(16);
  bytes[0] &= 0x7f;
  return bytes.toString("hex");
}

test("verifyCertificate: valid immediately after issuance", async () => {
  const { certificate } = await issueForTestUser("Valid");
  const result = await verifyCertificate(certificate.id);

  assert.equal(result.valid, true);
  assert.equal(result.details.revoked, false);
  assert.equal(result.details.expired, false);
  assert.equal(result.details.userSignatureValid, true);
  assert.equal(result.details.issuingSignatureValid, true);
  assert.equal(result.details.keyUsageValid, true);
});

test("verifyCertificate: invalid after revocation, with a reason naming it", async () => {
  const { user, certificate } = await issueForTestUser("Revoked");

  const before = await verifyCertificate(certificate.id);
  assert.equal(before.valid, true);

  await revokeCertificate({ certificateId: certificate.id, revokedByUserId: user.id, reason: "unit test revocation" });

  const after = await verifyCertificate(certificate.id);
  assert.equal(after.valid, false);
  assert.equal(after.details.revoked, true);
  assert.match(after.details.reason ?? "", /revoked/i);
});

test("verifyCertificate: invalid once past notAfter, even with a genuine Issuing CA signature", async () => {
  const { certificate } = await issueForTestUser("Expired");

  // Re-sign the SAME subject/key with a backdated validity window —
  // genuinely issued by the real Issuing CA (not tampered), just
  // naturally past its window.
  const { issuingPrivateKey, issuingCert } = await ensureIssuingCA();
  const cert = await prisma.certificate.findUnique({ where: { id: certificate.id } });
  const existingCert = new x509.X509Certificate(cert!.certificatePem);

  const notBefore = new Date(Date.now() - 2 * 365 * 24 * 60 * 60 * 1000);
  const notAfter = new Date(notBefore.getTime() + 365 * 24 * 60 * 60 * 1000);
  const backdated = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerialHex(),
    subject: existingCert.subject,
    issuer: issuingCert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: RSA_SIGNING_ALGORITHM,
    publicKey: existingCert.publicKey,
    signingKey: issuingPrivateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature),
    ],
  });
  await prisma.certificate.update({
    where: { id: certificate.id },
    data: { certificatePem: backdated.toString("pem"), issuedAt: notBefore, expiresAt: notAfter },
  });

  const result = await verifyCertificate(certificate.id);
  assert.equal(result.valid, false);
  assert.equal(result.details.expired, true);
  assert.equal(result.details.userSignatureValid, true); // genuinely signed — just expired, not forged
});

test("verifyCertificate: a tampered certificate (public key swapped) fails signature verification", async () => {
  const { certificate } = await issueForTestUser("Tampered");
  const cert = await prisma.certificate.findUnique({ where: { id: certificate.id } });
  const existingCert = new x509.X509Certificate(cert!.certificatePem);

  // An attacker with raw DB access swaps in a self-signed certificate
  // claiming the same subject/serial but a DIFFERENT key pair — the
  // Issuing CA never signed THIS object, so it must fail signature
  // verification even though it's a well-formed, validly-structured
  // certificate on its own.
  const otherKeys = (await webcrypto.subtle.generateKey(RSA_SIGNING_ALGORITHM, true, ["sign", "verify"])) as CryptoKeyPair;
  const forged = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: existingCert.serialNumber,
    name: existingCert.subject,
    notBefore: existingCert.notBefore,
    notAfter: existingCert.notAfter,
    signingAlgorithm: RSA_SIGNING_ALGORITHM,
    keys: otherKeys,
  });
  await prisma.certificate.update({ where: { id: certificate.id }, data: { certificatePem: forged.toString("pem") } });

  const result = await verifyCertificate(certificate.id);
  assert.equal(result.valid, false);
  assert.equal(result.details.userSignatureValid, false);
  assert.match(result.details.reason ?? "", /signature/i);
});

test("verifyCertificate: a certificate issued by an unknown CA is rejected", async () => {
  const { certificate } = await issueForTestUser("Unknown CA");
  const cert = await prisma.certificate.findUnique({ where: { id: certificate.id } });
  const existingCert = new x509.X509Certificate(cert!.certificatePem);

  // A completely separate, unrelated CA — not this app's root or issuing
  // CA at all — signs a certificate for the SAME subject and key. This is
  // what "unknown CA" means concretely: the signature is genuine, just
  // not produced by any key this server trusts.
  const foreignRootKeys = (await webcrypto.subtle.generateKey(RSA_SIGNING_ALGORITHM, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const foreignCert = await x509.X509CertificateGenerator.create({
    serialNumber: randomSerialHex(),
    subject: existingCert.subject,
    issuer: "CN=Some Other Certificate Authority",
    notBefore: existingCert.notBefore,
    notAfter: existingCert.notAfter,
    signingAlgorithm: RSA_SIGNING_ALGORITHM,
    publicKey: existingCert.publicKey,
    signingKey: foreignRootKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature),
    ],
  });
  await prisma.certificate.update({ where: { id: certificate.id }, data: { certificatePem: foreignCert.toString("pem") } });

  const result = await verifyCertificate(certificate.id);
  assert.equal(result.valid, false);
  assert.equal(result.details.userSignatureValid, false);
});

test("getSignedCRL: a revoked certificate's serial appears in the real X.509 CRL, and the CRL's own signature verifies", async () => {
  const { user, certificate } = await issueForTestUser("CRL Listed");

  const { issuingCert } = await ensureIssuingCA();
  const beforeCrl = new x509.X509Crl((await getSignedCRL()).pem);
  assert.equal(beforeCrl.findRevoked(certificate.serialNumber), null);

  await revokeCertificate({ certificateId: certificate.id, revokedByUserId: user.id, reason: "unit test CRL listing" });

  const afterSigned = await getSignedCRL();
  const afterCrl = new x509.X509Crl(afterSigned.pem);
  assert.ok(afterCrl.findRevoked(certificate.serialNumber));

  const crlSignatureValid = await afterCrl.verify({ publicKey: issuingCert.publicKey });
  assert.equal(crlSignatureValid, true);
});

test("getSignedCRL: a CRL signed by the wrong key fails verification against the real Issuing CA", async () => {
  const { issuingCert } = await ensureIssuingCA();
  const wrongKeys = (await webcrypto.subtle.generateKey(RSA_SIGNING_ALGORITHM, true, ["sign", "verify"])) as CryptoKeyPair;

  const forgedCrl = await x509.X509CrlGenerator.create({
    issuer: issuingCert.subject,
    thisUpdate: new Date(),
    nextUpdate: new Date(Date.now() + 60 * 60 * 1000),
    signingAlgorithm: RSA_SIGNING_ALGORITHM,
    signingKey: wrongKeys.privateKey, // NOT the real issuing CA's key
    entries: [],
  });

  const valid = await forgedCrl.verify({ publicKey: issuingCert.publicKey });
  assert.equal(valid, false);
});

test("getSignedCRL: a stale CRL (past its own nextUpdate) is distinguishable from a fresh one", async () => {
  const { issuingPrivateKey, issuingCert } = await ensureIssuingCA();

  const staleThisUpdate = new Date(Date.now() - 2 * 60 * 60 * 1000);
  const staleNextUpdate = new Date(staleThisUpdate.getTime() + 60 * 60 * 1000); // expired an hour ago
  const staleCrl = await x509.X509CrlGenerator.create({
    issuer: issuingCert.subject,
    thisUpdate: staleThisUpdate,
    nextUpdate: staleNextUpdate,
    signingAlgorithm: RSA_SIGNING_ALGORITHM,
    signingKey: issuingPrivateKey,
    entries: [],
  });

  // Genuinely signed by the real key — freshness is a separate concern
  // from signature validity, exactly like certificate expiry above.
  const signatureValid = await staleCrl.verify({ publicKey: issuingCert.publicKey });
  assert.equal(signatureValid, true);
  assert.ok(staleCrl.nextUpdate! < new Date(), "this CRL's nextUpdate must already be in the past for the test to be meaningful");
});
