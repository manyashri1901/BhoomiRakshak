// test/accessControl.test.ts
//
// Unit tests for middleware/auth.ts's requireCertifiedRole() — called
// directly against hand-built req/res/next stand-ins (no HTTP, no Express
// app), the same "real DB, no mock Prisma layer" approach as
// test/certificate.test.ts. scripts/test-access-control.ts covers the
// HTTP-level role x endpoint matrix; this file covers the middleware's own
// decision logic in isolation: a valid certificate, a revoked one, an
// expired one, and a role-mismatched one.

import "dotenv/config";
// Must precede the "@peculiar/x509" import below: its tsyringe dependency
// requires this polyfill at load time, not just before first use.
import "reflect-metadata";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as x509 from "@peculiar/x509";
import { prisma } from "../lib/prisma.ts";
import { generateUserKeyPair, issueCertificate, revokeCertificate, ensureIssuingCA } from "../lib/ca.ts";
import { RSA_SIGNING_ALGORITHM } from "../lib/x509Keys.ts";
import { requireCertifiedRole } from "../middleware/auth.ts";
import { reviewerIsPriorSigner } from "../routes/transactions.ts";
import type { TransactionWithChain } from "../routes/transactions.ts";

async function makeTestUser(label: string, role: "LANDOWNER" | "VILLAGE_OFFICER" | "REGISTRAR" | "ADMIN") {
  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  return prisma.user.create({
    data: {
      name: `Access Control Test ${label}`,
      email: `access-control-${label.toLowerCase().replace(/\s+/g, "-")}-${stamp}@example.com`,
      passwordHash: "unit-test-not-a-real-hash",
      role,
      publicKey: "placeholder-until-keypair-generated",
    },
  });
}

async function issueForTestUser(label: string, role: "LANDOWNER" | "VILLAGE_OFFICER" | "REGISTRAR" | "ADMIN") {
  const user = await makeTestUser(label, role);
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

// Minimal stand-ins for Express's Request/Response/NextFunction — just
// enough surface area for requireCertifiedRole() to read req.user/
// req.method/req.originalUrl and call res.status().json() or next().
function makeReq(userId: string, role: string) {
  return { user: { userId, role }, method: "POST", originalUrl: "/test-endpoint" } as never;
}

function makeRes() {
  const res = {
    statusCode: null as number | null,
    body: null as unknown,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(body: unknown) {
      res.body = body;
      return res;
    },
  };
  return res as never;
}

function makeNext() {
  let called = false;
  const next = () => {
    called = true;
  };
  return { next, wasCalled: () => called };
}

test("requireCertifiedRole: a valid certificate, correct role, calls next()", async () => {
  const { user } = await issueForTestUser("Valid", "REGISTRAR");
  const req = makeReq(user.id, "REGISTRAR");
  const res = makeRes();
  const { next, wasCalled } = makeNext();

  await requireCertifiedRole("REGISTRAR")(req, res, next);

  assert.equal(wasCalled(), true);
  assert.equal((res as unknown as { statusCode: number | null }).statusCode, null);
});

test("requireCertifiedRole: a revoked certificate is denied with reason CERT_REVOKED", async () => {
  const { user, certificate } = await issueForTestUser("Revoked", "VILLAGE_OFFICER");
  await revokeCertificate({ certificateId: certificate.id, revokedByUserId: user.id, reason: "unit test revocation" });

  const req = makeReq(user.id, "VILLAGE_OFFICER");
  const res = makeRes();
  const { next, wasCalled } = makeNext();

  await requireCertifiedRole("VILLAGE_OFFICER")(req, res, next);

  assert.equal(wasCalled(), false);
  const typedRes = res as unknown as { statusCode: number | null; body: { reason?: string } | null };
  assert.equal(typedRes.statusCode, 403);
  assert.equal(typedRes.body?.reason, "CERT_REVOKED");
});

test("requireCertifiedRole: an expired certificate is denied with reason CERT_EXPIRED", async () => {
  const { user, certificate } = await issueForTestUser("Expired", "LANDOWNER");

  // Same technique as test/certificate.test.ts's equivalent case: re-sign
  // the SAME subject/key with a backdated validity window, genuinely
  // issued by the real Issuing CA — not tampered, just naturally past its
  // window, so this tests expiry specifically, independent of signature
  // validity.
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

  const req = makeReq(user.id, "LANDOWNER");
  const res = makeRes();
  const { next, wasCalled } = makeNext();

  await requireCertifiedRole("LANDOWNER")(req, res, next);

  assert.equal(wasCalled(), false);
  const typedRes = res as unknown as { statusCode: number | null; body: { reason?: string } | null };
  assert.equal(typedRes.statusCode, 403);
  assert.equal(typedRes.body?.reason, "CERT_EXPIRED");
});

test("requireCertifiedRole: a valid certificate for a role not in the allowed list is denied with reason CERT_ROLE_MISMATCH", async () => {
  const { user } = await issueForTestUser("Role Mismatch", "LANDOWNER");

  const req = makeReq(user.id, "LANDOWNER");
  const res = makeRes();
  const { next, wasCalled } = makeNext();

  // A genuinely valid LANDOWNER certificate, asked to authorize a
  // REGISTRAR-only action — the certificate itself is fine; it just
  // doesn't carry the role this endpoint requires.
  await requireCertifiedRole("REGISTRAR")(req, res, next);

  assert.equal(wasCalled(), false);
  const typedRes = res as unknown as { statusCode: number | null; body: { reason?: string } | null };
  assert.equal(typedRes.statusCode, 403);
  assert.equal(typedRes.body?.reason, "CERT_ROLE_MISMATCH");
});

test("requireCertifiedRole: no certificate on file is denied with reason CERT_MISSING", async () => {
  const user = await makeTestUser("No Cert", "LANDOWNER");

  const req = makeReq(user.id, "LANDOWNER");
  const res = makeRes();
  const { next, wasCalled } = makeNext();

  await requireCertifiedRole("LANDOWNER")(req, res, next);

  assert.equal(wasCalled(), false);
  const typedRes = res as unknown as { statusCode: number | null; body: { reason?: string } | null };
  assert.equal(typedRes.statusCode, 403);
  assert.equal(typedRes.body?.reason, "CERT_MISSING");
});

// reviewerIsPriorSigner() backs the "nobody reviews a transaction they
// created, and nobody approves at two stages" rule in
// routes/transactions.ts. Under this app's one-role-per-account model, a
// Landowner account can never also hold a Village Officer or Registrar
// role, so the HTTP role gate alone already makes the violation this
// function guards against unreachable through the live API today (see
// scripts/test-access-control.ts and the report) — tested directly here
// instead, against a hand-built transaction shape, so the underlying
// comparison itself is still verified independent of whether any current
// HTTP path can reach it.
test("reviewerIsPriorSigner: true exactly when the reviewer already appears as a signer, at any prior stage", () => {
  const fakeTransaction = {
    signatures: [
      { actorId: "user-landowner-1" },
      { actorId: "user-vo-1" },
    ],
  } as unknown as TransactionWithChain;

  assert.equal(reviewerIsPriorSigner("user-landowner-1", fakeTransaction), true, "the creator is a prior signer");
  assert.equal(reviewerIsPriorSigner("user-vo-1", fakeTransaction), true, "an earlier-stage reviewer is a prior signer");
  assert.equal(reviewerIsPriorSigner("user-registrar-1", fakeTransaction), false, "a genuinely new reviewer is not");
});
