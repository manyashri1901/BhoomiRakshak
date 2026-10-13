// test/certificate.test.ts
//
// verifyCertificate(): valid for a freshly issued certificate, invalid
// after revocation, invalid once past its expiry. DB-backed (there is no
// mock Prisma layer in this project) — each test creates its own user, and
// per the lesson in scripts/test-ca.ts's header, none of them are deleted
// afterward: AuditLog.actorUserId is `onDelete: Restrict` specifically so
// a user referenced by the audit trail (issueCertificate logs
// CERTIFICATE_ISSUED) can't be deleted without breaking that guarantee.

import "dotenv/config";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { prisma } from "../lib/prisma.ts";
import { generateUserKeyPair, issueCertificate, verifyCertificate, revokeCertificate } from "../lib/ca.ts";
import { canonicalStringify } from "../lib/canonicalize.ts";

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

test("verifyCertificate: valid immediately after issuance", async () => {
  const user = await makeTestUser("Valid");
  const { publicKey } = generateUserKeyPair();
  await prisma.user.update({ where: { id: user.id }, data: { publicKey } });

  const certificate = await issueCertificate({ id: user.id, name: user.name, role: user.role, publicKey });
  const result = await verifyCertificate(certificate.id);

  assert.equal(result.valid, true);
  assert.equal(result.details.revoked, false);
  assert.equal(result.details.expired, false);
});

test("verifyCertificate: invalid after revocation, with a reason naming it", async () => {
  const user = await makeTestUser("Revoked");
  const { publicKey } = generateUserKeyPair();
  await prisma.user.update({ where: { id: user.id }, data: { publicKey } });
  const certificate = await issueCertificate({ id: user.id, name: user.name, role: user.role, publicKey });

  const before = await verifyCertificate(certificate.id);
  assert.equal(before.valid, true);

  await revokeCertificate({ certificateId: certificate.id, revokedByUserId: user.id, reason: "unit test revocation" });

  const after = await verifyCertificate(certificate.id);
  assert.equal(after.valid, false);
  assert.equal(after.details.revoked, true);
  assert.match(after.details.reason ?? "", /revoked/i);
});

test("verifyCertificate: invalid once past expiresAt, even with a genuine CA signature", async () => {
  const user = await makeTestUser("Expired");
  const { publicKey } = generateUserKeyPair();
  await prisma.user.update({ where: { id: user.id }, data: { publicKey } });
  const certificate = await issueCertificate({ id: user.id, name: user.name, role: user.role, publicKey });

  // Re-sign the same certificate row with a backdated issuedAt/expiresAt —
  // genuinely CA-signed (not tampered), just naturally past its window.
  const caPrivateKey = fs.readFileSync(path.join(process.cwd(), "keys", "ca-private.pem"), "utf8");
  const issuedAt = new Date(Date.now() - 2 * 365 * 24 * 60 * 60 * 1000);
  const expiresAt = new Date(issuedAt.getTime() + 365 * 24 * 60 * 60 * 1000);
  const payload = {
    subject: user.id,
    name: user.name,
    role: user.role,
    publicKey,
    issuer: "BhoomiRakshak Root CA",
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
  };
  const signature = crypto
    .sign("RSA-SHA256", Buffer.from(canonicalStringify(payload), "utf8"), caPrivateKey)
    .toString("base64");
  await prisma.certificate.update({ where: { id: certificate.id }, data: { issuedAt, expiresAt, signature } });

  const result = await verifyCertificate(certificate.id);
  assert.equal(result.valid, false);
  assert.equal(result.details.expired, true);
  assert.equal(result.details.signatureValid, true); // genuinely signed — just expired, not forged
});
