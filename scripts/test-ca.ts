// scripts/test-ca.ts
//
// Demonstrates one full CA cycle end to end:
//   1. Create a test User row (Certificate.subjectUserId is a real FK).
//   2. generateUserKeyPair() — the user's own RSA key pair.
//   3. issueCertificate()   — CA signs {subject, name, role, publicKey, ...}.
//      This also writes a CERTIFICATE_ISSUED row to the audit hash chain
//      (lib/audit.ts), referencing this test user as the actor.
//   4. verifyCertificate()  — checks the signature against the CA public key.
//   5. Print the result.
//
// Deliberately does NOT delete the test user/certificate afterward (an
// earlier version did): AuditLog.actorUserId is `onDelete: Restrict`
// precisely because actorUserId is one of the fields a row's hash commits
// to, so deleting a referenced user would either fail loudly (Restrict,
// what happens now if you try) or — with the old SetNull this schema used
// to have — silently null the field out from under an already-hashed row,
// which verifyAuditChain() then correctly reports as tampered. Leaving
// this script's test user/certificate in place is the price of having a
// real, immutable audit log: nothing that ever appears in it can be
// deleted without breaking a cryptographic guarantee, test data included.
//
// Run with: node scripts/test-ca.ts

import "dotenv/config";
import { prisma } from "../lib/prisma.ts";
import { generateUserKeyPair, issueCertificate, verifyCertificate } from "../lib/ca.ts";

async function main() {
  // 1. Create a test user (stands in for a Landowner completing registration).
  const testUser = await prisma.user.create({
    data: {
      name: "Test Landowner",
      email: `test-landowner-${Date.now()}@example.com`,
      passwordHash: "not-a-real-hash",
      role: "LANDOWNER",
      publicKey: "placeholder-until-keypair-generated",
    },
  });
  console.log("1. Created test user:", testUser.id);

  // 2. Generate the user's own RSA-2048 key pair.
  const { publicKey, privateKey } = generateUserKeyPair();
  console.log("2. Generated user key pair (RSA-2048).");
  console.log("   Public key starts with:", publicKey.split("\n")[0]);

  // Persist the public key on the user row (private key stays with the
  // user in a real flow; here we just show it exists and don't store it).
  await prisma.user.update({
    where: { id: testUser.id },
    data: { publicKey },
  });
  void privateKey; // demo only: never logged, never persisted server-side

  // 3. CA issues a certificate binding this user's identity to their public key.
  const certificate = await issueCertificate({
    id: testUser.id,
    name: testUser.name,
    role: testUser.role,
    publicKey,
  });
  console.log("3. Issued certificate:", certificate.id);
  console.log("   Signature (base64, truncated):", certificate.signature.slice(0, 40) + "...");
  console.log("   Fingerprint:", certificate.fingerprint);

  // 4. Verify the certificate against the CA's public key.
  const result = await verifyCertificate(certificate.id);
  console.log("4. Verification result:", result);
  console.log(`valid: ${result.valid}`);

  // 5. No cleanup — see the file header. This test user and certificate
  // are now part of the audit trail and stay.
  console.log("5. Done — test user and certificate are kept (see file header for why).");

  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error(err);
  await prisma.$disconnect();
  process.exit(1);
});
