// scripts/test-first-run-e2e.ts
//
// Proves first-run's CA bootstrap + certificate issuance flow works from
// scratch, against a TEMPORARY, empty keys directory (via the CA_KEYS_DIR
// override added to lib/ca.ts and scripts/first-run.ts) — this script
// never reads or writes the real keys/ folder.
//
// This reproduces, for real, the exact sequence that crashed before the
// pemToDer() pool-allocation fix: bootstrapCAHierarchy() generates a fresh
// root + issuing CA (writing the issuing private key to disk), then
// ensureIssuingCA() immediately reads it back and imports it — that import
// is the call that threw "Invalid keyData ... header too long"
// (lib/ca.ts:275, reached from issueCertificate() during first-run's
// admin-creation step).
//
// Does NOT run `prisma migrate deploy` (assumes migrations are already
// applied — if they aren't, the prisma.user.create() below will fail with
// a clear schema error) and does not delete anything. It creates one
// throwaway LANDOWNER user + certificate in the real database, same
// pattern as scripts/export-cert-check.ts, left in place afterward for the
// same reason test/certificate.test.ts's header comment gives: AuditLog's
// actorUserId is onDelete: Restrict, so a user referenced by the audit
// trail (issueCertificate logs CERTIFICATE_ISSUED) can't be deleted
// without breaking that guarantee.
//
// Run with: node scripts/test-first-run-e2e.ts

import "dotenv/config";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

async function main() {
  const tempKeysDir = fs.mkdtempSync(path.join(os.tmpdir(), "bhoomirakshak-first-run-e2e-"));
  process.env.CA_KEYS_DIR = tempKeysDir;
  // Must NOT be set — otherwise bootstrapCAHierarchy()/ensureIssuingCA()
  // would prefer these over generating fresh files in tempKeysDir,
  // defeating the point of this test (and risking use of real secrets).
  delete process.env.ROOT_CA_CERT_BASE64;
  delete process.env.ISSUING_CA_PRIVATE_KEY_BASE64;
  delete process.env.ISSUING_CA_CERT_BASE64;

  console.log(`Using temporary keys directory: ${tempKeysDir}`);
  console.log("(your real keys/ directory is not touched by this script)\n");

  // Dynamic import, AFTER CA_KEYS_DIR is set above — lib/ca.ts reads it
  // once, at module-load time, to resolve its CA_DIR constant; a static
  // top-level import would be hoisted ahead of the assignment above.
  const { bootstrapCAHierarchy, ensureIssuingCA, issueCertificate, verifyCertificate, generateUserKeyPair } =
    await import("../lib/ca.ts");
  const { prisma } = await import("../lib/prisma.ts");

  console.log("Step 1: bootstrapCAHierarchy() against the empty temp directory...");
  const bootstrap = await bootstrapCAHierarchy();
  assert.equal(bootstrap.rootGenerated, true, "expected a fresh root CA to be generated");
  assert.equal(bootstrap.issuingGenerated, true, "expected a fresh issuing CA to be generated");
  assert.ok(bootstrap.rootCertBase64, "expected rootCertBase64 to be returned");
  assert.ok(bootstrap.issuingPrivateKeyBase64, "expected issuingPrivateKeyBase64 to be returned");
  assert.ok(bootstrap.issuingCertBase64, "expected issuingCertBase64 to be returned");
  console.log("  OK - root + issuing CA generated.");

  for (const expectedFile of [
    path.join(tempKeysDir, "root-offline", "root-ca-private.pem"),
    path.join(tempKeysDir, "root-ca-cert.pem"),
    path.join(tempKeysDir, "issuing-ca-private.pem"),
    path.join(tempKeysDir, "issuing-ca-cert.pem"),
  ]) {
    assert.ok(fs.existsSync(expectedFile), `expected ${expectedFile} to exist`);
  }
  console.log("  OK - all four key/cert files written under the temp directory.");

  console.log("\nStep 2: ensureIssuingCA() - loads the issuing key back off disk and imports it...");
  // This is the exact call that threw "Invalid keyData ... header too
  // long" before the fix: importPrivateKeyPem() reading back the issuing
  // private key just written above.
  const loaded = await ensureIssuingCA();
  assert.ok(loaded.issuingPrivateKey);
  console.log("  OK - issuing private key imported without error.");

  console.log("\nStep 3: issueCertificate() for a throwaway test user (mirrors first-run's admin-creation step)...");
  const testUser = await prisma.user.create({
    data: {
      name: "First-Run E2E Test User",
      email: `first-run-e2e-${Date.now()}@example.com`,
      passwordHash: "not-a-real-hash",
      role: "LANDOWNER",
      publicKey: "placeholder-until-keypair-generated",
    },
  });
  const { publicKey } = generateUserKeyPair();
  await prisma.user.update({ where: { id: testUser.id }, data: { publicKey } });
  const certificate = await issueCertificate({
    id: testUser.id,
    name: testUser.name,
    role: testUser.role,
    publicKey,
  });
  console.log(`  OK - certificate issued, serial ${certificate.serialNumber}.`);

  console.log("\nStep 4: verifyCertificate() on the freshly issued certificate...");
  const result = await verifyCertificate(certificate.id);
  assert.equal(
    result.valid,
    true,
    `expected the freshly issued certificate to verify as valid, got: ${JSON.stringify(result.details)}`,
  );
  console.log("  OK - certificate verifies as valid (full chain: user -> issuing -> root).");

  fs.rmSync(tempKeysDir, { recursive: true, force: true });
  console.log(`\nCleaned up temp directory: ${tempKeysDir}`);
  console.log("\nAll checks passed - first-run's CA bootstrap + issuance flow works from scratch.");

  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error(err);
  try {
    const { prisma } = await import("../lib/prisma.ts");
    await prisma.$disconnect();
  } catch {
    // ignore - best-effort cleanup only
  }
  process.exit(1);
});
