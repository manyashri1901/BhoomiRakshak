// scripts/export-cert-check.ts
//
// Issues one real certificate exactly like scripts/test-ca.ts does, then
// writes the user, issuing CA, and root CA certificates out as plain PEM
// files in a temp folder — so the result can be checked with a completely
// independent, off-the-shelf tool (openssl) instead of only this
// project's own verification code. This is a one-time, manual artifact
// for the project report: run it, run the two printed openssl commands
// yourself, and screenshot the output.
//
// Run with: node scripts/export-cert-check.ts

import "dotenv/config";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { prisma } from "../lib/prisma.ts";
import { generateUserKeyPair, issueCertificate, getCAPublicCertificates } from "../lib/ca.ts";

async function main() {
  const testUser = await prisma.user.create({
    data: {
      name: "Export Cert Check",
      email: `export-cert-check-${Date.now()}@example.com`,
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
  const { rootCertPem, issuingCertPem } = await getCAPublicCertificates();

  const outDir = path.join(os.tmpdir(), "bhoomirakshak-cert-export");
  fs.mkdirSync(outDir, { recursive: true });
  const userPath = path.join(outDir, "user.pem");
  const issuingPath = path.join(outDir, "issuing.pem");
  const rootPath = path.join(outDir, "root.pem");
  fs.writeFileSync(userPath, certificate.certificatePem);
  fs.writeFileSync(issuingPath, issuingCertPem);
  fs.writeFileSync(rootPath, rootCertPem);

  console.log(`Wrote:\n  ${userPath}\n  ${issuingPath}\n  ${rootPath}\n`);
  console.log(`Certificate serial: ${certificate.serialNumber}`);
  console.log(`Certificate subject/role: ${testUser.name} / ${testUser.role}\n`);

  console.log("Run these yourself (independent of this app's own code) and screenshot the output:\n");
  console.log(`  openssl verify -CAfile "${rootPath}" -untrusted "${issuingPath}" "${userPath}"`);
  console.log(`  openssl x509 -in "${userPath}" -text -noout`);
  console.log(`  openssl x509 -in "${issuingPath}" -text -noout`);
  console.log(`  openssl x509 -in "${rootPath}" -text -noout\n`);
  console.log(
    "The first command should print \"user.pem: OK\" — that's openssl independently confirming the full " +
      "chain (user -> issuing -> root), not this project's own verification code agreeing with itself. " +
      "The three `-text -noout` commands print each certificate's real X.509 v3 fields (serial, validity, " +
      "issuer/subject DN, extensions) for the screenshot.",
  );

  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error(err);
  await prisma.$disconnect();
  process.exit(1);
});
