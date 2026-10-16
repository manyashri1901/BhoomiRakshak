// scripts/export-anchor-check.ts
//
// Writes the latest RFC 3161 anchor's token out as a plain .tsr file,
// plus the digest hex it covers and a bundle of the exact trusted roots
// this project's own code trusts (lib/timestamp.ts's trustedRootCertificates()
// — Node's own tls.rootCertificates, plus TSA_CA_CERT_BASE64 if set), so the
// result can be checked with a completely independent, off-the-shelf tool
// (openssl) instead of only this project's own verification code — same
// idea as scripts/export-cert-check.ts, for the timestamp side instead of
// the certificate chain.
//
// Every command below was tested by hand against a real DigiCert response
// before being written here — in particular, `-token_in` is required on
// both `openssl ts` commands because the file this script writes is the
// bare CMS token (what RFC 3161 calls the TimeStampToken), not a full
// TimeStampResp — and `-CAfile` must be the TRUSTED roots (this script's
// own node-roots.pem bundle), not the certificates the token itself
// carries (those go in `-untrusted`, to help chain-building only): a
// public TSA's response typically embeds its own leaf + intermediate
// certificates but never the root itself, by normal X.509 practice — the
// verifier is expected to already trust that root independently, exactly
// like a browser already trusting a web server's root CA rather than
// receiving it from the server.
//
// Run with: node scripts/export-anchor-check.ts

import "dotenv/config";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as tls from "node:tls";
import * as crypto from "node:crypto";
import { prisma } from "../lib/prisma.ts";

async function main() {
  const anchor = await prisma.auditAnchor.findFirst({ orderBy: { createdAt: "desc" } });
  if (!anchor) {
    console.error("No anchors found yet — run POST /api/audit/anchor (or let an approval trigger one) first.");
    await prisma.$disconnect();
    process.exit(1);
  }

  const tokenDer = Buffer.from(anchor.tokenBase64, "base64");
  // openssl's `-digest` flag wants the hex of the ORIGINAL message the
  // messageImprint was computed over — SHA-256 of this anchor's own stored
  // head hash (see lib/timestamp.ts's header comment for why it's hashed
  // once more here, not used verbatim).
  const digestHex = crypto.createHash("sha256").update(Buffer.from(anchor.headHash, "hex")).digest("hex");

  const outDir = path.join(os.tmpdir(), "bhoomirakshak-anchor-export");
  fs.mkdirSync(outDir, { recursive: true });
  const tsrPath = path.join(outDir, "anchor.tsr");
  const nodeRootsPath = path.join(outDir, "node-roots.pem");
  const tokenCertsPath = path.join(outDir, "token-certs.pem");
  fs.writeFileSync(tsrPath, tokenDer);

  let nodeRootsPem = tls.rootCertificates.join("\n");
  if (process.env.TSA_CA_CERT_BASE64) {
    nodeRootsPem += "\n" + Buffer.from(process.env.TSA_CA_CERT_BASE64, "base64").toString("utf8");
  }
  fs.writeFileSync(nodeRootsPath, nodeRootsPem);

  console.log(`Wrote:\n  ${tsrPath}\n  ${nodeRootsPath} (the exact ${tls.rootCertificates.length} trusted roots this project's own code checks against)\n`);
  console.log(`Anchor id: ${anchor.id}`);
  console.log(`Anchored AuditLog row id: ${anchor.headLogId}`);
  console.log(`Stored head hash: ${anchor.headHash}`);
  console.log(`Digest to pass to -digest below (SHA-256 of the head hash bytes): ${digestHex}`);
  console.log(`TSA: ${anchor.tsaUrl}`);
  console.log(`genTime (as this project parsed it): ${anchor.genTime.toISOString()}\n`);

  console.log("Run these yourself (independent of this app's own code) and screenshot the output:\n");
  console.log(`  openssl ts -reply -in "${tsrPath}" -token_in -text`);
  console.log("    (prints the token's own fields — status, policy, genTime, serial, nonce, message data)\n");

  console.log(`  openssl pkcs7 -inform DER -in "${tsrPath}" -print_certs -out "${tokenCertsPath}"`);
  console.log("    (extracts the TSA's own leaf + intermediate certificates the token carries — used only to");
  console.log("     help chain-building below via -untrusted, never as the trust anchor itself)\n");

  console.log(
    `  openssl ts -verify -in "${tsrPath}" -token_in -digest ${digestHex} -sha256 -CAfile "${nodeRootsPath}" -untrusted "${tokenCertsPath}"`,
  );
  console.log(
    '    Should print "Verification: OK" — openssl independently confirming the CMS signature chains to a ' +
      "real trusted root and that the messageImprint matches the digest above, not this project's own " +
      "verification code agreeing with itself.",
  );

  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error(err);
  await prisma.$disconnect();
  process.exit(1);
});
