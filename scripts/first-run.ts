// scripts/first-run.ts
//
// One script to bring a fresh deployment up: applies pending migrations,
// bootstraps the two-tier CA (root + issuing) if either is absent, and
// creates the first ADMIN account from env vars. No seed/demo data is
// created anywhere in this path. Safe to run twice — every step here is a
// no-op on a second run except the migration check, which only ever
// applies migrations that haven't run yet.
//
// Run with: npm run first-run
// (requires DATABASE_URL, JWT_SECRET, and — to create the admin —
// ADMIN_NAME/ADMIN_EMAIL/ADMIN_PASSWORD already set in the environment)

import "dotenv/config";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { prisma } from "../lib/prisma.ts";
import { bootstrapCAHierarchy } from "../lib/ca.ts";
import { createFirstAdminIfMissing } from "./create-first-admin.ts";

function step(label: string) {
  console.log(`\n=== ${label} ===`);
}

// Same CA_KEYS_DIR override as lib/ca.ts (must stay consistent with it —
// both independently derive CA_DIR from process.cwd() + "keys" otherwise).
const CA_DIR = process.env.CA_KEYS_DIR ? path.resolve(process.env.CA_KEYS_DIR) : path.join(process.cwd(), "keys");
const ROOT_CERT_PATH = path.join(CA_DIR, "root-ca-cert.pem");
const ISSUING_PRIVATE_KEY_PATH = path.join(CA_DIR, "issuing-ca-private.pem");
const ISSUING_CERT_PATH = path.join(CA_DIR, "issuing-ca-cert.pem");
const DEPLOY_ENV_PATH = path.join(CA_DIR, "deploy-env.txt");

async function main() {
  step("1. Database migrations");
  const migrate = spawnSync("npx", ["prisma", "migrate", "deploy"], {
    stdio: "inherit",
    shell: process.platform === "win32",
  });
  if (migrate.status !== 0) {
    console.error("Migration failed — stopping here. Fix the error above and re-run.");
    process.exit(1);
  }

  step("2. Certificate Authority (root + issuing)");
  // Checked BEFORE calling bootstrapCAHierarchy() — that function itself
  // never logs or prints anything (see its own doc comment); this script
  // decides what to tell the operator based on what it already knew
  // existed before the call, exactly the same pattern the single-tier CA
  // this replaces used.
  const hadRootAlready = Boolean(process.env.ROOT_CA_CERT_BASE64) || fs.existsSync(ROOT_CERT_PATH);
  const hadIssuingAlready =
    Boolean(process.env.ISSUING_CA_PRIVATE_KEY_BASE64 && process.env.ISSUING_CA_CERT_BASE64) ||
    (fs.existsSync(ISSUING_PRIVATE_KEY_PATH) && fs.existsSync(ISSUING_CERT_PATH));

  const bootstrap = await bootstrapCAHierarchy();

  if (hadRootAlready && hadIssuingAlready) {
    console.log("Loaded existing root + issuing CA — nothing to generate.");
  } else {
    const deployEnvLines: string[] = [];

    if (bootstrap.rootGenerated) {
      console.log("Generated a NEW root CA key pair (first run on this machine/environment).");
      console.log(
        "Its PRIVATE key has been written to keys/root-offline/root-ca-private.pem and NOWHERE else —",
      );
      console.log(
        "move that file off this machine now (offline storage, a hardware token, etc.) and delete it",
      );
      console.log(
        "from this disk once it's safely elsewhere. This running server never loads it again; only",
      );
      console.log("scripts/first-run.ts (to sign a new Issuing CA) and a human renewing the chain ever need it.\n");
      console.log("Its CERTIFICATE (public — safe to share/commit to config, just not to git) is:");
      console.log("ROOT_CA_CERT_BASE64=" + bootstrap.rootCertBase64);
      deployEnvLines.push("ROOT_CA_CERT_BASE64=" + bootstrap.rootCertBase64);
    }
    if (bootstrap.issuingGenerated) {
      console.log(
        bootstrap.rootGenerated ? "\nGenerated a NEW issuing CA, signed by the root above." : "Generated a NEW issuing CA.",
      );
      console.log("Its CERTIFICATE (public) is:");
      console.log("ISSUING_CA_CERT_BASE64=" + bootstrap.issuingCertBase64);
      deployEnvLines.push("ISSUING_CA_CERT_BASE64=" + bootstrap.issuingCertBase64);
      // The PRIVATE key never goes to stdout (shell history, CI logs, a
      // screen share) — only to a git-ignored file on disk. keys/ as a
      // whole is covered by .gitignore's `/keys` rule.
      deployEnvLines.push("ISSUING_CA_PRIVATE_KEY_BASE64=" + bootstrap.issuingPrivateKeyBase64);
      if (!bootstrap.rootGenerated) {
        // The root cert didn't change this run, but the running server
        // still needs it alongside the issuing key/cert above.
        const rootCertBase64 = Buffer.from(fs.readFileSync(ROOT_CERT_PATH, "utf8"), "utf8").toString("base64");
        console.log("ROOT_CA_CERT_BASE64=" + rootCertBase64);
        deployEnvLines.push("ROOT_CA_CERT_BASE64=" + rootCertBase64);
      }

      fs.writeFileSync(DEPLOY_ENV_PATH, deployEnvLines.join("\n") + "\n", { mode: 0o600 });
      console.log(
        `\nIf this deployment's disk is ephemeral (e.g. Render), copy the contents of ${DEPLOY_ENV_PATH}`,
      );
      console.log(
        "into your platform's SECRET env vars now (not plain env vars) — keys/ will not survive a redeploy there.",
      );
      console.log(
        `That file includes ISSUING_CA_PRIVATE_KEY_BASE64 — the private key itself — so treat it exactly like`,
      );
      console.log(
        "the private key file it's derived from: don't commit it, paste it into chat, or copy it into a log.",
      );
    }
  }

  step("3. First ADMIN account");
  const adminResult = await createFirstAdminIfMissing();
  if (adminResult.created) {
    console.log(`Created first ADMIN: ${adminResult.name} <${adminResult.email}> (id: ${adminResult.id})`);
  } else {
    console.log(adminResult.reason);
  }

  step("Done");
  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error(err);
  await prisma.$disconnect();
  process.exit(1);
});
