// scripts/first-run.ts
//
// One script to bring a fresh deployment up: applies pending migrations,
// generates the CA root key pair if one doesn't exist yet (locally or via
// env vars — see lib/ca.ts), and creates the first ADMIN account from env
// vars. No seed/demo data is created anywhere in this path. Safe to run
// twice — every step here is a no-op on a second run except the migration
// check, which only ever applies migrations that haven't run yet.
//
// Run with: npm run first-run
// (requires DATABASE_URL, JWT_SECRET, and — to create the admin —
// ADMIN_NAME/ADMIN_EMAIL/ADMIN_PASSWORD already set in the environment)

import "dotenv/config";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { prisma } from "../lib/prisma.ts";
import { ensureRootCA } from "../lib/ca.ts";
import { createFirstAdminIfMissing } from "./create-first-admin.ts";

function step(label: string) {
  console.log(`\n=== ${label} ===`);
}

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

  step("2. Certificate Authority root key");
  const usingEnvKeys = Boolean(process.env.CA_PRIVATE_KEY_BASE64 && process.env.CA_PUBLIC_KEY_BASE64);
  const CA_PRIVATE_KEY_PATH = path.join(process.cwd(), "keys", "ca-private.pem");
  const hadLocalKeysAlready = fs.existsSync(CA_PRIVATE_KEY_PATH);

  if (usingEnvKeys) {
    ensureRootCA();
    console.log("Loaded CA key pair from CA_PRIVATE_KEY_BASE64 / CA_PUBLIC_KEY_BASE64 — nothing to generate.");
  } else if (hadLocalKeysAlready) {
    ensureRootCA();
    console.log("Loaded existing CA key pair from keys/ca-private.pem.");
  } else {
    const { privateKey, publicKey } = ensureRootCA();
    console.log("Generated a NEW CA root key pair (first run on this machine/environment).");
    console.log(
      "If this deployment's disk is ephemeral (e.g. Render), copy BOTH values below into your",
    );
    console.log(
      "platform's SECRET env vars now (not plain env vars) — keys/ will not survive a redeploy there.",
    );
    console.log(
      "Do not commit these, paste them into chat, or leave them in a shell history / log file.\n",
    );
    console.log("CA_PRIVATE_KEY_BASE64=" + Buffer.from(privateKey, "utf8").toString("base64"));
    console.log("CA_PUBLIC_KEY_BASE64=" + Buffer.from(publicKey, "utf8").toString("base64"));
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
