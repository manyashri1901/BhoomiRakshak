// scripts/create-first-admin.ts
//
// Creates the first ADMIN account from environment variables — the only
// way an ADMIN account can ever be created. POST /api/auth/register
// deliberately excludes ADMIN from its accepted roles (routes/auth.ts),
// so there is no HTTP path to self-register as an admin; this script (or
// scripts/first-run.ts, which calls the same function) is the sole
// bootstrap mechanism, meant to be run once per deployment.
//
// Usage:
//   ADMIN_NAME="..." ADMIN_EMAIL="..." ADMIN_PASSWORD="..." node scripts/create-first-admin.ts
//
// Refuses to run if an ADMIN account already exists, so re-running it by
// accident (or as part of a deploy script) is a safe no-op, not a way to
// mint extra admins.

import "dotenv/config";
import bcrypt from "bcrypt";
import { pathToFileURL } from "node:url";
import { prisma } from "../lib/prisma.ts";
import { generateUserKeyPair, issueCertificate } from "../lib/ca.ts";

const BCRYPT_SALT_ROUNDS = 10;

export type CreateFirstAdminResult =
  | { created: true; id: string; name: string; email: string }
  | { created: false; reason: string };

/**
 * Creates the first ADMIN from ADMIN_NAME/ADMIN_EMAIL/ADMIN_PASSWORD env
 * vars if (and only if) no ADMIN exists yet. Safe to call on every
 * deployment/startup — a second call is always a no-op, never a second
 * admin or an error.
 */
export async function createFirstAdminIfMissing(): Promise<CreateFirstAdminResult> {
  const name = process.env.ADMIN_NAME;
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;

  if (!name || !email || !password) {
    return { created: false, reason: "ADMIN_NAME, ADMIN_EMAIL, and ADMIN_PASSWORD must all be set" };
  }
  if (password.length < 10) {
    return { created: false, reason: "ADMIN_PASSWORD must be at least 10 characters" };
  }

  const existingAdmin = await prisma.user.findFirst({ where: { role: "ADMIN" } });
  if (existingAdmin) {
    return { created: false, reason: `An ADMIN account already exists (${existingAdmin.email})` };
  }

  const existingEmail = await prisma.user.findUnique({ where: { email: email.trim().toLowerCase() } });
  if (existingEmail) {
    return { created: false, reason: `A user with email ${email} already exists (role: ${existingEmail.role})` };
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
  // An ADMIN account never signs anything — only LANDOWNER/VILLAGE_OFFICER/
  // REGISTRAR accounts generate a key pair in the browser and sign
  // transactions with it. generateUserKeyPair() here is purely so this
  // account has *a* public key to bind a certificate to; the private key
  // is discarded immediately rather than stored, wrapped or not — there's
  // nothing for it to ever sign.
  const { publicKey } = generateUserKeyPair();

  const admin = await prisma.user.create({
    data: {
      name: name.trim(),
      email: email.trim().toLowerCase(),
      passwordHash,
      role: "ADMIN",
      publicKey,
    },
  });

  await issueCertificate({ id: admin.id, name: admin.name, role: admin.role, publicKey: admin.publicKey });

  return { created: true, id: admin.id, name: admin.name, email: admin.email };
}

async function main() {
  const result = await createFirstAdminIfMissing();
  if (result.created) {
    console.log(`Created first ADMIN: ${result.name} <${result.email}> (id: ${result.id})`);
  } else {
    console.log(result.reason);
  }
  await prisma.$disconnect();
}

// Only auto-run when this file is executed directly (e.g. `npm run
// bootstrap-admin`) — not when scripts/first-run.ts imports
// createFirstAdminIfMissing() as a library function, which would
// otherwise run this a second time and print its result twice.
const isDirectRun = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isDirectRun) {
  main().catch(async (err) => {
    console.error(err);
    await prisma.$disconnect();
    process.exit(1);
  });
}
