// scripts/create-first-admin.ts
//
// Creates the first ADMIN account from environment variables — the only
// way an ADMIN account can ever be created. POST /api/auth/register
// deliberately excludes ADMIN from its accepted roles (routes/auth.ts),
// so there is no HTTP path to self-register as an admin; this script is
// the sole bootstrap mechanism, meant to be run once per deployment.
//
// Usage:
//   ADMIN_NAME="..." ADMIN_EMAIL="..." ADMIN_PASSWORD="..." node scripts/create-first-admin.ts
//
// Refuses to run if an ADMIN account already exists, so re-running it by
// accident (or as part of a deploy script) is a safe no-op, not a way to
// mint extra admins.

import "dotenv/config";
import bcrypt from "bcrypt";
import { prisma } from "../lib/prisma.ts";
import { generateUserKeyPair, issueCertificate } from "../lib/ca.ts";

const BCRYPT_SALT_ROUNDS = 10;

async function main() {
  const name = process.env.ADMIN_NAME;
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;

  if (!name || !email || !password) {
    console.error(
      "Usage: ADMIN_NAME=... ADMIN_EMAIL=... ADMIN_PASSWORD=... node scripts/create-first-admin.ts",
    );
    process.exit(1);
  }
  if (password.length < 8) {
    console.error("ADMIN_PASSWORD must be at least 8 characters");
    process.exit(1);
  }

  const existingAdmin = await prisma.user.findFirst({ where: { role: "ADMIN" } });
  if (existingAdmin) {
    console.log(`An ADMIN account already exists (${existingAdmin.email}). Nothing to do.`);
    await prisma.$disconnect();
    return;
  }

  const existingEmail = await prisma.user.findUnique({ where: { email: email.trim().toLowerCase() } });
  if (existingEmail) {
    console.error(`A user with email ${email} already exists (role: ${existingEmail.role}).`);
    process.exit(1);
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

  const certificate = await issueCertificate({
    id: admin.id,
    name: admin.name,
    role: admin.role,
    publicKey: admin.publicKey,
  });

  console.log(`Created first ADMIN: ${admin.name} <${admin.email}> (id: ${admin.id})`);
  console.log(`Certificate issued: ${certificate.id} (expires ${certificate.expiresAt})`);

  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error(err);
  await prisma.$disconnect();
  process.exit(1);
});
