// routes/auth.ts
//
// POST /api/auth/register — create a user, their PKI keypair, and their
//                            CA-issued certificate.
// POST /api/auth/login    — verify credentials, issue a session JWT.
// GET  /api/auth/me       — the logged-in user's display info (the JWT
//                            deliberately only carries {userId, role}, so
//                            the frontend nav needs a way to get the name).

import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { prisma } from "../lib/prisma.ts";
import { requireAuth } from "../middleware/auth.ts";
import { loginRateLimiter, registerRateLimiter } from "../middleware/rateLimit.ts";
import {
  generateUserKeyPair,
  proveKeyPossession,
  verifyKeyPossession,
  issueCertificate,
} from "../lib/ca.ts";
import { appendAuditEntry } from "../lib/audit.ts";
import type { Role } from "../generated/prisma/enums.ts";

const router = express.Router();

const VALID_ROLES: Role[] = ["LANDOWNER", "VILLAGE_OFFICER", "REGISTRAR"];
const BCRYPT_SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET as string;

// Login success/failure is high-volume and not something the PKI trust
// chain depends on (unlike registration, cert issuance/revocation, or a
// transaction's review stages — see lib/audit.ts), so it goes to
// structured console output instead of the audit hash chain: every write
// to that chain is serialized behind one advisory lock (see
// AUDIT_CHAIN_LOCK_KEY in lib/audit.ts), and every failed login attempt —
// exactly the traffic a brute-force or credential-stuffing attempt
// generates — would otherwise compete for that same lock with real,
// chain-worthy events. A structured line here is still fully greppable/
// ingestible by any log pipeline, just outside the tamper-evident chain.
function logAuthEvent(event: "LOGIN_FAILURE" | "LOGIN_SUCCESS", fields: Record<string, unknown>) {
  console.log(JSON.stringify({ level: "info", event, timestamp: new Date().toISOString(), ...fields }));
}

router.post("/register", registerRateLimiter, async (req, res) => {
  const { name, email, password, role } = req.body ?? {};

  if (typeof name !== "string" || !name.trim()) {
    res.status(400).json({ error: "name is required" });
    return;
  }
  if (typeof email !== "string" || !email.trim()) {
    res.status(400).json({ error: "email is required" });
    return;
  }
  if (typeof password !== "string" || password.length < 8) {
    res.status(400).json({ error: "password must be at least 8 characters" });
    return;
  }
  if (typeof role !== "string" || !VALID_ROLES.includes(role as Role)) {
    res.status(400).json({ error: `role must be one of ${VALID_ROLES.join(", ")}` });
    return;
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

  // This user's own RSA keypair (separate from the CA's own keypair in keys/).
  const { publicKey, privateKey } = generateUserKeyPair();

  // Proof of possession: before this keypair goes anywhere near a
  // certificate, prove the private key we hold really signs for the
  // public key we're about to publish. Guards against a corrupted keypair
  // now, and against a submitted-not-generated public key if this flow is
  // ever changed to accept client-generated keys.
  const proof = proveKeyPossession(privateKey);
  const possessionValid = verifyKeyPossession(publicKey, proof.nonce, proof.signature);
  if (!possessionValid) {
    res.status(500).json({ error: "Key possession check failed; registration aborted" });
    return;
  }

  try {
    const user = await prisma.user.create({
      data: {
        name: name.trim(),
        email: email.trim().toLowerCase(),
        passwordHash,
        role: role as Role,
        publicKey,
        // MVP ONLY: the raw private key PEM is stored server-side (in the
        // field named privateKeyRef) so this demo can sign on the user's
        // behalf without a client-side keystore. A production system would
        // never hold a user's private key in plaintext on the server —
        // it would be generated and kept client-side (browser/mobile
        // secure storage) or managed by an HSM/KMS, with the server only
        // ever seeing the public key.
        privateKeyRef: privateKey,
      },
    });

    const certificate = await issueCertificate({
      id: user.id,
      name: user.name,
      role: user.role,
      publicKey: user.publicKey,
    });

    await appendAuditEntry({
      action: "USER_REGISTERED",
      actorUserId: user.id,
      entityType: "USER",
      entityId: user.id,
      details: { name: user.name, email: user.email, role: user.role },
    });

    // Never echo passwordHash or privateKeyRef back to the client.
    res.status(201).json({
      id: user.id,
      name: user.name,
      role: user.role,
      certificate: {
        id: certificate.id,
        issuer: certificate.issuer,
        issuedAt: certificate.issuedAt,
        fingerprint: certificate.fingerprint,
      },
    });
  } catch (err: unknown) {
    if (typeof err === "object" && err !== null && "code" in err && err.code === "P2002") {
      res.status(409).json({ error: "Email already registered" });
      return;
    }
    throw err;
  }
});

router.post("/login", loginRateLimiter, async (req, res) => {
  const { email, password } = req.body ?? {};

  if (typeof email !== "string" || typeof password !== "string") {
    res.status(400).json({ error: "email and password are required" });
    return;
  }
  const normalizedEmail = email.trim().toLowerCase();

  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });

  // Same error for "no such user" and "wrong password" so login can't be
  // used to enumerate registered emails.
  if (!user) {
    logAuthEvent("LOGIN_FAILURE", { email: normalizedEmail, reason: "No such user" });
    res.status(401).json({ error: "Invalid email or password" });
    return;
  }

  const passwordValid = await bcrypt.compare(password, user.passwordHash);
  if (!passwordValid) {
    logAuthEvent("LOGIN_FAILURE", { userId: user.id, email: normalizedEmail, reason: "Wrong password" });
    res.status(401).json({ error: "Invalid email or password" });
    return;
  }

  const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, {
    expiresIn: "1h",
  });

  logAuthEvent("LOGIN_SUCCESS", { userId: user.id, email: normalizedEmail });

  res.json({ token });
});

router.get("/me", requireAuth, async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.user!.userId } });
  if (!user) {
    res.status(401).json({ error: "User no longer exists" });
    return;
  }

  res.json({ id: user.id, name: user.name, role: user.role });
});

export default router;
