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
import { verifyRegistrationProof, issueCertificate } from "../lib/ca.ts";
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
  const {
    name,
    email,
    password,
    role,
    publicKey,
    proofTimestamp,
    proofSignature,
    wrappedPrivateKey,
    wrapSalt,
    wrapIv,
  } = req.body ?? {};

  if (typeof name !== "string" || !name.trim()) {
    res.status(400).json({ error: "name is required" });
    return;
  }
  if (typeof email !== "string" || !email.trim()) {
    res.status(400).json({ error: "email is required" });
    return;
  }
  if (typeof password !== "string" || password.length < 10) {
    res.status(400).json({ error: "password must be at least 10 characters" });
    return;
  }
  if (typeof role !== "string" || !VALID_ROLES.includes(role as Role)) {
    res.status(400).json({ error: `role must be one of ${VALID_ROLES.join(", ")}` });
    return;
  }
  // The key pair is generated in the browser — see
  // frontend/src/lib/clientCrypto.ts. The server only ever receives the
  // public key, a proof that the browser holds the matching private key,
  // and that private key already wrapped (AES-256-GCM, key derived from
  // the user's password via PBKDF2) so it can never be read back out in
  // usable form, by this server or anyone with read access to its database.
  if (typeof publicKey !== "string" || !publicKey.trim()) {
    res.status(400).json({ error: "publicKey is required" });
    return;
  }
  if (typeof proofTimestamp !== "string" || typeof proofSignature !== "string") {
    res.status(400).json({ error: "proofTimestamp and proofSignature are required" });
    return;
  }
  if (
    typeof wrappedPrivateKey !== "string" ||
    typeof wrapSalt !== "string" ||
    typeof wrapIv !== "string" ||
    !wrappedPrivateKey ||
    !wrapSalt ||
    !wrapIv
  ) {
    res.status(400).json({ error: "wrappedPrivateKey, wrapSalt, and wrapIv are required" });
    return;
  }

  const normalizedEmail = email.trim().toLowerCase();

  const proof = verifyRegistrationProof({
    email: normalizedEmail,
    publicKey,
    timestamp: proofTimestamp,
    signature: proofSignature,
  });
  if (!proof.valid) {
    res.status(400).json({ error: `Key possession proof failed: ${proof.reason}` });
    return;
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

  try {
    const user = await prisma.user.create({
      data: {
        name: name.trim(),
        email: normalizedEmail,
        passwordHash,
        role: role as Role,
        publicKey,
        wrappedPrivateKey,
        wrapSalt,
        wrapIv,
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

    // Never echo passwordHash, wrappedPrivateKey, or wrap salt/iv back here
    // — the browser already has all three (it just generated/wrapped them);
    // echoing them back would gain nothing and only widen where they
    // appear in logs/responses.
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

  // Checked only after the password is confirmed correct — otherwise an
  // unauthenticated prober could use this response to learn an account's
  // deceased status from the email alone. Set only by an approved
  // SUCCESSION transaction (routes/transactions.ts); there is no path back
  // from DECEASED to ACTIVE.
  if (user.status === "DECEASED") {
    logAuthEvent("LOGIN_FAILURE", { userId: user.id, email: normalizedEmail, reason: "Account marked deceased" });
    res.status(403).json({ error: "This account is no longer active." });
    return;
  }

  const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, {
    expiresIn: "1h",
  });

  logAuthEvent("LOGIN_SUCCESS", { userId: user.id, email: normalizedEmail });

  // The wrapped key blob is useless without the password that was just
  // verified above (and that password is never stored — only its bcrypt
  // hash is) to re-derive the AES key client-side, so returning it here is
  // safe: this response is the ONE place the browser can get its wrapped
  // key back on a fresh session. Null for ADMIN (never signs anything) and
  // for any account created before this field existed.
  res.json({
    token,
    wrappedKey:
      user.wrappedPrivateKey && user.wrapSalt && user.wrapIv
        ? { ciphertext: user.wrappedPrivateKey, salt: user.wrapSalt, iv: user.wrapIv }
        : null,
  });
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
