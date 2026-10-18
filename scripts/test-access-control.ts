// scripts/test-access-control.ts
//
// HTTP-level matrix of identity-based access control: role x endpoint,
// and the object-level ownership rules on top of role alone — checking
// for exactly the status code each combination should produce (200, 403,
// or 404), against a RUNNING server (node server.ts on localhost:4000),
// using the real client-side crypto module (no mocks) to register users
// precisely as the browser would.
//
// Refuses to run unless TEST_DATABASE_URL is set AND equals DATABASE_URL
// (this script revokes a real certificate mid-run) — same explicit
// confirmation as scripts/attack-simulation.ts. Reads ADMIN_EMAIL/
// ADMIN_PASSWORD from the environment, no hardcoded fallback (this repo
// is public) — exits with a clear message if either is missing.
//
// One rule this suite does NOT exercise end-to-end over HTTP: "nobody
// approves at two stages of the same transaction." Under this app's
// strict one-role-per-account model, a Landowner account can never also
// hold a Village Officer or Registrar role, so the existing role gate
// alone already makes that violation unreachable through the live API —
// routes/transactions.ts's reviewerIsPriorSigner() (the guard that would
// catch it regardless) is unit-tested directly in
// test/accessControl.test.ts instead.
//
// Run with: node scripts/test-access-control.ts
// (server must already be running: node server.ts)

import "dotenv/config";
import {
  generateKeyPair,
  exportPublicKeySpkiPem,
  fingerprintOfPem,
  wrapPrivateKey,
  signCanonicalString,
} from "../frontend/src/lib/clientCrypto.ts";
import { canonicalStringify } from "../frontend/src/lib/canonicalize.ts";

if (!process.env.TEST_DATABASE_URL || process.env.TEST_DATABASE_URL !== process.env.DATABASE_URL) {
  console.error(
    "Refusing to run: TEST_DATABASE_URL is not set, or does not match DATABASE_URL.\n" +
      "This script revokes a real certificate as part of the matrix and must only ever run " +
      "against a disposable test database.\n" +
      "Set TEST_DATABASE_URL to the exact same value as DATABASE_URL to confirm that's what you intend.",
  );
  process.exit(1);
}
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
  console.error(
    "Refusing to run: ADMIN_EMAIL and ADMIN_PASSWORD env vars must both be set, matching an " +
      "existing ADMIN account (this script logs in as that admin to exercise admin-only endpoints " +
      "and to revoke a certificate mid-run).",
  );
  process.exit(1);
}
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const BASE = "http://localhost:4000/api";
const PASSWORD = "accesscontroltest123!";

let failures = 0;
function check(label: string, expectedStatus: number, actualStatus: number, extra?: unknown) {
  const pass = expectedStatus === actualStatus;
  console.log(
    `${pass ? "PASS" : "FAIL"}: ${label} — expected ${expectedStatus}, got ${actualStatus}` +
      (extra !== undefined ? ` — ${JSON.stringify(extra)}` : ""),
  );
  if (!pass) failures++;
}

async function api(path: string, token: string | null, method = "GET", body?: unknown) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => null);
  return { status: res.status, data };
}

interface TestUser {
  id: string;
  email: string;
  token: string;
}

async function registerUser(name: string, email: string, role: string): Promise<TestUser> {
  const keyPair = await generateKeyPair();
  const publicKeyPem = await exportPublicKeySpkiPem(keyPair.publicKey);
  const fingerprint = await fingerprintOfPem(publicKeyPem);
  const proofTimestamp = new Date().toISOString();
  const canonicalProof = canonicalStringify({ email, fingerprint, timestamp: proofTimestamp });
  const proofSignature = await signCanonicalString(keyPair.privateKey, canonicalProof);
  const wrapped = await wrapPrivateKey(keyPair.privateKey, PASSWORD);

  const registerRes = await fetch(`${BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name,
      email,
      password: PASSWORD,
      role,
      publicKey: publicKeyPem,
      proofTimestamp,
      proofSignature,
      wrappedPrivateKey: wrapped.ciphertext,
      wrapSalt: wrapped.salt,
      wrapIv: wrapped.iv,
    }),
  });
  const registerBody = await registerRes.json();
  if (registerRes.status !== 201) throw new Error(`Registration failed for ${email}: ${JSON.stringify(registerBody)}`);

  const loginRes = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  const loginBody = await loginRes.json();
  if (loginRes.status !== 200) throw new Error(`Login failed for ${email}: ${JSON.stringify(loginBody)}`);

  return { id: registerBody.id, email, token: loginBody.token };
}

async function main() {
  const stamp = Date.now();

  const landownerA = await registerUser("AC Landowner A", `ac-lo-a-${stamp}@example.com`, "LANDOWNER");
  const landownerB = await registerUser("AC Landowner B", `ac-lo-b-${stamp}@example.com`, "LANDOWNER");
  const vo = await registerUser("AC Village Officer", `ac-vo-${stamp}@example.com`, "VILLAGE_OFFICER");
  const registrar = await registerUser("AC Registrar", `ac-reg-${stamp}@example.com`, "REGISTRAR");

  const adminLogin = await api("/auth/login", null, "POST", { email: ADMIN_EMAIL, password: ADMIN_PASSWORD });
  if (adminLogin.status !== 200) {
    throw new Error(`Admin login failed: ${JSON.stringify(adminLogin.data)}`);
  }
  const adminToken = adminLogin.data.token as string;

  // --- Setup: one land record per landowner, via the real Registrar flow ---
  const lrA = await api("/land-records", registrar.token, "POST", {
    surveyNumber: `SN-AC-A-${stamp}`,
    location: "Access Control Test Village",
    area: 1,
    currentOwnerId: landownerA.id,
  });
  check("setup: Registrar creates land record A", 201, lrA.status);
  const landRecordAId = lrA.data.id as string;

  const lrB = await api("/land-records", registrar.token, "POST", {
    surveyNumber: `SN-AC-B-${stamp}`,
    location: "Access Control Test Village",
    area: 1,
    currentOwnerId: landownerB.id,
  });
  const landRecordBId = lrB.data.id as string;

  console.log("\n--- A. Certificate-bound authorization (role x endpoint) ---\n");

  {
    const res = await api("/land-records", landownerA.token, "POST", {
      surveyNumber: `SN-AC-REJECT-${stamp}`,
      location: "x",
      area: 1,
      currentOwnerId: landownerA.id,
    });
    check("Landowner cannot create a land record", 403, res.status, res.data);
  }
  {
    const res = await api("/land-records", adminToken, "POST", {
      surveyNumber: `SN-AC-REJECT2-${stamp}`,
      location: "x",
      area: 1,
      currentOwnerId: landownerA.id,
    });
    check("Admin cannot create a land record", 403, res.status, res.data);
  }
  {
    const res = await api("/transactions/prepare", vo.token, "POST", {
      type: "REGISTRATION",
      landRecordId: landRecordAId,
      documentPath: "uploads/does-not-matter.pdf",
      documentHash: "0".repeat(64),
    });
    check("Village Officer cannot prepare a landowner transaction", 403, res.status, res.data);
  }
  {
    const res = await api("/transactions/prepare", adminToken, "POST", {
      type: "REGISTRATION",
      landRecordId: landRecordAId,
      documentPath: "uploads/does-not-matter.pdf",
      documentHash: "0".repeat(64),
    });
    check("Admin cannot sign a land transaction", 403, res.status, res.data);
  }
  {
    const res = await api("/transactions/pending-vo", registrar.token, "GET");
    check("Registrar cannot read the Village Officer queue", 403, res.status, res.data);
  }
  {
    const res = await api("/transactions/pending-vo", vo.token, "GET");
    check("Village Officer can read the Village Officer queue", 200, res.status);
  }
  {
    const res = await api("/certificates/does-not-exist/revoke", registrar.token, "POST", { reason: "x" });
    check("Registrar cannot revoke a certificate", 403, res.status, res.data);
  }
  {
    const res = await api("/audit/anchors", landownerA.token, "GET");
    check("Landowner cannot read audit anchors", 403, res.status, res.data);
  }
  {
    const res = await api("/audit/anchors", adminToken, "GET");
    check("Admin can read audit anchors", 200, res.status);
  }
  {
    const res = await api("/audit/anchor", adminToken, "POST");
    // "anchored" or "skipped-too-soon"/"skipped-empty-chain" are all a
    // real 200 — only a TSA-side failure is the non-200 (502) outcome.
    check("Admin can call anchor-now", 200, res.status, res.data);
  }

  console.log("\n--- B. Object-level access ---\n");

  {
    const res = await api(`/land-records/${landRecordAId}/history`, landownerA.token, "GET");
    check("Landowner can read their own land record", 200, res.status);
  }
  {
    const res = await api(`/land-records/${landRecordAId}/history`, landownerB.token, "GET");
    check("Landowner cannot read another landowner's record (404, not 403)", 404, res.status, res.data);
  }
  {
    const res = await api(`/land-records/${landRecordBId}/history`, landownerA.token, "GET");
    check("Landowner cannot read another landowner's record, symmetric case (404)", 404, res.status, res.data);
  }
  {
    const res = await api(`/land-records/${landRecordAId}/history`, vo.token, "GET");
    check("Village Officer can read any land record (needs visibility to review)", 200, res.status);
  }
  {
    const res = await api(`/land-records/does-not-exist/history`, landownerA.token, "GET");
    check("A genuinely nonexistent land record is also 404 (indistinguishable from not-yours)", 404, res.status);
  }

  console.log("\n--- A (continued): a revoked identity is rejected with reason CERT_REVOKED ---\n");

  {
    const certLookup = await api(`/certificates/${landownerB.id}`, adminToken, "GET");
    const revoke = await api(`/certificates/${certLookup.data.id}/revoke`, adminToken, "POST", {
      reason: "access-control test",
    });
    check("setup: Admin revokes Landowner B's certificate", 200, revoke.status);

    const res = await api("/transactions/prepare", landownerB.token, "POST", {
      type: "REGISTRATION",
      landRecordId: landRecordBId,
      documentPath: "uploads/does-not-matter.pdf",
      documentHash: "0".repeat(64),
    });
    check("A revoked Landowner cannot prepare a transaction", 403, res.status, res.data);
    const reasonOk = res.data?.reason === "CERT_REVOKED";
    console.log(`${reasonOk ? "PASS" : "FAIL"}: denial reason is CERT_REVOKED — got ${res.data?.reason}`);
    if (!reasonOk) failures++;
  }

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  if (failures > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
