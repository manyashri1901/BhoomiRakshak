// scripts/test-certificate-lookup.ts
//
// HTTP-level tests for the Certificate Lookup rework — the parts that
// genuinely need the Express route + role-middleware layer, which the
// node --test unit tests (test/certificate.test.ts) can't exercise since
// they call lib/ca.ts directly. Same pattern as scripts/attack-simulation.ts:
// registers real users via the actual client-crypto module (no mocks) and
// hits a RUNNING server.
//
// Run with: node scripts/test-certificate-lookup.ts
// (server must already be running: node server.ts)

import "dotenv/config";
import assert from "node:assert/strict";
import {
  generateKeyPair,
  exportPublicKeySpkiPem,
  fingerprintOfPem,
  wrapPrivateKey,
  signCanonicalString,
} from "../frontend/src/lib/clientCrypto.ts";
import { canonicalStringify } from "../frontend/src/lib/canonicalize.ts";

const BASE = "http://localhost:4000/api";
const PASSWORD = "lookuptest123";

async function api(path: string, token: string | null, method = "GET") {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  const data = await res.json().catch(() => null);
  return { status: res.status, data };
}

async function registerUser(name: string, email: string, role: string) {
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

  return { id: registerBody.id, token: loginBody.token as string };
}

const FORBIDDEN_KEYS = ["email", "passwordHash", "wrappedPrivateKey", "wrapSalt", "wrapIv"];

function assertNoPrivateFields(obj: Record<string, unknown>, label: string) {
  for (const key of FORBIDDEN_KEYS) {
    assert.ok(!(key in obj), `${label}: response must not contain "${key}", got keys ${Object.keys(obj).join(", ")}`);
  }
}

async function main() {
  const stamp = Date.now();
  console.log("Registering test users...");
  const landowner = await registerUser("Lookup Test Landowner", `lookup-lo-${stamp}@example.com`, "LANDOWNER");
  const villageOfficer = await registerUser("Lookup Test VO", `lookup-vo-${stamp}@example.com`, "VILLAGE_OFFICER");

  let failures = 0;
  function check(label: string, pass: boolean) {
    console.log(`${pass ? "PASS" : "FAIL"} — ${label}`);
    if (!pass) failures += 1;
  }

  // 1. Landowner name search returns 403.
  const landownerSearch = await api(`/certificates/search?q=Lookup`, landowner.token);
  check(
    "landowner name search returns 403",
    landownerSearch.status === 403,
  );

  // 2. Village Officer CAN search (control case — proves the 403 above is
  // role-specific, not just broken for everyone).
  const voSearch = await api(`/certificates/search?q=Lookup`, villageOfficer.token);
  check("Village Officer name search succeeds (200)", voSearch.status === 200);
  check(
    "search results contain no private fields",
    Array.isArray(voSearch.data?.results) &&
      voSearch.data.results.every((row: Record<string, unknown>) => {
        assertNoPrivateFields(row, "search result row");
        return true;
      }),
  );

  // 3. Exact lookup by serial — any authenticated user (landowner included).
  //    First resolve the landowner's own certificate's real X.509 serial via
  //    the (untouched) legacy by-user-id endpoint, exactly as
  //    AdminDashboard already does.
  const legacyLookup = await api(`/certificates/${landowner.id}`, landowner.token);
  check("legacy /:userId lookup still works unchanged", legacyLookup.status === 200);
  const serial = legacyLookup.data?.serialNumber as string;

  const serialLookup = await api(`/certificates/serial/${serial}`, landowner.token);
  check("landowner CAN look up an exact serial (200)", serialLookup.status === 200);
  check(
    "serial lookup response has no private fields",
    (() => {
      if (!serialLookup.data) return false;
      assertNoPrivateFields(serialLookup.data, "serial lookup");
      return true;
    })(),
  );
  check(
    "serial lookup response carries the raw certificate PEMs, not a server-computed verdict",
    serialLookup.data &&
      typeof serialLookup.data.certificatePem === "string" &&
      typeof serialLookup.data.issuingCertificatePem === "string" &&
      serialLookup.data.serialNumber === serial &&
      !("valid" in serialLookup.data) &&
      !("reason" in serialLookup.data) &&
      !("revoked" in serialLookup.data),
  );
  // The api() helper above discards headers; redo this one call directly
  // to inspect Cache-Control.
  const rawRes = await fetch(`${BASE}/certificates/serial/${serial}`, {
    headers: { Authorization: `Bearer ${landowner.token}` },
  });
  const cacheControl = rawRes.headers.get("cache-control") ?? "";
  check(
    `serial lookup Cache-Control is private+immutable (got "${cacheControl}")`,
    cacheControl.includes("immutable") && cacheControl.includes("private"),
  );

  // 4. CA public certificates + fingerprint endpoint.
  const caInfo = await api("/certificates/ca", landowner.token);
  check(
    "GET /certificates/ca returns rootCertPem/issuingCertPem/fingerprint",
    caInfo.status === 200 &&
      typeof caInfo.data?.rootCertPem === "string" &&
      typeof caInfo.data?.issuingCertPem === "string" &&
      typeof caInfo.data?.fingerprint === "string",
  );

  // 5. Signed CRL endpoint — a real X.509 CRL PEM, not a canonicalStringify
  // JSON payload.
  const signedCrl = await api("/certificates/crl/signed", landowner.token);
  check(
    "GET /certificates/crl/signed returns a real CRL PEM with thisUpdate/nextUpdate",
    signedCrl.status === 200 &&
      typeof signedCrl.data?.pem === "string" &&
      signedCrl.data.pem.includes("BEGIN CRL") &&
      typeof signedCrl.data?.thisUpdate === "string" &&
      typeof signedCrl.data?.nextUpdate === "string",
  );

  // 6. /api/users min-length enumeration fix.
  const shortQuery = await api(`/users?q=lo`, landowner.token);
  check(
    "/api/users with a 2-char query returns []",
    shortQuery.status === 200 && Array.isArray(shortQuery.data) && shortQuery.data.length === 0,
  );
  const noQuery = await api(`/users`, landowner.token);
  check(
    "/api/users with no query returns []",
    noQuery.status === 200 && Array.isArray(noQuery.data) && noQuery.data.length === 0,
  );
  const longEnoughQuery = await api(`/users?q=Lookup`, landowner.token);
  check(
    "/api/users with a 3+ char query still works and caps at 10",
    longEnoughQuery.status === 200 &&
      Array.isArray(longEnoughQuery.data) &&
      longEnoughQuery.data.length <= 10 &&
      longEnoughQuery.data.every((row: Record<string, unknown>) => {
        assertNoPrivateFields(row, "/api/users result row");
        return true;
      }),
  );

  console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
