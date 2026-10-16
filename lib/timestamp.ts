// lib/timestamp.ts
//
// RFC 3161 trusted timestamping of the audit chain's head hash
// (lib/audit.ts's getAuditHead()) — an independent, third-party-attested
// "this hash existed no later than <genTime>", on top of (never replacing)
// the chain's own hash-link tamper evidence. Built entirely with pkijs +
// asn1js (no hand-rolled ASN.1 — ContentInfo/SignedData/TimeStampReq/
// TimeStampResp/TSTInfo are all real pkijs classes).
//
// WHAT GETS TIMESTAMPED: the audit head's `hash` field (hex, 32 bytes) is
// used as the MESSAGE pkijs's MessageImprint.create() hashes — i.e. the
// TSA's messageImprint.hashedMessage = SHA-256(headHashBytes), not
// headHashBytes verbatim. This is a deliberate one-line deviation from "use
// the head hash bytes as hashedMessage directly": pkijs's SignedData.verify()
// special-cases a TSTInfo-typed CMS payload (which this always is) by
// calling TSTInfo.verify({data}), which hashes `data` with the
// messageImprint's own algorithm and compares it to hashedMessage — this is
// the ONLY code path that lets pkijs check the messageImprint and the CMS
// signature together in one real, tested call, without hand-rolling either.
// Passing the raw head hash as `data` (so hashedMessage would equal it
// verbatim, unhashed) isn't an option: that requires skipping pkijs's own
// consistency check, which isn't exposed separately from the signature
// check. Treating headHashBytes as the message to hash (same as the real
// head hash existing is what's being attested either way) keeps every
// cryptographic check inside pkijs's own tested code.
//
// VERIFICATION (verifyAnchor(), per anchor, never short-circuited): each
// step below is computed and reported independently, exactly like
// lib/ca.ts's verifyCertificate() and frontend/src/lib/certificateVerify.ts
// — a report can say exactly which check failed, not just "invalid".
//   1. tokenParses     — the stored token decodes as CMS ContentInfo/SignedData.
//   2. messageImprint  — hashAlgorithm is SHA-256 and hashedMessage equals
//                        SHA-256(the anchor's own stored headHash bytes).
//   3. cmsSignature    — the CMS signature verifies against the TSA
//                        certificate carried in the token.
//   4. tsaCertificate  — that certificate has the timeStamping EKU and its
//                        chain validates to a trusted root (Node's own
//                        tls.rootCertificates, plus TSA_CA_CERT_BASE64 if
//                        set) AS OF genTime, not "now".
//   5. nonce           — the token's nonce matches the one this anchor sent.
//   6. genTime         — not further in the future than a small clock-skew
//                        allowance.
//   7. entryIntact     — the AuditLog row this anchor points at still
//                        exists, by id, and its CURRENT hash still equals
//                        headHash (the value that was actually anchored).
//   8. chainIntact     — verifyAuditChain()'s own full-chain walk reports
//                        no break at or before this anchor's seq (a break
//                        strictly AFTER it doesn't invalidate THIS anchor —
//                        a later anchor would be the one to catch that).
// Steps 7-8 are THE key security property this module adds over a plain
// CMS/TSP check: proving nothing *at or before* the anchored point was
// altered, even by someone who recomputed the entire chain afterward to
// make verifyAuditChain() alone pass again — recomputing the chain cannot
// also forge a new, independently-signed TSA token for the old (correct)
// hash.

import { webcrypto } from "node:crypto";
import * as tls from "node:tls";
import * as crypto from "node:crypto";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { prisma } from "./prisma.ts";
import { getAuditHead, verifyAuditChain } from "./audit.ts";

// ---------------------------------------------------------------------------
// 1. CONFIG + CRYPTO ENGINE
// ---------------------------------------------------------------------------

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

// DigiCert's public TSA: no registration, high uptime, widely used for code
// signing (so it's a realistic, well-maintained free TSA, not an obscure
// one) — its root is already in the Mozilla/Node trust set, so no
// TSA_CA_CERT_BASE64 is needed against the default.
export const TSA_URL = process.env.TSA_URL || "http://timestamp.digicert.com";
export const TSA_TIMEOUT_MS = envInt("TSA_TIMEOUT_MS", 8000);
export const TSA_MIN_INTERVAL_SECONDS = envInt("TSA_MIN_INTERVAL_SECONDS", 600);
// Deliberately NOT captured as a module-level const like the three above:
// trustedRootCertificates() below reads process.env.TSA_CA_CERT_BASE64
// fresh on every call. In production this makes no difference (dotenv
// loads .env before this module is ever imported), but a frozen constant
// would silently ignore the env var for the rest of the process if
// anything ever set it after import — exactly what test/timestamp.test.ts's
// in-process test TSA needs to do.

// How far into the future a TSA's genTime is still accepted as plausible
// clock skew rather than a sign something is wrong (a forged or
// badly-misconfigured TSA response).
const GENTIME_FUTURE_SKEW_MS = 5 * 60 * 1000;

const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const TIMESTAMPING_EKU_OID = "1.3.6.1.5.5.7.3.8";

// Registers Node's WebCrypto as pkijs's crypto provider — must happen
// before any pkijs operation in this process; idempotent, like
// lib/x509Keys.ts's equivalent call for @peculiar/x509.
pkijs.setEngine("nodeEngine", new pkijs.CryptoEngine({ name: "nodeEngine", crypto: webcrypto, subtle: webcrypto.subtle }));

function pemCertToPkijs(pem: string): pkijs.Certificate | null {
  try {
    const base64 = pem.replace(/-----BEGIN CERTIFICATE-----/, "").replace(/-----END CERTIFICATE-----/, "").replace(/\s+/g, "");
    const der = Buffer.from(base64, "base64");
    const asn1 = asn1js.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
    if (asn1.offset === -1) return null;
    return new pkijs.Certificate({ schema: asn1.result });
  } catch {
    return null;
  }
}

function trustedRootCertificates(): pkijs.Certificate[] {
  const roots = tls.rootCertificates.map(pemCertToPkijs).filter((c): c is pkijs.Certificate => c !== null);
  const tsaCaCertBase64 = process.env.TSA_CA_CERT_BASE64;
  if (tsaCaCertBase64) {
    const extra = pemCertToPkijs(Buffer.from(tsaCaCertBase64, "base64").toString("utf8"));
    if (extra) roots.push(extra);
  }
  return roots;
}

// ---------------------------------------------------------------------------
// 2. BUILDING + SENDING THE TIMESTAMP REQUEST
// ---------------------------------------------------------------------------

function randomNonceBytes(): Uint8Array {
  // Same reasoning as lib/ca.ts's generateSerialNumber(): clearing the top
  // bit keeps this a positive ASN.1 INTEGER without the DER encoder
  // silently prepending a padding byte, which would otherwise make the
  // nonce we sent and the nonce we read back out of a round-tripped
  // asn1js.Integer differ by a leading zero byte.
  const bytes = crypto.randomBytes(8);
  bytes[0] &= 0x7f;
  return bytes;
}

export interface RequestedTimestamp {
  tokenDer: Buffer; // the raw CMS ContentInfo (SignedData) — the "timeStampToken"
  genTime: Date;
  tsaSerialHex: string;
  policyOid: string;
  nonceHex: string;
}

/**
 * Sends one RFC 3161 TimeStampReq for `message` to TSA_URL and returns the
 * parsed, granted response. Throws on any network failure, timeout, or a
 * PKIStatus other than granted/grantedWithMods — callers that must never
 * block or fail on this (anchorAuditChain()) are responsible for catching
 * it themselves.
 */
export async function requestTimestampToken(message: Buffer): Promise<RequestedTimestamp> {
  const messageImprint = await pkijs.MessageImprint.create("SHA-256", message);
  const nonceBytes = randomNonceBytes();
  const nonceHex = Buffer.from(nonceBytes).toString("hex");

  const tsReq = new pkijs.TimeStampReq({
    version: 1,
    messageImprint,
    certReq: true,
    nonce: new asn1js.Integer({ valueHex: nonceBytes.buffer.slice(nonceBytes.byteOffset, nonceBytes.byteOffset + nonceBytes.byteLength) }),
  });
  const reqBer = Buffer.from(tsReq.toSchema().toBER(false));

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TSA_TIMEOUT_MS);
  let respBuffer: ArrayBuffer;
  try {
    const res = await fetch(TSA_URL, {
      method: "POST",
      headers: { "Content-Type": "application/timestamp-query" },
      body: reqBer,
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`TSA responded with HTTP ${res.status}`);
    }
    respBuffer = await res.arrayBuffer();
  } finally {
    clearTimeout(timeout);
  }

  const asn1 = asn1js.fromBER(respBuffer);
  if (asn1.offset === -1) {
    throw new Error("TSA response is not valid ASN.1");
  }
  const tsResp = new pkijs.TimeStampResp({ schema: asn1.result });
  // PKIStatus: 0 = granted, 1 = grantedWithMods — both usable; anything
  // else (rejection, waiting, revocationWarning, revocationNotification) is
  // not a usable token.
  if (tsResp.status.status !== 0 && tsResp.status.status !== 1) {
    throw new Error(`TSA did not grant the timestamp (PKIStatus ${tsResp.status.status})`);
  }
  if (!tsResp.timeStampToken) {
    throw new Error("TSA response carries no timeStampToken");
  }

  const tokenDer = Buffer.from(tsResp.timeStampToken.toSchema().toBER(false));
  const signedData = new pkijs.SignedData({ schema: tsResp.timeStampToken.content });
  const eContent = signedData.encapContentInfo.eContent;
  if (!eContent) {
    throw new Error("TSA token carries no TSTInfo content");
  }
  const tstInfo = new pkijs.TSTInfo({ schema: asn1js.fromBER(eContent.valueBlock.valueHexView).result });

  if (!tstInfo.nonce || Buffer.from(tstInfo.nonce.valueBlock.valueHexView).toString("hex") !== nonceHex) {
    throw new Error("TSA response nonce does not match the request");
  }

  return {
    tokenDer,
    genTime: tstInfo.genTime,
    tsaSerialHex: Buffer.from(tstInfo.serialNumber.valueBlock.valueHexView).toString("hex"),
    policyOid: tstInfo.policy,
    nonceHex,
  };
}

// ---------------------------------------------------------------------------
// 3. ANCHORING (automatic best-effort + manual)
// ---------------------------------------------------------------------------

export type AnchorAttemptResult =
  | { outcome: "anchored"; anchorId: string; headSeq: number; genTime: Date }
  | { outcome: "skipped-too-soon"; nextEligibleAt: Date }
  | { outcome: "skipped-empty-chain" }
  | { outcome: "failed"; reason: string };

/**
 * Anchors the current audit chain head, respecting TSA_MIN_INTERVAL_SECONDS
 * regardless of caller (automatic post-approval hook or the manual POST
 * /api/audit/anchor route both go through this one function, so "do not
 * hammer the TSA" is enforced in exactly one place). Never throws — every
 * failure mode (network, timeout, rejected status, too soon, no entries
 * yet) comes back as a tagged result instead, so the automatic call site
 * can log-and-continue without a try/catch of its own.
 */
export async function anchorAuditChain(): Promise<AnchorAttemptResult> {
  try {
    const head = await getAuditHead();
    if (!head) {
      return { outcome: "skipped-empty-chain" };
    }

    const last = await prisma.auditAnchor.findFirst({ orderBy: { createdAt: "desc" } });
    if (last) {
      const nextEligibleAt = new Date(last.createdAt.getTime() + TSA_MIN_INTERVAL_SECONDS * 1000);
      if (nextEligibleAt.getTime() > Date.now()) {
        return { outcome: "skipped-too-soon", nextEligibleAt };
      }
    }

    const headLog = await prisma.auditLog.findFirst({ where: { seq: head.seq }, select: { id: true } });
    if (!headLog) {
      return { outcome: "failed", reason: "Audit head row disappeared between read and anchor" };
    }

    const headHashBytes = Buffer.from(head.hash, "hex");
    const requested = await requestTimestampToken(headHashBytes);

    const anchor = await prisma.auditAnchor.create({
      data: {
        headLogId: headLog.id,
        headHash: head.hash,
        tsaUrl: TSA_URL,
        tokenBase64: requested.tokenDer.toString("base64"),
        genTime: requested.genTime,
        tsaSerial: requested.tsaSerialHex,
        policyOid: requested.policyOid,
        nonce: requested.nonceHex,
      },
    });

    return { outcome: "anchored", anchorId: anchor.id, headSeq: head.seq, genTime: requested.genTime };
  } catch (err) {
    // Never log the token or any other raw response bytes — just a short,
    // safe message, consistent with "never log tokens beyond a short id".
    return { outcome: "failed", reason: err instanceof Error ? err.message : "Unknown error contacting the TSA" };
  }
}

/**
 * Best-effort, non-blocking hook for call sites that must never slow down
 * or fail because of the TSA (a transaction's final Registrar approval or
 * rejection) — fires anchorAuditChain() and only ever logs a short warning
 * on anything other than a successful anchor or an expected skip.
 */
export function anchorAuditChainBestEffort(): void {
  anchorAuditChain()
    .then((result) => {
      if (result.outcome === "failed") {
        console.warn(`[timestamp] anchor attempt failed: ${result.reason}`);
      }
    })
    .catch(() => {
      // anchorAuditChain() itself never rejects, but guard anyway — this
      // call site must never produce an unhandled rejection.
      console.warn("[timestamp] anchor attempt failed unexpectedly");
    });
}

// ---------------------------------------------------------------------------
// 4. LISTING (no raw tokens)
// ---------------------------------------------------------------------------

export interface AnchorSummary {
  id: string;
  headLogId: string;
  headSeq: number | null;
  headHash: string;
  tsaUrl: string;
  genTime: string;
  tsaSerial: string;
  policyOid: string;
  createdAt: string;
}

export async function listAnchors(limit = 20): Promise<AnchorSummary[]> {
  const anchors = await prisma.auditAnchor.findMany({
    orderBy: { createdAt: "desc" },
    take: limit,
    include: { headLog: { select: { seq: true } } },
  });
  return anchors.map((a) => ({
    id: a.id,
    headLogId: a.headLogId,
    headSeq: a.headLog?.seq ?? null,
    headHash: a.headHash,
    tsaUrl: a.tsaUrl,
    genTime: a.genTime.toISOString(),
    tsaSerial: a.tsaSerial,
    policyOid: a.policyOid,
    createdAt: a.createdAt.toISOString(),
  }));
}

// ---------------------------------------------------------------------------
// 5. VERIFICATION
// ---------------------------------------------------------------------------

export type AnchorStatus = "VALID" | "TAMPERED" | "MISSING" | "TOKEN_INVALID";

export interface AnchorCheckStep {
  id: "tokenParses" | "messageImprint" | "cmsSignature" | "tsaCertificate" | "nonce" | "genTime" | "entryIntact" | "chainIntact";
  label: string;
  pass: boolean;
  detail: string;
}

export interface AnchorVerificationResult {
  anchorId: string;
  headLogId: string;
  tsaUrl: string;
  genTime: string;
  status: AnchorStatus;
  steps: AnchorCheckStep[];
}

function step(id: AnchorCheckStep["id"], label: string, pass: boolean, detail: string): AnchorCheckStep {
  return { id, label, pass, detail };
}

type AuditAnchorRow = Awaited<ReturnType<typeof prisma.auditAnchor.findFirstOrThrow>>;

/**
 * Runs every check for one anchor, independently and never short-circuited
 * (same principle as lib/ca.ts's verifyCertificate()) — see this file's
 * header comment for what each step proves.
 */
export async function verifyAnchor(anchor: AuditAnchorRow): Promise<AnchorVerificationResult> {
  const base = { anchorId: anchor.id, headLogId: anchor.headLogId, tsaUrl: anchor.tsaUrl, genTime: anchor.genTime.toISOString() };

  let tokenDer: Buffer;
  let contentInfo: pkijs.ContentInfo;
  let signedData: pkijs.SignedData;
  let tstInfo: pkijs.TSTInfo;
  try {
    tokenDer = Buffer.from(anchor.tokenBase64, "base64");
    contentInfo = pkijs.ContentInfo.fromBER(tokenDer.buffer.slice(tokenDer.byteOffset, tokenDer.byteOffset + tokenDer.byteLength));
    signedData = new pkijs.SignedData({ schema: contentInfo.content });
    const eContent = signedData.encapContentInfo.eContent;
    if (!eContent) throw new Error("no TSTInfo content");
    tstInfo = new pkijs.TSTInfo({ schema: asn1js.fromBER(eContent.valueBlock.valueHexView).result });
  } catch (err) {
    return {
      ...base,
      status: "TOKEN_INVALID",
      steps: [step("tokenParses", "Token parses", false, err instanceof Error ? err.message : "Could not decode the stored token as CMS")],
    };
  }

  const steps: AnchorCheckStep[] = [step("tokenParses", "Token parses", true, "The stored token decodes as a well-formed CMS SignedData / TSTInfo.")];

  // 2. messageImprint — hashAlgorithm + hashedMessage == SHA-256(headHash).
  const headHashBytes = Buffer.from(anchor.headHash, "hex");
  const expectedImprint = Buffer.from(await webcrypto.subtle.digest("SHA-256", headHashBytes));
  const actualAlgorithmOid = tstInfo.messageImprint.hashAlgorithm.algorithmId;
  const actualImprint = Buffer.from(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView);
  const imprintMatches = actualAlgorithmOid === SHA256_OID && actualImprint.equals(expectedImprint);
  steps.push(
    step(
      "messageImprint",
      "Message imprint",
      imprintMatches,
      imprintMatches
        ? "The token's messageImprint matches SHA-256 of this anchor's own stored head hash."
        : "The token's messageImprint does not match this anchor's stored head hash — it does not attest to this value.",
    ),
  );

  // 3. CMS signature — on a SEPARATE SignedData instance whose
  // eContentType has been swapped away from id_eContentType_TSTInfo, not
  // the one used for messageImprint/chain below. pkijs's SignedData.verify()
  // special-cases that exact content type: it parses TSTInfo and calls
  // tstInfo.verify({data}) — ITS OWN messageImprint pre-check — BEFORE ever
  // reaching the generic signature-verification code, and THROWS
  // immediately if that pre-check fails, without computing
  // signatureVerified at all. Left in place, a wrong messageImprint would
  // ALSO report as a signature failure, even though the underlying RSA
  // signature is perfectly genuine — the same two-findings conflation
  // checkChain caused above, from a different corner of the same method.
  // Swapping eContentType is safe for this purpose: the actual signature
  // covers signerInfo.signedAttrs, which only requires a content-type
  // ATTRIBUTE to be present (checked by pkijs itself) — its value is never
  // compared back against this field. This instance is never reused for
  // anything other than this.verify() call below.
  const GENERIC_CONTENT_TYPE_OID = "1.2.840.113549.1.7.1"; // id-data
  const signatureOnly = new pkijs.SignedData({ schema: contentInfo.content });
  signatureOnly.encapContentInfo.eContentType = GENERIC_CONTENT_TYPE_OID;

  let signatureValid = false;
  let signerCert: pkijs.Certificate | null = null;
  let verifyMessage = "";
  try {
    const result = await signatureOnly.verify({ signer: 0, extendedMode: true });
    signatureValid = result.signatureVerified === true;
    signerCert = result.signerCertificate ?? null;
    verifyMessage = result.message ?? "";
  } catch (err) {
    verifyMessage = err instanceof Error ? err.message : "CMS verification failed";
  }
  steps.push(
    step(
      "cmsSignature",
      "CMS signature",
      signatureValid,
      signatureValid
        ? "The CMS signature over the TSTInfo verifies against the TSA certificate carried in the token."
        : `The CMS signature does not verify${verifyMessage ? `: ${verifyMessage}` : "."}`,
    ),
  );

  // 4. TSA certificate chain — same spoofed instance (content type plays
  // no role in chain validation, only signerCert's own identity does, and
  // that's unaffected), only meaningful once we have a signer cert at all.
  let chainValid = false;
  let chainMessage = "";
  if (signerCert) {
    try {
      const chainResult = await signatureOnly.verify({
        signer: 0,
        checkChain: true,
        checkDate: tstInfo.genTime,
        trustedCerts: trustedRootCertificates(),
        extendedMode: true,
      });
      chainValid = chainResult.signerCertificateVerified === true;
      chainMessage = chainResult.message ?? "";
    } catch (err) {
      chainMessage = err instanceof Error ? err.message : "chain validation failed";
    }
  }

  let ekuValid = false;
  if (signerCert) {
    const eku = signerCert.extensions?.find((e) => e.extnID === "2.5.29.37");
    const purposes: string[] | undefined = (eku?.parsedValue as { keyPurposes?: string[] } | undefined)?.keyPurposes;
    ekuValid = Boolean(purposes?.includes(TIMESTAMPING_EKU_OID));
  }
  steps.push(
    step(
      "tsaCertificate",
      "TSA certificate",
      ekuValid && chainValid,
      !signerCert
        ? "No TSA certificate was found in the token to check."
        : !ekuValid
          ? "The TSA certificate does not carry the timeStamping extended key usage."
          : !chainValid
            ? `The TSA certificate's chain does not validate to a trusted root as of ${tstInfo.genTime.toISOString()}${chainMessage ? `: ${chainMessage}` : "."}`
            : "The TSA certificate carries the timeStamping EKU and its chain validates to a trusted root.",
    ),
  );

  // 5. nonce
  const nonceMatches = Boolean(tstInfo.nonce) && Buffer.from(tstInfo.nonce!.valueBlock.valueHexView).toString("hex") === anchor.nonce;
  steps.push(
    step(
      "nonce",
      "Nonce",
      nonceMatches,
      nonceMatches
        ? "The token's nonce matches the one sent with this anchor's request."
        : "The token's nonce does not match — this token may not be the response to this anchor's own request.",
    ),
  );

  // 6. genTime sanity
  const genTimeSane = tstInfo.genTime.getTime() <= Date.now() + GENTIME_FUTURE_SKEW_MS;
  steps.push(
    step(
      "genTime",
      "Timestamp plausibility",
      genTimeSane,
      genTimeSane
        ? `Generation time (${tstInfo.genTime.toISOString()}) is not implausibly in the future.`
        : `Generation time (${tstInfo.genTime.toISOString()}) is further in the future than this server's clock allows for — treat with suspicion.`,
    ),
  );

  // 7. entryIntact — the anchored AuditLog row still exists, by id, and its
  // CURRENT hash still equals what this anchor actually anchored.
  const entry = await prisma.auditLog.findUnique({ where: { id: anchor.headLogId }, select: { seq: true, hash: true } });
  const entryExists = Boolean(entry);
  const entryHashMatches = Boolean(entry) && entry!.hash === anchor.headHash;
  steps.push(
    step(
      "entryIntact",
      "Anchored entry intact",
      entryExists && entryHashMatches,
      !entryExists
        ? "The AuditLog entry this anchor points to no longer exists."
        : !entryHashMatches
          ? "The AuditLog entry this anchor points to now has a DIFFERENT hash than what was anchored — it was altered after being anchored."
          : "The anchored AuditLog entry still exists with the exact hash that was anchored.",
    ),
  );

  // 8. chainIntact — no break in the chain at or before this anchor's seq.
  // A break strictly after it is a different anchor's problem, not this
  // one's: this anchor's claim is only about history UP TO its own point.
  let chainIntactBeforeOrAt = false;
  let chainDetail = "Could not determine — the anchored entry itself is missing.";
  if (entry) {
    const chainResult = await verifyAuditChain();
    chainIntactBeforeOrAt = chainResult.valid || (chainResult.firstBrokenSeq !== null && chainResult.firstBrokenSeq > entry.seq);
    chainDetail = chainIntactBeforeOrAt
      ? "The full chain walk reports no break at or before this anchor's position."
      : `The chain walk reports a break at seq ${chainResult.firstBrokenSeq}, at or before this anchor's position (seq ${entry.seq}).`;
  }
  steps.push(step("chainIntact", "Chain intact up to anchor", chainIntactBeforeOrAt, chainDetail));

  const allPass = steps.every((s) => s.pass);
  let status: AnchorStatus;
  if (allPass) status = "VALID";
  else if (!entryExists) status = "MISSING";
  else if (!entryHashMatches || !chainIntactBeforeOrAt) status = "TAMPERED";
  else status = "TOKEN_INVALID";

  return { ...base, status, steps };
}

export async function verifyAnchors(limit = 20): Promise<AnchorVerificationResult[]> {
  const anchors = await prisma.auditAnchor.findMany({ orderBy: { createdAt: "desc" }, take: limit });
  const results: AnchorVerificationResult[] = [];
  for (const anchor of anchors) {
    // Sequential, not Promise.all: each call does its own chain walk
    // (verifyAuditChain() re-reads the whole table), so running many of
    // these concurrently would multiply database load for no benefit here
    // — this endpoint is an on-demand admin action, not a hot path.
    results.push(await verifyAnchor(anchor));
  }
  return results;
}
