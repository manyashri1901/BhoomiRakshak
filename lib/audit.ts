// lib/audit.ts
//
// System-wide tamper-evident audit log — a hash chain distinct from (and
// alongside) the per-transaction Signature chain in lib/signing.ts. Where
// the Signature chain proves "this land-record transaction's stages were
// signed by the right people in the right order," this chain proves "the
// full sequence of sensitive actions across the whole system has not been
// edited, reordered, or had entries deleted," independent of any single
// transaction.
//
// Each entry's hash commits to every field AND to the previous entry's
// hash (prevHash). Changing any field on any row, or removing a row,
// breaks that row's own hash and every hash after it — verifyAuditChain()
// recomputes the whole chain on demand and reports the first broken link,
// rather than trusting a cached "this was fine when written" flag (the
// same principle as verifySignatureChain/verifyCertificate elsewhere).
//
// WHAT HAPPENS IF AN AUDIT WRITE FAILS
// Neither appendAuditEntry() nor appendAuditEntryTx() catches its own
// errors — a failure (a DB error, a lock-wait timeout under heavy
// concurrency) propagates straight up to the caller. For every call site
// in this codebase, that caller is a route handler that awaits the call
// directly, so the failure becomes an unhandled rejection Express 5
// forwards to the global error handler (server.ts), which returns 500.
// This is deliberate: for every action this module is wired into
// (registration, certificate issuance/revocation, a transaction's
// creation or review stages, a document upload, the demo-tamper route,
// an admin integrity check), failing to log is treated as failing the
// action itself. A silently-unlogged state change is worse than a failed
// request the caller can retry — this is a system explicitly graded on
// trust management, and an audit trail with silent gaps is not trustworthy.
//
// Where the call is appendAuditEntryTx() joined to the caller's own
// prisma.$transaction(...) (every call site in routes/transactions.ts),
// this is also atomic: a failed audit write rolls back the business write
// alongside it, so the two can never go out of sync. Where the call is
// standalone appendAuditEntry() because no such transaction exists to join
// (lib/ca.ts's issueCertificate/revokeCertificate, routes/documents.ts's
// upload, routes/dev.ts's tamper route, routes/audit.ts's own integrity
// check), the business write and the audit write are two separate
// statements — the business write can still succeed while the audit write
// that follows it fails, leaving a real state change with no
// corresponding log entry even though the request itself returns 500.
// This is the documented, accepted gap for this project: every one of
// those call sites is a single Prisma statement already atomic on its
// own, not a multi-step sequence an interactive transaction would need to
// protect, so wrapping it would add a transaction purely to host the
// audit write. New call sites that DO span multiple statements should use
// appendAuditEntryTx() inside their own transaction, exactly as
// routes/transactions.ts does, rather than leaving that gap.

import * as crypto from "node:crypto";
import { prisma } from "./prisma.ts";
import { canonicalStringify } from "./canonicalize.ts";
import { Prisma } from "../generated/prisma/client.ts";
import type { AuditLog as AuditLogRow } from "../generated/prisma/client.ts";

// Every chain has to start somewhere: entry seq=1 links to this fixed,
// publicly-known value rather than to a real hash, so "is this the
// genesis entry" is a simple equality check, not a special case.
const GENESIS_PREV_HASH = "0".repeat(64);

// Fixed key for a Postgres session-level advisory lock, scoped to the
// current transaction (pg_advisory_xact_lock auto-releases on commit or
// rollback). Every writer — no matter which route or how many run at
// once — must hold this lock before it may read the current chain head
// and insert the next entry, which is what makes "read latest seq/hash,
// then insert seq+1 linked to it" atomic across concurrent requests.
// The actual numeric value is arbitrary; it only needs to be constant and
// unique to this lock's purpose within the database.
const AUDIT_CHAIN_LOCK_KEY = 72_70_01n;

export interface AppendAuditEntryInput {
  action: string;
  actorUserId?: string | null;
  entityType: string;
  entityId?: string | null;
  // Context for the action — never a password, private key, or raw JWT.
  details?: Record<string, unknown>;
}

export interface AuditLogEntry {
  id: string;
  seq: number;
  action: string;
  actorUserId: string | null;
  entityType: string;
  entityId: string | null;
  details: unknown;
  nonce: string;
  timestamp: Date;
  prevHash: string;
  hash: string;
}

export interface HashableFields {
  seq: number;
  action: string;
  actorUserId: string | null;
  entityType: string;
  entityId: string | null;
  details: unknown;
  nonce: string;
  timestamp: string; // ISO string — never a raw Date (see canonicalStringify)
  prevHash: string;
}

// Exported so callers that need to check one specific row in isolation
// (scripts/attack-simulation.ts's tamper-then-restore test) reuse the
// exact same formula rather than risking a subtly different reimplementation.
export function computeEntryHash(fields: HashableFields): string {
  const canonical = canonicalStringify(fields);
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

/**
 * Appends one entry to the chain using `db` as the Prisma client — shared
 * by appendAuditEntry() (opens its own transaction) and
 * appendAuditEntryTx() (joins a transaction the caller already has open,
 * so the audit entry commits or rolls back atomically with the business
 * write it documents).
 */
async function writeAuditEntry(
  db: Prisma.TransactionClient,
  input: AppendAuditEntryInput,
): Promise<AuditLogEntry> {
  // Serializes every concurrent writer against this exact read-then-insert
  // sequence — without it, two requests could both read the same "latest"
  // row and insert two entries claiming the same seq/prevHash, forking the
  // chain instead of extending it.
  await db.$executeRaw`SELECT pg_advisory_xact_lock(${AUDIT_CHAIN_LOCK_KEY})`;

  const last = await db.auditLog.findFirst({ orderBy: { seq: "desc" } });
  const seq = (last?.seq ?? 0) + 1;
  const prevHash = last?.hash ?? GENESIS_PREV_HASH;
  const nonce = crypto.randomBytes(16).toString("hex");
  const timestamp = new Date();
  const details = input.details ?? {};
  const actorUserId = input.actorUserId ?? null;
  const entityId = input.entityId ?? null;

  const hash = computeEntryHash({
    seq,
    action: input.action,
    actorUserId,
    entityType: input.entityType,
    entityId,
    details,
    nonce,
    timestamp: timestamp.toISOString(),
    prevHash,
  });

  return db.auditLog.create({
    data: {
      seq,
      action: input.action,
      actorUserId,
      entityType: input.entityType,
      entityId,
      details,
      nonce,
      timestamp,
      prevHash,
      hash,
    },
  });
}

// A burst of concurrent writers all queue on the same advisory lock
// (serialized, not parallel), so the transaction options need enough
// headroom for the slowest writer in a real burst to still get its turn
// before Prisma's own default 5s "interactive transaction" timeout trips —
// proven by the 20-concurrent-writer test in scripts/test-audit-chain.ts.
const AUDIT_TRANSACTION_OPTIONS = { maxWait: 60_000, timeout: 60_000 };

/** Standalone append — opens its own transaction. Use when the caller has
 * no existing transaction to join. */
export function appendAuditEntry(input: AppendAuditEntryInput): Promise<AuditLogEntry> {
  return prisma.$transaction((tx) => writeAuditEntry(tx, input), AUDIT_TRANSACTION_OPTIONS);
}

/** Append as part of an transaction the caller already opened (e.g. a
 * route's own `prisma.$transaction(async (db) => {...})` block), so the
 * audit entry is atomic with the business write it documents. */
export function appendAuditEntryTx(
  tx: Prisma.TransactionClient,
  input: AppendAuditEntryInput,
): Promise<AuditLogEntry> {
  return writeAuditEntry(tx, input);
}

export interface AuditVerificationResult {
  valid: boolean;
  // Count of entries confirmed valid before the first break (or the total
  // entry count if the whole chain is valid).
  checked: number;
  firstBrokenSeq: number | null;
  reason: string | null;
}

/**
 * Recomputes and checks every entry's hash and prevHash link, and that seq
 * is strictly sequential from 1 with no gaps — an attacker who deletes one
 * row (rather than editing it) wouldn't break any single row's own hash,
 * but would break the seq sequence and the prevHash link into the row
 * that used to follow it.
 */
export async function verifyAuditChain(): Promise<AuditVerificationResult> {
  const entries = await prisma.auditLog.findMany({ orderBy: { seq: "asc" } });

  let expectedPrevHash = GENESIS_PREV_HASH;
  let expectedSeq = 1;
  let checked = 0;

  for (const entry of entries) {
    if (entry.seq !== expectedSeq) {
      return {
        valid: false,
        checked,
        firstBrokenSeq: entry.seq,
        reason: `Expected seq ${expectedSeq} but found ${entry.seq} — an entry is missing, duplicated, or out of order.`,
      };
    }
    if (entry.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        checked,
        firstBrokenSeq: entry.seq,
        reason: `prevHash at seq ${entry.seq} does not match the hash of seq ${expectedSeq - 1} — the chain link is broken.`,
      };
    }

    const recomputed = computeEntryHash({
      seq: entry.seq,
      action: entry.action,
      actorUserId: entry.actorUserId,
      entityType: entry.entityType,
      entityId: entry.entityId,
      details: entry.details,
      nonce: entry.nonce,
      timestamp: entry.timestamp.toISOString(),
      prevHash: entry.prevHash,
    });
    if (recomputed !== entry.hash) {
      return {
        valid: false,
        checked,
        firstBrokenSeq: entry.seq,
        reason: `Stored hash at seq ${entry.seq} does not match its recomputed hash — this entry's data was altered after it was written.`,
      };
    }

    checked += 1;
    expectedPrevHash = entry.hash;
    expectedSeq += 1;
  }

  return { valid: true, checked, firstBrokenSeq: null, reason: null };
}

export interface AuditChainHead {
  seq: number;
  hash: string;
}

export async function getAuditHead(): Promise<AuditChainHead | null> {
  const last = await prisma.auditLog.findFirst({ orderBy: { seq: "desc" } });
  return last ? { seq: last.seq, hash: last.hash } : null;
}

export interface ListAuditEntriesOptions {
  page: number;
  pageSize: number;
}

export interface ListAuditEntriesResult {
  entries: AuditLogRow[];
  total: number;
  page: number;
  pageSize: number;
}

export async function listAuditEntries(
  options: ListAuditEntriesOptions,
): Promise<ListAuditEntriesResult> {
  const { page, pageSize } = options;
  const [entries, total] = await Promise.all([
    prisma.auditLog.findMany({
      orderBy: { seq: "desc" },
      skip: (page - 1) * pageSize,
      take: pageSize,
    }),
    prisma.auditLog.count(),
  ]);
  return { entries, total, page, pageSize };
}
