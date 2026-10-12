import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../generated/prisma/client.ts";

const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

// PG_POOL_MAX — the audit log's advisory-lock serialization (lib/audit.ts)
// means concurrent writers each hold a connection for the duration of
// their wait, so under a real concurrent burst (e.g. the 20-writer test
// in scripts/test-audit-chain.ts) the pool needs enough connections for
// all of them to be admitted at once rather than queuing behind the pg
// driver's own pool on top of the advisory lock queue. Default 10 (pg's
// own default) is enough for this app's normal traffic; raise it via env
// for a deployment that expects a higher concurrent-write burst, rather
// than hardcoding a number sized for one specific test.
const poolMax = Number(process.env.PG_POOL_MAX) || 10;
const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL, max: poolMax });

export const prisma = globalForPrisma.prisma ?? new PrismaClient({ adapter });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}
