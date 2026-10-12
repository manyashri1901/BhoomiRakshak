import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../generated/prisma/client.ts";

const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

// max: 20 — the audit log's advisory-lock serialization (lib/audit.ts)
// means concurrent writers each hold a connection for the duration of
// their wait, so the pool needs enough connections for a real concurrent
// burst (the 20-writer test in scripts/test-audit-chain.ts) to all be
// admitted rather than queuing behind the pg driver's own default pool.
const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL, max: 20 });

export const prisma = globalForPrisma.prisma ?? new PrismaClient({ adapter });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}
