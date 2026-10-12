-- Double-sale guard, enforced at the database level: at most one
-- transaction per land record may be mid-review (PENDING_VO or
-- PENDING_REGISTRAR) at a time. The application already checks this
-- before creating a transaction (routes/transactions.ts), but that check
-- and the INSERT it guards are not atomic — two concurrent requests can
-- both pass the check. This partial unique index makes the second INSERT
-- fail instead, closing the race window Prisma's schema.prisma cannot
-- express directly (no WHERE clause on @@unique).
CREATE UNIQUE INDEX "transactions_one_pending_per_land_record"
ON "transactions" ("landRecordId")
WHERE "status" IN ('PENDING_VO', 'PENDING_REGISTRAR');
