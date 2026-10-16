-- Replaces the old custom signed-JSON certificate envelope with a real
-- X.509 v3 certificate (see lib/ca.ts). This is a breaking schema change —
-- every certificate ever issued under the old format becomes unparseable,
-- since there is no migration path from a JSON envelope to a real
-- certificate (the old envelope was never signed by an X.509 CA). Intended
-- to be applied via `prisma migrate reset` against a fresh database, not
-- `migrate deploy` against one with existing Certificate rows.

-- AlterTable
ALTER TABLE "certificates" DROP COLUMN "issuer",
DROP COLUMN "publicKey",
DROP COLUMN "signature",
ADD COLUMN     "certificatePem" TEXT NOT NULL,
ADD COLUMN     "serialNumber" TEXT NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "certificates_serialNumber_key" ON "certificates"("serialNumber");
