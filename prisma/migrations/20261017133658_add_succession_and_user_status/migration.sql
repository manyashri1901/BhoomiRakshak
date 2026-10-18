-- CreateEnum
CREATE TYPE "UserStatus" AS ENUM ('ACTIVE', 'DECEASED');

-- AlterEnum
ALTER TYPE "TransactionType" ADD VALUE 'SUCCESSION';

-- AlterTable
ALTER TABLE "transactions" ADD COLUMN     "secondaryDocumentHash" TEXT,
ADD COLUMN     "secondaryDocumentPath" TEXT;

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "status" "UserStatus" NOT NULL DEFAULT 'ACTIVE';
