-- CreateEnum
CREATE TYPE "Role" AS ENUM ('LANDOWNER', 'VILLAGE_OFFICER', 'REGISTRAR');

-- CreateEnum
CREATE TYPE "LandRecordStatus" AS ENUM ('ACTIVE', 'PENDING', 'DISPUTED', 'TRANSFERRED');

-- CreateEnum
CREATE TYPE "TransactionType" AS ENUM ('REGISTRATION', 'TRANSFER', 'UPDATE');

-- CreateEnum
CREATE TYPE "TransactionStatus" AS ENUM ('PENDING_VO', 'PENDING_REGISTRAR', 'APPROVED', 'REJECTED');

-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" "Role" NOT NULL,
    "publicKey" TEXT NOT NULL,
    "privateKeyRef" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "certificates" (
    "id" TEXT NOT NULL,
    "subjectUserId" TEXT NOT NULL,
    "role" "Role" NOT NULL,
    "publicKey" TEXT NOT NULL,
    "issuer" TEXT NOT NULL DEFAULT 'BhoomiRakshak Root CA',
    "issuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "signature" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,

    CONSTRAINT "certificates_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "land_records" (
    "id" TEXT NOT NULL,
    "surveyNumber" TEXT NOT NULL,
    "location" TEXT NOT NULL,
    "area" DOUBLE PRECISION NOT NULL,
    "currentOwnerId" TEXT NOT NULL,
    "status" "LandRecordStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "land_records_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "transactions" (
    "id" TEXT NOT NULL,
    "type" "TransactionType" NOT NULL,
    "landRecordId" TEXT NOT NULL,
    "fromOwnerId" TEXT,
    "toOwnerId" TEXT NOT NULL,
    "documentPath" TEXT NOT NULL,
    "documentHash" TEXT NOT NULL,
    "status" "TransactionStatus" NOT NULL DEFAULT 'PENDING_VO',
    "rejectReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "transactions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "signatures" (
    "id" TEXT NOT NULL,
    "transactionId" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "role" "Role" NOT NULL,
    "signedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "signatureValue" TEXT NOT NULL,
    "dataHash" TEXT NOT NULL,
    "valid" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "signatures_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE UNIQUE INDEX "certificates_subjectUserId_key" ON "certificates"("subjectUserId");

-- CreateIndex
CREATE UNIQUE INDEX "land_records_surveyNumber_key" ON "land_records"("surveyNumber");

-- AddForeignKey
ALTER TABLE "certificates" ADD CONSTRAINT "certificates_subjectUserId_fkey" FOREIGN KEY ("subjectUserId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "land_records" ADD CONSTRAINT "land_records_currentOwnerId_fkey" FOREIGN KEY ("currentOwnerId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transactions" ADD CONSTRAINT "transactions_landRecordId_fkey" FOREIGN KEY ("landRecordId") REFERENCES "land_records"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transactions" ADD CONSTRAINT "transactions_fromOwnerId_fkey" FOREIGN KEY ("fromOwnerId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transactions" ADD CONSTRAINT "transactions_toOwnerId_fkey" FOREIGN KEY ("toOwnerId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "signatures" ADD CONSTRAINT "signatures_transactionId_fkey" FOREIGN KEY ("transactionId") REFERENCES "transactions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "signatures" ADD CONSTRAINT "signatures_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
