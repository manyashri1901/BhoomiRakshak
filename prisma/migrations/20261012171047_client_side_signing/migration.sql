-- AlterTable
ALTER TABLE "users" DROP COLUMN "privateKeyRef",
ADD COLUMN     "wrapIv" TEXT,
ADD COLUMN     "wrapSalt" TEXT,
ADD COLUMN     "wrappedPrivateKey" TEXT;

-- CreateTable
CREATE TABLE "signing_nonces" (
    "id" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "purpose" TEXT NOT NULL,
    "transactionId" TEXT,
    "payload" TEXT NOT NULL,
    "payloadHash" TEXT NOT NULL,
    "used" BOOLEAN NOT NULL DEFAULT false,
    "usedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "signing_nonces_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "signing_nonces_nonce_key" ON "signing_nonces"("nonce");

-- AddForeignKey
ALTER TABLE "signing_nonces" ADD CONSTRAINT "signing_nonces_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
