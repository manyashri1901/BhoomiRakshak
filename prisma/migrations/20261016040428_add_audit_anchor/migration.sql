-- CreateTable
CREATE TABLE "audit_anchors" (
    "id" TEXT NOT NULL,
    "headLogId" TEXT NOT NULL,
    "headHash" TEXT NOT NULL,
    "tsaUrl" TEXT NOT NULL,
    "tokenBase64" TEXT NOT NULL,
    "genTime" TIMESTAMP(3) NOT NULL,
    "tsaSerial" TEXT NOT NULL,
    "policyOid" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_anchors_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "audit_anchors_headLogId_idx" ON "audit_anchors"("headLogId");

-- CreateIndex
CREATE INDEX "audit_anchors_createdAt_idx" ON "audit_anchors"("createdAt");

-- AddForeignKey
ALTER TABLE "audit_anchors" ADD CONSTRAINT "audit_anchors_headLogId_fkey" FOREIGN KEY ("headLogId") REFERENCES "audit_logs"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
