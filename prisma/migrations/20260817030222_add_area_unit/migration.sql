-- CreateEnum
CREATE TYPE "AreaUnit" AS ENUM ('HECTARE', 'ACRE');

-- AlterTable
ALTER TABLE "land_records" ADD COLUMN     "areaUnit" "AreaUnit" NOT NULL DEFAULT 'HECTARE';
