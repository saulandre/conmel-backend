/*
  Warnings:

  - Added the required column `updatedAt` to the `Participantes2025` table without a default value. This is not possible if the table is not empty.
  - Added the required column `camisa` to the `Participantes2025` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "Camisa" AS ENUM ('Sim', 'Não');

-- AlterTable
ALTER TABLE "Participantes2025" ADD COLUMN     "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL,
DROP COLUMN "camisa",
ADD COLUMN     "camisa" "Camisa" NOT NULL;
