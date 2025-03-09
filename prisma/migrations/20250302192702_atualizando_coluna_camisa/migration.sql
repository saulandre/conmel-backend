/*
  Warnings:

  - The `camisa` column on the `Participantes2025` table would be dropped and recreated. This will lead to data loss if there is data in the column.

*/
-- AlterTable
ALTER TABLE "Participantes2025" DROP COLUMN "camisa",
ADD COLUMN     "camisa" BOOLEAN;

-- DropEnum
DROP TYPE "Camisa";
