/*
  Warnings:

  - The primary key for the `Participantes2025` table will be changed. If it partially fails, the table could be left without primary key constraint.

*/
-- AlterTable
ALTER TABLE "Participantes2025" DROP CONSTRAINT "Participantes2025_pkey",
ALTER COLUMN "id" DROP DEFAULT,
ALTER COLUMN "id" SET DATA TYPE TEXT,
ADD CONSTRAINT "Participantes2025_pkey" PRIMARY KEY ("id");
DROP SEQUENCE "Participantes2025_id_seq";
