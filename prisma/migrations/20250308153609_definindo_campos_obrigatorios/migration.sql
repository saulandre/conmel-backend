/*
  Warnings:

  - Made the column `IE` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.
  - Made the column `vegetariano` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "InstituicaoEspirita" ALTER COLUMN "logradouro" DROP NOT NULL;

-- AlterTable
ALTER TABLE "Participantes2025" ALTER COLUMN "medicacao" DROP NOT NULL,
ALTER COLUMN "alergia" DROP NOT NULL,
ALTER COLUMN "outrasInformacoes" DROP NOT NULL,
ALTER COLUMN "IE" SET NOT NULL,
ALTER COLUMN "nomeSocial" DROP DEFAULT,
ALTER COLUMN "vegetariano" SET NOT NULL;
