/*
  Warnings:

  - Made the column `email` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.
  - Made the column `telefone` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.
  - Made the column `cep` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "Participantes2025" ALTER COLUMN "email" SET NOT NULL,
ALTER COLUMN "telefone" SET NOT NULL,
ALTER COLUMN "nomeCompletoResponsavel" DROP NOT NULL,
ALTER COLUMN "documentoResponsavel" DROP NOT NULL,
ALTER COLUMN "telefoneResponsavel" DROP NOT NULL,
ALTER COLUMN "cep" SET NOT NULL;
