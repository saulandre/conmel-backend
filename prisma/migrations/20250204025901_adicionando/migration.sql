/*
  Warnings:

  - Made the column `nomeCompletoResponsavel` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.
  - Made the column `documentoResponsavel` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.
  - Made the column `telefoneResponsavel` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.
  - Made the column `comissao` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.
  - Made the column `tamanhoCamisa` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.
  - Made the column `complemento` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.
  - Made the column `medicacao` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.
  - Made the column `alergia` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.
  - Made the column `outrasInformacoes` on table `Participantes2025` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "Participantes2025" ADD COLUMN     "IE" TEXT,
ALTER COLUMN "nomeCompletoResponsavel" SET NOT NULL,
ALTER COLUMN "documentoResponsavel" SET NOT NULL,
ALTER COLUMN "telefoneResponsavel" SET NOT NULL,
ALTER COLUMN "comissao" SET NOT NULL,
ALTER COLUMN "tamanhoCamisa" SET NOT NULL,
ALTER COLUMN "complemento" SET NOT NULL,
ALTER COLUMN "medicacao" SET NOT NULL,
ALTER COLUMN "alergia" SET NOT NULL,
ALTER COLUMN "outrasInformacoes" SET NOT NULL;
