/*
  Warnings:

  - A unique constraint covering the columns `[CNPJ]` on the table `InstituicaoEspirita` will be added. If there are existing duplicate values, this will fail.
  - Made the column `sigla` on table `InstituicaoEspirita` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "InstituicaoEspirita" ALTER COLUMN "estado" DROP NOT NULL,
ALTER COLUMN "cidade" DROP NOT NULL,
ALTER COLUMN "bairro" DROP NOT NULL,
ALTER COLUMN "numero" DROP NOT NULL,
ALTER COLUMN "complemento" DROP NOT NULL,
ALTER COLUMN "telefone" DROP NOT NULL,
ALTER COLUMN "sigla" SET NOT NULL,
ALTER COLUMN "CEU" DROP NOT NULL,
ALTER COLUMN "dia" DROP NOT NULL,
ALTER COLUMN "horario" DROP NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "InstituicaoEspirita_CNPJ_key" ON "InstituicaoEspirita"("CNPJ");
