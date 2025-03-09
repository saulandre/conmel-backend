/*
  Warnings:

  - You are about to drop the column `CEU` on the `InstituicaoEspirita` table. All the data in the column will be lost.
  - You are about to drop the column `dia_evang` on the `InstituicaoEspirita` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "InstituicaoEspirita" DROP COLUMN "CEU",
DROP COLUMN "dia_evang";
