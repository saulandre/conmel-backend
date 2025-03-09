/*
  Warnings:

  - Added the required column `CEU` to the `InstituicaoEspirita` table without a default value. This is not possible if the table is not empty.
  - Added the required column `dia` to the `InstituicaoEspirita` table without a default value. This is not possible if the table is not empty.
  - Added the required column `horario` to the `InstituicaoEspirita` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "InstituicaoEspirita" ADD COLUMN     "CEU" TEXT NOT NULL,
ADD COLUMN     "dia" TEXT NOT NULL,
ADD COLUMN     "horario" TEXT NOT NULL;
