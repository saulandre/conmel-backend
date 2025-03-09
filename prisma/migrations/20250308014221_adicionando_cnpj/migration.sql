/*
  Warnings:

  - Added the required column `CNPJ` to the `InstituicaoEspirita` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "InstituicaoEspirita" ADD COLUMN     "CNPJ" TEXT NOT NULL;
