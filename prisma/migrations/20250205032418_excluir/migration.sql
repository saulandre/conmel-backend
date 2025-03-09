/*
  Warnings:

  - You are about to drop the column `telefoneDiJ` on the `InstituicaoEspirita` table. All the data in the column will be lost.
  - Added the required column `CEU` to the `InstituicaoEspirita` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "InstituicaoEspirita" DROP COLUMN "telefoneDiJ",
ADD COLUMN     "CEU" TEXT NOT NULL;
