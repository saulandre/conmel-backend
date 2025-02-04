/*
  Warnings:

  - The values [Não] on the enum `Camisa` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "Camisa_new" AS ENUM ('Sim');
ALTER TABLE "Participantes2025" ALTER COLUMN "camisa" TYPE "Camisa_new" USING ("camisa"::text::"Camisa_new");
ALTER TYPE "Camisa" RENAME TO "Camisa_old";
ALTER TYPE "Camisa_new" RENAME TO "Camisa";
DROP TYPE "Camisa_old";
COMMIT;
