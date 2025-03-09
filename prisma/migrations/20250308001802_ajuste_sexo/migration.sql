/*
  Warnings:

  - The values [Masculino,Feminino] on the enum `Sexo` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "Sexo_new" AS ENUM ('Masculino_SIS', 'Feminino_SIS', 'Masculinao_Trans', 'Feminino_Trans');
ALTER TABLE "Participantes2025" ALTER COLUMN "sexo" TYPE "Sexo_new" USING ("sexo"::text::"Sexo_new");
ALTER TYPE "Sexo" RENAME TO "Sexo_old";
ALTER TYPE "Sexo_new" RENAME TO "Sexo";
DROP TYPE "Sexo_old";
COMMIT;
