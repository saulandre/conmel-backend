/*
  Warnings:

  - The values [Divulgação] on the enum `Comissao` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "Comissao_new" AS ENUM ('Coordenação_Geral', 'Divulgacao', 'Recepção', 'Alimentação', 'Multimeios', 'Servicos_Gerais', 'Secretaria', 'Atendimento_Fraterno', 'Estudos_Doutrinarios');
ALTER TABLE "Participantes2025" ALTER COLUMN "comissao" TYPE "Comissao_new" USING ("comissao"::text::"Comissao_new");
ALTER TYPE "Comissao" RENAME TO "Comissao_old";
ALTER TYPE "Comissao_new" RENAME TO "Comissao";
DROP TYPE "Comissao_old";
COMMIT;
