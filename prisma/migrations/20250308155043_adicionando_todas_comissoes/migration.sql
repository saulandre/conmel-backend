/*
  Warnings:

  - The values [Divulgacao,Recepcao,Outros] on the enum `Comissao` will be removed. If these variants are still used in the database, this will fail.
  - The values [Masculinao_Trans] on the enum `Sexo` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "Comissao_new" AS ENUM ('Coordenação_Geral', 'Divulgação', 'Recepção', 'Alimentação', 'Multimeios', 'Servicos_Gerais', 'Secretaria', 'Atendimento_Fraterno', 'Estudos_Doutrinarios');
ALTER TABLE "Participantes2025" ALTER COLUMN "comissao" TYPE "Comissao_new" USING ("comissao"::text::"Comissao_new");
ALTER TYPE "Comissao" RENAME TO "Comissao_old";
ALTER TYPE "Comissao_new" RENAME TO "Comissao";
DROP TYPE "Comissao_old";
COMMIT;

-- AlterEnum
BEGIN;
CREATE TYPE "Sexo_new" AS ENUM ('Masculino_SIS', 'Feminino_SIS', 'Masculino_Trans', 'Feminino_Trans');
ALTER TABLE "Participantes2025" ALTER COLUMN "sexo" TYPE "Sexo_new" USING ("sexo"::text::"Sexo_new");
ALTER TYPE "Sexo" RENAME TO "Sexo_old";
ALTER TYPE "Sexo_new" RENAME TO "Sexo";
DROP TYPE "Sexo_old";
COMMIT;
