/*
  Warnings:

  - You are about to drop the column `numeroCMEJacas` on the `Participantes2025` table. All the data in the column will be lost.
  - The `comissao` column on the `Participantes2025` table would be dropped and recreated. This will lead to data loss if there is data in the column.
  - Changed the type of `sexo` on the `Participantes2025` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- AlterEnum
ALTER TYPE "Sexo" ADD VALUE 'Masculino Trans';

-- AlterTable
ALTER TABLE "Participantes2025" DROP COLUMN "numeroCMEJacas",
ADD COLUMN     "deficienciaAuditiva" BOOLEAN,
ADD COLUMN     "deficienciaAutismo" BOOLEAN,
ADD COLUMN     "deficienciaFisica" BOOLEAN,
ADD COLUMN     "deficienciaIntelectual" BOOLEAN,
ADD COLUMN     "deficienciaOutra" BOOLEAN,
ADD COLUMN     "deficienciaOutraDescricao" TEXT,
ADD COLUMN     "deficienciaParalisiaCerebral" BOOLEAN,
ADD COLUMN     "deficienciaVisual" BOOLEAN,
ADD COLUMN     "primeiraComejaca" BOOLEAN DEFAULT false,
DROP COLUMN "sexo",
ADD COLUMN     "sexo" TEXT NOT NULL,
DROP COLUMN "comissao",
ADD COLUMN     "comissao" TEXT,
ALTER COLUMN "tamanhoCamisa" DROP NOT NULL,
ALTER COLUMN "complemento" DROP NOT NULL;

-- DropEnum
DROP TYPE "Comissao";
