/*
  Warnings:

  - You are about to drop the column `isRole` on the `Users` table. All the data in the column will be lost.
  - You are about to drop the `_InstituicaoEspiritaToUsers` table. If the table is not empty, all the data it contains will be lost.

*/
-- AlterEnum
ALTER TYPE "Camisa" ADD VALUE 'Nao';

-- DropForeignKey
ALTER TABLE "Participantes2025" DROP CONSTRAINT "Participantes2025_userId_fkey";

-- DropForeignKey
ALTER TABLE "_InstituicaoEspiritaToUsers" DROP CONSTRAINT "_InstituicaoEspiritaToUsers_A_fkey";

-- DropForeignKey
ALTER TABLE "_InstituicaoEspiritaToUsers" DROP CONSTRAINT "_InstituicaoEspiritaToUsers_B_fkey";

-- AlterTable
ALTER TABLE "InstituicaoEspirita" ADD COLUMN     "criadoPorId" INTEGER,
ADD COLUMN     "sigla" TEXT;

-- AlterTable
ALTER TABLE "Participantes2025" ADD COLUMN     "instituicaoId" INTEGER,
ALTER COLUMN "comissao" DROP NOT NULL,
ALTER COLUMN "userId" DROP NOT NULL;

-- AlterTable
ALTER TABLE "Users" DROP COLUMN "isRole",
ADD COLUMN     "role" "Role" NOT NULL DEFAULT 'user';

-- DropTable
DROP TABLE "_InstituicaoEspiritaToUsers";

-- AddForeignKey
ALTER TABLE "InstituicaoEspirita" ADD CONSTRAINT "InstituicaoEspirita_criadoPorId_fkey" FOREIGN KEY ("criadoPorId") REFERENCES "Users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Participantes2025" ADD CONSTRAINT "Participantes2025_userId_fkey" FOREIGN KEY ("userId") REFERENCES "Users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Participantes2025" ADD CONSTRAINT "Participantes2025_instituicaoId_fkey" FOREIGN KEY ("instituicaoId") REFERENCES "InstituicaoEspirita"("id") ON DELETE SET NULL ON UPDATE CASCADE;
