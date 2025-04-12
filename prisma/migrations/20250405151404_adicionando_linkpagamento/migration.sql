-- AlterTable
ALTER TABLE "Participantes2025" ADD COLUMN     "linkPagamento" TEXT,
ADD COLUMN     "status" TEXT NOT NULL DEFAULT 'pendente';
