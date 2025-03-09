-- AlterTable
ALTER TABLE "InstituicaoEspirita" ADD COLUMN     "atualizadoPorId" INTEGER;

-- CreateTable
CREATE TABLE "_InstituicaoEspiritaToUsers" (
    "A" INTEGER NOT NULL,
    "B" INTEGER NOT NULL,

    CONSTRAINT "_InstituicaoEspiritaToUsers_AB_pkey" PRIMARY KEY ("A","B")
);

-- CreateIndex
CREATE INDEX "_InstituicaoEspiritaToUsers_B_index" ON "_InstituicaoEspiritaToUsers"("B");

-- AddForeignKey
ALTER TABLE "InstituicaoEspirita" ADD CONSTRAINT "InstituicaoEspirita_atualizadoPorId_fkey" FOREIGN KEY ("atualizadoPorId") REFERENCES "Users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_InstituicaoEspiritaToUsers" ADD CONSTRAINT "_InstituicaoEspiritaToUsers_A_fkey" FOREIGN KEY ("A") REFERENCES "InstituicaoEspirita"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_InstituicaoEspiritaToUsers" ADD CONSTRAINT "_InstituicaoEspiritaToUsers_B_fkey" FOREIGN KEY ("B") REFERENCES "Users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
