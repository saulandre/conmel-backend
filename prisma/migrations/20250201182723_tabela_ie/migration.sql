-- CreateTable
CREATE TABLE "InstituicaoEspirita" (
    "id" SERIAL NOT NULL,
    "nome" TEXT NOT NULL,
    "estado" TEXT NOT NULL,
    "cidade" TEXT NOT NULL,
    "bairro" TEXT NOT NULL,
    "logradouro" TEXT NOT NULL,
    "numero" TEXT NOT NULL,
    "complemento" TEXT NOT NULL,
    "telefone" TEXT NOT NULL,
    "telefoneDiJ" TEXT NOT NULL,
    "dia_evang" TEXT NOT NULL,
    "email" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "InstituicaoEspirita_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "_InstituicaoEspiritaToUsers" (
    "A" INTEGER NOT NULL,
    "B" INTEGER NOT NULL,

    CONSTRAINT "_InstituicaoEspiritaToUsers_AB_pkey" PRIMARY KEY ("A","B")
);

-- CreateIndex
CREATE INDEX "_InstituicaoEspiritaToUsers_B_index" ON "_InstituicaoEspiritaToUsers"("B");

-- AddForeignKey
ALTER TABLE "_InstituicaoEspiritaToUsers" ADD CONSTRAINT "_InstituicaoEspiritaToUsers_A_fkey" FOREIGN KEY ("A") REFERENCES "InstituicaoEspirita"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_InstituicaoEspiritaToUsers" ADD CONSTRAINT "_InstituicaoEspiritaToUsers_B_fkey" FOREIGN KEY ("B") REFERENCES "Users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
