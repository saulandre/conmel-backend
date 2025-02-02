/*
  Warnings:

  - You are about to drop the `inscricoes` table. If the table is not empty, all the data it contains will be lost.

*/
-- CreateEnum
CREATE TYPE "Role" AS ENUM ('user', 'admin');

-- CreateEnum
CREATE TYPE "InscricaoTipoParticipacao" AS ENUM ('Trabalhador', 'Confraternista');

-- DropTable
DROP TABLE "inscricoes";

-- DropEnum
DROP TYPE "enum_Users_isRole";

-- DropEnum
DROP TYPE "enum_inscricoes_tipoParticipacao";

-- DropEnum
DROP TYPE "role";

-- CreateTable
CREATE TABLE "Inscricoes" (
    "id" SERIAL NOT NULL,
    "nomeCompleto" VARCHAR(255) NOT NULL,
    "dataNascimento" DATE NOT NULL,
    "idade" INTEGER,
    "email" VARCHAR(255) NOT NULL,
    "telefone" VARCHAR(15),
    "instituicaoEspirita" VARCHAR(255),
    "dataInicioVinculo" TIMESTAMPTZ(6),
    "cep" VARCHAR(10),
    "estado" VARCHAR(2),
    "cidade" VARCHAR(255),
    "bairro" VARCHAR(255),
    "logradouro" VARCHAR(255),
    "complemento" VARCHAR(255),
    "telefoneEmergencia" VARCHAR(15),
    "medicacao" VARCHAR(50),
    "usoAlimentacaoVegetariana" BOOLEAN DEFAULT false,
    "observacoes" VARCHAR(50),
    "nomeResponsavel" VARCHAR(255),
    "documentoResponsavel" VARCHAR(20),
    "telefoneResponsavel" VARCHAR(15),
    "createdAt" TIMESTAMPTZ(6) NOT NULL,
    "updatedAt" TIMESTAMPTZ(6) NOT NULL,
    "ano" TEXT,
    "userId" INTEGER NOT NULL,
    "tipoParticipacao" "InscricaoTipoParticipacao" NOT NULL,
    "comissao" TEXT,

    CONSTRAINT "Inscricoes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Users" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "verificationCode" TEXT,
    "isVerified" BOOLEAN NOT NULL DEFAULT false,
    "isRole" "Role" NOT NULL DEFAULT 'user',
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "Users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "_SubscriptionToUsers" (
    "A" INTEGER NOT NULL,
    "B" INTEGER NOT NULL,

    CONSTRAINT "_SubscriptionToUsers_AB_pkey" PRIMARY KEY ("A","B")
);

-- CreateIndex
CREATE UNIQUE INDEX "Users_email_key" ON "Users"("email");

-- CreateIndex
CREATE INDEX "_SubscriptionToUsers_B_index" ON "_SubscriptionToUsers"("B");

-- AddForeignKey
ALTER TABLE "_SubscriptionToUsers" ADD CONSTRAINT "_SubscriptionToUsers_A_fkey" FOREIGN KEY ("A") REFERENCES "Subscriptions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_SubscriptionToUsers" ADD CONSTRAINT "_SubscriptionToUsers_B_fkey" FOREIGN KEY ("B") REFERENCES "Users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
