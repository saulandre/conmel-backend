-- CreateEnum
CREATE TYPE "Sexo" AS ENUM ('Masculino', 'Feminino');

-- CreateEnum
CREATE TYPE "TipoParticipacao" AS ENUM ('Confraternista', 'Trabalhador');

-- CreateEnum
CREATE TYPE "Comissao" AS ENUM ('Divulgacao', 'Recepcao', 'Outros');

-- CreateTable
CREATE TABLE "Participantes2025" (
    "id" SERIAL NOT NULL,
    "nomeCompleto" TEXT NOT NULL,
    "dataNascimento" TIMESTAMP(3) NOT NULL,
    "sexo" "Sexo" NOT NULL,
    "email" TEXT,
    "telefone" TEXT,
    "nomeCompletoResponsavel" TEXT,
    "documentoResponsavel" TEXT,
    "telefoneResponsavel" TEXT,
    "tipoParticipacao" "TipoParticipacao" NOT NULL,
    "comissao" "Comissao",
    "camisa" TEXT,
    "tamanhoCamisa" TEXT,
    "cep" TEXT,
    "estado" TEXT,
    "cidade" TEXT,
    "bairro" TEXT,
    "logradouro" TEXT,
    "numero" TEXT,
    "complemento" TEXT,
    "numeroCMEJacas" TEXT,
    "medicacao" TEXT,
    "alergia" TEXT,
    "outrasInformacoes" TEXT,
    "userId" INTEGER NOT NULL,

    CONSTRAINT "Participantes2025_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "Participantes2025" ADD CONSTRAINT "Participantes2025_userId_fkey" FOREIGN KEY ("userId") REFERENCES "Users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
