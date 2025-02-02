-- CreateEnum
CREATE TYPE "enum_Users_isRole" AS ENUM ('user', 'admin');

-- CreateEnum
CREATE TYPE "enum_inscricoes_tipoParticipacao" AS ENUM ('Trabalhador', 'Confraternista');

-- CreateEnum
CREATE TYPE "role" AS ENUM ('user', 'admin');

-- CreateTable
CREATE TABLE "Subscriptions" (
    "id" SERIAL NOT NULL,
    "year" INTEGER NOT NULL,
    "userId" INTEGER NOT NULL,
    "createdAt" TIMESTAMPTZ(6) NOT NULL,
    "updatedAt" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "Subscriptions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SequelizeMeta" (
    "name" VARCHAR(255) NOT NULL,

    CONSTRAINT "SequelizeMeta_pkey" PRIMARY KEY ("name")
);

-- CreateTable
CREATE TABLE "inscricoes" (
    "id" SERIAL NOT NULL,
    "nome_completo" VARCHAR(255) NOT NULL,
    "data_nascimento" DATE NOT NULL,
    "idade" INTEGER,
    "email" VARCHAR(255) NOT NULL,
    "telefone" VARCHAR(15),
    "instituicao_espirita" VARCHAR(255),
    "data_inicio_vinculo" TIMESTAMPTZ(6),
    "cep" VARCHAR(10),
    "estado" VARCHAR(2),
    "cidade" VARCHAR(255),
    "bairro" VARCHAR(255),
    "logradouro" VARCHAR(255),
    "complemento" VARCHAR(255),
    "telefone_emergencia" VARCHAR(15),
    "medicacao" VARCHAR(50),
    "uso_alimentacao_vegetariana" BOOLEAN DEFAULT false,
    "observacoes" VARCHAR(50),
    "nome_responsavel" VARCHAR(255),
    "documento_responsavel" VARCHAR(20),
    "telefone_responsavel" VARCHAR(15),
    "createdAt" TIMESTAMPTZ(6) NOT NULL,
    "updatedAt" TIMESTAMPTZ(6) NOT NULL,
    "ano" TEXT,
    "user_id" INTEGER NOT NULL,
    "tipoParticipacao" "enum_inscricoes_tipoParticipacao" NOT NULL,
    "comissao" TEXT,

    CONSTRAINT "inscricoes_pkey" PRIMARY KEY ("id")
);
