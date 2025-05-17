-- CreateTable
CREATE TABLE "Pagamentos" (
    "id" SERIAL NOT NULL,
    "nomeparticipante" TEXT NOT NULL,
    "comprovanteUrl" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Pagamentos_pkey" PRIMARY KEY ("id")
);
