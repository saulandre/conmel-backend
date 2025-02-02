/*
  Warnings:

  - You are about to drop the column `verificationCode` on the `Users` table. All the data in the column will be lost.
  - You are about to drop the `Inscricoes` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `SequelizeMeta` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `Subscriptions` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `_SubscriptionToUsers` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "_SubscriptionToUsers" DROP CONSTRAINT "_SubscriptionToUsers_A_fkey";

-- DropForeignKey
ALTER TABLE "_SubscriptionToUsers" DROP CONSTRAINT "_SubscriptionToUsers_B_fkey";

-- AlterTable
ALTER TABLE "Users" DROP COLUMN "verificationCode";

-- DropTable
DROP TABLE "Inscricoes";

-- DropTable
DROP TABLE "SequelizeMeta";

-- DropTable
DROP TABLE "Subscriptions";

-- DropTable
DROP TABLE "_SubscriptionToUsers";

-- DropEnum
DROP TYPE "InscricaoTipoParticipacao";
