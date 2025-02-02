-- AlterTable
ALTER TABLE "Users" ADD COLUMN     "verificationCode" TEXT,
ADD COLUMN     "verificationCodeExpiration" TIMESTAMP(3),
ALTER COLUMN "createdAt" SET DATA TYPE TIMESTAMP(3),
ALTER COLUMN "updatedAt" SET DATA TYPE TIMESTAMP(3);
