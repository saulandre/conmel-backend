-- =============================================================================
-- PROPOSTA DE MIGRATION — NÃO APLICADA AUTOMATICAMENTE
-- =============================================================================
-- Objetivo: persistir o estado das inscrições públicas (abrir/encerrar via admin).
-- Impacto: cria apenas a tabela AppSettings; NÃO altera Participantes, Users nem
--          dados de inscrição existentes.
--
-- Como aplicar (manual, após revisão):
--   1. Executar este SQL no PostgreSQL de produção (ou staging).
--   2. Rodar: npx prisma generate  (no conmel-backend)
--   3. Reiniciar o backend.
--
-- Como reverter:
--   DROP TABLE IF EXISTS "AppSettings";
-- =============================================================================

CREATE TABLE IF NOT EXISTS "AppSettings" (
  "key"       TEXT PRIMARY KEY,
  "value"     TEXT NOT NULL,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedBy" INTEGER
);

-- Estado inicial alinhado ao comportamento atual (env ausente/false = encerrado).
-- Idempotente: não sobrescreve se a chave já existir.
INSERT INTO "AppSettings" ("key", "value", "updatedAt")
VALUES ('public_registrations_open', 'false', CURRENT_TIMESTAMP)
ON CONFLICT ("key") DO NOTHING;
