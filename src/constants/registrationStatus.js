const { Prisma } = require('@prisma/client');

const SETTING_KEY = 'public_registrations_open';

const PUBLIC_REGISTRATIONS_CLOSED_MESSAGE =
  'As inscrições para a CONMEL estão encerradas.';

const PUBLIC_REGISTRATIONS_CLOSED_UI_MESSAGE =
  'As inscrições para a CONMEL estão encerradas. Agradecemos o seu interesse.';

/**
 * Fallback legado (env). Usado somente se a tabela AppSettings ainda não existir
 * ou se a chave ainda não foi gravada.
 */
function arePublicRegistrationsOpenFromEnv() {
  const value = process.env.PUBLIC_REGISTRATIONS_OPEN;
  if (value === undefined || value === null || String(value).trim() === '') {
    return false;
  }
  return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

function parseOpenFlag(raw) {
  return ['1', 'true', 'yes', 'on'].includes(String(raw ?? '').trim().toLowerCase());
}

function isMissingTableError(error) {
  if (!error) return false;
  if (error.code === 'P2021' || error.code === 'P2010') return true;
  const msg = String(error.message || '').toLowerCase();
  return (
    msg.includes('appsettings') &&
    (msg.includes('does not exist') || msg.includes('não existe') || msg.includes('relation'))
  );
}

/**
 * Lê o estado das inscrições públicas.
 * Prioridade: AppSettings (DB) → env → false (encerrado).
 */
async function getPublicRegistrationsOpen(prisma) {
  try {
    const row = await prisma.appSetting.findUnique({
      where: { key: SETTING_KEY },
      select: { value: true },
    });
    if (row) {
      return parseOpenFlag(row.value);
    }
    return arePublicRegistrationsOpenFromEnv();
  } catch (error) {
    if (isMissingTableError(error)) {
      console.warn(
        '[registrationStatus] Tabela AppSettings ausente — usando PUBLIC_REGISTRATIONS_OPEN do .env. Aplique a SQL em prisma/proposals/.'
      );
      return arePublicRegistrationsOpenFromEnv();
    }
    throw error;
  }
}

/**
 * Atualiza o estado (idempotente). Exige tabela AppSettings.
 * @returns {{ publicOpen: boolean, previousOpen: boolean, changed: boolean, source: 'db' }}
 */
async function setPublicRegistrationsOpen(prisma, publicOpen, adminUserId) {
  const desired = Boolean(publicOpen);
  const desiredValue = desired ? 'true' : 'false';

  try {
    const existing = await prisma.appSetting.findUnique({
      where: { key: SETTING_KEY },
      select: { value: true },
    });

    const previousOpen = existing
      ? parseOpenFlag(existing.value)
      : arePublicRegistrationsOpenFromEnv();

    if (existing && previousOpen === desired) {
      return {
        publicOpen: desired,
        previousOpen,
        changed: false,
        source: 'db',
      };
    }

    await prisma.appSetting.upsert({
      where: { key: SETTING_KEY },
      create: {
        key: SETTING_KEY,
        value: desiredValue,
        updatedBy: adminUserId ?? null,
      },
      update: {
        value: desiredValue,
        updatedBy: adminUserId ?? null,
      },
    });

    console.log(
      `[registrationStatus] adminUserId=${adminUserId ?? 'n/a'} ` +
        `previous=${previousOpen} next=${desired} changed=true`
    );

    return {
      publicOpen: desired,
      previousOpen,
      changed: previousOpen !== desired,
      source: 'db',
    };
  } catch (error) {
    if (isMissingTableError(error) || error instanceof Prisma.PrismaClientKnownRequestError) {
      if (isMissingTableError(error)) {
        const err = new Error(
          'Configuração de inscrições ainda não está disponível no banco. Aplique a SQL proposta em prisma/proposals/20260716_app_settings_public_registrations.sql.'
        );
        err.code = 'SETTINGS_TABLE_MISSING';
        throw err;
      }
    }
    throw error;
  }
}

/** @deprecated Prefer getPublicRegistrationsOpen(prisma) — sync só para env. */
function arePublicRegistrationsOpen() {
  return arePublicRegistrationsOpenFromEnv();
}

module.exports = {
  SETTING_KEY,
  PUBLIC_REGISTRATIONS_CLOSED_MESSAGE,
  PUBLIC_REGISTRATIONS_CLOSED_UI_MESSAGE,
  arePublicRegistrationsOpen,
  arePublicRegistrationsOpenFromEnv,
  getPublicRegistrationsOpen,
  setPublicRegistrationsOpen,
};
