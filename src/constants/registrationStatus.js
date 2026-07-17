/**
 * Controle de abertura das inscrições públicas.
 * Defina PUBLIC_REGISTRATIONS_OPEN=true no .env para reabrir ao público.
 * Ausente ou qualquer outro valor → inscrições públicas encerradas.
 * Administradores autenticados (role=admin) sempre podem inscrever via API.
 */
function arePublicRegistrationsOpen() {
  const value = process.env.PUBLIC_REGISTRATIONS_OPEN;
  if (value === undefined || value === null || String(value).trim() === '') {
    return false;
  }
  return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

const PUBLIC_REGISTRATIONS_CLOSED_MESSAGE =
  'As inscrições para a CONMEL estão encerradas.';

module.exports = {
  arePublicRegistrationsOpen,
  PUBLIC_REGISTRATIONS_CLOSED_MESSAGE,
};
