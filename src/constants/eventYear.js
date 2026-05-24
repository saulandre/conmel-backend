/** Ano do evento atual (inscrições novas). Sobrescreva com DEFAULT_EVENT_YEAR no .env se necessário. */
const DEFAULT_EVENT_YEAR = parseInt(process.env.DEFAULT_EVENT_YEAR || '2026', 10);

/** Data de referência para cálculo de idade na inscrição (dia do evento). */
const EVENT_REFERENCE_DATE = process.env.EVENT_REFERENCE_DATE || '2026-07-19';

function parseEventYear(value) {
  const y = parseInt(value, 10);
  if (Number.isFinite(y) && y >= 2000 && y <= 2100) return y;
  return DEFAULT_EVENT_YEAR;
}

function createdAtRangeForYear(year) {
  return {
    gte: new Date(`${year}-01-01T00:00:00.000Z`),
    lt: new Date(`${year + 1}-01-01T00:00:00.000Z`),
  };
}

function yearFilterFromQuery(req) {
  return parseEventYear(req.query?.ano);
}

module.exports = {
  DEFAULT_EVENT_YEAR,
  EVENT_REFERENCE_DATE,
  parseEventYear,
  createdAtRangeForYear,
  yearFilterFromQuery,
};
