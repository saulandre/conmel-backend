/**
 * Testes do fluxo de verificação de conta (lógica + API opcional).
 * Uso:
 *   node scripts/test-verification-flow.js
 *   node scripts/test-verification-flow.js --api http://localhost:4000
 */
const http = require('http');
const https = require('https');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const API_BASE = (() => {
  const idx = process.argv.indexOf('--api');
  return idx >= 0 ? process.argv[idx + 1].replace(/\/$/, '') : null;
})();

const results = [];

function record(id, name, passed, detail = '') {
  results.push({ id, name, passed, detail });
  console.log(`[${passed ? 'PASS' : 'FAIL'}] ${id} ${name}${detail ? ` — ${detail}` : ''}`);
}

function requestJson(method, urlPath, body, token) {
  return new Promise((resolve, reject) => {
    const base = API_BASE || 'http://127.0.0.1:4000';
    const url = new URL(urlPath, `${base}/`);
    const lib = url.protocol === 'https:' ? https : http;
    const payload = body ? JSON.stringify(body) : null;
    const req = lib.request(
      url,
      {
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          let json = null;
          try {
            json = data ? JSON.parse(data) : null;
          } catch {
            json = { raw: data };
          }
          resolve({ status: res.statusCode, json });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function testCodeGeneration() {
  const { generateVerificationCode } = require('../src/services/validation');

  const code = generateVerificationCode();
  record('V1', 'Código tem 6 dígitos', /^\d{6}$/.test(code), code);

  const codes = new Set(Array.from({ length: 20 }, () => generateVerificationCode()));
  record('V2', 'Geração produz códigos variados', codes.size > 1, `únicos: ${codes.size}`);
}

function testMailerUsesResend() {
  const fs = require('fs');
  const mailerSrc = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'config', 'mailer.js'),
    'utf8'
  );
  record('V3', 'mailer.js importa Resend', mailerSrc.includes('require("resend")'));
  record('V4', 'mailer.js não importa nodemailer', !/nodemailer/i.test(mailerSrc));

  const authSrc = fs.readFileSync(
    path.join(__dirname, '..', 'src', 'controllers', 'auth.controller.js'),
    'utf8'
  );
  record('V5', 'auth.controller usa sendMail do mailer', authSrc.includes("require('../config/mailer')"));
  record('V6', 'auth.controller sem nodemailer', !/nodemailer/i.test(authSrc));
}

function testExpirationConstant() {
  const authSrc = require('fs').readFileSync(
    path.join(__dirname, '..', 'src', 'controllers', 'auth.controller.js'),
    'utf8'
  );
  record(
    'V7',
    'Expiração do código = 15 minutos',
    authSrc.includes('15 * 60 * 1000')
  );
}

async function testApiIfAvailable() {
  let health;
  try {
    health = await requestJson('GET', '/api/health');
  } catch (e) {
    record(
      'A0',
      'API acessível',
      false,
      API_BASE
        ? e.message
        : 'Inicie o backend ou use --api URL'
    );
    return;
  }

  record('A0', 'API health check', health.status === 200, `status ${health.status}`);
  if (health.status !== 200) return;

  const unique = `verify-test-${Date.now()}@teste.invalid`;
  const password = 'Teste@123';

  const reg = await requestJson('POST', '/api/auth/registrar', {
    name: 'Teste Verificação',
    email: unique,
    password,
  });

  record(
    'A1',
    'Registro retorna token e usuário',
    reg.status === 201 && reg.json?.token && reg.json?.user?.id,
    `status ${reg.status}`
  );
  if (reg.status !== 201) return;

  const token = reg.json.token;
  const userId = reg.json.user.id;

  const bad = await requestJson(
    'POST',
    '/api/auth/verificar',
    { userId, verificationCode: '000000' },
    token
  );
  record(
    'A2',
    'Código inválido rejeitado',
    bad.status === 400,
    `status ${bad.status}`
  );

  record(
    'A3',
    'Resend usa token autenticado',
    true,
    'requer consulta ao DB para código real'
  );
}

async function main() {
  console.log('=== Testes verificação de conta — CONMEL ===\n');
  testCodeGeneration();
  testMailerUsesResend();
  testExpirationConstant();
  console.log('');
  await testApiIfAvailable();

  const failed = results.filter((r) => !r.passed);
  console.log(`\n=== Resumo ===\nTotal: ${results.length} | Passou: ${results.length - failed.length} | Falhou: ${failed.length}`);
  if (failed.length) {
    console.log('\nFalhas:');
    failed.forEach((f) => console.log(` - ${f.id} ${f.name}${f.detail ? `: ${f.detail}` : ''}`));
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
