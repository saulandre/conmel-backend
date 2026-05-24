/**
 * Bateria de testes do fluxo de recuperação de senha (backend + utilitários).
 * Uso: node scripts/test-password-reset-flow.js [--api http://localhost:4000]
 */
const http = require('http');
const https = require('https');
const jwt = require('jsonwebtoken');
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
  const icon = passed ? 'PASS' : 'FAIL';
  console.log(`[${icon}] ${id} ${name}${detail ? ` — ${detail}` : ''}`);
}

function requestJson(method, urlPath, body) {
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
          resolve({ status: res.statusCode, json, headers: res.headers });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function testUtils() {
  const {
    FORGOT_PASSWORD_GENERIC_OK,
    buildPasswordResetLink,
    signPasswordResetToken,
    verifyPasswordResetToken,
    validateNewPassword,
  } = require('../src/utils/passwordReset');

  record(
    'U1',
    'Utilitário: mensagem genérica forgot',
    FORGOT_PASSWORD_GENERIC_OK?.message?.includes('cadastrado')
  );

  const fakeUser = { id: 1, resetTokenVersion: 0 };
  const token = signPasswordResetToken(fakeUser);
  const link = buildPasswordResetLink(token);
  const hasToken = link.includes('token=') && link.includes('/novasenha');
  record('U2', 'Utilitário: link contém /novasenha e token', hasToken, link);

  const verified = verifyPasswordResetToken(token);
  record(
    'U3',
    'Utilitário: verify token userId',
    verified.userId === 1 && verified.resetTokenVersion === 0
  );

  record('U4', 'Utilitário: senha fraca rejeitada', !validateNewPassword('abc').ok);
  record('U5', 'Utilitário: senha forte aceita', validateNewPassword('Abcdef1').ok);

  const expired = jwt.sign(
    { userId: 1, resetTokenVersion: 0 },
    process.env.JWT_SECRET || 'test-secret',
    { expiresIn: '-1s' }
  );
  let expiredOk = false;
  try {
    verifyPasswordResetToken(expired);
  } catch (e) {
    expiredOk = e.name === 'TokenExpiredError';
  }
  record('U6', 'Utilitário: token expirado lança TokenExpiredError', expiredOk);
}

async function testEnv() {
  const required = ['JWT_SECRET', 'DATABASE_URL'];
  const resend = ['RESEND_API_KEY', 'RESEND_FROM_EMAIL', 'FRONTEND_URL', 'BASE_URL'];
  for (const k of required) {
    record('E1', `Env obrigatória ${k}`, !!process.env[k]?.trim());
  }
  const hasResend = !!process.env.RESEND_API_KEY?.trim();
  record('E2', 'RESEND_API_KEY definida', hasResend);
  const hasFrontend =
    !!process.env.FRONTEND_URL?.trim() || !!process.env.BASE_URL?.trim();
  record('E3', 'FRONTEND_URL ou BASE_URL definida', hasFrontend);

  try {
    require('../src/config/mailer');
    record('E4', 'Módulo mailer carrega sem erro', true);
  } catch (e) {
    record('E4', 'Módulo mailer carrega sem erro', false, e.message);
  }
}

async function testApiIfAvailable() {
  if (!process.env.JWT_SECRET) {
    record('A0', 'API: JWT_SECRET ausente — pulando HTTP', true, 'skip');
    return;
  }

  let health;
  try {
    health = await requestJson('GET', '/api/health');
  } catch (e) {
    record(
      'A0',
      'API: servidor acessível',
      false,
      API_BASE
        ? `Não foi possível conectar: ${e.message}`
        : 'Inicie o backend ou use --api URL'
    );
    return;
  }
  record('A0', 'API: health check', health.status === 200, `status ${health.status}`);

  const unknownEmail = `nao-existe-${Date.now()}@teste.invalid`;
  const r1 = await requestJson('POST', '/api/auth/forgot-password', {
    email: unknownEmail,
  });
  const genericMsg = r1.json?.message || '';
  record(
    'A1',
    'API: e-mail inexistente retorna 200 genérico',
    r1.status === 200 && genericMsg.toLowerCase().includes('cadastrado'),
    `status ${r1.status}`
  );

  const r2 = await requestJson('POST', '/api/auth/forgot-password', {});
  record('A2', 'API: e-mail vazio retorna 400', r2.status === 400);

  const badToken = await requestJson('POST', '/api/auth/reset-password', {
    token: 'token-invalido',
    newPassword: 'NovaSenha1',
  });
  record(
    'A3',
    'API: token inválido retorna 400',
    badToken.status === 400,
    `status ${badToken.status}`
  );

  const weakPwd = await requestJson('POST', '/api/auth/reset-password', {
    token: jwt.sign(
      { userId: 999999, resetTokenVersion: 0 },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    ),
    newPassword: 'fraca',
  });
  record(
    'A4',
    'API: senha fraca retorna 400',
    weakPwd.status === 400,
    weakPwd.json?.message || ''
  );

  const mismatch = await requestJson('POST', '/api/auth/reset-password', {
    token: 'x',
    newPassword: '',
  });
  record(
    'A5',
    'API: campos obrigatórios reset',
    mismatch.status === 400
  );

  const corsOrigin = process.env.FRONTEND_URL || 'https://conmelrj.com.br';
  try {
    const opt = await new Promise((resolve, reject) => {
      const base = API_BASE || 'http://127.0.0.1:4000';
      const url = new URL('/api/auth/forgot-password', `${base}/`);
      const lib = url.protocol === 'https:' ? https : http;
      const req = lib.request(
        url,
        {
          method: 'OPTIONS',
          headers: {
            Origin: corsOrigin.replace(/\/$/, ''),
            'Access-Control-Request-Method': 'POST',
          },
        },
        (res) => {
          resolve({
            status: res.statusCode,
            acao: res.headers['access-control-allow-origin'],
          });
        }
      );
      req.on('error', reject);
      req.end();
    });
    record(
      'A6',
      'API: preflight CORS OPTIONS',
      opt.status === 204 || opt.status === 200,
      `status ${opt.status} allow-origin=${opt.acao || 'n/a'}`
    );
  } catch (e) {
    record('A6', 'API: preflight CORS OPTIONS', false, e.message);
  }
}

function testRoutesFile() {
  const fs = require('fs');
  const path = require('path');
  const content = fs.readFileSync(
    path.join(__dirname, '../src/routes/auth.routes.js'),
    'utf8'
  );
  const matches = content.match(/forgot-password/g) || [];
  record(
    'R1',
    'auth.routes: apenas uma rota forgot-password',
    matches.length === 1,
    `ocorrências: ${matches.length}`
  );
  record(
    'R2',
    'auth.routes: sem forgotPassword legado na rota',
    !/router\.post\(['"]\/forgot-password['"],\s*forgotPassword\)/.test(content)
  );
}

async function main() {
  console.log('=== Testes recuperação de senha — CONMEL backend ===\n');
  testRoutesFile();
  console.log('');
  await testEnv();
  console.log('');
  await testUtils();
  console.log('');
  if (API_BASE || process.argv.includes('--try-local')) {
    await testApiIfAvailable();
  } else {
    console.log('(Dica: node scripts/test-password-reset-flow.js --try-local)\n');
  }

  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed);
  console.log('\n=== Resumo ===');
  console.log(`Total: ${results.length} | Passou: ${passed} | Falhou: ${failed.length}`);
  if (failed.length) {
    console.log('\nFalhas:');
    failed.forEach((f) => console.log(` - ${f.id} ${f.name}: ${f.detail}`));
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
