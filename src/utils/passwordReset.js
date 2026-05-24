const jwt = require('jsonwebtoken');

const FORGOT_PASSWORD_GENERIC_OK = {
  message:
    'Se o e-mail estiver cadastrado, você receberá instruções para redefinir a senha em instantes.',
};

const RESET_PASSWORD_POLICY_MESSAGE =
  'A senha deve ter pelo menos 6 caracteres, uma letra maiúscula e um número.';

const RESET_PASSWORD_REGEX = /^(?=.*[A-Z])(?=.*\d).{6,}$/;

function getFrontendBaseUrl() {
  const raw =
    process.env.FRONTEND_URL ||
    process.env.BASE_URL ||
    'http://localhost:3000';
  return String(raw).replace(/\/$/, '');
}

function buildPasswordResetLink(token) {
  const url = new URL('/novasenha', `${getFrontendBaseUrl()}/`);
  url.searchParams.set('token', token);
  return url.toString();
}

function signPasswordResetToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      resetTokenVersion: user.resetTokenVersion,
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

function verifyPasswordResetToken(token) {
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const userId = decoded.userId ?? decoded.id;
  if (!userId) {
    const err = new Error('Token inválido');
    err.name = 'JsonWebTokenError';
    throw err;
  }
  return {
    userId,
    resetTokenVersion: decoded.resetTokenVersion,
  };
}

function validateNewPassword(password) {
  const pwd = String(password ?? '').trim();
  if (!RESET_PASSWORD_REGEX.test(pwd)) {
    return { ok: false, message: RESET_PASSWORD_POLICY_MESSAGE };
  }
  return { ok: true, password: pwd };
}

module.exports = {
  FORGOT_PASSWORD_GENERIC_OK,
  RESET_PASSWORD_POLICY_MESSAGE,
  buildPasswordResetLink,
  signPasswordResetToken,
  verifyPasswordResetToken,
  validateNewPassword,
};
