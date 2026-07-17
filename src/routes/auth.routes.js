const express = require('express');
const { isAuthenticated } = require('../middlewares/authMiddleware.js');
const {
  login,
  register,
  resendVerificationCode,
  verificar,
  enviarEmailRedefinicao,
  validateToken,
  participante,
  obterInscricao,
  getparticipantes,
  criarInstituicao,
  listarInstituicoes,
  atualizarInstituicao,
  updateProfile,
  paymentId,
  resetPassword,
  listarParticipantes,
  notificacao,
  AtualizarpaymentId,
  atualizarPerfil,
  updateInscricao,
  enviarEmailComArquivo,
  getRegistrationStatus,
} = require('../controllers/auth.controller.js');
const upload = require('../config/upload');
const {
  validateLogin,
  validateRegister,
  validateVerification,
} = require('../../validators/authValidator.js');

const { isAdmin } = require('../middlewares/isAdmin.js');

const router = express.Router();
const fs = require('fs');

router.use((req, res, next) => {
  console.log(`📥 Nova requisição: ${req.method} ${req.url}`);
  next();
});

// --- Recuperação de senha (público; ordem: um handler por rota) ---
router.post('/forgot-password', enviarEmailRedefinicao);
router.post('/reset-password', resetPassword);
/** Legado: redefinição com { token, newPassword } no body */
router.post('/recuperarsenha', resetPassword);

// --- Autenticação pública ---
router.post('/entrar', validateLogin, login);
router.post('/registrar', validateRegister, register);
router.get('/inscricoes-status', getRegistrationStatus);

// --- Rotas autenticadas ---
router.post('/verificar', isAuthenticated, validateVerification, verificar);
router.post('/enviarcodigo', isAuthenticated, resendVerificationCode);
router.post('/validartoken', isAuthenticated, validateToken);
router.post('/inscrever', isAuthenticated, participante);
router.get('/inscrever', isAuthenticated, participante);
router.get('/obterinscricoes', isAuthenticated, getparticipantes);
router.get('/print/:participanteId', isAuthenticated, obterInscricao);
router.get('/pagamento/:id', isAuthenticated, paymentId);
router.get('/pagamentos', isAuthenticated, listarParticipantes);
router.post('/mercadopago/notificacao', notificacao);
router.post('/novainstituicao', isAuthenticated, isAdmin, criarInstituicao);
router.get('/instituicoes', listarInstituicoes);
router.put('/editarinstituicao/:id', isAuthenticated, atualizarInstituicao);
router.put('/updateProfile/:id', isAuthenticated, isAdmin, updateProfile);
router.put('/pagamentos/:id/status', isAuthenticated, isAdmin, AtualizarpaymentId);
router.put('/atualizarPerfil/', isAuthenticated, atualizarPerfil);
router.put('/participante/:id', isAuthenticated, updateInscricao);

router.post('/enviar-comprovante', upload.single('arquivo'), async (req, res) => {
  const { nomeCompleto, email } = req.body;
  const arquivo = req.file;

  if (!nomeCompleto || !arquivo) {
    return res.status(400).json({ erro: 'Nome completo e arquivo são obrigatórios.' });
  }

  try {
    await enviarEmailComArquivo(nomeCompleto, arquivo);
    res.status(200).json({ mensagem: 'Comprovante enviado com sucesso!' });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  } finally {
    if (arquivo?.path) {
      fs.unlink(arquivo.path, (err) => {
        if (err) console.error('Erro ao remover arquivo temporário:', err);
      });
    }
  }
});

router.use((err, req, res, next) => {
  console.error('💥 Erro:', err.message);
  res.status(500).json({ error: 'Erro interno do servidor' });
});

module.exports = router;
