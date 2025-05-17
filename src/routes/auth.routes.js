const express = require('express');
const { isAuthenticated } = require('../middlewares/authMiddleware.js');
const {
  login,
  register,
  resendVerificationCode,
  verificar,
  validateToken,
  participante,
  obterInscricao,
  getparticipantes,
  criarInstituicao,
  listarInstituicoes,
  atualizarInstituicao,
  updateProfile,
  paymentId,
  forgotPassword,
  resetPassword,
  listarParticipantes,
  notificacao,
  AtualizarpaymentId,
  atualizarPerfil,
  updateInscricao,
  enviarComprovante
} = require('../controllers/auth.controller.js');
const upload = require('../middlewares/upload');

const {
  validateLogin,
  validateRegister,
  validateVerification
} = require('../../validators/authValidator.js');

const { isAdmin } = require('../middlewares/isAdmin.js');

const router = express.Router();


// Middleware de logs para monitorar acesso
router.use((req, res, next) => {
  console.log(`📥 Nova requisição: ${req.method} ${req.url}`);
  next();
});

// Rotas públicas
router.post('/entrar', validateLogin, login); // Validação de dados antes do login
router.post('/registrar', validateRegister, register); // Validação de dados antes do registro

// Rotas protegidas (requerem autenticação)
/* router.post('/verificar', isAuthenticated, validateVerification, verificar); */
router.post('/verificar', isAuthenticated, validateVerification, verificar); // Validação de dados antes de verificar
router.post('/enviarcodigo', isAuthenticated, resendVerificationCode);
router.post('/validartoken', isAuthenticated, validateToken);
router.post('/inscrever', isAuthenticated, participante);
router.get('/inscrever', isAuthenticated, participante);
router.get('/obterinscricoes', isAuthenticated, getparticipantes);
router.get('/print/:participanteId', isAuthenticated, obterInscricao);
router.get('/pagamento/:id', isAuthenticated, paymentId);
router.get('/pagamentos', isAuthenticated, listarParticipantes);
router.post('/mercadopago/notificacao', notificacao);
router.post('/novainstituicao', isAuthenticated, isAdmin,  criarInstituicao);
router.get('/instituicoes', listarInstituicoes);
router.put('/editarinstituicao/:id', isAuthenticated, atualizarInstituicao);
router.put('/updateProfile/:id', isAuthenticated, isAdmin, updateProfile)
router.put('/pagamentos/:id/status', isAuthenticated, isAdmin, AtualizarpaymentId);
router.put('/atualizarPerfil/', isAuthenticated, atualizarPerfil)
router.put('/participante/:id', isAuthenticated, updateInscricao);
router.post('/enviar-comprovante', 
  upload.single('comprovante'), // Middleware Multer
  (req, res, next) => { // Middleware para log
    console.log("Arquivo recebido:", req.file);
    console.log("Dados do corpo:", req.body);
    next();
  },
  enviarComprovante
);
router.post('/forgot-password', forgotPassword);
router.post('/recuperarsenha', resetPassword);
// Middleware de tratamento de erros global
router.use((err, req, res, next) => {
  console.error('💥 Erro:', err.message);
  res.status(500).json({ error: 'Erro interno do servidor' });
});



module.exports = router;
