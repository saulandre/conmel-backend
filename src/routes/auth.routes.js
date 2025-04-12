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
  resetPassword
} = require('../controllers/auth.controller.js');

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


router.post('/novainstituicao', isAuthenticated, isAdmin,  criarInstituicao);
router.get('/instituicoes', listarInstituicoes);
router.put('/editarinstituicao/:id', isAuthenticated, atualizarInstituicao);
router.put('/updateProfile/:id', isAuthenticated, updateProfile)

router.post('/forgot-password', forgotPassword);
router.post('/recuperarsenha', resetPassword);
// Middleware de tratamento de erros global
router.use((err, req, res, next) => {
  console.error('💥 Erro:', err.message);
  res.status(500).json({ error: 'Erro interno do servidor' });
});



module.exports = router;
