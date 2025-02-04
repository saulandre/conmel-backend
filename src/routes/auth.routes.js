import { Router } from 'express';
import {
  login,
  register,
  resendVerificationCode,
  verificar,
  validateToken,
  participante,
  getparticipantes,
  criarInstituicao,
  listarInstituicoes
} from '../controllers/auth.controller.js';
import { isAuthenticated } from '../middlewares/authMiddleware.js';
import { validateLogin, validateRegister, validateVerification } from '../../validators/authValidator.js'; // Middlewares de validação
import { isAdmin } from '../middlewares/isAdmin.js';
const router = Router();

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
router.post('/validartoken', isAuthenticated, validateVerification, validateToken);
router.post('/inscrever', isAuthenticated, validateVerification, participante);
router.get('/inscrever', isAuthenticated, validateVerification, participante);
router.get('/obterinscricoes', isAuthenticated, validateVerification, getparticipantes);
router.post('/instituicao', isAuthenticated, validateVerification, isAdmin, criarInstituicao);
router.get('/listarInstituicoes', isAuthenticated, validateVerification, listarInstituicoes);
// Middleware de tratamento de erros global
router.use((err, req, res, next) => {
  console.error('💥 Erro:', err.message);
  res.status(500).json({ error: 'Erro interno do servidor' });
});



export default router;