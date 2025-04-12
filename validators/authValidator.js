const { body } = require('express-validator');

const validateLogin = [
  body('email').isEmail().withMessage('Email inválido'),
  body('password').notEmpty().withMessage('Senha é obrigatória'),
];

const validateRegister = [
  body('name').notEmpty().withMessage('Nome é obrigatório'),
  body('email').isEmail().withMessage('Email inválido'),
  body('password').isLength({ min: 6 }).withMessage('Senha deve ter pelo menos 6 caracteres'),
];

const validateVerification = [
  body('verificationCode').notEmpty().withMessage('Código de verificação é obrigatório'),
];

module.exports = {
  validateLogin,
  validateRegister,
  validateVerification,
};