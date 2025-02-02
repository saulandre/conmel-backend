import { body } from 'express-validator';

export const validateLogin = [
  body('email').isEmail().withMessage('Email inválido'),
  body('password').notEmpty().withMessage('Senha é obrigatória'),
];

export const validateRegister = [
  body('name').notEmpty().withMessage('Nome é obrigatório'),
  body('email').isEmail().withMessage('Email inválido'),
  body('password').isLength({ min: 6 }).withMessage('Senha deve ter pelo menos 6 caracteres'),
];

export const validateVerification = [
  body('verificationCode').notEmpty().withMessage('Código de verificação é obrigatório'),
];