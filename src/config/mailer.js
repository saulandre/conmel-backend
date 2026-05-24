/**
 * Ponto de entrada legado dos controllers — delega para Resend (email.service).
 * Não usa mais Nodemailer/SMTP.
 */
const { sendMail, sendEmail } = require('../services/email.service');

module.exports = { sendMail, sendEmail };
