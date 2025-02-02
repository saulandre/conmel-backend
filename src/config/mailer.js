import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

// Criação do transportador para o Nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST, // smtp.gmail.com
  port: Number(process.env.MAIL_PORT), // 587 (para Gmail)
  secure: process.env.MAIL_PORT === "465", // Verifica se a porta é 465 (SSL)
  auth: {
    user: process.env.MAIL_USER, // E-mail de envio
    pass: process.env.MAIL_PASS, // Senha ou App Password (para Gmail)
  },
});

// Testando a conexão
transporter.verify((error, success) => {
  if (error) {
    console.log("Erro ao conectar no SMTP:", error);
  } else {
    console.log("Conexão SMTP bem-sucedida!");
  }
});

export default transporter;
