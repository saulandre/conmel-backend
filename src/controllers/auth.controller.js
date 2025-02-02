import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import prisma from '../prisma.js';
import { generateVerificationCode } from '../services/validation.js';
import dotenv from 'dotenv';
import transporter from '../config/mailer.js';

dotenv.config();


// Constantes atualizadas para mensagens
const MESSAGES = {
  errors: {
    missingFields: 'O e-mail e a senha são obrigatórios.',
    emailInUse: 'E-mail já está em uso.',
    userNotFound: 'Usuário não encontrado.',
    invalidCredentials: 'Credenciais inválidas.',
    verificationCodeInvalid: 'Código de verificação inválido ou expirado.',
    internalError: 'Erro interno do servidor.',
    invalidEmail: 'Email inválido.',
    emailExists: 'Email já cadastrado.',
    unverifiedUser: 'Por favor, verifique seu e-mail antes de fazer login.',
    invalidData: 'Dados inválidos fornecidos.',
    codeExpired: 'Código expirado. Solicite um novo.',
    resendTooSoon: 'Aguarde 60 segundos antes de reenviar o código.',
  },
  success: {
    verificationEmailSent: 'Código de verificação enviado. Verifique seu e-mail.',
    verifiedUser: 'Usuário verificado com sucesso!',
    registeredUser: 'Usuário registrado com sucesso!',
    loggedIn: 'Login realizado com sucesso!',
    passwordReset: 'Senha redefinida com sucesso!',
    updatedUser: 'Dados atualizados com sucesso!',
    deletedUser: 'Conta removida com sucesso!',
    inscriptionCreated: 'Inscrição realizada com sucesso!',
  },
};

// Configurações
const CODE_EXPIRATION_TIME = 15 * 60 * 1000; // 15 minutos
const RESEND_INTERVAL = 60000; // 60 segundos
export const newAccountEmail = async (name, email, code) => {
  try {
    await transporter.sendMail({
      from: `"COMEJACA Gestão" <${process.env.MAIL_USER}>`,
      to: email,
      subject: 'Confirmação de Cadastro - Sistema de Gestão COMEJACA',
      html: `
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Confirmar Cadastro</title>
          <style>
            body {
              font-family: 'Arial', sans-serif;
              margin: 0;
              padding: 30px 0;
              background-color: #22223b;
            }
            .container {
              max-width: 680px;
              margin: 0 auto;
              background-color: #ffffff;
              border-radius: 8px;
              box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            }
            .header {
              padding: 40px 30px 20px;
              border-bottom: 1px solid #e9ecef;
              text-align: center;
            }
            .header img {
              height: 40px;
            }
            .content {
              padding: 40px 30px;
              color: #4a4e69;
            }
            .code-container {
              margin: 30px 0;
              text-align: center;
            }
            .verification-code {
              display: inline-block;
              padding: 15px 30px;
              background-color: #22223b;
              border-radius: 6px;
              font-size: 24px;
              font-weight: 600;
              color: #fff;
              letter-spacing: 2px;
            }
              a {
  color: #2b6cb0 !important;
  text-decoration: none !important;
}
            .footer {
              padding: 25px 30px;
              background-color: #f8f9fa;
              text-align: center;
              font-size: 14px;
              color: #6c757d;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <img src="https://via.placeholder.com/200x50?text=COMEJACA+Logo" alt="Logo COMEJACA">
            </div>
            
            <div class="content">
              <p>Prezado(a) ${name},</p>
              
              <p>Seu cadastro no Sistema de <strong>Gestão de Inscrição</strong> da COMEJACA está quase completo. <br><br>Para acessar sem restrições ao Gestor você precisa verificar o seu e-mail. <br> <br> Insira o código abaixo em <a href="https://www.comejaca.org.br" target="_blank">COMEJACA</a>.</p>

              <div class="code-container">
                <div class="verification-code">${code}</div>
              </div>

              <p>⏳ Este código é válido por 15 minutos.</p>

        

              <p>Atenciosamente,<br>
              Equipe de Tecnologia COMEJACA</p>
            </div>

            <div class="footer">
              <p>Esta é uma mensagem automática. Por favor não responda este e-mail.</p>
              <p>Dúvidas? Contate-nos: suporte@comejaca.org.br </p>
              <p>© ${new Date().getFullYear()} COMEJACA Gestão. Todos os direitos reservados.</p>
            </div>
          </div>
        </body>
        </html>
      `,
    });

    console.log(`✅ E-mail de verificação enviado para: ${email}`);
  } catch (error) {
    console.error('❌ Erro ao enviar e-mail:', error);
    throw new Error('Falha no envio do e-mail');
  }
};

export const accountVerifiedEmail = async (name, email) => {
  try {
    await transporter.sendMail({
      from: `"COMEJACA Gestão" <${process.env.MAIL_USER}>`,
      to: email,
      subject: 'Conta Verificada com Sucesso - Sistema de Gestão COMEJACA',
      html: `
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Conta Verificada</title>
          <style>
            body {
              font-family: 'Arial', sans-serif;
              margin: 0;
              padding: 30px 0;
              background-color: #22223b;
            }
            .container {
              max-width: 680px;
              margin: 0 auto;
              background-color: #ffffff;
              border-radius: 8px;
              box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            }
            .header {
              padding: 40px 30px 20px;
              border-bottom: 1px solid #e9ecef;
              text-align: center;
            }
            .header img {
              height: 40px;
            }
            .content {
              padding: 40px 30px;
              color: #4a4e69;
            }
            .success-message {
              text-align: center;
              margin: 30px 0;
              font-size: 20px;
              font-weight: 600;
              color: #2ecc71;
            }
            a {
              color: #2b6cb0 !important;
              text-decoration: none !important;
            }
            .footer {
              padding: 25px 30px;
              background-color: #f8f9fa;
              text-align: center;
              font-size: 14px;
              color: #6c757d;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <img src="https://via.placeholder.com/200x50?text=COMEJACA+Logo" alt="Logo COMEJACA">
            </div>
            
            <div class="content">
              <p>Prezado(a) ${name},</p>
              
              <p>Sua conta no Sistema de <strong>Gestão de Inscrição</strong> da COMEJACA foi verificada com sucesso! 🎉</p>

              <div class="success-message">
                ✅ Conta Verificada com Sucesso!
              </div>

              <p>Agora você tem acesso completo ao sistema. Para começar a utilizar todas as funcionalidades, <a href="https://www.comejaca.org.br" target="_blank">clique aqui</a>.</p>

              <p>Estamos empenhados em fazer você ter a melhor experiencia.</p>

              <p>Atenciosamente,<br>
              Equipe de Tecnologia COMEJACA</p>
            </div>

            <div class="footer">
              <p>Esta é uma mensagem automática. Por favor não responda este e-mail.</p>
              <p>Dúvidas? Contate-nos: suporte@comejaca.org.br </p>
              <p>© ${new Date().getFullYear()} COMEJACA Gestão. Todos os direitos reservados.</p>
            </div>
          </div>
        </body>
        </html>
      `,
    });

    console.log(`✅ E-mail de confirmação de verificação enviado para: ${email}`);
  } catch (error) {
    console.error('❌ Erro ao enviar e-mail:', error);
    throw new Error('Falha no envio do e-mail');
  }
};

export const novoCodigoEmail = async (name, email, code) => {
  try {
    await transporter.sendMail({
      from: `"COMEJACA Gestão" <${process.env.MAIL_USER}>`,
      to: email,
      subject: 'Novo código',
      html: `
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Novo código</title>
          <style>
            body {
              font-family: 'Arial', sans-serif;
              margin: 0;
              padding: 30px 0;
              background-color: #22223b;
            }
            .container {
              max-width: 680px;
              margin: 0 auto;
              background-color: #ffffff;
              border-radius: 8px;
              box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            }
            .header {
              padding: 40px 30px 20px;
              border-bottom: 1px solid #e9ecef;
              text-align: center;
            }
            .header img {
              height: 40px;
            }
            .content {
              padding: 40px 30px;
              color: #4a4e69;
            }
            .code-container {
              margin: 30px 0;
              text-align: center;
            }
            .verification-code {
              display: inline-block;
              padding: 15px 30px;
              background-color: #22223b;
              border-radius: 6px;
              font-size: 24px;
              font-weight: 600;
              color: #fff;
              letter-spacing: 2px;
            }
              a {
  color: #2b6cb0 !important;
  text-decoration: none !important;
}
            .footer {
              padding: 25px 30px;
              background-color: #f8f9fa;
              text-align: center;
              font-size: 14px;
              color: #6c757d;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <img src="https://via.placeholder.com/200x50?text=COMEJACA+Logo" alt="Logo COMEJACA">
            </div>
            
            <div class="content">
              <p>Prezado(a) ${name},</p>
              
              <p>Seu cadastro no Sistema de <strong>Gestão de Inscrição</strong> da COMEJACA está quase completo. <br><br> O próximo passo é verificar seu endereço e-mail inserindo o código abaixo através do portal <a href="https://www.comejaca.org.br" target="_blank">COMEJACA</a>.</p>

              <div class="code-container">
                <div class="verification-code">${code}</div>
              </div>

              <p>⏳ Este código é válido por 15 minutos.</p>

        

              <p>Atenciosamente,<br>
              Equipe de Tecnologia COMEJACA</p>
            </div>

            <div class="footer">
              <p>Esta é uma mensagem automática. Por favor não responda este e-mail.</p>
              <p>Dúvidas? Contate-nos: suporte@comejaca.org.br </p>
              <p>© ${new Date().getFullYear()} COMEJACA Gestão. Todos os direitos reservados.</p>
            </div>
          </div>
        </body>
        </html>
      `,
    });

    console.log(`✅ E-mail de verificação enviado para: ${email}`);
  } catch (error) {
    console.error('❌ Erro ao enviar e-mail:', error);
    throw new Error('Falha no envio do e-mail');
  }
};

export const verificar = async (req, res) => {
  const { userId, verificationCode } = req.body;
  console.log('Dados recebidos:', req.body);  // Adicionando log para verificar os dados

  if (!userId || !verificationCode) {
    return res.status(400).json({ error: MESSAGES.errors.missingFields });
  }

  try {
    // Busca o usuário no banco de dados
    const user = await prisma.users.findUnique({ where: { id: userId } });

    if (!user) {
      return res.status(404).json({ error: MESSAGES.errors.userNotFound });
    }

    // Verifica se o código de verificação coincide
    if (user.verificationCode !== verificationCode) {
      return res.status(400).json({ error: MESSAGES.errors.verificationCodeInvalid });
    }

    // Verifica se o código de verificação expirou
    if (new Date(user.verificationCodeExpiration).getTime() < new Date().getTime()) {
      return res.status(400).json({ error: MESSAGES.errors.codeExpired });
    }

    // Atualiza o usuário e confirma a transação
    const updatedUser = await prisma.users.update({
      where: { id: userId },
      data: {
        isVerified: true,
        verificationCode: null, // Invalida o código de verificação após o uso
        verificationCodeExpiration: null, // Limpa a data de expiração
      },
    });

    // Envia o e-mail de confirmação de verificação
    await accountVerifiedEmail(updatedUser.name, updatedUser.email);

    // Geração do token após a verificação
    const token = jwt.sign(
      { id: updatedUser.id, email: updatedUser.email, isVerified: true },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Retorno com a mensagem de sucesso e os dados do usuário
    return res.json({
      message: MESSAGES.success.verifiedUser,
      token,
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        isVerified: updatedUser.isVerified,
      },
    });
  } catch (error) {
    console.error('Verification Error:', error);
    return res.status(500).json({
      error: MESSAGES.errors.internalError,
      details: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
};



export const validateToken = async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ valid: false, error: "Token não fornecido" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ valid: true, user: decoded });

  } catch (error) {
    let errorMessage = "Token inválido";

    if (error.name === "TokenExpiredError") {
      errorMessage = "Token expirado. Faça login novamente.";
    } else if (error.name === "JsonWebTokenError") {
      errorMessage = "Token malformado.";
    }

    res.status(401).json({ valid: false, error: errorMessage });
  }
};


export const register = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Validação dos campos
    if (!name || !email || !password) {
      return res.status(400).json({ error: MESSAGES.errors.missingFields });
    }

    // Verifica usuário existente
    const existingUser = await prisma.users.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: MESSAGES.errors.emailInUse });
    }

    // Criptografia da senha
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Geração do código de verificação
    const verificationCode = generateVerificationCode();
    const verificationCodeExpiration = new Date(Date.now() + CODE_EXPIRATION_TIME);

    // Criação do usuário
    const newUser = await prisma.users.create({
      data: {
        name,
        email,
        password: hashedPassword,
        verificationCode,
        verificationCodeExpiration,
        isVerified: false,
      },
    });

    // Geração do JWT
    const token = jwt.sign(
      {
        id: newUser.id,
        email: newUser.email,
        isVerified: newUser.isVerified
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRATION || '2h' }
    );

    // Envio do e-mail de verificação
    await newAccountEmail(name, email, verificationCode);

    // Resposta com JWT e dados do usuário
    return res.status(201).json({
      message: MESSAGES.success.verificationEmailSent,
      token: token,
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        isVerified: newUser.isVerified
      }
    });

  } catch (error) {
    console.error('Registration Error:', error);
    return res.status(500).json({ 
      error: MESSAGES.errors.internalError,
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    console.log('Buscando usuário no banco de dados...');
    const user = await prisma.users.findUnique({ where: { email } });

    if (!user) {
      console.log('Usuário não encontrado:', email);
      return res.status(404).json({ error: MESSAGES.errors.userNotFound });
    }

    console.log('Usuário encontrado:', user);

    if (!user.isVerified) {
      console.log('Usuário não verificado:', user.email);
      return res.status(403).json({ error: MESSAGES.errors.unverifiedUser });
    }

    console.log('Verificando senha...');
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      console.log('Senha inválida para o usuário:', user.email);
      return res.status(401).json({ error: MESSAGES.errors.invalidCredentials });
    }

    console.log('Gerando token JWT...');
    const token = jwt.sign(
      { id: user.id, email: user.email, isVerified: true },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    console.log('Login bem-sucedido. Retornando token e dados do usuário...');
    return res.json({
      message: MESSAGES.success.loggedIn,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        isVerified: user.isVerified,
      },
    });
  } catch (error) {
    console.error('Login Error:', error);
    return res.status(500).json({ error: MESSAGES.errors.internalError });
  }
};
export const resendVerificationCode = async (req, res) => {
  const { email } = req.body;

  try {
    console.log('Iniciando reenvio do código de verificação para:', email);

    // Verifica se o usuário existe
    const user = await prisma.users.findUnique({ where: { email } });

    if (!user) {
      console.log(`Usuário não encontrado: ${email}`);
      return res.status(400).json({ error: MESSAGES.errors.userNotFound });
    }

    console.log(`Usuário encontrado: ${user.name}`);

    // Gera um novo código de verificação
    const newVerificationCode = generateVerificationCode();
    const verificationCodeExpiration = new Date(Date.now() + CODE_EXPIRATION_TIME);

    // Atualiza o código e a data de expiração no banco
    await prisma.users.update({
      where: { email },
      data: {
        verificationCode: newVerificationCode,
        verificationCodeExpiration,
      },
    });

    console.log('Novo código gerado e banco de dados atualizado.');

    // Envia o e-mail de verificação
    await novoCodigoEmail(user.name, user.email, newVerificationCode);

    console.log(`E-mail de verificação enviado para: ${user.email}`);

    return res.status(200).json({ message: MESSAGES.success.verificationCodeResent });
  } catch (error) {
    console.error('Erro ao reenviar código de verificação:', error);
    return res.status(500).json({
      error: MESSAGES.errors.internalError,
      details: process.env.NODE_ENV === 'development' ? error.message : undefined,
    });
  }
};
