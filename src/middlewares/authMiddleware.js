import jwt from 'jsonwebtoken';

export const isAuthenticated = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  // Log para verificar se o token foi extraído corretamente
  console.log('Token extraído:', token);

  if (!token) {
    return res.status(401).json({ error: 'Acesso não autorizado' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Log para verificar o conteúdo do token decodificado
    console.log('Token decodificado:', decoded);

    req.user = decoded; // Adiciona o usuário decodificado ao objeto de requisição
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
};
