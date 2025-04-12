const jwt = require('jsonwebtoken');


 const isAuthenticated = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  console.log('Cabeçalhos recebidos:', req.headers);

  // Verifica se o token foi enviado corretamente
  const token = authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;

  console.log('Token extraído:', token);

  if (!token) {
    return res.status(401).json({ error: 'Acesso não autorizado' });
  }
  console.log('Cabeçalhos recebidos:', req.headers);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Token decodificado:', decoded);
    
    req.userId = decoded.id;
    console.log('ID do usuário extraído:', req.userId);

    next();
  } catch (error) {
    console.error('Erro na verificação do token:', error.message);
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
};
module.exports = { isAuthenticated };
