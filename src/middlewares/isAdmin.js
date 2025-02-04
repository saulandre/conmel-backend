import prisma from '../prisma.js';

export const isAdmin = async (req, res, next) => {
    const userId = req.user?.id || req.body.userId;
  
    if (!userId) {
      return res.status(400).json({ error: "ID do usuário não fornecido." });
    }
  
    // Verificando se o usuário existe
    const user = await prisma.users.findUnique({
      where: { id: userId },
    });
  
    if (!user) {
      return res.status(404).json({ error: "Usuário não encontrado." });
    }
  
    // Verificando se o usuário tem permissão de admin
    if (user.role !== "admin") {
      return res.status(403).json({ error: "Acesso negado. Apenas administradores podem editar instituições." });
    }
  
    next(); // Se for admin, permite continuar com a edição
  };
  