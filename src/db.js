// src/db.js
import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

// Teste de conexão modificado
prisma.$connect()
  .then(() => console.log('✅ Conectado ao banco de dados'))
  .catch((error) => console.error('❌ Erro de conexão:', error))

export default prisma