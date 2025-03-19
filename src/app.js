import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import dotenv from 'dotenv'

import { PrismaClient } from '@prisma/client'
import authRoutes from './routes/auth.routes.js'

// Configuração inicial
dotenv.config()
const app = express()
const prisma = new PrismaClient()

app.use(helmet())
app.use(cors({
  origin: [process.env.FRONTEND_URL || 'http://localhost:3000', 'https://comejaca.org.br', 'https://comejaca-qa.netlify.app/'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));


app.use(express.json())
app.use(express.urlencoded({ extended: true }))



app.use('/api/auth', authRoutes)

app.get('/api/health', async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`
    res.status(200).json({
      status: 'OK',
      message: 'API and database connection are healthy',
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    res.status(503).json({
      status: 'DOWN',
      message: 'Database connection failed',
      error: error.message
    })
  }
})

app.use((err, req, res, next) => {
  console.error(`🚨 Erro capturado: ${err.message}`)
  console.error('📌 Stack Trace:', err.stack)

  res.status(err.status || 500).json({
    status: 'error',
    message: process.env.NODE_ENV === 'production' 
      ? 'Erro interno do servidor' 
      : err.message
  })
})


const server = app.listen(process.env.PORT || 4000, () => {
  console.log(`🚀 Servidor rodando na porta ${process.env.PORT || 4000}`)
})

const shutdown = async () => {
  console.log('\n🛑 Desligando servidor...')
  await prisma.$disconnect()
  server.close(() => {
    console.log('✅ Servidor finalizado com sucesso')
    process.exit(0)
  })
}

process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)

export { app, prisma }