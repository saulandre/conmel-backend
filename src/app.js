const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');

const { PrismaClient } = require('@prisma/client');
const authRoutes = require('./routes/auth.routes');

// Configuração inicial
dotenv.config()
const app = express()
const prisma = new PrismaClient()

app.use(helmet())
app.use(cors({
  origin: [process.env.FRONTEND_URL || 'https://conmelrj.com.br/', 'https://comejaca.org.br', 'https://comejaca-qa.netlify.app/'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
app.options('*', cors());


app.use(express.json())
app.use(express.urlencoded({ extended: true }))



app.use('/api/auth', authRoutes)
app.get('/api/health', async (req, res) => {
  const services = {
    api: 'UP',
    database: 'UP'
  };

  let dbOk = true;

  try {
    await prisma.$queryRaw`SELECT 1`;
  } catch (err) {
    services.database = 'DOWN';
    dbOk = false;
  }

  const status = dbOk ? 'UP' : services.api === 'UP' ? 'PARTIAL' : 'DOWN';

  res.status(dbOk ? 200 : 503).json({
    status,
    services,
    message: dbOk
      ? 'Working...'
      : 'API is up but database connection failed',
    timestamp: new Date().toISOString()
  });
});



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

module.exports = { app, prisma };
