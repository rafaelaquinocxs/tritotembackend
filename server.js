require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

console.log('🚀 Iniciando servidor mínimo...');

const app = express();

// CORS simples
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());

console.log('✅ Middlewares básicos configurados');

// Healthcheck
app.get('/', (req, res) => {
  res.json({ message: 'API Tritotem funcionando!' });
});

console.log('✅ Healthcheck configurado');

// Conexão MongoDB
(async () => {
  try {
    if (process.env.MONGODB_URI) {
      await mongoose.connect(process.env.MONGODB_URI);
      console.log('✅ Conectado ao MongoDB');
    } else {
      console.log('⚠️ MONGODB_URI não configurado');
    }
  } catch (err) {
    console.error('❌ Erro ao conectar ao MongoDB:', err);
  }
})();

// Rota simples de teste
app.get('/test', (req, res) => {
  res.json({ message: 'Teste OK' });
});

console.log('✅ Rota de teste configurada');

// Iniciar servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor mínimo rodando na porta ${PORT}`);
  console.log('✅ Servidor iniciado com sucesso!');
});
