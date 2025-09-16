require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');

const app = express();

console.log('🚀 Iniciando servidor...');

// ✅ CORS mais permissivo para produção
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// ✅ CORS adicional
const allowedOrigins = [
  'https://tritotemfrontend-liart.vercel.app',
  'http://localhost:3000',
  'http://localhost:5173'
];

app.use(cors({
  origin: function (origin, callback) {
    callback(null, true); // Permitir todas as origens
  },
  credentials: true,
}));

// ✅ Responder OPTIONS para preflight
app.options('*', cors());

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

console.log('✅ Middlewares configurados');

// 🛠 Cria a pasta uploads se não existir
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Servir arquivos estáticos
app.use('/uploads', express.static(uploadsDir));

console.log('✅ Pasta uploads configurada');

// HTTP + WebSocket
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
  },
});

// Disponibiliza io nas reqs
app.use((req, _res, next) => {
  req.io = io;
  next();
});

console.log('✅ WebSocket configurado');

// 🔗 Conexão MongoDB
(async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ Conectado ao MongoDB');
  } catch (err) {
    console.error('❌ Erro ao conectar ao MongoDB:', err);
  }
})();

// 🎥 STREAM com suporte a range
app.get('/stream/:filename', (req, res) => {
  try {
    const filePath = path.join(uploadsDir, req.params.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Arquivo não encontrado' });
    }

    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const range = req.headers.range;
    const ext = path.extname(filePath).toLowerCase();
    const mime =
      ext === '.webm' ? 'video/webm' :
      ext === '.ogg'  ? 'video/ogg'  :
                        'video/mp4';

    if (range) {
      const [startStr, endStr] = range.replace(/bytes=/, '').split('-');
      const start = parseInt(startStr, 10);
      const end = endStr ? parseInt(endStr, 10) : fileSize - 1;

      if (start >= fileSize || end >= fileSize) {
        res.status(416).set('Content-Range', `bytes */${fileSize}`).end();
        return;
      }

      const chunkSize = end - start + 1;
      const file = fs.createReadStream(filePath, { start, end });

      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunkSize,
        'Content-Type': mime,
        'Cache-Control': 'no-store',
      });

      file.pipe(res);
    } else {
      res.writeHead(200, {
        'Content-Length': fileSize,
        'Content-Type': mime,
        'Accept-Ranges': 'bytes',
        'Cache-Control': 'no-store',
      });

      fs.createReadStream(filePath).pipe(res);
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

console.log('✅ Rota de stream configurada');

// Healthcheck
app.get('/', (_req, res) => res.json({ message: 'API Tritotem funcionando!' }));

console.log('✅ Healthcheck configurado');

// ✅ Carregamento individual das rotas com debug
console.log('🔍 Carregando rotas...');

// 1. AUTH
try {
  console.log('🔍 Tentando carregar rota AUTH...');
  const authRoute = require('./routes/auth');
  app.use('/api/auth', authRoute);
  console.log('✅ Rota AUTH carregada com sucesso');
} catch (error) {
  console.error('❌ ERRO na rota AUTH:', error.message);
  console.error('Stack:', error.stack);
}

// 2. USERS
try {
  console.log('🔍 Tentando carregar rota USERS...');
  const usersRoute = require('./routes/users');
  app.use('/api/users', usersRoute);
  console.log('✅ Rota USERS carregada com sucesso');
} catch (error) {
  console.error('❌ ERRO na rota USERS:', error.message);
  console.error('Stack:', error.stack);
}

// 3. MEDIA
try {
  console.log('🔍 Tentando carregar rota MEDIA...');
  const mediaRoute = require('./routes/media');
  app.use('/api/media', mediaRoute);
  console.log('✅ Rota MEDIA carregada com sucesso');
} catch (error) {
  console.error('❌ ERRO na rota MEDIA:', error.message);
  console.error('Stack:', error.stack);
}

// 4. PLAYLISTS
try {
  console.log('🔍 Tentando carregar rota PLAYLISTS...');
  const playlistsRoute = require('./routes/playlists');
  app.use('/api/playlists', playlistsRoute);
  console.log('✅ Rota PLAYLISTS carregada com sucesso');
} catch (error) {
  console.error('❌ ERRO na rota PLAYLISTS:', error.message);
  console.error('Stack:', error.stack);
}

// 5. DEVICES
try {
  console.log('🔍 Tentando carregar rota DEVICES...');
  const devicesRoute = require('./routes/devices');
  app.use('/api/devices', devicesRoute);
  console.log('✅ Rota DEVICES carregada com sucesso');
} catch (error) {
  console.error('❌ ERRO na rota DEVICES:', error.message);
  console.error('Stack:', error.stack);
}

// 6. PLAYER
try {
  console.log('🔍 Tentando carregar rota PLAYER...');
  const playerRoute = require('./routes/player');
  app.use('/player', playerRoute);
  console.log('✅ Rota PLAYER carregada com sucesso');
} catch (error) {
  console.error('❌ ERRO na rota PLAYER:', error.message);
  console.error('Stack:', error.stack);
}

console.log('✅ Todas as rotas processadas');

// WebSocket
io.on('connection', (socket) => {
  console.log('🟢 Cliente conectado:', socket.id);

  socket.on('disconnect', () => {
    console.log('🔴 Cliente desconectado:', socket.id);
  });
});

// Iniciar servidor
const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
  console.log('✅ Servidor iniciado com sucesso!');
});
