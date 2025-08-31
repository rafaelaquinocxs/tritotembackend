require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Pastas estáticas
const uploadsDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// Serve arquivos estáticos
app.use('/uploads', express.static(uploadsDir)); // útil para download direto

// HTTP + Socket.IO
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET','POST','PUT','DELETE'] }
});

// Expõe o io para as rotas
app.use((req, _res, next) => { req.io = io; next(); });

// Conexão Mongo
(async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Conectado ao MongoDB');
  } catch (err) {
    console.error('Erro ao conectar ao MongoDB:', err);
  }
})();

/**
 * STREAM de vídeo com suporte a Range (206 Partial Content)
 * Use esta rota nas tags <video src="...">
 */
app.get('/stream/:filename', (req, res) => {
  try {
    const filePath = path.join(uploadsDir, req.params.filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Arquivo não encontrado' });
    }

    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const range = req.headers.range;

    // Com Range (recomendado pelos browsers para <video>)
    if (range) {
      const parts = range.replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;

      if (start >= fileSize || end >= fileSize) {
        res.status(416).set({
          'Content-Range': `bytes */${fileSize}`,
        }).end();
        return;
      }

      const chunkSize = (end - start) + 1;
      const file = fs.createReadStream(filePath, { start, end });

      // define Content-Type por extensão (mp4 padrão)
      const ext = path.extname(filePath).toLowerCase();
      const mime = ext === '.webm' ? 'video/webm'
                 : ext === '.ogg'  ? 'video/ogg'
                 : 'video/mp4';

      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunkSize,
        'Content-Type': mime,
        'Cache-Control': 'no-store',
      });
      file.pipe(res);
      return;
    }

    // Sem Range (fallback)
    const ext = path.extname(filePath).toLowerCase();
    const mime = ext === '.webm' ? 'video/webm'
               : ext === '.ogg'  ? 'video/ogg'
               : 'video/mp4';

    res.writeHead(200, {
      'Content-Length': fileSize,
      'Content-Type': mime,
      'Accept-Ranges': 'bytes',
      'Cache-Control': 'no-store',
    });
    fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Rotas de API
app.use('/api/media', require('./routes/media'));
app.use('/api/playlists', require('./routes/playlists'));
app.use('/api/devices', require('./routes/devices'));

// Player (agora inline, sem arquivo no disco)
app.use('/player', require('./routes/player'));

// Healthcheck
app.get('/', (_req, res) => res.json({ message: 'API Tritotem funcionando!' }));

// Socket.IO
io.on('connection', (socket) => {
  console.log('Cliente conectado:', socket.id);
  socket.on('disconnect', () => console.log('Cliente desconectado:', socket.id));
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
