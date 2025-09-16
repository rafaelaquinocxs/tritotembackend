require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');

console.log('🚀 Iniciando servidor completo...');

const app = express();

// CORS configurado
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

console.log('✅ Middlewares configurados');

// Pasta uploads
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));

console.log('✅ Pasta uploads configurada');

// WebSocket
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
  },
});

app.use((req, _res, next) => {
  req.io = io;
  next();
});

console.log('✅ WebSocket configurado');

// MongoDB
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

// Stream de vídeo
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
    const mime = ext === '.webm' ? 'video/webm' : ext === '.ogg' ? 'video/ogg' : 'video/mp4';

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
app.get('/', (req, res) => {
  res.json({ message: 'API Tritotem funcionando!' });
});

console.log('✅ Healthcheck configurado');

// ✅ ROTAS INLINE (sem arquivos externos para evitar erros)

// AUTH ROUTES
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// Modelo User inline
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'content_manager'], default: 'content_manager' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Middleware de auth inline
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de acesso requerido' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/init', async (req, res) => {
  try {
    const adminExists = await User.findOne({ role: 'admin' });
    if (adminExists) {
      return res.status(400).json({ error: 'Administrador já existe' });
    }

    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const admin = new User({
      name,
      email,
      password: hashedPassword,
      role: 'admin'
    });

    await admin.save();

    const token = jwt.sign(
      { userId: admin._id, email: admin.email, role: admin.role },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );

    res.status(201).json({
      token,
      user: { id: admin._id, name: admin.name, email: admin.email, role: admin.role }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

console.log('✅ Rotas AUTH configuradas');

// DEVICE ROUTES
const deviceSchema = new mongoose.Schema({
  name: { type: String, required: true },
  deviceToken: { type: String, required: true, unique: true },
  assignedPlaylistId: { type: mongoose.Schema.Types.ObjectId, ref: 'Playlist' },
  status: { type: String, enum: ['online', 'offline'], default: 'offline' },
  lastSeenAt: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

const Device = mongoose.model('Device', deviceSchema);

app.get('/api/devices', authenticateToken, async (req, res) => {
  try {
    const devices = await Device.find().populate('assignedPlaylistId');
    res.json(devices);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/devices', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    const device = new Device({
      name,
      deviceToken: require('crypto').randomBytes(32).toString('hex')
    });
    await device.save();
    res.status(201).json(device);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/devices/:id', authenticateToken, async (req, res) => {
  try {
    const { name, assignedPlaylistId } = req.body;
    const updateData = {};
    if (name) updateData.name = name;
    if (assignedPlaylistId !== undefined) updateData.assignedPlaylistId = assignedPlaylistId || null;

    const device = await Device.findByIdAndUpdate(req.params.id, updateData, { new: true }).populate('assignedPlaylistId');
    if (!device) return res.status(404).json({ error: 'Dispositivo não encontrado' });

    res.json(device);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/devices/:id', authenticateToken, async (req, res) => {
  try {
    const device = await Device.findByIdAndDelete(req.params.id);
    if (!device) return res.status(404).json({ error: 'Dispositivo não encontrado' });
    res.json({ message: 'Dispositivo excluído com sucesso' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/devices/:id/heartbeat', async (req, res) => {
  try {
    const device = await Device.findByIdAndUpdate(req.params.id, { 
      lastSeenAt: new Date(),
      status: 'online'
    }, { new: true });

    if (!device) return res.status(404).json({ error: 'Dispositivo não encontrado' });
    res.json({ message: 'Heartbeat recebido', status: 'online' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

console.log('✅ Rotas DEVICES configuradas');

// MEDIA ROUTES
const mediaSchema = new mongoose.Schema({
  name: { type: String, required: true },
  filename: { type: String, required: true },
  originalName: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  duration: { type: Number },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});

const Media = mongoose.model('Media', mediaSchema);

app.get('/api/media', authenticateToken, async (req, res) => {
  try {
    const media = await Media.find().populate('uploadedBy', 'name email');
    res.json(media);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

console.log('✅ Rotas MEDIA configuradas');

// PLAYLIST ROUTES
const playlistSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  media: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Media' }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});

const Playlist = mongoose.model('Playlist', playlistSchema);

app.get('/api/playlists', authenticateToken, async (req, res) => {
  try {
    const playlists = await Playlist.find().populate('media').populate('createdBy', 'name email');
    res.json(playlists);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

console.log('✅ Rotas PLAYLISTS configuradas');

// PLAYER ROUTE
app.get('/player/:deviceToken', async (req, res) => {
  try {
    const { deviceToken } = req.params;
    const device = await Device.findOne({ deviceToken }).populate('assignedPlaylistId');
    
    if (!device) {
      return res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <title>Dispositivo não encontrado</title>
          <style>
            body { margin: 0; padding: 50px; background: #000; color: #fff; text-align: center; font-family: Arial; }
            h1 { color: #ff6b6b; }
          </style>
        </head>
        <body>
          <h1>❌ Dispositivo não encontrado</h1>
          <p>Token: ${deviceToken}</p>
        </body>
        </html>
      `);
    }

    await Device.findByIdAndUpdate(device._id, { lastSeenAt: new Date(), status: 'online' });

    const baseUrl = process.env.NODE_ENV === 'production' 
      ? 'https://tritotem-cc0a461d6f3e.herokuapp.com' 
      : 'http://localhost:3001';

    const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Tritotem Player - ${device.name}</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #000; overflow: hidden; font-family: Arial; }
        video { width: 100vw; height: 100vh; object-fit: cover; }
        .info { position: fixed; top: 10px; left: 10px; color: white; background: rgba(0,0,0,0.7); padding: 10px; border-radius: 5px; font-size: 14px; z-index: 1000; }
      </style>
    </head>
    <body>
      <div class="info">
        <div><strong>Dispositivo:</strong> ${device.name}</div>
        <div><strong>Status:</strong> <span id="status">Carregando...</span></div>
      </div>
      <video id="player" autoplay muted loop>Seu navegador não suporta vídeo HTML5.</video>
      
      <script>
        const player = document.getElementById('player');
        const status = document.getElementById('status');
        const playlist = ${JSON.stringify(device.assignedPlaylistId?.media || [])};
        let currentIndex = 0;
        
        function playNext() {
          if (playlist.length === 0) {
            status.textContent = 'Nenhuma mídia na playlist';
            return;
          }
          
          const media = playlist[currentIndex];
          player.src = '${baseUrl}/stream/' + media.filename;
          status.textContent = 'Reproduzindo: ' + media.name;
          currentIndex = (currentIndex + 1) % playlist.length;
        }
        
        player.addEventListener('ended', playNext);
        player.addEventListener('canplay', () => status.textContent = 'Reproduzindo');
        player.addEventListener('error', () => {
          status.textContent = 'Erro ao carregar vídeo';
          setTimeout(playNext, 3000);
        });
        
        setTimeout(playNext, 2000);
        
        setInterval(() => {
          fetch('${baseUrl}/api/devices/${device._id}/heartbeat', { method: 'POST' }).catch(console.error);
        }, 30000);
      </script>
    </body>
    </html>`;
    
    res.send(html);
  } catch (error) {
    console.error('Erro no player:', error);
    res.status(500).send('Erro interno do servidor');
  }
});

console.log('✅ Rota PLAYER configurada');

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
  console.log(`🚀 Servidor completo rodando na porta ${PORT}`);
  console.log('✅ Todas as rotas configuradas!');
});
