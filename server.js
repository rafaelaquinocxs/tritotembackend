require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

console.log('🚀 Iniciando servidor Tritotem...');

const app = express();

// CORS
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Uploads
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));

// Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|mp4|webm|ogg|avi|mov/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Tipo de arquivo não permitido'));
  }
});

// MongoDB
(async () => {
  try {
    if (process.env.MONGODB_URI) {
      await mongoose.connect(process.env.MONGODB_URI);
      console.log('✅ MongoDB conectado');
    } else {
      console.log('⚠️ MONGODB_URI não configurado');
    }
  } catch (err) {
    console.error('❌ Erro MongoDB:', err);
  }
})();

// Modelos
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'content_manager'], default: 'content_manager' },
  createdAt: { type: Date, default: Date.now }
});

const mediaSchema = new mongoose.Schema({
  name: { type: String, required: true },
  filename: { type: String, required: true },
  originalName: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  duration: { type: Number },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const playlistSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  media: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Media' }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const deviceSchema = new mongoose.Schema({
  name: { type: String, required: true },
  deviceToken: { type: String, required: true, unique: true },
  assignedPlaylistId: { type: mongoose.Schema.Types.ObjectId, ref: 'Playlist' },
  status: { type: String, enum: ['online', 'offline'], default: 'offline' },
  lastSeenAt: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Media = mongoose.model('Media', mediaSchema);
const Playlist = mongoose.model('Playlist', playlistSchema);
const Device = mongoose.model('Device', deviceSchema);

// Auth middleware
const authenticateToken = (req, res, next) => {
  req.user = { userId: 'test', email: 'test@test.com', role: 'admin' };
  next();
};

// Stream
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

// Healthcheck
app.get('/', (req, res) => {
  res.json({ message: 'API Tritotem funcionando!', timestamp: new Date().toISOString() });
});

// AUTH ROUTES
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, password });
    
    if (!user) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    res.json({
      token: 'fake-token-for-testing',
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
    
    const admin = new User({
      name,
      email,
      password,
      role: 'admin'
    });

    await admin.save();

    res.status(201).json({
      token: 'fake-token-for-testing',
      user: { id: admin._id, name: admin.name, email: admin.email, role: admin.role }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: 'test@test.com' }).select('-password');
    res.json(user || { name: 'Test User', email: 'test@test.com', role: 'admin' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DEVICE ROUTES
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

app.get('/api/devices/:id', authenticateToken, async (req, res) => {
  try {
    const device = await Device.findById(req.params.id).populate('assignedPlaylistId');
    if (!device) return res.status(404).json({ error: 'Dispositivo não encontrado' });
    res.json(device);
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

app.post('/api/devices/broadcast-assign', authenticateToken, async (req, res) => {
  try {
    const { playlistId } = req.body;
    
    await Device.updateMany({}, { assignedPlaylistId: playlistId || null });
    
    const devices = await Device.find().populate('assignedPlaylistId');
    res.json({ message: 'Playlist atribuída a todos os dispositivos', devices });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// MEDIA ROUTES
app.get('/api/media', authenticateToken, async (req, res) => {
  try {
    const media = await Media.find().populate('uploadedBy', 'name email');
    res.json(media);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/media', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Nenhum arquivo enviado' });
    }

    const media = new Media({
      name: req.body.name || req.file.originalname,
      filename: req.file.filename,
      originalName: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      uploadedBy: req.user.userId
    });

    await media.save();
    res.status(201).json(media);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/media/:id', authenticateToken, async (req, res) => {
  try {
    const media = await Media.findById(req.params.id).populate('uploadedBy', 'name email');
    if (!media) return res.status(404).json({ error: 'Mídia não encontrada' });
    res.json(media);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/media/:id', authenticateToken, async (req, res) => {
  try {
    const media = await Media.findById(req.params.id);
    if (!media) return res.status(404).json({ error: 'Mídia não encontrada' });

    const filePath = path.join(uploadsDir, media.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    await Media.findByIdAndDelete(req.params.id);
    res.json({ message: 'Mídia excluída com sucesso' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PLAYLIST ROUTES
app.get('/api/playlists', authenticateToken, async (req, res) => {
  try {
    const playlists = await Playlist.find().populate('media').populate('createdBy', 'name email');
    res.json(playlists);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/playlists', authenticateToken, async (req, res) => {
  try {
    const { name, description, media } = req.body;
    
    const playlist = new Playlist({
      name,
      description,
      media: media || [],
      createdBy: req.user.userId
    });

    await playlist.save();
    await playlist.populate('media');
    res.status(201).json(playlist);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/playlists/:id', authenticateToken, async (req, res) => {
  try {
    const playlist = await Playlist.findById(req.params.id).populate('media').populate('createdBy', 'name email');
    if (!playlist) return res.status(404).json({ error: 'Playlist não encontrada' });
    res.json(playlist);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/playlists/:id', authenticateToken, async (req, res) => {
  try {
    const { name, description, media } = req.body;
    
    const playlist = await Playlist.findByIdAndUpdate(
      req.params.id,
      { name, description, media },
      { new: true }
    ).populate('media');

    if (!playlist) return res.status(404).json({ error: 'Playlist não encontrada' });
    res.json(playlist);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/playlists/:id', authenticateToken, async (req, res) => {
  try {
    const playlist = await Playlist.findByIdAndDelete(req.params.id);
    if (!playlist) return res.status(404).json({ error: 'Playlist não encontrada' });
    res.json({ message: 'Playlist excluída com sucesso' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PLAYER ROUTE
app.get('/player/:deviceToken', async (req, res) => {
  try {
    const { deviceToken } = req.params;
    const device = await Device.findOne({ deviceToken }).populate({
      path: 'assignedPlaylistId',
      populate: { path: 'media' }
    });
    
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

    await Device.findByIdAndUpdate(device._id, { 
      lastSeenAt: new Date(), 
      status: 'online' 
    });

    const baseUrl = process.env.NODE_ENV === 'production' 
      ? 'https://tritotem-cc0a461d6f3e.herokuapp.com' 
      : 'http://localhost:3001';

    const playlist = device.assignedPlaylistId?.media || [];

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
        .info { 
          position: fixed; top: 10px; left: 10px; color: white; 
          background: rgba(0,0,0,0.7); padding: 10px; border-radius: 5px; 
          font-size: 14px; z-index: 1000; 
        }
        .no-content {
          display: flex; align-items: center; justify-content: center;
          width: 100vw; height: 100vh; color: white; text-align: center;
          background: linear-gradient(45deg, #1a1a1a, #333);
        }
      </style>
    </head>
    <body>
      <div class="info">
        <div><strong>Dispositivo:</strong> ${device.name}</div>
        <div><strong>Status:</strong> <span id="status">Carregando...</span></div>
        <div><strong>Playlist:</strong> ${device.assignedPlaylistId?.name || 'Nenhuma'}</div>
      </div>
      
      ${playlist.length === 0 ? `
        <div class="no-content">
          <div>
            <h1>📺 Tritotem Player</h1>
            <h2>${device.name}</h2>
            <p>Nenhuma playlist atribuída</p>
          </div>
        </div>
      ` : `
        <video id="player" autoplay muted loop>
          Seu navegador não suporta vídeo HTML5.
        </video>
      `}
      
      <script>
        const player = document.getElementById('player');
        const status = document.getElementById('status');
        const playlist = ${JSON.stringify(playlist)};
        let currentIndex = 0;
        
        function playNext() {
          if (playlist.length === 0) {
            status.textContent = 'Nenhuma mídia na playlist';
            return;
          }
          
          const media = playlist[currentIndex];
          if (player) {
            player.src = '${baseUrl}/stream/' + media.filename;
            status.textContent = 'Reproduzindo: ' + media.name;
            currentIndex = (currentIndex + 1) % playlist.length;
          }
        }
        
        if (player) {
          player.addEventListener('ended', playNext);
          player.addEventListener('canplay', () => status.textContent = 'Reproduzindo');
          player.addEventListener('error', (e) => {
            console.error('Erro no player:', e);
            status.textContent = 'Erro ao carregar vídeo';
            setTimeout(playNext, 3000);
          });
          
          setTimeout(playNext, 2000);
        } else {
          status.textContent = 'Aguardando playlist';
        }
        
        setInterval(() => {
          fetch('${baseUrl}/api/devices/${device._id}/heartbeat', { 
            method: 'POST' 
          }).catch(console.error);
        }, 30000);
        
        setTimeout(() => location.reload(), 5 * 60 * 1000);
      </script>
    </body>
    </html>`;
    
    res.send(html);
  } catch (error) {
    console.error('Erro no player:', error);
    res.status(500).send('Erro interno do servidor');
  }
});

// Start server
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
  console.log('✅ Sistema Tritotem pronto!');
});