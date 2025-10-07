require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

console.log('🚀 Iniciando servidor Tritotem v2.0...');

const app = express();

// Configuração CORS otimizada para produção
const allowedOrigins = [
  'https://tritotem-frontend.vercel.app',
  'https://tritotem-cc0a461d6f3e.herokuapp.com',
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:5174',
  // Adicionar domínios das TVs se necessário
  /^https:\/\/.*\.vercel\.app$/,
  /^https:\/\/.*\.herokuapp\.com$/
];

app.use(cors({
  origin: function (origin, callback) {
    // Permitir requests sem origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    // Verificar se a origem está na lista permitida
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (typeof allowedOrigin === 'string') {
        return allowedOrigin === origin;
      }
      return allowedOrigin.test(origin);
    });
    
    if (isAllowed) {
      callback(null, true);
    } else {
      console.warn(`❌ CORS bloqueou origem: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true,
}));

// Middleware básico
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Headers de segurança
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Configuração de uploads
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('📁 Diretório de uploads criado');
}

// Servir arquivos estáticos
app.use('/uploads', express.static(uploadsDir, {
  maxAge: '1d',
  etag: true,
  lastModified: true
}));

// Configuração Multer otimizada
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueId = uuidv4();
    const ext = path.extname(file.originalname);
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, `${uniqueId}-${safeName}`);
  }
});

const upload = multer({ 
  storage,
  limits: { 
    fileSize: 500 * 1024 * 1024, // 500MB
    files: 1
  },
  fileFilter: (req, file, cb) => {
    const allowedMimes = [
      'video/mp4', 'video/webm', 'video/ogg', 'video/avi', 'video/mov',
      'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'
    ];
    
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Tipo de arquivo não permitido: ${file.mimetype}`));
    }
  }
});

// Conexão MongoDB com retry
const connectDB = async () => {
  const maxRetries = 5;
  let retries = 0;
  
  while (retries < maxRetries) {
    try {
      if (!process.env.MONGODB_URI) {
        throw new Error('MONGODB_URI não configurado');
      }
      
      await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
      });
      
      console.log('✅ MongoDB conectado com sucesso');
      return;
    } catch (err) {
      retries++;
      console.error(`❌ Tentativa ${retries}/${maxRetries} - Erro MongoDB:`, err.message);
      
      if (retries === maxRetries) {
        console.error('💀 Falha ao conectar MongoDB após todas as tentativas');
        // Não encerrar o processo, permitir que funcione sem DB para testes
      } else {
        await new Promise(resolve => setTimeout(resolve, 2000 * retries));
      }
    }
  }
};

// Inicializar conexão DB
connectDB();

// Schemas otimizados
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'content_manager'], default: 'content_manager' },
  isActive: { type: Boolean, default: true },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
}, {
  timestamps: true
});

const mediaSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  filename: { type: String, required: true },
  originalName: { type: String, required: true },
  mimetype: { type: String, required: true },
  size: { type: Number, required: true },
  duration: { type: Number, default: 0 },
  resolution: { type: String },
  tags: [{ type: String, trim: true }],
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
}, {
  timestamps: true
});

const playlistSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  description: { type: String, trim: true },
  media: [{
    mediaId: { type: mongoose.Schema.Types.ObjectId, ref: 'Media', required: true },
    order: { type: Number, default: 0 },
    duration: { type: Number } // Duração específica para esta mídia na playlist
  }],
  totalDuration: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
}, {
  timestamps: true
});

const deviceSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  deviceToken: { type: String, required: true, unique: true },
  location: { type: String, trim: true },
  resolution: { type: String, default: '1920x1080' },
  assignedPlaylistId: { type: mongoose.Schema.Types.ObjectId, ref: 'Playlist' },
  status: { type: String, enum: ['online', 'offline', 'maintenance'], default: 'offline' },
  lastSeenAt: { type: Date, default: Date.now },
  heartbeatInterval: { type: Number, default: 30000 }, // 30 segundos
  isActive: { type: Boolean, default: true },
  metadata: {
    userAgent: String,
    ipAddress: String,
    screenSize: String
  },
  createdAt: { type: Date, default: Date.now }
}, {
  timestamps: true
});

// Índices para performance
userSchema.index({ email: 1 });
mediaSchema.index({ createdAt: -1 });
mediaSchema.index({ uploadedBy: 1 });
playlistSchema.index({ createdAt: -1 });
playlistSchema.index({ createdBy: 1 });
deviceSchema.index({ deviceToken: 1 });
deviceSchema.index({ status: 1 });
deviceSchema.index({ lastSeenAt: -1 });

// Modelos
const User = mongoose.model('User', userSchema);
const Media = mongoose.model('Media', mediaSchema);
const Playlist = mongoose.model('Playlist', playlistSchema);
const Device = mongoose.model('Device', deviceSchema);

// Middleware de autenticação simplificado para desenvolvimento
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  // Para desenvolvimento, aceitar qualquer token ou sem token
  if (process.env.NODE_ENV !== 'production' || !token) {
    req.user = { 
      userId: 'dev-user', 
      email: 'dev@tritotem.com', 
      role: 'admin' 
    };
    return next();
  }
  
  // Em produção, implementar validação JWT real
  try {
    const jwt = require('jsonwebtoken');
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'tritotem-secret');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Token inválido' });
  }
};

// Middleware para logging de requests
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`${timestamp} - ${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Health check melhorado
app.get('/', (req, res) => {
  res.json({ 
    message: 'API Tritotem v2.0 funcionando!', 
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    status: 'healthy',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Página de demonstração das TVs
app.get('/demo', (req, res) => {
  const demoPath = path.join(__dirname, 'tv-demo.html');
  res.sendFile(demoPath);
});

app.get('/health', async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {
      database: 'unknown',
      uploads: 'unknown'
    }
  };
  
  try {
    // Verificar conexão DB
    if (mongoose.connection.readyState === 1) {
      health.services.database = 'connected';
    } else {
      health.services.database = 'disconnected';
      health.status = 'degraded';
    }
    
    // Verificar diretório de uploads
    if (fs.existsSync(uploadsDir)) {
      health.services.uploads = 'available';
    } else {
      health.services.uploads = 'unavailable';
      health.status = 'degraded';
    }
    
    res.json(health);
  } catch (error) {
    health.status = 'unhealthy';
    health.error = error.message;
    res.status(500).json(health);
  }
});

// Streaming otimizado com suporte a range requests
app.get('/stream/:filename', (req, res) => {
  try {
    const filename = req.params.filename;
    const filePath = path.join(uploadsDir, filename);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Arquivo não encontrado' });
    }

    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const range = req.headers.range;
    
    // Determinar MIME type
    const ext = path.extname(filename).toLowerCase();
    const mimeTypes = {
      '.mp4': 'video/mp4',
      '.webm': 'video/webm',
      '.ogg': 'video/ogg',
      '.avi': 'video/avi',
      '.mov': 'video/quicktime',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.webp': 'image/webp'
    };
    const mimeType = mimeTypes[ext] || 'application/octet-stream';

    if (range) {
      // Suporte a range requests para streaming
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      
      if (start >= fileSize || end >= fileSize) {
        res.status(416).set({
          'Content-Range': `bytes */${fileSize}`
        });
        return res.end();
      }

      const chunksize = (end - start) + 1;
      const file = fs.createReadStream(filePath, { start, end });
      
      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Type': mimeType,
        'Cache-Control': 'public, max-age=86400'
      });
      
      file.pipe(res);
    } else {
      // Streaming completo
      res.writeHead(200, {
        'Content-Length': fileSize,
        'Content-Type': mimeType,
        'Accept-Ranges': 'bytes',
        'Cache-Control': 'public, max-age=86400'
      });
      
      fs.createReadStream(filePath).pipe(res);
    }
  } catch (err) {
    console.error('Erro no streaming:', err);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ROTAS DE AUTENTICAÇÃO
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }
    
    // Em desenvolvimento, aceitar qualquer credencial
    if (process.env.NODE_ENV !== 'production') {
      return res.json({
        token: 'dev-token-' + Date.now(),
        user: { 
          id: 'dev-user', 
          name: 'Desenvolvedor', 
          email: email, 
          role: 'admin' 
        }
      });
    }
    
    const user = await User.findOne({ email: email.toLowerCase(), isActive: true });
    
    if (!user) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }
    
    // Verificar senha (implementar bcrypt em produção)
    const bcrypt = require('bcryptjs');
    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }
    
    // Atualizar último login
    user.lastLogin = new Date();
    await user.save();
    
    // Gerar JWT
    const jwt = require('jsonwebtoken');
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'tritotem-secret',
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: { 
        id: user._id, 
        name: user.name, 
        email: user.email, 
        role: user.role 
      }
    });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/auth/init', async (req, res) => {
  try {
    const adminExists = await User.findOne({ role: 'admin', isActive: true });
    if (adminExists) {
      return res.status(400).json({ error: 'Administrador já existe' });
    }

    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
    }
    
    const bcrypt = require('bcryptjs');
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const admin = new User({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      role: 'admin'
    });

    await admin.save();

    const jwt = require('jsonwebtoken');
    const token = jwt.sign(
      { userId: admin._id, email: admin.email, role: admin.role },
      process.env.JWT_SECRET || 'tritotem-secret',
      { expiresIn: '24h' }
    );

    res.status(201).json({
      token,
      user: { 
        id: admin._id, 
        name: admin.name, 
        email: admin.email, 
        role: admin.role 
      }
    });
  } catch (error) {
    console.error('Erro na inicialização:', error);
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Email já está em uso' });
    }
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    if (process.env.NODE_ENV !== 'production') {
      return res.json({ 
        id: 'dev-user',
        name: 'Desenvolvedor',
        email: 'dev@tritotem.com',
        role: 'admin'
      });
    }
    
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    res.json(user);
  } catch (error) {
    console.error('Erro ao buscar usuário:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ROTAS DE USUÁRIOS (CRUD)
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ isActive: true }).select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/users', authenticateToken, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Nome, email e senha são obrigatórios' });
    }
    
    const bcrypt = require('bcryptjs');
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = new User({ 
      name, 
      email, 
      password: hashedPassword, 
      role 
    });
    
    await newUser.save();
    res.status(201).json(newUser);
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Email já está em uso' });
    }
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    const { name, email, role, password } = req.body;
    const updateData = { name, email, role };

    if (password) {
      const bcrypt = require('bcryptjs');
      updateData.password = await bcrypt.hash(password, 10);
    }

    const updatedUser = await User.findByIdAndUpdate(req.params.id, updateData, { new: true });
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.params.id, { isActive: false });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ROTAS DE MÍDIA (CRUD)
app.get('/api/media', authenticateToken, async (req, res) => {
  try {
    const media = await Media.find({ isActive: true }).sort({ createdAt: -1 });
    res.json(media);
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/media', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Nenhum arquivo enviado' });
    }

    const { name, duration, resolution, tags } = req.body;
    
    const newMedia = new Media({
      name: name || req.file.originalname,
      filename: req.file.filename,
      originalName: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      duration: duration || 0,
      resolution: resolution || null,
      tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
      uploadedBy: req.user.userId
    });

    await newMedia.save();
    res.status(201).json(newMedia);
  } catch (error) {
    console.error('Erro no upload:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.put('/api/media/:id', authenticateToken, async (req, res) => {
  try {
    const { name, tags } = req.body;
    const updateData = { name, tags: tags ? tags.split(',').map(tag => tag.trim()) : [] };
    const updatedMedia = await Media.findByIdAndUpdate(req.params.id, updateData, { new: true });
    res.json(updatedMedia);
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.delete('/api/media/:id', authenticateToken, async (req, res) => {
  try {
    const media = await Media.findById(req.params.id);
    if (!media) {
      return res.status(404).json({ error: 'Mídia não encontrada' });
    }

    // Soft delete
    media.isActive = false;
    await media.save();

    // Opcional: remover arquivo físico após um tempo
    // fs.unlink(path.join(uploadsDir, media.filename), (err) => {
    //   if (err) console.error('Erro ao remover arquivo físico:', err);
    // });

    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ROTAS DE PLAYLISTS (CRUD)
app.get('/api/playlists', authenticateToken, async (req, res) => {
  try {
    const playlists = await Playlist.find({ isActive: true })
      .populate('media.mediaId')
      .sort({ createdAt: -1 });
    res.json(playlists);
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/playlists', authenticateToken, async (req, res) => {
  try {
    const { name, description, media } = req.body;
    const newPlaylist = new Playlist({ 
      name, 
      description, 
      media, 
      createdBy: req.user.userId 
    });
    await newPlaylist.save();
    res.status(201).json(newPlaylist);
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.put('/api/playlists/:id', authenticateToken, async (req, res) => {
  try {
    const { name, description, media } = req.body;
    const updatedPlaylist = await Playlist.findByIdAndUpdate(
      req.params.id,
      { name, description, media },
      { new: true }
    );
    res.json(updatedPlaylist);
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.delete('/api/playlists/:id', authenticateToken, async (req, res) => {
  try {
    await Playlist.findByIdAndUpdate(req.params.id, { isActive: false });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ROTAS DE DISPOSITIVOS (CRUD)
app.get('/api/devices', authenticateToken, async (req, res) => {
  try {
    const devices = await Device.find({ isActive: true })
      .populate('assignedPlaylistId', 'name')
      .sort({ lastSeenAt: -1 });
    res.json(devices);
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.post('/api/devices', authenticateToken, async (req, res) => {
  try {
    const { name, location, resolution } = req.body;
    const newDevice = new Device({ 
      name, 
      location, 
      resolution,
      deviceToken: uuidv4()
    });
    await newDevice.save();
    res.status(201).json(newDevice);
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.put('/api/devices/:id', authenticateToken, async (req, res) => {
  try {
    const { name, location, resolution, assignedPlaylistId } = req.body;
    const updatedDevice = await Device.findByIdAndUpdate(
      req.params.id,
      { name, location, resolution, assignedPlaylistId: assignedPlaylistId || null },
      { new: true }
    );
    res.json(updatedDevice);
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

app.delete('/api/devices/:id', authenticateToken, async (req, res) => {
  try {
    await Device.findByIdAndUpdate(req.params.id, { isActive: false });
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota para atribuir playlist a múltiplos dispositivos
app.post('/api/devices/assign-playlist', authenticateToken, async (req, res) => {
  try {
    const { deviceIds, playlistId } = req.body;
    await Device.updateMany(
      { _id: { $in: deviceIds } },
      { $set: { assignedPlaylistId: playlistId } }
    );
    res.json({ message: 'Playlist atribuída com sucesso' });
  } catch (error) {
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota de heartbeat para dispositivos
app.post('/api/devices/token/:deviceToken/heartbeat', async (req, res) => {
  try {
    const { deviceToken } = req.params;
    const { userAgent, screenSize } = req.body;
    
    const update = await Device.findOneAndUpdate(
      { deviceToken },
      { 
        lastSeenAt: new Date(), 
        status: 'online',
        'metadata.userAgent': userAgent,
        'metadata.screenSize': screenSize,
        'metadata.ipAddress': req.ip
      },
      { new: true }
    );

    if (!update) {
      return res.status(404).json({ message: 'Dispositivo não encontrado' });
    }

    res.json({ message: 'Heartbeat recebido' });
  } catch (error) {
    console.error('Erro no heartbeat:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ROTA DO PLAYER (substituída pela versão otimizada abaixo)

app.get('/player/:deviceToken', async (req, res) => {
  try {
    const { deviceToken } = req.params;
    
    const device = await Device.findOne({ 
      deviceToken, 
      isActive: true 
    }).populate({
      path: 'assignedPlaylistId',
      populate: {
        path: 'media.mediaId',
        match: { isActive: true }
      }
    });
    
    if (!device) {
      return res.status(404).send(`
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Dispositivo não encontrado - Tritotem</title>
          <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
              color: white; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
              display: flex; align-items: center; justify-content: center;
              min-height: 100vh; text-align: center;
            }
            .container { max-width: 500px; padding: 2rem; }
            h1 { font-size: 3rem; margin-bottom: 1rem; }
            p { font-size: 1.2rem; opacity: 0.9; margin-bottom: 0.5rem; }
            .token { font-family: monospace; background: rgba(255,255,255,0.1); 
                    padding: 0.5rem; border-radius: 4px; margin-top: 1rem; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>❌ Dispositivo não encontrado</h1>
            <p>O token fornecido não corresponde a nenhum dispositivo ativo.</p>
            <p>Entre em contato com o administrador do sistema.</p>
            <div class="token">Token: ${deviceToken}</div>
          </div>
        </body>
        </html>
      `);
    }

    // Atualizar status do dispositivo
    await Device.findByIdAndUpdate(device._id, { 
      lastSeenAt: new Date(), 
      status: 'online',
      'metadata.userAgent': req.get('User-Agent'),
      'metadata.ipAddress': req.ip
    });

    const baseUrl = process.env.NODE_ENV === 'production' 
      ? (process.env.BASE_URL || 'https://tritotem-cc0a461d6f3e.herokuapp.com')
      : 'http://localhost:3001';

    const playlist = device.assignedPlaylistId?.media?.filter(item => item.mediaId) || [];
    const playlistName = device.assignedPlaylistId?.name || 'Nenhuma';

    const html = `
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Tritotem Player - ${device.name}</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
          background: #000; overflow: hidden; 
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        video { 
          width: 100vw; height: 100vh; 
          object-fit: cover; display: block;
        }
        
        .no-content {
          display: flex; align-items: center; justify-content: center;
          width: 100vw; height: 100vh; color: white; text-align: center;
          background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 50%, #1a1a1a 100%);
        }
        
        .no-content h1 { font-size: 4rem; margin-bottom: 1rem; }
        .no-content h2 { font-size: 2rem; margin-bottom: 0.5rem; color: #4CAF50; }
        .no-content p { font-size: 1.2rem; opacity: 0.8; }
        
        .loading {
          position: fixed; top: 50%; left: 50%;
          transform: translate(-50%, -50%);
          color: white; text-align: center; z-index: 999;
        }
        
        .spinner {
          border: 4px solid rgba(255,255,255,0.3);
          border-top: 4px solid #4CAF50;
          border-radius: 50%; width: 50px; height: 50px;
          animation: spin 1s linear infinite;
          margin: 0 auto 20px;
        }
        
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        
        .hidden { display: none !important; }
      </style>
    </head>
    <body>
      <div id="loading" class="loading">
        <div class="spinner"></div>
        <p>Carregando conteúdo...</p>
      </div>
      
      ${playlist.length === 0 ? `
        <div class="no-content">
          <div>
            <h1>📺</h1>
            <h2>Tritotem Player</h2>
            <p><strong>${device.name}</strong></p>
            <p>Aguardando conteúdo...</p>
            <p style="margin-top: 2rem; font-size: 1rem; opacity: 0.6;">
              Nenhuma playlist atribuída a este dispositivo
            </p>
          </div>
        </div>
      ` : `
        <video id="player" autoplay muted preload="auto">
          Seu navegador não suporta reprodução de vídeo HTML5.
        </video>
      `}
      
      <script>
        // ==================== CONFIGURAÇÃO ====================
        const DB_NAME = 'TritotemCache';
        const DB_VERSION = 1;
        const STORE_NAME = 'videos';
        const CACHE_EXPIRY_DAYS = 7;
        
        // ==================== VARIÁVEIS GLOBAIS ====================
        let db = null;
        const player = document.getElementById('player');
        const loading = document.getElementById('loading');
        const playlist = ${JSON.stringify(playlist)};
        
        let currentIndex = 0;
        let nextVideoBlob = null;
        let isPreloading = false;
        let heartbeatInterval;
        let reloadTimeout;
        
        // Configurações
        const config = {
          baseUrl: '${baseUrl}',
          deviceId: '${device._id}',
          deviceToken: '${deviceToken}',
          heartbeatInterval: ${device.heartbeatInterval || 30000},
          reloadInterval: 10 * 60 * 1000, // 10 minutos
          retryDelay: 5000
        };
        
        // ==================== INDEXEDDB ====================
        async function initDB() {
          return new Promise((resolve, reject) => {
            const request = indexedDB.open(DB_NAME, DB_VERSION);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
              db = request.result;
              console.log('[Cache] IndexedDB inicializado');
              resolve(db);
            };
            
            request.onupgradeneeded = (event) => {
              const db = event.target.result;
              if (!db.objectStoreNames.contains(STORE_NAME)) {
                const store = db.createObjectStore(STORE_NAME, { keyPath: 'filename' });
                store.createIndex('timestamp', 'timestamp', { unique: false });
                console.log('[Cache] Object store criado');
              }
            };
          });
        }
        
        async function getCachedVideo(filename) {
          if (!db) return null;
          
          return new Promise((resolve, reject) => {
            const transaction = db.transaction([STORE_NAME], 'readonly');
            const store = transaction.objectStore(STORE_NAME);
            const request = store.get(filename);
            
            request.onsuccess = () => {
              const result = request.result;
              if (!result) {
                resolve(null);
                return;
              }
              
              // Verificar expiração
              const age = Date.now() - result.timestamp;
              const maxAge = CACHE_EXPIRY_DAYS * 24 * 60 * 60 * 1000;
              
              if (age > maxAge) {
                console.log('[Cache] Vídeo expirado:', filename);
                deleteCachedVideo(filename);
                resolve(null);
              } else {
                console.log('[Cache] Vídeo encontrado no cache:', filename);
                resolve(result.blob);
              }
            };
            
            request.onerror = () => reject(request.error);
          });
        }
        
        async function cacheVideo(filename, blob) {
          if (!db) return false;
          
          return new Promise((resolve, reject) => {
            const transaction = db.transaction([STORE_NAME], 'readwrite');
            const store = transaction.objectStore(STORE_NAME);
            
            const data = {
              filename: filename,
              blob: blob,
              timestamp: Date.now()
            };
            
            const request = store.put(data);
            
            request.onsuccess = () => {
              console.log('[Cache] Vídeo armazenado:', filename);
              resolve(true);
            };
            
            request.onerror = () => {
              console.error('[Cache] Erro ao armazenar:', request.error);
              reject(request.error);
            };
          });
        }
        
        async function deleteCachedVideo(filename) {
          if (!db) return false;
          
          return new Promise((resolve, reject) => {
            const transaction = db.transaction([STORE_NAME], 'readwrite');
            const store = transaction.objectStore(STORE_NAME);
            const request = store.delete(filename);
            
            request.onsuccess = () => {
              console.log('[Cache] Vídeo removido do cache:', filename);
              resolve(true);
            };
            
            request.onerror = () => reject(request.error);
          });
        }
        
        async function clearOldCache() {
          if (!db) return;
          
          const transaction = db.transaction([STORE_NAME], 'readwrite');
          const store = transaction.objectStore(STORE_NAME);
          const index = store.index('timestamp');
          const maxAge = CACHE_EXPIRY_DAYS * 24 * 60 * 60 * 1000;
          const cutoff = Date.now() - maxAge;
          
          const request = index.openCursor();
          
          request.onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
              if (cursor.value.timestamp < cutoff) {
                cursor.delete();
                console.log('[Cache] Removido vídeo antigo:', cursor.value.filename);
              }
              cursor.continue();
            }
          };
        }
        
        // ==================== DOWNLOAD E CACHE ====================
        async function downloadAndCacheVideo(filename, url) {
          try {
            console.log('[Download] Baixando:', filename);
            const response = await fetch(url);
            
            if (!response.ok) {
              throw new Error('Erro ao baixar vídeo: ' + response.status);
            }
            
            const blob = await response.blob();
            console.log('[Download] Concluído:', filename, '(' + (blob.size / 1024 / 1024).toFixed(2) + ' MB)');
            
            // Armazenar no cache
            await cacheVideo(filename, blob);
            
            return blob;
          } catch (error) {
            console.error('[Download] Erro:', error);
            return null;
          }
        }
        
        async function getVideoBlob(filename, url) {
          // Tentar obter do cache primeiro
          let blob = await getCachedVideo(filename);
          
          if (blob) {
            console.log('[Video] Usando cache para:', filename);
            return blob;
          }
          
          // Se não estiver no cache, baixar
          console.log('[Video] Não encontrado no cache, baixando:', filename);
          blob = await downloadAndCacheVideo(filename, url);
          
          return blob;
        }
        
        // ==================== PRÉ-CARREGAMENTO ====================
        async function preloadNextVideo() {
          if (isPreloading || playlist.length === 0) return;
          
          isPreloading = true;
          const nextIndex = (currentIndex + 1) % playlist.length;
          const nextMedia = playlist[nextIndex];
          
          if (!nextMedia || !nextMedia.mediaId) {
            isPreloading = false;
            return;
          }
          
          console.log('[Preload] Pré-carregando próximo vídeo:', nextMedia.mediaId.name);
          
          const videoUrl = config.baseUrl + '/stream/' + nextMedia.mediaId.filename;
          nextVideoBlob = await getVideoBlob(nextMedia.mediaId.filename, videoUrl);
          
          isPreloading = false;
          console.log('[Preload] Próximo vídeo pronto');
        }
        
        // ==================== PLAYER ====================
        function hideLoading() {
          if (loading) loading.classList.add('hidden');
        }
        
        function showLoading() {
          if (loading) loading.classList.remove('hidden');
        }
        
        async function playNext() {
          if (playlist.length === 0) {
            hideLoading();
            return;
          }
          
          const media = playlist[currentIndex];
          if (!media || !media.mediaId) {
            currentIndex = (currentIndex + 1) % playlist.length;
            setTimeout(playNext, 1000);
            return;
          }
          
          if (player) {
            showLoading();
            
            console.log('[Player] Reproduzindo:', media.mediaId.name);
            
            // Usar blob pré-carregado se disponível
            let blob = nextVideoBlob;
            nextVideoBlob = null;
            
            // Se não houver blob pré-carregado, obter agora
            if (!blob) {
              const videoUrl = config.baseUrl + '/stream/' + media.mediaId.filename;
              blob = await getVideoBlob(media.mediaId.filename, videoUrl);
            }
            
            if (blob) {
              const blobUrl = URL.createObjectURL(blob);
              player.src = blobUrl;
              
              // Liberar URL anterior
              player.addEventListener('loadeddata', () => {
                URL.revokeObjectURL(blobUrl);
              }, { once: true });
            } else {
              console.error('[Player] Erro ao obter vídeo');
              currentIndex = (currentIndex + 1) % playlist.length;
              setTimeout(playNext, 3000);
              return;
            }
            
            // Avançar índice
            currentIndex = (currentIndex + 1) % playlist.length;
            
            // Pré-carregar próximo vídeo
            setTimeout(preloadNextVideo, 2000);
          }
        }
        
        function sendHeartbeat() {
          const heartbeatData = {
            userAgent: navigator.userAgent,
            screenSize: screen.width + 'x' + screen.height,
            timestamp: new Date().toISOString()
          };
          
          fetch(config.baseUrl + '/api/devices/token/' + config.deviceToken + '/heartbeat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(heartbeatData)
          })
          .then(response => response.json())
          .then(data => {
            console.log('[Heartbeat]', data.message);
          })
          .catch(error => {
            console.error('[Heartbeat] Erro:', error);
          });
        }
        
        function setupPlayer() {
          if (!player || playlist.length === 0) {
            hideLoading();
            return;
          }
          
          player.addEventListener('canplay', () => {
            hideLoading();
            console.log('[Player] Vídeo pronto para reprodução');
          });
          
          player.addEventListener('playing', () => {
            hideLoading();
            console.log('[Player] Reproduzindo');
          });
          
          player.addEventListener('ended', () => {
            console.log('[Player] Vídeo finalizado, próximo...');
            setTimeout(playNext, 500);
          });
          
          player.addEventListener('error', (e) => {
            console.error('[Player] Erro:', e);
            hideLoading();
            setTimeout(playNext, config.retryDelay);
          });
          
          player.addEventListener('waiting', () => {
            console.log('[Player] Buffering...');
          });
          
          // Iniciar reprodução
          setTimeout(playNext, 2000);
        }
        
        async function init() {
          console.log('[Tritotem] Player inicializado');
          try {
            await initDB();
            clearOldCache();
            setupPlayer();
            
            // Iniciar heartbeat
            sendHeartbeat();
            heartbeatInterval = setInterval(sendHeartbeat, config.heartbeatInterval);
            
            // Recarregar a página periodicamente para buscar atualizações
            reloadTimeout = setTimeout(() => window.location.reload(), config.reloadInterval);
            
          } catch (error) {
            console.error('[Tritotem] Erro na inicialização:', error);
          }
        }
        
        // Iniciar tudo
        window.onload = init;
        
      </script>
    </body>
    </html>
    `;

    res.send(html);
  } catch (error) {
    console.error('Erro na rota do player:', error);
    res.status(500).send('Erro interno do servidor');
  }
});

// Rota de API para o player (deprecada, usar rota HTML acima)
app.get('/api/player/:deviceToken', async (req, res) => {
  try {
    const { deviceToken } = req.params;
    
    const device = await Device.findOne({ 
      deviceToken, 
      isActive: true 
    }).populate({
      path: 'assignedPlaylistId',
      populate: {
        path: 'media.mediaId',
        match: { isActive: true }
      }
    });
    
    if (!device) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }

    // Atualizar último acesso
    await Device.findByIdAndUpdate(device._id, { 
      lastSeenAt: new Date(), 
      status: 'online' 
    });

    const baseUrl = process.env.NODE_ENV === 'production' 
      ? (process.env.BASE_URL || 'https://tritotem-cc0a461d6f3e.herokuapp.com')
      : 'http://localhost:3001';

    const playlist = device.assignedPlaylistId?.media?.filter(item => item.mediaId) || [];
    
    // Preparar URLs das mídias
    const mediaWithUrls = playlist.map(item => ({
      id: item.mediaId._id,
      name: item.mediaId.name,
      filename: item.mediaId.filename,
      url: `${baseUrl}/stream/${item.mediaId.filename}`,
      mimetype: item.mediaId.mimetype,
      size: item.mediaId.size,
      duration: item.duration || item.mediaId.duration || 0,
      order: item.order || 0
    }));

    res.json({
      device: {
        id: device._id,
        name: device.name,
        location: device.location,
        resolution: device.resolution,
        status: device.status,
        lastSeenAt: device.lastSeenAt
      },
      playlist: {
        id: device.assignedPlaylistId?._id,
        name: device.assignedPlaylistId?.name || null,
        description: device.assignedPlaylistId?.description,
        totalDuration: device.assignedPlaylistId?.totalDuration || 0,
        media: mediaWithUrls
      },
      config: {
        heartbeatInterval: device.heartbeatInterval || 30000,
        baseUrl
      }
    });
  } catch (error) {
    console.error('Erro na API do player:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Rota para estatísticas do dashboard
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const [
      totalDevices,
      onlineDevices,
      totalPlaylists,
      totalMedia,
      totalStorage
    ] = await Promise.all([
      Device.countDocuments({ isActive: true }),
      Device.countDocuments({ isActive: true, status: 'online' }),
      Playlist.countDocuments({ isActive: true }),
      Media.countDocuments({ isActive: true }),
      Media.aggregate([
        { $match: { isActive: true } },
        { $group: { _id: null, total: { $sum: '$size' } } }
      ])
    ]);

    const storageUsed = totalStorage[0]?.total || 0;

    res.json({
      devices: {
        total: totalDevices,
        online: onlineDevices,
        offline: totalDevices - onlineDevices
      },
      playlists: {
        total: totalPlaylists
      },
      media: {
        total: totalMedia,
        storage: {
          used: storageUsed,
          usedFormatted: formatBytes(storageUsed)
        }
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Erro nas estatísticas:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Função auxiliar para formatar bytes
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Middleware para capturar erros não tratados
app.use((err, req, res, next) => {
  console.error('Erro não tratado:', err);
  
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'Arquivo muito grande' });
  }
  
  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    return res.status(400).json({ error: 'Campo de arquivo inesperado' });
  }
  
  res.status(500).json({ error: 'Erro interno do servidor' });
});

// Middleware para rotas não encontradas
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Rota não encontrada',
    path: req.originalUrl,
    method: req.method
  });
});

// Inicializar servidor
const PORT = process.env.PORT || 3001;
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor Tritotem v2.0 rodando na porta ${PORT}`);
  console.log(`🌐 Ambiente: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📁 Uploads: ${uploadsDir}`);
  console.log('✅ Sistema pronto para receber conexões!');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Recebido SIGTERM, encerrando servidor...');
  server.close(() => {
    console.log('✅ Servidor encerrado graciosamente');
    mongoose.connection.close(false, () => {
      console.log('✅ Conexão MongoDB encerrada');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('🛑 Recebido SIGINT, encerrando servidor...');
  server.close(() => {
    console.log('✅ Servidor encerrado graciosamente');
    mongoose.connection.close(false, () => {
      console.log('✅ Conexão MongoDB encerrada');
      process.exit(0);
    });
  });
});

module.exports = app;
