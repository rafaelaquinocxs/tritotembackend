// Script para inicializar dados de teste no sistema Tritotem
require('dotenv').config();
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

// Conectar ao MongoDB
const connectDB = async () => {
  try {
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/tritotem';
    await mongoose.connect(mongoUri);
    console.log('✅ Conectado ao MongoDB');
  } catch (error) {
    console.error('❌ Erro ao conectar MongoDB:', error);
    process.exit(1);
  }
};

// Schemas (copiados do server.js)
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'content_manager'], default: 'content_manager' },
  isActive: { type: Boolean, default: true },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

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
}, { timestamps: true });

const playlistSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  description: { type: String, trim: true },
  media: [{
    mediaId: { type: mongoose.Schema.Types.ObjectId, ref: 'Media', required: true },
    order: { type: Number, default: 0 },
    duration: { type: Number }
  }],
  totalDuration: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

const deviceSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  deviceToken: { type: String, required: true, unique: true },
  location: { type: String, trim: true },
  resolution: { type: String, default: '1920x1080' },
  assignedPlaylistId: { type: mongoose.Schema.Types.ObjectId, ref: 'Playlist' },
  status: { type: String, enum: ['online', 'offline', 'maintenance'], default: 'offline' },
  lastSeenAt: { type: Date, default: Date.now },
  heartbeatInterval: { type: Number, default: 30000 },
  isActive: { type: Boolean, default: true },
  metadata: {
    userAgent: String,
    ipAddress: String,
    screenSize: String
  },
  createdAt: { type: Date, default: Date.now }
}, { timestamps: true });

// Modelos
const User = mongoose.model('User', userSchema);
const Media = mongoose.model('Media', mediaSchema);
const Playlist = mongoose.model('Playlist', playlistSchema);
const Device = mongoose.model('Device', deviceSchema);

// Função para obter informações de arquivo
const getFileInfo = (filename) => {
  const filePath = path.join(__dirname, 'uploads', filename);
  
  if (!fs.existsSync(filePath)) {
    return null;
  }
  
  const stats = fs.statSync(filePath);
  const ext = path.extname(filename).toLowerCase();
  
  let mimetype = 'application/octet-stream';
  if (['.mp4', '.webm', '.ogg', '.avi', '.mov'].includes(ext)) {
    mimetype = 'video/mp4';
  } else if (['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext)) {
    mimetype = 'image/jpeg';
  }
  
  return {
    size: stats.size,
    mimetype,
    createdAt: stats.birthtime
  };
};

// Inicializar dados de teste
const initTestData = async () => {
  try {
    console.log('🚀 Inicializando dados de teste...');
    
    // Limpar dados existentes
    await Promise.all([
      User.deleteMany({}),
      Media.deleteMany({}),
      Playlist.deleteMany({}),
      Device.deleteMany({})
    ]);
    console.log('🧹 Dados existentes removidos');
    
    // 1. Criar usuário administrador
    const bcrypt = require('bcryptjs');
    const adminPassword = await bcrypt.hash('admin123', 10);
    
    const admin = await User.create({
      name: 'Administrador Tritotem',
      email: 'admin@tritotem.com',
      password: adminPassword,
      role: 'admin'
    });
    console.log('👤 Usuário administrador criado');
    
    // 2. Criar mídias baseadas nos arquivos existentes
    const uploadsDir = path.join(__dirname, 'uploads');
    const files = fs.readdirSync(uploadsDir).filter(file => 
      file.endsWith('.mp4') || file.endsWith('.webm') || 
      file.endsWith('.jpg') || file.endsWith('.png')
    );
    
    const mediaItems = [];
    
    for (const filename of files) {
      const fileInfo = getFileInfo(filename);
      if (fileInfo) {
        const media = await Media.create({
          name: filename.replace(/^[a-f0-9-]+/, '').replace(/\.[^.]+$/, '') || 'Vídeo de Teste',
          filename: filename,
          originalName: filename,
          mimetype: fileInfo.mimetype,
          size: fileInfo.size,
          duration: fileInfo.mimetype.startsWith('video/') ? 30 : 0, // Duração estimada
          uploadedBy: admin._id,
          tags: ['teste', 'demo']
        });
        
        mediaItems.push(media);
        console.log(`📁 Mídia criada: ${media.name}`);
      }
    }
    
    // 3. Criar playlist de teste
    let playlist = null;
    if (mediaItems.length > 0) {
      const totalDuration = mediaItems.reduce((sum, media) => sum + (media.duration || 0), 0);
      
      playlist = await Playlist.create({
        name: 'Playlist Principal',
        description: 'Playlist de demonstração com conteúdo de teste',
        media: mediaItems.map((media, index) => ({
          mediaId: media._id,
          order: index,
          duration: media.duration
        })),
        totalDuration: totalDuration,
        createdBy: admin._id
      });
      console.log(`📋 Playlist criada: ${playlist.name} (${mediaItems.length} mídias)`);
    }
    
    // 4. Criar dispositivos de teste (TVs)
    const devices = [
      {
        name: 'TV Recepção Principal',
        location: 'Recepção - Térreo',
        resolution: '1920x1080'
      },
      {
        name: 'TV Sala de Espera',
        location: 'Sala de Espera - 1º Andar',
        resolution: '1920x1080'
      },
      {
        name: 'TV Corredor Central',
        location: 'Corredor Principal - 2º Andar',
        resolution: '3840x2160'
      }
    ];
    
    const createdDevices = [];
    for (const deviceData of devices) {
      const device = await Device.create({
        ...deviceData,
        deviceToken: uuidv4(),
        assignedPlaylistId: playlist?._id || null,
        status: Math.random() > 0.5 ? 'online' : 'offline',
        lastSeenAt: new Date(Date.now() - Math.random() * 3600000) // Última vez visto nas últimas 1h
      });
      
      createdDevices.push(device);
      console.log(`📺 Dispositivo criado: ${device.name} (Token: ${device.deviceToken})`);
    }
    
    // 5. Exibir resumo
    console.log('\n✅ Dados de teste inicializados com sucesso!');
    console.log('\n📊 RESUMO:');
    console.log(`👤 Usuários: 1 (admin@tritotem.com / admin123)`);
    console.log(`📁 Mídias: ${mediaItems.length}`);
    console.log(`📋 Playlists: ${playlist ? 1 : 0}`);
    console.log(`📺 Dispositivos: ${createdDevices.length}`);
    
    console.log('\n🔗 URLs dos Players:');
    const baseUrl = process.env.BASE_URL || 'http://localhost:3001';
    createdDevices.forEach(device => {
      console.log(`${device.name}: ${baseUrl}/player/${device.deviceToken}`);
    });
    
    console.log('\n🌐 Acesso ao Sistema:');
    console.log(`Frontend: ${process.env.FRONTEND_URL || 'http://localhost:5173'}`);
    console.log(`Backend: ${baseUrl}`);
    
  } catch (error) {
    console.error('❌ Erro ao inicializar dados:', error);
  } finally {
    mongoose.connection.close();
  }
};

// Executar se chamado diretamente
if (require.main === module) {
  connectDB().then(initTestData);
}

module.exports = { initTestData };
