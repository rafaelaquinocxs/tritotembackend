require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");

console.log("🚀 Iniciando servidor Tritotem v2.0...");

const app = express();

// Configuração CORS otimizada para produção
const allowedOrigins = [
  "https://tritotem-frontend.vercel.app",
  "https://tritotem-cc0a461d6f3e.herokuapp.com",
  "http://localhost:3000",
  "http://localhost:5173",
  "http://localhost:5174",
  // Adicionar domínios das TVs se necessário
  /^https:\/\/.*\.vercel\.app$/,
  /^https:\/\/.*\.herokuapp\.com$/,
];

app.use(
  cors({
    origin: function (origin, callback ) {
      // Permitir requests sem origin (mobile apps, Postman, etc.)
      if (!origin) return callback(null, true);

      // Verificar se a origem está na lista permitida
      const isAllowed = allowedOrigins.some((allowedOrigin) => {
        if (typeof allowedOrigin === "string") {
          return allowedOrigin === origin;
        }
        return allowedOrigin.test(origin);
      });

      if (isAllowed) {
        callback(null, true);
      } else {
        console.warn(`❌ CORS bloqueou origem: ${origin}`);
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    credentials: true,
  })
);

// Middleware básico
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// Headers de segurança
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  next();
});

// Configuração de uploads
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log("📁 Diretório de uploads criado");
}

// Servir arquivos estáticos
app.use("/uploads", express.static(uploadsDir, {
  maxAge: "1d",
  etag: true,
  lastModified: true,
}));

// Configuração Multer otimizada
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const uniqueId = uuidv4();
    const ext = path.extname(file.originalname);
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, "_");
    cb(null, `${uniqueId}-${safeName}`);
  },
});

const upload = multer({
  storage,
  limits: {
    fileSize: 500 * 1024 * 1024, // 500MB
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    const allowedMimes = [
      "video/mp4",
      "video/webm",
      "video/ogg",
      "video/avi",
      "video/mov",
      "image/jpeg",
      "image/jpg",
      "image/png",
      "image/gif",
      "image/webp",
    ];

    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Tipo de arquivo não permitido: ${file.mimetype}`));
    }
  },
});

// Conexão MongoDB com retry
const connectDB = async () => {
  const maxRetries = 5;
  let retries = 0;

  while (retries < maxRetries) {
    try {
      if (!process.env.MONGODB_URI) {
        throw new Error("MONGODB_URI não configurado");
      }

      await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
      });

      console.log("✅ MongoDB conectado com sucesso");
      return;
    } catch (err) {
      retries++;
      console.error(
        `❌ Tentativa ${retries}/${maxRetries} - Erro MongoDB:`, err.message
      );

      if (retries === maxRetries) {
        console.error("💀 Falha ao conectar MongoDB após todas as tentativas");
        // Não encerrar o processo, permitir que funcione sem DB para testes
      } else {
        await new Promise((resolve) => setTimeout(resolve, 2000 * retries));
      }
    }
  }
};

// Inicializar conexão DB
connectDB();

// Schemas otimizados
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: { type: String, required: true },
    role: {
      type: String,
      enum: ["admin", "content_manager"],
      default: "content_manager",
    },
    isActive: { type: Boolean, default: true },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now },
  },
  {
    timestamps: true,
  }
);

const mediaSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    filename: { type: String, required: true },
    originalName: { type: String, required: true },
    mimetype: { type: String, required: true },
    size: { type: Number, required: true },
    duration: { type: Number, default: 0 },
    resolution: { type: String },
    tags: [{ type: String, trim: true }],
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
  },
  {
    timestamps: true,
  }
);

const playlistSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    description: { type: String, trim: true },
    media: [
      {
        mediaId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Media",
          required: true,
        },
        order: { type: Number, default: 0 },
        duration: { type: Number }, // Duração específica para esta mídia na playlist
      },
    ],
    totalDuration: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    createdAt: { type: Date, default: Date.now },
  },
  {
    timestamps: true,
  }
);

const deviceSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    deviceToken: { type: String, required: true, unique: true },
    location: { type: String, trim: true },
    resolution: { type: String, default: "1920x1080" },
    assignedPlaylistId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Playlist",
    },
    status: {
      type: String,
      enum: ["online", "offline", "maintenance"],
      default: "offline",
    },
    lastSeenAt: { type: Date, default: Date.now },
    heartbeatInterval: { type: Number, default: 30000 }, // 30 segundos
    isActive: { type: Boolean, default: true },
    metadata: {
      userAgent: String,
      ipAddress: String,
      screenSize: String,
    },
    createdAt: { type: Date, default: Date.now },
  },
  {
    timestamps: true,
  }
);

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
const User = mongoose.model("User", userSchema);
const Media = mongoose.model("Media", mediaSchema);
const Playlist = mongoose.model("Playlist", playlistSchema);
const Device = mongoose.model("Device", deviceSchema);

// Middleware de autenticação simplificado para desenvolvimento
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  // Para desenvolvimento, aceitar qualquer token ou sem token
  if (process.env.NODE_ENV !== "production" || !token) {
    req.user = {
      userId: "dev-user",
      email: "dev@tritotem.com",
      role: "admin",
    };
    return next();
  }

  // Em produção, implementar validação JWT real
  try {
    const jwt = require("jsonwebtoken");
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "tritotem-secret");
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: "Token inválido" });
  }
};

// Middleware para logging de requests
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`${timestamp} - ${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Health check melhorado
app.get("/", (req, res) => {
  res.json({
    message: "API Tritotem v2.0 funcionando!",
    timestamp: new Date().toISOString(),
    version: "2.0.0",
    status: "healthy",
    environment: process.env.NODE_ENV || "development",
  });
});

// Página de demonstração das TVs
app.get("/demo", (req, res) => {
  const demoPath = path.join(__dirname, "tv-demo.html");
  res.sendFile(demoPath);
});

app.get("/health", async (req, res) => {
  const health = {
    status: "healthy",
    timestamp: new Date().toISOString(),
    services: {
      database: "unknown",
      uploads: "unknown",
    },
  };

  try {
    // Verificar conexão DB
    if (mongoose.connection.readyState === 1) {
      health.services.database = "connected";
    } else {
      health.services.database = "disconnected";
      health.status = "degraded";
    }

    // Verificar diretório de uploads
    if (fs.existsSync(uploadsDir)) {
      health.services.uploads = "available";
    } else {
      health.services.uploads = "unavailable";
      health.status = "degraded";
    }

    res.json(health);
  } catch (error) {
    health.status = "unhealthy";
    health.error = error.message;
    res.status(500).json(health);
  }
});

// Streaming otimizado com suporte a range requests
app.get("/stream/:filename", (req, res) => {
  try {
    const filename = req.params.filename;
    const filePath = path.join(uploadsDir, filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "Arquivo não encontrado" });
    }

    const stat = fs.statSync(filePath);
    const fileSize = stat.size;
    const range = req.headers.range;

    // Determinar MIME type
    const ext = path.extname(filename).toLowerCase();
    const mimeTypes = {
      ".mp4": "video/mp4",
      ".webm": "video/webm",
      ".ogg": "video/ogg",
      ".avi": "video/avi",
      ".mov": "video/quicktime",
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".png": "image/png",
      ".gif": "image/gif",
      ".webp": "image/webp",
    };
    const mimeType = mimeTypes[ext] || "application/octet-stream";

    if (range) {
      // Suporte a range requests para streaming
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;

      if (start >= fileSize || end >= fileSize) {
        res.status(416).set({
          "Content-Range": `bytes */${fileSize}`,
        });
        return res.end();
      }

      const chunksize = end - start + 1;
      const file = fs.createReadStream(filePath, { start, end });

      res.writeHead(206, {
        "Content-Range": `bytes ${start}-${end}/${fileSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": chunksize,
        "Content-Type": mimeType,
        "Cache-Control": "public, max-age=86400",
      });

      file.pipe(res);
    } else {
      // Streaming completo
      res.writeHead(200, {
        "Content-Length": fileSize,
        "Content-Type": mimeType,
        "Accept-Ranges": "bytes",
        "Cache-Control": "public, max-age=86400",
      });

      fs.createReadStream(filePath).pipe(res);
    }
  } catch (err) {
    console.error("Erro no streaming:", err);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// ROTAS DE AUTENTICAÇÃO
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email e senha são obrigatórios" });
    }

    // Em desenvolvimento, aceitar qualquer credencial
    if (process.env.NODE_ENV !== "production") {
      return res.json({
        token: "dev-token-" + Date.now(),
        user: {
          id: "dev-user",
          name: "Desenvolvedor",
          email: email,
          role: "admin",
        },
      });
    }

    const user = await User.findOne({ email: email.toLowerCase(), isActive: true });

    if (!user) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    // Verificar senha (implementar bcrypt em produção)
    const bcrypt = require("bcryptjs");
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    // Atualizar último login
    user.lastLogin = new Date();
    await user.save();

    // Gerar JWT
    const jwt = require("jsonwebtoken");
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || "tritotem-secret",
      { expiresIn: "24h" }
    );

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Erro no login:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.post("/api/auth/init", async (req, res) => {
  try {
    const adminExists = await User.findOne({ role: "admin", isActive: true });
    if (adminExists) {
      return res.status(400).json({ error: "Administrador já existe" });
    }

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Todos os campos são obrigatórios" });
    }

    const bcrypt = require("bcryptjs");
    const hashedPassword = await bcrypt.hash(password, 10);

    const admin = new User({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      role: "admin",
    });

    await admin.save();

    const jwt = require("jsonwebtoken");
    const token = jwt.sign(
      { userId: admin._id, email: admin.email, role: admin.role },
      process.env.JWT_SECRET || "tritotem-secret",
      { expiresIn: "24h" }
    );

    res.status(201).json({
      token,
      user: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
        role: admin.role,
      },
    });
  } catch (error) {
    console.error("Erro na inicialização:", error);
    if (error.code === 11000) {
      return res.status(400).json({ error: "Email já está em uso" });
    }
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    if (process.env.NODE_ENV !== "production") {
      return res.json({
        userId: "dev-user",
        name: "Desenvolvedor",
        email: "dev@tritotem.com",
        role: "admin",
      });
    }

    const user = await User.findById(req.user.userId).select("-password");
    if (!user || !user.isActive) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    });
  } catch (error) {
    console.error("Erro ao buscar usuário:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// ROTAS DE DISPOSITIVOS (TVs)
app.get("/api/devices", authenticateToken, async (req, res) => {
  try {
    const devices = await Device.find({ isActive: true })
      .populate("assignedPlaylistId")
      .sort({ createdAt: -1 });
    res.json(devices);
  } catch (error) {
    console.error("Erro ao listar dispositivos:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.post("/api/devices", authenticateToken, async (req, res) => {
  try {
    const { name, location, resolution } = req.body;

    if (!name) {
      return res.status(400).json({ error: "Nome do dispositivo é obrigatório" });
    }

    const device = new Device({
      name: name.trim(),
      location: location?.trim(),
      resolution: resolution || "1920x1080",
      deviceToken: uuidv4(),
    });

    await device.save();
    await device.populate("assignedPlaylistId");

    console.log(`📱 Novo dispositivo criado: ${device.name} (${device.deviceToken})`);
    res.status(201).json(device);
  } catch (error) {
    console.error("Erro ao criar dispositivo:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.get("/api/devices/:id", authenticateToken, async (req, res) => {
  try {
    const device = await Device.findOne({
      _id: req.params.id,
      isActive: true,
    }).populate("assignedPlaylistId");

    if (!device) {
      return res.status(404).json({ error: "Dispositivo não encontrado" });
    }

    res.json(device);
  } catch (error) {
    console.error("Erro ao buscar dispositivo:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.put("/api/devices/:id", authenticateToken, async (req, res) => {
  try {
    const { name, location, resolution, assignedPlaylistId } = req.body;

    const updateData = {};
    if (name) updateData.name = name.trim();
    if (location !== undefined) updateData.location = location?.trim();
    if (resolution) updateData.resolution = resolution;
    if (assignedPlaylistId !== undefined) {
      updateData.assignedPlaylistId = assignedPlaylistId || null;
    }

    const device = await Device.findOneAndUpdate(
      { _id: req.params.id, isActive: true },
      updateData,
      { new: true }
    ).populate("assignedPlaylistId");

    if (!device) {
      return res.status(404).json({ error: "Dispositivo não encontrado" });
    }

    console.log(`📱 Dispositivo atualizado: ${device.name}`);
    res.json(device);
  } catch (error) {
    console.error("Erro ao atualizar dispositivo:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.delete("/api/devices/:id", authenticateToken, async (req, res) => {
  try {
    const device = await Device.findOneAndUpdate(
      { _id: req.params.id, isActive: true },
      { isActive: false },
      { new: true }
    );

    if (!device) {
      return res.status(404).json({ error: "Dispositivo não encontrado" });
    }

    console.log(`📱 Dispositivo removido: ${device.name}`);
    res.json({ message: "Dispositivo removido com sucesso" });
  } catch (error) {
    console.error("Erro ao remover dispositivo:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Heartbeat para monitoramento de TVs
app.post("/api/devices/:id/heartbeat", async (req, res) => {
  try {
    const { userAgent, screenSize } = req.body;

    const device = await Device.findOneAndUpdate(
      { _id: req.params.id, isActive: true },
      {
        lastSeenAt: new Date(),
        status: "online",
        "metadata.userAgent": userAgent,
        "metadata.ipAddress": req.ip,
        "metadata.screenSize": screenSize,
      },
      { new: true }
    );

    if (!device) {
      return res.status(404).json({ error: "Dispositivo não encontrado" });
    }

    res.json({
      message: "Heartbeat recebido",
      status: "online",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Erro no heartbeat:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Heartbeat por token (para as TVs)
app.post("/api/devices/token/:token/heartbeat", async (req, res) => {
  try {
    const { userAgent, screenSize } = req.body;

    const device = await Device.findOneAndUpdate(
      { deviceToken: req.params.token, isActive: true },
      {
        lastSeenAt: new Date(),
        status: "online",
        "metadata.userAgent": userAgent,
        "metadata.ipAddress": req.ip,
        "metadata.screenSize": screenSize,
      },
      { new: true }
    );

    if (!device) {
      return res.status(404).json({ error: "Dispositivo não encontrado" });
    }

    res.json({
      message: "Heartbeat recebido",
      status: "online",
      device: device.name,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Erro no heartbeat por token:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Atribuir playlist para todos os dispositivos
app.post("/api/devices/broadcast-assign", authenticateToken, async (req, res) => {
  try {
    const { playlistId } = req.body;

    const result = await Device.updateMany(
      { isActive: true },
      { assignedPlaylistId: playlistId || null }
    );

    const devices = await Device.find({ isActive: true }).populate("assignedPlaylistId");

    console.log(
      `📡 Playlist ${playlistId || "removida"} atribuída a ${result.modifiedCount} dispositivos`
    );
    res.json({
      message: `Playlist atribuída a ${result.modifiedCount} dispositivos`,
      devices,
    });
  } catch (error) {
    console.error("Erro na atribuição broadcast:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// ROTAS DE MÍDIA
app.get("/api/media", authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 50, search, type } = req.query;

    const query = { isActive: true };

    if (search) {
      query.$or = [
        { name: { $regex: search, $options: "i" } },
        { originalName: { $regex: search, $options: "i" } },
        { tags: { $in: [new RegExp(search, "i")] } },
      ];
    }

    if (type) {
      query.mimetype = { $regex: `^${type}/`, $options: "i" };
    }

    const media = await Media.find(query)
      .populate("uploadedBy", "name email")
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Media.countDocuments(query);

    res.json({
      media,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Erro ao listar mídias:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.post("/api/media", authenticateToken, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Nenhum arquivo enviado" });
    }

    const { name, tags } = req.body;

    const media = new Media({
      name: name?.trim() || req.file.originalname,
      filename: req.file.filename,
      originalName: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      tags: tags ? tags.split(",").map((tag) => tag.trim()) : [],
      uploadedBy: req.user.userId,
    });

    await media.save();
    await media.populate("uploadedBy", "name email");

    console.log(
      `📁 Nova mídia enviada: ${media.name} (${(media.size / 1024 / 1024).toFixed(2)} MB)`
    );
    res.status(201).json(media);
  } catch (error) {
    console.error("Erro no upload:", error);

    // Limpar arquivo em caso de erro
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }

    res.status(500).json({ error: "Erro no upload do arquivo" });
  }
});

app.get("/api/media/:id", authenticateToken, async (req, res) => {
  try {
    const media = await Media.findOne({
      _id: req.params.id,
      isActive: true,
    }).populate("uploadedBy", "name email");

    if (!media) {
      return res.status(404).json({ error: "Mídia não encontrada" });
    }

    res.json(media);
  } catch (error) {
    console.error("Erro ao buscar mídia:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.put("/api/media/:id", authenticateToken, async (req, res) => {
  try {
    const { name, tags } = req.body;

    const updateData = {};
    if (name) updateData.name = name.trim();
    if (tags !== undefined) {
      updateData.tags = Array.isArray(tags)
        ? tags
        : tags.split(",").map((tag) => tag.trim());
    }

    const media = await Media.findOneAndUpdate(
      { _id: req.params.id, isActive: true },
      updateData,
      { new: true }
    ).populate("uploadedBy", "name email");

    if (!media) {
      return res.status(404).json({ error: "Mídia não encontrada" });
    }

    res.json(media);
  } catch (error) {
    console.error("Erro ao atualizar mídia:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.delete("/api/media/:id", authenticateToken, async (req, res) => {
  try {
    const media = await Media.findOne({ _id: req.params.id, isActive: true });

    if (!media) {
      return res.status(404).json({ error: "Mídia não encontrada" });
    }

    // Verificar se a mídia está sendo usada em alguma playlist
    const playlistsUsingMedia = await Playlist.find({
      "media.mediaId": media._id,
      isActive: true,
    });

    if (playlistsUsingMedia.length > 0) {
      return res.status(400).json({
        error: "Mídia está sendo usada em playlists ativas",
        playlists: playlistsUsingMedia.map((p) => p.name),
      });
    }

    // Remover arquivo físico
    const filePath = path.join(uploadsDir, media.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Marcar como inativa
    media.isActive = false;
    await media.save();

    console.log(`🗑️ Mídia removida: ${media.name}`);
    res.json({ message: "Mídia removida com sucesso" });
  } catch (error) {
    console.error("Erro ao remover mídia:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// ROTAS DE PLAYLISTS
app.get("/api/playlists", authenticateToken, async (req, res) => {
  try {
    const playlists = await Playlist.find({ isActive: true })
      .populate({
        path: "media.mediaId",
        match: { isActive: true },
      })
      .populate("createdBy", "name email")
      .sort({ createdAt: -1 });

    // Calcular duração total e filtrar mídias inativas
    const processedPlaylists = playlists.map((playlist) => {
      const activeMedia = playlist.media.filter((item) => item.mediaId);
      let totalDuration = 0;

      activeMedia.forEach((item) => {
        totalDuration += item.duration || item.mediaId?.duration || 0;
      });

      return {
        ...playlist.toObject(),
        media: activeMedia,
        totalDuration,
      };
    });

    res.json(processedPlaylists);
  } catch (error) {
    console.error("Erro ao listar playlists:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.post("/api/playlists", authenticateToken, async (req, res) => {
  try {
    const { name, description, media } = req.body;

    if (!name) {
      return res.status(400).json({ error: "Nome da playlist é obrigatório" });
    }

    // Validar mídias
    const mediaItems = media || [];
    let totalDuration = 0;

    for (let i = 0; i < mediaItems.length; i++) {
      const item = mediaItems[i];
      const mediaDoc = await Media.findOne({ _id: item.mediaId, isActive: true });

      if (!mediaDoc) {
        return res.status(400).json({
          error: `Mídia não encontrada: ${item.mediaId}`,
        });
      }

      item.order = i;
      totalDuration += item.duration || mediaDoc.duration || 0;
    }

    const playlist = new Playlist({
      name: name.trim(),
      description: description?.trim(),
      media: mediaItems,
      totalDuration,
      createdBy: req.user.userId,
    });

    await playlist.save();
    await playlist.populate([
      { path: "media.mediaId" },
      { path: "createdBy", select: "name email" },
    ]);

    console.log(
      `📋 Nova playlist criada: ${playlist.name} (${mediaItems.length} mídias)`
    );
    res.status(201).json(playlist);
  } catch (error) {
    console.error("Erro ao criar playlist:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.get("/api/playlists/:id", authenticateToken, async (req, res) => {
  try {
    const playlist = await Playlist.findOne({
      _id: req.params.id,
      isActive: true,
    })
      .populate({
        path: "media.mediaId",
        match: { isActive: true },
      })
      .populate("createdBy", "name email");

    if (!playlist) {
      return res.status(404).json({ error: "Playlist não encontrada" });
    }

    // Filtrar mídias inativas
    const activeMedia = playlist.media.filter((item) => item.mediaId);
    playlist.media = activeMedia;

    res.json(playlist);
  } catch (error) {
    console.error("Erro ao buscar playlist:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.put("/api/playlists/:id", authenticateToken, async (req, res) => {
  try {
    const { name, description, media } = req.body;

    const updateData = {};
    if (name) updateData.name = name.trim();
    if (description !== undefined) updateData.description = description?.trim();

    if (media) {
      // Validar e processar mídias
      let totalDuration = 0;

      for (let i = 0; i < media.length; i++) {
        const item = media[i];
        const mediaDoc = await Media.findOne({ _id: item.mediaId, isActive: true });

        if (!mediaDoc) {
          return res.status(400).json({
            error: `Mídia não encontrada: ${item.mediaId}`,
          });
        }

        item.order = i;
        totalDuration += item.duration || mediaDoc.duration || 0;
      }

      updateData.media = media;
      updateData.totalDuration = totalDuration;
    }

    const playlist = await Playlist.findOneAndUpdate(
      { _id: req.params.id, isActive: true },
      updateData,
      { new: true }
    ).populate([
      { path: "media.mediaId" },
      { path: "createdBy", select: "name email" },
    ]);

    if (!playlist) {
      return res.status(404).json({ error: "Playlist não encontrada" });
    }

    console.log(`📋 Playlist atualizada: ${playlist.name}`);
    res.json(playlist);
  } catch (error) {
    console.error("Erro ao atualizar playlist:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

app.delete("/api/playlists/:id", authenticateToken, async (req, res) => {
  try {
    // Verificar se a playlist está sendo usada por algum dispositivo
    const devicesUsingPlaylist = await Device.find({
      assignedPlaylistId: req.params.id,
      isActive: true,
    });

    if (devicesUsingPlaylist.length > 0) {
      return res.status(400).json({
        error: "Playlist está sendo usada por dispositivos ativos",
        devices: devicesUsingPlaylist.map((d) => d.name),
      });
    }

    const playlist = await Playlist.findOneAndUpdate(
      { _id: req.params.id, isActive: true },
      { isActive: false },
      { new: true }
    );

    if (!playlist) {
      return res.status(404).json({ error: "Playlist não encontrada" });
    }

    console.log(`🗑️ Playlist removida: ${playlist.name}`);
    res.json({ message: "Playlist removida com sucesso" });
  } catch (error) {
    console.error("Erro ao remover playlist:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// ROTA DO PLAYER PARA TVs
app.get("/player/:deviceToken", async (req, res) => {
  try {
    const { deviceToken } = req.params;

    const device = await Device.findOne({
      deviceToken,
      isActive: true,
    }).populate({
      path: "assignedPlaylistId",
      populate: {
        path: "media.mediaId",
        match: { isActive: true },
      },
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
      status: "online",
      "metadata.userAgent": req.get("User-Agent"),
      "metadata.ipAddress": req.ip,
    });

    const baseUrl = process.env.NODE_ENV === "production"
      ? (process.env.BASE_URL || "https://tritotem-cc0a461d6f3e.herokuapp.com" )
      : "http://localhost:3001";

    const playlist = device.assignedPlaylistId?.media?.filter((item ) => item.mediaId) || [];
    const playlistName = device.assignedPlaylistId?.name || "Nenhuma";

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
        
        .video-container {
          position: relative; width: 100vw; height: 100vh;
          overflow: hidden;
        }

        video {
          position: absolute; top: 0; left: 0;
          width: 100%; height: 100%;
          object-fit: cover; display: block;
          transition: opacity 0.5s ease-in-out;
        }
        
        .video-hidden { opacity: 0; }
        .video-active { opacity: 1; z-index: 1; }
        
        .info { 
          position: fixed; top: 20px; left: 20px; 
          color: white; background: rgba(0,0,0,0.8); 
          padding: 15px 20px; border-radius: 10px; 
          font-size: 14px; z-index: 1000; 
          backdrop-filter: blur(10px);
          border: 1px solid rgba(255,255,255,0.1);
        }
        
        .info h3 { margin-bottom: 8px; color: #4CAF50; }
        .info div { margin-bottom: 4px; }
        .info strong { color: #fff; }
        .info .status { color: #4CAF50; }
        .info .status.loading { color: #FF9800; }
        .info .status.error { color: #f44336; }
        
        .no-content {
          display: flex; align-items: center; justify-content: center;
          width: 100vw; height: 100vh; color: white; text-align: center;
          background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 50%, #1a1a1a 100%);
        }
        
        .no-content h1 { font-size: 4rem; margin-bottom: 1rem; }
        .no-content h2 { font-size: 2rem; margin-bottom: 0.5rem; color: #4CAF50; }
        .no-content p { font-size: 1.2rem; opacity: 0.8; }
        
        .loading-overlay {
          position: fixed; top: 0; left: 0; width: 100%; height: 100%;
          background: rgba(0,0,0,0.8); display: flex; align-items: center;
          justify-content: center; flex-direction: column; z-index: 9999;
          transition: opacity 0.3s ease-in-out;
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
        
        .hidden { opacity: 0; pointer-events: none; }
      </style>
    </head>
    <body>
      <div class="info">
        <h3>📺 Tritotem Player v2.0</h3>
        <div><strong>Dispositivo:</strong> ${device.name}</div>
        <div><strong>Local:</strong> ${device.location || "Não definido"}</div>
        <div><strong>Status:</strong> <span id="status" class="status loading">Inicializando...</span></div>
        <div><strong>Playlist:</strong> ${playlistName}</div>
        <div><strong>Mídias:</strong> ${playlist.length}</div>
        <div><strong>Resolução:</strong> ${device.resolution}</div>
      </div>
      
      <div id="loading-overlay" class="loading-overlay">
        <div class="spinner"></div>
        <p style="color:white;">Carregando conteúdo...</p>
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
        <div class="video-container">
          <video id="player1" class="video-active" autoplay muted playsinline preload="auto"></video>
          <video id="player2" class="video-hidden" muted playsinline preload="auto"></video>
        </div>
      `}
      
      <script>
        const player1 = document.getElementById("player1");
        const player2 = document.getElementById("player2");
        const statusSpan = document.getElementById("status");
        const loadingOverlay = document.getElementById("loading-overlay");
        const playlist = ${JSON.stringify(playlist)};
        
        let currentIndex = 0;
        let heartbeatInterval;
        let reloadTimeout;
        let activePlayer = player1;
        let nextPlayer = player2;
        
        // Configurações
        const config = {
          baseUrl: "${baseUrl}",
          deviceId: "${device._id}",
          deviceToken: "${deviceToken}",
          heartbeatInterval: ${device.heartbeatInterval || 30000},
          reloadInterval: 10 * 60 * 1000, // 10 minutos
          retryDelay: 5000,
          preloadOffset: 5 // Segundos antes do fim para iniciar o preload
        };
        
        function updateStatus(message, type = "status") {
          if (statusSpan) {
            statusSpan.textContent = message;
            statusSpan.className = "status " + type;
          }
          console.log("[Tritotem]", message);
        }
        
        function hideLoading() {
          if (loadingOverlay) {
            loadingOverlay.classList.add("hidden");
          }
        }
        
        function showLoading() {
          if (loadingOverlay) {
            loadingOverlay.classList.remove("hidden");
          }
        }

        function getMediaUrl(mediaItem) {
          if (!mediaItem || !mediaItem.mediaId) return null;
          return config.baseUrl + "/stream/" + mediaItem.mediaId.filename;
        }

        function switchPlayers() {
          activePlayer.classList.remove("video-active");
          activePlayer.classList.add("video-hidden");
          
          nextPlayer.classList.remove("video-hidden");
          nextPlayer.classList.add("video-active");

          [activePlayer, nextPlayer] = [nextPlayer, activePlayer]; // Troca de referência
        }

        function loadAndPlay(player, mediaItem, isPreload = false) {
          const url = getMediaUrl(mediaItem);
          if (!url) return;

          player.src = url;
          player.load(); // Garante que o navegador comece a carregar
          player.muted = true; // Sempre mutado para preload

          if (!isPreload) {
            player.play().catch(e => console.error("Erro ao iniciar reprodução:", e));
            player.muted = false; // Desmuta o player ativo
            updateStatus("Reproduzindo: " + mediaItem.mediaId.name, "status");
          } else {
            updateStatus("Pré-carregando: " + mediaItem.mediaId.name, "loading");
          }
        }

        function playNext() {
          if (playlist.length === 0) {
            updateStatus("Aguardando playlist", "loading");
            hideLoading();
            return;
          }

          // Troca os players visivelmente
          switchPlayers();

          // O player que estava pre-carregando agora é o ativo
          // O player que estava ativo agora vai pre-carregar o proximo

          // Inicia a reprodução do player ativo (que já deveria estar pré-carregado)
          activePlayer.play().catch(e => console.error("Erro ao iniciar reprodução:", e));
          activePlayer.muted = false; // Desmuta o player ativo
          hideLoading();
          updateStatus("Reproduzindo: " + playlist[currentIndex].mediaId.name, "status");

          // Avança para o próximo item da playlist
          currentIndex = (currentIndex + 1) % playlist.length;

          // Pré-carrega o próximo vídeo no player inativo
          const nextMediaItem = playlist[currentIndex];
          if (nextMediaItem) {
            loadAndPlay(nextPlayer, nextMediaItem, true);
          }
        }
        
        function sendHeartbeat() {
          const heartbeatData = {
            userAgent: navigator.userAgent,
            screenSize: screen.width + "x" + screen.height,
            timestamp: new Date().toISOString()
          };
          
          fetch(config.baseUrl + "/api/devices/token/" + config.deviceToken + "/heartbeat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(heartbeatData)
          })
          .then(response => response.json())
          .then(data => {
            console.log("[Heartbeat]", data.message);
          })
          .catch(error => {
            console.error("[Heartbeat] Erro:", error);
          });
        }
        
        function setupPlayerEvents(playerElement) {
          playerElement.addEventListener("ended", () => {
            console.log("Video ended on", playerElement.id);
            playNext();
          });

          playerElement.addEventListener("error", (e) => {
            console.error("[Player] Erro no " + playerElement.id + ":", e);
            updateStatus("Erro no vídeo (" + playerElement.id + ")", "error");
            // Tentar próximo vídeo após delay em caso de erro
            setTimeout(playNext, config.retryDelay);
          });

          playerElement.addEventListener("stalled", () => {
            updateStatus("Conexão lenta (" + playerElement.id + ")...", "loading");
          });

          playerElement.addEventListener("waiting", () => {
            updateStatus("Buffering (" + playerElement.id + ")...", "loading");
          });

          playerElement.addEventListener("canplaythrough", () => {
            if (playerElement === nextPlayer) {
              console.log("Next video canplaythrough on", playerElement.id);
              // Opcional: esconder o loading se o próximo já estiver pronto
              // hideLoading(); 
            }
          });

          playerElement.addEventListener("timeupdate", () => {
            if (playerElement === activePlayer && activePlayer.duration && !isNaN(activePlayer.duration)) {
              const remaining = activePlayer.duration - activePlayer.currentTime;
              if (remaining <= config.preloadOffset && remaining > 0) {
                // Se o próximo vídeo ainda não foi pré-carregado, iniciar agora
                const nextIndex = (currentIndex) % playlist.length;
                const nextMediaItem = playlist[nextIndex];
                if (nextMediaItem && nextPlayer.src !== getMediaUrl(nextMediaItem)) {
                  console.log("Preloading next video due to timeupdate:", nextMediaItem.mediaId.name);
                  loadAndPlay(nextPlayer, nextMediaItem, true);
                }
              }
            }
          });
        }
        
        function init() {
          updateStatus("Inicializando...", "loading");
          
          if (playlist.length === 0) {
            hideLoading();
            return;
          }

          setupPlayerEvents(player1);
          setupPlayerEvents(player2);

          // Carrega e reproduz o primeiro vídeo no player1
          loadAndPlay(activePlayer, playlist[currentIndex]);
          activePlayer.muted = false; // Garante que o primeiro vídeo não esteja mutado

          // Pré-carrega o segundo vídeo no player2
          currentIndex = (currentIndex + 1) % playlist.length;
          if (playlist[currentIndex]) {
            loadAndPlay(nextPlayer, playlist[currentIndex], true);
          }

          // Iniciar heartbeat
          sendHeartbeat();
          heartbeatInterval = setInterval(sendHeartbeat, config.heartbeatInterval);
          
          // Reload automático
          reloadTimeout = setTimeout(() => {
            console.log("[System] Reload automático");
            location.reload();
          }, config.reloadInterval);
          
          // Detectar perda de foco e recarregar
          document.addEventListener("visibilitychange", () => {
            if (document.visibilityState === "visible") {
              console.log("[System] Página voltou ao foco");
              setTimeout(() => location.reload(), 2000);
            }
          });
          
          updateStatus("Sistema pronto", "status");
        }
        
        // Cleanup ao sair
        window.addEventListener("beforeunload", () => {
          if (heartbeatInterval) clearInterval(heartbeatInterval);
          if (reloadTimeout) clearTimeout(reloadTimeout);
        });
        
        // Inicializar quando DOM estiver pronto
        if (document.readyState === "loading") {
          document.addEventListener("DOMContentLoaded", init);
        } else {
          init();
        }
        
        // Log de informações do sistema
        console.log("[Tritotem] Player v2.0 iniciado");
        console.log("[Device]", "${device.name}", "(${deviceToken})");
        console.log("[Playlist]", "${playlistName}", "(${playlist.length} mídias)");
        console.log("[Config]", config);
      </script>
    </body>
    </html>`;
    
    res.send(html);
  } catch (error) {
    console.error("Erro no player:", error);
    res.status(500).send(`
      <!DOCTYPE html>
      <html lang="pt-BR">
      <head>
        <meta charset="UTF-8">
        <title>Erro - Tritotem Player</title>
        <style>
          body { margin: 0; padding: 50px; background: #000; color: #fff; 
                 text-align: center; font-family: Arial; }
          h1 { color: #f44336; }
        </style>
      </head>
      <body>
        <h1>❌ Erro interno do servidor</h1>
        <p>Não foi possível carregar o player.</p>
        <p>Tente novamente em alguns instantes.</p>
      </body>
      </html>
    `);
  }
});

// API para obter dados da playlist do dispositivo (para apps externos)
app.get("/api/player/:deviceToken", async (req, res) => {
  try {
    const { deviceToken } = req.params;

    const device = await Device.findOne({
      deviceToken,
      isActive: true,
    }).populate({
      path: "assignedPlaylistId",
      populate: {
        path: "media.mediaId",
        match: { isActive: true },
      },
    });

    if (!device) {
      return res.status(404).json({ error: "Dispositivo não encontrado" });
    }

    // Atualizar último acesso
    await Device.findByIdAndUpdate(device._id, {
      lastSeenAt: new Date(),
      status: "online",
    });

    const baseUrl = process.env.NODE_ENV === "production"
      ? (process.env.BASE_URL || "https://tritotem-cc0a461d6f3e.herokuapp.com" )
      : "http://localhost:3001";

    const playlist = device.assignedPlaylistId?.media?.filter((item ) => item.mediaId) || [];

    // Preparar URLs das mídias
    const mediaWithUrls = playlist.map((item) => ({
      id: item.mediaId._id,
      name: item.mediaId.name,
      filename: item.mediaId.filename,
      url: `${baseUrl}/stream/${item.mediaId.filename}`,
      mimetype: item.mediaId.mimetype,
      size: item.mediaId.size,
      duration: item.duration || item.mediaId.duration || 0,
      order: item.order || 0,
    }));

    res.json({
      device: {
        id: device._id,
        name: device.name,
        location: device.location,
        resolution: device.resolution,
        status: device.status,
        lastSeenAt: device.lastSeenAt,
      },
      playlist: {
        id: device.assignedPlaylistId?._id,
        name: device.assignedPlaylistId?.name,
        description: device.assignedPlaylistId?.description,
        media: mediaWithUrls,
        totalDuration: device.assignedPlaylistId?.totalDuration,
      },
    });
  } catch (error) {
    console.error("Erro ao obter dados do player:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// ROTAS DO DASHBOARD
app.get("/api/dashboard/stats", authenticateToken, async (req, res) => {
  try {
    const totalDevices = await Device.countDocuments({ isActive: true });
    const onlineDevices = await Device.countDocuments({
      isActive: true,
      status: "online",
    });
    const totalMedia = await Media.countDocuments({ isActive: true });
    const totalPlaylists = await Playlist.countDocuments({ isActive: true });

    // Calcular armazenamento total e média por mídia
    const allMedia = await Media.find({ isActive: true });
    const totalStorageBytes = allMedia.reduce((sum, media) => sum + media.size, 0);
    const totalStorageMB = (totalStorageBytes / (1024 * 1024)).toFixed(2);
    const avgMediaSizeMB = totalMedia > 0
      ? (totalStorageBytes / totalMedia / (1024 * 1024)).toFixed(2)
      : 0;

    // Mídias por playlist (média)
    const playlistsWithMedia = await Playlist.find({ isActive: true }).populate("media.mediaId");
    let totalMediaInPlaylists = 0;
    playlistsWithMedia.forEach(p => {
      totalMediaInPlaylists += p.media.filter(item => item.mediaId).length;
    });
    const avgMediaPerPlaylist = totalPlaylists > 0
      ? (totalMediaInPlaylists / totalPlaylists).toFixed(2)
      : 0;

    // Status dos dispositivos (últimos 3)
    const latestDevices = await Device.find({ isActive: true })
      .sort({ lastSeenAt: -1 })
      .limit(3)
      .select("name location status lastSeenAt");

    res.json({
      totalDevices,
      onlineDevices,
      offlineDevices: totalDevices - onlineDevices,
      totalMedia,
      totalPlaylists,
      totalStorageMB,
      avgMediaSizeMB,
      avgMediaPerPlaylist,
      latestDevices,
    });
  } catch (error) {
    console.error("Erro ao obter estatísticas do dashboard:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Middleware de tratamento de erros
app.use((err, req, res, next) => {
  console.error("🚨 Erro inesperado:", err.stack);
  res.status(500).json({ error: "Erro interno do servidor" });
});

// Iniciar o servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Servidor Tritotem v2.0 rodando na porta ${PORT}`);
  console.log(`🌐 Ambiente: ${process.env.NODE_ENV || "development"}`);
  console.log(`📁 Uploads: ${uploadsDir}`);
  console.log("✅ Sistema pronto para receber conexões!");
});
