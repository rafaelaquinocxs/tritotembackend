const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const Media = require('../models/Media');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

// ✅ Pasta de uploads compatível com Heroku e local
const uploadDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// 🎥 Configuração do Multer para salvar vídeos
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '');
    const base = path.basename(file.originalname || 'arquivo', ext);
    cb(null, `${uuidv4()}-${base}${ext}`);
  }
});

const upload = multer({
  storage,
  fileFilter: (_req, file, cb) => {
    if (file.mimetype && file.mimetype.startsWith('video/')) return cb(null, true);
    return cb(new Error('Apenas arquivos de vídeo são permitidos'), false);
  },
  limits: { fileSize: 500 * 1024 * 1024 } // 500MB
});

// 📦 GET /api/media - lista de mídias
router.get('/', authenticate, async (_req, res) => {
  try {
    const medias = await Media.find().sort({ createdAt: -1 });
    res.json(medias);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ⬆️ POST /api/media - upload de vídeo
router.post(
  '/',
  authenticate,
  upload.fields([{ name: 'media', maxCount: 1 }, { name: 'video', maxCount: 1 }]),
  async (req, res) => {
    try {
      const file =
        (req.files?.media && req.files.media[0]) ||
        (req.files?.video && req.files.video[0]);

      if (!file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });

      const { name } = req.body;

      // Salva URL apontando para a rota de STREAM
      const url = `/stream/${file.filename}`;

      const media = new Media({
        name: name || file.originalname,
        filename: file.filename,
        url,
        fileSize: file.size,
        mimeType: file.mimetype
      });

      await media.save();
      return res.status(201).json(media);
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  }
);

// 🔍 GET /api/media/:id - detalhe
router.get('/:id', authenticate, async (req, res) => {
  try {
    const media = await Media.findById(req.params.id);
    if (!media) return res.status(404).json({ error: 'Mídia não encontrada' });
    res.json(media);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ❌ DELETE /api/media/:id
router.delete('/:id', authenticate, async (req, res) => {
  try {
    const media = await Media.findById(req.params.id);
    if (!media) return res.status(404).json({ error: 'Mídia não encontrada' });

    const filePath = path.join(uploadDir, media.filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    await Media.findByIdAndDelete(req.params.id);
    res.json({ message: 'Mídia excluída com sucesso' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ⚠️ Tratador de erros do Multer
router.use((err, _req, res, next) => {
  if (err && (err.name === 'MulterError' || /Apenas arquivos de vídeo/.test(err.message))) {
    return res.status(400).json({ error: err.message });
  }
  return next(err);
});

module.exports = router;
