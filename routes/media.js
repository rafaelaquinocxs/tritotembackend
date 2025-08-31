const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const Media = require('../models/Media');

const router = express.Router();

// Configuração do multer para upload de arquivos
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, '../../uploads');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}-${file.originalname}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('video/')) {
      cb(null, true);
    } else {
      cb(new Error('Apenas arquivos de vídeo são permitidos'), false);
    }
  },
  limits: {
    fileSize: 500 * 1024 * 1024 // 500MB
  }
});

// GET /api/media - Listar todas as mídias
router.get('/', async (req, res) => {
  try {
    const medias = await Media.find().sort({ createdAt: -1 });
    res.json(medias);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/media - Upload de nova mídia
router.post('/', upload.single('video'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Nenhum arquivo enviado' });
    }

    const { name } = req.body;
    const url = `/uploads/${req.file.filename}`;

    const media = new Media({
      name: name || req.file.originalname,
      filename: req.file.filename,
      url: url,
      fileSize: req.file.size,
      mimeType: req.file.mimetype
    });

    await media.save();
    res.status(201).json(media);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/media/:id - Obter mídia específica
router.get('/:id', async (req, res) => {
  try {
    const media = await Media.findById(req.params.id);
    if (!media) {
      return res.status(404).json({ error: 'Mídia não encontrada' });
    }
    res.json(media);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/media/:id - Excluir mídia
router.delete('/:id', async (req, res) => {
  try {
    const media = await Media.findById(req.params.id);
    if (!media) {
      return res.status(404).json({ error: 'Mídia não encontrada' });
    }

    // Remover arquivo físico
    const filePath = path.join(__dirname, '../../uploads', media.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    await Media.findByIdAndDelete(req.params.id);
    res.json({ message: 'Mídia excluída com sucesso' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;

