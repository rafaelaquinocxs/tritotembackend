const express = require('express');
const Playlist = require('../models/Playlist');
const Media = require('../models/Media');

const router = express.Router();

// GET /api/playlists - Listar todas as playlists
router.get('/', async (req, res) => {
  try {
    const playlists = await Playlist.find()
      .populate('items.mediaId')
      .sort({ createdAt: -1 });
    res.json(playlists);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/playlists - Criar nova playlist
router.post('/', async (req, res) => {
  try {
    const { name, items, isGlobal } = req.body;

    const playlist = new Playlist({
      name,
      items: items || [],
      isGlobal: isGlobal || false
    });

    await playlist.save();
    await playlist.populate('items.mediaId');
    
    res.status(201).json(playlist);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/playlists/:id - Obter playlist específica
router.get('/:id', async (req, res) => {
  try {
    const playlist = await Playlist.findById(req.params.id)
      .populate('items.mediaId');
    
    if (!playlist) {
      return res.status(404).json({ error: 'Playlist não encontrada' });
    }
    
    res.json(playlist);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/playlists/:id - Atualizar playlist
router.put('/:id', async (req, res) => {
  try {
    const { name, items, isGlobal } = req.body;

    const playlist = await Playlist.findByIdAndUpdate(
      req.params.id,
      { name, items, isGlobal },
      { new: true }
    ).populate('items.mediaId');

    if (!playlist) {
      return res.status(404).json({ error: 'Playlist não encontrada' });
    }

    // Emitir evento de atualização via Socket.IO
    if (req.io) {
      req.io.emit('playlist_updated', { playlistId: playlist._id });
    }

    res.json(playlist);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/playlists/:id - Excluir playlist
router.delete('/:id', async (req, res) => {
  try {
    const playlist = await Playlist.findByIdAndDelete(req.params.id);
    
    if (!playlist) {
      return res.status(404).json({ error: 'Playlist não encontrada' });
    }

    res.json({ message: 'Playlist excluída com sucesso' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/playlists/:id/items - Adicionar mídia à playlist
router.post('/:id/items', async (req, res) => {
  try {
    const { mediaId, order } = req.body;
    
    const playlist = await Playlist.findById(req.params.id);
    if (!playlist) {
      return res.status(404).json({ error: 'Playlist não encontrada' });
    }

    // Verificar se a mídia existe
    const media = await Media.findById(mediaId);
    if (!media) {
      return res.status(404).json({ error: 'Mídia não encontrada' });
    }

    // Adicionar item à playlist
    playlist.items.push({ mediaId, order: order || playlist.items.length });
    await playlist.save();
    await playlist.populate('items.mediaId');

    // Emitir evento de atualização
    if (req.io) {
      req.io.emit('playlist_updated', { playlistId: playlist._id });
    }

    res.json(playlist);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/playlists/:id/items/:itemId - Remover mídia da playlist
router.delete('/:id/items/:itemId', async (req, res) => {
  try {
    const playlist = await Playlist.findById(req.params.id);
    if (!playlist) {
      return res.status(404).json({ error: 'Playlist não encontrada' });
    }

    playlist.items = playlist.items.filter(item => item._id.toString() !== req.params.itemId);
    await playlist.save();
    await playlist.populate('items.mediaId');

    // Emitir evento de atualização
    if (req.io) {
      req.io.emit('playlist_updated', { playlistId: playlist._id });
    }

    res.json(playlist);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;

