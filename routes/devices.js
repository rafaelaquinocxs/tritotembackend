const express = require('express');
const { v4: uuidv4 } = require('uuid');
const Device = require('../models/Device');
const Playlist = require('../models/Playlist');

const router = express.Router();

// GET /api/devices - Listar todos os dispositivos
router.get('/', async (req, res) => {
  try {
    const devices = await Device.find()
      .populate('assignedPlaylistId')
      .sort({ createdAt: -1 });
    
    // Atualizar status online/offline baseado no heartbeat
    const updatedDevices = devices.map(device => {
      const isOnline = device.isOnline();
      if (device.status !== (isOnline ? 'online' : 'offline')) {
        device.status = isOnline ? 'online' : 'offline';
        device.save();
      }
      return device;
    });

    res.json(updatedDevices);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/devices - Criar novo dispositivo
router.post('/', async (req, res) => {
  try {
    const { name } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Nome do dispositivo é obrigatório' });
    }

    const deviceToken = uuidv4();
    
    const device = new Device({
      name,
      deviceToken
    });

    await device.save();
    res.status(201).json(device);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/devices/:id - Obter dispositivo específico
router.get('/:id', async (req, res) => {
  try {
    const device = await Device.findById(req.params.id)
      .populate('assignedPlaylistId');
    
    if (!device) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }
    
    res.json(device);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/devices/:id - Atualizar dispositivo
router.put('/:id', async (req, res) => {
  try {
    const { name, assignedPlaylistId } = req.body;

    const device = await Device.findByIdAndUpdate(
      req.params.id,
      { name, assignedPlaylistId },
      { new: true }
    ).populate('assignedPlaylistId');

    if (!device) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }

    // Emitir evento de atualização para o dispositivo específico
    if (req.io) {
      req.io.emit('device_updated', { deviceId: device._id, deviceToken: device.deviceToken });
    }

    res.json(device);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE /api/devices/:id - Excluir dispositivo
router.delete('/:id', async (req, res) => {
  try {
    const device = await Device.findByIdAndDelete(req.params.id);
    
    if (!device) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }

    res.json({ message: 'Dispositivo excluído com sucesso' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/devices/broadcast-assign - Atribuir playlist a todos os dispositivos
router.post('/broadcast-assign', async (req, res) => {
  try {
    const { playlistId } = req.body;
    
    if (!playlistId) {
      return res.status(400).json({ error: 'ID da playlist é obrigatório' });
    }

    // Verificar se a playlist existe
    const playlist = await Playlist.findById(playlistId);
    if (!playlist) {
      return res.status(404).json({ error: 'Playlist não encontrada' });
    }

    // Atualizar todos os dispositivos
    await Device.updateMany({}, { assignedPlaylistId: playlistId });

    // Emitir evento de atualização para todos os dispositivos
    if (req.io) {
      req.io.emit('broadcast_update', { playlistId });
    }

    res.json({ message: 'Playlist atribuída a todos os dispositivos com sucesso' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/devices/:deviceToken/playlist - Obter playlist do dispositivo (para o player)
router.get('/:deviceToken/playlist', async (req, res) => {
  try {
    const device = await Device.findOne({ deviceToken: req.params.deviceToken })
      .populate({
        path: 'assignedPlaylistId',
        populate: {
          path: 'items.mediaId'
        }
      });

    if (!device) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }

    // Se não há playlist atribuída, verificar se há playlist global
    let playlist = device.assignedPlaylistId;
    if (!playlist) {
      playlist = await Playlist.findOne({ isGlobal: true })
        .populate('items.mediaId');
    }

    if (!playlist || !playlist.items.length) {
      return res.json({ items: [] });
    }

    // Ordenar itens da playlist
    const sortedItems = playlist.items
      .sort((a, b) => a.order - b.order)
      .map(item => ({
        id: item._id,
        mediaId: item.mediaId._id,
        name: item.mediaId.name,
        url: `${req.protocol}://${req.get('host')}${item.mediaId.url}`,
        duration: item.mediaId.durationSec,
        order: item.order
      }));

    res.json({
      playlistId: playlist._id,
      playlistName: playlist.name,
      items: sortedItems,
      timestamp: Date.now()
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/devices/:deviceToken/heartbeat - Receber heartbeat do dispositivo
router.post('/:deviceToken/heartbeat', async (req, res) => {
  try {
    const device = await Device.findOne({ deviceToken: req.params.deviceToken });
    
    if (!device) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }

    device.lastSeenAt = new Date();
    device.status = 'online';
    await device.save();

    res.json({ message: 'Heartbeat recebido', timestamp: Date.now() });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;

