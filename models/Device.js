const mongoose = require('mongoose');

const deviceSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  deviceToken: {
    type: String,
    required: true,
    unique: true
  },
  assignedPlaylistId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Playlist',
    default: null
  },
  lastSeenAt: {
    type: Date,
    default: Date.now
  },
  status: {
    type: String,
    enum: ['online', 'offline'],
    default: 'offline'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Método para verificar se o dispositivo está online (heartbeat nos últimos 2 minutos)
deviceSchema.methods.isOnline = function() {
  const twoMinutesAgo = new Date(Date.now() - 2 * 60 * 1000);
  return this.lastSeenAt > twoMinutesAgo;
};

module.exports = mongoose.model('Device', deviceSchema);

