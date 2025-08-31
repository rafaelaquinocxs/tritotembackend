const mongoose = require('mongoose');

const mediaSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  filename: {
    type: String,
    required: true
  },
  url: {
    type: String,
    required: true
  },
  durationSec: {
    type: Number,
    default: 0
  },
  fileSize: {
    type: Number,
    default: 0
  },
  mimeType: {
    type: String,
    default: 'video/mp4'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Media', mediaSchema);

