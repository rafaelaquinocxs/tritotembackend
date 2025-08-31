const express = require('express');
const path = require('path');

const router = express.Router();

// Servir o player para um dispositivo específico
router.get('/:deviceToken', (req, res) => {
  const playerPath = path.join(__dirname, '../../player/index.html');
  res.sendFile(playerPath);
});

module.exports = router;

