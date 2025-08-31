// backend/routes/player.js
const express = require('express');
const Device = require('../models/Device');
const Playlist = require('../models/Playlist');
const Media = require('../models/Media');

const router = express.Router();

// GET /player/:deviceToken → HTML dinâmico com playlist do totem
router.get('/:deviceToken', async (req, res) => {
  try {
    const { deviceToken } = req.params;
    let urls = [];

    // Tenta achar o dispositivo e a playlist atribuída
    const device = await Device.findOne({ deviceToken })
      .populate({
        path: 'assignedPlaylistId',
        populate: { path: 'items.mediaId' }
      });

    if (device?.assignedPlaylistId?.items?.length) {
      urls = device.assignedPlaylistId.items
        .sort((a, b) => a.order - b.order)
        .map(it => it.mediaId && it.mediaId.url)
        .filter(Boolean);
    }

    // Fallback: se não houver playlist atribuída, toca TODAS as mídias em ordem de upload
    if (!urls.length) {
      const all = await Media.find().sort({ createdAt: 1 });
      urls = all.map(m => m.url);
    }

    const html = `<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8" />
  <title>Tritotem Player</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>
    html,body{margin:0;height:100%;background:#000}
    .wrap{display:flex;align-items:center;justify-content:center;height:100%}
    video{width:100%;height:100%;object-fit:contain;background:#000}
    .msg{color:#fff;font:16px/1.4 system-ui,sans-serif;text-align:center;padding:24px}
  </style>
</head>
<body>
  <div class="wrap">
    ${urls.length ? `<video id="v" autoplay controls playsinline></video>` :
      `<div class="msg">Nenhuma mídia encontrada para este totem.</div>`}
  </div>
  <script>
    const playlist = ${JSON.stringify(urls)};
    if (playlist.length) {
      const v = document.getElementById('v');
      let i = 0;

      function play(idx){
        i = (idx + playlist.length) % playlist.length;
        v.src = playlist[i];
        v.load();
        v.play().catch(()=>{/* autoplay blockado */});
      }
      v.addEventListener('ended', ()=> play(i+1));
      v.addEventListener('error', ()=> play(i+1)); // se der erro, pula pro próximo
      play(0);

      // Opcional: atualizar a playlist a cada 60s sem recarregar a página
      // fetch(window.location.href + '?json=1') → você pode criar um endpoint JSON depois
    }
  </script>
</body>
</html>`;
    res.set('Content-Type', 'text/html; charset=utf-8').send(html);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
