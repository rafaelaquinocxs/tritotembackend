const express = require('express');
const router = express.Router();
const Device = require('../models/Device');

// ✅ Rota do player para o totem - SINTAXE CORRIGIDA
router.get('/:deviceToken', async (req, res) => {
  try {
    const deviceToken = req.params.deviceToken;
    
    if (!deviceToken) {
      return res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <title>Tritotem Player - Token inválido</title>
          <style>
            body { 
              margin: 0; 
              padding: 50px; 
              background: #000; 
              color: #fff; 
              text-align: center; 
              font-family: Arial, sans-serif;
            }
            h1 { color: #ff6b6b; }
          </style>
        </head>
        <body>
          <h1>❌ Token inválido</h1>
          <p>Token do dispositivo não fornecido.</p>
        </body>
        </html>
      `);
    }
    
    const device = await Device.findOne({ deviceToken }).populate('assignedPlaylistId');
    
    if (!device) {
      return res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <title>Tritotem Player - Dispositivo não encontrado</title>
          <style>
            body { 
              margin: 0; 
              padding: 50px; 
              background: #000; 
              color: #fff; 
              text-align: center; 
              font-family: Arial, sans-serif;
            }
            h1 { color: #ff6b6b; }
            .token { 
              background: #333; 
              padding: 10px; 
              border-radius: 5px; 
              font-family: monospace; 
              margin: 20px 0;
            }
          </style>
        </head>
        <body>
          <h1>❌ Dispositivo não encontrado</h1>
          <p>O token fornecido não corresponde a nenhum dispositivo cadastrado.</p>
          <div class="token">Token: ${deviceToken}</div>
          <p>Verifique se o dispositivo foi cadastrado no sistema.</p>
        </body>
        </html>
      `);
    }

    // Atualizar último acesso
    await Device.findByIdAndUpdate(device._id, { 
      lastSeenAt: new Date(),
      status: 'online'
    });

    // ✅ HTML do player
    const baseUrl = process.env.NODE_ENV === 'production' 
      ? 'https://tritotem-cc0a461d6f3e.herokuapp.com' 
      : 'http://localhost:3001';

    const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Tritotem Player - ${device.name}</title>
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
          background: #000; 
          overflow: hidden; 
          font-family: Arial, sans-serif;
        }
        video { 
          width: 100vw; 
          height: 100vh; 
          object-fit: cover; 
          display: block;
        }
        .info { 
          position: fixed; 
          top: 10px; 
          left: 10px; 
          color: white; 
          background: rgba(0,0,0,0.7);
          padding: 10px;
          border-radius: 5px;
          font-size: 14px;
          z-index: 1000;
        }
        .loading {
          position: fixed;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          color: white;
          text-align: center;
          z-index: 1000;
        }
        .spinner {
          border: 4px solid #333;
          border-top: 4px solid #fff;
          border-radius: 50%;
          width: 40px;
          height: 40px;
          animation: spin 1s linear infinite;
          margin: 0 auto 20px;
        }
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        .error {
          position: fixed;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          color: #ff6b6b;
          text-align: center;
          z-index: 1000;
        }
      </style>
    </head>
    <body>
      <div class="info">
        <div><strong>Dispositivo:</strong> ${device.name}</div>
        <div><strong>Status:</strong> <span id="status">Carregando...</span></div>
        <div><strong>Mídia:</strong> <span id="currentMedia">-</span></div>
      </div>
      
      <div id="loading" class="loading">
        <div class="spinner"></div>
        <div>Carregando playlist...</div>
      </div>
      
      <div id="error" class="error" style="display: none;">
        <h2>❌ Erro</h2>
        <p id="errorMessage">Erro desconhecido</p>
        <p><small>Tentando novamente em <span id="countdown">10</span> segundos...</small></p>
      </div>
      
      <video id="player" autoplay muted loop style="display: none;">
        Seu navegador não suporta vídeo HTML5.
      </video>
      
      <script>
        const player = document.getElementById('player');
        const status = document.getElementById('status');
        const currentMedia = document.getElementById('currentMedia');
        const loading = document.getElementById('loading');
        const error = document.getElementById('error');
        const errorMessage = document.getElementById('errorMessage');
        const countdown = document.getElementById('countdown');
        
        // ✅ Lista de vídeos da playlist
        const playlist = ${JSON.stringify(device.assignedPlaylistId?.media || [])};
        let currentIndex = 0;
        let retryCount = 0;
        const maxRetries = 3;
        
        function hideLoading() {
          loading.style.display = 'none';
          player.style.display = 'block';
        }
        
        function showError(message) {
          error.style.display = 'block';
          errorMessage.textContent = message;
          player.style.display = 'none';
          loading.style.display = 'none';
          
          let count = 10;
          countdown.textContent = count;
          
          const timer = setInterval(() => {
            count--;
            countdown.textContent = count;
            if (count <= 0) {
              clearInterval(timer);
              error.style.display = 'none';
              playNext();
            }
          }, 1000);
        }
        
        function playNext() {
          if (playlist.length === 0) {
            status.textContent = 'Offline';
            currentMedia.textContent = 'Nenhuma mídia na playlist';
            showError('Nenhuma mídia encontrada na playlist');
            return;
          }
          
          const media = playlist[currentIndex];
          const videoUrl = '${baseUrl}/stream/' + media.filename;
          
          status.textContent = 'Carregando...';
          currentMedia.textContent = media.name;
          
          player.src = videoUrl;
          player.load();
          
          currentIndex = (currentIndex + 1) % playlist.length;
        }
        
        player.addEventListener('loadstart', () => {
          status.textContent = 'Carregando vídeo...';
        });
        
        player.addEventListener('canplay', () => {
          hideLoading();
          status.textContent = 'Reproduzindo';
          retryCount = 0;
        });
        
        player.addEventListener('ended', () => {
          status.textContent = 'Próximo vídeo...';
          setTimeout(playNext, 1000);
        });
        
        player.addEventListener('error', (e) => {
          console.error('Erro no player:', e);
          retryCount++;
          
          if (retryCount <= maxRetries) {
            status.textContent = \`Erro - Tentativa \${retryCount}/\${maxRetries}\`;
            showError(\`Erro ao carregar vídeo. Tentativa \${retryCount} de \${maxRetries}\`);
          } else {
            status.textContent = 'Erro crítico';
            showError('Falha crítica no carregamento. Verifique a conexão.');
            retryCount = 0;
          }
        });
        
        // ✅ Heartbeat para marcar como online
        function sendHeartbeat() {
          fetch('${baseUrl}/api/devices/${device._id}/heartbeat', { 
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            }
          }).catch(err => {
            console.error('Erro no heartbeat:', err);
          });
        }
        
        // ✅ Iniciar reprodução
        setTimeout(() => {
          playNext();
        }, 2000);
        
        // ✅ Heartbeat a cada 30 segundos
        setInterval(sendHeartbeat, 30000);
        
        // ✅ Heartbeat inicial
        sendHeartbeat();
        
        // ✅ Recarregar página a cada 6 horas para evitar memory leaks
        setTimeout(() => {
          window.location.reload();
        }, 6 * 60 * 60 * 1000);
        
        // ✅ Detectar se saiu de foco e voltar ao foco
        window.addEventListener('blur', () => {
          setTimeout(() => window.focus(), 1000);
        });
        
        // ✅ Prevenir context menu
        document.addEventListener('contextmenu', e => e.preventDefault());
        
        // ✅ Prevenir teclas de desenvolvedor
        document.addEventListener('keydown', (e) => {
          if (e.key === 'F12' || 
              (e.ctrlKey && e.shiftKey && e.key === 'I') ||
              (e.ctrlKey && e.shiftKey && e.key === 'C') ||
              (e.ctrlKey && e.key === 'u')) {
            e.preventDefault();
          }
        });
      </script>
    </body>
    </html>`;
    
    res.send(html);
  } catch (error) {
    console.error('Erro no player:', error);
    res.status(500).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Erro - Tritotem Player</title>
        <style>
          body { 
            margin: 0; 
            padding: 50px; 
            background: #000; 
            color: #fff; 
            text-align: center; 
            font-family: Arial, sans-serif;
          }
          h1 { color: #ff6b6b; }
        </style>
      </head>
      <body>
        <h1>❌ Erro interno do servidor</h1>
        <p>Ocorreu um erro ao carregar o player.</p>
        <p><small>Erro: ${error.message}</small></p>
      </body>
      </html>
    `);
  }
});

module.exports = router;