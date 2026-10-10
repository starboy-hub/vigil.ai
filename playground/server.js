/**
 * VIGIL AI Public Cyber Range Playground Server
 * Serves playground/index.html locally on port 4006.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 4006;
const HTML = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  if (req.url === '/api/chat' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ response: 'Assistant received: ' + body.slice(0, 60) }));
    });
    return;
  }

  const currentHtml = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(currentHtml);
});

function startPlayground(port = PORT) {
  return new Promise((resolve, reject) => {
    server.once('error', err => {
      if (err.code === 'EADDRINUSE') {
        resolve(server);
      } else {
        reject(err);
      }
    });
    server.listen(port, '127.0.0.1', () => {
      resolve(server);
    });
  });
}

function stopPlayground() {
  return new Promise(resolve => {
    if (server.listening) {
      server.close(resolve);
    } else {
      resolve();
    }
  });
}

if (require.main === module) {
  startPlayground().then(() => {
    console.log(`🚀 VIGIL Cyber Range Playground live at: http://127.0.0.1:${PORT}`);
  });
}

module.exports = { startPlayground, stopPlayground, PORT };

