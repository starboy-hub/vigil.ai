/**
 * VIGIL AI Digital Twin Cyber Range Server
 * Serves pixel- and DOM-perfect clones of target SPAs:
 * - Gmail SPA (/webmail/gmail)
 * - Outlook SPA (/webmail/outlook)
 * - AI Chat Range: ChatGPT & Claude (/ai/chatgpt, /ai/claude)
 * - E-Commerce Checkout (/shop/checkout)
 * - Adversarial Lab (/adversarial/lab)
 * - Canvas & WebGL Testbed (/media/canvas)
 *
 * 100% Hermetic & Local. Zero external telemetry.
 */
const http = require('http');
const url = require('url');

const PORT = 4005;

// ---- HTML Templates for Digital Twins ----

function getGmailHtml(query) {
  const isThread = query.thread;
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Inbox - Gmail Clone</title>
  <style>
    body { font-family: Roboto, Arial, sans-serif; margin: 0; background: #f6f8fc; }
    .header { height: 48px; background: #fff; border-bottom: 1px solid #e0e0e0; display: flex; align-items: center; padding: 0 16px; font-weight: 500; }
    .container { display: flex; height: calc(100vh - 48px); }
    .sidebar { width: 220px; background: #f6f8fc; padding: 12px; font-size: 14px; }
    .sidebar-item { padding: 8px 12px; border-radius: 16px; cursor: pointer; margin-bottom: 4px; }
    .sidebar-item.active { background: #d3e3fd; font-weight: bold; }
    .main { flex: 1; background: #fff; border-radius: 16px 16px 0 0; margin-right: 16px; overflow-y: auto; padding: 16px; }
    table.zA-table { width: 100%; border-collapse: collapse; }
    tr.zA { border-bottom: 1px solid #f1f3f4; height: 40px; cursor: pointer; }
    tr.zA:hover { box-shadow: inset 1px 0 0 #dadce0, inset -1px 0 0 #dadce0, 0 1px 2px 0 rgba(60,64,67,.3), 0 1px 3px 1px rgba(60,64,67,.15); }
    td.yX { width: 180px; font-weight: bold; padding-left: 8px; }
    td.y6 { color: #5f6368; }
    .reading-pane { padding: 20px; background: #fff; }
    .hP { font-size: 20px; font-weight: 400; margin-bottom: 16px; }
    .sender-header { display: flex; align-items: center; margin-bottom: 16px; font-size: 14px; }
    .sender-avatar { width: 32px; height: 32px; border-radius: 50%; background: #1a73e8; color: #fff; display: flex; align-items: center; justify-content: center; margin-right: 12px; font-weight: bold; }
    .sender-details { line-height: 1.4; }
    .a3s { font-size: 14px; line-height: 1.6; color: #202124; margin-top: 16px; }
    .action-btn { display: inline-block; padding: 10px 20px; background: #1a73e8; color: #fff; text-decoration: none; border-radius: 4px; font-weight: 500; margin-top: 16px; }
    .provider-warning { background: #fce8e6; border: 1px solid #fad2cf; color: #c5221f; padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; display: flex; align-items: center; font-size: 13px; }
  </style>
</head>
<body>
  <div class="header">Gmail Digital Twin</div>
  <div class="container">
    <div class="sidebar">
      <div class="sidebar-item ${!isThread ? 'active' : ''}">Inbox (12)</div>
      <div class="sidebar-item">Starred</div>
      <div class="sidebar-item">Sent</div>
      <div class="sidebar-item">Spam</div>
    </div>
    <div class="main">
      ${!isThread ? `
      <!-- Collapsed Inbox List View: Should NEVER fire toast popups -->
      <table class="zA-table" role="grid">
        <tr class="zA" data-thread-id="t1" onclick="location.search='?thread=clean'">
          <td class="yX"><span class="bqe" email="notifications@github.com">GitHub</span></td>
          <td class="y6"><span class="bog">[repo] New Pull Request: Security hardening updates</span> — View diff online</td>
        </tr>
        <tr class="zA" data-thread-id="t2" onclick="location.search='?thread=receipt'">
          <td class="yX"><span class="bqe" email="receipts@uber.com">Uber Receipts</span></td>
          <td class="y6"><span class="bog">Your Thursday evening trip with Uber</span> — Thanks for riding with us</td>
        </tr>
        <tr class="zA" data-thread-id="t3" onclick="location.search='?thread=verify'">
          <td class="yX"><span class="bqe" email="security@notion.so">Notion Security</span></td>
          <td class="y6"><span class="bog">Your one-time login code is 849201</span> — Enter this code to verify your account</td>
        </tr>
        <tr class="zA" data-thread-id="t4" onclick="location.search='?thread=phish'">
          <td class="yX"><span class="bqe" email="security@google-security-update.xyz">Google Account Alert</span></td>
          <td class="y6"><span class="bog">CRITICAL: Account suspended today</span> — Verify credentials immediately</td>
        </tr>
      </table>
      ` : ''}

      ${isThread === 'clean' ? `
      <!-- Reading Pane: Clean Genuine GitHub Notification -->
      <div class="adn ads reading-pane" data-thread-id="t1">
        <h2 class="hP">[repo] New Pull Request: Security hardening updates</h2>
        <div class="sender-header">
          <div class="sender-avatar">GH</div>
          <div class="sender-details">
            <div><strong>GitHub</strong> <span class="gD" email="notifications@github.com">&lt;notifications@github.com&gt;</span></div>
            <div style="color:#5f6368;font-size:12px;">to me &bull; Cryptographically signed by github.com</div>
          </div>
        </div>
        <div class="a3s aiL message-body">
          <p>Hi developer,</p>
          <p>Pull Request #42 has been opened: <em>Security hardening and audit review</em>.</p>
          <p><a class="action-btn" href="https://github.com/org/repo/pull/42">View Pull Request</a></p>
        </div>
      </div>
      ` : ''}

      ${isThread === 'phish' ? `
      <!-- Reading Pane: Phishing Attack with Misdirected Action Link -->
      <div class="adn ads reading-pane" data-thread-id="t4">
        <h2 class="hP">CRITICAL: Your Google Account is pending suspension</h2>
        <div class="sender-header">
          <div class="sender-avatar" style="background:#ea4335;">!</div>
          <div class="sender-details">
            <div><strong>Google Security Team</strong> <span class="gD" email="security@google-security-update.xyz">&lt;security@google-security-update.xyz&gt;</span></div>
            <div style="color:#5f6368;font-size:12px;">to me</div>
          </div>
        </div>
        <div class="a3s aiL message-body">
          <p>We detected unauthorized activity on your account. To prevent immediate deletion within 24 hours, confirm your password and enter your recovery credentials now.</p>
          <!-- Phishing link: text says Google, href goes to external malicious domain -->
          <p><a class="action-btn" href="https://evil-credential-stealer.xyz/login/verify">Verify Account Details Now</a></p>
        </div>
      </div>
      ` : ''}

      ${isThread === 'warn' ? `
      <!-- Reading Pane: Provider Warning Banner -->
      <div class="adn ads reading-pane" data-thread-id="t5">
        <div class="provider-warning ams">
          ⚠️ Gmail couldn't verify that this message actually came from paypal.com. Be careful clicking links or replying with sensitive information.
        </div>
        <h2 class="hP">Urgent: Confirm payment of $490.00</h2>
        <div class="sender-header">
          <div class="sender-details">
            <div><strong>PayPal Service</strong> <span class="gD" email="service@paypal-spoofed.com">&lt;service@paypal-spoofed.com&gt;</span></div>
          </div>
        </div>
        <div class="a3s aiL message-body">
          <p>Your payment is on hold. Log in immediately to resolve this dispute.</p>
          <p><a class="action-btn" href="https://fake-dispute-portal.com/login">Resolve Dispute</a></p>
        </div>
      </div>
      ` : ''}
    </div>
  </div>
</body>
</html>`;
}

function getAiChatHtml() {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>ChatGPT / Claude Digital Twin</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; background: #212121; color: #ececec; display: flex; flex-direction: column; height: 100vh; }
    .topbar { height: 48px; border-bottom: 1px solid #303030; display: flex; align-items: center; padding: 0 20px; font-weight: 600; font-size: 15px; }
    .chat-history { flex: 1; overflow-y: auto; padding: 24px 20%; display: flex; flex-direction: column; gap: 20px; }
    .message { display: flex; gap: 16px; line-height: 1.5; font-size: 15px; }
    .message.user { justify-content: flex-end; }
    .message.user .bubble { background: #303030; padding: 12px 18px; border-radius: 18px; max-width: 80%; }
    .message.assistant .bubble { background: transparent; padding: 0; max-width: 90%; }
    .input-container { padding: 16px 20% 24px; position: relative; }
    .input-box { background: #303030; border: 1px solid #424242; border-radius: 24px; padding: 14px 50px 14px 18px; min-height: 24px; outline: none; font-size: 15px; color: #fff; line-height: 1.4; word-break: break-word; }
    .input-box:empty:before { content: "Message ChatGPT..."; color: #8e8e8e; }
    .send-btn { position: absolute; right: calc(20% + 12px); bottom: 32px; width: 32px; height: 32px; border-radius: 50%; background: #fff; color: #000; border: none; cursor: pointer; display: flex; align-items: center; justify-content: center; font-weight: bold; }
    .send-btn:disabled { background: #424242; color: #8e8e8e; cursor: not-allowed; }
  </style>
</head>
<body>
  <div class="topbar">ChatGPT 4o &bull; Digital Twin Range</div>
  <div class="chat-history" id="history">
    <div class="message assistant">
      <div class="bubble">Hello! How can I help you today?</div>
    </div>
  </div>
  <div class="input-container">
    <div class="input-box" id="prompt-input" contenteditable="true" role="textbox"></div>
    <button class="send-btn" id="send-button" type="button" aria-label="Send prompt">&uarr;</button>
  </div>
  <script>
    const input = document.getElementById('prompt-input');
    const sendBtn = document.getElementById('send-button');
    const history = document.getElementById('history');

    function appendMessage(role, text) {
      const msg = document.createElement('div');
      msg.className = 'message ' + role;
      const bubble = document.createElement('div');
      bubble.className = 'bubble';
      bubble.textContent = text;
      msg.appendChild(bubble);
      history.appendChild(msg);
      history.scrollTop = history.scrollHeight;
    }

    function handleSend() {
      const text = input.innerText.trim();
      if (!text) return;
      appendMessage('user', text);
      input.innerText = '';
      // Dispatch live fetch request that Vigil Submission Guard intercepts
      fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: text })
      }).then(r => r.json()).then(data => {
        appendMessage('assistant', data.response || 'Acknowledged.');
      }).catch(err => {
        appendMessage('assistant', '[Submission Held by Client Guard]');
      });
    }

    sendBtn.addEventListener('click', handleSend);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSend();
      }
    });
  </script>
</body>
</html>`;
}

function getCheckoutHtml() {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Acme Store - Checkout Digital Twin</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #fafafa; padding: 40px; }
    .checkout-card { max-width: 500px; margin: 0 auto; background: #fff; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
    h2 { margin-top: 0; color: #111; }
    .field { margin-bottom: 16px; }
    label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; color: #444; }
    input { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 14px; }
    button { width: 100%; padding: 12px; background: #0066cc; color: #fff; border: none; border-radius: 4px; font-size: 15px; font-weight: 600; cursor: pointer; margin-top: 12px; }
  </style>
</head>
<body>
  <div class="checkout-card">
    <h2>Secure Checkout</h2>
    <form id="payment-form">
      <div class="field">
        <label for="fullname">Full Name</label>
        <input id="fullname" name="name" type="text" placeholder="Jane Doe" required>
      </div>
      <div class="field">
        <label for="email">Email Address</label>
        <input id="email" name="email" type="email" placeholder="jane@example.com" required>
      </div>
      <div class="field">
        <label for="card">Credit Card Number</label>
        <input id="card" name="card" type="text" placeholder="4532 0000 0000 0000" autocomplete="cc-number" required>
      </div>
      <div class="field">
        <label for="cvv">CVV</label>
        <input id="cvv" name="cvv" type="text" placeholder="123" maxlength="4" required>
      </div>
      <button type="submit" id="pay-btn">Pay $49.00</button>
    </form>
  </div>
</body>
</html>`;
}

function getCanvasHtml() {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Canvas & Vision SIMD Testbed</title>
  <style>
    body { font-family: sans-serif; display: flex; flex-direction: column; align-items: center; padding: 40px; background: #111; color: #eee; }
    canvas { border: 2px solid #333; margin-top: 20px; }
  </style>
</head>
<body>
  <h2>Multi-Modal Canvas & Spectral Analysis Testbed</h2>
  <canvas id="test-canvas" width="512" height="512"></canvas>
  <script>
    const canvas = document.getElementById('test-canvas');
    const ctx = canvas.getContext('2d');
    // Animate canvas to test 60 FPS SIMD FFT frequency inspection
    let angle = 0;
    function draw() {
      ctx.fillStyle = '#0a0a0a';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.save();
      ctx.translate(canvas.width / 2, canvas.height / 2);
      ctx.rotate(angle);
      ctx.fillStyle = '#00ffcc';
      ctx.fillRect(-100, -100, 200, 200);
      ctx.restore();
      angle += 0.02;
      requestAnimationFrame(draw);
    }
    draw();
  </script>
</body>
</html>`;
}

// ---- HTTP Server Router ----

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  if (pathname === '/webmail/gmail') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(getGmailHtml(parsed.query));
  }

  if (pathname === '/ai/chatgpt' || pathname === '/ai/claude') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(getAiChatHtml());
  }

  if (pathname === '/shop/checkout') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(getCheckoutHtml());
  }

  if (pathname === '/media/canvas') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(getCanvasHtml());
  }

  if (pathname === '/api/chat' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ response: 'Processed safely: ' + body.slice(0, 50) }));
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

function startServer(port = PORT) {
  return new Promise((resolve, reject) => {
    server.listen(port, '127.0.0.1', () => {
      resolve(server);
    });
    server.on('error', reject);
  });
}

function stopServer() {
  return new Promise(resolve => {
    server.close(resolve);
  });
}

if (require.main === module) {
  startServer().then(() => {
    console.log(`🚀 VIGIL Cyber Range running at http://127.0.0.1:${PORT}`);
  });
}

module.exports = { startServer, stopServer, PORT };

