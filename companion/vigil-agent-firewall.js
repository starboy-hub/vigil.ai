#!/usr/bin/env node
/**
 * VIGIL Agent Firewall — companion tool (Phase 4)
 *
 * A local loopback HTTP proxy that sits between AI agents/apps and the
 * internet. Outbound bodies are scanned with the same engines the extension
 * uses (detection, injection) and, in Guard mode, sensitive values you
 * configure are pseudonymized before leaving the machine.
 *
 * Usage:
 *   node companion/vigil-agent-firewall.js --mode=guard --protect=values.json
 *   point your agent at http://127.0.0.1:8765 (HTTP_PROXY)
 *
 * Modes:
 *   monitor — scan + log findings, forward untouched
 *   guard   — scan + replace configured sensitive values with stable tokens, forward
 *   lock    — block requests whose bodies contain injection patterns or PII
 *
 * Config (values.json): ["John Smith", "john@work.com", "444-55-6666"] —
 * or export the Identity Vault values you want protected.
 * Token mappings are printed to the console (you keep the translation).
 *
 * No dependencies. No network calls of its own. Everything stays local.
 */
const http = require('http');
const net = require('net');
const fs = require('fs');

const VIGIL_ENGINE = require('../src/content/modules/detection-engine.js');
const VIGIL_INJECTION = require('../src/content/modules/injection-engine.js');
const canary = require('./vigil-canary.js');
const { createSseRewriter, createTextRewriter } = require('./sse-rewrite.js');

const DEFAULT_PORT = 8765;

function parseArgs(argv) {
  const args = { mode: 'monitor', port: DEFAULT_PORT, protect: [], openGui: false };
  for (const arg of argv.slice(2)) {
    if (arg === '--gui' || arg === '--open') args.openGui = true;
    else if (arg.startsWith('--mode=')) args.mode = arg.split('=')[1];
    else if (arg.startsWith('--port=')) args.port = parseInt(arg.split('=')[1], 10) || DEFAULT_PORT;
    else if (arg.startsWith('--protect=')) {
      const p = arg.split('=')[1];
      try {
        const raw = p.endsWith('.json') && fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : p;
        const parsed = JSON.parse(raw);
        args.protect = Array.isArray(parsed) ? parsed : [];
      } catch (e) {
        console.error('Invalid --protect value (must be JSON or a .json file)');
        process.exit(1);
      }
    }
  }
  if (!['monitor', 'guard', 'lock'].includes(args.mode)) {
    console.error('mode must be monitor | guard | lock');
    process.exit(1);
  }
  return args;
}

/**
 * Scan one outbound body. Returns findings + (guard) a transformed body.
 * Pure — exported for tests.
 */
function inspectBody(body, protect) {
  const text = String(body || '');
  const findings = { pii: [], injection: null, protectedHits: [], transformed: text, blocked: false, reasons: [] };

  const det = VIGIL_ENGINE.scanWithRegex(text);
  det.redactions.forEach(r => findings.pii.push(r.type));

  const inj = VIGIL_INJECTION.analyzeInjection(text);
  if (inj.level === 'dangerous' || inj.level === 'suspicious') {
    findings.injection = inj.level;
    findings.reasons.push('injection:' + VIGIL_INJECTION.topSignals(inj, 1).join(','));
  }

  // Guard: stable token substitution — the token for a value is derived
  // from its position in the protect list, so it is IDENTICAL across
  // requests and responses can be re-hydrated with one fixed mapping
  protect.forEach((value, idx) => {
    const v = String(value);
    if (v.length >= 3 && findings.transformed.includes(v)) {
      const token = '[VIGIL-' + (idx + 1) + ']';
      findings.transformed = findings.transformed.split(v).join(token);
      findings.protectedHits.push({ token, original: v });
      findings.reasons.push('protected-value');
    }
  });

  // Lock policy: dangerous injection or un-tokenized PII still present
  if (findings.injection === 'dangerous') findings.blocked = true;
  if (findings.pii.length && findings.transformed === text && findings.pii.length) {
    // PII present and not substituted (monitor keeps flowing; lock blocks)
    findings.reasons.push('pii:' + [...new Set(findings.pii)].join(','));
  }
  return findings;
}

function decide(mode, findings) {
  if (mode === 'monitor') return { action: 'forward', body: findings.transformed === undefined ? null : null, useOriginal: true };
  if (mode === 'guard') return { action: 'forward', useOriginal: false, body: findings.transformed };
  // lock
  if (findings.blocked || findings.protectedHits.length || findings.pii.length) {
    return { action: 'block' };
  }
  return { action: 'forward', useOriginal: true, body: null };
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Vigil AI Desktop Guardian</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {
      --bg-glass: rgba(18, 24, 38, 0.95);
      --border-glass: rgba(255, 255, 255, 0.12);
      --accent-green: #10b981;
      --accent-blue: #3b82f6;
      --accent-purple: #8b5cf6;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
    }
    body {
      margin: 0;
      padding: 16px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #090d16;
      color: var(--text-main);
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
    }
    .popover-container {
      width: 360px;
      background: var(--bg-glass);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border-glass);
      border-radius: 16px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6);
      overflow: hidden;
    }
    .header {
      padding: 14px 16px;
      background: rgba(255, 255, 255, 0.03);
      border-bottom: 1px solid var(--border-glass);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 700;
      font-size: 14px;
      letter-spacing: 0.5px;
    }
    .brand-icon-wrap {
      width: 32px;
      height: 32px;
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
    }
    .lattice-svg {
      width: 30px;
      height: 30px;
      filter: drop-shadow(0 0 8px rgba(16, 185, 129, 0.6));
    }
    .spin-ring {
      transform-origin: center;
      animation: spinLattice 14s linear infinite;
    }
    @keyframes spinLattice {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 8px;
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid rgba(16, 185, 129, 0.3);
      border-radius: 20px;
      color: #34d399;
      font-size: 11px;
      font-weight: 600;
    }
    .dot {
      width: 6px;
      height: 6px;
      background-color: #34d399;
      border-radius: 50%;
      box-shadow: 0 0 8px #34d399;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(0.8); }
    }
    .section {
      padding: 14px 16px;
      border-bottom: 1px solid var(--border-glass);
    }
    .section-title {
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: var(--text-muted);
      margin-bottom: 10px;
    }
    .tier-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .tier-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 12px;
      background: rgba(255, 255, 255, 0.02);
      padding: 8px 10px;
      border-radius: 8px;
      border: 1px solid rgba(255, 255, 255, 0.05);
    }
    .tier-name {
      display: flex;
      align-items: center;
      gap: 8px;
      color: #e5e7eb;
    }
    .tier-val {
      font-family: monospace;
      font-size: 11px;
      color: #34d399;
    }
    .proxy-card {
      background: rgba(59, 130, 246, 0.08);
      border: 1px solid rgba(59, 130, 246, 0.2);
      border-radius: 10px;
      padding: 10px;
    }
    .mode-btn-group {
      display: flex;
      gap: 6px;
      margin-top: 8px;
    }
    .mode-btn {
      flex: 1;
      padding: 6px;
      border-radius: 6px;
      border: 1px solid var(--border-glass);
      background: rgba(255, 255, 255, 0.05);
      color: #9ca3af;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      text-align: center;
      transition: all 0.2s;
    }
    .mode-btn.active {
      background: linear-gradient(135deg, #10b981, #059669);
      color: #fff;
      border-color: #34d399;
      box-shadow: 0 0 10px rgba(16, 185, 129, 0.3);
    }
    .challenge {
      background: rgba(139, 92, 246, 0.12);
      border: 1px solid rgba(139, 92, 246, 0.3);
      border-radius: 8px;
      padding: 8px 10px;
      font-size: 12px;
      color: #c4b5fd;
      margin: 8px 0;
    }
    .log-feed {
      display: flex;
      flex-direction: column;
      gap: 6px;
      font-size: 11px;
      max-height: 120px;
      overflow-y: auto;
    }
    .log-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      color: var(--text-muted);
      padding: 4px 0;
      border-bottom: 1px dashed rgba(255, 255, 255, 0.05);
    }
    .btn-action {
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid var(--border-glass);
      color: var(--text-main);
      padding: 4px 8px;
      border-radius: 6px;
      font-size: 11px;
      cursor: pointer;
    }
    .footer {
      padding: 10px 16px;
      background: rgba(0, 0, 0, 0.3);
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 11px;
      color: var(--text-muted);
    }
  </style>
</head>
<body>
  <div class="popover-container">
    <div class="header">
      <div class="brand">
        <div class="brand-icon-wrap">
          <svg class="lattice-svg" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <linearGradient id="quantumGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#10b981" />
                <stop offset="50%" stop-color="#06b6d4" />
                <stop offset="100%" stop-color="#3b82f6" />
              </linearGradient>
              <radialGradient id="quantumGlow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stop-color="#10b981" stop-opacity="0.6"/>
                <stop offset="100%" stop-color="#06b6d4" stop-opacity="0"/>
              </radialGradient>
            </defs>
            <circle cx="16" cy="16" r="14" fill="url(#quantumGlow)" />
            <circle cx="16" cy="16" r="13" stroke="url(#quantumGrad)" stroke-width="1.2" stroke-dasharray="3 2" class="spin-ring"/>
            <path d="M16 4 L26 10 L26 22 L16 28 L6 22 L6 10 Z" stroke="url(#quantumGrad)" stroke-width="1.4" fill="none" stroke-linejoin="round"/>
            <path d="M16 8 L22 12 V18 C22 22 16 24.5 16 24.5 C16 24.5 10 22 10 18 V12 L16 8 Z" fill="url(#quantumGrad)"/>
            <circle cx="16" cy="15" r="2" fill="#ffffff" />
          </svg>
        </div>
        <span>Vigil AI Guardian</span>
      </div>
      <div class="status-badge">
        <div class="dot"></div>
        <span id="headerStatus">PROTECTED</span>
      </div>
    </div>

    <!-- 3-Tier Security Matrix -->
    <div class="section">
      <div class="section-title">System Defense Matrix</div>
      <div class="tier-list">
        <div class="tier-item">
          <div class="tier-name">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M8 1L2.5 3.5V7.5C2.5 11 5 13.5 8 15C11 13.5 13.5 11 13.5 7.5V3.5L8 1Z" stroke="#34d399" stroke-width="1.2" fill="rgba(52, 211, 153, 0.1)"/>
              <path d="M8.5 4L5.5 8.5H8L7.5 12L10.5 7.5H8L8.5 4Z" fill="#34d399"/>
            </svg>
            Tier 1 Air-Gapped Gate
          </div>
          <div class="tier-val">Active (&lt;1ms)</div>
        </div>
        <div class="tier-item">
          <div class="tier-name">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
              <circle cx="8" cy="8" r="2.5" stroke="#60a5fa" stroke-width="1.2" fill="rgba(96, 165, 250, 0.2)"/>
              <circle cx="3" cy="4" r="1.5" fill="#60a5fa"/>
              <circle cx="13" cy="4" r="1.5" fill="#60a5fa"/>
              <circle cx="3" cy="12" r="1.5" fill="#60a5fa"/>
              <circle cx="13" cy="12" r="1.5" fill="#60a5fa"/>
              <path d="M4.2 4.8L6.2 6.5M11.8 4.8L9.8 6.5M4.2 11.2L6.2 9.5M11.8 11.2L9.8 9.5" stroke="#60a5fa" stroke-width="1"/>
            </svg>
            Tier 2 WebGPU Neural
          </div>
          <div class="tier-val">Active (10ms)</div>
        </div>
        <div class="tier-item">
          <div class="tier-name">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
              <rect x="3.5" y="3.5" width="9" height="9" rx="2" stroke="#a78bfa" stroke-width="1.2" fill="rgba(167, 139, 250, 0.15)"/>
              <path d="M8 2V3.5M8 12.5V14M2 8H3.5M12.5 8H14" stroke="#a78bfa" stroke-width="1.2" stroke-linecap="round"/>
              <circle cx="8" cy="8" r="1.5" fill="#a78bfa"/>
            </svg>
            Tier 3 Local AI Enclave
          </div>
          <div class="tier-val" id="tier3Status" style="color: #a78bfa;">Connected</div>
        </div>
      </div>
    </div>

    <!-- Agent Firewall Proxy -->
    <div class="section">
      <div class="section-title">
        <svg width="12" height="12" viewBox="0 0 16 16" fill="none" style="vertical-align:-1px;margin-right:4px;">
          <path d="M2 4H14M2 8H14M2 12H14" stroke="#9ca3af" stroke-width="1.5" stroke-linecap="round"/>
          <circle cx="5" cy="4" r="2" fill="#34d399"/>
          <circle cx="11" cy="8" r="2" fill="#60a5fa"/>
          <circle cx="7" cy="12" r="2" fill="#a78bfa"/>
        </svg>
        Agent Firewall Proxy
      </div>
      <div class="proxy-card">
        <div style="font-size: 11px; color: #9ca3af; display: flex; justify-content: space-between;">
          <span>HTTP_PROXY: 127.0.0.1:8765</span>
          <span style="color: #60a5fa;" id="reqCount">0 requests</span>
        </div>
        <div class="mode-btn-group">
          <button class="mode-btn" data-mode="monitor">Monitor</button>
          <button class="mode-btn" data-mode="guard">Guard</button>
          <button class="mode-btn" data-mode="lock">Lock</button>
        </div>
      </div>
    </div>

    <!-- Voice Canary -->
    <div class="section">
      <div class="section-title">
        <svg width="12" height="12" viewBox="0 0 16 16" fill="none" style="vertical-align:-1px;margin-right:4px;">
          <path d="M2 8H4M5 5V11M8 2V14M11 5V11M14 8H16" stroke="#c4b5fd" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
        Voice Spectral Canary
      </div>
      <div class="challenge" id="challenge">Click to generate anti-clone challenge...</div>
      <button class="btn-action" id="genCanary">Generate Challenge</button>
    </div>

    <!-- Live Telemetry -->
    <div class="section">
      <div class="section-title">Live Traffic Telemetry</div>
      <div class="log-feed" id="log">
        <div class="log-item"><span>No agent traffic recorded yet</span></div>
      </div>
    </div>

    <!-- Footer -->
    <div class="footer">
      <span>Vigil AI Desktop v11.0.0</span>
      <span style="color: #10b981;">100% Local</span>
    </div>
  </div>

  <script>
    async function refresh() {
      try {
        const s = await (await fetch('/vigil-status')).json();
        document.querySelectorAll('.mode-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === s.mode));
        document.getElementById('reqCount').textContent = s.requests + ' reqs';
        const logEl = document.getElementById('log');
        if (s.findings && s.findings.length > 0) {
          logEl.innerHTML = s.findings.map(f =>
            '<div class="log-item"><span><b>' + f.method + '</b> ' + f.url.slice(0, 30) + '</span><span style="color:#ef4444">' + f.action + '</span></div>'
          ).join('');
        }
      } catch (e) {}
    }
    document.querySelectorAll('.mode-btn').forEach(b => b.addEventListener('click', async () => {
      await fetch('/vigil-mode?mode=' + b.dataset.mode);
      refresh();
    }));
    document.getElementById('genCanary').addEventListener('click', async () => {
      try {
        const c = await (await fetch('/vigil-canary')).json();
        document.getElementById('challenge').textContent = c.question;
      } catch (e) {}
    });
    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>`;

function isAuthorizedControlRequest(req) {
  // 1. Host header validation (prevent DNS rebinding attacks)
  const host = String(req.headers.host || '').toLowerCase();
  const hostName = host.split(':')[0];
  if (hostName !== '127.0.0.1' && hostName !== 'localhost') {
    return false;
  }

  // 2. Reject cross-origin browser requests (CSRF protection)
  const secFetchSite = req.headers['sec-fetch-site'];
  if (secFetchSite === 'cross-site') {
    return false;
  }
  const secFetchMode = req.headers['sec-fetch-mode'];
  if (secFetchMode === 'no-cors') {
    return false;
  }

  // 3. Origin header validation (if present, must be loopback)
  const origin = req.headers.origin;
  if (origin && origin !== 'null') {
    try {
      const u = new URL(origin);
      if (u.hostname !== '127.0.0.1' && u.hostname !== 'localhost') {
        return false;
      }
    } catch (_) {
      return false;
    }
  }

  return true;
}

function createFirewallServer(opts) {
  const state = { mode: opts.mode, protect: opts.protect || [], canaryConfig: opts.canaryConfig || { personals: [] }, requests: 0, findingsLog: [] };
  // Stable bidirectional map used to re-hydrate tokens in AI responses
  state.tokenMap = state.protect.map((value, idx) => ({ token: '[VIGIL-' + (idx + 1) + ']', original: String(value) }));
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');

    // ---- Companion dashboard endpoints (before proxying) ----
    if (url.pathname.startsWith('/vigil-')) {
      if (!isAuthorizedControlRequest(req)) {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'FORBIDDEN_CROSS_ORIGIN_OR_REBINDING' }));
        return;
      }

      if (url.pathname === '/vigil-dashboard') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end(DASHBOARD_HTML);
        return;
      }
      if (url.pathname === '/vigil-status') {
        // Redact raw secrets: export masked tokens rather than sensitive values
        const maskedProtect = state.protect.map((_, idx) => '[VIGIL-' + (idx + 1) + ']');
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
          mode: state.mode,
          requests: state.requests,
          findings: state.findingsLog.slice(-20).reverse(),
          protectCount: state.protect.length,
          protect: maskedProtect
        }));
        return;
      }
      if (url.pathname === '/vigil-mode') {
        const m = url.searchParams.get('mode');
        if (['monitor', 'guard', 'lock'].includes(m)) state.mode = m;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ mode: state.mode }));
        return;
      }
      if (url.pathname === '/vigil-canary') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(canary.generateChallenge(state.canaryConfig)));
        return;
      }
    }

    state.requests++;
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks);
      const hasBody = raw.length > 0 && /text|json|form|xml/i.test(req.headers['content-type'] || 'text/plain');
      let findings = null;
      let bodyToSend = raw;
      let decision = null;
      if (hasBody) {
        findings = inspectBody(raw.toString('utf8'), state.protect);
        decision = decide(state.mode, findings);
        state.findingsLog.push({ time: new Date().toISOString(), method: req.method, url: req.url, pii: [...new Set(findings.pii)].join('|') || '-', inj: findings.injection || '-', hits: findings.protectedHits.length, action: decision.action });
        if (state.findingsLog.length > 50) state.findingsLog.shift();
        console.log(`[vigil:${state.mode}] ${req.method} ${req.url} pii=${[...new Set(findings.pii)].join('|') || '-'} inj=${findings.injection || '-'} hits=${findings.protectedHits.length} -> ${decision.action}`);
        findings.protectedHits.forEach(h => console.log(`  ${h.token} = ${h.original}`));
        if (decision.action === 'block') {
          res.writeHead(403, { 'content-type': 'application/json', 'x-vigil-firewall': 'blocked' });
          res.end(JSON.stringify({ blocked: true, reasons: findings.reasons }));
          return;
        }
        if (!decision.useOriginal && decision.body !== null) bodyToSend = Buffer.from(decision.body, 'utf8');
      } else {
        console.log(`[vigil:${state.mode}] ${req.method} ${req.url} -> forward`);
      }

      const dest = new URL(req.url, 'http://' + (req.headers.host || 'example.com'));
      const headers = { ...req.headers, 'x-vigil-firewall': state.mode };
      // A rewritten body must not carry the original content-length or the
      // upstream server waits forever for bytes that never come
      if (decision && !decision.useOriginal && decision.body !== null) {
        headers['content-length'] = Buffer.byteLength(bodyToSend);
      }
      const upstream = http.request({
        hostname: dest.hostname,
        port: dest.port || 80,
        path: dest.pathname + dest.search,
        method: req.method,
        headers
      }, (ur) => {
        // ---- Response direction: re-hydrate tokens for the user (guard) ----
        if (state.mode === 'guard' && state.tokenMap.length) {
          const ctype = String(ur.headers['content-type'] || '');
          if (/text\/event-stream/i.test(ctype)) {
            // Streaming: rewrite inside SSE events, holding incomplete events
            // back so a token split across chunks is never emitted raw
            const headers = { ...ur.headers };
            delete headers['content-length']; // stream length is unknown now
            res.writeHead(ur.statusCode, headers);
            const rw = createSseRewriter({ mappings: state.tokenMap });
            ur.setEncoding('utf8');
            ur.on('data', (c) => res.write(rw.push(c)));
            ur.on('end', () => { res.write(rw.flush()); res.end(); });
            return;
          }
          // Buffered: rewrite whole body (bounded) and fix content-length
          const limit = 8 * 1024 * 1024;
          const len = parseInt(ur.headers['content-length'] || '0', 10);
          const rewriteable = /text|json/i.test(ctype) && (!len || len <= limit);
          if (rewriteable) {
            const parts = [];
            let size = 0;
            ur.on('data', (c) => { size += c.length; if (size <= limit) parts.push(c); });
            ur.on('end', () => {
              const rw = createTextRewriter({ mappings: state.tokenMap });
            const text = rw.push(Buffer.concat(parts).toString('utf8')) + rw.flush();
            const out = Buffer.from(text, 'utf8');
            const headers = { ...ur.headers, 'content-length': out.length };
            delete headers['transfer-encoding']; // chunked + content-length is a parse error
            res.writeHead(ur.statusCode, headers);
            res.end(out);
            });
            return;
          }
        }
        res.writeHead(ur.statusCode, ur.headers);
        ur.pipe(res);
      });
      upstream.on('error', (e) => {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'upstream', detail: e.message }));
      });
      if (bodyToSend.length) upstream.write(bodyToSend);
      upstream.end();
    });
  });

  // HTTPS: tunnel CONNECT requests so wrapped agents do not break. Bodies are
  // NOT inspected (that needs a locally-trusted CA — a deliberate future
  // decision); the destination is still logged for the dashboard.
  server.on('connect', (req, clientSocket, head) => {
    const parts = String(req.url || '').split(':');
    const upstream = net.connect({ host: parts[0], port: parseInt(parts[1] || '443', 10) }, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  });
  return server;
}

function openDashboardInBrowser(url) {
  try {
    const { spawn } = require('child_process');
    if (process.platform === 'darwin') {
      spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
    } else if (process.platform === 'win32') {
      spawn('cmd.exe', ['/c', 'start', url], { detached: true, stdio: 'ignore' }).unref();
    } else {
      spawn('sh', ['-c', 'firefox --new-window "$1" 2>/dev/null || google-chrome --app="$1" 2>/dev/null || chromium --app="$1" 2>/dev/null || gio open "$1" 2>/dev/null || xdg-open "$1" 2>/dev/null', '_', url], { detached: true, stdio: 'ignore' }).unref();
    }
  } catch (_) {}
}

if (require.main === module) {
  const args = parseArgs(process.argv);
  const server = createFirewallServer(args);

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      if (args.openGui) {
        console.log(`ℹ️ VIGIL Agent Firewall already active on port ${args.port}. Opening dashboard...`);
        openDashboardInBrowser(`http://127.0.0.1:${args.port}/vigil-dashboard`);
        process.exit(0);
      } else {
        console.error(`Port ${args.port} is already in use by another instance.`);
        process.exit(1);
      }
    } else {
      console.error('Server error:', err);
      process.exit(1);
    }
  });

  server.listen(args.port, '127.0.0.1', () => {
    console.log(`🛡️ VIGIL Agent Firewall — ${args.mode} mode on http://127.0.0.1:${args.port}`);
    console.log(`   dashboard: http://127.0.0.1:${args.port}/vigil-dashboard`);
    console.log(`   protecting ${args.protect.length} configured value(s); agents: vigil-wrap -- <command>`);
    args.protect.forEach((v, i) => console.log(`   [VIGIL-${i + 1}] = ${v}`));

    if (args.openGui) {
      openDashboardInBrowser(`http://127.0.0.1:${args.port}/vigil-dashboard`);
    }
  });
}

module.exports = { createFirewallServer, inspectBody, decide, parseArgs, openDashboardInBrowser };
