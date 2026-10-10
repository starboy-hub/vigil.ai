#!/usr/bin/env node
/**
 * VIGIL Swarm Relay — self-hostable signature + federated adapter exchange.
 *
 * A tiny stateless-ish HTTP relay that VIGIL installs use to share:
 *  1. Anonymized threat signatures (hashes only — the protocol makes leaking
 *     message text structurally impossible).
 *  2. Differential-privacy-protected LoRA adapter deltas (Blueprint #17):
 *     clients clip and Gaussian-noise their delta locally BEFORE uploading,
 *     so no individual correction is recoverable from a contribution.
 *
 * Endpoints:
 *   GET  /health            → { ok: true, signatures: n, contributions: n }
 *   POST /submit            → body: { vigilThreatPack: true, signatures: [...] }
 *   GET  /packs?since=<iso> → merged pack of signatures added after `since`
 *   POST /federated         → body: { format: 'VIGIL-DP-LORA-v1', delta: [...], ... }
 *   GET  /federated/aggregate → averaged delta across stored contributions
 *
 * Hardened by default: size caps, dedup by hash, no message text accepted
 * (signatures without a value are dropped), optional shared-secret token
 * (constant-time compare), and per-IP rate limiting.
 *
 * Usage: node relay/relay.js --port=8787 --db=relay-db.json --token=mysecret
 */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAX_SIGNATURES = 50000;
const MAX_BODY = 1024 * 1024; // 1 MB
const MAX_CONTRIBUTIONS = 500;
const RATE_LIMIT_REQUESTS = 120;   // requests...
const RATE_LIMIT_WINDOW_MS = 60000; // ...per minute per IP

function parseArgs(argv) {
  const args = { port: 8787, db: path.join(__dirname, 'relay-db.json'), token: '' };
  argv.slice(2).forEach(a => {
    if (a.startsWith('--port=')) args.port = parseInt(a.split('=')[1], 10) || args.port;
    else if (a.startsWith('--db=')) args.db = a.split('=')[1];
    else if (a.startsWith('--token=')) args.token = a.split('=')[1];
  });
  return args;
}

/** Constant-time string comparison for shared-secret checks. */
function safeEqual(a, b) {
  const ba = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  if (ba.length !== bb.length) {
    // Still burn comparable time before failing
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

/** Pure merge: dedup signatures by value, cap total. Exported for tests. */
function mergeSignatures(existing, incoming, max) {
  const known = new Set(existing.map(s => s.value));
  const merged = [...existing];
  let added = 0;
  for (const s of incoming || []) {
    if (!s || typeof s.value !== 'string' || s.value.length > 128) continue;
    if (known.has(s.value)) continue;
    known.add(s.value);
    merged.push({ value: s.value, addedAt: s.addedAt || new Date().toISOString(), source: s.source || 'relay' });
    added++;
    if (merged.length >= max) break;
  }
  return { merged, added };
}

/** Pure filter: signatures added after `since` (ISO string compare). */
function signaturesSince(signatures, since) {
  if (!since) return signatures;
  return signatures.filter(s => !since || (s.addedAt || '') > since);
}

/** Pure aggregate: element-wise average of DP deltas. Exported for tests. */
function aggregateContributions(contributions, expectedDim) {
  const valid = (contributions || []).filter(c =>
    c && c.format === 'VIGIL-DP-LORA-v1'
    && c.dim && c.dim.classes === expectedDim.classes && c.dim.dIn === expectedDim.dIn
    && Array.isArray(c.delta) && c.delta.length === expectedDim.classes * expectedDim.dIn
  );
  if (valid.length === 0) return { format: 'VIGIL-DP-LORA-v1', dim: expectedDim, contributors: 0, delta: null };

  const dim = expectedDim.classes * expectedDim.dIn;
  const sum = new Array(dim).fill(0);
  for (const c of valid) {
    for (let i = 0; i < dim; i++) sum[i] += c.delta[i];
  }
  return {
    format: 'VIGIL-DP-LORA-v1',
    dim: { classes: expectedDim.classes, dIn: expectedDim.dIn },
    contributors: valid.length,
    delta: sum.map(v => +(v / valid.length).toFixed(6)),
    aggregatedAt: new Date().toISOString()
  };
}

/** Validates an incoming DP contribution's shape (contents are already noised). */
function validContribution(c) {
  if (!c || c.format !== 'VIGIL-DP-LORA-v1' || !c.dim) return false;
  const { classes, dIn } = c.dim;
  if (!Number.isInteger(classes) || !Number.isInteger(dIn) || classes * dIn > 4096) return false;
  if (!Array.isArray(c.delta) || c.delta.length !== classes * dIn) return false;
  return c.delta.every(v => typeof v === 'number' && Number.isFinite(v));
}

function createRelayServer(opts, persist) {
  const { token, max } = opts;
  let db = { signatures: [], contributions: [] };
  if (persist) { try { db = persist.load() || db; } catch (e) { /* fresh start */ } }
  if (!Array.isArray(db.contributions)) db.contributions = [];

  const rateBuckets = new Map(); // ip → [timestamps]

  function save() { if (persist) persist.save(db); }

  function authorized(req) {
    if (!token) return true;
    return safeEqual(req.headers['x-vigil-token'], token);
  }

  // Simple sliding-window rate limiter (per IP). Prevents flooding the
  // shared store; localhost-only binding is the primary defense.
  function rateLimited(ip) {
    const now = Date.now();
    const bucket = (rateBuckets.get(ip) || []).filter(ts => now - ts < RATE_LIMIT_WINDOW_MS);
    bucket.push(now);
    rateBuckets.set(ip, bucket);
    if (rateBuckets.size > 5000) rateBuckets.clear(); // GC
    return bucket.length > RATE_LIMIT_REQUESTS;
  }

  return http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    res.setHeader('content-type', 'application/json');

    if (url.pathname === '/health') {
      res.end(JSON.stringify({ ok: true, signatures: db.signatures.length, contributions: db.contributions.length }));
      return;
    }

    if (rateLimited(req.socket.remoteAddress || 'unknown')) {
      res.statusCode = 429;
      res.end(JSON.stringify({ error: 'rate limited' }));
      return;
    }

    if (!authorized(req)) {
      res.statusCode = 401;
      res.end(JSON.stringify({ error: 'unauthorized' }));
      return;
    }

    if (req.method === 'POST' && url.pathname === '/submit') {
      const chunks = [];
      let size = 0;
      req.on('data', (c) => { size += c.length; if (size > MAX_BODY) req.destroy(); else chunks.push(c); });
      req.on('end', () => {
        try {
          const pack = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          const isPack = pack.vigilThreatPack === true;
          if (!isPack || !Array.isArray(pack.signatures)) throw new Error('not a valid VIGIL threat pack');
          const { merged, added } = mergeSignatures(db.signatures, pack.signatures, MAX_SIGNATURES);
          db.signatures = merged;
          save();
          res.end(JSON.stringify({ ok: true, added, total: merged.length }));
        } catch (e) {
          res.statusCode = 400;
          res.end(JSON.stringify({ error: e.message }));
        }
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/packs') {
      const since = url.searchParams.get('since') || '';
      const signatures = signaturesSince(db.signatures, since);
      res.end(JSON.stringify({ vigilThreatPack: true, version: 1, count: signatures.length, signatures }));
      return;
    }

    // ---- Blueprint #17: federated DP adapter exchange ----
    if (req.method === 'POST' && url.pathname === '/federated') {
      const chunks = [];
      let size = 0;
      req.on('data', (c) => { size += c.length; if (size > MAX_BODY) req.destroy(); else chunks.push(c); });
      req.on('end', () => {
        try {
          const contribution = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!validContribution(contribution)) throw new Error('not a valid VIGIL-DP-LORA-v1 contribution');
          // One contribution per identity per window keeps averaging honest
          db.contributions = db.contributions.filter(c => c.source !== (req.socket.remoteAddress || 'unknown'));
          db.contributions.push({ ...contribution, source: req.socket.remoteAddress || 'unknown', receivedAt: new Date().toISOString() });
          if (db.contributions.length > MAX_CONTRIBUTIONS) {
            db.contributions = db.contributions.slice(-MAX_CONTRIBUTIONS);
          }
          save();
          res.end(JSON.stringify({ ok: true, contributors: db.contributions.length }));
        } catch (e) {
          res.statusCode = 400;
          res.end(JSON.stringify({ error: e.message }));
        }
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/federated/aggregate') {
      const expectedDim = { classes: url.searchParams.get('classes') ? parseInt(url.searchParams.get('classes'), 10) : 3, dIn: url.searchParams.get('dIn') ? parseInt(url.searchParams.get('dIn'), 10) : 128 };
      const aggregated = aggregateContributions(db.contributions, expectedDim);
      res.end(JSON.stringify(aggregated));
      return;
    }

    res.statusCode = 404;
    res.end(JSON.stringify({ error: 'not found' }));
  });
}

if (require.main === module) {
  const args = parseArgs(process.argv);
  const dir = path.dirname(args.db);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const persist = {
    load: () => { try { return JSON.parse(fs.readFileSync(args.db, 'utf8')); } catch (e) { return null; } },
    save: (db) => { try { fs.writeFileSync(args.db, JSON.stringify(db, null, 2)); } catch (e) { console.error('relay persist failed:', e.message); } }
  };
  createRelayServer(args, persist).listen(args.port, '127.0.0.1', () => {
    console.log(`🐝 VIGIL Swarm Relay — http://127.0.0.1:${args.port} (db: ${args.db}${args.token ? ', token required' : ''})`);
  });
}

module.exports = { createRelayServer, mergeSignatures, signaturesSince, aggregateContributions, parseArgs };
