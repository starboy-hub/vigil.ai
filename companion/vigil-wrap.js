#!/usr/bin/env node
/**
 * VIGIL Agent Wrapper — launch any CLI agent under the Agent Firewall.
 *
 *   vigil-wrap --mode=guard --protect='["John Smith","444-55-6666"]' -- <command> [args...]
 *   vigil-wrap --port=8765 -- claude          # attach options, launch command
 *
 * Starts the firewall on 127.0.0.1 (unless VIGIL_FIREWALL_PORT is set, then
 * attaches to that instance), spawns <command> with proxy env vars pointed at
 * it, forwards exit codes and signals, and tears the firewall down on exit.
 *
 * What is protected:
 *   - plain HTTP traffic (e.g. a local Ollama at http://localhost:11434) is
 *     fully inspected: outbound values tokenized, streamed responses
 *     re-hydrated token → real value before you see them
 *   - HTTPS traffic is TUNNELED but not inspected (body inspection needs a
 *     locally-trusted CA — a deliberate decision left to the user)
 *
 * No dependencies. Everything stays local.
 */
'use strict';
const { spawn } = require('child_process');
const http = require('http');
const path = require('path');

const FIREWALL = path.join(__dirname, 'vigil-agent-firewall.js');
const DEFAULT_PORT = 8765;

/** Pure: split argv into firewall options and the wrapped command. */
function parseWrapArgs(argv) {
  const raw = argv.slice(2);
  const sep = raw.indexOf('--');
  const optArgs = sep === -1 ? raw : raw.slice(0, sep);
  const command = sep === -1 ? [] : raw.slice(sep + 1);
  const firewallOpts = { mode: 'guard', port: process.env.VIGIL_FIREWALL_PORT ? parseInt(process.env.VIGIL_FIREWALL_PORT, 10) : DEFAULT_PORT, protect: [] };
  for (const a of optArgs) {
    if (a.startsWith('--mode=')) firewallOpts.mode = a.split('=')[1];
    else if (a.startsWith('--port=')) firewallOpts.port = parseInt(a.split('=')[1], 10) || DEFAULT_PORT;
    else if (a.startsWith('--protect=')) {
      const v = a.split('=').slice(1).join('=');
      try {
        const parsed = JSON.parse(v.endsWith('.json') && require('fs').existsSync(v) ? require('fs').readFileSync(v, 'utf8') : v);
        firewallOpts.protect = Array.isArray(parsed) ? parsed : [];
      } catch (e) {
        throw new Error('Invalid --protect value (must be a JSON array or a .json file)');
      }
    }
  }
  if (!['monitor', 'guard', 'lock'].includes(firewallOpts.mode)) throw new Error('mode must be monitor | guard | lock');
  return { firewallOpts, command };
}

/** Pure: the env a wrapped agent should run with. */
function buildProxyEnv(port, base) {
  const proxy = 'http://127.0.0.1:' + port;
  const noProxy = [base.NO_PROXY, base.no_proxy, '127.0.0.1', 'localhost'].filter(Boolean).join(',');
  return {
    ...base,
    HTTP_PROXY: proxy, HTTPS_PROXY: proxy, http_proxy: proxy, https_proxy: proxy,
    NO_PROXY: noProxy, no_proxy: noProxy,
    VIGIL_FIREWALL: proxy
  };
}

function waitUntilReady(port, timeoutMs) {
  const deadline = Date.now() + (timeoutMs || 8000);
  return new Promise((resolve, reject) => {
    (function poll() {
      const req = http.get({ host: '127.0.0.1', port, path: '/vigil-status', timeout: 1500 }, (res) => {
        res.resume();
        resolve();
      });
      req.on('error', () => {
        if (Date.now() > deadline) reject(new Error('firewall did not become ready on port ' + port));
        else setTimeout(poll, 250);
      });
      req.on('timeout', () => { req.destroy(); });
    })();
  });
}

async function main() {
  let parsed;
  try {
    parsed = parseWrapArgs(process.argv);
  } catch (e) {
    console.error('vigil-wrap: ' + e.message);
    console.error('usage: vigil-wrap [--mode=...] [--protect=\'["Value"]\'] [--port=8765] -- <command> [args...]');
    process.exit(2);
  }
  const { firewallOpts, command } = parsed;
  if (!command.length) {
    console.error('vigil-wrap: no command given after --');
    process.exit(2);
  }

  // Attach to an already-running firewall, or start one
  let firewallProc = null;
  const attachPort = process.env.VIGIL_FIREWALL_PORT ? parseInt(process.env.VIGIL_FIREWALL_PORT, 10) : null;
  let port = firewallOpts.port;
  if (attachPort) {
    port = attachPort;
    console.log('[vigil-wrap] attaching to running firewall on ' + port);
  } else {
    firewallProc = spawn(process.execPath, [FIREWALL,
      '--mode=' + firewallOpts.mode,
      '--port=' + firewallOpts.port,
      '--protect=' + JSON.stringify(firewallOpts.protect)
    ], { stdio: ['ignore', 'inherit', 'inherit'] });
    try {
      await waitUntilReady(firewallOpts.port);
    } catch (e) {
      console.error('[vigil-wrap] ' + e.message);
      firewallProc.kill();
      process.exit(1);
    }
  }
  console.log('[vigil-wrap] agent traffic routes through http://127.0.0.1:' + port +
    ' (plain HTTP inspected · HTTPS tunneled)');

  const child = spawn(command[0], command.slice(1), {
    stdio: 'inherit',
    env: buildProxyEnv(port, process.env)
  });
  const shutdown = (code) => {
    if (firewallProc) firewallProc.kill();
    process.exit(code);
  };
  child.on('exit', (code, signal) => {
    console.log('[vigil-wrap] agent exited (' + (signal || code) + ')');
    shutdown(code == null ? 1 : code);
  });
  ['SIGINT', 'SIGTERM'].forEach((sig) => process.on(sig, () => {
    child.kill(sig === 'SIGINT' ? 'SIGINT' : 'SIGTERM');
    setTimeout(() => shutdown(0), 500);
  }));
}

if (require.main === module) main();

module.exports = { parseWrapArgs, buildProxyEnv, waitUntilReady };
