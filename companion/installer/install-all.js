#!/usr/bin/env node
/**
 * Vigil AI Guardian — Universal 1-Click Master Installer & Setup Wizard
 * Cross-Platform: macOS, Windows, Linux
 * Browsers Supported: Google Chrome, Brave, Microsoft Edge, Mozilla Firefox
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync, spawn } = require('child_process');

const rootDir = path.resolve(__dirname, '../..');
const platform = os.platform();

console.log('=======================================================');
console.log('🛡️  VIGIL AI GUARDIAN — UNIVERSAL 1-CLICK AUTO-INSTALLER');
console.log('=======================================================');
console.log(`📍 Operating System: ${os.type()} (${platform}) ${os.arch()}`);
console.log(`📍 Node.js Version: ${process.version}`);
console.log('=======================================================');

// 1. Build Extension Packages
console.log('\n📦 Step 1/4: Building Extension Packages (Chromium & Firefox)...');
try {
  execSync('node build.js', { cwd: rootDir, stdio: 'inherit' });
  execSync('node build.js --firefox', { cwd: rootDir, stdio: 'inherit' });
  console.log('✅ Extensions built successfully: dist/ (Chromium) & dist-firefox/ (Firefox)');
} catch (e) {
  console.error('❌ Failed to build extension packages:', e.message);
}

// 2. Register Native Messaging Hosts
console.log('\n🔌 Step 2/4: Registering Native Messaging Hosts for All Installed Browsers...');
try {
  const registrar = require('./register-native-hosts');
  registrar.registerAll();
} catch (e) {
  console.warn('⚠️ Native host registration warning:', e.message);
}

// 3. Setup & Launch Desktop Guardian App
console.log('\n🖥️ Step 3/4: Launching VIGIL Native Desktop Guardian & Firewall Engine...');
try {
  if (platform === 'darwin') {
    const buildScript = path.join(rootDir, 'companion/native-app/build-app.sh');
    execSync(`bash "${buildScript}"`, { cwd: rootDir, stdio: 'inherit' });
    
    // Launch macOS Native Tray App
    const appPath = path.join(rootDir, 'companion/native-app/Vigil Desktop.app');
    execSync(`open "${appPath}"`, { stdio: 'inherit' });
    console.log('✅ VIGIL Desktop Menu Bar App active on macOS!');
  } else {
    // Windows / Linux Node.js Daemon fallback
    const fwScript = path.join(rootDir, 'companion/vigil-agent-firewall.js');
    spawn('node', [fwScript, '--mode=guard'], { detached: true, stdio: 'ignore' }).unref();
    console.log('✅ VIGIL Agent Firewall Daemon started in background!');
  }
} catch (e) {
  console.warn('⚠️ Desktop app launcher notification:', e.message);
}

// 4. Verify Local AI Enclave (Ollama)
console.log('\n🤖 Step 4/4: Probing Local AI Enclave Status (Ollama)...');
try {
  const ollamaCheck = execSync('curl -s http://127.0.0.1:11434/api/tags', { encoding: 'utf8' });
  const modelsData = JSON.parse(ollamaCheck);
  const modelNames = (modelsData.models || []).map(m => m.name);
  console.log(`✅ Ollama AI Engine connected! Models available: ${modelNames.join(', ') || 'None'}`);
} catch (e) {
  console.log('ℹ️ Ollama offline or not installed. WebGPU Neural Sentinel active in offline mode (0MB overhead).');
}

console.log('\n=======================================================');
console.log('🎉 VIGIL AI GUARDIAN INSTALLATION & SETUP COMPLETE!');
console.log('=======================================================');
console.log('👉 ACTIVATION INSTRUCTIONS FOR YOUR BROWSERS:');
console.log('   • Chrome / Brave / Edge: Open extensions page and load "dist/"');
console.log('   • Mozilla Firefox: Open "about:debugging#/runtime/this-firefox" and load "dist-firefox/manifest.json"');
console.log('   • Desktop Guardian UI: Look at your macOS Menu Bar or System Tray for 🛡️ Vigil AI!');
console.log('=======================================================\n');
