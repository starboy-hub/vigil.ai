#!/usr/bin/env node
/**
 * VIGIL Universal Native Messaging Host Registrar
 * Cross-Platform: macOS, Windows, Linux
 * Supported Browsers: Google Chrome, Brave, Microsoft Edge, Mozilla Firefox
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

// Must match HOST_NAME in src/background/native-bridge.js — the browser
// looks the native host manifest up under this exact name.
const HOST_NAME = 'com.vigil.desktop';
const PLATFORM = os.platform(); // 'darwin', 'win32', 'linux'
const HOME = os.homedir();

function getRootDirectory() {
  return path.resolve(__dirname, '../..');
}

function resolveBinaryPath() {
  const rootDir = getRootDirectory();
  if (PLATFORM === 'darwin') {
    const appBinary = path.join(rootDir, 'companion/native-app/VIGIL Desktop.app/Contents/MacOS/VIGILDesktop');
    if (fs.existsSync(appBinary)) return appBinary;
    return path.join(rootDir, 'companion/native-app/VIGILDesktop');
  } else if (PLATFORM === 'win32') {
    return path.join(rootDir, 'companion', 'vigil-native-host.exe');
  } else {
    return path.join(rootDir, 'companion', 'vigil-native-host');
  }
}

const DEFAULT_ALLOWED_ORIGINS = [
  'chrome-extension://emkokehejldjlfljlhhcimnfefcjcmon/',
  'chrome-extension://vigil-guardian-id/',
  'chrome-extension://vigil-guardian-id/'
];

function createChromiumManifest(binaryPath, customOrigins = null) {
  const origins = Array.isArray(customOrigins) && customOrigins.length > 0
    ? customOrigins
    : DEFAULT_ALLOWED_ORIGINS;

  // Strict origin validation: prevent any wildcard or improper URI patterns
  const validatedOrigins = origins.filter(origin => {
    if (typeof origin !== 'string') return false;
    if (origin.includes('*') || origin === 'chrome-extension://') return false;
    return origin.startsWith('chrome-extension://') && origin.endsWith('/');
  });

  return {
    name: HOST_NAME,
    description: 'Vigil / VIGIL Local Security Sentinel & Local AI Enclave Bridge',
    path: binaryPath,
    type: 'stdio',
    allowed_origins: validatedOrigins.length > 0 ? validatedOrigins : DEFAULT_ALLOWED_ORIGINS
  };
}

function createFirefoxManifest(binaryPath) {
  return {
    name: HOST_NAME,
    description: 'Vigil / VIGIL Local Security Sentinel & Local AI Enclave Bridge (Firefox)',
    path: binaryPath,
    type: 'stdio',
    allowed_extensions: [
      'vigil@starboy-hub.github.io',
      'vigil@starboy-hub.github.io'
    ]
  };
}

function registerMacOS() {
  const binaryPath = resolveBinaryPath();
  const appSupport = path.join(HOME, 'Library', 'Application Support');

  const targets = [
    { browser: 'Google Chrome', dir: path.join(appSupport, 'Google/Chrome/NativeMessagingHosts'), type: 'chromium' },
    { browser: 'Brave Browser', dir: path.join(appSupport, 'BraveSoftware/Brave-Browser/NativeMessagingHosts'), type: 'chromium' },
    { browser: 'Microsoft Edge', dir: path.join(appSupport, 'Microsoft Edge/NativeMessagingHosts'), type: 'chromium' },
    { browser: 'Mozilla Firefox', dir: path.join(appSupport, 'Mozilla/NativeMessagingHosts'), type: 'firefox' }
  ];

  let registeredCount = 0;
  targets.forEach(t => {
    try {
      fs.mkdirSync(t.dir, { recursive: true });
      const manifestPath = path.join(t.dir, `${HOST_NAME}.json`);
      const manifestObj = t.type === 'firefox' ? createFirefoxManifest(binaryPath) : createChromiumManifest(binaryPath);
      fs.writeFileSync(manifestPath, JSON.stringify(manifestObj, null, 2) + '\n');
      console.log(`  ✅ Registered for ${t.browser} -> ${manifestPath}`);
      registeredCount++;
    } catch (e) {
      console.warn(`  ⚠️ Could not register for ${t.browser}: ${e.message}`);
    }
  });

  return registeredCount;
}

function registerLinux() {
  const binaryPath = resolveBinaryPath();
  const configDir = path.join(HOME, '.config');

  const targets = [
    { browser: 'Google Chrome', dir: path.join(configDir, 'google-chrome/NativeMessagingHosts'), type: 'chromium' },
    { browser: 'Brave Browser', dir: path.join(configDir, 'BraveSoftware/Brave-Browser/NativeMessagingHosts'), type: 'chromium' },
    { browser: 'Microsoft Edge', dir: path.join(configDir, 'microsoft-edge/NativeMessagingHosts'), type: 'chromium' },
    { browser: 'Mozilla Firefox', dir: path.join(HOME, '.mozilla/native-messaging-hosts'), type: 'firefox' }
  ];

  let registeredCount = 0;
  targets.forEach(t => {
    try {
      fs.mkdirSync(t.dir, { recursive: true });
      const manifestPath = path.join(t.dir, `${HOST_NAME}.json`);
      const manifestObj = t.type === 'firefox' ? createFirefoxManifest(binaryPath) : createChromiumManifest(binaryPath);
      fs.writeFileSync(manifestPath, JSON.stringify(manifestObj, null, 2) + '\n');
      console.log(`  ✅ Registered for ${t.browser} -> ${manifestPath}`);
      registeredCount++;
    } catch (e) {
      console.warn(`  ⚠️ Could not register for ${t.browser}: ${e.message}`);
    }
  });

  return registeredCount;
}

function registerWindows() {
  const binaryPath = resolveBinaryPath();
  const rootDir = getRootDirectory();
  const manifestDir = path.join(rootDir, 'companion', 'native-manifests');
  fs.mkdirSync(manifestDir, { recursive: true });

  const chromeManifestPath = path.join(manifestDir, `${HOST_NAME}-chrome.json`);
  const firefoxManifestPath = path.join(manifestDir, `${HOST_NAME}-firefox.json`);

  fs.writeFileSync(chromeManifestPath, JSON.stringify(createChromiumManifest(binaryPath), null, 2) + '\n');
  fs.writeFileSync(firefoxManifestPath, JSON.stringify(createFirefoxManifest(binaryPath), null, 2) + '\n');

  const regTargets = [
    { name: 'Google Chrome', key: `HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${HOST_NAME}`, file: chromeManifestPath },
    { name: 'Brave Browser', key: `HKCU\\Software\\BraveSoftware\\Brave-Browser\\NativeMessagingHosts\\${HOST_NAME}`, file: chromeManifestPath },
    { name: 'Microsoft Edge', key: `HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\${HOST_NAME}`, file: chromeManifestPath },
    { name: 'Mozilla Firefox', key: `HKCU\\Software\\Mozilla\\NativeMessagingHosts\\${HOST_NAME}`, file: firefoxManifestPath }
  ];

  let registeredCount = 0;
  regTargets.forEach(t => {
    try {
      const cmd = `REG ADD "${t.key}" /ve /t REG_SZ /d "${t.file}" /f`;
      execSync(cmd, { stdio: 'ignore' });
      console.log(`  ✅ Windows Registry registered for ${t.name}`);
      registeredCount++;
    } catch (e) {
      console.warn(`  ⚠️ Could not write Registry for ${t.name}: ${e.message}`);
    }
  });

  return registeredCount;
}

function registerAll() {
  console.log('=======================================================');
  console.log(`🛡️  VIGIL Registering Native Messaging Host for [${PLATFORM}]`);
  console.log('=======================================================');

  let count = 0;
  if (PLATFORM === 'darwin') {
    count = registerMacOS();
  } else if (PLATFORM === 'linux') {
    count = registerLinux();
  } else if (PLATFORM === 'win32') {
    count = registerWindows();
  } else {
    console.error(`Unsupported OS platform: ${PLATFORM}`);
    process.exit(1);
  }

  console.log('=======================================================');
  console.log(`✅ Native Messaging Host registered for ${count} browser(s).`);
  console.log('=======================================================');
}

if (require.main === module) {
  registerAll();
}

module.exports = { registerAll, resolveBinaryPath, createChromiumManifest, createFirefoxManifest };
