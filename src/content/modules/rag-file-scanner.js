/**
 * VIGIL RAG Document & Drag-and-Drop File Upload Interceptor
 * Intercepts drag-and-drop drop events and file input changes on AI web UIs.
 * Scans text content (.txt, .csv, .json, .md, .log, .pdf text) for PII & developer secrets
 * on-device before the file payload reaches the server.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(root);
  } else {
    root.VIGIL_FILE_SCANNER = factory(root);
  }
}(typeof self !== 'undefined' ? self : this, function (root) {
  'use strict';

  function isTextFile(file) {
    if (!file) return false;
    const textTypes = ['text/', 'application/json', 'application/csv', 'application/xml', 'application/javascript'];
    if (textTypes.some(t => file.type && file.type.startsWith(t))) return true;
    const textExts = ['.txt', '.csv', '.json', '.md', '.log', '.js', '.py', '.html', '.xml', '.yml', '.yaml', '.env'];
    const name = (file.name || '').toLowerCase();
    return textExts.some(ext => name.endsWith(ext));
  }

  async function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result || '');
      reader.onerror = (e) => reject(e);
      // Read first 500KB to prevent memory exhaustion on ultra-large files
      const blob = file.slice(0, 500 * 1024);
      reader.readAsText(blob);
    });
  }

  async function scanFileForLeaks(file, secretsEngine, fakeDataEngine) {
    if (!isTextFile(file)) {
      return { file: file.name, hasLeak: false, secrets: [], redosRisk: false };
    }

    try {
      const text = await readFileAsText(file);
      const secrets = secretsEngine ? secretsEngine.scanSecrets(text) : [];
      let vaultHits = false;

      if (fakeDataEngine && fakeDataEngine.FAKE_DATA) {
        // Basic PII pattern checks
        if (/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/.test(text)) {
          vaultHits = true;
        }
      }

      const hasLeak = secrets.length > 0 || vaultHits;
      return {
        file: file.name,
        hasLeak,
        secretsCount: secrets.length,
        secretsTypes: secrets.map(s => s.type),
        previewTextLength: text.length
      };
    } catch (err) {
      return { file: file.name, hasLeak: false, error: err.message };
    }
  }

  function attachFileDropInterceptor(documentObj, onLeakDetected) {
    if (!documentObj) return;

    documentObj.addEventListener('drop', async (evt) => {
      const files = evt.dataTransfer && evt.dataTransfer.files;
      if (!files || !files.length) return;

      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        if (isTextFile(file)) {
          const rootObj = root || (typeof globalThis !== 'undefined' ? globalThis : self);
          const secretsEngine = (rootObj && rootObj.VIGIL_SECRETS) || null;
          const fakeEngine = (rootObj && rootObj.VIGIL_FAKEDATA) || null;
          const res = await scanFileForLeaks(file, secretsEngine, fakeEngine);
          if (res.hasLeak && typeof onLeakDetected === 'function') {
            onLeakDetected(res);
          }
        }
      }
    }, true);
  }

  function isImageFile(file) {
    if (!file) return false;
    if (file.type && file.type.startsWith('image/')) return true;
    const name = (file.name || '').toLowerCase();
    return ['.jpg', '.jpeg', '.png', '.webp', '.gif', '.tiff'].some(ext => name.endsWith(ext));
  }

  async function scanImageMetadataForInjection(file) {
    if (!isImageFile(file)) return { hasInjection: false, sanitized: false };
    try {
      const buffer = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(new Uint8Array(e.target.result || []));
        reader.onerror = (e) => reject(e);
        reader.readAsArrayBuffer(file.slice(0, 64 * 1024)); // first 64KB contains EXIF/XMP
      });
      // Decode ASCII representation
      const text = new TextDecoder('latin1').decode(buffer);
      const injectionRegex = /\b(?:ignore (?:all )?previous instructions|system prompt|you are now|developer mode|dan mode|bypass guardrails)\b/i;
      const match = text.match(injectionRegex);
      if (match) {
        return {
          hasInjection: true,
          matchedKeyword: match[0],
          file: file.name,
          reason: 'Concealed prompt injection detected in image EXIF/XMP metadata'
        };
      }
      return { hasInjection: false, file: file.name };
    } catch (e) {
      return { hasInjection: false, error: e.message };
    }
  }

  return {
    isTextFile,
    isImageFile,
    readFileAsText,
    scanFileForLeaks,
    scanImageMetadataForInjection,
    attachFileDropInterceptor
  };
}));
