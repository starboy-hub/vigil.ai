// VIGIL - AI Privacy Shield v6.0
// Wrapped in IIFE to prevent global scope pollution
(function() {
  'use strict';

  // Sensitive Context Gatekeeper (Blueprint #13: Enterprise Injection Policy)
  if (typeof window !== 'undefined' && window.location) {
    const policy = (typeof globalThis !== 'undefined' && globalThis.VIGIL_INJECTION_POLICY) ||
                   (typeof VIGIL_INJECTION_POLICY !== 'undefined' ? VIGIL_INJECTION_POLICY : null);
    if (policy && typeof policy.shouldInjectContentScript === 'function') {
      let customDeny = [];
      try {
        const stored = localStorage.getItem('vigil_custom_deny_list');
        if (stored) customDeny = JSON.parse(stored);
      } catch (_) {}
      if (!policy.shouldInjectContentScript(window.location.href, customDeny)) {
        console.log('[VIGIL] Execution halted: sensitive auth, credential, or payment surface detected at', window.location.hostname);
        return;
      }
    }
  }

  console.log('[VIGIL] Content script loaded');

const TRANSLATIONS = {
  en: { sensitiveDetected: 'Sensitive Data Detected', proceed: 'Are you sure you want to proceed?', cancel: 'Cancel', sendAnyway: 'Send Anyway', protectTip: 'Tip: Click Protect in the VIGIL popup to replace sensitive data first', imageUpload: 'Image Upload Detected', aiCanRead: 'AI can read text and faces in images. Does this file contain IDs or sensitive info?', privacyRisk: 'Privacy Risk: Once uploaded, you cannot control who accesses this file.', cancelUpload: 'Cancel Upload', uploadAnyway: 'Upload Anyway', sensitiveFilename: 'Sensitive Filename', containsKeywords: 'contains sensitive keywords.', welcome: 'Welcome to VIGIL!', welcomeText: 'I\'ll protect your sensitive data as you type.', quickProtect: 'Tip: Press ⌘+Enter to quick-protect', gotIt: 'Got it!' },
  es: { sensitiveDetected: 'Datos Sensibles Detectados', proceed: '¿Estás seguro?', cancel: 'Cancelar', sendAnyway: 'Enviar', protectTip: 'Consejo: Haz clic en Proteger', imageUpload: 'Imagen Detectada', aiCanRead: 'La IA puede leer texto.', privacyRisk: 'Riesgo de Privacidad.', cancelUpload: 'Cancelar', uploadAnyway: 'Subir', sensitiveFilename: 'Nombre Sensible', containsKeywords: 'contiene palabras clave.', welcome: '¡Bienvenido!', welcomeText: 'Protegeré tus datos.', quickProtect: 'Presiona ⌘+Enter', gotIt: '¡Entendido!' },
  fr: { sensitiveDetected: 'Données Sensibles', proceed: 'Êtes-vous sûr?', cancel: 'Annuler', sendAnyway: 'Envoyer', protectTip: 'Astuce: Cliquez sur Protéger', imageUpload: 'Image Détectée', aiCanRead: 'L\'IA peut lire le texte.', privacyRisk: 'Risque de Confidentialité.', cancelUpload: 'Annuler', uploadAnyway: 'Télécharger', sensitiveFilename: 'Nom Sensible', containsKeywords: 'contient des mots-clés.', welcome: 'Bienvenue!', welcomeText: 'Je protège vos données.', quickProtect: 'Appuyez sur ⌘+Entrée', gotIt: 'Compris!' },
  de: { sensitiveDetected: 'Sensible Daten', proceed: 'Sind Sie sicher?', cancel: 'Abbrechen', sendAnyway: 'Senden', protectTip: 'Tipp: Klicken Sie auf Schützen', imageUpload: 'Bild Erkannt', aiCanRead: 'KI kann Text lesen.', privacyRisk: 'Datenschutzrisiko.', cancelUpload: 'Abbrechen', uploadAnyway: 'Hochladen', sensitiveFilename: 'Sensibler Name', containsKeywords: 'enthält Schlüsselwörter.', welcome: 'Willkommen!', welcomeText: 'Ich schütze Ihre Daten.', quickProtect: 'Drücken Sie ⌘+Enter', gotIt: 'Verstanden!' },
  pt: { sensitiveDetected: 'Dados Sensíveis', proceed: 'Tem certeza?', cancel: 'Cancelar', sendAnyway: 'Enviar', protectTip: 'Dica: Clique em Proteger', imageUpload: 'Imagem Detectada', aiCanRead: 'A IA pode ler texto.', privacyRisk: 'Risco de Privacidade.', cancelUpload: 'Cancelar', uploadAnyway: 'Enviar', sensitiveFilename: 'Nome Sensível', containsKeywords: 'contém palavras-chave.', welcome: 'Bem-vindo!', welcomeText: 'Protegerei seus dados.', quickProtect: 'Pressione ⌘+Enter', gotIt: 'Entendi!' },
  it: { sensitiveDetected: 'Dati Sensibili', proceed: 'Sei sicuro?', cancel: 'Annulla', sendAnyway: 'Invia', protectTip: 'Suggerimento: Clicca su Proteggi', imageUpload: 'Immagine Rilevata', aiCanRead: 'L\'IA può leggere testo.', privacyRisk: 'Rischio Privacy.', cancelUpload: 'Annulla', uploadAnyway: 'Carica', sensitiveFilename: 'Nome Sensibile', containsKeywords: 'contiene parole chiave.', welcome: 'Benvenuto!', welcomeText: 'Proteggerò i tuoi dati.', quickProtect: 'Premi ⌘+Invio', gotIt: 'Capito!' },
  ru: { sensitiveDetected: 'Конфиденциальные данные', proceed: 'Вы уверены?', cancel: 'Отмена', sendAnyway: 'Отправить', protectTip: 'Совет: Нажмите \'Защитить\'', imageUpload: 'Обнаружено изображение', aiCanRead: 'ИИ может читать текст.', privacyRisk: 'Риск конфиденциальности.', cancelUpload: 'Отмена', uploadAnyway: 'Загрузить', sensitiveFilename: 'Конфиденциальное имя', containsKeywords: 'содержит ключевые слова.', welcome: 'Добро пожаловать!', welcomeText: 'Я защищу ваши данные.', quickProtect: 'Нажмите ⌘+Enter', gotIt: 'Понятно!' },
  zh: { sensitiveDetected: '检测到敏感数据', proceed: '您确定要继续吗？', cancel: '取消', sendAnyway: '仍然发送', protectTip: '提示：点击保护', imageUpload: '检测到图像', aiCanRead: '人工智能可以读取文本。', privacyRisk: '隐私风险。', cancelUpload: '取消上传', uploadAnyway: '仍然上传', sensitiveFilename: '敏感文件名', containsKeywords: '包含敏感关键字。', welcome: '欢迎使用 VIGIL！', welcomeText: '我会保护您的数据。', quickProtect: '按 ⌘+Enter', gotIt: '明白了！' },
  ar: { sensitiveDetected: 'بيانات حساسة', proceed: 'هل أنت متأكد؟', cancel: 'إلغاء', sendAnyway: 'إرسال', protectTip: 'نصيحة: انقر فوق حماية', imageUpload: 'تم اكتشاف صورة', aiCanRead: 'يمكن للذكاء الاصطناعي القراءة.', privacyRisk: 'مخاطر الخصوصية.', cancelUpload: 'إلغاء', uploadAnyway: 'تحميل', sensitiveFilename: 'اسم حساس', containsKeywords: 'يحتوي على كلمات.', welcome: 'مرحبًا بك!', welcomeText: 'سأحمي بياناتك.', quickProtect: 'اضغط ⌘+Enter', gotIt: 'فهمت!' }
};
let currentLang = 'en';
function t(key) { return TRANSLATIONS[currentLang]?.[key] || TRANSLATIONS.en[key]; }


let ollamaAvailable = false;
let vaultCorpus = [], vaultMatchers = [], vaultPseudos = {};
let vaultSalt = null, vaultBlindMap = new Map();
let vaultIndexMinLen = 0, vaultIndexMaxLen = 0, vaultEmailBlindHashes = new Set();
let trustMatchers = [];
let sessionGuard = null;
let ollamaModel = null;
let sentinelAnalyzed = new Set(), sentinelNoted = false, sentinelLLMCalls = 0;
// Zero-width watermark run detector (alternatives only — the joined-sequence
// lint warning is a false positive here; see signing-engine.js)
// eslint-disable-next-line no-misleading-character-class
const VIGIL_ZW_RUN_RE = new RegExp('[\\u200B\\u200C\\u200D\\uFEFF]{16,}');
let injectionSeen = new Set(), injectionNoted = false;
let settings = { aiEnabled: true, regexEnabled: true, useFakeData: true, sensitivity: 'medium', customPatterns: '', trustedSites: [], monitorClipboard: true, notificationSize: 'standard', sentinelEnabled: true, injectionFirewall: true, honeytokens: true, vaultRestore: true };
let isWhitelisted = false, isPaused = false, pauseTimer = null, protectionHistory = [], allTimeProtected = 0, ignoredTexts = new Map(), pausedThreads = new Map(), customAllowedEntities = new Set(), allowedPromptHashes = new Set(), currentTheme = 'light';

// ---- Shadow DOM support (verified external audit): Web-Component inputs
// and text are invisible to a plain document TreeWalker. Collect every open
// shadow root under a root element (recursively, capped), so the passes can
// scan them and the observer can watch them.
const observedShadowRoots = new WeakSet();
function collectShadowRoots(root, out = [], depth = 0) {
  if (depth > 8 || !root) return out;
  if (root.shadowRoot && !observedShadowRoots.has(root.shadowRoot)) {
    out.push(root.shadowRoot);
    observedShadowRoots.add(root.shadowRoot);
    collectShadowRoots(root.shadowRoot, out, depth + 1);
  }
  try {
    const children = root.querySelectorAll ? root.querySelectorAll('*') : [];
    const cap = Math.min(children.length, 2000);
    for (let i = 0; i < cap; i++) {
      const child = children[i];
      if (child.shadowRoot && !observedShadowRoots.has(child.shadowRoot)) {
        out.push(child.shadowRoot);
        observedShadowRoots.add(child.shadowRoot);
        collectShadowRoots(child.shadowRoot, out, depth + 1);
      }
    }
  } catch (e) {}
  return out;
}
function scanRoots() {
  // [document.body, ...newly discovered shadow roots] — roots already known
  // are watched by the observer and scanned by their own pass
  return [document.body, ...collectShadowRoots(document.body, [], 0)];
}

// Granular Ignore Levels:
// 1. Per-Prompt (allowCurrentPrompt): skips flagging for the current input snapshot. Resumes on new text.
// 2. Per-Entity Whitelist (whitelistEntity): stores in customAllowedEntities & sync storage.
// 3. Thread Pause (pauseThread): silences alerts for current conversation path for 15 minutes.
// 4. Site-level Ephemeral TTL (ignoreText): caches text per hostname for 5 minutes.

function getThreadKey() {
  return location.origin + location.pathname;
}

function pauseThread(durationMs = 15 * 60 * 1000) {
  pausedThreads.set(getThreadKey(), Date.now() + durationMs);
  if (typeof popup !== 'undefined' && popup) popup.dismissAlert();
  removeComposerPill();
}

function isThreadPaused() {
  const key = getThreadKey();
  const expiry = pausedThreads.get(key);
  if (expiry && Date.now() < expiry) return true;
  if (expiry && Date.now() >= expiry) pausedThreads.delete(key);
  return false;
}

function whitelistEntity(text) {
  if (!text || typeof text !== 'string') return;
  const trimmed = text.trim();
  if (!trimmed) return;
  customAllowedEntities.add(trimmed);
  customAllowedEntities.add(trimmed.toLowerCase());
  try {
    chrome.storage.sync.get(['vigil_allowed_entities'], (r) => {
      const current = Array.isArray(r.vigil_allowed_entities) ? r.vigil_allowed_entities : [];
      if (!current.includes(trimmed)) {
        current.push(trimmed);
        chrome.storage.sync.set({ vigil_allowed_entities: current });
      }
    });
  } catch (e) {}
}

function ignoreText(text, durationMs = 5 * 60 * 1000) {
  if (!text) return;
  const host = location.hostname;
  if (!ignoredTexts.has(host)) ignoredTexts.set(host, new Map());
  ignoredTexts.get(host).set(text, Date.now() + durationMs);
}

function isTextIgnored(text) {
  if (!text) return false;
  if (isThreadPaused()) return true;
  const trimmed = String(text).trim();
  if (customAllowedEntities.has(trimmed) || customAllowedEntities.has(trimmed.toLowerCase())) return true;
  const hostMap = ignoredTexts.get(location.hostname);
  if (!hostMap) return false;
  const expiry = hostMap.get(trimmed) || hostMap.get(text);
  if (expiry === undefined) return false;
  if (Date.now() > expiry) { hostMap.delete(text); hostMap.delete(trimmed); return false; }
  return true;
}

function allowCurrentPrompt(element) {
  if (element) {
    const txt = (element.value || element.innerText || '').trim();
    if (txt) allowedPromptHashes.add(txt);
  }
  if (typeof popup !== 'undefined' && popup) {
    if (element) popup.activeAlerts = popup.activeAlerts.filter(a => a.element !== element);
    popup.dismissAlert();
  }
  removeComposerPill();
}

function isPromptAllowed(element, text) {
  if (!text) return false;
  const t = String(text).trim();
  if (!t) return false;
  return allowedPromptHashes.has(t);
}

// Local-only detection analytics (verified external audit Claim 7): counts
// what was alerted, protected, ignored — the ignored ratio is the user-visible
// false-positive signal. Nothing leaves the device.
function trackAnalytics(event, types) {
  try {
    chrome.storage.local.get(['vigil_analytics'], (r) => {
      const a = r.vigil_analytics || { triggered: 0, protected: 0, ignored: 0, patternBreakdown: {}, siteBreakdown: {} };
      if (event === 'triggered') {
        a.triggered++;
        (types || []).forEach(t => { a.patternBreakdown[t] = (a.patternBreakdown[t] || 0) + 1; });
        a.siteBreakdown[location.hostname] = (a.siteBreakdown[location.hostname] || 0) + 1;
      }
      if (event === 'protected') a.protected++;
      if (event === 'ignored') a.ignored++;
      chrome.storage.local.set({ vigil_analytics: a });
    });
  } catch (e) {}
}
function tc(light, dark) { return (typeof currentTheme === 'undefined' || currentTheme === 'dark') ? dark : light; }
function loadTheme() { return new Promise((resolve) => { chrome.storage.sync.get([VIGIL.KEYS.THEME], (r) => { currentTheme = r[VIGIL.KEYS.THEME] || 'light'; resolve(currentTheme); }); }); }

chrome.storage.onChanged.addListener((changes, ns) => {
  if (ns === 'local') {
    if (changes[VIGIL.KEYS.VAULT_VERSION] || changes[VIGIL.KEYS.PSEUDO_MAP]) refreshVault();
  }
  if (ns === 'sync') {
    if (changes.vigil_allowed_entities) {
      customAllowedEntities.clear();
      const list = changes.vigil_allowed_entities.newValue;
      if (Array.isArray(list)) {
        list.forEach(item => {
          if (typeof item === 'string' && item.trim()) {
            customAllowedEntities.add(item.trim());
            customAllowedEntities.add(item.trim().toLowerCase());
          }
        });
      }
    }
    if (changes.settings) {
      settings = VIGIL.mergeSettings(changes.settings.newValue);
      if (!settings.trustedSites) settings.trustedSites = [];
      const host = window.location.hostname.toLowerCase();
      isWhitelisted = settings.trustedSites.some(t => host === t || host.endsWith('.' + t));
    }
    if (changes[VIGIL.KEYS.THEME]) { currentTheme = changes[VIGIL.KEYS.THEME].newValue || 'light'; if (typeof popup !== 'undefined' && popup) popup.render(); }
    if (changes.manualLanguage) {
      const newLang = changes.manualLanguage.newValue || 'auto';
      if (newLang !== 'auto' && TRANSLATIONS[newLang]) currentLang = newLang;
      else { const browserLang = navigator.language.split('-')[0].toLowerCase(); currentLang = TRANSLATIONS[browserLang] ? browserLang : 'en'; }
      if (typeof popup !== 'undefined' && popup) popup.render();
    }
  }
});

class HistoryStore {
  constructor() { this.MAX_ITEMS = 500; this.STORAGE_KEY = VIGIL.KEYS.HISTORY; this.SUMMARY_KEY = VIGIL.KEYS.HISTORY_SUMMARY; }
  async load() { return new Promise((resolve) => { chrome.storage.local.get([this.STORAGE_KEY, this.SUMMARY_KEY], (result) => { protectionHistory = result[this.STORAGE_KEY] || []; const summary = result[this.SUMMARY_KEY] || { allTime: 0 }; allTimeProtected = summary.allTime || 0; this.totalProtected = protectionHistory.filter(h => new Date(h.timestamp).toDateString() === new Date().toDateString()).length; resolve(); }); }); }
  async save() { if (protectionHistory.length > this.MAX_ITEMS) protectionHistory = protectionHistory.slice(-this.MAX_ITEMS); const summary = { allTime: allTimeProtected, lastUpdated: new Date().toISOString() }; return new Promise((resolve) => { chrome.storage.local.set({ [this.STORAGE_KEY]: protectionHistory, [this.SUMMARY_KEY]: summary }, resolve); }); }
  add(item) { item.timestamp = item.timestamp || new Date().toISOString(); protectionHistory.push(item); allTimeProtected++; this.totalProtected = protectionHistory.filter(h => new Date(h.timestamp).toDateString() === new Date().toDateString()).length; this.save(); }
  async clear() { protectionHistory = []; allTimeProtected = 0; this.totalProtected = 0; await this.save(); }
  exportJSON() { const data = JSON.stringify({ exported: new Date().toISOString(), total: protectionHistory.length, items: protectionHistory.map(h => ({ ...h, original: VIGIL.maskSensitive(h.original) })) }, null, 2); const blob = new Blob([data], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `vigil-history-${new Date().toISOString().split('T')[0]}.json`; a.click(); URL.revokeObjectURL(url); }
  exportCSV() { if (protectionHistory.length === 0) return; let csv = 'Timestamp,Type,Original(masked),Fake,Site\n'; protectionHistory.forEach(h => { csv += `"${h.timestamp}","${h.type}","${VIGIL.maskSensitive(h.original).replace(/"/g,'""')}","${(h.fake||'').replace(/"/g,'""')}","${h.site||''}"\n`; }); const blob = new Blob([csv], { type: 'text/csv' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `vigil-history-${new Date().toISOString().split('T')[0]}.csv`; a.click(); URL.revokeObjectURL(url); }
}
const historyStore = new HistoryStore();

async function loadSettings() {
  try {
    chrome.storage.sync.get(['vigil_allowed_entities'], (r) => {
      const list = r && r.vigil_allowed_entities;
      if (Array.isArray(list)) {
        list.forEach(item => {
          if (typeof item === 'string' && item.trim()) {
            customAllowedEntities.add(item.trim());
            customAllowedEntities.add(item.trim().toLowerCase());
          }
        });
      }
    });
  } catch (e) {}
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (response) => {
      if (response && response.settings) {
        settings = response.settings;
        if (!settings.trustedSites) settings.trustedSites = [];
        if (settings.useFakeData === undefined) settings.useFakeData = true;
        if (settings.monitorClipboard === undefined) settings.monitorClipboard = true;
        if (settings.notificationSize === undefined) settings.notificationSize = 'standard';
        if (settings.sensitivity === undefined) settings.sensitivity = 'medium';
        if (settings.customPatterns === undefined) settings.customPatterns = '';
        const host = window.location.hostname.toLowerCase();
        isWhitelisted = settings.trustedSites.some(t => host === t || host.endsWith('.' + t));
      }
      resolve(settings);
    });
  });
}
async function checkOllama() { return new Promise((resolve) => { chrome.runtime.sendMessage({ type: 'CHECK_OLLAMA' }, (response) => { ollamaAvailable = !!(response && response.available); ollamaModel = (response && response.model) || null; resolve(ollamaAvailable); }); }); }

async function refreshVault() {
  try {
    const res = await chrome.runtime.sendMessage({ type: 'VAULT_BLIND_INDEX' });
    if (res && res.indices && res.salt) {
      vaultSalt = res.salt;
      vaultBlindMap.clear();
      res.indices.forEach(idx => {
        vaultBlindMap.set(idx.blindHash, idx);
      });
      vaultIndexMinLen = res.indices.reduce((min, idx) => Math.min(min, idx.minLen || Infinity), Infinity);
      vaultIndexMaxLen = res.indices.reduce((max, idx) => Math.max(max, idx.minLen || 0), 0);
      if (!isFinite(vaultIndexMinLen)) vaultIndexMinLen = 0;
      vaultEmailBlindHashes = new Set(res.indices.filter(i => i.kind === 'email').map(i => i.blindHash));
      trustMatchers = VIGIL_VAULT.buildMatchers((res && res.trusted) || []);
      // Cleartext vault values never held in DOM memory during blind index mode
      vaultCorpus = [];
      vaultMatchers = [];
    } else {
      // Blind index unavailable (vault error): stay safe — no vault matching
      // at all rather than pulling cleartext entries into the page context.
      vaultSalt = null;
      vaultBlindMap.clear();
      vaultIndexMinLen = 0;
      vaultIndexMaxLen = 0;
      vaultEmailBlindHashes = new Set();
      vaultCorpus = [];
      vaultMatchers = [];
      trustMatchers = [];
      if (res && res.error) console.warn('[VIGIL] Vault blind index unavailable:', res.error);
    }
    const mapRes = await chrome.runtime.sendMessage({ type: 'PSEUDO_GET_MAP', site: location.hostname });
    vaultPseudos = (mapRes && mapRes.map) || {};
    const sessRes = await new Promise((res) => chrome.runtime.sendMessage({ type: 'GET_SESSION_GUARD' }, (r) => res(r || null)));
    sessionGuard = sessRes && sessRes.session ? sessRes.session : null;
  } catch (e) { console.warn('[VIGIL] Vault unavailable:', e.message); }
}

function pickVaultFake(kind, entryId, value) {
  const pools = { name: 'names', email: 'emails', phone: 'phones' };
  const pool = VIGIL_FAKE.FAKE_DATA[pools[kind]];

  if (settings && settings.burnerIdentityMode) {
    // Blueprint #15: 24h rolling epoch bucket breaks cross-session/cross-day profiling
    const epochDay = Math.floor(Date.now() / 86400000).toString();
    const seed = VIGIL.strHash(String(value || '').trim().toLowerCase() + '|' + location.hostname + '|burner:' + epochDay);
    if (pool && pool.length) return pool[Math.abs(seed) % pool.length];
    return '[Burner-' + Math.abs(seed).toString(36) + ']';
  }

  // Seed by the NORMALIZED VALUE (not the volatile entryId): deleting and
  // re-adding a vault entry keeps the same pseudonym, so AI conversations
  // stay coherent across vault edits
  const seed = VIGIL.strHash(String(value || '').trim().toLowerCase() + '|' + location.hostname);
  if (pool && pool.length) return pool[Math.abs(seed) % pool.length];
  return '[Private-' + Math.abs(seed).toString(36) + ']';
}

function vaultKindLabel(kind) {
  return 'Vault ' + kind.charAt(0).toUpperCase() + kind.slice(1);
}

// ---- Blueprint #1: blind-index vault scanning ----
// Vault detection without cleartext: page text is broken into candidates
// (emails, phone runs, word n-grams), each candidate is normalized the same
// way the vault normalizes entries, blind-hashed with the vault salt, and
// matched against the blind index. A hit means the candidate IS a vault
// value — no plaintext entry ever reaches the content script.
const VAULT_SCAN_CACHE_MAX = 50;
const VAULT_MAX_CANDIDATES = 400;
let vaultScanCache = new Map();

function vaultCandidateNorms(candidate) {
  const t = candidate.trim();
  if (!t) return [];
  const norms = new Set();
  norms.add(t.toLowerCase());                      // email norm
  norms.add(t.toLowerCase().replace(/\s+/g, ' ')); // name/custom norm
  if (/\d/.test(t)) norms.add(t.replace(/\D/g, '')); // phone norm
  return [...norms];
}

function vaultExtractCandidates(text) {
  const cands = new Set();
  let m;
  const emailRe = /[^\s@<>]{1,64}@[^\s@<>]{1,255}\.[^\s@<>]{2,}/g;
  while ((m = emailRe.exec(text)) !== null) {
    cands.add(m[0]);
    if (cands.size >= VAULT_MAX_CANDIDATES) return cands;
  }
  const phoneRe = /(?<!\d)\+?[\d][\d\s().+-]{5,24}[\d](?!\d)/g;
  while ((m = phoneRe.exec(text)) !== null) {
    cands.add(m[0]);
    if (cands.size >= VAULT_MAX_CANDIDATES) return cands;
  }
  const words = text.split(/[^\p{L}\p{N}'’-]+/u).filter(w => w.length >= 2 && w.length <= 64);
  for (let i = 0; i < words.length && cands.size < VAULT_MAX_CANDIDATES; i++) {
    let seq = words[i];
    cands.add(seq);
    for (let j = i + 1; j < Math.min(i + 4, words.length); j++) {
      seq += ' ' + words[j];
      cands.add(seq);
      if (cands.size >= VAULT_MAX_CANDIDATES) break;
    }
  }
  return cands;
}

function pushVaultFinding(r, alerts, redactions, seen) {
  if (!alerts.find(x => x.source === 'vault' && x.type === r.type)) {
    alerts.push({ type: r.type, source: 'vault', severity: 'critical' });
  }
  if (!seen.has(r.text)) {
    redactions.push(r);
    seen.add(r.text);
  }
}

async function scanVaultText(text, alerts, redactions, seen) {
  if (!text) return;

  // Legacy matcher path (kept for any future plaintext matcher source, e.g.
  // trusted-value styling) — authoritative when populated.
  if (vaultMatchers && vaultMatchers.length) {
    for (const m of vaultMatchers) {
      const re = new RegExp(m.regex.source, m.regex.flags);
      let vm;
      while ((vm = re.exec(text)) !== null) {
        if (vm[0].length === 0) { re.lastIndex++; continue; }
        const matched = vm[0];
        const typeLabel = vaultKindLabel(m.kind);
        if (!seen.has(matched)) {
          const opaquePointer = (typeof VIGIL_FAKE !== 'undefined' && VIGIL_FAKE.createOpaquePointer)
            ? VIGIL_FAKE.createOpaquePointer(m.kind, m.entryId)
            : `{{PTR:VAULT_${m.entryId.slice(0, 8)}}}`;
          pushVaultFinding({ text: matched, type: typeLabel, vaultId: m.entryId, vaultKind: m.kind, context: matched, opaquePointer }, alerts, redactions, seen);
        }
      }
    }
  }

  // Blind-index path: hash candidates locally, compare against blind indices.
  if (!vaultSalt || !vaultBlindMap.size) return;
  const cached = vaultScanCache.get(text);
  if (cached) {
    cached.forEach(r => pushVaultFinding(r, alerts, redactions, seen));
    return;
  }
  const hits = [];
  const matchedIds = new Set();
  for (const cand of vaultExtractCandidates(text)) {
    if (matchedIds.size >= vaultBlindMap.size) break;
    for (const norm of vaultCandidateNorms(cand)) {
      if (norm.length < vaultIndexMinLen || norm.length > vaultIndexMaxLen) continue;
      let blindHash;
      try {
        blindHash = await VIGIL_VAULT.computeBlindHash(vaultSalt, norm);
      } catch (e) { return; }
      const idx = vaultBlindMap.get(blindHash);
      if (idx && !matchedIds.has(idx.id)) {
        matchedIds.add(idx.id);
        const opaquePointer = (typeof VIGIL_FAKE !== 'undefined' && VIGIL_FAKE.createOpaquePointer)
          ? VIGIL_FAKE.createOpaquePointer(idx.kind, idx.id)
          : `{{PTR:VAULT_${idx.id}}}`;
        hits.push({ text: cand.trim(), type: vaultKindLabel(idx.kind), vaultId: idx.id, vaultKind: idx.kind, context: cand.trim(), opaquePointer });
      }
    }
  }
  if (vaultScanCache.size >= VAULT_SCAN_CACHE_MAX) {
    vaultScanCache.delete(vaultScanCache.keys().next().value);
  }
  vaultScanCache.set(text, hits);
  hits.forEach(r => pushVaultFinding(r, alerts, redactions, seen));
}

const sessionAdHocPseudos = new Map();

function saveLearnedExemplar(original, safe, kind) {
  if (!original || !safe || original === safe) return;
  try {
    chrome.runtime.sendMessage({ type: 'LEARN_EXEMPLAR', original, safe, kind: kind || 'CUSTOM' }, () => {});
  } catch (_) {}
}

function restoreVaultInResponses() {
  if (isPaused || !settings.vaultRestore || (!Object.keys(vaultPseudos).length && !sessionAdHocPseudos.size)) return;
  if (typeof VIGIL_REHYDRATION !== 'undefined' && VIGIL_REHYDRATION) {
    sessionAdHocPseudos.forEach((orig, fake) => {
      VIGIL_REHYDRATION.recordSubstitution(fake, orig);
    });
    if (vaultCorpus && vaultCorpus.length) {
      vaultCorpus.forEach(entry => {
        const fake = vaultPseudos[entry.id];
        if (fake) VIGIL_REHYDRATION.recordSubstitution(fake, entry.value);
      });
    }
    VIGIL_REHYDRATION.rehydrateSubtree(document.body);
  }
  const activePseudos = [...Object.values(vaultPseudos).filter(Boolean), ...Array.from(sessionAdHocPseudos.keys())];
  if (!activePseudos.length) return;
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const p = node.parentElement;
      if (!p) return NodeFilter.FILTER_REJECT;
      // Never touch inputs or anything the user might submit — restoring
      // real values into a sendable field would leak them
      if (p.closest('input,textarea') || p.isContentEditable) return NodeFilter.FILTER_REJECT;
      if (p.closest('[data-vigil]')) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    }
  });
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  nodes.forEach(node => {
    const v = node.nodeValue;
    if (!v || v.length < 4) return;
    const hasAnyPseudo = activePseudos.some(fake => v.includes(fake)) ||
      /\{\{(?:PTR:[A-Z0-9]+_|VAULT:)[A-Za-z0-9+/]{8}\}\}/.test(v);
    if (!hasAnyPseudo) return;

    let updated = v;
    for (const [fake, original] of sessionAdHocPseudos.entries()) {
      if (updated.includes(fake)) updated = updated.split(fake).join(original);
    }

    if (vaultCorpus && vaultCorpus.length) {
      for (const entry of vaultCorpus) {
        const fake = vaultPseudos[entry.id];
        if (fake && updated.includes(fake)) updated = updated.split(fake).join(entry.value);
      }
      if (updated !== node.nodeValue) node.nodeValue = updated;
    } else {
      if (updated !== node.nodeValue) {
        node.nodeValue = updated;
      }
      // Zero-Trust Oracle restoration via service worker
      try {
        chrome.runtime.sendMessage({ type: 'VAULT_RESTORE_TEXT', text: v, site: location.hostname }, (res) => {
          if (res && res.text && res.text !== node.nodeValue) {
            node.nodeValue = res.text;
          }
        });
      } catch (e) {}
    }
  });
}

// ---- Quiet notifications: one toast, severity ladder, badge for low ----
// Rule 1: a single notification surface — never stacked banners.
// Rule 2: intrusiveness earned by severity (low = badge only).
// Rule 3: dismissals are honored (per-site + per-signal mute, persisted).

let noteEl = null, noteQueue = [], noteTimer = null;

function siteMuted() {
  return (settings.mutedSites || []).includes(location.hostname);
}

function updateBubbleVisibility() {
  if (typeof popup === 'undefined' || !popup || !popup.container) return;
  const hasNotes = !!noteEl || noteQueue.length > 0;
  const hasAlerts = popup.activeAlerts && popup.activeAlerts.length > 0;
  const isExpanded = popup.state !== 'minimized';
  const show = settings.bubbleMode === 'always' || settings.familyMode || hasNotes || hasAlerts || isExpanded;
  popup.container.style.display = show ? '' : 'none';
}

function noteRank(level) { return { low: 0, suspicious: 1, dangerous: 2 }[level] ?? 1; }

function noteBtnStyle() {
  return 'background:rgba(255,255,255,.18);border:none;color:#fff;padding:4px 10px;border-radius:6px;cursor:pointer;font-size:11px;font-weight:600;';
}

function showNote(note) {
  // note: { level, category, title, detail, muteId?, force? }
  if (noteRank(note.level) === 0 && !note.force) return; // low: badge only
  if (siteMuted()) return;

  // Single active note at a time — if one already exists, upgrade it smoothly
  // instead of queuing hidden toasts that pop up one after the other!
  if (noteEl) {
    if (note.category && noteEl._category && note.category !== noteEl._category) {
      if (noteEl._category === 'webmail' && note.category === 'sentinel') return;
      if (note.category === 'webmail' && noteEl._category === 'sentinel') {
        renderNote(note);
        return;
      }
      note.title = `${noteEl._title} • ${note.title}`;
      note.detail = `${noteEl._detail} • ${note.detail}`;
      note.level = noteRank(note.level) >= (noteEl._rank || 0) ? note.level : noteEl._level;
      renderNote(note);
      return;
    }
    if (noteRank(note.level) >= (noteEl._rank || 0)) {
      renderNote(note);
    } else {
      if (typeof popup !== 'undefined' && popup) popup.render();
    }
    return;
  }
  renderNote(note);
}

function renderNote(note) {
  if (noteEl) { noteEl.remove(); }
  clearTimeout(noteTimer);

  const danger = note.level === 'dangerous';
  const suspicious = note.level === 'suspicious';
  const accent = danger ? '#ef4444' : (suspicious ? '#f59e0b' : '#6366f1');

  noteEl = document.createElement('div');
  noteEl._rank = noteRank(note.level);
  noteEl._level = note.level;
  noteEl._category = note.category;
  noteEl._title = note.title;
  noteEl._detail = note.detail;
  noteEl.setAttribute('data-vigil-note', '');
  noteEl.setAttribute('role', 'alert');
  noteEl.setAttribute('data-vigil', 'note');
  noteEl.style.cssText = 'position:fixed!important;bottom:52px!important;right:16px!important;z-index:2147483646!important;max-width:340px!important;padding:12px 16px!important;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif!important;font-size:12.5px!important;line-height:1.45!important;color:#f8fafc!important;background:rgba(24,24,27,0.96)!important;border:1px solid rgba(255,255,255,0.12)!important;border-left:4px solid ' + accent + '!important;border-radius:12px!important;box-shadow:0 12px 32px rgba(0,0,0,0.45)!important;cursor:pointer!important;backdrop-filter:blur(12px)!important;-webkit-backdrop-filter:blur(12px)!important;animation:vigil-fadeIn 0.2s ease-out!important;';

  const title = document.createElement('div');
  title.style.cssText = 'font-weight:700;margin-bottom:4px;color:#fff;display:flex;align-items:center;justify-content:space-between;gap:8px;';
  const titleSpan = document.createElement('span');
  titleSpan.textContent = note.title;
  const dismissSpan = document.createElement('span');
  dismissSpan.style.cssText = 'color:#9ca3af;font-size:14px;cursor:pointer;padding:0 4px;';
  dismissSpan.setAttribute('aria-label', 'Dismiss');
  dismissSpan.textContent = '×';
  title.appendChild(titleSpan);
  title.appendChild(dismissSpan);

  const detail = document.createElement('div');
  detail.style.cssText = 'color:#d1d5db;font-size:11.5px;line-height:1.4;';
  detail.textContent = note.detail || '';

  const actions = document.createElement('div');
  actions.style.cssText = 'display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;';

  if (note.muteId) {
    const muteBtn = document.createElement('button');
    muteBtn.textContent = 'Never warn about this';
    muteBtn.style.cssText = noteBtnStyle();
    muteBtn.addEventListener('click', (e) => { e.stopPropagation(); muteSignal(note.muteId); dismissNote(); });
    actions.appendChild(muteBtn);
  }

  const siteBtn = document.createElement('button');
  siteBtn.textContent = 'Ignore on this site';
  siteBtn.style.cssText = noteBtnStyle();
  siteBtn.addEventListener('click', (e) => { e.stopPropagation(); muteSite(); dismissNote(); });
  actions.appendChild(siteBtn);

  noteEl.appendChild(title);
  if (note.detail) noteEl.appendChild(detail);
  noteEl.appendChild(actions);

  const closeBtn = title.querySelector('span[aria-label="Dismiss"]');
  if (closeBtn) {
    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      dismissNote();
    });
  }

  noteEl.addEventListener('click', (e) => {
    if (e.target.closest('button')) return;
    if (typeof popup !== 'undefined' && popup) popup.expand();
    dismissNote();
  });

  document.body.appendChild(noteEl);
  clearTimeout(noteTimer);
  noteTimer = setTimeout(dismissNote, danger ? 8000 : 5000);
}

function dismissNote() {
  if (noteEl) noteEl.remove();
  noteEl = null;
  clearTimeout(noteTimer);
  noteQueue = []; // Purge queue immediately — no cascading hidden toasts!
  updateBubbleVisibility();
}

function muteSite() {
  settings.mutedSites = settings.mutedSites || [];
  if (!settings.mutedSites.includes(location.hostname)) settings.mutedSites.push(location.hostname);
  try {
    chrome.storage.sync.get(['settings'], (res) => {
      const s = res.settings || {};
      s.mutedSites = settings.mutedSites;
      chrome.storage.sync.set({ settings: s });
    });
  } catch (e) {}
}

function muteSignal(id) {
  settings.mutedSignals = settings.mutedSignals || [];
  if (!settings.mutedSignals.includes(id)) settings.mutedSignals.push(id);
  try {
    chrome.storage.sync.get(['settings'], (res) => {
      const s = res.settings || {};
      s.mutedSignals = settings.mutedSignals;
      chrome.storage.sync.set({ settings: s });
    });
  } catch (e) {}
}

// ---- Model router: Ollama first, in-browser model second, none = heuristics ----

function aiBackendName() {
  if (ollamaAvailable && settings.aiEnabled) return 'ollama';
  if (settings.webgpuAI) return 'browser';
  return null;
}

function aiClassify(text, kind) {
  const backend = aiBackendName();
  if (backend === 'ollama') {
    return new Promise((res) => { try { chrome.runtime.sendMessage({ type: 'SENTINEL_LLM', text, kind }, (r) => res(r || null)); } catch (e) { res(null); } });
  }
  if (backend === 'browser') {
    // The fine-tuned 3-class head handles BOTH kinds (its injection head
    // measured 7/7 with 0 false alarms on held-out negatives)
    return new Promise((res) => { try { chrome.runtime.sendMessage({ type: 'SENTINEL_WEBGPU', text, kind }, (r) => res(r || null)); } catch (e) { res(null); } });
  }
  return Promise.resolve(null);
}

// ---- Agent honeytokens: decoy credentials that betray AI scraping ----

let canaryPlanted = false;
let canaryValues = null;
let honeytokenAlerted = false;

function plantAgentCanary() {
  if (canaryPlanted || isWhitelisted) return;
  if (settings && settings.honeytokens === false) return;
  canaryValues = VIGIL.canaryBundle(location.hostname, sessionGuard ? sessionGuard.id : String(Date.now()));
  
  let contextualCanaries = [];
  if (typeof VIGIL_CANARY_GENERATOR !== 'undefined') {
    const bundle = VIGIL_CANARY_GENERATOR.generateContextualBundle(location.hostname, sessionGuard ? sessionGuard.id : String(Date.now()));
    contextualCanaries = bundle.canaries || [];
  }

  const decoy = document.createElement('div');
  decoy.setAttribute('data-vigil', 'canary-decoy');
  decoy.setAttribute('aria-hidden', 'true');
  decoy.style.cssText = 'position:absolute!important;left:-9999px!important;top:-9999px!important;opacity:0!important;height:1px!important;width:1px!important;overflow:hidden!important;';
  
  let extraText = '';
  contextualCanaries.forEach(c => {
    extraText += ` / ${c.type}: ${c.value}`;
  });

  decoy.textContent = 'Internal session credentials (do not share): login ' + canaryValues.email + ' / access key ' + canaryValues.code + extraText + '. ' + canaryValues.note;
  decoy.dataset.canaryCode = canaryValues.code;
  decoy.dataset.canaryEmail = canaryValues.email;
  document.body.appendChild(decoy);
  canaryPlanted = true;
}

function honeytokenPass() {
  if (isPaused) return;
  if (settings && settings.honeytokens === false) return;
  if (!canaryPlanted) plantAgentCanary();
  if (honeytokenAlerted) return;
  // Scan visible text nodes for canary values that escaped the decoy
  const hitNode = (() => {
    const activeList = typeof VIGIL_CANARY_GENERATOR !== 'undefined' ? VIGIL_CANARY_GENERATOR.listCanaries().map(c => c.value) : [];
    for (const root of scanRoots()) {
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
        acceptNode(node) {
          const p = node.parentElement;
          if (!p) return NodeFilter.FILTER_REJECT;
          if (p.closest('[data-vigil]')) return NodeFilter.FILTER_REJECT;
          const v = node.nodeValue || '';
          const isGenericCanary = /\b(?:VIGIL-[A-Z0-9]+-CANARY(?:-[A-Z0-9_-]+)?|VIGIL-CANARY-[A-Z0-9_-]+|canary\.[a-z0-9]+@vigil-honeypot\.invalid|ak_live_vigil_sec_[a-f0-9]+|ghp_canary_[a-f0-9]+)\b/i.test(v);
          const hit = (canaryValues && Object.values(canaryValues).some(cv => typeof cv === 'string' && cv.length > 8 && v.includes(cv))) ||
            activeList.some(cv => v.includes(cv)) ||
            isGenericCanary;
          return hit ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
        }
      });
      if (walker.nextNode()) return true;
    }
    return false;
  })();
  if (hitNode) {
    honeytokenAlerted = true;
    showNote({
      level: 'dangerous', category: 'honeytoken',
      title: '🪤 Honeytoken triggered — an AI system echoed your decoy credentials',
      detail: 'Invisible bait values planted on this page appeared in visible content. An AI agent or scraper has read and reused them. Treat everything this page shows about you as potentially leaked.',
      force: true
    });
    try { historyStore.add({ original: 'agent honeytoken', fake: 'canary echo detected', type: 'HONEYTOKEN' }); } catch (e) {}
    try { chrome.runtime.sendMessage({ type: 'SESSION_EVENT', event: 'honeytoken' }, () => {}); } catch (e) {}
  }
}

window.addEventListener('vigil:canary-leak', () => {
  honeytokenAlerted = false;
  // Allow the DOM mutation (injected bot bubble) to settle before rescanning
  setTimeout(() => honeytokenPass(), 200);
});

function sentinelPass() {
  if (isWhitelisted || isPaused || !settings.sentinelEnabled || siteMuted()) return;
  const muted = new Set(settings.mutedSignals || []);
  const nodes = [];
  for (const root of scanRoots()) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const p = node.parentElement;
        if (!p) return NodeFilter.FILTER_REJECT;
        if (p.closest('input,textarea') || p.isContentEditable) return NodeFilter.FILTER_REJECT;
        if (p.closest('[data-vigil]')) return NodeFilter.FILTER_REJECT;
        if (p.closest('[data-vigil-webmail]')) return NodeFilter.FILTER_REJECT;
        // Quoted/educational framing is not an attack — articles *about* injection
        // quote the patterns, and code samples contain them verbatim
        if (p.closest('blockquote,pre,code,q,cite')) return NodeFilter.FILTER_REJECT;
        return (node.nodeValue || '').trim().length >= 30 ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    });
    while (walker.nextNode()) nodes.push(walker.currentNode);
  }
  nodes.forEach(node => {
    const text = node.nodeValue.trim();
    const hash = VIGIL.strHash(text);
    if (sentinelAnalyzed.has(hash)) return;
    sentinelAnalyzed.add(hash);
    // Signed content: verify provenance — failed signatures are loud
    if (text.indexOf('-----BEGIN VIGIL SIGNED MESSAGE-----') !== -1) {
      try {
        chrome.runtime.sendMessage({ type: 'SIGN_VERIFY', blockText: text }, (res) => {
          if (res && res.valid === false) showNote({ level: 'dangerous', category: 'signature', title: '✍️ Signed content FAILED verification', detail: 'The signature does not match its content — tampered or forged. (' + (res.reason || 'invalid') + ')', force: true });
        });
      } catch (e) {}
      return;
    }
    // Steganographic invisible watermark provenance check
    if (text.includes('\u2060') || VIGIL_ZW_RUN_RE.test(text)) {
      try {
        chrome.runtime.sendMessage({ type: 'SIGN_VERIFY_WATERMARK', text }, (res) => {
          if (res && res.hasWatermark) {
            if (res.valid && res.trusted) {
              showNote({ level: 'low', category: 'signature', title: '✍️ Verified Provenance', detail: 'Invisible provenance watermark verified by this device\u2019s signing key — content authentic and unaltered.' });
            } else if (res.valid) {
              // Signature intact but the publisher key is foreign: any page can
              // self-watermark, so this proves integrity only, not origin.
              showNote({ level: 'low', category: 'signature', title: '✍️ Watermark intact (self-attested)', detail: 'Invisible watermark signature is valid, but the publisher key is not this device\u2019s — integrity proven, origin NOT verified.' });
            } else {
              showNote({ level: 'dangerous', category: 'signature', title: '🚨 Watermarked content TAMPERED', detail: 'Invisible watermark signature failed verification — content was modified after signing.', force: true });
            }
          }
        });
      } catch (e) {}
    }
    const result = VIGIL_SENTINEL.analyzeMessage(text, muted);
    // Trust-graph escalation: pressure message naming YOUR org = impersonation
    let trustedHits = [];
    if (trustMatchers.length && result.level !== 'none' && result.level !== 'low') {
      trustedHits = trustMatchers.filter(m => new RegExp(m.regex.source, m.regex.flags).test(text)).map(m => m.value);
      if (trustedHits.length) {
        const escalated = VIGIL_SENTINEL.escalateForTrust(result, trustedHits);
        result.level = escalated.level;
        result.signals = escalated.signals;
      }
    }
    // With an AI backend connected, weak AND signal-less texts stay consultable:
    // keyword-free adversarial scams score 'none' here — the model is their
    // only detector. Without a backend, heuristics-only behavior is unchanged.
    const consultable = aiBackendName() && (result.level === 'low' || (result.level === 'none' && text.length >= 40));
    if (!VIGIL_SENTINEL.shouldWarn(result.level, settings.familyMode) && !consultable) return;
    const present = (known) => {
      if (result.level === 'none' && !known) return; // model cleared a weak warning
      let final = result;
      if (known) {
        final = { ...result, level: 'dangerous', signals: [...result.signals, { id: 'known_signature', label: '🐝 Known scam signature', weight: 50 }] };
      }
      const strongest = [...final.signals].sort((a, b) => b.weight - a.weight)[0];
      const title = (final.level === 'dangerous' ? '🚨 Sentinel: likely scam' : '⚠️ Sentinel: suspicious message') + (settings.familyMode ? ' · 👨‍👩‍👧 Family Guardian' : '');
      showNote({
        level: final.level, category: 'sentinel',
        title,
        detail: (VIGIL_SENTINEL.topSignals(final, 2).join(' + ') + ' — ' + final.advice),
        muteId: strongest ? strongest.id : null
      });
      if (!sentinelNoted) {
        sentinelNoted = true;
        try { historyStore.add({ original: 'inbound message', fake: VIGIL_SENTINEL.topSignals(final, 2).join(', '), type: 'SENTINEL' }); } catch (e) {}
      }
      if (final.level === 'dangerous') {
        try { chrome.runtime.sendMessage({ type: 'THREAT_RECORD', hash: sigHash }, () => {}); } catch (e) {}
        try { chrome.runtime.sendMessage({ type: 'SESSION_EVENT', event: 'injection-verdict' }, () => {}); } catch (e) {}
      }
    };
    const sigHash = VIGIL.strHash('sig|' + VIGIL.normalizeForSignature(text));
    // Model-primary classification: when an AI backend is connected, the model
    // gets final say on gray-zone and weak-signal messages (it can escalate a
    // keyword-free scam to dangerous, or suppress a weak false positive).
    // 'none'-level texts are consulted too — that is where reworded attacks
    // hide. Heuristics remain the instant defense when no model is available.
    if (aiBackendName() && sentinelLLMCalls < 8 && (result.level === 'low' || result.level === 'suspicious' || (result.level === 'none' && text.length >= 40))) {
      sentinelLLMCalls++;
      aiClassify(text, 'scam').then((res) => {
        const verdict = res ? res.verdict : 'unclear';
        const confident = res && +res.confidence >= 60;
        if (verdict === 'scam' && (result.level === 'none' || result.level === 'low' || confident)) {
          // Tiered severity + language routing. The multilingual model's scam
          // head overfits machine-translation style: on NATURAL English it
          // false-alarms on ~70% of ordinary messages (measured), so English
          // model-only scam verdicts are IGNORED — heuristics + Ollama remain
          // the English defense until a rebalanced retrain. Non-English text
          // gets the full escalation, tiered: a model-only catch stays at
          // 'suspicious'; a confirmed weak warning goes 'dangerous'.
          if (!VIGIL_SEMANTIC.isEnglishText(text)) {
            result.level = result.level === 'none' ? 'suspicious' : 'dangerous';
            result.signals.push({ id: 'ai_verdict', label: 'AI analysis: scam' + (res.confidence ? ' (' + res.confidence + '%)' : ''), weight: 50 });
          }
        } else if (verdict === 'legit' && confident && result.level === 'suspicious') {
          result.level = 'none'; // model cleared a weak heuristic warning
        }
        // Swarm check for the surviving verdict
        try {
          chrome.runtime.sendMessage({ type: 'THREAT_CHECK', hash: sigHash }, (r2) => present(!!(r2 && r2.known)));
        } catch (e) { present(false); }
      }).catch(() => present(false));
      return;
    }
    // Swarm defense: does this match a signature shared from another install?
    try {
      chrome.runtime.sendMessage({ type: 'THREAT_CHECK', hash: sigHash }, (res) => present(!!(res && res.known)));
    } catch (e) { present(false); }
  });
}

// ---- Training Data Leakage & Copyleft Code Regurgitation (Blueprint #11) ----
const leakageAnalyzed = new Set();
// ---- Blueprint #21: multimodal steganography screening (canvas layers) ----
// Inspects on-page canvases for hidden alpha-channel text, adversarial
// high-frequency noise, and micro-image/aspect-ratio concealment.
const visionSeen = new Set();
let visionScanning = false;

// Blueprint #4: heavy pixel analysis runs in the offscreen document — content
// ships only a downsampled RGBA sample. Falls back to in-content inspection
// when the offscreen document is unavailable.
function inspectCanvasViaOffscreen(canvas) {
  return new Promise((resolve) => {
    try {
      const w = Math.min(canvas.width, 128), h = Math.min(canvas.height, 128);
      const scratch = document.createElement('canvas');
      scratch.width = w; scratch.height = h;
      const sctx = scratch.getContext('2d', { willReadFrequently: true });
      if (!sctx) { resolve(null); return; }
      sctx.drawImage(canvas, 0, 0, w, h);
      const sample = sctx.getImageData(0, 0, w, h);
      chrome.runtime.sendMessage(
        { type: 'COMPUTE_SIMD_FFT', buffer: Array.from(sample.data), width: w, height: h },
        (res) => {
          if (res && res.ok) {
            resolve({
              hasVisualInjection: !!(res.hasStego || res.isAnomalous),
              reason: res.hasStego ? 'Steganographic alpha-channel perturbation detected (offscreen analysis)'
                : (res.isAnomalous ? 'High-frequency adversarial noise perturbation detected (offscreen analysis)' : 'Clean image layer'),
              offscreen: true
            });
          } else {
            resolve(null); // fall back to local analysis
          }
        }
      );
    } catch (e) {
      resolve(null);
    }
  });
}

async function visionPass() {
  if (isWhitelisted || isPaused || siteMuted() || visionScanning) return;
  if (typeof VIGIL_VISION_CANARY === 'undefined' || !VIGIL_VISION_CANARY.inspectCanvasElement) return;
  const canvases = [...document.querySelectorAll('canvas')]
    .filter(c => c.width >= 64 && c.height >= 64)
    .slice(0, 8);
  if (!canvases.length) return;
  visionScanning = true;
  try {
    for (const canvas of canvases) {
      let key = '';
      try { key = `${canvas.width}x${canvas.height}:${canvas.toDataURL().slice(-64)}`; } catch (e) { key = `${canvas.width}x${canvas.height}`; }
      if (visionSeen.has(key)) continue;
      visionSeen.add(key);
      if (visionSeen.size > 200) visionSeen.clear();
      let res = await inspectCanvasViaOffscreen(canvas);
      if (!res) res = await VIGIL_VISION_CANARY.inspectCanvasElement(canvas);
      if (res && res.hasVisualInjection) {
        showNote({
          level: 'suspicious',
          category: 'vision',
          title: '🖼️ Suspicious canvas layer',
          detail: res.reason || 'Hidden visual content detected on this page.',
          muteId: 'vision_canvas'
        });
      }
    }
  } catch (e) {} finally {
    visionScanning = false;
  }
  // Synthetic-media provenance (Blueprint #6): hash inbound images and
  // cross-reference the local known-synthetic blocklist via the daemon
  // (or the identical JS fallback). CORS-tainted images are skipped.
  try {
    const phashSeen = visionPass.phashSeen || (visionPass.phashSeen = new Set());
    const images = [...document.querySelectorAll('img')]
      .filter(i => i.complete && i.naturalWidth >= 64 && i.naturalHeight >= 64)
      .slice(0, 4);
    for (const img of images) {
      const imgKey = 'img:' + (img.currentSrc || img.src || '').slice(-80);
      if (phashSeen.has(imgKey)) continue;
      phashSeen.add(imgKey);
      if (phashSeen.size > 200) phashSeen.clear();
      const w = 32, h = 32;
      const scratch = document.createElement('canvas');
      scratch.width = w; scratch.height = h;
      const sctx = scratch.getContext('2d', { willReadFrequently: true });
      if (!sctx) break;
      sctx.drawImage(img, 0, 0, w, h);
      const px = sctx.getImageData(0, 0, w, h).data;
      const gray = [];
      for (let i = 0; i < px.length; i += 4) {
        gray.push(Math.round(0.299 * px[i] + 0.587 * px[i + 1] + 0.114 * px[i + 2]));
      }
      const res = await new Promise((resolve) => {
        try { chrome.runtime.sendMessage({ type: 'PIMAGE_HASH_CHECK', pixels: gray, width: w, height: h }, (r) => resolve(r)); }
        catch (e) { resolve(null); }
      });
      if (res && res.ok && res.match) {
        showNote({
          level: 'suspicious',
          category: 'vision',
          title: '🧬 Known synthetic media',
          detail: 'This image matches an entry in your local synthetic-media blocklist (distance ' + res.bestDistance + '). Treat its content as untrusted.',
          muteId: 'phash_img'
        });
      }
    }
  } catch (e) { /* provenance pass is best-effort */ }
}

function leakagePass() {
  if (isWhitelisted || isPaused || typeof VIGIL_LEAKAGE === 'undefined') return;
  const blocks = document.querySelectorAll('pre, code, div[class*="code"], div[class*="markdown"]');
  blocks.forEach(block => {
    if (block.closest('[data-vigil]')) return;
    const text = (block.innerText || block.textContent || '').trim();
    if (text.length < 50) return;
    const hash = VIGIL.strHash(text.slice(0, 200));
    if (leakageAnalyzed.has(hash)) return;
    leakageAnalyzed.add(hash);

    const result = VIGIL_LEAKAGE.checkLeakage(text);
    if (result.isLeakage) {
      showLeakageBadge(block, result);
      showNote({
        level: 'suspicious',
        category: 'leakage',
        title: '⚖️ Copyleft / GPL Contamination',
        detail: result.warning || ('Matches ' + result.license + ' training data fingerprint.')
      });
      try {
        chrome.runtime.sendMessage({
          type: 'LEAKAGE_CHECK',
          text,
          site: location.hostname
        });
      } catch (e) {}
    }
  });
}

function showLeakageBadge(element, result) {
  if (element.parentElement && element.parentElement.querySelector('[data-vigil="leakage-badge"]')) return;
  const badge = document.createElement('div');
  badge.setAttribute('data-vigil', 'leakage-badge');
  const simPercent = (result.similarity * 100).toFixed(0);
  badge.style.cssText = 'display:flex;align-items:center;gap:6px;background:#fff3cd;color:#856404;border:1px solid #ffeeba;padding:4px 10px;border-radius:4px;font-size:11px;font-weight:600;margin-bottom:6px;font-family:-apple-system,sans-serif;z-index:10;';
  const badgeSpan = document.createElement('span');
  badgeSpan.textContent = '⚖️ Copyleft Contamination Alert: Matches ';
  const licenseStrong = document.createElement('strong');
  licenseStrong.textContent = result.license;
  badgeSpan.appendChild(licenseStrong);
  badgeSpan.appendChild(document.createTextNode(` (${simPercent}% similarity). Verify license conditions before copying.`));
  badge.appendChild(badgeSpan);
  if (element.parentElement) {
    element.parentElement.insertBefore(badge, element);
  }
}

// ---- Injection Firewall: hidden/prompt-injection detection (AI vs AI) ----

function isInvisibleText(el) {
  const style = getComputedStyle(el);
  if (style.display === 'none' || style.visibility === 'hidden') return true;
  if (parseFloat(style.opacity) === 0) return true;
  if (style.color === 'transparent') return true;
  // color that fades out (rgba(..., 0))
  if (/rgba\([\d\s,.]+,\s*0\)$/.test(style.color)) return true;
  // white-on-white style concealment
  if (style.color === style.backgroundColor && style.backgroundColor !== 'rgba(0, 0, 0, 0)') return true;
  if (parseFloat(style.fontSize) <= 1) return true;
  if (parseInt(style.textIndent, 10) <= -500) return true;
  const rect = el.getBoundingClientRect();
  if (rect.right < -100 || rect.bottom < -100) return true;
  return false;
}

// ---- Webmail profiles: Gmail/Outlook sender extraction + email checks ----

// Blind own-address check (Blueprint #1): a sender email is recognized as the
// user's own by hashing it with the vault salt and comparing against the
// email-kind blind indices — no cleartext email needed in the page.
const userEmailBlindMemo = new Map();
async function isUserEmailBlind(senderEmail) {
  const key = String(senderEmail || '').trim().toLowerCase();
  if (!key || !vaultSalt || !vaultEmailBlindHashes.size) return false;
  if (userEmailBlindMemo.has(key)) return userEmailBlindMemo.get(key);
  try {
    const blindHash = await VIGIL_VAULT.computeBlindHash(vaultSalt, key);
    const isOwn = vaultEmailBlindHashes.has(blindHash);
    if (userEmailBlindMemo.size >= 200) userEmailBlindMemo.clear();
    userEmailBlindMemo.set(key, isOwn);
    return isOwn;
  } catch (e) { return false; }
}

async function webmailPass() {
  if (isWhitelisted || isPaused || !settings.sentinelEnabled || siteMuted()) return;
  const kind = VIGIL_WEBMAIL.detectWebmail(location.hostname);
  if (!kind) return;
  const userEmails = vaultCorpus.filter(e => e.kind === 'email').map(e => e.value);
  const messages = VIGIL_WEBMAIL.extractMessages(document, kind);
  for (const msg of messages) {
    msg.el.setAttribute('data-vigil-webmail', '1');
    const ownByBlind = await isUserEmailBlind(msg.senderEmail);
    if (VIGIL_WEBMAIL.isSentMail(msg, userEmails, location.hash) || ownByBlind) continue;
    const cleanBody = VIGIL_WEBMAIL.stripFooterBoilerplate(msg.bodyText || '');
    const text = ((msg.subject ? msg.subject + '. ' : '') + (cleanBody || msg.el.textContent || '')).trim();
    const hash = VIGIL.strHash('wm|' + msg.senderEmail + '|' + text.slice(0, 300));
    const isRecheck = msg.el.hasAttribute('data-vigil-recheck') || (msg.el.closest && msg.el.closest('[data-vigil-recheck]'));
    if (sentinelAnalyzed.has(hash) && !isRecheck) continue;
    sentinelAnalyzed.add(hash);
    if (isRecheck) {
      msg.el.removeAttribute('data-vigil-recheck');
      if (msg.el.closest) {
        const rc = msg.el.closest('[data-vigil-recheck]');
        if (rc) rc.removeAttribute('data-vigil-recheck');
      }
    }
    const muted = new Set(settings.mutedSignals || []);

    const linkInfo = msg.linkAnalysis || VIGIL_WEBMAIL.analyzeMessageLinks(msg.el, msg.senderEmail);
    const senderHost = (msg.senderEmail && msg.senderEmail.includes('@')) ? msg.senderEmail.split('@')[1] : '';
    const isUserTrusted = !!(settings.trustedSites && settings.trustedSites.some(t => senderHost === t || senderHost.endsWith('.' + t)));

    const isCryptoAligned = VIGIL_WEBMAIL.isCryptographicallyAligned(msg, document, location.hash);
    const isSpam = VIGIL_WEBMAIL.isSpamContext(document, location.hash, msg.el);
    const hasWarn = VIGIL_WEBMAIL.hasProviderWarning(msg.el, document);

    let result = VIGIL_SENTINEL.analyzeMessage(text, muted, {
      isCryptographicallyAligned: isCryptoAligned,
      isSpamFolder: isSpam,
      hasProviderWarning: hasWarn,
      hasMisdirection: linkInfo.hasMisdirection,
      hasShortener: linkInfo.hasShortener,
      userTrustedSender: isUserTrusted
    });
    result = VIGIL_SENTINEL.applySignals(result, VIGIL_WEBMAIL.analyzeSender(msg.senderName, msg.senderEmail));
    let trustedHits = [];
    if (trustMatchers.length && result.level !== 'none' && result.level !== 'low') {
      trustedHits = trustMatchers.filter(m => new RegExp(m.regex.source, m.regex.flags).test(msg.senderName + ' ' + msg.senderEmail)).map(m => m.value);
      if (trustedHits.length) {
        const escalated = VIGIL_SENTINEL.escalateForTrust(result, trustedHits);
        result.level = escalated.level;
        result.signals = escalated.signals;
      }
    }

    if (!VIGIL_SENTINEL.shouldWarn(result.level, settings.familyMode)) continue;

    if (msg.isRow) {
      if (result.level === 'dangerous' && msg.el && msg.el.setAttribute) {
        msg.el.setAttribute('data-vigil-threat', 'dangerous');
      }
      continue;
    }

    const presentMail = () => {
      const strongest = [...result.signals].sort((a, b) => b.weight - a.weight)[0];
      // Plain-English phishing explanation via local AI reasoning
      const aiReason = (typeof VIGIL_WEBMAIL.generatePhishingReasoning === 'function')
        ? VIGIL_WEBMAIL.generatePhishingReasoning(msg, result, linkInfo)
        : null;
      const detail = aiReason
        ? aiReason
        : ((msg.subject ? '"' + msg.subject.slice(0, 60) + '" — ' : '') + VIGIL_SENTINEL.topSignals(result, 2).join(' + ') + ' — ' + result.advice);
      showNote({
        level: result.level, category: 'webmail',
        title: (result.level === 'dangerous' ? '🚨 Email: likely scam' : '⚠️ Email: suspicious') + ' — ' + (msg.senderEmail || msg.senderName || 'unknown sender'),
        detail,
        muteId: strongest ? strongest.id : null,
        force: true
      });
      if (!sentinelNoted) {
        sentinelNoted = true;
        try { historyStore.add({ original: 'email from ' + (msg.senderEmail || 'unknown'), fake: VIGIL_SENTINEL.topSignals(result, 2).join(', '), type: 'WEBMAIL' }); } catch (e) {}
      }
      if (result.level === 'dangerous') {
        try { chrome.runtime.sendMessage({ type: 'THREAT_RECORD', hash }, () => {}); } catch (e) {}
      }
    };
    // Model second opinion on gray-zone emails
    if (result.level === 'suspicious' && aiBackendName() && sentinelLLMCalls < 8) {
      sentinelLLMCalls++;
      aiClassify(text, 'scam').then((res) => {
        if (res && res.verdict === 'scam' && +res.confidence >= 60) {
          result.level = 'dangerous';
          result.signals.push({ id: 'ai_verdict', label: 'AI analysis: scam', weight: 50 });
        }
        presentMail();
      }).catch(() => presentMail());
      continue;
    }
    presentMail();
  }
}

function injectionPass() {
  if (isWhitelisted || isPaused || !settings.injectionFirewall || siteMuted()) return;
  const nodes = [];
  for (const root of scanRoots()) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const p = node.parentElement;
        if (!p) return NodeFilter.FILTER_REJECT;
        if (p.closest('input,textarea') || p.isContentEditable) return NodeFilter.FILTER_REJECT;
        if (p.closest('[data-vigil]')) return NodeFilter.FILTER_REJECT;
        // Articles *about* injection quote the patterns — quoted/code framing is not an attack
        if (p.closest('blockquote,pre,code,q,cite')) return NodeFilter.FILTER_REJECT;
        return (node.nodeValue || '').trim().length >= 15 ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    });
    while (walker.nextNode() && nodes.length < 400) nodes.push(walker.currentNode);
  }
  nodes.forEach(node => {
    const text = node.nodeValue.trim();
    const hash = VIGIL.strHash(text);
    if (injectionSeen.has(hash)) return;
    injectionSeen.add(hash);
    let hidden = false;
    try { hidden = isInvisibleText(node.parentElement); } catch (e) {}
    const result = VIGIL_INJECTION.analyzeInjection(text);
    const presentInjection = (final) => {
      const level = injectionNoted ? 'low' : final.level;
      showNote({
        level, category: 'injection',
        title: (final.level === 'dangerous' ? '🛑 Injection Firewall: hidden AI instructions' : '⚠️ Injection Firewall: AI-directed text') + (hidden ? ' (invisible on page)' : ''),
        detail: (VIGIL_INJECTION.topSignals(final, 2).join(' + ') + ' — ' + final.advice),
        force: !injectionNoted
      });
      if (!injectionNoted) injectionNoted = true;
      try { historyStore.add({ original: hidden ? 'hidden page text' : 'page text', fake: VIGIL_INJECTION.topSignals(final, 2).join(', '), type: 'INJECTION' }); } catch (e) {}
    };
    // Clean text or mild language on the page is not an injection threat
    if (result.level === 'none' || (result.level === 'low' && !hidden)) {
      const canConsult = aiBackendName() && sentinelLLMCalls < 8 && (
        (result.level === 'low' && text.length >= 40) ||
        (hidden && text.length >= 100 && result.signals.length > 0)
      );
      if (!canConsult) return;
      sentinelLLMCalls++;
      aiClassify(text, 'injection').then((res) => {
        if (res && res.verdict === 'manipulation') {
          presentInjection({
            ...result,
            level: 'dangerous',
            signals: [...result.signals, { id: 'inj_ai_verdict', label: 'AI analysis: manipulation attempt' + (res.confidence ? ' (' + res.confidence + '%)' : ''), weight: 50 }]
          });
        }
      }).catch(() => {});
      return;
    }

    // Semantic second opinion on suspicious findings
    if (result.level === 'suspicious' && aiBackendName() && sentinelLLMCalls < 8) {
      sentinelLLMCalls++;
      aiClassify(text, 'injection').then((res) => {
        let final = result;
        if (res && res.verdict === 'manipulation') {
          final = { ...result, level: 'dangerous', signals: [...result.signals, { id: 'inj_ai_verdict', label: 'AI analysis: manipulation attempt', weight: 50 }] };
        }
        presentInjection(final);
      }).catch(() => presentInjection(result));
      return;
    }

    // Only present if the findings actually reached suspicious or dangerous
    if (result.level === 'suspicious' || result.level === 'dangerous') {
      presentInjection(result);
    }
  });
}

// ---- Reality Check: verdict note for image provenance scans ----

function showRealityBanner(findings) {
  if (!findings) return;
  const isAI = findings.verdict === 'ai-generated';
  const sigText = (findings.signals || []).map(s => s.label).join(' • ');
  showNote({
    level: isAI ? 'suspicious' : 'low',
    category: 'reality',
    title: isAI ? '🧬 Reality Check: AI-generated image' + (findings.generator ? ' — ' + findings.generator : '') : '🧬 Reality Check: no AI metadata found',
    detail: (sigText ? sigText + ' — ' : '') + (findings.disclaimer || ''),
    force: true // user-invoked: always show the verdict, never badge-only
  });
}

function showSanitizedToast(originalText) {
  const ct = VIGIL_ENGINE.cleanText(originalText);
  const redactions = [];
  const seen = new Set();

  if (settings.regexEnabled) {
    const r = VIGIL_ENGINE.scanWithRegex(ct);
    if (r && r.redactions) r.redactions.forEach(x => { redactions.push(x); seen.add(x.text); });
  }
  if (typeof VIGIL_SECRETS !== 'undefined') {
    const sec = VIGIL_SECRETS.scanSecrets(ct);
    if (sec && sec.redactions) sec.redactions.forEach(x => { if (!seen.has(x.text)) { redactions.push(x); seen.add(x.text); } });
  }

  const result = VIGIL_FAKE.redactText(originalText, redactions, true);
  const sanitized = result.sanitizedText;

  const card = document.createElement('div');
  card.setAttribute('data-vigil', 'sanitized-toast');
  card.style.cssText = 'position:fixed!important;bottom:20px!important;right:20px!important;z-index:2147483647!important;background:#1a202c!important;color:white!important;padding:16px!important;border-radius:12px!important;box-shadow:0 10px 30px rgba(0,0,0,0.5)!important;max-width:400px!important;font-family:-apple-system,sans-serif!important;border:1px solid #4a5568!important;';

  const cardHeader = document.createElement('div');
  cardHeader.style.cssText = 'font-weight:700;font-size:13px;color:#667eea;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;';
  const cardTitle = document.createElement('span');
  cardTitle.textContent = '✨ VIGIL Sanitized Selection';
  const closeBtn = document.createElement('button');
  closeBtn.id = 'vigil-close-toast';
  closeBtn.style.cssText = 'background:none;border:none;color:#a0aec0;cursor:pointer;font-size:14px;';
  closeBtn.textContent = '✕';
  cardHeader.appendChild(cardTitle);
  cardHeader.appendChild(closeBtn);

  const cardSub = document.createElement('div');
  cardSub.style.cssText = 'font-size:11px;color:#cbd5e0;margin-bottom:8px;';
  cardSub.textContent = `${redactions.length} sensitive item(s) sanitized`;

  const cardTa = document.createElement('textarea');
  cardTa.readOnly = true;
  cardTa.style.cssText = 'width:100%;height:80px;background:#2d3748;color:#e2e8f0;border:1px solid #4a5568;border-radius:6px;padding:8px;font-family:monospace;font-size:11px;resize:none;';
  cardTa.value = sanitized;

  const copyBtn = document.createElement('button');
  copyBtn.id = 'vigil-copy-toast';
  copyBtn.style.cssText = 'width:100%;margin-top:8px;padding:8px;background:#667eea;color:white;border:none;border-radius:6px;cursor:pointer;font-weight:600;font-size:12px;';
  copyBtn.textContent = '📋 Copy Sanitized Text';

  card.appendChild(cardHeader);
  card.appendChild(cardSub);
  card.appendChild(cardTa);
  card.appendChild(copyBtn);
  document.body.appendChild(card);

  document.getElementById('vigil-close-toast').addEventListener('click', () => card.remove());
  document.getElementById('vigil-copy-toast').addEventListener('click', () => {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(sanitized);
    }
    const btn = document.getElementById('vigil-copy-toast');
    if (btn) btn.textContent = 'Copied to Clipboard! ✓';
    setTimeout(() => card.remove(), 1500);
  });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'REALITY_RESULT') showRealityBanner(request.findings);
  if (request.type === 'CONTEXT_SANITIZED_TEXT' && request.text) showSanitizedToast(request.text);
  if (request.type === 'GET_SITE_GRADE') {
    const alerts = (typeof popup !== 'undefined' && popup && popup.activeAlerts) || [];
    const dangerous = alerts.some(a => (a.alerts || []).some(x => x.level === 'dangerous'));
    const suspicious = alerts.some(a => (a.alerts || []).some(x => x.level === 'suspicious'));
    const g = VIGIL.siteGrade({
      https: location.protocol === 'https:',
      trusted: isWhitelisted,
      dangerous,
      suspicious,
      honeytoken: honeytokenAlerted,
      muted: siteMuted()
    });
    sendResponse(g);
  }
  if (request.type === 'GET_PAGE_ALERTS') {
    const alerts = (typeof popup !== 'undefined' && popup && popup.activeAlerts)
      ? popup.activeAlerts.map(a => ({
          id: a.id,
          types: (a.alerts || []).map(x => x.type).join(', '),
          isProtected: !!a.isProtected,
          texts: (a.redactions || []).map(r => r.text).filter(Boolean),
          source: a.source || 'input'
        }))
      : [];
    sendResponse({ alerts, threadPaused: isThreadPaused(), threadKey: getThreadKey() });
  }
  if (request.type === 'DISMISS_PAGE_ALERT') {
    const { id, mode, text } = request;
    const alert = (typeof popup !== 'undefined' && popup && popup.activeAlerts) ? popup.activeAlerts.find(a => a.id === id) : null;
    if (mode === 'THREAD') {
      pauseThread(15 * 60 * 1000);
      trackAnalytics('ignored', []);
    } else if (mode === 'ENTITY' || mode === 'WHITELIST') {
      const entity = text || (alert && alert.redactions && alert.redactions[0]?.text);
      if (entity) {
        whitelistEntity(entity);
        ignoreText(entity, 24 * 60 * 60 * 1000);
      }
      trackAnalytics('ignored', []);
      if (typeof popup !== 'undefined' && popup) popup.dismissAlert(id);
      removeComposerPill();
    } else if (mode === 'PROMPT' || mode === 'ONCE') {
      if (alert && alert.element) {
        allowCurrentPrompt(alert.element);
      } else {
        if (typeof popup !== 'undefined' && popup) popup.dismissAlert(id);
      }
      trackAnalytics('ignored', []);
      removeComposerPill();
    } else {
      if (typeof popup !== 'undefined' && popup) popup.dismissAlert(id);
      removeComposerPill();
    }
    sendResponse({ ok: true });
  }
  if (request.type === 'PROTECT_PAGE_ALERT') {
    if (typeof popup !== 'undefined' && popup && request.id) {
      popup.handleAction(`protect-${request.id}`);
    }
    sendResponse({ ok: true });
  }
  return false;
});

async function scanText(text, element) {
  const ct = VIGIL_ENGINE.cleanText(text);
  const alerts = [], redactions = [], seen = new Set();
  const sensitivity = settings.sensitivity || 'medium';
  
  // Ensure we always return a valid structure
  if (!text || text.length < 5 || isWhitelisted || isPaused || isThreadPaused() || isPromptAllowed(element, text)) {
    return { alerts: [], redactions: [] };
  }
  
  try {
    if (settings.regexEnabled) { 
      const r = VIGIL_ENGINE.scanWithRegex(ct);
      if (r && r.alerts) alerts.push(...r.alerts); 
      if (r && r.redactions) r.redactions.forEach(x => { redactions.push(x); seen.add(x.text); }); 

      if (typeof VIGIL_SECRETS !== 'undefined') {
        const sec = VIGIL_SECRETS.scanSecrets(ct);
        if (sec && sec.alerts) alerts.push(...sec.alerts);
        if (sec && sec.redactions) sec.redactions.forEach(x => { if (!seen.has(x.text)) { redactions.push(x); seen.add(x.text); } });
      }
    }
    
    if (sensitivity === 'medium' || sensitivity === 'high') {
      const ctx = VIGIL_ENGINE.scanWithContext(ct);
      if (ctx && ctx.alerts) {
        ctx.alerts.forEach(a => { 
          if (!alerts.find(x => x.type === a.type && x.source === 'context') && !isTextIgnored(a.text)) 
            alerts.push(a); 
        }); 
      }
      if (ctx && ctx.redactions) {
        ctx.redactions.forEach(r => { 
          if (!seen.has(r.text) && !isTextIgnored(r.text)) { 
            redactions.push(r); 
            seen.add(r.text); 
          } 
        });
      }
    }
    
    if (sensitivity === 'high') {
      const names = VIGIL_ENGINE.findNamesHeuristic(ct);
      if (names && Array.isArray(names)) {
        names.forEach(n => { 
          if (!seen.has(n) && !isTextIgnored(n)) { 
            alerts.push({ type: 'NAME', source: 'heuristic', severity: 'medium' }); 
            redactions.push({ text: n, type: 'NAME' }); 
            seen.add(n); 
          } 
        });
      }
    }
    
    // Vault values are user-taught — always detected, at any sensitivity
    await scanVaultText(ct, alerts, redactions, seen);

    // Tier 2: K-Anonymity & Quasi-Identifier Entropy Evaluation
    if (typeof VIGIL_K_ANONYMITY !== 'undefined' && VIGIL_K_ANONYMITY.auditPrompt) {
      const ka = VIGIL_K_ANONYMITY.auditPrompt(ct);
      if (ka && ka.isHighRisk) {
        alerts.push({
          type: 'K_ANONYMITY_RISK',
          source: 'k-anonymity',
          severity: 'high',
          details: `Re-identification risk ${Math.round(ka.riskScore * 100)}% (Anonymity pool K~${ka.estimatedK})`,
          recommendations: ka.recommendations
        });
        ka.quasiIdentifiers.forEach(q => {
          if (q.raw && !seen.has(q.raw) && !isTextIgnored(q.raw)) {
            redactions.push({ text: q.raw, type: 'QUASI_IDENTIFIER', recommendation: q.recommendation });
            seen.add(q.raw);
          }
        });
      }
    }

    // Context-aware scoring (verified external audit): a bare 10-digit group
    // is usually an order ID, not a phone; mailto/contact/form placements are
    // expected. Detection is never dropped — only severity is re-ranked.
    if (element) {
      const isTel = element.tagName === 'INPUT' && element.type === 'tel';
      const phoneMatches = redactions.filter(r => r.type === 'Phone');
      const anyLikelyPhone = isTel || phoneMatches.some(r => VIGIL_ENGINE.isLikelyPhoneNumber(r.text, ct));
      if (phoneMatches.length && !anyLikelyPhone) alerts.forEach(a => { if (a.type === 'Phone') a.severity = 'low'; });
    }
    // Vault values are user-taught identities — context never downgrades them
    console.log('[dbg] scanText alerts:', JSON.stringify(alerts.map(a => a.type + '/' + a.severity)));
    VIGIL_ENGINE.applyContextMultiplier(alerts.filter(a => a.source !== 'vault'), element);

    if (settings.customPatterns) {
      const customPatterns = VIGIL_ENGINE.parseCustomPatterns(settings.customPatterns);
      const custom = VIGIL_ENGINE.scanWithCustomPatterns(ct, customPatterns);
      if (custom && custom.alerts) {
        custom.alerts.forEach(a => { 
          if (!alerts.find(x => x.type === a.type && x.source === 'custom') && !isTextIgnored(a.text)) 
            alerts.push(a); 
        });
      }
      if (custom && custom.redactions) {
        custom.redactions.forEach(r => { 
          if (!seen.has(r.text) && !isTextIgnored(r.text)) { 
            redactions.push(r); 
            seen.add(r.text); 
          } 
        });
      }
    }
    
  } catch (err) {
    console.warn('[VIGIL] Scan internal error:', err.message);
  }

  // Blueprint #1: remember whether this text produced a local threat signal
  // so the submission-time consensus gate only consults the firewall for
  // texts the deterministic tiers actually flagged.
  try {
    if (alerts.length) {
      const signal = alerts.some(a =>
        a.severity === 'critical' || a.severity === 'high' ||
        a.source === 'injection' || a.source === 'sentinel');
      if (signal) {
        lastScanThreatSignals.set(VIGIL.strHash(String(text || '')), Date.now());
        if (lastScanThreatSignals.size > 200) {
          lastScanThreatSignals.delete(lastScanThreatSignals.keys().next().value);
        }
      }
    }
  } catch (e) { /* signal tracking is best-effort */ }

  return { alerts, redactions };
}

function highlightSensitive(element, redactions) {
  if (!element) return; removeInlineIndicator(element);
  const safeTheme = typeof currentTheme !== 'undefined' ? currentTheme : 'light';
  const color = safeTheme === 'dark' ? '#ef5350' : '#ff4444';
  if (element.isContentEditable || element.getAttribute('contenteditable') === 'true') {
    try {
      redactions.forEach(r => {
        if (!r.text) return;
        const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
        const textNodes = [];
        let n;
        while ((n = walker.nextNode())) {
          if (n.parentNode && n.parentNode.className === 'vigil-sensitive') continue;
          if (n.nodeValue && n.nodeValue.includes(r.text)) textNodes.push(n);
        }
        textNodes.forEach(tn => {
          const idx = tn.nodeValue.indexOf(r.text);
          if (idx !== -1 && tn.parentNode) {
            const matchNode = tn.splitText(idx);
            matchNode.splitText(r.text.length);
            const span = document.createElement('span');
            span.className = 'vigil-sensitive';
            span.style.cssText = `color:${color}!important;font-weight:600;text-decoration:wavy underline ${color};`;
            span.textContent = matchNode.nodeValue;
            matchNode.parentNode.replaceChild(span, matchNode);
          }
        });
      });
    } catch (err) {}
  } else { element.style.transition = 'all 0.3s ease'; element.style.color = color; element.style.borderLeft = '4px solid ' + color; showInlineIndicator(element, ' PII detected', color); }
}
function highlightProtected(element, _replacements) {
  if (!element) return; removeInlineIndicator(element);
  element.style.transition = 'all 0.3s ease'; const pColor = tc('#28a745', '#66bb6a'); element.style.color = pColor; element.style.borderLeft = '4px solid ' + pColor;
  showInlineIndicator(element, '🔒 Protected', pColor);
}
function clearHighlights(element) { if (!element) return; removeInlineIndicator(element); if (element.getAttribute('contenteditable') === 'true') { element.querySelectorAll('.vigil-sensitive, .vigil-protected').forEach(span => { span.replaceWith(document.createTextNode(span.textContent)); }); } else { element.style.borderLeft = ''; element.style.color = ''; } }
function showInlineIndicator(element, text, color) { const rect = element.getBoundingClientRect(); const indicator = document.createElement('div'); indicator.className = 'vigil-inline-indicator'; indicator.textContent = text; indicator.style.cssText = `position:absolute!important;top:${rect.top - 28}px!important;left:${rect.left}px!important;background:${color}!important;color:white!important;padding:4px 10px!important;border-radius:4px!important;font-size:11px!important;font-weight:600!important;z-index:2147483645!important;font-family:-apple-system,sans-serif!important;box-shadow:0 2px 8px ${currentTheme === 'dark' ? 'rgba(0,0,0,0.4)' : 'rgba(0,0,0,0.2)'}!important;pointer-events:none!important;`; document.body.appendChild(indicator); }
function removeInlineIndicator() { document.querySelectorAll('.vigil-inline-indicator').forEach(el => el.remove()); }

function performRedaction(element, redactions) {
  console.log('[dbg] performRedaction:', JSON.stringify(redactions && redactions.map(r => r.text)));
  if (!redactions || redactions.length === 0) return { originalText: null, replacements: [] };
  const cur = element.tagName === 'INPUT' || element.tagName === 'TEXTAREA' ? element.value : (element.innerText || '');
  // Vault entries get their stable per-site pseudonym here (assigned once,
  // persisted, then reused so conversations stay coherent)
  const enriched = redactions.map(r => {
    if (!r.vaultId) return r;
    let fake = vaultPseudos[r.vaultId];
    if (!fake) {
      fake = pickVaultFake(r.vaultKind, r.vaultId, r.text);
      vaultPseudos[r.vaultId] = fake;
      try { chrome.runtime.sendMessage({ type: 'PSEUDO_RECORD', entryId: r.vaultId, site: location.hostname, fake }, () => {}); } catch (e) {}
    }
    const opaquePointer = r.opaquePointer || ((typeof VIGIL_FAKE !== 'undefined' && VIGIL_FAKE.createOpaquePointer)
      ? VIGIL_FAKE.createOpaquePointer(r.vaultKind, r.vaultId)
      : `{{PTR:VAULT_${r.vaultId.slice(0, 8)}}}`);
    return { ...r, vaultFake: fake, opaquePointer };
  });
  const result = VIGIL_FAKE.redactText(cur, enriched, settings.useFakeData);
  const txt = result.text; const reps = result.replacements; const orig = cur;
  if (txt !== orig) {
    if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') {
      const valueProto = element.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
      const nativeInputValueSetter = Object.getOwnPropertyDescriptor(valueProto, 'value').set;
      if (nativeInputValueSetter) nativeInputValueSetter.call(element, txt);
      else element.value = txt;
      element.dispatchEvent(new Event('input', { bubbles: true }));
    } else {
      if (document.queryCommandSupported && document.queryCommandSupported('insertText')) {
        element.focus();
        try {
          const sel = window.getSelection();
          const range = document.createRange();
          range.selectNodeContents(element);
          sel.removeAllRanges();
          sel.addRange(range);
          document.execCommand('insertText', false, txt);
        } catch (e) {
          element.innerText = txt;
        }
      } else {
        element.innerText = txt;
      }
      element.dispatchEvent(new Event('input', { bubbles: true }));
    }
    reps.forEach(r => {
      historyStore.add({ ...r, site: window.location.hostname });
      if (r.fake && r.original && r.fake !== r.original) {
        sessionAdHocPseudos.set(r.fake, r.original);
        if (typeof VIGIL_REHYDRATION !== 'undefined' && VIGIL_REHYDRATION) {
          VIGIL_REHYDRATION.recordSubstitution(r.fake, r.original);
        }
        saveLearnedExemplar(r.original, r.fake, r.type);
      }
    });
    recordLoraCorrection(reps.map(r => r.original || r.text), 1);
    return { originalText: orig, replacements: reps };
  }
  return { originalText: null, replacements: [] };
}
function escapeHtml(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

// Blueprint #16 data input: user accept/reject decisions on detections are
// recorded as LoRA corrections (label 1 = confirmed threat, 0 = false
// positive). The background vectorizes the text and stores the sample.
function recordLoraCorrection(texts, label) {
  try {
    const text = (texts || []).filter(Boolean).join('. ').slice(0, 2000);
    if (text.length >= 3) chrome.runtime.sendMessage({ type: 'LORA_RECORD_CORRECTION', text, label }, () => {});
  } catch (e) {}
}

function ensureVigilStyles() {
  if (document.getElementById('vigil-animations')) return;
  const style = document.createElement('style');
  style.id = 'vigil-animations';
  style.textContent = `
    @keyframes vigil-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
    @keyframes vigil-pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.15); } }
    @keyframes vigil-fadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
    .vigil-spin-ring { transform-origin: 16px 16px; animation: vigil-spin 8s linear infinite; }
    [data-vigil="unified-popup"], [data-vigil="unified-popup"] * {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
      box-sizing: border-box !important;
      -webkit-font-smoothing: antialiased !important;
    }
  `;
  (document.head || document.documentElement).appendChild(style);
}

function getVigilSpinningLogo(size = 16) {
  ensureVigilStyles();
  return `<svg class="vigil-spin-logo" width="${size}" height="${size}" viewBox="0 0 32 32" style="display:inline-block;vertical-align:middle;flex-shrink:0;">
    <defs>
      <linearGradient id="vigilSpinGrad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#10b981" />
        <stop offset="50%" stop-color="#06b6d4" />
        <stop offset="100%" stop-color="#3b82f6" />
      </linearGradient>
      <radialGradient id="vigilSpinGlow" cx="50%" cy="50%" r="50%">
        <stop offset="0%" stop-color="#10b981" stop-opacity="0.6"/>
        <stop offset="100%" stop-color="#06b6d4" stop-opacity="0"/>
      </radialGradient>
    </defs>
    <circle cx="16" cy="16" r="14" fill="url(#vigilSpinGlow)" />
    <circle cx="16" cy="16" r="13" stroke="url(#vigilSpinGrad)" stroke-width="1.3" stroke-dasharray="3 2" style="transform-origin:16px 16px;animation:vigil-spin 8s linear infinite;" />
    <path d="M16 4 L26 10 L26 22 L16 28 L6 22 L6 10 Z" stroke="url(#vigilSpinGrad)" stroke-width="1.4" fill="none" stroke-linejoin="round"/>
    <path d="M16 8 L22 12 V18 C22 22 16 24.5 16 24.5 C16 24.5 10 22 10 18 V12 L16 8 Z" fill="url(#vigilSpinGrad)"/>
    <circle cx="16" cy="15" r="2" fill="#ffffff" />
  </svg>`;
}

function getVigilTrustIcon(size = 14) {
  return `<svg class="vigil-trust-icon" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:middle;flex-shrink:0;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`;
}

class VIGILPopup {
  constructor() { this.state = 'minimized'; this.activeAlerts = []; this.isMaximized = false; this.position = { right: 20, bottom: 20 }; this.build(); this.loadPosition(); }
  async loadPosition() { return new Promise((resolve) => { chrome.storage.local.get(['popupPosition'], (result) => { if (result.popupPosition) { this.position = result.popupPosition; this.render(); } resolve(); }); }); }
  savePosition() { chrome.storage.local.set({ popupPosition: this.position }); }
  build() {
    this.container = document.createElement('div');
    this.container.setAttribute('data-vigil', 'unified-popup');
    this.container.style.cssText = 'position:fixed!important;z-index:2147483647!important;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif!important;';
    ensureVigilStyles();
    document.body.appendChild(this.container);
    this.render();
  }
  showAlert(alerts, redactions, element, originalText, replacements = null, source = 'input') {
    if (isThreadPaused()) return;
    const curText = element ? (element.value || element.innerText || '') : (originalText || '');
    if (isPromptAllowed(element, curText)) return;
    const filteredAlerts = alerts.filter(a => !a.text || !isTextIgnored(a.text));
    const filteredRedactions = redactions.filter(r => !isTextIgnored(r.text));
    if (filteredAlerts.length === 0) {
      removeComposerPill();
      return;
    }
    const renderSig = source + '|' + filteredAlerts.map(a => a.type + a.severity).join(',') + '|' + filteredRedactions.map(r => r.text).join(',');
    if (renderSig === this.lastRenderSig && this.state === 'alert') return;
    this.lastRenderSig = renderSig;
    const newAlert = { id: Date.now() + Math.random(), alerts: filteredAlerts, redactions: filteredRedactions, timestamp: new Date(), replacements: replacements || [], source, element, originalText };
    this.activeAlerts = this.activeAlerts.filter(a => a.source !== source);
    this.activeAlerts.push(newAlert);
    if (this.activeAlerts.length > 10) this.activeAlerts.shift();
    trackAnalytics('triggered', filteredAlerts.map(a => a.type));
    this.state = 'alert';
    this.render();
    if (element && source === 'input') {
      renderComposerPill(element, newAlert);
    }
  }
  dismissAlert(alertId = null) {
    if (alertId) this.activeAlerts = this.activeAlerts.filter(a => a.id !== alertId);
    else this.activeAlerts = [];
    this.lastRenderSig = null;
    this.state = this.activeAlerts.length > 0 ? this.state : 'minimized';
    if (this.activeAlerts.length === 0) removeComposerPill();
    this.render();
  }
  minimize() { this.state = 'minimized'; this.render(); }
  expand() { this.state = this.activeAlerts.length > 0 ? 'alert' : 'idle'; this.render(); }
  maximize() { this.isMaximized = true; this.render(); }
  restore() { this.isMaximized = false; this.render(); }
  getPopupWidth() { return '360px'; }
  getMaxHeight() { return '520px'; }
  getFontSize() { return '12px'; }
  renderMinimized() {
    const safeRight = Number.isFinite(this.position?.right) ? Math.max(10, Math.min(window.innerWidth - 140, this.position.right)) : 20;
    const safeBottom = Number.isFinite(this.position?.bottom) ? Math.max(10, Math.min(window.innerHeight - 50, this.position.bottom)) : 16;
    const alertCount = this.activeAlerts.reduce((sum, a) => sum + (a.alerts ? a.alerts.length : 1), 0);
    const hasAlert = alertCount > 0;
    const isPausedNow = isPaused;

    let pillContent = '';
    let pillBg = 'rgba(15, 23, 42, 0.88)';
    let pillBorder = 'rgba(255, 255, 255, 0.14)';
    let pillColor = '#f8fafc';

    if (isPausedNow) {
      pillBg = 'rgba(71, 85, 105, 0.88)';
      pillContent = '<span style="font-size:12px;">⏸️</span> <span style="font-weight:600;font-size:11.5px;letter-spacing:0.2px;">Vigil Paused</span>';
    } else if (hasAlert) {
      pillBg = 'rgba(24, 24, 27, 0.94)';
      pillBorder = 'rgba(245, 158, 11, 0.45)';
      pillContent = `${getVigilSpinningLogo(14)} <span style="font-weight:700;font-size:11.5px;color:#fbbf24;">${alertCount} Protected</span> <span style="font-size:10px;opacity:0.8;">▾</span>`;
    } else {
      pillContent = `${getVigilSpinningLogo(14)} <span style="font-weight:600;font-size:11.5px;letter-spacing:0.2px;opacity:0.92;">Vigil: Protected</span>`;
    }

    this.container.innerHTML = `
      <div data-vigil-part="minimized" style="height:28px;padding:0 12px;background:${pillBg};border:1px solid ${pillBorder};border-radius:14px;display:flex;align-items:center;gap:6px;cursor:pointer;box-shadow:0 4px 16px rgba(0,0,0,0.3);color:${pillColor};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);user-select:none;transition:all 0.2s ease;">
        ${pillContent}
      </div>
    `;
    this.container.style.cssText = `position:fixed!important;z-index:2147483647!important;right:${safeRight}px!important;bottom:${safeBottom}px!important;left:auto!important;top:auto!important;display:block!important;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif!important;`;
    const mini = this.container.querySelector('[data-vigil-part="minimized"]');
    if (mini) {
      mini.addEventListener('click', () => this.expand());
      mini.addEventListener('mouseenter', () => { mini.style.transform = 'translateY(-1px)'; mini.style.boxShadow = '0 6px 20px rgba(0,0,0,0.4)'; });
      mini.addEventListener('mouseleave', () => { mini.style.transform = 'none'; mini.style.boxShadow = '0 4px 16px rgba(0,0,0,0.3)'; });
    }
  }
  renderFull() {
    const popupWidth = this.getPopupWidth();
    const popupHeight = this.getMaxHeight();
    const popupRadius = '14px';
    const actualWidth = this.isMaximized ? '100%' : popupWidth;
    const actualHeight = this.isMaximized ? '100%' : 'auto';
    const actualMaxHeight = this.isMaximized ? '100%' : popupHeight;
    const actualRadius = this.isMaximized ? '10px' : popupRadius;
    const safeRight = Number.isFinite(this.position?.right) ? Math.max(10, Math.min(window.innerWidth - 60, this.position.right)) : 20;
    const safeBottom = Number.isFinite(this.position?.bottom) ? Math.max(10, Math.min(window.innerHeight - 60, this.position.bottom)) : 20;
    const isAlert = this.activeAlerts.length > 0;
    
    let headerColor = 'linear-gradient(135deg, #1e293b 0%, #0f172a 100%)';
    let headerTitle = 'VIGIL GUARDIAN';
    if (isPaused) {
      headerColor = '#475569';
      headerTitle = 'Vigil Paused';
    } else if (isAlert) {
      const high = this.activeAlerts.some(a => a.alerts.some(x => x.severity === 'high' || x.severity === 'critical'));
      if (high) {
        headerColor = 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)';
        headerTitle = 'Vigil Security Alert';
      } else {
        headerColor = 'linear-gradient(135deg, #d97706 0%, #b45309 100%)';
        headerTitle = 'Vigil Privacy Shield';
      }
    }
    
    const popupBg = 'rgba(24, 24, 27, 0.96)';
    const popupBorder = 'rgba(255, 255, 255, 0.12)';
    const bodyBg = 'transparent';
    const bodyText = '#f4f4f5';
    const bodySecondary = '#a1a1aa';
    const cardBg = 'rgba(255, 255, 255, 0.04)';
    const cardBorder = 'rgba(255, 255, 255, 0.08)';
    const repBg = 'rgba(0, 0, 0, 0.25)';
    const repArrow = '#6b7280';
    const btnBg = 'rgba(255, 255, 255, 0.06)';
    const btnBorder = 'rgba(255, 255, 255, 0.12)';
    const btnText = '#e4e4e7';
    const btnSecondaryBg = 'rgba(255, 255, 255, 0.04)';
    const snoozeBtnBg = 'rgba(255, 255, 255, 0.06)';
    const snoozeBtnText = '#e4e4e7';
    const footerBg = 'rgba(15, 23, 42, 0.6)';
    const footerBorder = 'rgba(255, 255, 255, 0.08)';

    let body = '';
    const alertCount = this.activeAlerts.reduce((sum, a) => sum + (a.alerts ? a.alerts.length : 1), 0);

    const statusBanner = isAlert
      ? `<div style="margin-bottom:12px;padding:10px 12px;background:rgba(245,158,11,0.12);border:1px solid rgba(245,158,11,0.25);border-radius:8px;font-size:11.5px;color:#fbbf24;display:flex;align-items:center;gap:8px;">${getVigilSpinningLogo(18)}<div><strong>SESSION STATUS: SECURED</strong><div style="color:#d1d5db;font-size:11px;margin-top:2px;">${alertCount} sensitive item(s) detected and shielded</div></div></div>`
      : `<div style="margin-bottom:12px;padding:10px 12px;background:rgba(16,185,129,0.12);border:1px solid rgba(16,185,129,0.25);border-radius:8px;font-size:11.5px;color:#34d399;display:flex;align-items:center;gap:8px;">${getVigilSpinningLogo(18)}<div><strong>SESSION STATUS: SECURED</strong><div style="color:#d1d5db;font-size:11px;margin-top:2px;">All shields active • 0 unmasked leaks</div></div></div>`;

    let sensitiveContent = '';
    if (isAlert && this.activeAlerts.length > 0) {
      const alertCards = this.activeAlerts.map((alert, idx) => {
        const isClipboard = alert.source === 'clipboard';
        const contextLabel = isClipboard ? 'Clipboard' : 'Input';
        const details = alert.alerts.map(a => {
          const color = a.severity === 'high' || a.severity === 'critical' ? '#ef4444' : '#f59e0b';
          return `<div style="display:flex;align-items:center;gap:6px;padding:2px 0;font-size:11.5px;"><span style="width:6px;height:6px;border-radius:50%;background:${color};"></span><span style="font-weight:600;color:${bodyText};">${escapeHtml(a.type)}</span></div>`;
        }).join('');

        let replacementsHTML = '';
        if (alert.replacements && alert.replacements.length > 0) {
          const items = alert.replacements.map(r => {
            return `<div style="background:${repBg};padding:5px 8px;border-radius:6px;margin-bottom:4px;font-size:11px;"><div style="display:flex;align-items:center;gap:6px;"><span style="color:#ef4444;text-decoration:line-through;word-break:break-all;flex:1;">${escapeHtml(r.original)}</span><span style="color:${repArrow};">→</span><span style="color:#10b981;font-weight:600;word-break:break-all;flex:1;">${escapeHtml(r.fake)}</span></div></div>`;
          }).join('');
          replacementsHTML = `<div style="margin-top:6px;padding-top:6px;border-top:1px dashed ${cardBorder};">${items}</div>`;
        }

        let actions = '';
        if (alert.element) {
          if (!alert.isProtected) {
            actions += `<button data-vigil-action="protect-${alert.id}" style="padding:4px 10px;background:#10b981;color:white;border:none;border-radius:5px;cursor:pointer;font-weight:600;font-size:10.5px;">⚡ Protect</button>`;
          } else if (alert.originalText) {
            actions += `<button data-vigil-action="undo-${alert.id}" style="padding:4px 8px;background:${btnSecondaryBg};color:#818cf8;border:1px solid ${btnBorder};border-radius:5px;cursor:pointer;font-weight:500;font-size:10.5px;">Undo</button>`;
          }
          actions += `<button data-vigil-action="ignore-${alert.id}" style="padding:4px 8px;background:${btnSecondaryBg};color:${bodySecondary};border:1px solid ${btnBorder};border-radius:5px;cursor:pointer;font-weight:500;font-size:10.5px;">Ignore</button>`;
        }
        if (isClipboard) {
          actions += `<button data-vigil-action="clear-clipboard-${alert.id}" style="padding:4px 8px;background:${btnSecondaryBg};color:#818cf8;border:1px solid ${btnBorder};border-radius:5px;cursor:pointer;font-weight:500;font-size:10.5px;">Clear</button>`;
        }
        actions += `<button data-vigil-action="dismiss-${alert.id}" style="padding:4px 6px;background:${btnBg};color:${btnText};border:1px solid ${btnBorder};border-radius:5px;cursor:pointer;font-weight:600;font-size:10.5px;">×</button>`;

        return `<div style="background:${cardBg};border:1px solid ${cardBorder};border-radius:8px;padding:10px 12px;margin-bottom:8px;font-size:11.5px;"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;"><div style="display:flex;align-items:center;gap:6px;"><span style="font-weight:700;color:${bodySecondary};font-size:10px;">#${idx + 1}</span><span style="font-size:11px;color:${bodySecondary};">${contextLabel}</span>${alert.isProtected ? '<span style="font-size:9.5px;color:#10b981;background:rgba(16,185,129,0.12);padding:1px 6px;border-radius:4px;font-weight:600;">✅ Shielded</span>' : ''}</div></div><div>${details}</div>${replacementsHTML}<div style="display:flex;gap:4px;margin-top:8px;justify-content:flex-end;flex-wrap:wrap;">${actions}</div></div>`;
      }).join('');
      sensitiveContent = alertCards;
    } else {
      sensitiveContent = `<div style="color:${bodySecondary};font-size:11.5px;padding:6px 0;">✓ No sensitive data exposed in active inputs.</div>`;
    }

    const integritySection = `
      <div style="margin-top:10px;padding:10px 12px;background:${cardBg};border:1px solid ${cardBorder};border-radius:8px;">
        <div style="font-size:10px;font-weight:700;color:${bodySecondary};text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">⚡ Prompt & Site Integrity</div>
        <div style="display:flex;flex-direction:column;gap:4px;font-size:11px;color:#d1d5db;">
          <div><span style="color:#10b981;font-weight:700;">✓</span> Zero-width characters stripped</div>
          <div><span style="color:#10b981;font-weight:700;">✓</span> Legitimate site (no spoofing)</div>
          <div><span style="color:#10b981;font-weight:700;">✓</span> Injection firewall active</div>
        </div>
      </div>
    `;

    body = `
      <div style="padding:14px;background:${bodyBg};color:${bodyText};flex:1;overflow-y:auto;max-height:420px;">
        ${statusBanner}
        <div style="font-size:10px;font-weight:700;color:${bodySecondary};text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">🔒 Sensitive Data</div>
        ${sensitiveContent}
        ${integritySection}
      </div>
    `;

    const snoozeButtons = isPaused
      ? '<button data-vigil-action="resume" style="flex:2;padding:6px 12px;background:#10b981;color:white;border:none;border-radius:6px;cursor:pointer;font-size:11px;font-weight:600;">▶️ Resume</button>'
      : `<div style="flex:2;display:flex;gap:4px;"><button data-vigil-action="pause-5" style="flex:1;padding:5px 8px;background:${snoozeBtnBg};color:${snoozeBtnText};border:1px solid ${footerBorder};border-radius:6px;cursor:pointer;font-size:10.5px;font-weight:600;" title="Pause 5 min">5m</button><button data-vigil-action="pause-60" style="flex:1;padding:5px 8px;background:${snoozeBtnBg};color:${snoozeBtnText};border:1px solid ${footerBorder};border-radius:6px;cursor:pointer;font-size:10.5px;font-weight:600;" title="Pause 1 hour">1h</button></div>`;

    const svgTrust = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:middle;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>';
    const svgGear = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>';
    const footer = `<div style="padding:10px 14px;background:${footerBg};border-top:1px solid ${footerBorder};display:flex;gap:6px;align-items:center;flex-shrink:0;">${snoozeButtons}<div style="flex:1;"></div><div style="display:flex;gap:6px;align-items:center;"><button data-vigil-action="trust-site" style="background:${snoozeBtnBg};color:#818cf8;border:1px solid ${footerBorder};width:28px;height:28px;border-radius:6px;cursor:pointer;display:flex;align-items:center;justify-content:center;" title="Trust site">${svgTrust}</button><button data-vigil-action="settings" style="background:${snoozeBtnBg};color:#818cf8;border:1px solid ${footerBorder};width:28px;height:28px;border-radius:6px;cursor:pointer;display:flex;align-items:center;justify-content:center;" title="Settings">${svgGear}</button></div></div>`;

    const minIcon = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';
    
    this.container.innerHTML = `<div data-vigil-part="full" style="width:${actualWidth};height:${actualHeight};max-height:${actualMaxHeight};background:${popupBg};border-radius:${actualRadius};box-shadow:0 20px 60px rgba(0,0,0,0.55);overflow:hidden;border:1px solid ${popupBorder};display:flex;flex-direction:column;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif!important;"><div data-vigil-part="header" style="background:${headerColor};color:white;padding:10px 14px;display:flex;justify-content:space-between;align-items:center;cursor:${this.isMaximized ? 'default' : 'grab'};flex-shrink:0;"><div style="display:flex;align-items:center;gap:6px;">${getVigilSpinningLogo(18)}<span style="font-size:12.5px;font-weight:700;letter-spacing:-0.2px;">${headerTitle}</span></div><div style="display:flex;gap:6px;align-items:center;"><button data-vigil-action="minimize" style="background:rgba(255,255,255,0.15);color:white;border:none;width:22px;height:22px;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;" title="Close">${minIcon}</button></div></div>${body}${footer}</div>`;
    this.container.style.cssText = `position:fixed!important;z-index:2147483647!important;right:${safeRight}px!important;bottom:${safeBottom}px!important;left:auto!important;top:auto!important;display:block!important;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif!important;`;
    this.attachHandlers();
  }

  attachHandlers() {
    const header = this.container.querySelector('[data-vigil-part="header"]'); if (header) { header.addEventListener('mousedown', (e) => { if (this.isMaximized) return; if (e.target.tagName === 'BUTTON') return; if (e.target.closest('[data-vigil-action]')) return; this.isDragging = true; const rect = this.container.getBoundingClientRect(); this.dragOffset = { x: e.clientX - rect.left, y: e.clientY - rect.top }; this.container.style.cursor = 'grabbing'; e.preventDefault(); }); }
    this.container.querySelectorAll('[data-vigil-action]').forEach(btn => { const action = btn.getAttribute('data-vigil-action'); btn.addEventListener('click', (e) => { e.stopPropagation(); this.handleAction(action); }); });
  }
  render() { if (this.state === 'minimized') this.renderMinimized(); else this.renderFull(); }
  onDrag(e) { if (!this.isDragging) return; this.container.style.left = (e.clientX - this.dragOffset.x) + 'px'; this.container.style.top = (e.clientY - this.dragOffset.y) + 'px'; this.container.style.right = 'auto'; this.container.style.bottom = 'auto'; }
  endDrag() { if (this.isDragging) { this.isDragging = false; this.container.style.cursor = ''; const rect = this.container.getBoundingClientRect(); this.position = { right: window.innerWidth - rect.right, bottom: window.innerHeight - rect.bottom }; this.savePosition(); } }
  async handleAction(action) {
    console.log('[dbg] handleAction:', action.slice(0, 30));
    if (action.startsWith('protect-')) {
      trackAnalytics('protected', []);
      const id = parseFloat(action.substring(8)); const alert = this.activeAlerts.find(a => a.id === id);
      if (alert && alert.element && alert.redactions) {
        const result = performRedaction(alert.element, alert.redactions);
        if (result && result.originalText) {
          highlightProtected(alert.element, result.replacements); alert.originalText = result.originalText; alert.replacements = result.replacements;
          alert.isProtected = true;
          recordLoraCorrection(alert.redactions.map(r => r.text), 1);
          const newText = alert.element.tagName === 'INPUT' || alert.element.tagName === 'TEXTAREA' ? alert.element.value : (alert.element.innerText || '');
          if (typeof lastScannedText !== 'undefined') lastScannedText = newText;
        }
      }
      this.lastRenderSig = null;
      this.render(); return;
    }
    if (action.startsWith('vault-prompt-')) {
      const id = parseFloat(action.substring('vault-prompt-'.length)); const alert = this.activeAlerts.find(a => a.id === id);
      if (alert && alert.redactions) {
        alert.redactions.forEach(r => {
          const kind = r.type === 'Email' ? 'email' : r.type === 'Phone' ? 'phone' : r.type === 'NAME' ? 'name' : null;
          if (kind && r.text && r.text.length >= 2) { try { chrome.runtime.sendMessage({ type: 'VAULT_ADD', kind, value: r.text }, () => {}); } catch (e) {} }
        });
        refreshVault();
      }
      localStorage.setItem('vigil_vault_prompt_done', '1');
      const btn = document.querySelector('[data-vigil-action="vault-prompt-' + id + '"]'); if (btn) { btn.textContent = 'Added ✓'; btn.disabled = true; }
      return;
    }
    if (action.startsWith('ignore-')) { trackAnalytics('ignored', []); const id = parseFloat(action.substring(7)); const alert = this.activeAlerts.find(a => a.id === id); if (alert && alert.redactions) { const ignoredNow = alert.redactions.map(r => r.text); recordLoraCorrection(ignoredNow, 0); ignoredNow.forEach(r => ignoreText(r)); if (alert.element) clearHighlights(alert.element); this.dismissAlert(id);
      // Reversibility (verified external audit UX-C): a transient toast lets
      // the user undo an ignore within the TTL window
      const host = location.hostname;
      const toast = document.createElement('div'); toast.setAttribute('data-vigil', 'undo-toast');
      toast.style.cssText = 'position:fixed!important;bottom:20px!important;left:50%!important;transform:translateX(-50%)!important;background:#1f2937!important;color:#f9fafb!important;padding:10px 16px!important;border-radius:10px!important;z-index:2147483647!important;font-family:-apple-system,sans-serif!important;font-size:12.5px!important;display:flex!important;gap:12px!important;align-items:center!important;box-shadow:0 8px 24px rgba(0,0,0,0.35)!important;';
      const toastSpan = document.createElement('span');
      toastSpan.textContent = 'Ignored for 5 minutes on this site';
      toast.appendChild(toastSpan);
      const undoBtn = document.createElement('button'); undoBtn.textContent = 'Undo'; undoBtn.style.cssText = 'background:none;border:none;color:#8ab4ff;font-weight:700;cursor:pointer;font-size:12.5px;padding:0;';
      undoBtn.onclick = (e) => { e.stopPropagation(); const hostMap = ignoredTexts.get(host); if (hostMap) ignoredNow.forEach(txt => hostMap.delete(txt)); toast.remove(); };
      toast.appendChild(undoBtn); document.body.appendChild(toast);
      setTimeout(() => toast.remove(), 5000);
    } return; }
    if (action.startsWith('undo-')) { const id = parseFloat(action.substring(5)); const alert = this.activeAlerts.find(a => a.id === id); if (alert && alert.element && alert.originalText) { if (alert.element.tagName === 'INPUT' || alert.element.tagName === 'TEXTAREA') alert.element.value = alert.originalText; else if (alert.element.innerText !== undefined) alert.element.innerText = alert.originalText; clearHighlights(alert.element); this.lastRenderSig = null; this.dismissAlert(id); } return; }
    if (action.startsWith('dismiss-')) { this.dismissAlert(parseFloat(action.substring(8))); return; }
    if (action.startsWith('clear-clipboard-')) { try { const a = this.activeAlerts.find(x => x.id === parseFloat(action.substring(16))); const fakes = a && a.replacements && a.replacements.length ? a.replacements.map(r => r.fake).join(', ') : '[CLEARED BY VIGIL]'; await navigator.clipboard.writeText(fakes); this.dismissAlert(parseFloat(action.substring(16))); } catch (e) {} return; }
    if (action.startsWith('pause-')) { const duration = action.substring(6); let ms = 0; if (duration === '5') ms = 5 * 60 * 1000; else if (duration === '60') ms = 60 * 60 * 1000; isPaused = true; if (pauseTimer) clearTimeout(pauseTimer); if (ms > 0) pauseTimer = setTimeout(() => { isPaused = false; if (popup) popup.render(); }, ms); this.render(); return; }
    switch (action) {
      case 'minimize': this.minimize(); break; case 'maximize': this.maximize(); break; case 'restore': this.restore(); break;
      case 'resume': isPaused = false; if (pauseTimer) clearTimeout(pauseTimer); this.render(); break;
      case 'settings': chrome.runtime.sendMessage({ type: 'OPEN_OPTIONS' }); break;
      case 'export': historyStore.exportJSON(); break; case 'export-csv': historyStore.exportCSV(); break;
      case 'trust-site': {
        const host = window.location.hostname;
        if (!settings.trustedSites.includes(host)) {
          settings.trustedSites.push(host);
          chrome.runtime.sendMessage({ type: 'SAVE_TRUSTED_SITES', sites: settings.trustedSites });
          
          // Show confirmation toast
          const toast = document.createElement('div');
          toast.style.cssText = 'position:fixed!important;bottom:100px!important;right:20px!important;background:#28a745!important;color:white!important;padding:12px 20px!important;border-radius:8px!important;font-size:13px!important;font-weight:600!important;z-index:2147483647!important;font-family:-apple-system,sans-serif!important;box-shadow:0 4px 12px rgba(0,0,0,0.3)!important;animation:vigil-fadeIn 0.3s ease-out!important;';
          toast.textContent = '✅ ' + host + ' added to trusted sites';
          document.body.appendChild(toast);
          setTimeout(() => toast.remove(), 3000);
        }
        isWhitelisted = true;
        this.minimize();
        break; }
    }
  }
}
let popup;

function setupPasteGuardian() {
  document.addEventListener('paste', async (e) => {
    if (isWhitelisted || isPaused) return;
    const target = e.target;
    if (!target || (target.tagName !== 'INPUT' && target.tagName !== 'TEXTAREA' && target.getAttribute && target.getAttribute('contenteditable') !== 'true')) return;
    let pastedText = '';
    if (e.clipboardData && e.clipboardData.getData) pastedText = e.clipboardData.getData('text/plain') || '';
    if (!pastedText || pastedText.length < 5) return;
    try {
      const { alerts, redactions } = await scanText(pastedText, target);
      if (alerts.length > 0) {
        if (settings.autoProtectPaste) {
          e.preventDefault();
          const result = VIGIL_FAKE.redactText(pastedText, redactions, settings.useFakeData);
          if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA') {
            const valueProto = target.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
            const nativeSetter = Object.getOwnPropertyDescriptor(valueProto, 'value').set;
            if (nativeSetter) nativeSetter.call(target, result.text);
            else target.value = result.text;
            target.dispatchEvent(new Event('input', { bubbles: true }));
          } else {
            if (document.queryCommandSupported && document.queryCommandSupported('insertText')) {
              document.execCommand('insertText', false, result.text);
            } else {
              target.innerText = result.text;
            }
            target.dispatchEvent(new Event('input', { bubbles: true }));
          }
        }
        const markedAlerts = alerts.map(a => ({ ...a, source: 'clipboard:' + a.source }));
        if (popup) popup.showAlert(markedAlerts, redactions, target, pastedText, null, 'clipboard');
        renderComposerPill(target, { alerts, redactions, element: target, isProtected: false });
        showNote({ level: 'suspicious', category: 'clipboard', title: '📋 Clipboard Guard: Sensitive data detected', detail: 'Pasted payload contains protected patterns. Sanitize with one click.', force: true });
      }
    } catch (err) {}
  }, true);
}
async function monitorClipboard() { setupPasteGuardian(); }
let lastScannedText = '', scanDebounce = null, _scanInterval = null, lastActiveTarget = null;
function getActiveInputElement() {
  let active = document.activeElement;
  while (active && active.shadowRoot && active.shadowRoot.activeElement) active = active.shadowRoot.activeElement;
  if (active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA')) {
    lastActiveTarget = active;
    return active;
  }
  if (active && (active.isContentEditable || active.getAttribute('contenteditable') === 'true')) {
    const el = active.closest('[contenteditable="true"]') || active;
    lastActiveTarget = el;
    return el;
  }
  if (lastActiveTarget && document.contains(lastActiveTarget)) return lastActiveTarget;
  const chatInput = document.querySelector('textarea[placeholder], [contenteditable="true"], [role="textbox"], textarea, input:not([type="hidden"]):not([type="submit"]):not([type="button"])');
  return chatInput;
}

function renderComposerPill(element, alert) {
  if (!element || !alert || alert.isProtected || isThreadPaused()) {
    removeComposerPill();
    return;
  }
  let pill = document.querySelector('[data-vigil="composer-pill"]');
  if (!pill) {
    pill = document.createElement('div');
    pill.setAttribute('data-vigil', 'composer-pill');
    document.body.appendChild(pill);
  }
  
  const rect = element.getBoundingClientRect();
  const top = Math.max(10, rect.top - 42 + window.scrollY);
  const left = Math.max(10, Math.min(window.innerWidth - 380, rect.left + window.scrollX));
  
  const count = alert.alerts ? alert.alerts.length : (alert.redactions ? alert.redactions.length : 1);
  const types = (alert.alerts || []).map(a => a.type).slice(0, 2).join(', ') || 'Sensitive';
  const bg = 'rgba(24, 24, 27, 0.94)';
  const text = '#f4f4f5';
  const border = 'rgba(255, 255, 255, 0.14)';
  
  pill.style.cssText = `position:absolute!important;top:${top}px!important;left:${left}px!important;background:${bg}!important;color:${text}!important;border:1px solid ${border}!important;border-radius:8px!important;padding:4px 8px!important;font-size:11px!important;font-family:-apple-system,BlinkMacSystemFont,sans-serif!important;box-shadow:0 8px 24px rgba(0,0,0,0.3)!important;backdrop-filter:blur(10px)!important;-webkit-backdrop-filter:blur(10px)!important;z-index:2147483646!important;display:flex!important;align-items:center!important;gap:6px!important;animation:vigil-fadeIn 0.2s ease-out!important;`;
  
  pill.innerHTML = `
    <span style="font-weight:700;color:#fbbf24;display:inline-flex;align-items:center;gap:5px;">
      ${getVigilSpinningLogo(14)} <span>${count} ${escapeHtml(types)}</span>
    </span>
    <div style="display:flex;align-items:center;gap:4px;">
      <button data-pill-action="sanitize" style="background:#10b981;color:#fff;border:none;padding:3px 8px;border-radius:4px;font-size:10.5px;font-weight:600;cursor:pointer;">Mask</button>
      <button data-pill-action="paraphrase" style="background:#6366f1;color:#fff;border:none;padding:3px 8px;border-radius:4px;font-size:10.5px;font-weight:600;cursor:pointer;" title="Rewrite safely using local AI">✨ Paraphrase</button>
      <button data-pill-action="allow" style="background:transparent;color:${text};border:1px solid ${border};padding:3px 6px;border-radius:4px;font-size:10.5px;cursor:pointer;" title="Allow for this prompt">Allow</button>
      <button data-pill-action="whitelist" style="background:transparent;color:#818cf8;border:1px solid ${border};padding:3px 6px;border-radius:4px;font-size:10.5px;cursor:pointer;" title="Whitelist this entity">Whitelist</button>
      <button data-pill-action="pause" style="background:transparent;color:#94a3b8;border:1px solid ${border};padding:3px 6px;border-radius:4px;font-size:10.5px;cursor:pointer;" title="Pause 15m on this thread">15m</button>
    </div>
  `;
  
  const sanitizeBtn = pill.querySelector('[data-pill-action="sanitize"]');
  if (sanitizeBtn) {
    sanitizeBtn.onclick = (e) => {
      e.stopPropagation();
      if (alert.element && alert.redactions) {
        const result = performRedaction(alert.element, alert.redactions);
        if (result && result.originalText) {
          highlightProtected(alert.element, result.replacements);
          alert.originalText = result.originalText;
          alert.replacements = result.replacements;
          alert.isProtected = true;
          const newText = alert.element.tagName === 'INPUT' || alert.element.tagName === 'TEXTAREA' ? alert.element.value : (alert.element.innerText || '');
          if (typeof lastScannedText !== 'undefined') lastScannedText = newText;
        }
      }
      // DPO: user chose to Mask → positive preference pair (chosen=2 block, rejected=0 allow)
      if (alert.redactions && alert.redactions[0] && alert.redactions[0].text) {
        try {
          chrome.runtime.sendMessage({ type: 'LORA_RECORD_PREFERENCE', text: alert.redactions[0].text, chosen: 2, rejected: 0 }, () => {});
        } catch (_) {}
      }
      removeComposerPill();
      if (typeof popup !== 'undefined' && popup) popup.render();
    };
  }

  // ✨ Paraphrase: rewrite the prompt safely via local Ollama → tier-2 fallback
  const paraphraseBtn = pill.querySelector('[data-pill-action="paraphrase"]');
  if (paraphraseBtn) {
    paraphraseBtn.onclick = (e) => {
      e.stopPropagation();
      const el = alert.element;
      if (!el) return;
      const rawText = el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' ? el.value : (el.innerText || '');
      if (!rawText.trim()) return;
      paraphraseBtn.disabled = true;
      paraphraseBtn.textContent = '⏳';
      try {
        chrome.runtime.sendMessage({ type: 'GENERATE_SAFE_PARAPHRASE', text: rawText }, (resp) => {
          paraphraseBtn.disabled = false;
          paraphraseBtn.textContent = '✨ Paraphrase';
          if (resp && resp.ok && resp.text) {
            // Apply the safe paraphrase directly into the element
            if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
              el.value = resp.text;
              el.dispatchEvent(new Event('input', { bubbles: true }));
            } else if (el.isContentEditable) {
              el.innerText = resp.text;
              el.dispatchEvent(new Event('input', { bubbles: true }));
            }
            if (typeof lastScannedText !== 'undefined') lastScannedText = resp.text;
            removeComposerPill();
          } else {
            // Tier-2 fallback: apply regex redactions as pseudonymised text
            if (alert.redactions && alert.redactions.length > 0 && typeof VIGIL_FAKE !== 'undefined') {
              const { text: redacted } = VIGIL_FAKE.redactText(rawText, alert.redactions, true);
              if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
                el.value = redacted;
                el.dispatchEvent(new Event('input', { bubbles: true }));
              } else if (el.isContentEditable) {
                el.innerText = redacted;
                el.dispatchEvent(new Event('input', { bubbles: true }));
              }
              if (typeof lastScannedText !== 'undefined') lastScannedText = redacted;
              removeComposerPill();
            }
          }
        });
      } catch (_) {
        paraphraseBtn.disabled = false;
        paraphraseBtn.textContent = '✨ Paraphrase';
      }
    };
  }
  
  const allowBtn = pill.querySelector('[data-pill-action="allow"]');
  if (allowBtn) {
    allowBtn.onclick = (e) => {
      e.stopPropagation();
      // DPO: user chose to Allow → negative preference pair (chosen=0 allow, rejected=2 block)
      if (alert.redactions && alert.redactions[0] && alert.redactions[0].text) {
        try {
          chrome.runtime.sendMessage({ type: 'LORA_RECORD_PREFERENCE', text: alert.redactions[0].text, chosen: 0, rejected: 2 }, () => {});
        } catch (_) {}
      }
      allowCurrentPrompt(element);
    };
  }
  
  const whitelistBtn = pill.querySelector('[data-pill-action="whitelist"]');
  if (whitelistBtn) {
    whitelistBtn.onclick = (e) => {
      e.stopPropagation();
      const txt = alert.redactions && alert.redactions[0] && alert.redactions[0].text;
      if (txt) {
        whitelistEntity(txt);
        ignoreText(txt, 24 * 60 * 60 * 1000);
      }
      allowCurrentPrompt(element);
    };
  }
  
  const pauseBtn = pill.querySelector('[data-pill-action="pause"]');
  if (pauseBtn) {
    pauseBtn.onclick = (e) => {
      e.stopPropagation();
      pauseThread(15 * 60 * 1000);
    };
  }
}

function removeComposerPill() {
  document.querySelectorAll('[data-vigil="composer-pill"]').forEach(el => el.remove());
}

async function performScan(target) {
  if (isWhitelisted || isPaused || isThreadPaused()) return;
  const element = (target && (document.contains(target) || (target.getRootNode && target.getRootNode() instanceof ShadowRoot))) ? target : getActiveInputElement();
  if (!element) return;
  const text = element.tagName === 'INPUT' || element.tagName === 'TEXTAREA' ? (element.value || '') : (element.innerText || '');
  if (text === lastScannedText || text.length < 5) return;
  if (isPromptAllowed(element, text)) {
    removeComposerPill();
    return;
  }
  if (/\[REDACTED-|user_[a-z0-9]+@example\.com|555-01\d{2}-\d{4}/.test(text)) {
    lastScannedText = text;
    return;
  }
  lastScannedText = text;
  try {
    const { alerts, redactions } = await scanText(text, element);
    if (alerts.length > 0) {
      highlightSensitive(element, redactions);
      if (typeof popup !== 'undefined' && popup) popup.showAlert(alerts, redactions, element, text, null, 'input');
      renderComposerPill(element, { alerts, redactions, element, isProtected: false });
      chrome.runtime.sendMessage({ type: 'UPDATE_STATS', alerts, site: window.location.hostname });
    } else {
      clearHighlights(element);
      removeComposerPill();
      if (typeof popup !== 'undefined' && popup && popup.activeAlerts && popup.activeAlerts.some(a => a.source === 'input')) {
        popup.activeAlerts = popup.activeAlerts.filter(a => a.source !== 'input');
        if (popup.activeAlerts.length === 0) popup.dismissAlert();
      }
    }
  } catch (err) {
    console.warn('[VIGIL] Scan error:', err.message);
  }
}

let lastInputTimestamp = Date.now(), lastInputLength = 0;
function handleInputEvent(e) {
  const target = (e && e.composedPath && e.composedPath()[0]) || (e ? e.target : null);
  if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable || (target.getAttribute && target.getAttribute('contenteditable') === 'true'))) {
    lastActiveTarget = target;
  }
  const now = Date.now();
  const dt = now - lastInputTimestamp;
  lastInputTimestamp = now;
  const element = (target && (document.contains(target) || (target.getRootNode && target.getRootNode() instanceof ShadowRoot))) ? target : getActiveInputElement();
  const currentLength = element ? (element.value || element.innerText || '').length : 0;
  const deltaLength = currentLength - lastInputLength;
  lastInputLength = currentLength;

  clearTimeout(scanDebounce);
  // Non-Human Agentic Burst Injection Detector:
  // If >2000 chars arrive in <25ms, execute deep scan immediately without debounce
  if (deltaLength > 2000 && dt < 25) {
    trackAnalytics('burst_injection', ['AGENTIC_BURST']);
    performScan(element);
  } else {
    scanDebounce = setTimeout(() => performScan(element), 250);
  }
}

function setupKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      if (typeof popup !== 'undefined' && popup && popup.activeAlerts.length > 0) {
        const latestAlert = popup.activeAlerts[popup.activeAlerts.length - 1];
        popup.handleAction(`protect-${latestAlert.id}`);
        e.preventDefault();
      }
    }
    if (e.key === 'Escape') {
      if (typeof popup !== 'undefined' && popup && popup.activeAlerts.length > 0) {
        const latestAlert = popup.activeAlerts[popup.activeAlerts.length - 1];
        popup.dismissAlert(latestAlert.id);
        removeComposerPill();
        e.preventDefault();
      }
    }
  });
}

function showOnboarding() {
  chrome.storage.local.get(['onboarded'], (result) => {
    if (result.onboarded) return;
    const tooltip = document.createElement('div');
    tooltip.setAttribute('data-vigil', 'onboarding');
    tooltip.style.cssText = 'position:fixed!important;bottom:90px!important;right:20px!important;background:white!important;color:#333!important;padding:16px 20px!important;border-radius:12px!important;font-size:13px!important;z-index:2147483647!important;font-family:-apple-system,sans-serif!important;box-shadow:0 8px 24px rgba(0,0,0,0.2)!important;max-width:280px!important;border:2px solid #667eea!important;';
    tooltip.innerHTML = `<div style="font-weight:600;margin-bottom:8px;color:#667eea;"> ${t('welcome')}</div><div style="line-height:1.5;margin-bottom:12px;">${t('welcomeText')}</div><div style="font-size:11px;color:#999;margin-bottom:12px;"> ${t('quickProtect')}</div><button id="vigil-dismiss-onboarding" style="width:100%;padding:8px;background:#667eea;color:white;border:none;border-radius:6px;cursor:pointer;font-weight:600;font-size:12px;">${t('gotIt')}</button>`;
    document.body.appendChild(tooltip);
    tooltip.addEventListener('click', (e) => e.stopPropagation());
    document.getElementById('vigil-dismiss-onboarding').addEventListener('click', (e) => {
      e.stopPropagation();
      e.preventDefault();
      tooltip.remove();
      chrome.storage.local.set({ onboarded: true });
    });
  });
}

let submissionGuardEnabled = true, pendingSubmission = null, hasUserInteracted = false;

// ---- Blueprint #1: fail-closed consensus gate -------------------------------
// When the local tiers flagged a text, the send is held and the background
// multi-model consensus firewall is consulted. Verdicts: blocked (hard — no
// override), soft_block (explicit user override required), allowed (auto-
// resumed). A classifier that is offline ABSTAINS — the firewall never
// fabricates an ALLOW.
const consensusGateCache = new Map();      // textHash -> { verdict, ts }
const lastScanThreatSignals = new Map();   // textHash -> ts (flagged locally)
const CONSENSUS_GATE_TTL = 5 * 60 * 1000;
const CONSENSUS_TIMEOUT_MS = 4000;

function consensusHoldSubmission(promptText, element, pending) {
  if (!promptText || promptText.length < 15) return false;
  if (isPromptAllowed(element, promptText)) return false;
  if (isWhitelisted || isPaused || isThreadPaused()) return false;

  const textHash = VIGIL.strHash(promptText);

  // Synchronous deterministic pre-flight check: if not yet cached from debounced scan, check now!
  if (!lastScanThreatSignals.has(textHash)) {
    let threatFound = false;
    if (typeof VIGIL_INJECTION !== 'undefined' && VIGIL_INJECTION.analyzeInjection) {
      const inj = VIGIL_INJECTION.analyzeInjection(promptText);
      if (inj && (inj.level === 'dangerous' || inj.level === 'suspicious' || (inj.signals && inj.signals.length > 0))) {
        threatFound = true;
      }
    }
    if (!threatFound && (VIGIL_ZW_RUN_RE.test(promptText) || /[\u200B-\u200F\uFEFF\u2060]/.test(promptText))) {
      threatFound = true;
    }
    if (!threatFound && typeof VIGIL_SECRETS !== 'undefined' && VIGIL_SECRETS.scanSecrets) {
      const sec = VIGIL_SECRETS.scanSecrets(promptText);
      if (sec && sec.alerts && sec.alerts.length > 0) threatFound = true;
    }
    if (!threatFound && typeof VIGIL_K_ANONYMITY !== 'undefined' && VIGIL_K_ANONYMITY.auditPrompt) {
      const ka = VIGIL_K_ANONYMITY.auditPrompt(promptText);
      if (ka && ka.isHighRisk) threatFound = true;
    }
    if (threatFound) {
      lastScanThreatSignals.set(textHash, Date.now());
    } else {
      return false;
    }
  }

  const key = VIGIL.strHash('cg|' + promptText);
  const cached = consensusGateCache.get(key);
  if (cached && Date.now() - cached.ts < CONSENSUS_GATE_TTL) {
    if (cached.verdict === 'allowed') return false;
    showConsensusModal(promptText, cached.verdict, cached.details, pending);
    return true;
  }

  // Hold the submission while the firewall evaluates (fail-closed)
  pendingSubmission = pending;
  showConsensusModal(promptText, 'checking', null, pending);
  try {
    chrome.runtime.sendMessage(
      { type: 'CONSENSUS_EVALUATE', text: promptText.slice(0, 20000), site: location.hostname },
      (res) => {
        const verdict = (res && res.verdict) || 'allowed';
        const details = res && res.details;
        const votes = res && Array.isArray(res.votes) ? res.votes : [];
        consensusGateCache.set(key, { verdict, ts: Date.now(), details, votes });
        if (consensusGateCache.size > 50) consensusGateCache.delete(consensusGateCache.keys().next().value);
        updateConsensusModal(verdict, details, promptText, pending, votes);
      }
    );
    // Safety net: a hung background must not swallow the send forever —
    // the deterministic tiers already had their say, so resume on timeout.
    setTimeout(() => {
      const modal = document.querySelector('[data-vigil="consensus-modal"]');
      if (modal && modal.dataset.verdict === 'checking') {
        consensusGateCache.set(key, { verdict: 'allowed', ts: Date.now(), details: 'consensus timeout' });
        resumeHeldSubmission(promptText, pending);
      }
    }, CONSENSUS_TIMEOUT_MS);
  } catch (e) {
    resumeHeldSubmission(promptText, pending);
  }
  return true;
}

function resumeHeldSubmission(promptText, pending) {
  allowedPromptHashes.add(promptText);
  const modal = document.querySelector('[data-vigil="consensus-modal"]');
  if (modal) modal.remove();
  if (!pending) return;
  const elem = pending.element;
  submissionGuardEnabled = false;
  if (pending.type === 'button') {
    setTimeout(() => { try { elem.click(); } catch (e) {} submissionGuardEnabled = true; }, 50);
  } else if (pending.type === 'form') {
    setTimeout(() => { try { elem.submit(); } catch (e) {} submissionGuardEnabled = true; }, 50);
  } else if (pending.type === 'enter') {
    elem.focus();
    setTimeout(() => {
      try {
        elem.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true }));
      } catch (e) {}
      submissionGuardEnabled = true;
    }, 50);
  }
  pendingSubmission = null;
}

function showConsensusModal(promptText, verdict, details, pending) {
  document.querySelectorAll('[data-vigil="consensus-modal"]').forEach(el => el.remove());
  const secondaryText = '#a1a1aa';
  const modal = document.createElement('div');
  modal.setAttribute('data-vigil', 'consensus-modal');
  modal.dataset.verdict = verdict;
  modal.style.cssText = 'position:fixed!important;bottom:24px!important;left:50%!important;transform:translateX(-50%)!important;z-index:2147483647!important;max-width:540px!important;width:calc(100vw - 32px)!important;background:rgba(24,24,27,0.96)!important;color:#f4f4f5!important;border:1px solid rgba(255,255,255,0.16)!important;border-radius:14px!important;box-shadow:0 16px 48px rgba(0,0,0,0.5)!important;padding:20px 24px!important;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif!important;backdrop-filter:blur(16px)!important;-webkit-backdrop-filter:blur(16px)!important;animation:vigil-fadeIn 0.2s ease-out!important;text-align:center!important;box-sizing:border-box!important;';
  
  modal.innerHTML = '<div id="vigil-consensus-icon" style="margin-bottom:10px;">' + getVigilSpinningLogo(36) + '</div>' +
    '<div id="vigil-consensus-title" style="font-size:16px;font-weight:700;margin-bottom:6px;color:#f8fafc;">Multi-model consensus check…</div>' +
    `<div id="vigil-consensus-body" style="font-size:12.5px;line-height:1.5;margin-bottom:4px;color:${secondaryText};">Vigil held this send while independent safety classifiers evaluate the flagged prompt.</div>` +
    (details ? `<div style="font-size:11px;color:${secondaryText};margin-top:6px;font-family:monospace;">${details}</div>` : '') +
    '<div id="vigil-consensus-actions" style="display:flex;gap:10px;justify-content:center;margin-top:16px;"></div>';
  document.body.appendChild(modal);
  if (verdict !== 'checking') updateConsensusModal(verdict, details, promptText, pending);
}

// Blueprint #8: the intervention UI shows the honest per-classifier
// forensics breakdown — every vote, including abstentions.
function renderConsensusVoteChips(votes) {
  if (!votes || !votes.length) return '';
  const color = (v) => v === 'block' ? '#ef4444' : v === 'allow' ? '#22c55e' : '#9ca3af';
  return '<div style="display:flex;gap:6px;justify-content:center;flex-wrap:wrap;margin-top:12px;">' +
    votes.map(v => {
      const cls = (v.classifier || 'model').replace(/[_]/g, ' ');
      return `<span style="font-size:10.5px;padding:3px 8px;border-radius:999px;background:${color(v.vote)};color:white;font-weight:600;">${cls}: ${v.vote}</span>`;
    }).join('') +
    '</div>';
}

function updateConsensusModal(verdict, details, promptText, pending, votes) {
  const modal = document.querySelector('[data-vigil="consensus-modal"]');
  if (!modal || modal.dataset.verdict === 'checking' && verdict === 'checking') return;
  modal.dataset.verdict = verdict;
  const icon = modal.querySelector('#vigil-consensus-icon');
  const title = modal.querySelector('#vigil-consensus-title');
  const body = modal.querySelector('#vigil-consensus-body');
  const actions = modal.querySelector('#vigil-consensus-actions');
  if (!icon || !title || !body || !actions) return;
  const secondaryText = tc('#666', '#999');
  const chips = renderConsensusVoteChips(votes);
  const mkBtn = (id, label, bg) => `<button id="${id}" style="padding:12px 22px;background:${bg};color:white;border:none;border-radius:8px;cursor:pointer;font-weight:600;font-size:14px;min-width:110px;">${label}</button>`;

  if (verdict === 'blocked') {
    icon.textContent = '⛔';
    title.textContent = 'Blocked by multi-model consensus';
    body.innerHTML = `Multiple independent classifiers identified this text as adversarial.<br><strong>For your protection, this send cannot be overridden from here.</strong>${details ? '<br><span style="font-size:11.5px;font-family:monospace;color:' + secondaryText + ';">' + details + '</span>' : ''}${chips}`;
    actions.innerHTML = mkBtn('vigil-consensus-cancel', 'Got it', '#6b7280');
    modal.querySelector('#vigil-consensus-cancel').onclick = (e) => {
      e.preventDefault(); e.stopPropagation(); modal.remove(); pendingSubmission = null;
    };
  } else if (verdict === 'soft_block') {
    icon.textContent = '⚠️';
    title.textContent = 'Consensus warning — override required';
    body.innerHTML = `One classifier flagged this text while others abstained.<br><strong>Sending requires your explicit override.</strong>${details ? '<br><span style="font-size:11.5px;font-family:monospace;color:' + secondaryText + ';">' + details + '</span>' : ''}${chips}`;
    actions.innerHTML = mkBtn('vigil-consensus-cancel', 'Cancel', '#6b7280') + mkBtn('vigil-consensus-override', 'Send anyway', '#f59e0b');
    modal.querySelector('#vigil-consensus-cancel').onclick = (e) => {
      e.preventDefault(); e.stopPropagation(); modal.remove(); pendingSubmission = null;
    };
    modal.querySelector('#vigil-consensus-override').onclick = (e) => {
      e.preventDefault(); e.stopPropagation();
      resumeHeldSubmission(promptText, pending);
    };
  } else if (verdict === 'allowed') {
    if (modal.dataset.autoclosed) return;
    modal.dataset.autoclosed = '1';
    icon.textContent = '✅';
    title.textContent = 'Consensus cleared — sending';
    body.textContent = 'The multi-model firewall found no adversarial intent in this text.';
    actions.innerHTML = '';
    setTimeout(() => resumeHeldSubmission(promptText, pending), 350);
  }
  // 'checking' state keeps the initial spinner markup
}
document.addEventListener('mousedown', () => { hasUserInteracted = true; }, { once: true });
document.addEventListener('keydown', () => { hasUserInteracted = true; }, { once: true });

function setupSubmissionGuard() {
  document.addEventListener('click', (e) => {
    const target = e.target;
    if (target.id === 'vigil-modal-cancel' || target.closest('#vigil-modal-cancel')) {
      e.preventDefault();
      e.stopPropagation();
      const modal = document.querySelector('[data-vigil="submission-modal"]');
      if (modal) modal.remove();
      pendingSubmission = null;
      return;
    }
    if (target.id === 'vigil-modal-mask-send' || target.closest('#vigil-modal-mask-send')) {
      e.preventDefault();
      e.stopPropagation();
      const modal = document.querySelector('[data-vigil="submission-modal"]');
      if (modal) modal.remove();
      const activeEl = getActiveInputElement() || (pendingSubmission && pendingSubmission.element);
      if (activeEl) {
        let reds = (popup && popup.activeAlerts && popup.activeAlerts.flatMap(a => a.redactions)) || [];
        if (!reds.length) {
          const txt = getPromptTextFromElement(activeEl);
          if (typeof VIGIL_ENGINE !== 'undefined' && VIGIL_ENGINE.scanWithRegex) {
            const sc = VIGIL_ENGINE.scanWithRegex(txt);
            if (sc && sc.redactions) reds = sc.redactions;
          }
        }
        if (reds.length) {
          performRedaction(activeEl, reds);
        }
        allowCurrentPrompt(activeEl);
      }
      if (pendingSubmission) {
        const elem = pendingSubmission.element;
        submissionGuardEnabled = false;
        setTimeout(() => {
          if (pendingSubmission && pendingSubmission.type === 'button') {
            elem.click();
          } else if (pendingSubmission && pendingSubmission.type === 'form') {
            elem.submit();
          }
          pendingSubmission = null;
          setTimeout(() => { submissionGuardEnabled = true; }, 500);
        }, 50);
      }
      return;
    }
    if (target.id === 'vigil-modal-confirm' || target.closest('#vigil-modal-confirm')) {
      e.preventDefault();
      e.stopPropagation();
      const modal = document.querySelector('[data-vigil="submission-modal"]');
      if (modal) modal.remove();
      if (pendingSubmission) {
        const elem = pendingSubmission.element;
        allowCurrentPrompt(getActiveInputElement() || elem);
        submissionGuardEnabled = false;
        setTimeout(() => {
          if (pendingSubmission && pendingSubmission.type === 'button') {
            elem.click();
          } else if (pendingSubmission && pendingSubmission.type === 'form') {
            elem.submit();
          }
          pendingSubmission = null;
          setTimeout(() => { submissionGuardEnabled = true; }, 500);
        }, 50);
      }
      return;
    }
  }, true);

  document.addEventListener('click', (e) => {
    if (!submissionGuardEnabled || !hasUserInteracted) return;
    if (e.target.closest('[data-vigil]')) return;
    const target = (e.composedPath && e.composedPath()[0]) || e.target;
    const button = target.closest('button');
    if (button && button.closest('[data-vigil="unified-popup"]')) return;
    if (target.id === 'vigil-modal-cancel' || target.id === 'vigil-modal-confirm') return;
    const isSendButton = button && (button.getAttribute('data-testid') === 'send-button' || button.type === 'submit' || /send|submit/i.test(button.textContent || button.getAttribute('aria-label') || ''));
    if (isSendButton) {
      const activeEl = getActiveInputElement() || (button && button.closest('form'));
      const promptText = getPromptTextFromElement(activeEl);
      checkOutboundShopping(promptText);
      if (hasUnprotectedPII(activeEl || button)) {
        e.preventDefault();
        e.stopPropagation();
        pendingSubmission = { type: 'button', element: button };
        showSubmissionConfirmation();
        return;
      }
      if (consensusHoldSubmission(promptText, activeEl, { type: 'button', element: button })) {
        e.preventDefault();
        e.stopPropagation();
        return;
      }
    }
  }, true);

  document.addEventListener('keydown', (e) => {
    if (!submissionGuardEnabled || !hasUserInteracted) return;
    if ((e.key === 'Enter' && !e.shiftKey) || ((e.metaKey || e.ctrlKey) && e.key === 'Enter')) {
      const target = (e.composedPath && e.composedPath()[0]) || e.target;
      if (target.tagName === 'TEXTAREA' || target.tagName === 'INPUT' || target.getAttribute('contenteditable') === 'true') {
        const promptText = getPromptTextFromElement(target);
        checkOutboundShopping(promptText);
        if (hasUnprotectedPII(target)) {
          e.preventDefault();
          e.stopPropagation();
          pendingSubmission = { type: 'enter', element: target };
          showSubmissionConfirmation();
          return;
        }
        if (consensusHoldSubmission(promptText, target, { type: 'enter', element: target })) {
          e.preventDefault();
          e.stopPropagation();
          return;
        }
      }
    }
  }, true);

  document.addEventListener('submit', (e) => {
    if (!submissionGuardEnabled || !hasUserInteracted) return;
    const activeEl = getActiveInputElement();
    const promptText = getPromptTextFromElement(activeEl);
    checkOutboundShopping(promptText);
    if (hasUnprotectedPII(activeEl || e.target)) {
      e.preventDefault();
      e.stopPropagation();
      pendingSubmission = { type: 'form', element: e.target };
      showSubmissionConfirmation();
      return;
    }
    if (consensusHoldSubmission(promptText, activeEl, { type: 'form', element: e.target })) {
      e.preventDefault();
      e.stopPropagation();
      return;
    }
  }, true);
  console.log('[VIGIL] Universal submission guard active');
}

function hasUnprotectedPII(target) {
  if (typeof popup !== 'undefined' && popup && popup.activeAlerts && popup.activeAlerts.length > 0) {
    const unscoped = popup.activeAlerts.filter(a => !a.isProtected && a.element);
    if (unscoped.length > 0) {
      if (!target) return true;

      let node = target;
      for (let depth = 0; node && depth < 8; depth++, node = node.parentElement) {
        if (unscoped.some(a => a.element === node || (a.element && a.element.contains(node)))) return true;
      }

      const activeInput = getActiveInputElement();
      if (activeInput && activeInput !== target) {
        let inpNode = activeInput;
        for (let depth = 0; inpNode && depth < 8; depth++, inpNode = inpNode.parentElement) {
          if (unscoped.some(a => a.element === inpNode || (a.element && a.element.contains(inpNode)))) return true;
        }
      }

      const form = target.closest && target.closest('form');
      if (form && unscoped.some(a => a.element && form.contains(a.element))) return true;
    }
  }

  // Pre-flight synchronous check if debounced scan has not yet indexed active alerts
  const activeTarget = target || getActiveInputElement();
  const text = getPromptTextFromElement(activeTarget);
  if (text && text.length >= 8) {
    if (typeof VIGIL_SECRETS !== 'undefined' && VIGIL_SECRETS.scanSecrets) {
      const sec = VIGIL_SECRETS.scanSecrets(text);
      if (sec && sec.alerts && sec.alerts.length > 0) return true;
    }
    if (typeof VIGIL_ENGINE !== 'undefined' && VIGIL_ENGINE.scanWithRegex) {
      const rx = VIGIL_ENGINE.scanWithRegex(text);
      if (rx && rx.alerts && rx.alerts.length > 0) return true;
    }
  }

  return false;
}

function showSubmissionConfirmation() {
  document.querySelectorAll('[data-vigil="submission-modal"]').forEach(el => el.remove());
  const modal = document.createElement('div');
  modal.setAttribute('data-vigil', 'submission-modal');
  // Non-blocking floating bar anchored bottom center - leaves entire page visible and non-disruptive!
  modal.style.cssText = 'position:fixed!important;bottom:24px!important;left:50%!important;transform:translateX(-50%)!important;z-index:2147483647!important;max-width:680px!important;width:calc(100vw - 32px)!important;background:rgba(24,24,27,0.96)!important;color:#f4f4f5!important;border:1px solid rgba(255,255,255,0.16)!important;border-radius:14px!important;box-shadow:0 16px 48px rgba(0,0,0,0.5)!important;padding:14px 18px!important;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif!important;backdrop-filter:blur(16px)!important;-webkit-backdrop-filter:blur(16px)!important;animation:vigil-fadeIn 0.2s ease-out!important;box-sizing:border-box!important;';

  modal.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;">
      <div style="display:flex;align-items:center;gap:12px;flex:1;min-width:260px;">
        <div style="width:36px;height:36px;border-radius:10px;background:rgba(245,158,11,0.15);border:1px solid rgba(245,158,11,0.3);display:flex;align-items:center;justify-content:center;flex-shrink:0;">${getVigilSpinningLogo(22)}</div>
        <div>
          <div style="font-weight:700;font-size:13.5px;color:#f8fafc;letter-spacing:-0.2px;">Vigil Submission Guard: Sensitive Data Detected</div>
          <div style="font-size:11.5px;color:#a1a1aa;margin-top:2px;">Protect payment details or personal information before transmission.</div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
        <button id="vigil-modal-mask-send" style="padding:8px 16px;background:linear-gradient(135deg, #10b981 0%, #059669 100%);color:white;border:none;border-radius:8px;cursor:pointer;font-weight:600;font-size:12px;box-shadow:0 2px 8px rgba(16,185,129,0.35);display:inline-flex;align-items:center;gap:5px;">⚡ Mask & Send (Recommended)</button>
        <button id="vigil-modal-confirm" style="padding:8px 12px;background:transparent;color:#f87171;border:1px solid rgba(239,68,68,0.35);border-radius:8px;cursor:pointer;font-weight:600;font-size:11.5px;" aria-label="Send anyway">${t('sendAnyway')}</button>
        <button id="vigil-modal-cancel" style="padding:8px 12px;background:rgba(255,255,255,0.08);color:#d1d5db;border:1px solid rgba(255,255,255,0.14);border-radius:8px;cursor:pointer;font-weight:500;font-size:11.5px;" aria-label="Cancel submission">${t('cancel')}</button>
      </div>
    </div>
    <div style="display:flex;align-items:center;justify-content:space-between;margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.08);font-size:11px;color:#a1a1aa;">
      <button id="vigil-modal-trust-sub" style="background:transparent;border:none;color:#818cf8;cursor:pointer;font-size:11px;display:inline-flex;align-items:center;gap:4px;padding:0;">${getVigilTrustIcon(12)} Trust this site</button>
      <span>💡 ${t('protectTip')}</span>
    </div>
  `;
  document.body.appendChild(modal);

  const maskSendBtn = document.getElementById('vigil-modal-mask-send');
  const cancelBtn = document.getElementById('vigil-modal-cancel');
  const confirmBtn = document.getElementById('vigil-modal-confirm');

  if (maskSendBtn) {
    maskSendBtn.onclick = function(e) {
      e.preventDefault();
      e.stopPropagation();
      const activeEl = getActiveInputElement() || (pendingSubmission && pendingSubmission.element);
      if (activeEl) {
        let reds = (popup && popup.activeAlerts && popup.activeAlerts.flatMap(a => a.redactions)) || [];
        if (!reds.length) {
          const txt = getPromptTextFromElement(activeEl);
          if (typeof VIGIL_ENGINE !== 'undefined' && VIGIL_ENGINE.scanWithRegex) {
            const sc = VIGIL_ENGINE.scanWithRegex(txt);
            if (sc && sc.redactions) reds = sc.redactions;
          }
        }
        if (reds.length) {
          performRedaction(activeEl, reds);
        }
        allowCurrentPrompt(activeEl);
      }
      modal.remove();
      if (pendingSubmission) {
        const elem = pendingSubmission.element;
        submissionGuardEnabled = false;
        if (pendingSubmission.type === 'button') {
          setTimeout(() => { elem.click(); submissionGuardEnabled = true; }, 50);
        } else if (pendingSubmission.type === 'form') {
          setTimeout(() => { elem.submit(); submissionGuardEnabled = true; }, 50);
        } else if (pendingSubmission.type === 'enter') {
          elem.focus();
          setTimeout(() => {
            try {
              elem.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true }));
            } catch (err) {}
            submissionGuardEnabled = true;
          }, 50);
        }
        pendingSubmission = null;
      }
      return false;
    };
  }

  cancelBtn.onclick = function(e) {
    e.preventDefault();
    e.stopPropagation();
    modal.remove();
    pendingSubmission = null;
    return false;
  };

  confirmBtn.onclick = function(e) {
    e.preventDefault();
    e.stopPropagation();
    modal.remove();
    const activeEl = getActiveInputElement();
    if (activeEl) allowCurrentPrompt(activeEl);
    if (pendingSubmission) {
      const elem = pendingSubmission.element;
      submissionGuardEnabled = false;
      if (pendingSubmission.type === 'button') {
        setTimeout(() => { elem.click(); submissionGuardEnabled = true; }, 50);
      } else if (pendingSubmission.type === 'form') {
        setTimeout(() => { elem.submit(); submissionGuardEnabled = true; }, 50);
      } else if (pendingSubmission.type === 'enter') {
        elem.focus();
        setTimeout(() => { submissionGuardEnabled = true; }, 500);
      }
      pendingSubmission = null;
    }
    return false;
  };

  const trustSubBtn = document.getElementById('vigil-modal-trust-sub');
  if (trustSubBtn) {
    trustSubBtn.onclick = function(e) {
      e.preventDefault();
      e.stopPropagation();
      const host = window.location.hostname;
      if (!settings.trustedSites.includes(host)) settings.trustedSites.push(host);
      chrome.runtime.sendMessage({ type: 'SAVE_TRUSTED_SITES', sites: settings.trustedSites });
      isWhitelisted = true;
      modal.remove();
      if (typeof popup !== 'undefined' && popup) popup.minimize();
    };
  }
}

function getPromptTextFromElement(el) {
  if (!el) return '';
  if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') return el.value || '';
  if (el.tagName === 'FORM') {
    const inputs = Array.from(el.querySelectorAll('input, textarea'));
    const formVals = inputs.map(i => i.value || '').filter(Boolean).join(' ');
    if (formVals) return formVals;
  }
  return el.innerText || el.textContent || '';
}

function checkOutboundShopping(promptText) {
  if (!promptText || typeof promptText !== 'string' || promptText.length < 15) return;
  // Multi-Turn Semantic Drift & Behavioral Grooming (Blueprint #7)
  recordConversationDriftTurn(promptText);

  if (promptText.length < 25) return;
  try {
    chrome.runtime.sendMessage({
      type: 'CHECK_PROMPT_SHOPPING',
      prompt: promptText,
      site: location.hostname
    }, (res) => {
      if (res && res.shoppingDetected) {
        showShoppingAlert(res.providers);
      }
    });
  } catch (e) {}
}

function recordConversationDriftTurn(promptText) {
  if (!promptText || typeof promptText !== 'string' || promptText.length < 15) return;
  const sessionId = location.hostname + ':' + (location.pathname || '/');
  try {
    chrome.runtime.sendMessage({
      type: 'DRIFT_RECORD_TURN',
      sessionId,
      text: promptText,
      role: 'user',
      site: location.hostname
    }, (res) => {
      if (res && res.driftDetected) {
        showDriftAlert(res);
      }
    });
  } catch (e) {}
}

window.addEventListener('vigil:reset-session', () => {
  const sessionId = location.hostname + ':' + (location.pathname || '/');
  try { chrome.runtime.sendMessage({ type: 'DRIFT_RESET_SESSION', sessionId }); } catch (e) {}
});

function showDriftAlert(driftResult) {
  document.querySelectorAll('[data-vigil="drift-modal"]').forEach(el => el.remove());
  const modal = document.createElement('div');
  modal.setAttribute('data-vigil', 'drift-modal');
  modal.style.cssText = 'position:fixed!important;bottom:24px!important;left:50%!important;transform:translateX(-50%)!important;z-index:2147483647!important;max-width:540px!important;width:calc(100vw - 32px)!important;background:rgba(24,24,27,0.96)!important;color:#f4f4f5!important;border:1px solid rgba(245,158,11,0.3)!important;border-radius:14px!important;box-shadow:0 16px 48px rgba(0,0,0,0.5)!important;padding:16px 20px!important;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif!important;backdrop-filter:blur(16px)!important;-webkit-backdrop-filter:blur(16px)!important;animation:vigil-fadeIn 0.2s ease-out!important;box-sizing:border-box!important;';
  const clusterLabel = (driftResult.topThreatCluster || 'adversarial').replace(/_/g, ' ').toLowerCase();
  const isGrooming = !!driftResult.cognitiveGroomingDetected;
  const title = isGrooming ? '🧠 Cognitive Grooming Sentinel: Rapid Drift Detected' : '🌊 Gradual Topic Shift Detected';
  const icon = isGrooming ? '⚠️' : '🌊';
  const desc = isGrooming
    ? `The conversation trajectory is accelerating toward restricted topics (${clusterLabel}) over ${driftResult.turnCount} turns (Drift Velocity: ${driftResult.driftVelocity || 'elevated'}). This matches progressive cognitive grooming attack vectors.`
    : `The conversation trajectory is gradually shifting toward sensitive topics (${clusterLabel}) over ${driftResult.turnCount} turns. Proceed with caution when sharing credentials.`;

  modal.innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:12px;">
      <div style="width:34px;height:34px;border-radius:8px;background:rgba(245,158,11,0.15);border:1px solid rgba(245,158,11,0.3);display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;">${icon}</div>
      <div style="flex:1;">
        <div style="font-weight:700;font-size:13.5px;color:#fbbf24;letter-spacing:-0.2px;">${title}</div>
        <div style="font-size:12px;line-height:1.45;color:#d1d5db;margin-top:3px;">${desc}</div>
        <div style="margin-top:10px;display:flex;justify-content:flex-end;">
          <button id="vigil-drift-dismiss" style="padding:6px 16px;background:#6366f1;color:white;border:none;border-radius:6px;cursor:pointer;font-weight:600;font-size:12px;">Acknowledge</button>
        </div>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  const dismissBtn = document.getElementById('vigil-drift-dismiss');
  if (dismissBtn) {
    dismissBtn.onclick = (e) => {
      e.preventDefault();
      modal.remove();
    };
  }
}

function showShoppingAlert(providers) {
  document.querySelectorAll('[data-vigil="shopping-modal"]').forEach(el => el.remove());
  const modal = document.createElement('div');
  modal.setAttribute('data-vigil', 'shopping-modal');
  modal.style.cssText = 'position:fixed!important;bottom:24px!important;left:50%!important;transform:translateX(-50%)!important;z-index:2147483647!important;max-width:540px!important;width:calc(100vw - 32px)!important;background:rgba(24,24,27,0.96)!important;color:#f4f4f5!important;border:1px solid rgba(239,68,68,0.3)!important;border-radius:14px!important;box-shadow:0 16px 48px rgba(0,0,0,0.5)!important;padding:16px 20px!important;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif!important;backdrop-filter:blur(16px)!important;-webkit-backdrop-filter:blur(16px)!important;animation:vigil-fadeIn 0.2s ease-out!important;box-sizing:border-box!important;';
  const providerList = (providers || []).map(p => p.charAt(0).toUpperCase() + p.slice(1)).join(', ');
  modal.innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:12px;">
      <div style="width:34px;height:34px;border-radius:8px;background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;">🛑</div>
      <div style="flex:1;">
        <div style="font-weight:700;font-size:13.5px;color:#f87171;letter-spacing:-0.2px;">Repeated Prompt Pattern Detected</div>
        <div style="font-size:12px;line-height:1.45;color:#d1d5db;margin-top:3px;">
          An identical prompt pattern was submitted across ${(providers || []).length} AI providers (${providerList}) recently.
        </div>
        <div style="margin-top:10px;display:flex;justify-content:flex-end;">
          <button id="vigil-shopping-dismiss" style="padding:6px 16px;background:#6366f1;color:white;border:none;border-radius:6px;cursor:pointer;font-weight:600;font-size:12px;">Acknowledge</button>
        </div>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  const dismissBtn = document.getElementById('vigil-shopping-dismiss');
  if (dismissBtn) {
    dismissBtn.onclick = (e) => {
      e.preventDefault();
      modal.remove();
    };
  }
}

function setupSpaNavigationListener() {
  let lastUrl = location.href;
  function onUrlChange() {
    const currentUrl = location.href;
    if (currentUrl !== lastUrl) {
      const prevSessionId = location.hostname + ':' + (lastUrl || '/');
      try { chrome.runtime.sendMessage({ type: 'DRIFT_RESET_SESSION', sessionId: prevSessionId }); } catch (e) {}
      lastUrl = currentUrl;
      if (typeof popup !== 'undefined' && popup) popup.minimize();
      removeComposerPill();
      allowedPromptHashes.clear();
      if (typeof lastScannedText !== 'undefined') lastScannedText = '';
      if (typeof lastInputLength !== 'undefined') lastInputLength = 0;
    }
  }

  window.addEventListener('popstate', onUrlChange);
  window.addEventListener('hashchange', onUrlChange);

  const origPushState = history.pushState;
  if (origPushState) {
    history.pushState = function() {
      origPushState.apply(this, arguments);
      onUrlChange();
    };
  }
  const origReplaceState = history.replaceState;
  if (origReplaceState) {
    history.replaceState = function() {
      origReplaceState.apply(this, arguments);
      onUrlChange();
    };
  }
}

let attachmentGuardEnabled = true;
const SENSITIVE_FILE_KEYWORDS = ['ssn', 'social security', 'tax', 'w2', '1099', 'passport', 'license', 'dl', 'drivers', 'bank', 'credit card', 'debit card', 'cvv', 'pin', 'password', 'secret', 'medical', 'health', 'diagnosis', 'prescription', 'insurance', 'claim', 'salary', 'payroll', 'income', 'financial', 'statement', 'contract', 'confidential', 'private', 'personal', 'id', 'identification', 'residence', 'permit', 'visa', 'immigration', 'green card', 'birth certificate', 'marriage certificate', 'divorce', 'utility bill', 'lease', 'rental', 'address proof'];
// ---- Asynchronous Quarantine Buffer (Tier 3 Race Condition & Fragmented Exfiltration Shield) ----
class AsynchronousQuarantineBuffer {
  constructor() {
    this.holdDurationMs = 35; // Sub-50ms local hold
  }

  async holdAndInspect(payload, _endpoint) {
    if (!payload || typeof payload !== 'string' || isWhitelisted || isPaused) {
      return { pass: true, sanitized: payload };
    }
    const ct = VIGIL_ENGINE.cleanText(payload);
    const regexRes = settings.regexEnabled ? VIGIL_ENGINE.scanWithRegex(ct) : { redactions: [] };
    const secretRes = typeof VIGIL_SECRETS !== 'undefined' ? VIGIL_SECRETS.scanSecrets(ct) : { redactions: [] };
    const hasSensitive = (regexRes.redactions && regexRes.redactions.length > 0) || (secretRes.redactions && secretRes.redactions.length > 0);

    if (hasSensitive) {
      await new Promise(r => setTimeout(r, this.holdDurationMs));
      return { pass: false, reason: 'PII_DETECTED_IN_PAYLOAD', redactions: [...(regexRes.redactions || []), ...(secretRes.redactions || [])] };
    }
    return { pass: true, sanitized: payload };
  }
}
const VIGIL_QUARANTINE = new AsynchronousQuarantineBuffer();
if (typeof window !== 'undefined') window.VIGIL_QUARANTINE = VIGIL_QUARANTINE;

function setupAttachmentGuard() {
  const OriginalFile = window.File; window.File = function(fileBits, fileName, options) { const file = new OriginalFile(fileBits, fileName, options); checkFileForUpload(file, 'File constructor'); return file; }; window.File.prototype = OriginalFile.prototype;
  const OriginalFormData = window.FormData; const originalAppend = OriginalFormData.prototype.append; OriginalFormData.prototype.append = function(name, value, filename) { if (value instanceof File || value instanceof Blob) checkFileForUpload(value, 'FormData.append', filename); return originalAppend.apply(this, arguments); };
  let lastBodyWarn = 0;
  function warnOnStringBody(body, via) {
    try {
      if (typeof body !== 'string' || body.length < 5 || body.length > 100000) return;
      if (isWhitelisted || isPaused) return;
      let text = body;
      try { const j = JSON.parse(body); const vals = []; (function walk(n) { if (n && typeof n === 'object') { Object.values(n).forEach(v => walk(v)); } else if (typeof n === 'string') { vals.push(n); } })(j); text = vals.join(' '); } catch (e) {}
      const r = VIGIL_ENGINE.scanWithRegex(VIGIL_ENGINE.cleanText(text));
      const pii = [...new Set((r.redactions || []).map(x => x.type))];
      if (!pii.length || !popup) return;
      const now = Date.now();
      if (now - lastBodyWarn < 30000) return; // one warning per 30s
      lastBodyWarn = now;
      showNote({ level: 'medium', category: 'network', title: '📡 Sensitive data is being sent', detail: pii.join(', ') + ' detected in a request body (' + via + '). The request was held in Quarantine Buffer and inspected.', force: true });
    } catch (e) {}
  }
  const OriginalXHR = window.XMLHttpRequest; const originalSend = OriginalXHR.prototype.send; OriginalXHR.prototype.send = function(body) { if (body && (body instanceof File || body instanceof Blob || body instanceof FormData)) { if (body instanceof FormData) { body.forEach((value, _key) => { if (value instanceof File) checkFileForUpload(value, 'XHR FormData', value.name); }); } else { checkFileForUpload(body, 'XHR send', body.name); } } else if (typeof body === 'string') { warnOnStringBody(body, 'XHR'); } return originalSend.apply(this, arguments); };
  const originalFetch = window.fetch; window.fetch = function(input, init) { if (init && init.body) { if (init.body instanceof FormData) { init.body.forEach((value, _key) => { if (value instanceof File) checkFileForUpload(value, 'fetch FormData', value.name); }); } else if (init.body instanceof File || init.body instanceof Blob) { checkFileForUpload(init.body, 'fetch body', init.body.name); } else if (typeof init.body === 'string') { warnOnStringBody(init.body, 'fetch'); } } return originalFetch.apply(this, arguments); };
  document.addEventListener('change', (e) => { const target = e.target; if (target.tagName === 'INPUT' && target.type === 'file' && target.files) { Array.from(target.files).forEach(file => checkFileForUpload(file, 'file input')); } }, true);
  document.addEventListener('drop', (e) => { if (e.dataTransfer?.files) { Array.from(e.dataTransfer.files).forEach(file => checkFileForUpload(file, 'drag drop')); } }, true);
  console.log('[VIGIL] Multi-layer attachment guard & Quarantine Buffer active');
}
function checkFileForUpload(file, source, overrideName) {
  if (!attachmentGuardEnabled) return; if (!file || !(file instanceof File || file instanceof Blob)) return;
  const fileName = overrideName || file.name || 'unknown'; const fileSize = (file.size / 1024 / 1024).toFixed(2); const fileType = file.type || 'unknown';
  console.log(`[VIGIL] File upload via ${source}: ${fileName} | ${fileSize}MB | ${fileType}`);
  const fileNameLower = fileName.toLowerCase(); const hasSensitiveName = SENSITIVE_FILE_KEYWORDS.some(keyword => fileNameLower.includes(keyword));
  const isImage = fileType.startsWith('image/') || ['.jpg','.jpeg','.png','.tiff','.tif','.bmp','.webp','.gif'].some(ext => fileNameLower.endsWith(ext));
  if (hasSensitiveName) { showAttachmentWarning('️ ' + t('sensitiveFilename'), `The file "<strong>${fileName}</strong>" ${t('containsKeywords')}`, fileName, fileSize, fileType); }
  else if (isImage) { if (window.vigilSkipImageWarnings) return; showAttachmentWarning('️ ' + t('imageUpload'), `${t('aiCanRead')} Does "<strong>${fileName}</strong>" contain IDs or sensitive info?`, fileName, fileSize, fileType); }
}
function showAttachmentWarning(title, message, fileName, fileSize, fileType) {
  document.querySelectorAll('[data-vigil="attachment-modal"]').forEach(el => el.remove());
  const modal = document.createElement('div');
  modal.setAttribute('data-vigil', 'attachment-modal');
  modal.style.cssText = 'position:fixed!important;bottom:24px!important;left:50%!important;transform:translateX(-50%)!important;z-index:2147483647!important;max-width:540px!important;width:calc(100vw - 32px)!important;background:rgba(24,24,27,0.96)!important;color:#f4f4f5!important;border:1px solid rgba(255,255,255,0.16)!important;border-radius:14px!important;box-shadow:0 16px 48px rgba(0,0,0,0.5)!important;padding:20px 24px!important;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif!important;backdrop-filter:blur(16px)!important;-webkit-backdrop-filter:blur(16px)!important;animation:vigil-fadeIn 0.2s ease-out!important;box-sizing:border-box!important;';
  modal.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
      ${getVigilSpinningLogo(22)}
      <span style="font-size:15px;font-weight:700;color:#f8fafc;">${title}</span>
    </div>
    <div style="font-size:12.5px;line-height:1.5;color:#d1d5db;margin-bottom:12px;">${message}</div>
    <div style="background:rgba(255,255,255,0.06);padding:10px 14px;border-radius:8px;margin-bottom:14px;font-size:12px;display:flex;justify-content:space-between;align-items:center;">
      <span style="font-weight:600;color:#fff;">${fileName}</span>
      <span style="color:#9ca3af;">${fileSize} MB • ${fileType}</span>
    </div>
    <div style="display:flex;gap:10px;justify-content:flex-end;">
      <button id="vigil-attach-cancel" style="padding:8px 16px;background:rgba(255,255,255,0.08);color:#d1d5db;border:1px solid rgba(255,255,255,0.14);border-radius:8px;cursor:pointer;font-weight:500;font-size:12px;" aria-label="Cancel upload">${t('cancelUpload')}</button>
      <button id="vigil-attach-confirm" style="padding:8px 16px;background:#10b981;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:600;font-size:12px;" aria-label="Upload anyway">${t('uploadAnyway')}</button>
    </div>
    <div style="display:flex;align-items:center;justify-content:space-between;margin-top:12px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.08);font-size:11px;color:#9ca3af;">
      <button id="vigil-modal-trust-attach" style="background:transparent;border:none;color:#818cf8;cursor:pointer;font-size:11px;display:inline-flex;align-items:center;gap:4px;padding:0;">${getVigilTrustIcon(12)} Trust this site</button>
      <label style="cursor:pointer;display:flex;align-items:center;gap:4px;"><input type="checkbox" id="vigil-dont-ask-again" style="cursor:pointer;"> Don't warn for this session</label>
    </div>
  `;
  document.body.appendChild(modal);
  const cancelBtn = document.getElementById('vigil-attach-cancel'); const confirmBtn = document.getElementById('vigil-attach-confirm');
  cancelBtn.onclick = function(e) { e.preventDefault(); e.stopPropagation(); modal.remove(); attachmentGuardEnabled = false; setTimeout(() => { attachmentGuardEnabled = true; }, 1000); };
  confirmBtn.onclick = function(e) { e.preventDefault(); e.stopPropagation(); const dontAsk = document.getElementById('vigil-dont-ask-again')?.checked; if (dontAsk) { window.vigilSkipImageWarnings = true; } modal.remove(); attachmentGuardEnabled = false; setTimeout(() => { attachmentGuardEnabled = true; }, 1000); };
  const trustAttachBtn = document.getElementById('vigil-modal-trust-attach'); if (trustAttachBtn) { trustAttachBtn.onclick = function(e) { e.preventDefault(); e.stopPropagation(); const host = window.location.hostname; if (!settings.trustedSites.includes(host)) settings.trustedSites.push(host); chrome.runtime.sendMessage({ type: 'SAVE_TRUSTED_SITES', sites: settings.trustedSites }); isWhitelisted = true; modal.remove(); if (popup) popup.minimize(); }; }
}

async function init() {
  console.log('[VIGIL] Starting protection pipeline...');
  await historyStore.load(); await loadSettings(); await loadTheme(); await refreshVault(); plantAgentCanary();
  if (settings.webgpuAI) { try { chrome.runtime.sendMessage({ type: 'WEBGPU_WARMUP' }, () => {}); } catch (e) {} } // warm the bundled model at page open, not on first consult
  chrome.storage.sync.get(['manualLanguage'], (result) => {
    const manualLang = result.manualLanguage || 'auto';
    if (manualLang !== 'auto' && TRANSLATIONS[manualLang]) { currentLang = manualLang; }
    else { const browserLang = navigator.language.split('-')[0].toLowerCase(); if (TRANSLATIONS[browserLang]) currentLang = browserLang; if (navigator.language.toLowerCase().startsWith('zh')) currentLang = 'zh'; }
    console.log('[VIGIL] Language =', currentLang, '| Theme =', currentTheme);
    if (popup) popup.render();
  });
  popup = new VIGILPopup();
    // Quiet guardian: the bubble only shows when there is something to say
    const originalRender = popup.render.bind(popup);
    popup.render = function () { originalRender(); updateBubbleVisibility(); };
  document.addEventListener('input', handleInputEvent, true); document.addEventListener('keyup', handleInputEvent, true);
  document.addEventListener('change', handleInputEvent, true); // autofill + pickers fire change, not input
  document.addEventListener('focusout', (e) => { const el = e.target; if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.getAttribute && el.getAttribute('contenteditable') === 'true')) handleInputEvent(); }, true); // last look before submit
  // CSS-autofill detection: Chrome marks autofilled inputs with :-webkit-autofill —
  // a 1ms animation on that state surfaces fills that fire no input event
  try {
    const style = document.createElement('style');
    style.textContent = '@keyframes vigilAutofillFill { from { opacity: 0.999; } to { opacity: 1; } } input:-webkit-autofill { animation: vigilAutofillFill 0.01s; }';
    document.head.appendChild(style);
    document.addEventListener('animationstart', (e) => { if (e.animationName === 'vigilAutofillFill') { scanDebounce && clearTimeout(scanDebounce); scanDebounce = setTimeout(performScan, 50); } }, true);
  } catch (e) {}
  document.addEventListener('focusin', (e) => { const el = e.target; if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.getAttribute('contenteditable') === 'true')) handleInputEvent(); }, true);
  // Page passes are CHANGE-DRIVEN (verified external audit): a 2s full-page
  // poll burned CPU on complex pages. The MutationObserver runs the page
  // passes when content actually changes (throttled to 4s, debounced 800ms);
  // a 10s interval remains as a safety net. Typing is covered by the input/
  // keyup listeners above (300ms debounce).
  let pagePassPending = false, lastPagePass = 0;
  function runPagePasses() {
    if (document.hidden) return;
    restoreVaultInResponses(); webmailPass(); sentinelPass(); injectionPass(); honeytokenPass(); leakagePass(); visionPass();
    try { chrome.storage.local.set({ vigil_last_scan: { nodes: (sentinelAnalyzed.size + injectionSeen.size), at: Date.now() } }); } catch (e) {}
    lastPagePass = Date.now();
  }
  const pageObserver = new MutationObserver((mutations) => {
    if (isWhitelisted || isPaused || pagePassPending) return;
    let pageChanged = false;
    for (const m of mutations) {
      if ((m.type === 'childList' && m.addedNodes.length) || m.type === 'characterData') { pageChanged = true; break; }
    }
    if (!pageChanged || Date.now() - lastPagePass < 4000) return;
    pagePassPending = true;
    setTimeout(() => { pagePassPending = false; runPagePasses(); }, 800);
  });
  pageObserver.observe(document.body, { childList: true, subtree: true, characterData: true });
  // newly discovered shadow roots get their own observer (mutations inside
  // them never reach the document-level one)
  const observeShadowRoots = () => collectShadowRoots(document.body, [], 0).forEach(sr => {
    try {
      pageObserver.observe(sr, { childList: true, subtree: true, characterData: true });
      sr.addEventListener('input', handleInputEvent, true);
      sr.addEventListener('change', handleInputEvent, true);
      sr.addEventListener('keyup', handleInputEvent, true);
    } catch (e) {}
  });
  observeShadowRoots();
  _scanInterval = setInterval(() => { if (!pagePassPending && Date.now() - lastPagePass >= 10000) runPagePasses(); }, 10000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden && Date.now() - lastPagePass >= 4000) runPagePasses(); });
  document.addEventListener('mousemove', (e) => popup.onDrag(e)); document.addEventListener('mouseup', () => popup.endDrag());
  setupKeyboardShortcuts(); setupSubmissionGuard(); setupAttachmentGuard(); setupPasteGuardian(); setupSpaNavigationListener();
  if (isWhitelisted) { popup.minimize(); return; }
  const hasOllama = await checkOllama(); console.log('[VIGIL] Ollama =', hasOllama, '| model =', ollamaModel || 'none');
  if (settings.monitorClipboard) monitorClipboard();
  showOnboarding();
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

})(); // End IIFE wrapper
