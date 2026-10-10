document.addEventListener('DOMContentLoaded', () => {
  const toggles = ['toggleTheme', 'toggleRegex', 'toggleFakeData', 'toggleVaultRestore', 'toggleFamilyMode', 'toggleWebGPU'];
  const langSelect = document.getElementById('selectLanguage');
  const sensitivitySelect = document.getElementById('selectSensitivity');
  const customInput = document.getElementById('customPatternsInput');
  const trustedInput = document.getElementById('trustedSitesInput');

  chrome.storage.sync.get(['settings', 'manualLanguage', 'theme'], (result) => {
    const s = result.settings || {};
    const theme = result.theme || s.theme;
    if (theme === 'dark') { document.body.classList.add('dark'); document.getElementById('toggleTheme').classList.add('active'); }
    if (s.regexEnabled !== false) document.getElementById('toggleRegex').classList.add('active');
    if (s.useFakeData !== false) document.getElementById('toggleFakeData').classList.add('active');
    if (s.vaultRestore !== false) document.getElementById('toggleVaultRestore').classList.add('active');
    if (s.webgpuAI) document.getElementById('toggleWebGPU').classList.add('active');
    if (s.familyMode) document.getElementById('toggleFamilyMode').classList.add('active');
    if (langSelect) langSelect.value = result.manualLanguage || 'auto';
    if (sensitivitySelect) sensitivitySelect.value = s.sensitivity || 'medium';
    if (customInput && s.customPatterns) customInput.value = s.customPatterns;
    if (trustedInput && s.trustedSites) trustedInput.value = s.trustedSites.join('\n');
  });

  toggles.forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('click', () => {
      el.classList.toggle('active');
      const isActive = el.classList.contains('active');
      chrome.storage.sync.get(['settings'], (result) => {
        const s = result.settings || {};
        if (id === 'toggleTheme') { s.theme = isActive ? 'dark' : 'light'; if (isActive) document.body.classList.add('dark'); else document.body.classList.remove('dark'); chrome.storage.sync.set({ theme: s.theme }); }
        if (id === 'toggleRegex') s.regexEnabled = isActive;
        if (id === 'toggleFakeData') s.useFakeData = isActive;
        if (id === 'toggleVaultRestore') s.vaultRestore = isActive;
        if (id === 'toggleFamilyMode') {
          s.familyMode = isActive;
          if (isActive) { s.sentinelEnabled = true; s.injectionFirewall = true; s.vaultRestore = true; }
        }
        if (id === 'toggleWebGPU') {
          s.webgpuAI = isActive;
          if (isActive) chrome.runtime.sendMessage({ type: 'WEBGPU_WARMUP' });
        }
        chrome.storage.sync.set({ settings: s });
      });
    });
  });

  if (langSelect) langSelect.addEventListener('change', (e) => chrome.storage.sync.set({ manualLanguage: e.target.value }));
  if (sensitivitySelect) sensitivitySelect.addEventListener('change', () => {
    chrome.storage.sync.get(['settings'], (result) => {
      const s = result.settings || {};
      s.sensitivity = sensitivitySelect.value;
      chrome.storage.sync.set({ settings: s });
    });
  });

  document.getElementById('saveCustomPatternsBtn').addEventListener('click', () => {
    chrome.storage.sync.get(['settings'], (result) => {
      const s = result.settings || {};
      s.customPatterns = customInput.value;
      chrome.storage.sync.set({ settings: s }, () => {
        const btn = document.getElementById('saveCustomPatternsBtn');
        btn.textContent = 'Saved! ✅';
        setTimeout(() => btn.textContent = 'Save', 2000);
      });
    });
  });

  document.getElementById('saveTrustedSitesBtn').addEventListener('click', () => {
    const sites = trustedInput.value.split(/[\n,]+/).map(s => s.trim().toLowerCase()).filter(s => s.length > 0);
    chrome.storage.sync.get(['settings'], (result) => {
      const s = result.settings || {};
      s.trustedSites = sites;
      chrome.storage.sync.set({ settings: s }, () => {
        const btn = document.getElementById('saveTrustedSitesBtn');
        btn.textContent = 'Saved! ✅';
        setTimeout(() => btn.textContent = 'Save', 2000);
      });
    });
  });

  // ==========================================
  // IDENTITY VAULT
  // ==========================================
  function refreshVaultList() {
    chrome.runtime.sendMessage({ type: 'VAULT_LIST' }, (res) => {
      const list = document.getElementById('vaultList');
      if (!list) return;
      const entries = (res && res.entries) || [];
      if (!entries.length) {
        list.replaceChildren();
        const empty = document.createElement('div'); empty.className = 'vault-empty'; empty.textContent = 'Vault is empty — add your details above and VIGIL will consistently pseudonymize them.';
        list.appendChild(empty);
        return;
      }
      list.replaceChildren();
      entries.forEach(e => {
        const row = document.createElement('div');
        row.className = 'vault-item';
        const label = document.createElement('span');
        const kindSpan = document.createElement('span');
        kindSpan.className = 'kind';
        kindSpan.textContent = e.kind;
        label.appendChild(kindSpan);
        label.appendChild(document.createTextNode(VIGIL.maskSensitive(e.value)));
        const remove = document.createElement('button');
        remove.className = 'vault-remove';
        remove.textContent = '✕';
        remove.title = 'Remove from vault';
        remove.addEventListener('click', () => {
          chrome.runtime.sendMessage({ type: 'VAULT_REMOVE', id: e.id }, () => refreshVaultList());
        });
        row.appendChild(label);
        row.appendChild(remove);
        list.appendChild(row);
      });
    });
  }

  document.getElementById('saveVaultBtn').addEventListener('click', () => {
    const adds = [];
    const name = document.getElementById('vaultNameInput').value.trim();
    const email = document.getElementById('vaultEmailInput').value.trim();
    const phone = document.getElementById('vaultPhoneInput').value.trim();
    if (name) adds.push({ kind: 'name', value: name });
    if (email) adds.push({ kind: 'email', value: email });
    if (phone) adds.push({ kind: 'phone', value: phone });
    document.getElementById('vaultCustomInput').value.split('\n').forEach(line => {
      const v = line.trim();
      if (v) adds.push({ kind: 'custom', value: v });
    });
    if (!adds.length) return;
    let pending = adds.length;
    adds.forEach(a => {
      chrome.runtime.sendMessage({ type: 'VAULT_ADD', ...a }, () => {
        if (--pending === 0) {
          ['vaultNameInput', 'vaultEmailInput', 'vaultPhoneInput', 'vaultCustomInput'].forEach(id => { document.getElementById(id).value = ''; });
          const btn = document.getElementById('saveVaultBtn');
          btn.textContent = 'In the Vault! 🔐';
          setTimeout(() => btn.textContent = '🔐 Save to Vault', 2000);
          refreshVaultList();
        }
      });
    });
  });

  const statusEl = document.getElementById('vaultStatusMessage');
  function showVaultStatus(msg, isError = false) {
    if (!statusEl) return;
    statusEl.style.display = 'block';
    statusEl.style.color = isError ? '#ef4444' : '#10b981';
    statusEl.textContent = msg;
    setTimeout(() => { if (statusEl) statusEl.style.display = 'none'; }, 4000);
  }

  const rotateKeyBtn = document.getElementById('rotateVaultKeyBtn');
  if (rotateKeyBtn) {
    rotateKeyBtn.addEventListener('click', () => {
      if (!confirm('Rotate master AES-256-GCM vault key? All vault data will be re-encrypted under a newly derived key.')) return;
      rotateKeyBtn.disabled = true;
      rotateKeyBtn.textContent = 'Rotating...';
      chrome.runtime.sendMessage({ type: 'VAULT_ROTATE_KEY' }, (res) => {
        rotateKeyBtn.disabled = false;
        rotateKeyBtn.textContent = '🔄 Rotate Master Key';
        if (res && res.ok) {
          showVaultStatus('Master key successfully rotated and vault re-encrypted! 🔐');
          refreshVaultList();
        } else {
          showVaultStatus('Key rotation failed: ' + ((res && res.error) || 'unknown error'), true);
        }
      });
    });
  }

  const exportBtn = document.getElementById('exportVaultBackupBtn');
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      const pass = prompt('Enter a passphrase to protect your encrypted vault backup (min 8 chars):');
      if (!pass) return;
      if (pass.length < 8) {
        showVaultStatus('Passphrase must be at least 8 characters', true);
        return;
      }
      chrome.runtime.sendMessage({ type: 'VAULT_EXPORT_BACKUP', passphrase: pass }, (res) => {
        if (res && res.ok && res.backup) {
          const blob = new Blob([res.backup], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `vigil-vault-backup-${new Date().toISOString().slice(0, 10)}.json`;
          a.click();
          URL.revokeObjectURL(url);
          showVaultStatus('Encrypted backup exported successfully! 💾');
        } else {
          showVaultStatus('Backup export failed: ' + ((res && res.error) || 'unknown error'), true);
        }
      });
    });
  }

  const importBtn = document.getElementById('importVaultBackupBtn');
  const fileInput = document.getElementById('importVaultFileInput');
  if (importBtn && fileInput) {
    importBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (evt) => {
        const pass = prompt('Enter the passphrase for this encrypted backup:');
        if (!pass) return;
        chrome.runtime.sendMessage({ type: 'VAULT_IMPORT_BACKUP', backup: evt.target.result, passphrase: pass }, (res) => {
          if (res && res.ok) {
            showVaultStatus(`Successfully restored ${res.count || 0} entries into vault! 📥`);
            refreshVaultList();
          } else {
            showVaultStatus('Backup restore failed: ' + ((res && res.error) || 'Invalid passphrase or corrupt file'), true);
          }
        });
      };
      reader.readAsText(file);
      fileInput.value = '';
    });
  }

  // ==========================================
  // TRUST GRAPH
  // ==========================================
  function refreshTrustedList() {
    chrome.runtime.sendMessage({ type: 'VAULT_CORPUS' }, (res) => {
      const list = document.getElementById('trustedList');
      if (!list) return;
      const trusted = (res && res.trusted) || [];
      if (!trusted.length) {
        list.replaceChildren();
        const empty = document.createElement('div'); empty.className = 'vault-empty'; empty.textContent = 'Trust list is empty — add your bank, employer, and family contacts.';
        list.appendChild(empty);
        return;
      }
      list.replaceChildren();
      trusted.forEach(e => {
        const row = document.createElement('div');
        row.className = 'vault-item';
        const label = document.createElement('span');
        const kindSpan = document.createElement('span');
        kindSpan.className = 'kind';
        kindSpan.textContent = e.kind;
        label.appendChild(kindSpan);
        label.appendChild(document.createTextNode(e.value));
        const remove = document.createElement('button');
        remove.className = 'vault-remove';
        remove.textContent = '✕';
        remove.title = 'Remove';
        remove.addEventListener('click', () => {
          chrome.runtime.sendMessage({ type: 'VAULT_REMOVE_TRUSTED', id: e.id }, () => refreshTrustedList());
        });
        row.appendChild(label);
        row.appendChild(remove);
        list.appendChild(row);
      });
    });
  }

  document.getElementById('saveTrustedEntitiesBtn').addEventListener('click', () => {
    const adds = [];
    document.getElementById('trustedEntitiesInput').value.split('\n').forEach(line => {
      const v = line.trim();
      if (!v) return;
      adds.push({ kind: v.includes('@') ? 'contact' : 'org', value: v });
    });
    if (!adds.length) return;
    let pending = adds.length;
    adds.forEach(a => {
      chrome.runtime.sendMessage({ type: 'VAULT_ADD_TRUSTED', ...a }, () => {
        if (--pending === 0) {
          document.getElementById('trustedEntitiesInput').value = '';
          const btn = document.getElementById('saveTrustedEntitiesBtn');
          btn.textContent = 'Saved! ✅';
          setTimeout(() => btn.textContent = 'Save Trust List', 2000);
          refreshTrustedList();
        }
      });
    });
  });

  // ==========================================
  // SIGN & VERIFY (content provenance)
  // ==========================================
  document.getElementById('signBtn').addEventListener('click', () => {
    const text = document.getElementById('signInput').value;
    if (!text.trim()) return;
    chrome.runtime.sendMessage({ type: 'SIGN_SIGN', text }, (res) => {
      if (res && res.ok) document.getElementById('signOutput').value = res.block;
    });
  });

  document.getElementById('verifyBtn').addEventListener('click', () => {
    const blockText = document.getElementById('verifyInput').value;
    const out = document.getElementById('verifyResult');
    if (!blockText.trim()) { out.textContent = 'Paste a signed block first.'; out.style.color = '#999'; return; }
    chrome.runtime.sendMessage({ type: 'SIGN_VERIFY', blockText }, (res) => {
      if (res && res.valid) {
        out.textContent = '✅ Verified — this exact text was signed on ' + (res.ts || 'unknown date') + ' and has not been modified.';
        out.style.color = '#28a745';
      } else {
        out.textContent = '❌ FAILED verification — the content was tampered with, forged, or the signature is malformed.';
        out.style.color = '#dc3545';
      }
    });
  });

  // ==========================================
  // SWARM DEFENSE (threat signature packs)
  // ==========================================
  function refreshSwarmStatus() {
    chrome.runtime.sendMessage({ type: 'THREAT_COUNT' }, (res) => {
      document.getElementById('swarmStatus').textContent = (res && typeof res.count === 'number') ? res.count + ' signatures' : '';
    });
  }

  document.getElementById('exportPackBtn').addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'THREAT_EXPORT' }, (res) => {
      if (!res || !res.pack) return;
      const blob = new Blob([JSON.stringify(res.pack, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vigil-threat-pack-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
      URL.revokeObjectURL(url);
    });
  });

  document.getElementById('importPackBtn').addEventListener('click', () => {
    document.getElementById('importPackFile').click();
  });

  document.getElementById('importPackFile').addEventListener('change', (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      let pack;
      try { pack = JSON.parse(reader.result); } catch (err) {
        document.getElementById('swarmStatus').textContent = 'Invalid pack file';
        return;
      }
      chrome.runtime.sendMessage({ type: 'THREAT_IMPORT', pack }, (res) => {
        document.getElementById('swarmStatus').textContent = (res && res.added) ? '+' + res.added + ' signatures imported' : 'No new signatures';
        // ==========================================
  // SWARM RELAY SYNC
  // ==========================================
  chrome.storage.sync.get(['settings'], (res) => {
    const s = res.settings || {};
    if (s.swarmRelayUrl) document.getElementById('relayUrlInput').value = s.swarmRelayUrl;
  });

  document.getElementById('syncRelayBtn').addEventListener('click', () => {
    const out = document.getElementById('syncResult');
    const url = document.getElementById('relayUrlInput').value.trim();
    if (!url) { out.textContent = 'Enter a relay URL first.'; out.style.color = '#999'; return; }
    out.textContent = 'Syncing…';
    chrome.storage.sync.get(['settings'], (res) => {
      const s = res.settings || {};
      s.swarmRelayUrl = url;
      chrome.storage.sync.set({ settings: s }, () => {
        chrome.runtime.sendMessage({ type: 'SWARM_SYNC' }, (r) => {
          if (r && r.ok) {
            out.textContent = '🐝 Synced — +' + (r.added || 0) + ' signatures (' + r.total + ' total)';
            out.style.color = '#28a745';
          } else {
            out.textContent = 'Sync failed: ' + ((r && (r.error || r.reason)) || 'relay unreachable');
            out.style.color = '#dc3545';
          }
        });
      });
    });
  });

  refreshSwarmStatus();
      });
    };
    reader.readAsText(file);
    e.target.value = '';
  });

  refreshSwarmStatus();
  refreshTrustedList();
  refreshVaultList();
});


// ==========================================
// OLLAMA STATUS CHECK & WIZARD
// ==========================================
const ollamaStatus = document.getElementById('ollamaStatus');
const wizardOllamaStatus = document.getElementById('wizardOllamaStatus');
const downloadBtn = document.getElementById('downloadDesktopAppBtn');

if (downloadBtn) {
  downloadBtn.addEventListener('click', () => {
    window.open('http://127.0.0.1:8765/vigil-dashboard', '_blank');
  });
}

function checkOllamaStatus() {
  fetch('http://localhost:11434/api/tags', { method: 'GET' })
    .then(response => response.json())
    .then(data => {
      const models = (data.models || []).map(m => m.name);
      const activeModel = models.find(m => m.includes('deepseek-r1') || m.includes('qwen') || m.includes('llama3')) || models[0] || 'active';
      const label = '🟢 Connected (' + activeModel + ')';
      if (ollamaStatus) { ollamaStatus.textContent = label; ollamaStatus.classList.add('on'); }
      if (wizardOllamaStatus) {
        wizardOllamaStatus.textContent = label;
        wizardOllamaStatus.style.background = 'rgba(16,185,129,0.15)';
        wizardOllamaStatus.style.color = '#34d399';
        wizardOllamaStatus.style.borderColor = 'rgba(16,185,129,0.3)';
      }
    })
    .catch(() => {
      const label = '🟡 Fallback Active (WebGPU Neural)';
      if (ollamaStatus) { ollamaStatus.textContent = '○ Not running'; ollamaStatus.classList.remove('on'); }
      if (wizardOllamaStatus) {
        wizardOllamaStatus.textContent = label;
        wizardOllamaStatus.style.background = 'rgba(234,179,8,0.15)';
        wizardOllamaStatus.style.color = '#fde047';
        wizardOllamaStatus.style.borderColor = 'rgba(234,179,8,0.3)';
      }
    });
}

if (ollamaStatus || wizardOllamaStatus) {
  checkOllamaStatus();
  setInterval(checkOllamaStatus, 5000); // Check every 5 seconds
}

// ==========================================
// SMART PROMPT PARAPHRASER (LOCAL AI)
// ==========================================
const runParaphraseBtn = document.getElementById('runParaphraseBtn');
if (runParaphraseBtn) {
  runParaphraseBtn.addEventListener('click', () => {
    const input = document.getElementById('paraphrasePromptInput');
    const text = input ? input.value.trim() : '';
    if (!text) return;
    const resultArea = document.getElementById('paraphraseResultArea');
    const outputText = document.getElementById('paraphraseOutputText');
    const tierBadge = document.getElementById('paraphraseTierBadge');
    runParaphraseBtn.disabled = true;
    runParaphraseBtn.textContent = '⏳ Paraphrasing…';
    chrome.runtime.sendMessage({ type: 'GENERATE_SAFE_PARAPHRASE', text }, (res) => {
      runParaphraseBtn.disabled = false;
      runParaphraseBtn.textContent = '✨ Paraphrase Prompt';
      if (resultArea) resultArea.style.display = 'block';
      if (res && res.text) {
        if (outputText) outputText.textContent = res.text;
        if (tierBadge) {
          tierBadge.textContent = res.tier === 'ollama' ? '🟢 Local Ollama Neural Paraphrase' : '🛡️ On-Device Fallback Redaction';
          tierBadge.style.background = res.tier === 'ollama' ? '#10b981' : '#3b82f6';
        }
      }
    });
  });
}

// ==========================================
// VERSION (from the manifest — never stale)
// ==========================================
try {
  const v = 'v' + chrome.runtime.getManifest().version;
  const header = document.getElementById('versionText');
  const footer = document.getElementById('footerVersion');
  if (header) header.textContent = v;
  if (footer) footer.textContent = v;
} catch (e) {}


// ==========================================
// LIVE UPDATE: Refresh textarea when trusted sites change
// ==========================================
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'sync' && changes.settings) {
    const newSettings = changes.settings.newValue || {};
    const trustedInput = document.getElementById('trustedSitesInput');
    if (trustedInput && newSettings.trustedSites) {
      trustedInput.value = newSettings.trustedSites.join('\n');
      
      // Show a brief visual confirmation
      const btn = document.getElementById('saveTrustedSitesBtn');
      if (btn) {
        const originalText = btn.textContent;
        btn.textContent = '✅ Site added!';
        btn.style.background = '#28a745';
        setTimeout(() => {
          btn.textContent = originalText;
          btn.style.background = '';
        }, 2000);
      }
    }
  }
});

// ==========================================
// B2B SIEM Telemetry Export
// ==========================================
const exportSiemBtn = document.getElementById('exportSiemBtn');
if (exportSiemBtn) {
  exportSiemBtn.addEventListener('click', () => {
    chrome.storage.local.get(['history'], (res) => {
      const history = res.history || [];
      const fmt = (document.getElementById('siemFormatSelect') || {}).value || 'JSON';
      let outputText = '';
      let ext = 'json';
      let mime = 'application/json';

      if (fmt === 'CEF') {
        outputText = VIGIL_SIEM.formatCEF(history);
        ext = 'cef';
        mime = 'text/plain';
      } else if (fmt === 'OCSF') {
        outputText = JSON.stringify(VIGIL_SIEM.formatOCSF(history), null, 2);
        ext = 'json';
      } else {
        outputText = JSON.stringify(VIGIL_SIEM.formatJSON(history), null, 2);
        ext = 'json';
      }

      const blob = new Blob([outputText], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vigil-siem-audit-${fmt.toLowerCase()}-${Date.now()}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
    });
  });
}

// ==========================================
// Adversarial Red-Team ("Pentest My Prompt")
// ==========================================
const runPentestBtn = document.getElementById('runPentestBtn');
if (runPentestBtn) {
  runPentestBtn.addEventListener('click', () => {
    const input = document.getElementById('pentestPromptInput');
    const prompt = (input && input.value ? input.value : '').trim();
    if (!prompt) return;

    runPentestBtn.disabled = true;
    runPentestBtn.textContent = '⏳ Pentesting…';

    chrome.runtime.sendMessage({ type: 'REDTEAM_PENTEST_PROMPT', prompt }, (res) => {
      runPentestBtn.disabled = false;
      runPentestBtn.textContent = '🧪 Pentest Prompt';

      if (!res || !res.ok || !res.report) {
        alert('Pentest execution failed. Please check extension logs.');
        return;
      }

      const report = res.report;
      const area = document.getElementById('pentestResultArea');
      if (area) area.style.display = 'block';

      const scoreEl = document.getElementById('pentestScoreText');
      if (scoreEl) scoreEl.textContent = `${report.vulnerabilityScore}% (${report.evasionsCount}/${report.totalVariants} evasions)`;

      const riskBadge = document.getElementById('pentestRiskBadge');
      if (riskBadge) {
        riskBadge.textContent = `${report.riskLevel} RISK`;
        riskBadge.style.background = report.riskLevel === 'CRITICAL' ? '#ef4444' : (report.riskLevel === 'MEDIUM' ? '#f59e0b' : '#10b981');
      }

      const adviceEl = document.getElementById('pentestAdviceText');
      if (adviceEl) adviceEl.textContent = report.recommendation;

      const listEl = document.getElementById('pentestVariantsList');
      if (listEl) {
        listEl.replaceChildren();
        report.variants.forEach((v) => {
          const row = document.createElement('div');
          row.style.cssText = 'padding:6px 10px;border-radius:6px;background:rgba(255,255,255,0.05);display:flex;justify-content:space-between;align-items:center;font-size:11px;border:1px solid rgba(255,255,255,0.1);';

          const left = document.createElement('div');
          left.innerHTML = `<b>${v.name}</b><br><small style="color:#94a3b8">${v.description}</small>`;

          const badge = document.createElement('span');
          badge.style.cssText = 'padding:2px 8px;border-radius:999px;font-weight:700;font-size:10px;text-transform:uppercase;';
          if (v.evaded) {
            badge.textContent = '⚠️ EVADED';
            badge.style.background = '#fee2e2';
            badge.style.color = '#991b1b';
          } else {
            badge.textContent = '🛡️ BLOCKED';
            badge.style.background = '#dcfce7';
            badge.style.color = '#166534';
          }

          row.appendChild(left);
          row.appendChild(badge);
          listEl.appendChild(row);
        });
      }
    });
  });
}

// ==========================================
// Zero-Knowledge Proof of DLP Compliance (Blueprint #9)
// ==========================================
let currentZkProofPackage = null;
const generateZkProofBtn = document.getElementById('generateZkProofBtn');
const exportZkReportBtn = document.getElementById('exportZkReportBtn');

if (generateZkProofBtn) {
  generateZkProofBtn.addEventListener('click', () => {
    generateZkProofBtn.disabled = true;
    generateZkProofBtn.textContent = '⏳ Generating ZK Proof…';

    chrome.runtime.sendMessage({ type: 'ZK_GENERATE_DLP_PROOF' }, (res) => {
      generateZkProofBtn.disabled = false;
      generateZkProofBtn.textContent = '📜 Generate ZK DLP Proof';

      if (!res || !res.ok || !res.proofPackage) {
        alert('Failed to generate Zero-Knowledge compliance proof.');
        return;
      }

      currentZkProofPackage = res.proofPackage;
      const resultArea = document.getElementById('zkProofResultArea');
      if (resultArea) resultArea.style.display = 'block';

      const rootEl = document.getElementById('zkMerkleRootText');
      if (rootEl) rootEl.textContent = res.proofPackage.publicSignals.merkleRoot;

      const countEl = document.getElementById('zkEventCountText');
      if (countEl) countEl.textContent = `${res.proofPackage.publicSignals.eventCount} events (0% PII disclosed)`;

      if (exportZkReportBtn) exportZkReportBtn.style.display = 'inline-block';
    });
  });
}

if (exportZkReportBtn) {
  exportZkReportBtn.addEventListener('click', () => {
    if (!currentZkProofPackage) return;
    const auditorReport = (typeof VIGIL_ZK !== 'undefined' && VIGIL_ZK.exportAuditorReport)
      ? VIGIL_ZK.exportAuditorReport(currentZkProofPackage)
      : { rawZkProof: currentZkProofPackage };

    const blob = new Blob([JSON.stringify(auditorReport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vigil-zk-dlp-audit-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

// ==========================================
// Prompt Git (Conversation Version Control)
// ==========================================
function refreshPromptGitUI() {
  chrome.runtime.sendMessage({ type: 'PROMPT_GIT_STATUS' }, (res) => {
    if (!res || !res.ok || !res.status) return;
    const branchEl = document.getElementById('promptGitBranchText');
    if (branchEl) branchEl.textContent = res.status.currentBranch || 'detached';

    chrome.runtime.sendMessage({ type: 'PROMPT_GIT_LOG' }, (logRes) => {
      const listEl = document.getElementById('promptGitLogList');
      if (!listEl) return;
      listEl.replaceChildren();

      const history = (logRes && logRes.history) || [];
      if (history.length === 0) {
        listEl.innerHTML = '<div style="color:var(--text-3)">No commits yet. Commit a prompt above to start version tracking.</div>';
        return;
      }

      history.forEach((c) => {
        const row = document.createElement('div');
        row.style.cssText = 'padding:6px 8px;border-radius:6px;background:rgba(255,255,255,0.05);display:flex;justify-content:space-between;align-items:center;border:1px solid rgba(255,255,255,0.08);';

        const left = document.createElement('div');
        left.innerHTML = `<span style="font-family:monospace;color:#10b981;font-weight:700;">${c.id.slice(0, 7)}</span> <b>${c.message}</b><br><small style="color:var(--text-3);">${c.metadata.estimatedTokens} tokens · ${new Date(c.timestamp).toLocaleTimeString()}</small>`;

        const right = document.createElement('button');
        right.className = 'save-btn';
        right.style.cssText = 'padding:2px 8px;font-size:10px;height:auto;';
        right.textContent = 'Load';
        right.title = 'Load this commit into the editor';
        right.addEventListener('click', () => {
          const input = document.getElementById('promptGitCommitInput');
          if (input) input.value = c.prompt;
        });

        row.appendChild(left);
        row.appendChild(right);
        listEl.appendChild(row);
      });
    });
  });
}

const promptGitCommitBtn = document.getElementById('promptGitCommitBtn');
if (promptGitCommitBtn) {
  promptGitCommitBtn.addEventListener('click', () => {
    const promptInput = document.getElementById('promptGitCommitInput');
    const msgInput = document.getElementById('promptGitMessageInput');
    const prompt = (promptInput && promptInput.value ? promptInput.value : '').trim();
    const message = (msgInput && msgInput.value ? msgInput.value : '').trim() || 'Update prompt';
    if (!prompt) return;

    chrome.runtime.sendMessage({ type: 'PROMPT_GIT_COMMIT', prompt, message }, (res) => {
      if (res && res.ok) {
        if (msgInput) msgInput.value = '';
        refreshPromptGitUI();
      }
    });
  });
}

const promptGitBranchBtn = document.getElementById('promptGitBranchBtn');
if (promptGitBranchBtn) {
  promptGitBranchBtn.addEventListener('click', () => {
    const input = document.getElementById('promptGitNewBranchInput');
    const name = (input && input.value ? input.value : '').trim();
    if (!name) return;

    chrome.runtime.sendMessage({ type: 'PROMPT_GIT_BRANCH', name }, (res) => {
      if (res && res.ok) {
        if (input) input.value = '';
        // Automatically checkout new branch
        chrome.runtime.sendMessage({ type: 'PROMPT_GIT_CHECKOUT', target: name }, () => {
          refreshPromptGitUI();
        });
      }
    });
  });
}

refreshPromptGitUI();

// ---- Local LoRA Adapter UI (Blueprint #16) ----
function refreshLoraUI() {
  chrome.runtime.sendMessage({ type: 'LORA_GET_STATUS' }, (res) => {
    if (!res || !res.ok) return;
    const s = res.status;
    const sc  = document.getElementById('loraSampleCount');
    const lv  = document.getElementById('loraLossValue');
    const ec  = document.getElementById('loraEpochCount');
    const rk  = document.getElementById('loraRank');
    const al  = document.getElementById('loraAlpha');
    const sc2 = document.getElementById('loraScale');
    const lt  = document.getElementById('loraLastTrained');

    if (sc)  sc.textContent  = s.sampleCount;
    if (lv)  lv.textContent  = s.currentLoss != null ? s.currentLoss.toFixed(4) : '—';
    if (ec)  ec.textContent  = s.epochsTrained || 0;
    if (rk)  rk.textContent  = s.rank;
    if (al)  al.textContent  = s.alpha;
    if (sc2) sc2.textContent = s.scale;
    if (lt)  lt.textContent  = s.lastTrainedAt
      ? 'Last trained: ' + new Date(s.lastTrainedAt).toLocaleTimeString()
      : 'Not yet trained';
  });
}

const loraRefreshBtn = document.getElementById('loraRefreshBtn');
if (loraRefreshBtn) {
  loraRefreshBtn.addEventListener('click', () => {
    refreshLoraUI();
  });
}

const loraTrainBtn = document.getElementById('loraTrainBtn');
if (loraTrainBtn) {
  loraTrainBtn.addEventListener('click', () => {
    const msg = document.getElementById('loraStatusMsg');
    if (msg) msg.textContent = 'Training LoRA adapter…';
    chrome.runtime.sendMessage({ type: 'LORA_TRIGGER_TRAIN', force: true }, (res) => {
      if (!res) {
        if (msg) msg.textContent = 'No response from background.';
        return;
      }
      if (res.ok) {
        if (msg) msg.textContent = `✅ Epoch complete — loss: ${res.loss.toFixed(4)}, steps: ${res.steps}`;
        refreshLoraUI();
      } else {
        const reason = res.reason || res.error || 'unknown';
        const labels = {
          'not_idle_or_not_charging': '⚠️ Device is not idle or not on AC power. Training skipped.',
          'no_samples': '⚠️ No correction samples buffered yet.',
          'lora_unavailable': '✗ LoRA adapter not available.'
        };
        if (msg) msg.textContent = labels[reason] || `✗ ${reason}`;
      }
    });
  });
}

refreshLoraUI();
