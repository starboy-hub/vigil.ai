/**
 * VIGIL UI functional suite — every control in the popup and options page,
 * driven as a user would: click → verify behavior → verify persisted state.
 * Runs serially per page (state flows between ordered checks on purpose).
 */
const { test, chromium, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

const EXT = path.join(process.cwd(), 'dist');
const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'src', 'manifest.json'), 'utf8'));

test.describe.configure({ mode: 'serial' });

async function openPopup(context, extensionId) {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/popup.html`);
  return page;
}

async function openOptions(context, extensionId) {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/options.html`);
  return page;
}

async function getSync(page, key) {
  return page.evaluate((k) => new Promise((res) => chrome.storage.sync.get(k, (r) => res(r[k] ?? null))), key);
}

async function getLocal(page, key) {
  return page.evaluate((k) => new Promise((res) => chrome.storage.local.get(k, (r) => res(r[k] ?? null))), key);
}

// ================= POPUP =================

test.describe('popup controls', () => {
  let context, page, extensionId;

  test.beforeAll(async () => {
    context = await chromium.launchPersistentContext('', {
      headless: false,
      args: [
        `--disable-extensions-except=${EXT}`,
        `--load-extension=${EXT}`,
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu'
      ]
    });
    let [sw] = context.serviceWorkers();
    if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 20000 });
    extensionId = new URL(sw.url()).host;
    page = await openPopup(context, extensionId);
    // First-run onboarding is shown on a fresh profile — dismiss it, reload, then open collapsed sections (reload resets open state)
    await page.evaluate(() => localStorage.setItem('vigil_onboarding9', '1'));
    await page.reload();
    await page.evaluate(() => document.querySelectorAll('details').forEach((d) => { d.open = true; }));
  });

  test.afterAll(async () => { await context.close(); });

  test('spinning quantum lattice shield renders with animation in popup header', async () => {
    const logo = page.locator('.hero-left .lattice-svg');
    await expect(logo).toBeVisible();
    const spinRing = page.locator('.hero-left .spin-ring');
    await expect(spinRing).toBeVisible();
  });

  test('version chip matches the manifest (never stale)', async () => {
    await expect(page.locator('#versionText')).toHaveText('v' + manifest.version);
  });

  test('status pill renders active protection status', async () => {
    const text = await page.locator('#statusText').textContent();
    expect(text).toMatch(/(Active|Standby|Native Host)/);
  });

  test('popup tab navigation switches Overview, Alerts, and History pages seamlessly', async () => {
    // Click Alerts tab
    await page.click('button.tab[data-tab="alerts"]');
    await expect(page.locator('#tab-alerts')).toBeVisible();
    await expect(page.locator('#tab-overview')).toBeHidden();

    // Click History tab
    await page.click('button.tab[data-tab="history"]');
    await expect(page.locator('#tab-history')).toBeVisible();
    await expect(page.locator('#tab-alerts')).toBeHidden();

    // Click Overview tab
    await page.click('button.tab[data-tab="overview"]');
    await expect(page.locator('#tab-overview')).toBeVisible();
    await expect(page.locator('#tab-history')).toBeHidden();
  });

  test('dark mode toggle applies the theme class and persists', async () => {
    await page.click('label.icon-toggle');
    await expect(page.locator('body')).toHaveClass(/dark-mode/);
    const theme = await getSync(page, 'theme');
    expect(theme).toBe('dark');
    await page.click('label.icon-toggle'); // restore
  });

  test('settings button opens the options page', async () => {
    const optionsPage = context.waitForEvent('page');
    await page.click('#openOptions');
    const opt = await optionsPage;
    await expect(opt.locator('#versionText')).toBeVisible();
    await opt.close();
  });

  test('protection layer toggles persist to settings', async () => {
    await page.click('#sentinelToggle + .track');
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({ sentinelEnabled: false });
    await page.click('#sentinelToggle + .track'); // restore
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({ sentinelEnabled: true });
  });

  test('injection firewall toggle persists', async () => {
    await page.click('#firewallToggle + .track');
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({ injectionFirewall: false });
    await page.click('#firewallToggle + .track');
  });

  test('local AI toggle persists', async () => {
    await page.click('#ollamaToggle + .track');
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({ aiEnabled: false });
    await page.click('#ollamaToggle + .track');
  });

  test('family toggle arms every layer and shows the badge', async () => {
    await page.click('#familyToggle + .track');
    await expect(page.locator('#familyBadge')).toBeVisible();
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({
      familyMode: true, sentinelEnabled: true, injectionFirewall: true, vaultRestore: true
    });
  });

  test('sensitivity selector persists', async () => {
    await page.selectOption('#sensitivity', 'high');
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({ sensitivity: 'high' });
  });

  test('seeded history renders in the History tab; Alerts tab shows page state', async () => {
    // Seed one protection entry through the popup's own storage access
    await page.evaluate(() => new Promise((res) => chrome.storage.local.set({
      vigil_history: [{ timestamp: new Date().toISOString(), type: 'SSN', site: 'test.example', original: '123-45-6789', fake: '000-12-3456' }],
      vigil_summary: { allTime: 1 }
    }, () => res())));
    await page.reload();
    await page.click('[data-tab="history"]');
    await expect(page.locator('#historyList .activity-item').first()).toContainText('SSN');
    await page.click('[data-tab="alerts"]');
    // Active tab is the extension page itself — guidance text is correct here
    await expect(page.locator('#alertsList')).toContainText('Open a website');
  });

  test('clear stats wipes history and zeroes the dashboard', async () => {
    await page.click('[data-tab="history"]');
    await page.click('#clearStats');
    await expect(page.locator('#totalProtected')).toHaveText('0');
    const hist = await getLocal(page, 'vigil_history');
    expect(hist).toEqual([]);
  });

  test('export audit log downloads a masked JSON report', async () => {
    await page.evaluate(() => new Promise((res) => chrome.storage.local.set({
      vigil_history: [{ timestamp: new Date().toISOString(), type: 'SSN', site: 'test.example', original: '123-45-6789', fake: '000-45-6789' }],
      vigil_summary: { allTime: 1 }
    }, () => res())));
    await page.reload();
    await page.click('[data-tab="history"]');
    const [download] = await Promise.all([page.waitForEvent('download'), page.click('#exportLogs')]);
    expect(download.suggestedFilename()).toMatch(/^vigil-audit-\d{4}-\d{2}-\d{2}\.json$/);
    const report = JSON.parse(fs.readFileSync(await download.path(), 'utf8'));
    expect(report.items[0].original).not.toContain('123-45-6789'); // masked
    expect(report.items[0].type).toBe('SSN');
  });
});

// ================= OPTIONS =================

test.describe('options controls', () => {
  let context, page, extensionId;

  test.beforeAll(async () => {
    context = await chromium.launchPersistentContext('', {
      headless: false,
      args: [
        `--disable-extensions-except=${EXT}`,
        `--load-extension=${EXT}`,
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu'
      ]
    });
    let [sw] = context.serviceWorkers();
    if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 20000 });
    extensionId = new URL(sw.url()).host;
    page = await openOptions(context, extensionId);
    // Open every collapsible section so controls are reachable
    await page.evaluate(() => document.querySelectorAll('details').forEach((d) => { d.open = true; }));
  });

  test.afterAll(async () => { await context.close(); });

  test('spinning quantum lattice shield renders with animation in options topbar', async () => {
    const logo = page.locator('.topbar-brand .lattice-svg');
    await expect(logo).toBeVisible();
    const spinRing = page.locator('.topbar-brand .spin-ring');
    await expect(spinRing).toBeVisible();
  });

  test('version chips match the manifest', async () => {
    await expect(page.locator('#versionText')).toHaveText('v' + manifest.version);
    await expect(page.locator('#footerVersion')).toHaveText('v' + manifest.version);
  });

  test('ollama status chip reflects the local daemon (connected here, not on CI)', async () => {
    await expect(page.locator('#ollamaStatus')).toContainText(/Connected|Not running/, { timeout: 10000 });
  });

  test('detection toggles persist', async () => {
    await page.click('#toggleRegex');
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({ regexEnabled: false });
    await page.click('#toggleRegex');
  });

  test('sensitivity + language selects persist', async () => {
    await page.selectOption('#selectSensitivity', 'high');
    await page.selectOption('#selectLanguage', 'de');
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({ sensitivity: 'high' });
    // manualLanguage is a top-level sync key (content scripts read it directly)
    await expect.poll(() => getSync(page, 'manualLanguage'), { timeout: 5000 }).toBe('de');
    await page.selectOption('#selectLanguage', 'en');
  });

  test('guardian toggles persist (fake data, un-mask)', async () => {
    await page.click('#toggleFakeData');
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({ useFakeData: false });
    await page.click('#toggleFakeData');
    await page.click('#toggleVaultRestore');
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({ vaultRestore: false });
    await page.click('#toggleVaultRestore');
  });

  test('identity vault: add, masked list, remove', async () => {
    await page.fill('#vaultNameInput', 'Sarah Mitchell');
    await page.fill('#vaultEmailInput', 'sarah.private@proton.me');
    await page.fill('#vaultCustomInput', '12 Ocean Avenue');
    await page.click('#saveVaultBtn');
    await expect(page.locator('#vaultList .vault-item')).toHaveCount(3, { timeout: 10000 });
    const listText = await page.locator('#vaultList').textContent();
    expect(listText).not.toContain('sarah.private@proton.me'); // masked
    expect(listText).toContain('sa••');
    // remove one
    await page.locator('#vaultList .vault-remove').first().click();
    await expect(page.locator('#vaultList .vault-item')).toHaveCount(2, { timeout: 10000 });
  });

  test('trust graph: add + list + remove', async () => {
    await page.fill('#trustedEntitiesInput', 'Global Bank\njohn@family.com');
    await page.click('#saveTrustedEntitiesBtn');
    await expect(page.locator('#trustedList .vault-item')).toHaveCount(2, { timeout: 10000 });
    await expect(page.locator('#trustedList')).toContainText('Global Bank');
    await page.locator('#trustedList .vault-remove').first().click();
    await expect(page.locator('#trustedList .vault-item')).toHaveCount(1, { timeout: 10000 });
  });

  test('trusted sites save persists', async () => {
    await page.fill('#trustedSitesInput', 'mybank.example\nnews.example');
    await page.click('#saveTrustedSitesBtn');
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({ trustedSites: ['mybank.example', 'news.example'] });
  });

  test('custom patterns save persists', async () => {
    await page.fill('#customPatternsInput', 'EMPLOYEE_ID:/EMP-\\d{5}/g');
    await page.click('#saveCustomPatternsBtn');
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({ customPatterns: 'EMPLOYEE_ID:/EMP-\\d{5}/g' });
  });

  test('sign & verify: sign produces a block, verify passes, tampering fails', async () => {
    await page.fill('#signInput', 'Transfer approved for project A');
    await page.click('#signBtn');
    await expect(page.locator('#signOutput')).toHaveValue(/-----BEGIN VIGIL SIGNED MESSAGE-----/, { timeout: 10000 });
    const block = await page.inputValue('#signOutput');
    expect(block).toContain('-----BEGIN VIGIL SIGNED MESSAGE-----');
    // verify untampered
    await page.fill('#verifyInput', block);
    await page.click('#verifyBtn');
    await expect(page.locator('#verifyResult')).toContainText('✅ Verified', { timeout: 10000 });
    // verify tampered (change the amount inside the signed text)
    await page.fill('#verifyInput', block.replace('project A', 'project B'));
    await page.click('#verifyBtn');
    await expect(page.locator('#verifyResult')).toContainText('❌ FAILED', { timeout: 10000 });
  });

  test('swarm: export pack downloads, import pack merges', async () => {
    // export
    const [download] = await Promise.all([page.waitForEvent('download'), page.click('#exportPackBtn')]);
    const packPath = await download.path();
    const pack = JSON.parse(fs.readFileSync(packPath, 'utf8'));
    expect(pack.vigilThreatPack).toBe(true);
    expect(Array.isArray(pack.signatures)).toBe(true);
    // import a crafted pack with one new signature
    const importFile = path.join(__dirname, 'fixtures', 'import-pack.json');
    fs.writeFileSync(importFile, JSON.stringify({ vigilThreatPack: true, version: 1, signatures: [{ value: 'e2e-test-hash', addedAt: new Date().toISOString() }] }));
    await page.setInputFiles('#importPackFile', importFile);
    // Import completes → count updates to include the imported signature
    await expect(page.locator('#swarmStatus')).toContainText('1 signatures', { timeout: 10000 });
    fs.rmSync(importFile);
  });
});

// ================= ENGINEERING (service worker level) =================

test.describe('engineering checks (service worker)', () => {
  let context, sw;

  test.beforeAll(async () => {
    context = await chromium.launchPersistentContext('', {
      headless: false,
      args: [
        `--disable-extensions-except=${EXT}`,
        `--load-extension=${EXT}`,
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu'
      ]
    });
    let [worker] = context.serviceWorkers();
    if (!worker) worker = await context.waitForEvent('serviceworker', { timeout: 20000 });
    sw = worker;
    const p = await context.newPage();
    await p.goto(`chrome-extension://${new URL(sw.url()).host}/popup.html`);
    await p.waitForTimeout(500);
    await p.close();
  });

  test.afterAll(async () => { await context.close(); });

  test('reality engine flags AI-marked bytes and clears clean ones', async () => {
    const r = await sw.evaluate(() => {
      const reality = typeof VIGIL_REALITY !== 'undefined' ? VIGIL_REALITY : (self.VIGIL_REALITY || globalThis.VIGIL_REALITY);
      const enc = (s) => Array.from(s).map((c) => c.charCodeAt(0));
      const png = [0x89, 0x50, 0x4E, 0x47];
      const ai = reality.analyzeImageBytes(new Uint8Array([...png, ...enc('c2pa trainedAlgorithmicMedia DALL-E')]));
      const clean = reality.analyzeImageBytes(new Uint8Array([...png, ...enc('a normal photo without any metadata at all')]));
      return { ai: ai.verdict, clean: clean.verdict };
    });
    expect(r.ai).toBe('ai-generated');
    expect(r.clean).toBe('no-metadata');
  });

  test('vault ciphertext is not plaintext in storage', async () => {
    const r = await sw.evaluate(async () => {
      // add a vault value via the real handler path
      await new Promise((res) => chrome.runtime.sendMessage({ type: 'VAULT_ADD', kind: 'name', value: 'Secretive Person' }, res));
      const raw = await new Promise((res) => chrome.storage.local.get(['vault_data'], (g) => res(JSON.stringify(g))));
      return { raw, hasPlaintext: raw.includes('Secretive Person') };
    });
    expect(r.hasPlaintext).toBe(false);
  });

  test('malformed messages are rejected by the validation gate', async () => {
    // Send from a page context (a service worker cannot receive its own messages)
    const extId = new URL(sw.url()).host;
    const p = await context.newPage();
    await p.goto(`chrome-extension://${extId}/popup.html`);
    const r = await p.evaluate(() => new Promise((res) => {
      chrome.runtime.sendMessage({ type: 'VAULT_ADD', kind: 'name' }, (r1) => {
        if (chrome.runtime.lastError) res({ err: chrome.runtime.lastError.message }); else res(r1);
      });
    }));
    expect(r.error).toBe('invalid_message');
    await p.close();
  });
});


test.describe('popup presets and site grade', () => {
  let context, page, extensionId;

  test.beforeAll(async () => {
    context = await chromium.launchPersistentContext('', {
      headless: false,
      args: [
        `--disable-extensions-except=${EXT}`,
        `--load-extension=${EXT}`,
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu'
      ]
    });
    let [sw] = context.serviceWorkers();
    if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 20000 });
    extensionId = new URL(sw.url()).host;
    page = await openPopup(context, extensionId);
    await page.evaluate(() => localStorage.setItem('vigil_onboarding9', '1'));
    await page.reload();
  });

  test.afterAll(async () => { await context.close(); });

  test('preset: Strict arms every layer and sets high sensitivity', async () => {
    await page.click('#presetControl [data-preset="strict"]');
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({
      preset: 'strict', regexEnabled: true, sentinelEnabled: true, injectionFirewall: true, sensitivity: 'high'
    });
    await expect(page.locator('#familyBadge')).toBeHidden();
  });

  test('preset: Family arms family mode and the badge', async () => {
    await page.click('#presetControl [data-preset="family"]');
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({ preset: 'family', familyMode: true });
    await expect(page.locator('#familyBadge')).toBeVisible();
    await page.click('#presetControl [data-preset="standard"]');
  });

  test('preset: Off stops active scanning but keeps the Vault armed', async () => {
    await page.click('#presetControl [data-preset="off"]');
    await expect.poll(() => getSync(page, 'settings'), { timeout: 5000 }).toMatchObject({
      preset: 'off', regexEnabled: false, sentinelEnabled: false
    });
    await page.click('#presetControl [data-preset="standard"]');
  });

  test('site grade renders for the active tab', async () => {
    // popup itself is an extension page — grade shows the standby dash
    await expect(page.locator('#gradeLetter')).toHaveText('–');
  });
});
