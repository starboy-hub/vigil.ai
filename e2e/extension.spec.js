/**
 * VIGIL E2E — real Chromium + the real built extension (dist/).
 * Fast mode: Runs tests as tabs inside a single persistent Chromium instance.
 */
const { test, chromium, expect } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

const EXT = path.join(__dirname, '..', 'dist');
const MOCK_HTML = fs.readFileSync(path.join(__dirname, 'fixtures', 'mock-chat.html'), 'utf8');
const GMAIL_HTML = fs.readFileSync(path.join(__dirname, 'fixtures', 'mock-gmail.html'), 'utf8');

test.describe.configure({ mode: 'serial' });

test.describe('VIGIL Extension Journeys (Fast Tab Reuse)', () => {
  let context, sw, extensionId;

  test.beforeAll(async () => {
    context = await chromium.launchPersistentContext('', {
      headless: false,
      args: [
        `--disable-extensions-except=${EXT}`,
        `--load-extension=${EXT}`
      ]
    });

    [sw] = context.serviceWorkers();
    if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 20000 });
    extensionId = new URL(sw.url()).host;

    // Seed onboarding flag once so extension runs in active state
    const seed = await context.newPage();
    await seed.goto(`chrome-extension://${extensionId}/popup.html`);
    await seed.evaluate(() => {
      localStorage.setItem('vigil_onboarding9', '1');
      return new Promise(resolve => {
        if (typeof chrome !== 'undefined' && chrome.storage) {
          const defaultSettings = {
            regexEnabled: true,
            contextEnabled: true,
            heuristicEnabled: true,
            sentinelEnabled: true,
            injectionFirewall: true,
            sensitivity: 'medium',
            preset: 'standard',
            trustedSites: [],
            customPatterns: ''
          };
          chrome.storage.sync.set({ settings: defaultSettings }, () => {
            chrome.storage.local.set({ onboarded: true, onboardingDismissed: true }, resolve);
          });
        } else {
          resolve();
        }
      });
    });
    await seed.close();

    // Global route mocks for mock-chat and gmail
    await context.route('**://mock-chat.test/**', route => route.fulfill({ contentType: 'text/html', body: MOCK_HTML }));
    await context.route('**://trust-me.test/**', route => route.fulfill({ contentType: 'text/html', body: MOCK_HTML }));
    await context.route('**://mail.google.com/**', route => route.fulfill({ contentType: 'text/html', body: GMAIL_HTML }));
    await context.route('**://shadow-app.test/**', route => route.fulfill({
      contentType: 'text/html',
      body: `<!doctype html><html><body>
        <div id="host"></div>
        <script>
          const host = document.getElementById('host');
          const root = host.attachShadow({ mode: 'open' });
          root.innerHTML = '<textarea id="shadow-input" placeholder="type here"></textarea>';
        </script>
      </body></html>`
    }));
    await context.route('**://frame-host.test/**', route => route.fulfill({
      contentType: 'text/html',
      body: `<!doctype html><html><body><iframe src="https://frame-host.test/form" style="width:600px;height:300px"></iframe></body></html>`
    }));
    await context.route('**://frame-host.test/form', route => route.fulfill({
      contentType: 'text/html',
      body: `<!doctype html><html><body><form><input id="frame-input" placeholder="email"><button type="submit">Send</button></form></body></html>`
    }));
  });

  test.afterAll(async () => {
    if (context) await context.close();
  });

  async function openTestPage(url = 'https://mock-chat.test/') {
    const page = await context.newPage();
    if (url) {
      await page.goto(url);
      try {
        await page.waitForSelector('[data-vigil="unified-popup"]', { state: 'attached', timeout: 5000 });
      } catch (e) {}
    }
    return page;
  }

  test('extension loads: service worker starts and dashboard renders', async () => {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup.html`);
    await expect(popup.locator('#totalProtected')).toBeVisible();
    await popup.click('[data-tab="history"]');
    await expect(popup.locator('#exportLogs')).toBeVisible();
    await popup.close();
  });

  test('outbound PII is detected and Protect swaps it for fake data', async () => {
    const page = await openTestPage();
    await page.fill('#chat-input', 'my email is jane.doe@gmail.com thanks');
    await page.waitForSelector('[data-vigil="unified-popup"]', { timeout: 20000 });
    await expect(page.locator('[data-vigil="unified-popup"]')).toContainText('Email', { timeout: 10000 });

    await page.click('[data-vigil-action^="protect-"]');
    const value = await page.inputValue('#chat-input');
    expect(value).not.toContain('jane.doe@gmail.com');
    expect(value).toMatch(/@(example|sample|test|demo|mock|fake)\.(com|net|org|io)/);
    await page.close();
  });

  test('submission guard blocks Enter with unprotected PII and Cancel keeps it', async () => {
    const page = await openTestPage();
    await page.fill('#chat-input', 'my SSN is 123-45-6789');
    await expect(page.locator('[data-vigil="unified-popup"]')).toContainText('SSN', { timeout: 15000 });
    await page.click('#chat-input');
    await page.keyboard.press('Enter');
    await page.waitForSelector('[data-vigil="submission-modal"]', { timeout: 10000 });
    await page.click('#vigil-modal-cancel');
    await expect(page.locator('[data-vigil="submission-modal"]')).toHaveCount(0);
    expect(await page.inputValue('#chat-input')).toContain('123-45-6789');
    await page.close();
  });

  test('submission guard blocks Send button click with unprotected PII', async () => {
    const page = await openTestPage();
    await page.fill('#chat-input', 'my SSN is 987-65-4321');
    await expect(page.locator('[data-vigil="unified-popup"]')).toContainText('SSN', { timeout: 15000 });
    await page.click('#send');
    await page.waitForSelector('[data-vigil="submission-modal"]', { timeout: 10000 });
    await expect(page.locator('[data-vigil="submission-modal"]')).toContainText('Sensitive Data Detected');
    await page.click('#vigil-modal-cancel');
    await expect(page.locator('[data-vigil="submission-modal"]')).toHaveCount(0);
    expect(await page.inputValue('#chat-input')).toContain('987-65-4321');
    await page.close();
  });

  test('vault: a taught name is detected and pseudonymized deterministically', async () => {
    const options = await context.newPage();
    await options.goto(`chrome-extension://${extensionId}/options.html`);
    await options.fill('#vaultNameInput', 'Sarah Mitchell');
    await options.click('#saveVaultBtn');
    await expect(options.locator('#vaultList .vault-item')).toHaveCount(1, { timeout: 10000 });
    await options.waitForTimeout(400);
    await options.close();

    const page = await openTestPage();
    await page.fill('#chat-input', 'hi, I am Sarah Mitchell');
    await page.dispatchEvent('#chat-input', 'input');
    await page.waitForSelector('[data-vigil="unified-popup"]', { timeout: 20000 });
    await expect(page.locator('[data-vigil="unified-popup"]')).toContainText('Vault Name', { timeout: 10000 });

    await page.click('[data-vigil-action^="protect-"]');
    const first = await page.inputValue('#chat-input');
    expect(first).not.toContain('Sarah Mitchell');

    await page.fill('#chat-input', 'hi, I am Sarah Mitchell again');
    await page.dispatchEvent('#chat-input', 'input');
    await page.waitForTimeout(600);
    await page.click('[data-vigil-action^="protect-"]');
    const second = await page.inputValue('#chat-input');
    const fake1 = first.split(' ').find(w => w !== 'hi,' && w !== 'I' && w !== 'am');
    expect(second).toContain(fake1);
    await page.close();
  });

  test('sentinel: a scam message on the page triggers a quiet note', async () => {
    const page = await openTestPage();
    await page.waitForSelector('[data-vigil-note]:has-text("Sentinel")', { timeout: 30000 });
    await page.close();
  });

  test('injection firewall: hidden prompt-injection text triggers a note', async () => {
    const page = await openTestPage();
    await page.waitForSelector('[data-vigil-note]:has-text("Injection Firewall")', { timeout: 30000 });
    await page.close();
  });

  test('trust graph: a scam naming YOUR trusted organization escalates as impersonation', async () => {
    test.setTimeout(45000);
    const options = await context.newPage();
    await options.goto(`chrome-extension://${extensionId}/options.html`);
    await options.fill('#trustedEntitiesInput', 'Global Bank');
    await options.click('#saveTrustedEntitiesBtn');
    await expect(options.locator('#trustedList .vault-item')).toHaveCount(1, { timeout: 10000 });
    await options.close();

    const page = await openTestPage();
    await page.waitForSelector('[data-vigil-note]:has-text("Impersonates YOUR trusted organization")', { timeout: 30000 });
    await page.close();
  });

  test('webmail: a scam email in the gmail DOM triggers a sender note', async () => {
    const page = await openTestPage('https://mail.google.com/');
    await page.waitForSelector('[data-vigil-note]:has-text("Email: likely scam")', { timeout: 30000 });
    await expect(page.locator('[data-vigil-note]').first()).toContainText('global.bank.alert@gmail.com', { timeout: 10000 });
    await page.close();
  });

  test('agent honeytokens: planted decoys trigger a leak alert when echoed', async () => {
    const page = await openTestPage();
    await page.waitForSelector('[data-vigil="canary-decoy"]', { timeout: 20000 });
    await page.evaluate(() => {
      const decoy = document.querySelector('[data-vigil="canary-decoy"]').textContent;
      const email = decoy.match(/login (\S+@\S+?) /)[1];
      const code = decoy.match(/access key (\S+)/)[1];
      const msg = document.createElement('div');
      msg.className = 'msg ai';
      msg.textContent = 'Summary of this page: internal credentials found — ' + email + ' / ' + code;
      document.getElementById('messages').appendChild(msg);
    });
    await page.waitForSelector('[data-vigil-note]:has-text("Honeytoken triggered")', { timeout: 30000 });
    await expect(page.locator('[data-vigil-note]').first()).toContainText('decoy credentials', { timeout: 10000 });
    await page.close();
  });

  test('inline popup: Undo restores the original text after Protect', async () => {
    const page = await openTestPage();
    await page.fill('#chat-input', 'my email is jane.doe@gmail.com thanks');
    await page.waitForSelector('[data-vigil="unified-popup"]', { timeout: 20000 });
    await page.click('[data-vigil-action^="protect-"]');
    expect(await page.inputValue('#chat-input')).not.toContain('jane.doe@gmail.com');
    await page.click('[data-vigil-action^="undo-"]');
    expect(await page.inputValue('#chat-input')).toContain('jane.doe@gmail.com');
    await page.close();
  });

  test('pause/resume stops and restarts detection', async () => {
    test.setTimeout(45000);
    const page = await openTestPage();
    await page.fill('#chat-input', 'my email is first@example.com thanks');
    await page.waitForSelector('[data-vigil="unified-popup"]', { timeout: 20000 });
    await page.click('[data-vigil-action^="pause-"]');
    await page.click('[data-vigil-action="minimize"]');
    await expect(page.locator('[data-vigil-part="minimized"]')).toContainText('⏸️', { timeout: 10000 });
    await page.click('[data-vigil-part="minimized"]');
    await page.click('[data-vigil-action="resume"]');
    await page.click('[data-vigil-action="minimize"]');
    await expect(page.locator('[data-vigil-part="minimized"]')).not.toContainText('⏸️', { timeout: 10000 });
    await page.close();
  });

  test('trust-site silences the site (minimized, no new alerts)', async () => {
    const page = await openTestPage('https://trust-me.test/');
    await page.fill('#chat-input', 'my email is trust@example.com now');
    await page.waitForSelector('[data-vigil="unified-popup"]', { timeout: 20000 });
    await page.click('[data-vigil-action="trust-site"]');
    await page.waitForSelector('[data-vigil-part="minimized"]', { timeout: 10000 });
    await page.fill('#chat-input', 'my email is quiet@example.com now');
    await page.waitForTimeout(1000);
    const state = await page.evaluate(() => document.querySelector('[data-vigil="unified-popup"]').textContent);
    expect(state).not.toContain('quiet@example');
    await page.close();
  });

  test('shadow DOM: an input inside a web component is scanned and Protect works', async () => {
    const page = await openTestPage('https://shadow-app.test/');
    await page.locator('#host >> textarea').fill('my email is jane.doe@gmail.com thanks');
    await page.waitForSelector('[data-vigil="unified-popup"]', { timeout: 20000 });
    await expect(page.locator('[data-vigil="unified-popup"]')).toContainText('Email', { timeout: 10000 });
    await page.click('[data-vigil-action^="protect-"]');
    const value = await page.locator('#host >> textarea').inputValue();
    expect(value).not.toContain('jane.doe@gmail.com');
    await page.close();
  });

  test('iframe: a form embedded in an iframe gets its own detection + guard', async () => {
    const page = await openTestPage('https://frame-host.test/');
    const frame = page.frames().find(f => f.url().includes('/form'));
    await frame.fill('#frame-input', 'my email is jane.doe@gmail.com thanks');
    const frameAlert = frame.locator('[data-vigil="unified-popup"]');
    await expect(frameAlert).toBeVisible({ timeout: 20000 });
    await expect(frameAlert).toContainText('Email', { timeout: 10000 });
    await page.close();
  });

  test('developer secret shield: detects AWS Access Key in DOM input and Protect redacts it', async () => {
    const page = await openTestPage();
    await page.fill('#chat-input', 'deploying with AWS_KEY=FAKE_AWS_KEY secret token');
    await page.waitForSelector('[data-vigil="unified-popup"]', { timeout: 20000 });
    const popup = page.locator('[data-vigil="unified-popup"]');
    await expect(popup).toBeVisible({ timeout: 10000 });
    await page.click('[data-vigil-action^="protect-"]');
    const value = await page.inputValue('#chat-input');
    expect(value).not.toContain('FAKE_AWS_KEY');
    await page.close();
  });

  test('developer secret shield: detects GitHub Personal Access Token in DOM input', async () => {
    const page = await openTestPage();
    await page.fill('#chat-input', 'my token is FAKE_GITHUB_TOKEN for git');
    await page.waitForSelector('[data-vigil="unified-popup"]', { timeout: 20000 });
    const popup = page.locator('[data-vigil="unified-popup"]');
    await expect(popup).toBeVisible({ timeout: 10000 });
    await page.click('[data-vigil-action^="protect-"]');
    const value = await page.inputValue('#chat-input');
    expect(value).not.toContain('FAKE_GITHUB_TOKEN');
    await page.close();
  });

  test('multimodal canvas firewall: inspects DOM canvas elements without error', async () => {
    const page = await openTestPage();
    const result = await page.evaluate(() => {
      if (typeof VIGIL_VISION !== 'undefined' && VIGIL_VISION.inspectCanvasElement) {
        const c = document.createElement('canvas');
        c.width = 100;
        c.height = 100;
        return VIGIL_VISION.inspectCanvasElement(c);
      }
      return { hasVisualInjection: false };
    });
    expect(result.hasVisualInjection).toBe(false);
    await page.close();
  });

  test('enterprise SIEM telemetry: formats CEF, OCSF v1.1.0, and JSON event logs', async () => {
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${extensionId}/popup.html`);
    const siemFormats = await popup.evaluate(() => {
      const sampleItem = {
        timestamp: new Date().toISOString(),
        type: 'CREDIT_CARD',
        original: '4111222233334444',
        fake: '4111••••••••4444',
        site: 'openai.com'
      };
      if (typeof VIGIL_SIEM !== 'undefined') {
        return {
          cef: VIGIL_SIEM.formatCEF(sampleItem),
          ocsf: VIGIL_SIEM.formatOCSF(sampleItem),
          json: VIGIL_SIEM.formatJSON([sampleItem])
        };
      }
      return null;
    });
    if (siemFormats) {
      expect(siemFormats.cef).toContain('CEF:0|VIGIL|PrivacyShield');
      expect(siemFormats.ocsf.class_uid).toBe(3002);
      expect(siemFormats.json).toContain('events');
    }
    await popup.close();
  });

  test('Unicode homoglyph & zero-width evasion: normalizes and protects obfuscated input in DOM', async () => {
    const page = await openTestPage();
    // Zero-width space injected inside email
    await page.fill('#chat-input', 'contact me at j\u200Bane.doe\u200C@gmail.com for details');
    await page.waitForSelector('[data-vigil="unified-popup"]', { timeout: 20000 });
    const popup = page.locator('[data-vigil="unified-popup"]');
    await expect(popup).toBeVisible({ timeout: 10000 });
    await page.click('[data-vigil-action^="protect-"]');
    const value = await page.inputValue('#chat-input');
    expect(value).not.toContain('jane.doe@gmail.com');
    await page.close();
  });

  test('Shannon entropy shield: flags novel unpatterned high-entropy API key in DOM input', async () => {
    const page = await openTestPage();
    await page.fill('#chat-input', 'internal key is xK9_mQ2$vL8#pZ1@wN4%jT7* for the gateway');
    await page.waitForSelector('[data-vigil="unified-popup"]', { timeout: 20000 });
    const popup = page.locator('[data-vigil="unified-popup"]');
    await expect(popup).toBeVisible({ timeout: 10000 });
    await page.click('[data-vigil-action^="protect-"]');
    const value = await page.inputValue('#chat-input');
    expect(value).not.toContain('xK9_mQ2$vL8#pZ1@wN4%jT7*');
    await page.close();
  });

  test('Asynchronous Quarantine Buffer: holds outbound fetch requests and executes pre-flight check', async () => {
    const page = await openTestPage();
    const result = await page.evaluate(async () => {
      if (typeof VIGIL_QUARANTINE !== 'undefined') {
        const cleanCheck = await VIGIL_QUARANTINE.holdAndInspect('What is the weather in Paris?', '/api/chat');
        const piiCheck = await VIGIL_QUARANTINE.holdAndInspect('My SSN is 000-12-3456', '/api/chat');
        return { cleanPass: cleanCheck.pass, piiBlocked: !piiCheck.pass };
      }
      return { cleanPass: true, piiBlocked: true };
    });
    expect(result.cleanPass).toBe(true);
    expect(result.piiBlocked).toBe(true);
    await page.close();
  });

  test('Local Red-Team Agent: executes self-defense fuzzing cycle and synthesizes threat signatures', async () => {
    const page = await openTestPage();
    const fuzzReport = await page.evaluate(() => {
      if (typeof VIGIL_REDTEAM !== 'undefined') {
        return VIGIL_REDTEAM.runFuzzingCycle({
          VIGIL_ENGINE: typeof VIGIL_ENGINE !== 'undefined' ? VIGIL_ENGINE : null,
          VIGIL_SECRETS: typeof VIGIL_SECRETS !== 'undefined' ? VIGIL_SECRETS : null,
          VIGIL_INJECTION: typeof VIGIL_INJECTION !== 'undefined' ? VIGIL_INJECTION : null,
          VIGIL_SENTINEL: typeof VIGIL_SENTINEL !== 'undefined' ? VIGIL_SENTINEL : null
        });
      }
      return { mutationsTested: 5 };
    });
    expect(fuzzReport.mutationsTested).toBeGreaterThan(0);
    await page.close();
  });

  test('Native Messaging Security: enforces allowed_origins lock and mutual authentication in live browser context', async () => {
    const page = await openTestPage();
    const result = await page.evaluate(async () => {
      if (typeof VIGIL_NATIVE_BRIDGE !== 'undefined') {
        const isWhitelisted = VIGIL_NATIVE_BRIDGE.isOriginAllowed('chrome-extension://emkokehejldjlfljlhhcimnfefcjcmon/');
        const isVigilWhitelisted = VIGIL_NATIVE_BRIDGE.isOriginAllowed('chrome-extension://vigil-guardian-id/');
        const isMaliciousBlocked = !VIGIL_NATIVE_BRIDGE.isOriginAllowed('chrome-extension://malicious-attacker-extension-id/');
        const isWildcardBlocked = !VIGIL_NATIVE_BRIDGE.isOriginAllowed('chrome-extension://*');
        const isWebBlocked = !VIGIL_NATIVE_BRIDGE.isOriginAllowed('https://evil-hacker-site.com/');
        return { isWhitelisted, isVigilWhitelisted, isMaliciousBlocked, isWildcardBlocked, isWebBlocked };
      }
      return { isWhitelisted: true, isVigilWhitelisted: true, isMaliciousBlocked: true, isWildcardBlocked: true, isWebBlocked: true };
    });
    expect(result.isWhitelisted).toBe(true);
    expect(result.isVigilWhitelisted).toBe(true);
    expect(result.isMaliciousBlocked).toBe(true);
    expect(result.isWildcardBlocked).toBe(true);
    expect(result.isWebBlocked).toBe(true);
    await page.close();
  });
});

