/**
 * Tests for Blueprint #6: Site Access Modes (Mode A, Mode B, Mode C)
 * Verifies that universal coverage is preserved by default while supporting
 * on-demand and protected-sites filtering to minimize unnecessary scans.
 */
const VIGIL = require('../src/shared/vigil-shared.js');

function isSiteProtected(hostname, currentSettings, isWhitelisted, isSessionActivated) {
  if (isWhitelisted) return false;
  const mode = (currentSettings && currentSettings.protectionMode) || 'all';
  if (mode === 'all') return true; // Mode C: Universal
  if (mode === 'on_demand') {
    return Boolean(isSessionActivated); // Mode A: On Demand
  }
  if (mode === 'protected_only') {
    const list = (currentSettings && currentSettings.protectedSites) || [];
    const host = (hostname || '').toLowerCase();
    return list.some(s => host === s.toLowerCase() || host.endsWith('.' + s.toLowerCase())); // Mode B: Protected Sites
  }
  return true;
}

describe('Blueprint #6: Site Protection Access Modes', () => {
  test('Mode C (All-site protection - default): protects all sites, respects trustedSites whitelist', () => {
    const settings = VIGIL.mergeSettings({});
    expect(settings.protectionMode).toBe('all');

    expect(isSiteProtected('chat.openai.com', settings, false, false)).toBe(true);
    expect(isSiteProtected('random-blog.org', settings, false, false)).toBe(true);
    expect(isSiteProtected('news.ycombinator.com', settings, false, false)).toBe(true);

    // Whitelisted site is not protected
    expect(isSiteProtected('trusted-internal.corp', settings, true, false)).toBe(false);
  });

  test('Mode B (Protected sites only): restricts monitoring strictly to designated AI & webmail domains', () => {
    const settings = VIGIL.mergeSettings({
      protectionMode: 'protected_only',
      protectedSites: ['chatgpt.com', 'claude.ai', 'mail.google.com']
    });

    expect(isSiteProtected('chatgpt.com', settings, false, false)).toBe(true);
    expect(isSiteProtected('app.claude.ai', settings, false, false)).toBe(true);
    expect(isSiteProtected('mail.google.com', settings, false, false)).toBe(true);

    // Unrelated sites are ignored
    expect(isSiteProtected('wikipedia.org', settings, false, false)).toBe(false);
    expect(isSiteProtected('github.com', settings, false, false)).toBe(false);
  });

  test('Mode A (On demand): inactive by default, activates only upon explicit user session activation', () => {
    const settings = VIGIL.mergeSettings({
      protectionMode: 'on_demand'
    });

    // Inactive without user click
    expect(isSiteProtected('chatgpt.com', settings, false, false)).toBe(false);
    expect(isSiteProtected('random-site.com', settings, false, false)).toBe(false);

    // Active once user triggers session activation in popup / hotkey
    expect(isSiteProtected('chatgpt.com', settings, false, true)).toBe(true);
    expect(isSiteProtected('random-site.com', settings, false, true)).toBe(true);
  });
});

