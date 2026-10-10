/**
 * Tests for webmail profiles (extraction, sender checks, sent-skip) and
 * the Sentinel applySignals fold.
 */
const VIGIL_WEBMAIL = require('../src/content/modules/webmail-profile.js');
const VIGIL_SENTINEL = require('../src/content/modules/sentinel-engine.js');
const { detectWebmail, extractMessages, analyzeSender, isSentMail } = VIGIL_WEBMAIL;

function gmailDoc() {
  const doc = document.implementation.createHTMLDocument('Inbox - Gmail');
  const row = (name, email, subject, body) => {
    const tr = doc.createElement('tr');
    const sender = doc.createElement('span');
    sender.setAttribute('email', email);
    sender.textContent = name;
    const subj = doc.createElement('span');
    subj.className = 'bog';
    subj.textContent = subject;
    const bodyEl = doc.createElement('div');
    bodyEl.className = 'y6';
    bodyEl.textContent = body;
    tr.appendChild(sender); tr.appendChild(subj); tr.appendChild(bodyEl);
    doc.body.appendChild(tr);
  };
  row('Global Bank Security', 'global.bank.alert@gmail.com', 'Account suspended', 'Urgent: verify your password now or lose access immediately.');
  row('Sarah', 'sarah@family.com', 'Dinner Friday', 'Are we still on for dinner on Friday? I will bring the salad.');
  row('me', 'me', 'Sent message', 'I sent this myself yesterday.');
  return doc;
}

describe('webmail detection', () => {
  test('recognizes gmail and outlook hosts, rejects others', () => {
    expect(detectWebmail('mail.google.com')).toBe('gmail');
    expect(detectWebmail('outlook.live.com')).toBe('outlook');
    expect(detectWebmail('chat.openai.com')).toBeNull();
    expect(detectWebmail('')).toBeNull();
  });
});

describe('webmail extraction (gmail DOM shape)', () => {
  test('extracts sender name, email and subject per row', () => {
    const msgs = extractMessages(gmailDoc(), 'gmail');
    expect(msgs.length).toBe(3);
    const scam = msgs[0];
    expect(scam.senderEmail).toBe('global.bank.alert@gmail.com');
    expect(scam.senderName).toBe('Global Bank Security');
    expect(msgs[1].senderEmail).toBe('sarah@family.com');
  });
});

describe('sender checks', () => {
  test('corporate name from a free provider = display spoof', () => {
    const s = analyzeSender('Global Bank Security', 'global.bank.alert@gmail.com');
    expect(s.some(x => x.id === 'display_spoof')).toBe(true);
  });

  test('personal name from gmail is fine', () => {
    expect(analyzeSender('Sarah', 'sarah@family.com')).toEqual([]);
  });

  test('typosquat domains are caught (paypa1, rnicrosoft)', () => {
    expect(analyzeSender('Support', 'billing@paypa1.com').some(x => x.id === 'lookalike_domain')).toBe(true);
    expect(analyzeSender('Microsoft Support', 'help@rnicrosoft.com').some(x => x.id === 'lookalike_domain')).toBe(true);
  });

  test('the real domain itself is not flagged', () => {
    expect(analyzeSender('PayPal', 'service@paypal.com').some(x => x.id === 'lookalike_domain')).toBe(false);
  });
});

describe('sent-mail skip', () => {
  test('sender "me", vault email, and #sent views are skipped', () => {
    expect(isSentMail({ senderEmail: 'me', senderName: '' }, [], '')).toBe(true);
    expect(isSentMail({ senderEmail: 'me@work.com', senderName: 'Me' }, ['me@work.com'], '')).toBe(true);
    expect(isSentMail({ senderEmail: 'x@y.com' }, [], '#sent')).toBe(true);
    expect(isSentMail({ senderEmail: 'x@y.com' }, ['me@work.com'], '#inbox')).toBe(false);
  });
});

describe('Sentinel applySignals (webmail fold)', () => {
  test('sender signals escalate the level with standard thresholds', () => {
    const base = VIGIL_SENTINEL.analyzeMessage('Hi, quick question about your account settings when you have a moment today.');
    expect(base.level).toBe('none');
    const folded = VIGIL_SENTINEL.applySignals(base, [{ id: 'display_spoof', label: 'x', weight: 40 }]);
    expect(folded.level).toBe('suspicious');
  });

  test('no duplicate signal ids', () => {
    const base = VIGIL_SENTINEL.analyzeMessage('Urgent: act now to avoid legal action regarding your case.');
    const folded = VIGIL_SENTINEL.applySignals(base, [{ id: 'urgency', label: 'dup', weight: 15 }]);
    expect(folded.signals.filter(s => s.id === 'urgency')).toHaveLength(1);
  });
});

describe('Foundational Cryptographic Alignment & Link Disambiguation', () => {
  const { isCryptographicallyAligned, isSpamContext, hasProviderWarning, stripFooterBoilerplate, analyzeMessageLinks } = VIGIL_WEBMAIL;

  test('genuine github / google / amazon domains are cryptographically aligned when clean', () => {
    const doc = document.implementation.createHTMLDocument('Inbox');
    expect(isCryptographicallyAligned({ senderEmail: 'notifications@github.com' }, doc, '#inbox')).toBe(true);
    expect(isCryptographicallyAligned({ senderEmail: 'no-reply@accounts.google.com' }, doc, '#inbox')).toBe(true);
    expect(isCryptographicallyAligned({ senderEmail: 'auto-confirm@amazon.com' }, doc, '#inbox')).toBe(true);
  });

  test('messages in spam folder are NEVER cryptographically aligned', () => {
    const doc = document.implementation.createHTMLDocument('Spam');
    expect(isCryptographicallyAligned({ senderEmail: 'notifications@github.com' }, doc, '#spam')).toBe(false);
  });

  test('messages with provider unverified warnings are NEVER cryptographically aligned', () => {
    const doc = document.implementation.createHTMLDocument('Inbox');
    const container = doc.createElement('div');
    const warn = doc.createElement('div');
    warn.className = 'bBe';
    warn.textContent = 'Gmail couldn\'t verify that github.com actually sent this message';
    container.appendChild(warn);
    doc.body.appendChild(container);

    expect(hasProviderWarning(container, doc)).toBe(true);
    expect(isCryptographicallyAligned({ senderEmail: 'notifications@github.com', el: container }, doc, '#inbox')).toBe(false);
  });

  test('extracts spam rows even when span[email] is omitted by Gmail', () => {
    const doc = document.implementation.createHTMLDocument('Spam');
    const tr = doc.createElement('tr');
    tr.className = 'zA';
    const senderCell = doc.createElement('div');
    senderCell.className = 'yW';
    senderCell.textContent = 'support@suspicious-crypto.xyz';
    const subj = doc.createElement('span');
    subj.className = 'bog';
    subj.textContent = 'Claim your Bitcoin lottery reward immediately';
    const body = doc.createElement('div');
    body.className = 'y6';
    body.textContent = 'Send $500 processing fee to release your funds.';
    tr.appendChild(senderCell); tr.appendChild(subj); tr.appendChild(body);
    doc.body.appendChild(tr);

    const msgs = extractMessages(doc, 'gmail');
    expect(msgs.length).toBe(1);
    expect(msgs[0].senderEmail).toBe('support@suspicious-crypto.xyz');
    expect(msgs[0].subject).toContain('Bitcoin');
  });

  test('ignores standard collapsed inbox rows lacking email addresses to prevent false positives', () => {
    const doc = document.implementation.createHTMLDocument('Inbox');
    const tr = doc.createElement('tr');
    tr.className = 'zA yO';
    const senderCell = doc.createElement('div');
    senderCell.className = 'yW';
    senderCell.textContent = 'Google';
    const subj = doc.createElement('span');
    subj.className = 'bog';
    subj.textContent = 'Security alert: new sign-in from Mac';
    tr.appendChild(senderCell); tr.appendChild(subj);
    doc.body.appendChild(tr);

    const msgs = extractMessages(doc, 'gmail');
    expect(msgs.length).toBe(0);
  });

  test('recognizes spam context from hash and DOM', () => {
    const doc = document.implementation.createHTMLDocument('Spam folder');
    expect(isSpamContext(doc, '#spam')).toBe(true);
    expect(isSpamContext(doc, '#junk')).toBe(true);
    expect(isSpamContext(doc, '#inbox')).toBe(false);
  });

  test('stripFooterBoilerplate eliminates marketing and unsubscribe footers', () => {
    const body = 'Hello team, please find the quarterly report details above.\n\nTo update your email preferences or unsubscribe from this list, click here.\nAll rights reserved.';
    const cleaned = stripFooterBoilerplate(body);
    expect(cleaned).toContain('quarterly report details');
    expect(cleaned).not.toContain('unsubscribe from this list');
  });

  test('analyzeMessageLinks flags shorteners and phishing login misdirection', () => {
    const doc = document.implementation.createHTMLDocument('Email');
    const container = doc.createElement('div');
    const a1 = doc.createElement('a');
    a1.href = 'https://bit.ly/3XYZphish';
    a1.textContent = 'Click here';
    const a2 = doc.createElement('a');
    a2.href = 'https://paypal-security-account.net/login';
    a2.textContent = 'Log in to your PayPal account';
    container.appendChild(a1);
    container.appendChild(a2);

    const res = analyzeMessageLinks(container, 'service@paypal.com');
    expect(res.hasShortener).toBe(true);
    expect(res.hasMisdirection).toBe(true);
  });
});

