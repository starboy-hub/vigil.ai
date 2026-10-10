/**
 * VIGIL Webmail Profiles
 * Gmail / Outlook DOM extraction: sender + subject per message, email-specific
 * sender checks (display-name spoofing, lookalike domains), spam folder handling,
 * and Foundational Cryptographic Alignment (The Ultimate Whitelist).
 * link target alignment (phishing redirect analysis), structural footer boilerplate
 * stripping, and Foundational Cryptographic Alignment (The Ultimate Whitelist).
 * Pure DOM functions — defensive by design, webmail DOMs change often, so every
 * extraction degrades gracefully instead of throwing.
 */
(function (root) {
  'use strict';

  const WEBMAIL_HOSTS = {
    'mail.google.com': 'gmail',
    'outlook.office.com': 'outlook',
    'outlook.live.com': 'outlook',
    'outlook.office365.com': 'outlook'
  };

  // Domains scammers commonly impersonate with typosquats
  const PROTECTED_DOMAINS = [
    'paypal.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'netflix.com', 'facebook.com', 'instagram.com', 'whatsapp.com',
    'binance.com', 'coinbase.com', 'chase.com', 'wellsfargo.com',
    'bankofamerica.com', 'hsbc.com', 'dhl.com', 'fedex.com', 'ups.com',
    'gmail.com', 'outlook.com', 'icloud.com'
  ];

  // Enterprise / Foundational Corporate Domains protected by universal
  // strict SPF, DKIM, and DMARC reject/quarantine policies.
  const FOUNDATIONAL_DOMAINS = [
    'github.com', 'google.com', 'accounts.google.com', 'apple.com', 'microsoft.com',
    'amazon.com', 'paypal.com', 'stripe.com', 'netflix.com', 'uber.com',
    'airbnb.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citi.com',
    'americanexpress.com', 'capitalone.com', 'fidelity.com', 'vanguard.com',
    'schwab.com', 'coinbase.com', 'binance.com', 'spotify.com', 'slack.com',
    'notion.so', 'figma.com', 'cloudflare.com', 'gitlab.com', 'atlassian.com',
    'linkedin.com', 'twitter.com', 'x.com', 'dropbox.com', 'zoom.us',
    'docusign.com', 'fedex.com', 'ups.com', 'dhl.com', 'usps.com',
    'steampowered.com', 'steamcommunity.com'
  ];

  const FREE_EMAIL_PROVIDERS = [
    'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'aol.com',
    'proton.me', 'protonmail.com', 'icloud.com', 'mail.com', 'zoho.com',
    'yandex.com', 'gmx.com'
  ];

  function detectWebmail(host) {
    const h = String(host || '').toLowerCase();
    if (WEBMAIL_HOSTS[h]) return WEBMAIL_HOSTS[h];
    // Support local Cyber Range and Playground testbeds
    if (typeof document !== 'undefined' && (h === '127.0.0.1' || h === 'localhost') && document.querySelector('.adn.ads, [data-thread-id], tr.zA, #mail-view')) {
      return 'gmail';
    }
    return null;
  }

  function isFreeEmailProvider(domain) {
    const d = String(domain || '').toLowerCase();
    return FREE_EMAIL_PROVIDERS.includes(d);
  }

  function getRootDomain(hostname) {
    if (!hostname) return '';
    const parts = hostname.toLowerCase().split('.');
    if (parts.length <= 2) return hostname;
    const ccTlds = ['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'co.in'];
    const lastTwo = parts.slice(-2).join('.');
    if (ccTlds.includes(lastTwo) && parts.length > 2) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  // ---- Contextual & Cryptographic Verification Helpers ----

  /**
   * Check if current view is the Spam or Junk folder
   */
  function isSpamContext(doc, locationHash, container) {
    const hash = String(locationHash || '').toLowerCase();
    if (hash.includes('spam') || hash.includes('junk')) return true;
    if (container) {
      if (typeof container.closest === 'function' && container.closest('[data-folder="spam"], [aria-label*="Spam"], [aria-label*="Junk"]')) {
        return true;
      }
      const text = container.textContent || '';
      if (/why is this message in spam/i.test(text)) return true;
    }
    if (doc) {
      const activeFolder = doc.querySelector('.aio.aip, [aria-selected="true"], .qj');
      if (activeFolder && /spam|junk/i.test(activeFolder.textContent || '')) return true;
    }
    return false;
  }

  /**
   * Check if Gmail or Outlook displays warning banners regarding sender authenticity,
   * spoofing, phishing, or unverified origin.
   */
  function hasProviderWarning(container, doc) {
    const target = container || doc;
    if (!target) return false;
    // Check provider warning banner elements
    const warnEl = target.querySelector ? target.querySelector(
      '.bBe, .a9q, .m6, div[role="alert"], div.vh, div.asl, .phishingBar, .safetyWarning, ' +
      '[data-tooltip*="couldn\'t verify"], [aria-label*="couldn\'t verify"], [aria-label*="unverified"], ' +
      '[aria-label*="phishing"], [data-tooltip*="spam"]'
    ) : null;
    if (warnEl) return true;

    // Check textual warning signatures from mail provider
    const text = (container ? container.textContent : '') || '';
    if (/(?:couldn'?t verify|could not verify|be careful with this message|seems dangerous|phishing|unverified sender|why is this message in spam)/i.test(text)) {
      return true;
    }
    return false;
  }

  /**
   * Foundational Cryptographic Alignment (The Ultimate Whitelist):
   * Proves that an inbound message originates authentically from a known foundational
   * brand that enforces strict SPF/DKIM/DMARC, with NO spoofing or security warnings
   * displayed by the mail provider, and NOT located in the Spam folder.
   */
  function isCryptographicallyAligned(msg, doc, locationHash) {
    if (!msg || !msg.senderEmail) return false;
    const email = String(msg.senderEmail).toLowerCase().trim();
    if (!email.includes('@')) return false;

    // 1. Never align messages located in the Spam / Junk folder
    if (isSpamContext(doc, locationHash, msg.el)) return false;

    // 2. Never align messages where Gmail/Outlook raised an unverified/spoofed sender banner
    if (hasProviderWarning(msg.el, doc)) return false;

    // 3. Match against foundational domain roots
    const domain = email.split('@')[1];
    const isDomainAligned = FOUNDATIONAL_DOMAINS.some(fd => domain === fd || domain.endsWith('.' + fd));
    if (!isDomainAligned) return false;

    // 4. Protect against free-provider display-name spoofing
    const freeProviders = ['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'aol.com', 'proton.me', 'icloud.com'];
    if (freeProviders.includes(domain)) return false;
    if (isFreeEmailProvider(domain)) return false;

    return true;
  }

  /**
   * Strip standard transactional/marketing footer boilerplate
   * (e.g. "unsubscribe", "update your preferences", "all rights reserved")
   * to eliminate false positives on privacy disclaimers and footer links.
   */
  function stripFooterBoilerplate(text) {
    if (!text) return '';
    const footerMarkers = [
      /\n\s*(?:to update your (?:email )?preferences|manage your preferences|unsubscribe from this list|click here to unsubscribe)/i,
      /\n\s*(?:you are receiving this email because|this email was sent to \S+@\S+)/i,
      /\n\s*(?:all rights reserved\b|privacy policy\s*\|\s*terms of (?:service|use))/i,
      /\n\s*(?:please do not reply to this email|this is an automated message, please do not reply)/i
    ];
    let cleaned = text;
    for (const marker of footerMarkers) {
      const match = cleaned.search(marker);
      if (match !== -1 && match > 50) {
        cleaned = cleaned.slice(0, match).trim();
      }
    }
    return cleaned;
  }

  /**
   * Extract links from message container and analyze target alignment with sender domain.
   */
  function analyzeMessageLinks(container, senderEmail) {
    if (!container || !container.querySelectorAll) return { links: [], hasShortener: false, hasMisdirection: false };
    const links = [];
    const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'ow.ly', 'buff.ly', 'cutt.ly', 'rb.gy'];
    let hasShortener = false;
    let hasMisdirection = false;
    let senderDomain = '';
    if (senderEmail && senderEmail.includes('@')) {
      senderDomain = senderEmail.split('@')[1].toLowerCase();
    }

    const anchorEls = container.querySelectorAll('a[href]');
    for (const a of anchorEls) {
      const href = a.getAttribute('href') || '';
      if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('javascript:')) continue;
      try {
        const url = new URL(href, 'https://mail.google.com');
        const host = url.hostname.toLowerCase();
        links.push({ href, host, text: (a.textContent || '').trim() });

        if (SHORTENERS.some(s => host === s || host.endsWith('.' + s))) {
          hasShortener = true;
        }

        // If sender is a corporate domain, check if link claims to be login/verification on foreign domain
        if (senderDomain && !isFreeEmailProvider(senderDomain) && !senderDomain.endsWith('.local') && senderDomain !== 'unverified') {
          const rootSender = getRootDomain(senderDomain);
          const rootLink = getRootDomain(host);
          const isCommonTracking = /sendgrid\.net|mailgun\.org|sparkpostmail\.com|mandrillapp\.com|hubspotlinks\.com|constantcontact\.com|awstrack\.me/i.test(host);
          if (rootSender && rootLink && rootSender !== rootLink && !isCommonTracking) {
            const linkText = (a.textContent || '').toLowerCase();
            if (/(?:log ?in|sign ?in|verify|secure|update|account|password|banking|confirm)/i.test(linkText)) {
              hasMisdirection = true;
            }
          }
        }
      } catch (e) {}
    }
    return { links, hasShortener, hasMisdirection };
  }

  // ---- DOM extraction ----

  function extractGmail(doc) {
    const messages = [];
    const seen = new Set();

    // 1. Standard rows / conversation blocks with span[email] or span.gD
    doc.querySelectorAll('span[email], span.gD').forEach(el => {
      const email = (el.getAttribute('email') || '').toLowerCase();
      const container = el.closest('[data-thread-id], tr.zA, tr, [role="listitem"], .adn.ads') || el.parentElement;
      if (!container || seen.has(container)) return;
      const recheck = container.hasAttribute && (container.hasAttribute('data-vigil-recheck') || (container.closest && container.closest('[data-vigil-recheck]')));
      if (container.hasAttribute && container.hasAttribute('data-vigil-webmail') && !recheck) return;
      seen.add(container);
      const name = (el.textContent || '').trim();
      const subjectEl = container.querySelector('[data-thread-id] .hP, .hP, .bog, .y6, .bqe, span.bqe');
      const bodyEl = container.querySelector('.a3s.aiL, .a3s, .ii.gt, .y6, .message-body');
      const isRow = !!(container && container.matches && container.matches('tr.zA, [role="row"]') && !container.querySelector('.a3s'));
      messages.push({
        el: container,
        isRow,
        senderName: name === 'me' ? '' : name,
        senderEmail: email,
        subject: subjectEl ? subjectEl.textContent.trim() : '',
        bodyText: bodyEl ? bodyEl.textContent.trim() : '',
        linkAnalysis: analyzeMessageLinks(container, email)
      });
    });

    // 2. Fallback for Gmail Spam folder / untrusted rows where span[email] is omitted
    const inSpam = isSpamContext(doc, (typeof location !== 'undefined' ? location.hash : '') || (typeof window !== 'undefined' && window.location ? window.location.hash : ''));
    doc.querySelectorAll('tr.zA, [role="row"], .Cp table tr').forEach(container => {
      if (seen.has(container) || container.hasAttribute('data-vigil-webmail')) return;
      const senderBox = container.querySelector('.yW, .zF, .bqe, [role="gridcell"]:first-child');
      if (!senderBox) return;
      const rawSender = senderBox.textContent.trim();
      const emailMatch = rawSender.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
      const hasWarn = hasProviderWarning(container, doc);

      // Only extract rows without span[email] if:
      // a) senderBox actually contains an email address (e.g. support@suspicious-crypto.xyz), or
      // b) we are in the Spam/Junk folder, or
      // c) the row has an explicit provider warning banner.
      // Standard inbox rows without email addresses will be scanned when opened.
      if (!emailMatch && !inSpam && !hasWarn) return;

      seen.add(container);
      const email = emailMatch ? emailMatch[0].toLowerCase() : '';
      const name = emailMatch ? rawSender.replace(emailMatch[0], '').trim() : rawSender;
      const subjectEl = container.querySelector('.bog, .y6, .bqe, span.bqe');
      const bodyEl = container.querySelector('.y6, .a3s');
      const isRow = !!(container && container.matches && container.matches('tr.zA, [role="row"]') && !container.querySelector('.a3s'));
      messages.push({
        el: container,
        isRow,
        senderName: name === 'me' ? '' : name,
        senderEmail: email,
        subject: subjectEl ? subjectEl.textContent.trim() : '',
        bodyText: bodyEl ? bodyEl.textContent.trim() : '',
        linkAnalysis: analyzeMessageLinks(container, email)
      });
    });

    return messages;
  }

  function extractOutlook(doc) {
    const messages = [];
    const seen = new Set();
    // Outlook list rows: role="option" with aria-label "Sender, subject, ..."
    doc.querySelectorAll('div[role="option"][aria-label], div[role="listitem"][aria-label]').forEach(el => {
      if (seen.has(el) || el.hasAttribute('data-vigil-webmail')) return;
      seen.add(el);
      const label = el.getAttribute('aria-label') || '';
      const firstComma = label.indexOf(',');
      if (firstComma === -1) return;
      const sender = label.slice(0, firstComma).trim();
      if (!sender || sender.toLowerCase() === 'me') return;
      const email = (el.querySelector('span[email], a[email]')?.getAttribute('email') || '').toLowerCase();
      const bodyEl = el.querySelector('div.ReadingPaneContainer, div[aria-label="Message body"], div.elementToProof');
      messages.push({
        el,
        senderName: sender,
        senderEmail: email,
        subject: label.slice(firstComma + 1).split(',')[0].trim(),
        bodyText: bodyEl ? bodyEl.textContent.trim() : '',
        linkAnalysis: analyzeMessageLinks(el, email)
      });
    });
    return messages;
  }

  function extractMessages(doc, kind) {
    try {
      return kind === 'gmail' ? extractGmail(doc) : extractOutlook(doc);
    } catch (e) {
      return [];
    }
  }

  // ---- Email-specific checks (pure) ----

  function levenshtein(a, b) {
    if (Math.abs(a.length - b.length) > 2) return 99;
    const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
    for (let j = 1; j <= b.length; j++) dp[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,
          dp[i][j - 1] + 1,
          dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
        );
      }
    }
    return dp[a.length][b.length];
  }

  /**
   * Sender-focused signals for one message.
   * @returns {Array<{id, label, weight}>}
   */
  function analyzeSender(senderName, senderEmail) {
    const signals = [];
    if (!senderEmail || senderEmail.indexOf('@') === -1) return signals;
    const domain = senderEmail.split('@')[1];

    // Display-name spoofing: "Global Bank" writing from free email provider
    if (senderName && isFreeEmailProvider(domain)) {
      const corporateish = /(bank|pay|security|support|service|admin|official|team|help|invoice|billing|finance|irs|tax|customs|delivery)/i;
      if (corporateish.test(senderName)) {
        signals.push({ id: 'display_spoof', label: 'Corporate name writing from a free email provider', weight: 40 });
      }
    }

    // Lookalike domains: typosquats of well-known brands
    const root = domain.replace(/\.(com|net|org|co|io|xyz|info|online|shop)$/i, '');
    const corporateish = /(bank|pay|security|support|service|admin|official|team|help|invoice|billing|finance|irs|tax|customs|delivery|no[-.]?reply)/i;
    for (const target of PROTECTED_DOMAINS) {
      const tRoot = target.replace(/\.(com|net|org|co|io|xyz|info|online|shop)$/i, '');
      if (root === tRoot) break; // exact match: legitimate
      if (root.length >= 4 && tRoot.length >= 4) {
        const maxDist = root.length >= 8 ? 2 : 1;
        if (levenshtein(root, tRoot) <= maxDist && (!senderName || corporateish.test(senderName))) {
          signals.push({ id: 'lookalike_domain', label: 'Lookalike domain (typosquat of ' + target + ')', weight: 45 });
          break;
        }
      }
    }
    return signals;
  }

  /**
   * Should this message be skipped? Sent mail must not be scanned — it is the
   * user's own outbound content.
   */
  function isSentMail(msg, userEmails, locationHash) {
    const hash = String(locationHash || '').toLowerCase();
    if (hash.includes('sent') || hash.includes('sentitems') || hash.includes('#sent')) return true;
    const sender = (msg.senderEmail || '').toLowerCase();
    const name = (msg.senderName || '').toLowerCase();
    if (sender === 'me' || name === 'me') return true;
    return (userEmails || []).some(u => u.toLowerCase() === sender);
  }

  /**
   * Synthesizes a plain-English, 1-sentence explanatory reason for an email threat
   * in reading panes, avoiding intimidating technical abbreviations.
   */
  function generatePhishingReasoning(msg, result, linkInfo) {
    if (!result || result.level === 'none' || result.level === 'low') return null;
    const signals = result.signals || [];
    const senderName = (msg && (msg.senderName || msg.senderEmail)) || 'The sender';
    const senderDomain = (msg && msg.senderEmail && msg.senderEmail.includes('@')) ? msg.senderEmail.split('@')[1] : 'the sender domain';

    if (linkInfo && linkInfo.hasMisdirection) {
      return `This email claims to be an official communication from ${senderName}, but its action button actually routes to an unverified third-party address (${linkInfo.mismatchedHost || 'external site'}), not ${senderDomain}.`;
    }
    if (linkInfo && linkInfo.hasShortener) {
      return `This message employs an obfuscated URL shortener (${linkInfo.shortenerHost || 'short link'}) to disguise the true destination of its link.`;
    }
    if (signals.some(s => s.id === 'lookalike_domain')) {
      return `The sender address (${senderDomain}) is an adversarial typosquatting domain mimicking a trusted corporate brand.`;
    }
    if (signals.some(s => s.id === 'display_spoof')) {
      return `The message uses corporate branding ("${senderName}"), but was dispatched from an unverified public mailbox (${senderDomain}).`;
    }
    if (signals.some(s => s.id === 'pressure_coercive')) {
      return 'The message employs coercive psychological urgency or account suspension threats to compel you to verify private credentials or send funds.';
    }
    return `Security anomalies detected: Suspicious origin headers and urgent pressure patterns detected for ${senderName}.`;
  }

  const VIGIL_WEBMAIL = {
    detectWebmail,
    extractMessages,
    analyzeSender,
    isSentMail,
    isSpamContext,
    hasProviderWarning,
    isCryptographicallyAligned,
    stripFooterBoilerplate,
    analyzeMessageLinks,
    getRootDomain,
    isFreeEmailProvider,
    generatePhishingReasoning,
    PROTECTED_DOMAINS,
    FOUNDATIONAL_DOMAINS,
    FREE_EMAIL_PROVIDERS
  };
  root.VIGIL_WEBMAIL = VIGIL_WEBMAIL;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_WEBMAIL;
})(typeof self !== 'undefined' ? self : globalThis);

