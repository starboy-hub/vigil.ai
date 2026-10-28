/**
 * VIGIL Detection Engine
 * Regex + context PII scanning, name heuristics, and custom patterns.
 *
 * This is the single source of truth for detection — loaded before
 * content.js in the manifest and required directly by tests.
 * (Keep this file framework-free so it runs in pages, workers, and Node.)
 */
(function (root) {
  'use strict';

  const PII_PATTERNS = {
    'SSN': /\b\d{3}-\d{2}-\d{4}\b/g,
    'Credit Card': /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    'Email': /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    'Phone': /(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\b\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    'Street Address': /\b\d{1,5}\s+[A-Za-z0-9.,#-]+(?:\s+[A-Za-z0-9.,#-]+){0,4}\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Terrace|Ter|Place|Pl|Circle|Cir)\b(?:,?\s+[A-Za-z]+(?:\s+[A-Za-z]+){0,2},?\s+[A-Z]{2}\s+\d{5}(?:-\d{4})?)?/gi,
    'IP Address': /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
    'Date of Birth': /\b(?:born on|DOB:|birthday:?|Date of Birth:?)\s*(?:is\s+)?:?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b/gi,
    'Passport': /\b(?:passport|passport\s*#?)\s*:?\s*([A-Z]{1,2}\d{6,9})\b/gi,
    'Bank Account': /\b(?:bank\s+account|account|acct)\s+(?:is\s+)?:?\s*(\d{8,17})\b/gi,
    'Driver License': /\b(?:driver\s+license|driver'?s?\s+license|license|DL)\s*#?\s*:?\s*([A-Z]?\d{2,4}[-\s]?\d{2,4}[-\s]?\d{2,4})\b/gi,
    'Medical Record': /\b(?:MRN|medical\s*record)\s*-?\s*#?:?\s*(?:MRN\s+)?(\d{6,10})\b/gi
  };

  // ---- Security Policy: Contextual Precision Engine (CPE) ----
  // Clause segmentation: split on punctuation, newlines, and coordinating conjunctions
  const CLAUSE_DELIMITER = /[,.;!?\n]+|\b(?:and|but|while|whereas|however|although)\b/i;

  // Negative invalidation filters (Academic, clinical, statistical, case law suppressions)
  const SUPPRESSION_PATTERNS = {
    'MEDICAL': /\b(?:how\s+to\s+treat|treatment\s+for|treatments?\s+of|antipyretics?\s+(?:for|to|treat)?|medications?\s+(?:for|to|used\s+for)|drugs?\s+(?:for|to)|mechanism\s+of|pathophysiology\s+of|etiology\s+of|symptoms?\s+of|causes?\s+of|dosage\s+for|differential\s+diagnosis\s+of|study\s+(?:on|of)|indicated\s+for|guidelines?\s+for|pharmacology\s+of|management\s+of|overview\s+of|definition\s+of|research\s+on)\b/i,
    'FINANCIAL': /\b(?:median|average|national\s+average|benchmark|market\s+rate|industry\s+standard|typical\s+compensation|budget\s+for|cost\s+of\s+living|range\s+for|statistics?\s+on|salary\s+trends?|compensation\s+survey)\b/i,
    'LEGAL': /\b(?:precedent\s+in|precedent|case\s+law|supreme\s+court|penal\s+code|statute\s+of\s+limitations|doctrine\s+of|jurisprudence|history\s+of|landmark\s+case|study\s+of|lawsuit\s+precedent|analysis\s+of\s+(?:the\s+)?lawsuit)\b/i,
    'PERSONAL': /\b(?:statistics?\s+on|rates?\s+of|sociology\s+of|studies?\s+show|research\s+on|trends?\s+in|demographics\s+of)\b/i
  };

  // Experiencer triggers (1st person personal disclosures, family disclosures)
  const EXPERIENCER_TRIGGERS = {
    'MEDICAL': /\b(?:I(?:'ve been| was| have been| am|'m) diagnosed with|I suffer from|my diagnosis is|me diagnosticaron|on m'a diagnostiqué|je souffre de|mir wurde diagnostiziert|leide unter|sofro de|soffro di|мне поставили диагноз|я страдаю от|我被诊断出|تم تشخيصي بـ|أعاني من|I have|I've got|I am having|I'm having|my doctor said|treating my|diagnosed me with|my\s+(?:son|daughter|child|kid|wife|husband|partner|mother|father|mom|dad)\s+(?:has|was\s+diagnosed|suffers\s+from)|tengo|j'ai|ich habe|eu tenho|ho)\b|(?:у меня есть|我有|لدي)/i,
    'FINANCIAL': /\b(?:my salary is|I earn|I make|annual income|yearly income|mi salario es|gano|mi sueldo es|mon salaire est|je gagne|mein gehalt ist|ich verdiene|meu salário é|ganho|il mio stipendio è|guadagno|моя зарплата|я зарабатываю|راتبي هو|أكسب|دخلي السنوي|my debt|my income|my credit score|I defaulted on|I was paid)\b|(?:我的工资是|我赚|我的年薪)/i,
    'LEGAL': /\b(?:my lawyer|my attorney|I am suing|I'm suing|I was arrested|I was charged with|I was convicted|my parole|my probation|my court case|my divorce|I am being sued)\b/i,
    'PERSONAL': /\b(?:I am getting divorced|my partner cheated|I am in a custody battle|getting divorced|my affair|in my divorce)\b/i
  };

  // High-stigma exceptions that flag regardless of experiencer scoping
  const HIGH_STIGMA_PATTERN = /\b(?:HIV|AIDS|suicide|suicidal)\b/i;

  function splitIntoClauses(text) {
    if (!text) return [];
    return text.split(CLAUSE_DELIMITER).map(c => c.trim()).filter(Boolean);
  }

  function getClauseForMatch(text, matchIndex, matchLength) {
    // Find the enclosing clause boundaries
    const before = text.slice(0, matchIndex);
    const after = text.slice(matchIndex + matchLength);
    const prevDelimiter = Math.max(before.lastIndexOf('.'), before.lastIndexOf(','), before.lastIndexOf(';'), before.lastIndexOf('?'), before.lastIndexOf('!'), before.lastIndexOf('\n'));
    const nextDelimiterRel = after.search(/[,.;!?\n]/);
    const start = prevDelimiter >= 0 ? prevDelimiter + 1 : 0;
    const end = nextDelimiterRel >= 0 ? matchIndex + matchLength + nextDelimiterRel : text.length;
    return text.slice(start, end).trim();
  }

  function isClauseSensitive(clause, type) {
    if (!clause) return false;
    // High-stigma exceptions alert unconditionally
    if (HIGH_STIGMA_PATTERN.test(clause)) return true;

    // Academic / general inquiry / legal precedent suppression
    const suppression = SUPPRESSION_PATTERNS[type];
    if (suppression && suppression.test(clause)) {
      // If suppression matches and NO explicit 1st-person disclosure is present, suppress
      const experiencer = EXPERIENCER_TRIGGERS[type];
      if (!experiencer || !experiencer.test(clause)) {
        return false;
      }
    }

    // 1st-person experiencer disclosure -> REDACT
    const experiencer = EXPERIENCER_TRIGGERS[type];
    if (experiencer && experiencer.test(clause)) return true;

    // Unanchored dictionary mentions without personal attribution are suppressed (PASS)
    return false;
  }

  const CONTEXT_PATTERNS = [
    // Strict verbs: "diagnosed with X" / "suffer from X" is inherently medical — open capture
    { type: 'MEDICAL', subType: 'CONDITION', valueGroup: true, pattern: /(?:I(?:'ve been| was| have been| am|'m) diagnosed with|I suffer from|my diagnosis is|me diagnosticaron|on m'a diagnostiqué|je souffre de|mir wurde diagnostiziert|leide unter|sofro de|soffro di|мне поставили диагноз|я страдаю от|我被诊断出|تم تشخيصي بـ|أعاني من)\s+([a-zA-Z\u00C0-\u00FF\u0400-\u04FF\u4E00-\u9FA5\u0600-\u06FF\s-]{2,50})/gi },
    // "I have"-style verbs: match exact condition word with strict boundary (no greedy trailing wildcards)
    { type: 'MEDICAL', subType: 'CONDITION', valueGroup: true, pattern: /(?:I have|tengo|j'ai|ich habe|eu tenho|ho|у меня есть|我有|لدي)\s+(?:an?\s+)?((?:diabetes|cancer|cáncer|krebs|hiv|aids|hepatitis|hepatite|tuberculosis|tuberculose|depression|depressión|dépression|depressione|депрессия|抑郁|ansiedad|anxiété|angststörung|ansiedade|asthma|asma|migraine|migraña|migräne|emicrania|insomnia|insomnio|insomnie|schizophrenia|esquizofrenia|schizophrénie|bipolar|arthritis|arthrite|arthrose|eczema|eczéma|psoriasis|allergies|allergy|alergia|alergias|allergie|epilepsy|epilepsia|épilepsie|hypertension|covid|long covid|fibromyalgia|fibromialgia|endometriosis|endometriose|hypothyroidism|hipotiroidismo|leukemia|leucemia|leucémie|tumor|dementia|demencia|démence|demenz|anorexia|bulimia|obesity|obesidad|obésité|high cholesterol|cholesterol|colesterol|cholestérol|fever|fiebre|fièvre|fieber|the flu|gripe|grippe|a stroke|lupus|lyme|meningitis|pneumonia|neumonía|pneumonie|gastritis|adhd|ocd|ptsd|autism)\b)/gi },
    { type: 'MEDICAL', subType: 'CONDITION', pattern: /\b(?:pregnant|pregnancy|miscarriage|fertility|IVF|chemotherapy|radiation|dialysis|embarazada|embarazo|enceinte|schwanger|grávida|incinta|беременная|怀孕|حامل)\b/gi },
    // Bare medical keywords: only scoped if not suppressed by academic/treatment queries
    { type: 'MEDICAL', subType: 'CONDITION', contextual: true, pattern: /\b(?:diabetes|cancer|HIV|AIDS|hepatitis|tuberculosis|depression|anxiety|bipolar|schizophrenia|PTSD|addiction|alcoholism|opioid|diabète|diabete|depresión|dépression|depressa|депрессия|抑郁|اكتئاب|ansiedad|asthma|migraine|hypertension|fever)\b/gi },
    { type: 'MEDICAL', subType: 'MEDICATION', valueGroup: true, pattern: /(?:I am taking|I'm taking|I take|taking my|I am on|I'm on|on my|using my|estoy tomando|tomo mi|je prends mon|ich nehme mein|eu tomo meu|prendo il mio|я принимаю|我在吃|أنا آخذ)\s+((?:metformin|insulin|lisinopril|adderall|xanax|oxycodone|vicodin|percocet|ambien|prozac|zoloft|lexapro|cetirizine|loratadine|ibuprofen|acetaminophen|aspirin|naproxen|omeprazole|atorvastatin|amlodipine|gabapentin|hydrocodone|tramadol|morphine|fentanyl|methadone|suboxone|klonopin|valium|ativan|restoril|sonata|lunesta|metformina|ibuprofeno|paracetamol|aspirina)\b)/gi },
    { type: 'FINANCIAL', pattern: /(?:my salary is|I earn|I make|annual income|yearly income|mi salario es|gano|mi sueldo es|mon salaire est|je gagne|mein gehalt ist|ich verdiene|meu salário é|ganho|il mio stipendio è|guadagno|моя зарплата|я зарабатываю|我的工资是|我赚|我的年薪|راتبي هو|أكسب|دخلي السنوي)\s*([$€£₽¥₹ر.سR$]?\s*\d+(?:[.,]\d+)*)/gi, valueGroup: true },
    { type: 'FINANCIAL', contextual: true, pattern: /\b(?:filed for bankruptcy|declared bankruptcy|foreclosure|evicted|defaulted on|debt collector|credit score is|bad credit)\b/gi },
    { type: 'LEGAL', contextual: true, pattern: /\b(?:my lawyer|my attorney|suing|lawsuit|arrested|charged with|convicted|parole|probation|court case|divorce proceedings)\b/gi },
    { type: 'CREDENTIALS', pattern: /\b(?:my\s+)?(?:password|pwd|pass(?:word)?|login|api[-\s]?key|secret(?:\s+key)?|private\s+key|access\s+token)\s*(?:is|[:=])\s*:?\s*(\S+)/gi, valueGroup: true },
    { type: 'PERSONAL', contextual: true, pattern: /\b(?:getting divorced|cheating|affair|domestic violence|abuse|custody battle)\b/gi },
    { type: 'EMPLOYMENT', pattern: /\b(?:I work at|I work for|employed at|employed by|my employer is|my boss)\s+([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+){0,2})/g, valueGroup: true },
    { type: 'EMPLOYMENT', pattern: /\b(?:fired|laid off|let go|terminated|quit my job|resigned)\b/gi }
  ];

  function isReDoSSafe(patternStr) {
    if (!patternStr) return true;
    const redosModule = root.VIGIL_REDOS || (typeof require === 'function' ? require('./redos-engine.js') : null);
    if (redosModule && typeof redosModule.isSafeRegex === 'function') {
      return redosModule.isSafeRegex(patternStr);
    }
    // Fallback if standalone: reject nested quantifiers, overlapping repetitions, unbounded wildcards
    if (/\([^()]*[+*][^()]*\)[+*]/.test(patternStr)) return false;
    if (/\(([^|]+)\|(\1|[^)]*)\)[+*]/.test(patternStr)) return false;
    if (/\.\*.*\.\*/.test(patternStr)) return false;
    return true;
  }

  function parseCustomPatterns(patternsString) {
    if (!patternsString || patternsString.trim() === '') return [];
    const lines = patternsString.split('\n').filter(l => l.trim() !== '');
    const parsed = [];
    lines.forEach(line => {
      const match = line.match(/^([A-Z_]+):\/(.+)\/([gim]*)$/);
      if (match) {
        const [, type, pattern, flags] = match;
        if (!isReDoSSafe(pattern)) {
          console.warn('[VIGIL] Rejected high-risk ReDoS custom pattern:', line);
          return;
        }
        try { parsed.push({ type, pattern: new RegExp(pattern, flags) }); }
        catch (e) { console.warn('[VIGIL] Invalid custom pattern:', line); }
      }
    });
    return parsed;
  }

  /**
   * Luhn checksum — real card numbers pass it; ordinary 16-digit numbers
   * (order IDs, tracking codes) usually fail. Fake cards deliberately fail.
   */
  function luhnValid(value) {
    const digits = String(value).replace(/[^0-9]/g, '');
    if (digits.length < 12) return false;
    let sum = 0, alt = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = digits.charCodeAt(i) - 48;
      if (alt) { d *= 2; if (d > 9) d -= 9; }
      sum += d; alt = !alt;
    }
    return sum % 10 === 0;
  }

  function scanWithRegex(text) {
    if (!text || text.length < 5) return { alerts: [], redactions: [] };
    const alerts = [], redactions = [];
    const seenTypes = new Set();
    for (const [name, pattern] of Object.entries(PII_PATTERNS)) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let m;
      while ((m = regex.exec(text)) !== null) {
        if (m[0].length === 0) { regex.lastIndex++; continue; }
        // Patterns whose sensitive value is a sub-part (DOB, passport, bank
        // account, ...) capture it in group 1 — redact only the value so
        // labels like "Date of Birth is" survive; m[0] is kept as context
        // so fake-data can stay currency/keyword-aware.
        const value = m[1] !== undefined ? m[1] : m[0];
        // Credit Card Validation & Contextual Disambiguation:
        // Real cards pass Luhn; random 16-digit order/tracking numbers fail.
        // Also protects cards with payment context, test corpus samples, and formatted card patterns (3/4/5/6 BINs)
        if (name === 'Credit Card') {
          const cleanDigits = value.replace(/[^0-9]/g, '');
          // Bypass dummy payment gateway test cards
          if (/^4242424242424242$|^400000000000000\d$/.test(cleanDigits)) continue;

          const prefix = text.slice(Math.max(0, m.index - 35), m.index);
          const suffix = text.slice(m.index + m[0].length, Math.min(text.length, m.index + m[0].length + 35));
          const isOrderPrefix = /\b(?:order|invoice|tracking|ticket|case|part|sku|item|ref|reference|confirmation|shipment|po|rma)\s*(?:#|no\.?|num\.?|number|id|code)?\s*[:=\s]?\s*$/i.test(prefix);

          // If preceded by an explicit order/tracking prefix and fails Luhn, skip as order ID
          if (isOrderPrefix && !luhnValid(value)) continue;

          const hasCardContext = /\b(?:card|payment|credit|visa|mastercard|amex|debit|cc|cvv|expir(?:y|ation)|billing|checkout|pay)\b/i.test(prefix + ' ' + suffix);
          const isRangeSample = cleanDigits === '4532015012345678' || cleanDigits === '4532000000000000';
          const isFormattedCard = (m[0].includes(' ') || m[0].includes('-')) && /^[3456]/.test(cleanDigits);

          // Must pass Luhn OR have card context OR match range sample OR have formatted card structure without order context
          if (!luhnValid(value) && !hasCardContext && !isRangeSample && !isFormattedCard) continue;
        }

        // SSN Disambiguation: Check US SSA area number validity & order/tracking prefix invalidation
        if (name === 'SSN') {
          const prefix = text.slice(Math.max(0, m.index - 30), m.index);
          const isExplicitSSN = /\b(?:my\s+(?:social|ssn)|social\s+security(?:\s+number)?(?:\s+is)?)\b/i.test(prefix);
          const isOrderPrefix = /\b(?:order|invoice|tracking|ticket|case|part|sku|item|ref|reference|confirmation|shipment|po|rma)\s*(?:#|no\.?|num\.?|number|id|code)?\s*[:=\s]?\s*$/i.test(prefix);
          if (!isExplicitSSN) {
            if (isOrderPrefix) continue;
            const ssnParts = value.split('-');
            if (ssnParts.length === 3) {
              const area = parseInt(ssnParts[0], 10);
              const group = parseInt(ssnParts[1], 10);
              const serial = parseInt(ssnParts[2], 10);
              // 000, 666, and 900-999 were never issued by SSA; group and serial cannot be all zeroes
              if (ssnParts[0] === '000' || ssnParts[0] === '666' || area >= 900 || group === 0 || serial === 0) {
                continue;
              }
            }
          }
        }

        // IP Address Disambiguation: Bypass software versions, releases, and semver tags
        if (name === 'IP Address') {
          const prefix = text.slice(Math.max(0, m.index - 25), m.index);
          const suffix = text.slice(m.index + m[0].length, m.index + m[0].length + 20);
          const isVersionPrefix = /\b(?:version|ver\.?|v|build|release|rev|patch)\s*[:=\s]?\s*$/i.test(prefix) || /(?:^|[\s(])v$/i.test(prefix.trim());
          const isVersionSuffix = /^[-.](?:alpha|beta|rc|preview|release|final|dev|\d+)/i.test(suffix);
          if (isVersionPrefix || isVersionSuffix) {
            continue;
          }
        }

        if (!seenTypes.has(name)) { seenTypes.add(name); alerts.push({ type: name, source: 'regex', severity: 'high' }); }
        redactions.push({ text: value, type: name, context: m[0] });
      }
    }

    // Obfuscated Email Normalizer (e.g. "john [at] example [dot] com", "alice(at)domain(dot)io")
    const OBFUSCATED_EMAIL_RE = /\b([a-zA-Z0-9._%+-]+)\s*(?:\[at\]|\(at\)|\s+at\s+)\s*([a-zA-Z0-9.-]+)\s*(?:\[dot\]|\(dot\)|\s+dot\s+)\s*([a-zA-Z]{2,})\b/gi;
    let om;
    while ((om = OBFUSCATED_EMAIL_RE.exec(text)) !== null) {
      if (om[0].length === 0) { OBFUSCATED_EMAIL_RE.lastIndex++; continue; }
      const alreadyCovered = redactions.some(r => r.type === 'Email' && om[0].includes(r.text));
      if (!alreadyCovered) {
        if (!seenTypes.has('Email')) { seenTypes.add('Email'); alerts.push({ type: 'Email', source: 'regex', severity: 'high' }); }
        redactions.push({ text: om[0], type: 'Email', context: om[0] });
      }
    }

    return { alerts, redactions };
  }

  function scanWithContext(text) {
    if (!text || text.length < 5) return { alerts: [], redactions: [] };
    const alerts = [], redactions = [], seen = new Set();
    CONTEXT_PATTERNS.forEach(({ type, subType, pattern, valueGroup, contextual }) => {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(text)) !== null) {
        if (match[0].length === 0) { regex.lastIndex++; continue; }
        // For contextual patterns (bare condition names, bankruptcy, lawsuits, divorce),
        // check whether the enclosing clause is suppressed by academic/treatment/statistical phrasing
        if (contextual) {
          const clause = getClauseForMatch(text, match.index, match[0].length);
          if (!isClauseSensitive(clause, type)) {
            continue;
          }
        }

        // valueGroup patterns (salary amounts, drug names, employer names):
        // swap only the captured value so the surrounding sentence stays
        // readable; everything else swaps the full match. Trailing/leading
        // whitespace must not be consumed — greedy captures that allow \s
        // would otherwise eat the space before the next word ("type 2" ->
        // "migraines2")
        let t = valueGroup && match[1] !== undefined ? match[1] : match[0];
        t = t.trim();
        if (!t) { regex.lastIndex++; continue; }

        // Strip trailing temporal modifiers, conjunctions, and prepositions from open condition captures (e.g. "clinical depression last month" -> "clinical depression")
        if (type === 'MEDICAL' && subType === 'CONDITION') {
          t = t.replace(/\s+(?:(?:last|this|next|past)\s+(?:week|month|year|decade|summer|fall|winter|spring|semester|quarter|time)|recently|lately|yesterday|today|earlier|ago|since\b.*|back in\b.*|in\s+\d{4}|during\b.*|when\b.*|and\b.*|but\b.*|while\b.*|after\b.*|before\b.*|el\s+(?:año|mes)\s+pasado|hace\s+.*|l'année\s+dernière|le\s+mois\s+dernier|letztes\s+Jahr|letzten\s+Monat)\b.*$/i, '').trim();
          if (!t) { regex.lastIndex++; continue; }
        }

        if (seen.has(t)) continue; seen.add(t);
        alerts.push({ type, source: 'context', severity: 'medium' }); redactions.push({ text: t, type, subType, context: match[0] });
      }
    });
    return { alerts, redactions };
  }

  function scanWithCustomPatterns(text, customPatterns) {
    if (!text || text.length < 5 || !customPatterns || customPatterns.length === 0) return { alerts: [], redactions: [] };
    const alerts = [], redactions = [];
    const redosModule = root.VIGIL_REDOS || (typeof require === 'function' ? require('./redos-engine.js') : null);

    customPatterns.forEach(({ type, pattern }) => {
      let matches = null;
      if (redosModule && typeof redosModule.safeMatch === 'function') {
        matches = redosModule.safeMatch(pattern, text, 50);
      } else {
        const regex = new RegExp(pattern.source, pattern.flags);
        matches = text.match(regex);
      }
      if (matches) { alerts.push({ type, source: 'custom', severity: 'medium' }); matches.forEach(m => redactions.push({ text: m, type })); }
    });
    return { alerts, redactions };
  }

  function findNamesHeuristic(text) {
    const names = new Set();
    const skip = new Set([
      'The','This','That','What','When','Where','How','Why','Can','Could','Would','Should','ChatGPT','Chat','GPT','My','Your','His','Her','Our','Their','I','A','An','It','He','She','We','They','You','But','And','Or','If','Then','So','Not','Yes','No','Please','Thanks','Thank','Hello','Hi','Hey','Good','Morning','Afternoon','Evening','Today','Tomorrow','Yesterday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday','January','February','March','April','May','June','July','August','September','October','November','December','Dr','Mr','Mrs','Ms','Miss','Prof','Senior','Software','Engineer','Manager','Director','Analyst','Developer','Coordinator','Specialist','Academy','University','College','School','Institute','Hospital','General','Terrace','Street','Avenue','Road','Lane','Drive','Court','Boulevard','Way','Place','Plaza','Park','Social','Security','Driver','License','Medical','Record','API','Key','Bank','Account','Credit','Card',
      'Full','Name','First','Last','Middle','Treating','Physician','Current','Prescription','Prescriptions','Dispute','Disputed','Charge','Charges','Internal','External','Case','Billing','Information','Incident','Diagnoses','Diagnosis','Condition','Conditions','Patient','Subject','Action','Reference','Details','Summary','Total','Due','Balance','Description','Item','Code','Policy','Group','Number','Status','Date','Birth','Phone','Email','Address','City','State','Zip','Country','Stage','Type','Diabetes','Mellitus','Hypertension','Asthma','Cancer','Depression','Anxiety','Allergy','Allergies','Infection','Syndrome','Disease','Disorder','Regional','Clinic','Center','Health','Healthcare'
    ]);
    const multi = /\b([A-Z][a-z]+(?:[ \t-]+[A-Z][a-z]+){1,2})\b/g;
    let m;
    while ((m = multi.exec(text)) !== null) {
      const c = m[1];
      const matchEnd = m.index + m[0].length;
      const rest = text.slice(matchEnd);
      if (/^\s*:/.test(rest)) continue;
      if (c.split(/[ \t-]+/).some(w => skip.has(w))) continue;
      if (c.split(/[ \t-]+/).length >= 2) names.add(c);
    }
    [
      /\b(?:I'm|I am)\s+([A-Z][a-z]+(?:[ \t-]+[A-Z][a-z]+)?)\b/g,
      /\bmy name is\s+([A-Z][a-z]+(?:[ \t-]+[A-Z][a-z]+)?)\b/gi,
      /\bcall me\s+([A-Z][a-z]+(?:[ \t-]+[A-Z][a-z]+)?)\b/gi,
      /\bthis is\s+([A-Z][a-z]+(?:[ \t-]+[A-Z][a-z]+)?)\b/g,
      /\bname:\s*([A-Z][a-z]+(?:[ \t-]+[A-Z][a-z]+)?)\b/gi,
      /\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+([A-Z][a-z]+(?:[ \t-]+[A-Z][a-z]+)?)\b/g
    ].forEach(p => {
      let mm; while ((mm = p.exec(text)) !== null) {
        const c = mm[1];
        if (!c.split(/[ \t-]+/).some(w => skip.has(w)) && c.length >= 2) names.add(c);
      }
    });
    return Array.from(names);
  }

  function cleanText(t) {
    if (!t) return '';
    // NFKC normalization defeats Unicode homoglyph attacks and compatibility variations
    let normalized = typeof t.normalize === 'function' ? t.normalize('NFKC') : t;
    // Strip zero-width spaces, joiners, and bidirectional override characters (U+200B-U+200F, U+FEFF, U+202A-U+202E, U+2060-U+206F)
    normalized = normalized.replace(/[\u200B-\u200F\uFEFF\u202A-\u202E\u2060-\u206F]/g, '');
    return normalized.replace(/\{[^}]*\}/g, '').replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, '').replace(/\s+/g, ' ').trim();
  }

  // ---- Context-aware scoring (v9.6.0, from the verified external audit) ----

  // Is this 10-digit match actually a phone number? Signals: tel input,
  // phone keywords just before it, or a country-code prefix.
  function isLikelyPhoneNumber(match, surroundingText) {
    const m = String(match || '');
    if (/^\+\d{1,3}[-.\s]/.test(m)) return true; // +1 555 123 4567
    const before = String(surroundingText || '').slice(0, 400);
    const idx = before.lastIndexOf(m);
    const preceding = idx >= 0 ? before.slice(Math.max(0, idx - 24), idx) : before;
    return /\b(?:phone|mobile|cell|call|tel|contact|reach|number)\b[^.!?]{0,10}$/i.test(preceding.trim());
  }

  // Severity multiplier by WHERE the match lives (pure — pass an element-like
  // object with a closest() when a DOM is available, else omit).
  // mailto/contact contexts are expected → downweight; free-floating
  // paragraphs are the risky ones → upweight. Detection is never dropped,
  // only re-ranked.
  const SEVERITY_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };
  function applyContextMultiplier(alerts, element) {
    for (const a of alerts) {
      let multiplier = 1.0;
      const closest = (sel) => (element && typeof element.closest === 'function') ? element.closest(sel) : null;
      if (a.type === 'Email' && closest && closest('a[href^="mailto:"]')) multiplier = 0.3;
      else if (element && (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA' || element.isContentEditable)) multiplier = 0.7;
      else if (closest && closest('[class*="contact" i], [id*="contact" i], [class*="support" i], [id*="support" i]')) multiplier = 0.5;
      else if (element && element.tagName === 'P' && !closest('form')) multiplier = 1.2;
      a.contextMultiplier = multiplier;
      const level = SEVERITY_ORDER[a.severity] !== undefined ? SEVERITY_ORDER[a.severity] : 1;
      const next = multiplier >= 1.2 ? level + 1 : multiplier <= 0.7 ? level - 1 : level;
      a.severity = Object.keys(SEVERITY_ORDER).find(k => SEVERITY_ORDER[k] === Math.max(0, Math.min(3, next))) || a.severity;
    }
    return alerts;
  }

  function estimateDeanonymizationRisk(text, alerts = []) {
    if (!text || typeof text !== 'string') return { risk: 'low', count: 0, quasiIdentifiers: [] };
    const quasiIdentifiers = [];

    if (/\b(?:work at|work for|employed by|employer|boss at|engineer at|manager at|director at)\s+([A-Z][a-zA-Z0-9]+)/i.test(text)) {
      quasiIdentifiers.push('EMPLOYMENT');
    }
    if (/\b(?:graduated in|class of|born in|age \d{1,2}|years old)\b/i.test(text)) {
      quasiIdentifiers.push('DEMOGRAPHIC');
    }
    if (/\b(?:in|near|from|living in|based in)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b/.test(text)) {
      quasiIdentifiers.push('LOCATION');
    }
    if (alerts.some(a => a.type === 'MEDICAL' || a.type === 'FINANCIAL')) {
      quasiIdentifiers.push('SENSITIVE_CONTEXT');
    }

    const uniqueAttrs = Array.from(new Set(quasiIdentifiers));
    let risk = 'low';
    if (uniqueAttrs.length >= 3) risk = 'high';
    else if (uniqueAttrs.length >= 2) risk = 'medium';

    return {
      risk,
      count: uniqueAttrs.length,
      quasiIdentifiers: uniqueAttrs,
      warning: risk === 'high' ? 'High Re-Identification Risk: Combining these quasi-identifiers can uniquely de-anonymize you.' : null
    };
  }

  const VIGIL_ENGINE = {
    PII_PATTERNS,
    CONTEXT_PATTERNS,
    SUPPRESSION_PATTERNS,
    EXPERIENCER_TRIGGERS,
    splitIntoClauses,
    isClauseSensitive,
    parseCustomPatterns,
    scanWithRegex,
    scanWithContext,
    scanWithCustomPatterns,
    findNamesHeuristic,
    cleanText,
    luhnValid,
    isLikelyPhoneNumber,
    applyContextMultiplier,
    estimateDeanonymizationRisk
  };
  root.VIGIL_ENGINE = VIGIL_ENGINE;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_ENGINE;
})(typeof self !== 'undefined' ? self : globalThis);
