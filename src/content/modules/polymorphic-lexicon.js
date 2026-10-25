/**
 * VIGIL AI — Polymorphic Sub-Entity Lexicon (PolymorphicLexicon)
 *
 * Implements deterministic, referentially consistent, gender- and
 * morphology-aware entity pseudonymization for Conversational AI.
 *
 * Capabilities:
 * - Deterministic PRNG seeding via FNV-1a (ThreadID + Canonical Entity)
 * - Structural decomposition (Title, First Name, Last Name, Possessive)
 * - Gender agreement and title preservation
 * - Sub-entity hierarchical inheritance (John Doe's -> Thomas Miller's, John -> Thomas)
 * - Non-overlapping greedy replacement (longest original span first)
 *
 * 100% Local / Zero-Cloud / Fail-Closed.
 */
(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VIGIL_POLYMORPHIC_LEXICON = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Seeded Mulberry32 PRNG
  function createMulberry32(seed) {
    let s = seed >>> 0;
    return function () {
      let t = (s += 0x6D2B79F5);
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // 32-bit FNV-1a Hash
  function fnv1a32(str) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      hash ^= str.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193);
    }
    return hash >>> 0;
  }

  // Curated gender-consistent name pools
  const MALE_NAMES = [
    'Thomas Miller', 'James Wilson', 'Michael Brown', 'Robert Taylor', 'Carlos García',
    'Jean Dupont', 'Hans Müller', 'João Silva', 'Marco Rossi', 'Ivan Ivanov',
    'Wei Zhang', 'Mohammed Al-Sayed', 'Kenji Sato', 'Ahmed Ali', 'Lucas Silva',
    'Noah Williams', 'David Kim', 'Omar Hassan', 'Andrei Novak', 'Kenzo Tanaka'
  ];

  const FEMALE_NAMES = [
    'Sarah Chen', 'Emily Davis', 'Lisa Anderson', 'María Rodríguez', 'Marie Laurent',
    'Anna Schmidt', 'Ana Costa', 'Giulia Bianchi', 'Maria Petrova', 'Li Wang',
    'Fatima Hassan', 'Yuki Tanaka', 'Layla Mansour', 'Elena Rossi', 'Isabella Costa',
    'Emma Johnson', 'Priya Patel', 'Sofia Popov', 'Elena Novak', 'Chloe Martin'
  ];

  const NEUTRAL_NAMES = [
    'Alex Jordan', 'Morgan Taylor', 'Casey Morgan', 'Taylor Brooks', 'Sam Avery',
    'Riley Quinn', 'Jordan Lee', 'Jamie Smith', 'Avery Reed', 'Cameron Kelly'
  ];

  const TITLES = [
    'dr', 'dr.', 'doctor', 'prof', 'prof.', 'professor',
    'mr', 'mr.', 'mrs', 'mrs.', 'ms', 'ms.', 'mx', 'mx.'
  ];

  const MALE_FIRST_NAMES = new Set([
    'john', 'james', 'michael', 'robert', 'william', 'david', 'richard', 'joseph',
    'thomas', 'charles', 'christopher', 'daniel', 'matthew', 'anthony', 'mark',
    'donald', 'steven', 'paul', 'andrew', 'joshua', 'kenji', 'ahmed', 'lucas',
    'noah', 'omar', 'wei', 'hans', 'jean', 'ivan', 'marco', 'carlos', 'andrei',
    'kenzo', 'joão', 'joao', 'mohammed', 'alexander', 'brian', 'kevin', 'george'
  ]);

  const FEMALE_FIRST_NAMES = new Set([
    'mary', 'patricia', 'jennifer', 'linda', 'elizabeth', 'barbara', 'susan',
    'jessica', 'sarah', 'karen', 'lisa', 'nancy', 'betty', 'margaret', 'sandra',
    'ashley', 'dorothy', 'kimberly', 'emily', 'donna', 'michelle', 'carol',
    'amanda', 'melissa', 'deborah', 'stephanie', 'rebecca', 'sharon', 'laura',
    'cynthia', 'kathleen', 'amy', 'shirley', 'angela', 'helen', 'anna', 'maria',
    'maría', 'marie', 'ana', 'giulia', 'li', 'priya', 'fatima', 'yuki', 'elena',
    'isabella', 'emma', 'sofia', 'layla', 'chloe', 'clara', 'olivia', 'alice'
  ]);

  /**
   * Infers gender from name string.
   */
  function inferGender(nameText) {
    if (!nameText) return 'NEUTRAL';
    const lower = nameText.toLowerCase().trim();
    if (lower.startsWith('mr.') || lower.startsWith('mr ')) return 'MALE';
    if (lower.startsWith('mrs.') || lower.startsWith('mrs ') || lower.startsWith('ms.') || lower.startsWith('ms ')) return 'FEMALE';

    const clean = lower.replace(/^(?:dr\.|dr|prof\.|prof|mr\.|mr|mrs\.|mrs|ms\.|ms|mx\.|mx)\s+/i, '');
    const tokens = clean.split(/\s+/).filter(Boolean);
    const first = tokens[0] || '';

    if (MALE_FIRST_NAMES.has(first)) return 'MALE';
    if (FEMALE_FIRST_NAMES.has(first)) return 'FEMALE';
    return 'NEUTRAL';
  }

  /**
   * Parses structural elements of a name.
   */
  function parseNameStructure(rawText) {
    let text = rawText.trim();
    let isPossessive = false;

    // Check for possessive markers ('s or ’s)
    if (text.endsWith("'s") || text.endsWith("’s")) {
      isPossessive = true;
      text = text.slice(0, -2).trim();
    }

    // Extract title if present
    let title = null;
    const tokens = text.split(/\s+/).filter(Boolean);
    if (tokens.length > 1 && TITLES.includes(tokens[0].toLowerCase())) {
      title = tokens[0];
      tokens.shift();
    }

    const firstName = tokens[0] || '';
    const lastName = tokens.length > 1 ? tokens.slice(1).join(' ') : null;

    return {
      original: rawText,
      clean: text,
      isPossessive,
      title,
      firstName,
      lastName
    };
  }

  /**
   * Generates a deterministic surrogate for a given entity in a thread.
   */
  function generateSurrogate(entityText, category, threadId = 'default_thread') {
    const raw = String(entityText || '').trim();
    if (!raw) return { surrogate: raw, subEntities: [] };

    const normKey = raw.toLowerCase();
    const seed = fnv1a32(`${threadId}:${category}:${normKey}`);
    const prng = createMulberry32(seed);
    const pick = arr => arr[Math.floor(prng() * arr.length)];

    if (category === 'NAME' || category === 'PERSON') {
      const parsed = parseNameStructure(raw);
      const gender = inferGender(parsed.clean);
      const pool = gender === 'MALE' ? MALE_NAMES : (gender === 'FEMALE' ? FEMALE_NAMES : NEUTRAL_NAMES);
      const baseSurrogate = pick(pool);
      const surrTokens = baseSurrogate.split(' ');
      const surrFirst = surrTokens[0];
      const surrLast = surrTokens.slice(1).join(' ');

      // Build primary surrogate matching title and possessive state
      let primary = baseSurrogate;
      if (parsed.title) primary = `${parsed.title} ${primary}`;
      if (parsed.isPossessive) primary = `${primary}'s`;

      // Build sub-entity hierarchy
      const subEntities = [];

      // 1. Full name possessive
      if (parsed.firstName && parsed.lastName) {
        subEntities.push({
          original: `${parsed.firstName} ${parsed.lastName}'s`,
          surrogate: `${surrFirst} ${surrLast}'s`
        });
        subEntities.push({
          original: `${parsed.firstName} ${parsed.lastName}’s`,
          surrogate: `${surrFirst} ${surrLast}'s`
        });
        // Full name bare
        subEntities.push({
          original: `${parsed.firstName} ${parsed.lastName}`,
          surrogate: `${surrFirst} ${surrLast}`
        });
      }

      // 2. Title + Last Name
      if (parsed.title && parsed.lastName) {
        subEntities.push({
          original: `${parsed.title} ${parsed.lastName}'s`,
          surrogate: `${parsed.title} ${surrLast}'s`
        });
        subEntities.push({
          original: `${parsed.title} ${parsed.lastName}`,
          surrogate: `${parsed.title} ${surrLast}`
        });
      }

      // 3. First name possessive and bare
      if (parsed.firstName) {
        subEntities.push({
          original: `${parsed.firstName}'s`,
          surrogate: `${surrFirst}'s`
        });
        subEntities.push({
          original: `${parsed.firstName}’s`,
          surrogate: `${surrFirst}'s`
        });
        subEntities.push({
          original: parsed.firstName,
          surrogate: surrFirst
        });
      }

      // 4. Last name bare
      if (parsed.lastName) {
        subEntities.push({
          original: parsed.lastName,
          surrogate: surrLast
        });
      }

      return {
        original: raw,
        surrogate: primary,
        category: 'NAME',
        subEntities
      };
    }

    if (category === 'Email') {
      const hex = Math.floor(prng() * 0xffffff).toString(16).padStart(6, '0');
      const domains = ['example.com', 'sample.net', 'test.org', 'demo.io', 'mock.com'];
      const surr = `user_${hex}@${pick(domains)}`;
      return { original: raw, surrogate: surr, category: 'Email', subEntities: [] };
    }

    if (category === 'Phone') {
      const num = 1000 + Math.floor(prng() * 9000);
      const surr = `555-0199-${num}`;
      return { original: raw, surrogate: surr, category: 'Phone', subEntities: [] };
    }

    if (category === 'SSN') {
      // Deliberately use unissued SSA areas (000, 666, 900+)
      const areas = ['000', '666', '999'];
      const group = String(Math.floor(prng() * 90) + 10);
      const serial = String(Math.floor(prng() * 9000) + 1000);
      const surr = `${pick(areas)}-${group}-${serial}`;
      return { original: raw, surrogate: surr, category: 'SSN', subEntities: [] };
    }

    if (category === 'Credit Card') {
      // Realistic look, guaranteed Luhn check failure
      const cards = [
        '4532-8871-2934-1150', '4916-3389-0472-1150', '5425-2334-8876-9920',
        '5193-7742-9918-3340', '6011-1111-1111-1110', '4532-9871-5534-8860'
      ];
      return { original: raw, surrogate: pick(cards), category: 'Credit Card', subEntities: [] };
    }

    if (category === 'IP Address') {
      // RFC 5737 TEST-NET documentation blocks
      const lastOctet = Math.floor(prng() * 250) + 2;
      const surr = `198.51.100.${lastOctet}`;
      return { original: raw, surrogate: surr, category: 'IP Address', subEntities: [] };
    }

    // Default fallback
    return { original: raw, surrogate: `[REDACTED-${category}]`, category, subEntities: [] };
  }

  /**
   * Applies non-overlapping polymorphic replacements over input text.
   * Longest original match is replaced first to prevent substring collisions.
   */
  function applyReplacements(text, substitutions) {
    if (!text || typeof text !== 'string') return text || '';
    if (!substitutions || substitutions.length === 0) return text;

    // Flatten all primary and sub-entities into a single sorted list
    const flat = [];
    substitutions.forEach(s => {
      if (s.original && s.surrogate) {
        flat.push({ original: s.original, surrogate: s.surrogate });
      }
      if (Array.isArray(s.subEntities)) {
        s.subEntities.forEach(sub => {
          if (sub.original && sub.surrogate) {
            flat.push({ original: sub.original, surrogate: sub.surrogate });
          }
        });
      }
    });

    // Sort by descending original text length (crucial for "John Doe's" before "John")
    flat.sort((a, b) => b.original.length - a.original.length);

    let result = text;
    flat.forEach(({ original, surrogate }) => {
      if (!original || !surrogate || original === surrogate) return;
      // Word boundary regex when practical, otherwise exact match
      const escaped = original.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const isWord = /^[a-zA-Z0-9_]+$/.test(original);
      const regex = isWord ? new RegExp(`\\b${escaped}\\b`, 'g') : new RegExp(escaped, 'g');
      result = result.replace(regex, surrogate);
    });

    return result;
  }

  return {
    generateSurrogate,
    applyReplacements,
    parseNameStructure,
    inferGender,
    _fnv1a32: fnv1a32
  };
});
