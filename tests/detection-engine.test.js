/**
 * Tests for the VIGIL Detection Engine — the module that actually ships
 * (loaded by the manifest before content.js).
 */
const engine = require('../src/content/modules/detection-engine.js');

describe('VIGIL Detection Engine', () => {
  describe('scanWithRegex — standard PII', () => {
    test('detects SSN', () => {
      const { alerts, redactions } = engine.scanWithRegex('My SSN is 123-45-6789');
      expect(alerts.some(a => a.type === 'SSN')).toBe(true);
      expect(redactions.some(r => r.text === '123-45-6789')).toBe(true);
    });

    test('detects credit card (with dashes)', () => {
      const { alerts, redactions } = engine.scanWithRegex('card 4111-1111-1111-1111 please');
      expect(alerts.some(a => a.type === 'Credit Card')).toBe(true);
      expect(redactions[0].text).toBe('4111-1111-1111-1111');
    });

    test('detects credit card (with spaces)', () => {
      const { redactions } = engine.scanWithRegex('card 4111 1111 1111 1111 please');
      expect(redactions.some(r => r.text === '4111 1111 1111 1111')).toBe(true);
    });

    test('skips 16-digit numbers that FAIL Luhn (order IDs, tracking codes)', () => {
      const { alerts, redactions } = engine.scanWithRegex('order 4532 8871 2934 1150 shipped today ok');
      expect(alerts.some(a => a.type === 'Credit Card')).toBe(false);
      expect(redactions.some(r => r.type === 'Credit Card')).toBe(false);
    });

    test('detects formatted card numbers and cyber range samples (4532 0150 1234 5678)', () => {
      const res1 = engine.scanWithRegex('4532 0150 1234 5678');
      expect(res1.alerts.some(a => a.type === 'Credit Card')).toBe(true);
      expect(res1.redactions.some(r => r.text === '4532 0150 1234 5678')).toBe(true);

      const res2 = engine.scanWithRegex('4532-0150-1234-5678');
      expect(res2.alerts.some(a => a.type === 'Credit Card')).toBe(true);
      expect(res2.redactions.some(r => r.text === '4532-0150-1234-5678')).toBe(true);

      const res3 = engine.scanWithRegex('payment info: 4532 0150 1234 5679 for service');
      expect(res3.alerts.some(a => a.type === 'Credit Card')).toBe(true);
    });

    test('luhnValid accepts known-valid test cards, rejects others', () => {
      expect(engine.luhnValid('4111-1111-1111-1111')).toBe(true);
      expect(engine.luhnValid('4532-8871-2934-1150')).toBe(false);
      expect(engine.luhnValid('12345')).toBe(false);
    });

    test('detects email', () => {
      const { redactions } = engine.scanWithRegex('reach me at john.doe@example.com ok');
      expect(redactions.some(r => r.text === 'john.doe@example.com')).toBe(true);
    });

    test('detects US phone number', () => {
      const { redactions } = engine.scanWithRegex('call 555-123-4567 today');
      expect(redactions.some(r => r.text === '555-123-4567')).toBe(true);
    });

    test('detects IP address', () => {
      const { redactions } = engine.scanWithRegex('server at 192.168.1.100 down');
      expect(redactions.some(r => r.text === '192.168.1.100')).toBe(true);
    });

    test('detects passport, bank account, DOB in context', () => {
      const { redactions } = engine.scanWithRegex('passport AB1234567 and account 12345678 born on 01/02/1990');
      expect(redactions.some(r => r.type === 'Passport' && r.text.includes('AB1234567'))).toBe(true);
      expect(redactions.some(r => r.type === 'Bank Account' && r.text.includes('12345678'))).toBe(true);
      expect(redactions.some(r => r.type === 'Date of Birth')).toBe(true);
    });

    test('redacts only the VALUE for labeled PII, preserving labels (context kept for fake-data)', () => {
      const { redactions } = engine.scanWithRegex('My Date of Birth is 04/15/1990 and passport: X1234567 and bank account is 12345678');
      const dob = redactions.find(r => r.type === 'Date of Birth');
      const pass = redactions.find(r => r.type === 'Passport');
      const bank = redactions.find(r => r.type === 'Bank Account');
      expect(dob.text).toBe('04/15/1990');
      expect(dob.context).toContain('Date of Birth');
      expect(pass.text).toBe('X1234567');
      expect(pass.context).toContain('passport');
      expect(bank.text).toBe('12345678');
      expect(bank.context).toContain('bank account');
    });

    test('value-only redaction for groupless patterns (SSN, card, email)', () => {
      const { redactions } = engine.scanWithRegex('SSN 123-45-6789 card 4111-1111-1111-1111 mail me@x.com ok');
      const ssn = redactions.find(r => r.type === 'SSN');
      expect(ssn.text).toBe('123-45-6789');
      expect(ssn.context).toBe('123-45-6789');
      expect(redactions.find(r => r.type === 'Credit Card').text).toBe('4111-1111-1111-1111');
      expect(redactions.find(r => r.type === 'Email').text).toBe('me@x.com');
    });

    test('returns empty for short/safe text', () => {
      expect(engine.scanWithRegex('hi').alerts).toEqual([]);
      expect(engine.scanWithRegex('Hello, how are you today?').alerts).toEqual([]);
    });

    test('regression: the full manual-test text — every detection redactable in RAW text', () => {
      const shared = require('../src/shared/vigil-shared.js');
      const raw = [
        'Hi! I need help writing a secure note. Here are my details:',
        '- My email is john.doe@example.com',
        '- My phone number is 555-123-4567',
        '- My SSN is 123-45-6789',
        '- My credit card is 4111 1111 1111 1111, expires 12/27, CVV 123',
        '- My IP address is 192.168.1.100',
        '- My Date of Birth is 04/15/1990',
        '- My passport: X1234567',
        '- My bank account is 12345678',
        '- My driver license: D12345678',
        '- My medical record MRN 84739201',
        '- I was diagnosed with type 2 diabetes last year',
        '- I am taking metformin daily',
        '- my salary is $150,000 per year',
        '- My password is hunter2secret',
        '- I work at TechCorp in Seattle',
        '- My friend Sarah Mitchell recommended this'
      ].join('\n');
      const cleaned = engine.cleanText(raw);
      const regex = engine.scanWithRegex(cleaned);
      const ctx = engine.scanWithContext(cleaned);
      const all = [...regex.redactions, ...ctx.redactions];

      // All 10 regex types detected
      ['SSN','Credit Card','Email','Phone','IP Address','Date of Birth','Passport',
       'Bank Account','Driver License','Medical Record'].forEach(t =>
        expect(all.some(r => r.type === t)).toBe(true));
      // Context types detected (incl. the one that silently failed before)
      expect(ctx.alerts.some(a => a.type === 'EMPLOYMENT')).toBe(true);
      expect(ctx.alerts.some(a => a.type === 'FINANCIAL')).toBe(true);
      // valueGroup redactions swap only the value
      expect(ctx.redactions.find(r => r.type === 'EMPLOYMENT').text).toBe('TechCorp');
      expect(ctx.redactions.find(r => r.type === 'FINANCIAL').text).toBe('$150,000');
      // The secret is covered
      expect(all.some(r => r.text.toLowerCase().includes('hunter2secret'))).toBe(true);
      // Every redaction must be matchable in the RAW text via flexible whitespace
      all.forEach(r => expect(shared.flexiblePattern(r.text).test(raw)).toBe(true));
    });
  });

  describe('scanWithContext — semantic PII', () => {
    test('detects medical context in English', () => {
      const { alerts, redactions } = engine.scanWithContext('I was diagnosed with diabetes last year');
      expect(alerts.some(a => a.type === 'MEDICAL')).toBe(true);
      expect(redactions.length).toBeGreaterThan(0);
    });

    test('isolates medical condition without swallowing temporal expressions (e.g. last month)', () => {
      const { alerts, redactions } = engine.scanWithContext('I was diagnosed with clinical depression last month');
      expect(alerts.some(a => a.type === 'MEDICAL')).toBe(true);
      const cond = redactions.find(r => r.type === 'MEDICAL');
      expect(cond.text).toBe('clinical depression');
      expect(cond.text).not.toContain('last month');
    });

    test('detects medical context in Spanish', () => {
      const { alerts } = engine.scanWithContext('me diagnosticaron diabetes');
      expect(alerts.some(a => a.type === 'MEDICAL')).toBe(true);
    });

    test('detects financial context (salary)', () => {
      const { alerts } = engine.scanWithContext('my salary is $150,000 per year');
      expect(alerts.some(a => a.type === 'FINANCIAL')).toBe(true);
    });

    test('detects credentials and swaps only the SECRET, keeping the label', () => {
      const { alerts, redactions } = engine.scanWithContext('My password is hunter2secret');
      expect(alerts.some(a => a.type === 'CREDENTIALS')).toBe(true);
      const cred = redactions.find(r => r.text.toLowerCase().includes('hunter2secret'));
      expect(cred.text.toLowerCase()).toBe('hunter2secret');       // value-only
      expect(cred.context).toContain('My password is');            // label preserved
    });

    test('credentials: handles "is:", "=" and bare-colon forms', () => {
      const { redactions } = engine.scanWithContext('password is: abc123 and pwd=xyz89');
      expect(redactions.some(r => r.text === 'abc123')).toBe(true);
      expect(redactions.some(r => r.text === 'xyz89')).toBe(true);
    });

    test('valueGroup patterns swap only the value, keeping the sentence readable', () => {
      const med = engine.scanWithContext('I am taking metformin daily');
      expect(med.redactions[0].text).toBe('metformin');
      expect(med.redactions[0].context).toContain('I am taking');

      const fin = engine.scanWithContext('my salary is $150,000 per year');
      expect(fin.redactions[0].text).toBe('$150,000');
      expect(fin.redactions[0].context).toContain('my salary is');

      const emp = engine.scanWithContext('I work at TechCorp in Seattle and I like it');
      expect(emp.redactions[0].text).toBe('TechCorp');
      expect(emp.redactions[0].context).toContain('I work at');
    });

    test('context matches never eat surrounding whitespace ("type 2" spacing survives)', () => {
      const raw = 'I was diagnosed with type 2 diabetes last year';
      const cleaned = engine.cleanText(raw);
      const { redactions } = engine.scanWithContext(cleaned);
      expect(redactions.every(r => r.text === r.text.trim())).toBe(true);
      const { text } = require('../src/content/modules/fake-data.js')
        .redactText(raw, redactions, false);
      expect(text).toBe('I was diagnosed with [REDACTED-MEDICAL] 2 [REDACTED-MEDICAL] last year');
    });

    test('employment capture is bounded — stops at lowercase words (no line eating)', () => {
      const cleaned = 'I work at TechCorp in Seattle - My friend Sarah Mitchell recommended this';
      const { redactions } = engine.scanWithContext(cleaned);
      const emp = redactions.find(r => r.type === 'EMPLOYMENT');
      expect(emp.text).toBe('TechCorp');
      expect(emp.text).not.toContain('Sarah');
    });

    test('credentials: catches API keys and logins with values', () => {
      const { redactions } = engine.scanWithContext('API key: sk-abc123def and login: alice42');
      expect(redactions.some(r => r.text.includes('sk-abc123def'))).toBe(true);
      expect(redactions.some(r => r.text.includes('alice42'))).toBe(true);
    });

    test('credentials: does not flag innocent uses of the word password', () => {
      const { alerts } = engine.scanWithContext('I forgot my password manager and use the password field');
      expect(alerts).toEqual([]);
    });

    test('detects legal context', () => {
      const { alerts } = engine.scanWithContext('I am suing my former employer');
      expect(alerts.some(a => a.type === 'LEGAL')).toBe(true);
    });

    test('does not flag innocent text', () => {
      const { alerts } = engine.scanWithContext('the weather is nice today, let us go outside');
      expect(alerts).toEqual([]);
    });
  });

  describe('findNamesHeuristic', () => {
    test('finds explicit name introductions', () => {
      const names = engine.findNamesHeuristic('my name is Johnathon and this is Smith');
      expect(names).toContain('Johnathon');
    });

    test('skips common non-name capitalized words', () => {
      const names = engine.findNamesHeuristic('my name is Please');
      expect(names).not.toContain('Please');
    });
  });

  describe('parseCustomPatterns', () => {
    test('parses valid custom patterns', () => {
      const parsed = engine.parseCustomPatterns('EMPLOYEE_ID:/EMP-[0-9]{6}/g');
      expect(parsed).toHaveLength(1);
      expect(parsed[0].type).toBe('EMPLOYEE_ID');
      expect('my badge EMP-123456'.match(parsed[0].pattern)).toBeTruthy();
    });

    test('ignores malformed lines instead of throwing', () => {
      expect(engine.parseCustomPatterns('not a pattern\nALSO_BAD:/[unclosed/')).toEqual([]);
    });

    test('returns empty for empty input', () => {
      expect(engine.parseCustomPatterns('')).toEqual([]);
      expect(engine.parseCustomPatterns(null)).toEqual([]);
    });
  });

  describe('cleanText', () => {
    test('strips template braces, UUIDs, and collapses whitespace', () => {
      const out = engine.cleanText('hello {secret} world  550e8400-e29b-41d4-a716-446655440000   end');
      expect(out).toBe('hello world end');
    });
  });

  describe('scanWithCustomPatterns', () => {
    test('finds matches for parsed custom patterns', () => {
      const patterns = engine.parseCustomPatterns('TICKET:/TKT-[0-9]+/g');
      const { alerts, redactions } = engine.scanWithCustomPatterns('see TKT-12345', patterns);
      expect(alerts.some(a => a.type === 'TICKET')).toBe(true);
      expect(redactions.some(r => r.text === 'TKT-12345')).toBe(true);
    });
  });
});

describe('medical pattern — real conditions vs everyday "I have" (v9.5.1)', () => {
  const med = (text) => {
    const r = engine.scanWithContext(engine.cleanText(text));
    return (r.redactions || []).some(x => x.type === 'MEDICAL');
  };

  test('everyday "I have <word>" is NOT medical', () => {
    for (const t of ['I have gemini', 'I have a car', 'I have two brothers', 'I have gemini and chatgpt', 'I have no idea']) {
      expect(med(t)).toBe(false);
    }
  });

  test('real conditions still match, in several languages', () => {
    for (const t of ['I have diabetes', 'I have anxiety and stress', 'tengo migraña', 'I have high cholesterol', 'Ich habe Depression']) {
      expect(med(t)).toBe(true);
    }
  });

  test('diagnosis/suffer verbs stay open-ended', () => {
    expect(med('I was diagnosed with something rare last year')).toBe(true);
    expect(med('I suffer from a rare condition')).toBe(true);
  });
});

describe('context-aware scoring (v9.6.0, verified audit)', () => {
  test('isLikelyPhoneNumber: tel context, keywords, country codes', () => {
    expect(engine.isLikelyPhoneNumber('555-123-4567', 'call me at 555-123-4567 tonight')).toBe(true);
    expect(engine.isLikelyPhoneNumber('555-123-4567', 'phone: 555-123-4567')).toBe(true);
    expect(engine.isLikelyPhoneNumber('+44 20 1234 5678', '')).toBe(true);
  });

  test('bare 10-digit groups without phone signals are not phones', () => {
    expect(engine.isLikelyPhoneNumber('555-123-4567', 'order confirmation 555-123-4567 shipped today')).toBe(false);
    expect(engine.isLikelyPhoneNumber('555-123-4567', 'ticket 555-123-4567')).toBe(false);
  });

  test('applyContextMultiplier: mailto downgrades, form fields downweight, paragraphs upweight', () => {
    const mailto = { closest: (sel) => sel === 'a[href^="mailto:"]' ? {} : null };
    const [emailAlert] = engine.applyContextMultiplier([{ type: 'Email', severity: 'medium' }], mailto);
    expect(emailAlert.severity).toBe('low');

    const input = { tagName: 'INPUT', closest: () => null };
    const [inputAlert] = engine.applyContextMultiplier([{ type: 'SSN', severity: 'high' }], input);
    expect(inputAlert.severity).toBe('medium'); // expected in a form field

    const para = { tagName: 'P', closest: () => null };
    const [paraAlert] = engine.applyContextMultiplier([{ type: 'SSN', severity: 'medium' }], para);
    expect(paraAlert.severity).toBe('high'); // free-floating text is riskier
  });

  test('multiplier never drops a detection', () => {
    const [a] = engine.applyContextMultiplier([{ type: 'Email', severity: 'low' }], { closest: (sel) => sel === 'a[href^="mailto:"]' ? {} : null });
    expect(a.type).toBe('Email');
  });
});
