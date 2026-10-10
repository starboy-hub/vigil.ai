/**
 * Tests for VIGIL Fake Data Generator
 */

const { getFakeData, FAKE_DATA, redactText } = require('../src/content/modules/fake-data.js');
const contentSrc = require('fs').readFileSync(
  require('path').join(__dirname, '..', 'src', 'content', 'content.js'), 'utf8');

describe('redactText (the Protect path)', () => {
  test('swaps a detected value for fake data and records the replacement', () => {
    const { text, replacements } = redactText('my email is john@x.com ok', [{ text: 'john@x.com', type: 'Email' }], true);
    expect(text).toBe('my email is ' + replacements[0].fake + ' ok');
    expect(replacements).toHaveLength(1);
    expect(replacements[0].original).toBe('john@x.com');
    expect(replacements[0].type).toBe('Email');
  });

  test('useFakeData=false produces [REDACTED-TYPE] placeholders', () => {
    const { text } = redactText('ssn 123-45-6789', [{ text: '123-45-6789', type: 'SSN' }], false);
    expect(text).toBe('ssn [REDACTED-SSN]');
  });

  test('matches across line breaks (detection ran on normalized text)', () => {
    const redactions = [{ text: 'I work at TechCorp in Seattle', type: 'EMPLOYMENT', context: 'I work at TechCorp in Seattle' }];
    const raw = 'I work at TechCorp in Seattle\n- more text';
    const { text, replacements } = redactText(raw, redactions, true);
    expect(replacements).toHaveLength(1);
    expect(text).toContain('- more text');
    expect(text).not.toContain('TechCorp');
  });

  test('no matches -> text unchanged, nothing recorded', () => {
    const { text, replacements } = redactText('nothing here', [{ text: 'missing-value', type: 'SSN' }], true);
    expect(text).toBe('nothing here');
    expect(replacements).toHaveLength(0);
  });

  test('longer redactions apply first (no partial-clobbering)', () => {
    const redactions = [
      { text: '456', type: 'X' },
      { text: '123456', type: 'Y' }
    ];
    const { text } = redactText('id 123456 end', redactions, false);
    expect(text).toBe('id [REDACTED-Y] end');
  });

  test('vaultFake is used verbatim when provided (Identity Vault pseudonyms)', () => {
    const { text, replacements } = redactText('hi Sarah Mitchell here', [{ text: 'Sarah Mitchell', type: 'Vault Name', vaultFake: 'James Wilson' }], false);
    expect(text).toBe('hi James Wilson here');
    expect(replacements[0].fake).toBe('James Wilson');
  });

  test('currency context drives the fake salary', () => {
    const { text, replacements } = redactText('my salary is ₽150,000 ok', [{ text: '150,000', type: 'FINANCIAL', context: 'my salary is ₽150,000' }], true);
    expect(text).toContain('my salary is ₽');
    expect(replacements[0].fake).toMatch(/^₽/);
  });
});

// Luhn checksum — fake cards must FAIL it so they can never be charged
function luhnValid(numStr) {
  const digits = numStr.replace(/[^0-9]/g, '');
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i], 10);
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

describe('Fake Data Generator', () => {
  describe('getFakeData', () => {
    test('should generate fake names', () => {
      const name = getFakeData('NAME');
      expect(name.length).toBeGreaterThan(3);
      expect(name.split(' ').length).toBeGreaterThanOrEqual(2);
    });

    test('should generate fake emails', () => {
      const email = getFakeData('Email');
      expect(email).toMatch(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
    });

    test('should generate fake phone numbers', () => {
      const phone = getFakeData('Phone');
      expect(phone).toMatch(/\d{3}-\d{4}-\d{4}/);
    });

    test('should generate fake SSNs', () => {
      const ssn = getFakeData('SSN');
      expect(ssn).toMatch(/^\d{3}-\d{2}-\d{4}$/);
    });

    test('should generate fake credit cards', () => {
      const cc = getFakeData('Credit Card');
      expect(cc).toMatch(/^\d{4}-\d{4}-\d{4}-\d{4}$/);
    });

    test('fake credit cards must FAIL Luhn validation (never chargeable)', () => {
      FAKE_DATA.creditCards.forEach(cc => {
        expect(luhnValid(cc)).toBe(false);
      });
    });

    test('fake SSNs must use areas never issued by the SSA (000, 666, 900+)', () => {
      FAKE_DATA.ssns.forEach(ssn => {
        const area = parseInt(ssn.split('-')[0], 10);
        expect([0, 666].includes(area) || area >= 900).toBe(true);
      });
    });

    test('should generate fake IP addresses', () => {
      const ip = getFakeData('IP Address');
      expect(ip).toMatch(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
    });

    test('should return redacted placeholder for unknown types', () => {
      const result = getFakeData('UNKNOWN_TYPE');
      expect(result).toMatch(/\[REDACTED-.*\]/);
    });

    test('should handle empty original text', () => {
      const name = getFakeData('NAME', '');
      expect(name).toBeTruthy();
    });

    test('picks currency-aware fake salaries', () => {
      expect(getFakeData('FINANCIAL', 'my salary is €50,000')).toMatch(/^€/);
      expect(getFakeData('FINANCIAL', 'зарплата 100000')).toMatch(/^₽/);
      expect(getFakeData('FINANCIAL', 'my salary is $90,000')).toMatch(/^\$/);
    });

    test('picks medical conditions or medications by context', () => {
      expect(FAKE_DATA.medicals).toContain(getFakeData('MEDICAL_CONDITION', 'I have fever'));
      expect(FAKE_DATA.meds).not.toContain(getFakeData('MEDICAL_CONDITION', 'I have fever'));
      expect(FAKE_DATA.meds).toContain(getFakeData('MEDICAL_MEDICATION', 'I take loratadine'));
      expect(FAKE_DATA.medicals).not.toContain(getFakeData('MEDICAL_MEDICATION', 'I take loratadine'));
    });

    test('picks fake companies for employment context', () => {
      expect(FAKE_DATA.companies).toContain(getFakeData('EMPLOYMENT', 'I work at TechCorp Inc'));
      expect(getFakeData('EMPLOYMENT', 'my boss said hi')).toMatch(/^\[REDACTED-/);
    });

    test('generates realistic random passwords for CREDENTIALS', () => {
      const p1 = getFakeData('CREDENTIALS', 'my password is x');
      const p2 = getFakeData('CREDENTIALS', 'my password is x');
      expect(p1).toMatch(/^[A-Za-z0-9!@#$%&*?]{14,20}$/); // password-shaped
      expect(p1).not.toBe(p2);                            // random, not a pool
      expect(/[a-z]/.test(p1) && /[A-Z]/.test(p1) && /[0-9]/.test(p1) && /[!@#$%&*?]/.test(p1)).toBe(true);
    });

    test('Medical Record fakes are bare digits (label now preserved by value-only redaction)', () => {
      expect(getFakeData('Medical Record', 'medical record MRN 84739201')).toMatch(/^\d{6,10}$/);
    });

    test('content.js no longer carries an inline FAKE_DATA copy (single source of truth)', () => {
      expect(contentSrc).not.toContain('FAKE_DATA = {');
      expect(contentSrc).toContain('VIGIL_FAKE.redactText(');
    });
  });
});
