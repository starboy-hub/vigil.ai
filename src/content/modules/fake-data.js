/**
 * VIGIL Fake Data Generator
 * Generates realistic fake PII data for redaction.
 *
 * Loaded before content.js in the manifest and required directly by tests.
 *
 * Safety rules:
 *   - Credit cards are realistic-looking but deliberately FAIL the Luhn
 *     checksum, so they can never be mistaken for a real, chargeable card.
 *   - SSNs use areas that are never issued by the SSA (000, 666, 900-999).
 *   Both guarantees are pinned by tests.
 */
(function (root) {
  'use strict';

  const FAKE_DATA = {
    names: ['James Wilson', 'Sarah Chen', 'Michael Brown', 'Emily Davis', 'Robert Taylor', 'Lisa Anderson', 'Carlos García', 'María Rodríguez', 'Jean Dupont', 'Marie Laurent', 'Hans Müller', 'Anna Schmidt', 'João Silva', 'Ana Costa', 'Marco Rossi', 'Giulia Bianchi', 'Ivan Ivanov', 'Maria Petrova', 'Wei Zhang', 'Li Wang', 'Mohammed Al-Sayed', 'Fatima Hassan', 'Yuki Tanaka', 'Kenji Sato', 'Olga Sokolova', 'Dmitry Volkov', 'Ahmed Ali', 'Layla Mansour', 'Chen Wei', 'Liu Yang', 'Sofia Popov', 'Andrei Novak', 'Elena Rossi', 'Lucas Silva', 'Isabella Costa', 'Noah Williams', 'Emma Johnson', 'David Kim', 'Priya Patel', 'Omar Hassan'],
    emails: ['user_8f7a2@example.com', 'contact_3k9x1@sample.net', 'info_5m2p4@test.org', 'hello_7j6n8@demo.io', 'admin_9b2c3@mock.com', 'support_1a4d5@fake.net', 'dev_6e8f9@test.io', 'team_2x5y7@sample.org', 'hello_4k8m1@demo.com', 'info_9p3q2@mock.net', 'contact_7h3j9@example.org', 'user_2m5n8@sample.io', 'mail_3b7c1@test.com', 'dev_8x2y4@mock.io', 'info_5k9m2@sample.net'],
    phones: ['555-0147-8234', '555-0183-9472', '555-0129-6358', '555-0164-2791', '555-0192-3847', '555-0156-7293', '555-0138-4920', '555-0174-8392', '555-0111-2233', '555-0144-5566', '555-0177-8899', '555-0100-1122'],
    ssns: ['000-12-3456', '000-45-6789', '666-98-7654', '666-54-3210', '999-11-2222', '999-33-4444', '000-77-8899', '666-12-9034', '999-88-7766', '000-31-7549', '666-47-8213', '999-52-6041'],
    creditCards: ['4532-8871-2934-1150', '4916-3389-0472-1150', '5425-2334-8876-9920', '5193-7742-9918-3340', '6011-1111-1111-1110', '4532-9871-5534-8860', '4916-8811-7742-2291', '5425-6699-3311-0040'],
    ips: ['10.20.30.40', '192.168.99.99', '172.16.0.1', '10.0.0.99', '192.0.2.1', '198.51.100.1', '203.0.113.1'],
    medicals: ['seasonal allergies', 'mild asthma', 'common cold', 'myopia', 'hypertension', 'migraines', 'vitamin D deficiency', 'mild anxiety', 'seasonal depression'],
    meds: ['famotidine', 'loratadine', 'ibuprofen', 'acetaminophen', 'omeprazole', 'cetirizine', 'amoxicillin', 'metformin', 'lisinopril'],
    companies: ['Acme Corp', 'Global Solutions Inc', 'Tech Innovations LLC', 'Prime Services Ltd', 'Nexus Industries', 'Apex Dynamics', 'Stellar Systems', 'Quantum Labs'],
    salaries: ['$75,000', '€60,000', '£55,000', '₽150,000', '¥50,000', 'ر.س 20,000', 'R$5,000', '$85,000', '€70,000', '¥80,000', 'R$8,000'],
    medicalRecords: ['84739201', '92837465', '10293847', '56473829'],
    passports: ['A93847562', 'B10293847', 'C83746592', 'D92837465'],
    driverLicenses: ['DL-8374-9201', 'DL-1029-3847', 'DL-5647-3829', 'DL-9283-7465'],
    bankAccounts: ['9384756201', '1029384756', '8374659201', '9283746501'],
    datesOfBirth: ['03/14/1988', '11/22/1992', '07/08/1985', '09/30/1995']
  };

  /**
   * Get fake data for a given PII type
   * @param {string} type - The type of PII
   * @param {string} originalText - Original text for context-aware faking
   * @returns {string} Fake data string
   */
  function getFakeData(type, originalText, subType) {
    const pick = arr => arr[Math.floor(Math.random() * arr.length)];
    const t = originalText ? originalText.toLowerCase() : '';
    switch (type) {
      case 'NAME': return pick(FAKE_DATA.names);
      case 'Email': return pick(FAKE_DATA.emails);
      case 'Phone': return pick(FAKE_DATA.phones);
      case 'SSN': return pick(FAKE_DATA.ssns);
      case 'Credit Card': return pick(FAKE_DATA.creditCards);
      case 'IP Address': return pick(FAKE_DATA.ips);
      case 'FINANCIAL': {
        if (t.includes('₽') || t.includes('рублей') || t.includes('зарплата')) return pick(['₽150,000', '₽200,000']);
        if (t.includes('¥') || t.includes('元') || t.includes('工资')) return pick(['¥50,000', '¥80,000']);
        if (t.includes('ر.س') || t.includes('ريال') || t.includes('راتبي')) return pick(['ر.س 20,000', '$20,000']);
        if (t.includes('r$') || t.includes('reais') || t.includes('salário')) return pick(['R$5,000', 'R$8,000']);
        if (t.includes('£') || t.includes('libras')) return pick(['£55,000', '£65,000']);
        if (t.includes('€') || t.includes('euro') || t.includes('euros') || t.includes('gagne') || t.includes('guadagno') || t.includes('verdiene') || t.includes('stipendio')) return pick(['€60,000', '€75,000']);
        if (t.includes('$') || t.includes('salary') || t.includes('salario') || t.includes('gano') || t.includes('earn')) return pick(['$75,000', '$85,000']);
        return '[REDACTED-FINANCIAL]';
      }
      case 'MEDICAL_CONDITION': return pick(FAKE_DATA.medicals);
      case 'MEDICAL_MEDICATION': return pick(FAKE_DATA.meds);
      case 'MEDICAL': {
        if (subType === 'CONDITION') return pick(FAKE_DATA.medicals);
        if (subType === 'MEDICATION') return pick(FAKE_DATA.meds);
        if (FAKE_DATA.meds.some(m => t.includes(m))) return pick(FAKE_DATA.meds);
        return pick(FAKE_DATA.medicals);
      }
      case 'CREDENTIALS': {
        // Realistic random credential — no fixed pool for secrets
        const sets = ['abcdefghijkmnpqrstuvwxyz', 'ABCDEFGHJKLMNPQRSTUVWXYZ', '23456789', '!@#$%&*?'];
        let out = sets.map(s => pick(s)).join('');
        const all = sets.join('');
        while (out.length < 14) out += pick(all);
        return out;
      }
      case 'EMPLOYMENT': {
        const companyKeywords = ['corp', 'inc', 'ltd', 'llc', 'company', 'solutions', 'industries'];
        if (companyKeywords.some(k => t.includes(k))) return pick(FAKE_DATA.companies);
        return '[REDACTED-EMPLOYMENT]';
      }
      case 'Medical Record': return pick(FAKE_DATA.medicalRecords);
      case 'Passport': return pick(FAKE_DATA.passports);
      case 'Driver License': return pick(FAKE_DATA.driverLicenses);
      case 'Bank Account': return pick(FAKE_DATA.bankAccounts);
      case 'Date of Birth': return pick(FAKE_DATA.datesOfBirth);
      default: return '[REDACTED-' + type + ']';
    }
  }

  /**
   * Create an opaque session pointer token for zero-trust redaction.
   * Format: {{PTR:<CATEGORY>_<ID>}}
   */
  function createOpaquePointer(category, seedId) {
    const cat = String(category || 'PII').toUpperCase().replace(/[^A-Z0-9]/g, '');
    const id = seedId || Math.random().toString(36).slice(2, 10);
    return `{{PTR:${cat}_${id}}}`;
  }

  /**
   * Pure Protect-path: apply redactions to a raw text value. Detections are
   * computed on whitespace-normalized text, so matching is whitespace-
   * tolerant; longest matches apply first; each applied swap is recorded.
   * @returns {{text: string, replacements: Array<{original, fake, type, timestamp}>}}
   */
  function redactText(text, redactions, useFakeData) {
    if (!text || !redactions || redactions.length === 0) return { text, replacements: [] };
    const shared = root.VIGIL || (typeof require === 'function' ? require('../../shared/vigil-shared.js') : null);
    let txt = text;
    const replacements = [];
    [...redactions].sort((a, b) => (b.text || '').length - (a.text || '').length).forEach(r => {
      if (!r.text || r.text.length === 0) return;
      const rep = r.vaultFake || r.opaquePointer || (useFakeData ? getFakeData(r.type, r.context || r.text, r.subType) : '[REDACTED-' + r.type + ']');
      if (!shared) return;
      const flexible = shared.flexiblePattern(r.text);
      if (flexible.test(txt)) {
        flexible.lastIndex = 0;
        replacements.push({ original: r.text, fake: rep, type: r.type, timestamp: new Date().toISOString() });
        txt = txt.replace(flexible, rep);
      }
    });
    return { text: txt, replacements };
  }

  const VIGIL_FAKE = { FAKE_DATA, getFakeData, redactText, createOpaquePointer };
  root.VIGIL_FAKE = VIGIL_FAKE;
  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_FAKE;
})(typeof self !== 'undefined' ? self : globalThis);
