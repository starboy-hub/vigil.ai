/**
 * Unit Tests for Conversational Mode: Thread Registry & Polymorphic Lexicon
 */

const ThreadRegistry = require('../src/content/modules/thread-registry');
const PolymorphicLexicon = require('../src/content/modules/polymorphic-lexicon');

describe('VIGIL Conversational Mode: Thread State Registry', () => {
  beforeEach(() => {
    ThreadRegistry.resetAll();
  });

  test('resolves deterministic ephemeral thread ID for elements in the same DOM container', () => {
    const fakeContainer = { closest: () => fakeContainer };
    const fakeChildA = { closest: (sel) => fakeContainer };
    const fakeChildB = { closest: (sel) => fakeContainer };

    const threadIdA = ThreadRegistry.resolveThreadId(fakeChildA);
    const threadIdB = ThreadRegistry.resolveThreadId(fakeChildB);

    expect(threadIdA).toBeDefined();
    expect(threadIdA).toMatch(/^vigil_session_/);
    expect(threadIdA).toBe(threadIdB);
  });

  test('records and retrieves thread entities deterministically', () => {
    const threadId = 'test_thread_123';
    const entity = {
      surrogate: 'Thomas Miller',
      category: 'NAME',
      subEntities: [
        { original: 'John', surrogate: 'Thomas' },
        { original: 'Doe', surrogate: 'Miller' }
      ]
    };

    ThreadRegistry.recordThreadEntity(threadId, 'John Doe', entity);

    expect(ThreadRegistry.hasThreadEntity(threadId, 'John Doe')).toBe(true);
    expect(ThreadRegistry.hasThreadEntity(threadId, 'john doe')).toBe(true); // case-insensitive

    const retrieved = ThreadRegistry.getThreadEntity(threadId, 'John Doe');
    expect(retrieved.surrogate).toBe('Thomas Miller');
    expect(retrieved.subEntities).toHaveLength(2);
  });

  test('getAllThreadSubstitutions generates full surrogate-to-original dictionary', () => {
    const threadId = 'test_thread_subst';
    ThreadRegistry.recordThreadEntity(threadId, 'John Doe', {
      surrogate: 'Thomas Miller',
      category: 'NAME',
      subEntities: [
        { original: "John Doe's", surrogate: "Thomas Miller's" },
        { original: 'John', surrogate: 'Thomas' }
      ]
    });

    const subs = ThreadRegistry.getAllThreadSubstitutions(threadId);
    expect(subs['Thomas Miller']).toBe('John Doe');
    expect(subs["Thomas Miller's"]).toBe("John Doe's");
    expect(subs['Thomas']).toBe('John');
  });

  test('aliasThread merges ephemeral session state into canonical server thread ID', () => {
    const ephemeralId = 'vigil_session_ephemeral_99';
    const canonicalId = 'chatgpt_c-abc-123';

    ThreadRegistry.recordThreadEntity(ephemeralId, 'Alice Smith', {
      surrogate: 'Sarah Chen',
      category: 'NAME'
    });
    ThreadRegistry.recordThreadQuasiIdentifier(ephemeralId, {
      category: 'EDUCATION',
      raw: 'MIT graduate 2018'
    });
    ThreadRegistry.setStickyConsent(ephemeralId, true);

    // Reconcile on URL pushState
    ThreadRegistry.aliasThread(ephemeralId, canonicalId);

    // Canonical thread now holds state
    expect(ThreadRegistry.hasThreadEntity(canonicalId, 'Alice Smith')).toBe(true);
    expect(ThreadRegistry.getThreadEntity(canonicalId, 'Alice Smith').surrogate).toBe('Sarah Chen');
    expect(ThreadRegistry.getThreadQuasiIdentifiers(canonicalId)).toHaveLength(1);
    expect(ThreadRegistry.isStickyConsentActive(canonicalId)).toBe(true);

    // Old ephemeral thread is cleaned up
    expect(ThreadRegistry.hasThreadEntity(ephemeralId, 'Alice Smith')).toBe(false);
  });

  test('cleanupStaleThreads evicts threads exceeding TTL', () => {
    const threadId = 'old_thread_ttl';
    ThreadRegistry.recordThreadEntity(threadId, 'Bob', { surrogate: 'James' });
    expect(ThreadRegistry.hasThreadEntity(threadId, 'Bob')).toBe(true);

    // Simulate aging > maxAgeMs
    ThreadRegistry.cleanupStaleThreads(-1);
    expect(ThreadRegistry.hasThreadEntity(threadId, 'Bob')).toBe(false);
  });
});

describe('VIGIL Conversational Mode: Polymorphic Sub-Entity Lexicon', () => {
  test('generates deterministic surrogates across multiple calls with same threadId and entity', () => {
    const threadId = 'chat_thread_alpha';
    const s1 = PolymorphicLexicon.generateSurrogate('John Doe', 'NAME', threadId);
    const s2 = PolymorphicLexicon.generateSurrogate('John Doe', 'NAME', threadId);
    const s3 = PolymorphicLexicon.generateSurrogate('John Doe', 'NAME', threadId);

    expect(s1.surrogate).toBe(s2.surrogate);
    expect(s2.surrogate).toBe(s3.surrogate);
    expect(s1.category).toBe('NAME');
  });

  test('differentiates distinct entities with deterministic distinct surrogates in same thread', () => {
    const threadId = 'chat_thread_alpha';
    const doctor = PolymorphicLexicon.generateSurrogate('John Doe', 'NAME', threadId);
    const patient = PolymorphicLexicon.generateSurrogate('Sarah Jenkins', 'NAME', threadId);

    expect(doctor.surrogate).not.toBe(patient.surrogate);
  });

  test('preserves gender agreement for male and female names', () => {
    const threadId = 'chat_thread_gender';
    const male = PolymorphicLexicon.generateSurrogate('David Williams', 'NAME', threadId);
    const female = PolymorphicLexicon.generateSurrogate('Emily Davis', 'NAME', threadId);

    // Male input should yield surrogate from male pool (e.g. Thomas, James, Michael...)
    expect(PolymorphicLexicon.inferGender(male.surrogate)).toBe('MALE');
    // Female input should yield surrogate from female pool (e.g. Sarah, Lisa, Anna...)
    expect(PolymorphicLexicon.inferGender(female.surrogate)).toBe('FEMALE');
  });

  test('preserves professional titles', () => {
    const threadId = 'chat_thread_titles';
    const res = PolymorphicLexicon.generateSurrogate('Dr. Robert Taylor', 'NAME', threadId);
    expect(res.surrogate).toMatch(/^Dr\.\s+/);
  });

  test('generates hierarchical sub-entities for first names, last names, and possessives', () => {
    const threadId = 'chat_thread_hierarchy';
    const res = PolymorphicLexicon.generateSurrogate('John Doe', 'NAME', threadId);

    const subs = res.subEntities;
    expect(subs.some(s => s.original === 'John')).toBe(true);
    expect(subs.some(s => s.original === 'Doe')).toBe(true);
    expect(subs.some(s => s.original === "John's")).toBe(true);
    expect(subs.some(s => s.original === "John Doe's")).toBe(true);

    const firstSub = subs.find(s => s.original === 'John');
    const fullSurrogateParts = res.surrogate.split(' ');
    expect(firstSub.surrogate).toBe(fullSurrogateParts[0]);
  });

  test('applyReplacements safely replaces longest match first without corrupting sub-names', () => {
    const threadId = 'chat_thread_replacement';
    const entity = PolymorphicLexicon.generateSurrogate('John Doe', 'NAME', threadId);

    const input = "John Doe's prescription was handed to John Doe, then John called his pharmacy.";
    const output = PolymorphicLexicon.applyReplacements(input, [entity]);

    const surrFull = entity.surrogate;
    const surrFirst = surrFull.split(' ')[0];

    // Verify correct structure:
    // "Thomas Miller's prescription was handed to Thomas Miller, then Thomas called his pharmacy."
    expect(output).toContain(`${surrFull}'s prescription`);
    expect(output).toContain(`handed to ${surrFull}`);
    expect(output).toContain(`then ${surrFirst} called`);
    // Ensure no broken tokens like "Thomas Miller's Doe's"
    expect(output).not.toContain("Doe's");
    expect(output).not.toContain("John");
  });

  test('generates safety-guaranteed fake PII (SSN never issued, CC fails Luhn)', () => {
    const ssnRes = PolymorphicLexicon.generateSurrogate('123-45-6789', 'SSN', 't1');
    expect(ssnRes.surrogate).toMatch(/^(?:000|666|999)-\d{2}-\d{4}$/);

    const ccRes = PolymorphicLexicon.generateSurrogate('4111-2222-3333-4444', 'Credit Card', 't1');
    expect(ccRes.surrogate).toMatch(/^\d{4}-\d{4}-\d{4}-\d{4}$/);
    // CC must end in 0 or 1 and fail Luhn
    const digits = ccRes.surrogate.replace(/\D/g, '');
    let sum = 0;
    for (let i = 0; i < digits.length; i++) {
      let d = parseInt(digits[digits.length - 1 - i], 10);
      if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
      sum += d;
    }
    expect(sum % 10).not.toBe(0); // Fails Luhn
  });
});

describe('VIGIL Conversational Mode: Multi-Turn Quasi-Identifier Longitudinal Auditing', () => {
  const KAnonymity = require('../src/content/modules/k-anonymity-auditor');

  beforeEach(() => {
    ThreadRegistry.resetAll();
  });

  test('accumulates fragmented quasi-identifiers across turns and collapses k-anonymity', () => {
    const threadId = 'thread_longitudinal_qi';

    // Turn 1: Benign graduation
    const turn1 = KAnonymity.auditPrompt('I graduated from Stanford University in 2018.', threadId);
    expect(turn1.quasiIdentifiers).toHaveLength(1);
    expect(turn1.isHighRisk).toBe(false);
    expect(turn1.isMultiTurn).toBe(false);

    // Turn 2: Niche employment
    const turn2 = KAnonymity.auditPrompt('I am employed at a 12-person biotech startup in Zurich.', threadId);
    expect(turn2.quasiIdentifiers).toHaveLength(1);
    expect(turn2.isMultiTurn).toBe(true);

    // Turn 3: Rare clinical condition
    const turn3 = KAnonymity.auditPrompt('My patient was diagnosed with rare pulmonary fibrosis.', threadId);
    expect(turn3.isMultiTurn).toBe(true);
    expect(turn3.accumulatedQuasiIdentifiers.length).toBeGreaterThanOrEqual(3);
    expect(turn3.isHighRisk).toBe(true);
    expect(turn3.estimatedK).toBeLessThanOrEqual(25);
    expect(turn3.warning).toContain('Across this conversation');
  });

  test('applies Copula discount to correlated quasi-identifiers (no false alarm)', () => {
    const threadId = 'thread_correlated_qi';

    // Disclosing tech specialization and software niche in same area
    const turn1 = KAnonymity.auditPrompt('I work at an agency in San Francisco.', threadId);
    const turn2 = KAnonymity.auditPrompt('I specialize in infrastructure cryptography.', threadId);

    expect(turn2.isMultiTurn).toBe(true);
    // Discount factor should prevent overcounting correlated tech traits into a false CRITICAL alarm
    expect(turn2.cumulativeEntropy).toBeLessThan(turn1.cumulativeEntropy + 4.2);
  });
});
