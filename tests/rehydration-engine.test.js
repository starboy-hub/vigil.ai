/**
 * @jest-environment jsdom
 */
const rehydration = require('../src/content/modules/rehydration-engine.js');

describe('VIGIL Autonomous Bidirectional Rehydration Engine', () => {
  beforeEach(() => {
    rehydration.clearSubstitutions();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    rehydration.stopStreamingObserver();
  });

  describe('Substitution Mapping Store', () => {
    test('records single surrogate-to-real substitutions', () => {
      expect(rehydration.recordSubstitution('Alex Mercer', 'Sarah Mitchell')).toBe(true);
      expect(rehydration.getSubstitutionCount()).toBe(1);
    });

    test('bulk records substitution trees', () => {
      const tree = {
        'Alex Mercer': 'Sarah Mitchell',
        'Apex Systems': 'Acme Corp',
        'Metropolis': 'San Francisco'
      };
      const count = rehydration.recordSubstitutionTree(tree);
      expect(count).toBe(3);
      expect(rehydration.getSubstitutionCount()).toBe(3);
    });

    test('ignores invalid or identity substitutions', () => {
      expect(rehydration.recordSubstitution('Same', 'Same')).toBe(false);
      expect(rehydration.recordSubstitution('', 'Real')).toBe(false);
      expect(rehydration.recordSubstitution('Surrogate', '')).toBe(false);
    });
  });

  describe('Pure Text Rehydration', () => {
    test('translates multiple surrogates in string back to real entities', () => {
      rehydration.recordSubstitutionTree({
        'Alex Mercer': 'Sarah Mitchell',
        'Apex Systems': 'Acme Corp'
      });

      const responseFromCloud = 'Hello Alex Mercer, welcome to Apex Systems support!';
      const rehydrated = rehydration.rehydrateText(responseFromCloud);

      expect(rehydrated).toBe('Hello Sarah Mitchell, welcome to Acme Corp support!');
    });

    test('returns original string when no surrogates are matched', () => {
      rehydration.recordSubstitution('SurrogateX', 'RealX');
      const text = 'Clean text with no surrogates.';
      expect(rehydration.rehydrateText(text)).toBe(text);
    });
  });

  describe('DOM Tree Rehydration & Safety Boundaries', () => {
    test('rehydrates text nodes in safe response containers', () => {
      rehydration.recordSubstitution('Alex Mercer', 'Sarah Mitchell');

      const container = document.createElement('div');
      container.className = 'chat-message-assistant';
      const p = document.createElement('p');
      p.textContent = 'Patient Alex Mercer report: stable.';
      container.appendChild(p);
      document.body.appendChild(container);

      const modified = rehydration.rehydrateSubtree(container);
      expect(modified).toBe(1);
      expect(p.textContent).toBe('Patient Sarah Mitchell report: stable.');
    });

    test('NEVER mutates input fields or contenteditable user inputs', () => {
      rehydration.recordSubstitution('Alex Mercer', 'Sarah Mitchell');

      const input = document.createElement('input');
      input.value = 'Alex Mercer';
      document.body.appendChild(input);

      const editable = document.createElement('div');
      editable.contentEditable = 'true';
      const textNode = document.createTextNode('Draft for Alex Mercer');
      editable.appendChild(textNode);
      document.body.appendChild(editable);

      expect(rehydration.rehydrateTextNode(textNode)).toBe(false);
      expect(textNode.nodeValue).toBe('Draft for Alex Mercer');
    });

    test('streaming MutationObserver rehydrates newly appended nodes dynamically', async () => {
      rehydration.recordSubstitution('Alex Mercer', 'Sarah Mitchell');

      const chatContainer = document.createElement('div');
      chatContainer.className = 'assistant-container';
      document.body.appendChild(chatContainer);

      rehydration.startStreamingObserver(chatContainer);

      const streamP = document.createElement('p');
      streamP.textContent = 'Streaming reply for Alex Mercer...';
      chatContainer.appendChild(streamP);

      // Wait for microtask / MutationObserver dispatch
      await new Promise(res => setTimeout(res, 50));

      expect(streamP.textContent).toBe('Streaming reply for Sarah Mitchell...');
    });
  });
});

