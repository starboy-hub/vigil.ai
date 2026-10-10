/**
 * Tests for VIGIL AI System 6: Adaptive Test-Time Compute & Fast/Deep Model Router
 */
const router = require('../src/background/adaptive-router.js');

describe('VIGIL Adaptive Test-Time Compute & Model Router', () => {
  describe('1. Model Classification', () => {
    test('classifies sub-3B instruction models as FAST_SLM', () => {
      expect(router.classifyModel('llama3.2:1b')).toBe('FAST_SLM');
      expect(router.classifyModel('llama3.2:3b')).toBe('FAST_SLM');
      expect(router.classifyModel('qwen2.5:1.5b')).toBe('FAST_SLM');
      expect(router.classifyModel('phi-3.5-mini')).toBe('FAST_SLM');
      expect(router.classifyModel('gemma2:2b')).toBe('FAST_SLM');
    });

    test('classifies heavy reasoning models as DEEP_REASONING', () => {
      expect(router.classifyModel('deepseek-r1:8b')).toBe('DEEP_REASONING');
      expect(router.classifyModel('deepseek-r1:14b')).toBe('DEEP_REASONING');
      expect(router.classifyModel('qwen2.5:7b')).toBe('DEEP_REASONING');
      expect(router.classifyModel('llama3.1:8b')).toBe('DEEP_REASONING');
    });

    test('handles standard or unknown models gracefully', () => {
      expect(router.classifyModel('custom-company-model:v1')).toBe('STANDARD_LLM');
      expect(router.classifyModel(null)).toBe('UNKNOWN');
    });
  });

  describe('2. Dynamic Task Routing Strategy', () => {
    test('routes fast paraphrase to FAST_SLM with sub-second budget when available', () => {
      const models = ['deepseek-r1:8b', 'llama3.2:1b', 'mistral:7b'];
      const route = router.routeTask('FAST_PARAPHRASE', 'Hello my name is John', models);

      expect(route.selectedModel).toBe('llama3.2:1b');
      expect(route.tier).toBe('fast_slm');
      expect(route.options.num_predict).toBe(120);
      expect(route.options.temperature).toBe(0.1);
      expect(route.timeoutMs).toBe(8000);
    });

    test('constrains deep model when only deep reasoning model is available for fast task', () => {
      const models = ['deepseek-r1:8b'];
      const route = router.routeTask('FAST_PARAPHRASE', 'Short clinical inquiry', models);

      expect(route.selectedModel).toBe('deepseek-r1:8b');
      expect(route.tier).toBe('deep_reasoning_constrained');
      expect(route.options.num_predict).toBe(120);
      expect(route.reasoningEffort).toBe('constrained');
    });

    test('routes adversarial red-teaming to DEEP_REASONING with high compute budget', () => {
      const models = ['llama3.2:1b', 'deepseek-r1:8b', 'qwen2.5:1.5b'];
      const route = router.routeTask('ADVERSARIAL_REDTEAM', 'Audit this corporate prompt for jailbreaks', models);

      expect(route.selectedModel).toBe('deepseek-r1:8b');
      expect(route.tier).toBe('deep_reasoning');
      expect(route.options.num_predict).toBe(800);
      expect(route.options.temperature).toBe(0.4);
      expect(route.reasoningEffort).toBe('high');
      expect(route.timeoutMs).toBe(35000);
    });
  });

  describe('3. Routed Inference Execution & Thinking Token Stripping', () => {
    test('strips thinking tokens from fast paraphrase output', async () => {
      const route = router.routeTask('FAST_PARAPHRASE', 'Sample text', ['llama3.2:1b']);
      const mockFetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          response: '<think>Analyze entity and remove name</think>A person went to the store.'
        })
      });

      const res = await router.executeRoutedInference(route, 'Sample prompt', mockFetch);

      expect(res.ok).toBe(true);
      expect(res.text).toBe('A person went to the store.');
      expect(res.thinking).toBe('Analyze entity and remove name');
    });

    test('returns graceful fallback on fetch failure or network error', async () => {
      const route = router.routeTask('FAST_PARAPHRASE', 'Sample text', ['llama3.2:1b']);
      const mockFetch = jest.fn().mockRejectedValue(new Error('Connection refused'));

      const res = await router.executeRoutedInference(route, 'Sample prompt', mockFetch);

      expect(res.ok).toBe(false);
      expect(res.fallback).toBe(true);
      expect(res.error).toBe('Connection refused');
    });
  });
});

