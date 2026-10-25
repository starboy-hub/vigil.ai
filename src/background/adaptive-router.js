/**
 * VIGIL AI — System 6: Adaptive Test-Time Compute & Fast/Deep Model Router
 *
 * Dynamically orchestrates local AI inference between:
 *  - Fast System 1 SLMs (1B-3B, e.g. llama3.2:1b/3b, qwen2.5:1.5b): sub-second low-latency (<800ms)
 *    for instant prompt paraphrasing, sanitization, and PII anonymization.
 *  - Deep System 2 Reasoning Models (7B-8B+, e.g. deepseek-r1:8b, qwen2.5:7b): high test-time compute
 *    with chain-of-thought for adversarial red-teaming and complex legal/contract abstraction.
 *
 * Prevents inference hangs, thermal throttling, and model mismatches.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VIGIL_ADAPTIVE_ROUTER = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const FAST_SLM_REGEX = /(?:llama3\.2:(?:1b|3b)|qwen2\.5:(?:0\.5b|1\.5b|3b)|phi(?:-3\.5|-3)?(?:-mini)?|gemma(?:2)?:2b)/i;
  const DEEP_REASONING_REGEX = /(?:deepseek-r1|qwen2\.5:(?:7b|14b|32b)|llama3\.1:(?:8b|70b)|mistral(?:-small)?:8b)/i;

  /**
   * Classifies a model name into its performance and reasoning tier
   */
  function classifyModel(modelName) {
    if (!modelName || typeof modelName !== 'string') return 'UNKNOWN';
    if (FAST_SLM_REGEX.test(modelName)) return 'FAST_SLM';
    if (DEEP_REASONING_REGEX.test(modelName)) return 'DEEP_REASONING';
    return 'STANDARD_LLM';
  }

  /**
   * Evaluates prompt complexity and returns the optimal model and inference config
   */
  function routeTask(taskType, prompt, availableModels = []) {
    const text = typeof prompt === 'string' ? prompt : '';
    const models = Array.isArray(availableModels) ? availableModels : [];

    // Categorize available models
    const fastModels = models.filter(m => classifyModel(m) === 'FAST_SLM');
    const deepModels = models.filter(m => classifyModel(m) === 'DEEP_REASONING');
    const standardModels = models.filter(m => classifyModel(m) === 'STANDARD_LLM');

    let selectedModel = null;
    let tier = 'client_fallback';
    let options = {
      temperature: 0.1,
      num_predict: 150
    };
    let reasoningEffort = 'low';

    const isDeepTask = taskType === 'ADVERSARIAL_REDTEAM' || taskType === 'DEEP_AUDIT' || text.length > 2500;

    if (isDeepTask) {
      // Prioritize deep reasoning model
      if (deepModels.length > 0) {
        selectedModel = deepModels[0];
        tier = 'deep_reasoning';
        options = {
          temperature: 0.4,
          num_predict: 800
        };
        reasoningEffort = 'high';
      } else if (standardModels.length > 0) {
        selectedModel = standardModels[0];
        tier = 'standard_llm';
        options = {
          temperature: 0.2,
          num_predict: 400
        };
        reasoningEffort = 'medium';
      } else if (fastModels.length > 0) {
        selectedModel = fastModels[0];
        tier = 'fast_slm';
        options = {
          temperature: 0.2,
          num_predict: 250
        };
        reasoningEffort = 'low';
      }
    } else {
      // Fast, low-latency task (safe paraphrase, PII masking, etc.)
      if (fastModels.length > 0) {
        selectedModel = fastModels[0];
        tier = 'fast_slm';
        options = {
          temperature: 0.1,
          num_predict: 120,
          stop: ['\n\nOriginal:', '\nRewritten:']
        };
        reasoningEffort = 'minimal';
      } else if (standardModels.length > 0) {
        selectedModel = standardModels[0];
        tier = 'standard_llm';
        options = {
          temperature: 0.1,
          num_predict: 150
        };
        reasoningEffort = 'low';
      } else if (deepModels.length > 0) {
        // Deep model assigned to fast task: heavily constrain output tokens
        selectedModel = deepModels[0];
        tier = 'deep_reasoning_constrained';
        options = {
          temperature: 0.1,
          num_predict: 120
        };
        reasoningEffort = 'constrained';
      }
    }

    return {
      taskType,
      selectedModel,
      tier,
      options,
      reasoningEffort,
      timeoutMs: tier.startsWith('deep') ? 35000 : 8000
    };
  }

  /**
   * Executes inference via the routed model, applying token cleaning & thinking strip
   */
  async function executeRoutedInference(routeConfig, promptText, fetchFn = null) {
    const f = fetchFn || (typeof fetch !== 'undefined' ? fetch : null);
    if (!f || !routeConfig || !routeConfig.selectedModel) {
      return { ok: false, fallback: true, error: 'no_model_or_fetch' };
    }

    const { selectedModel, options, timeoutMs, taskType } = routeConfig;

    try {
      const headers = Object.assign({
        'Content-Type': 'application/json',
        'X-Vigil-Origin': 'chrome-extension://vigil-local',
        'X-Requested-With': 'VigilAI'
      }, routeConfig.headers || {});

      const resp = await f('http://localhost:11434/api/generate', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          model: selectedModel,
          prompt: promptText,
          options,
          stream: false
        }),
        signal: typeof AbortSignal !== 'undefined' && AbortSignal.timeout && typeof timeoutMs === 'number' ? AbortSignal.timeout(timeoutMs) : undefined
      });

      if (!resp || !resp.ok) {
        return { ok: false, fallback: true, status: resp ? resp.status : 0 };
      }

      // Rogue server mitigation: Ensure content-type is valid json
      const ct = (resp.headers && resp.headers.get) ? (resp.headers.get('content-type') || '') : 'application/json';
      if (ct && !ct.includes('application/json') && !ct.includes('text/plain')) {
        return { ok: false, fallback: true, status: 415, error: 'invalid_content_type' };
      }

      const data = await resp.json().catch(() => null);
      if (!data || typeof data !== 'object') {
        return { ok: false, fallback: true, error: 'invalid_json_payload' };
      }

      let rawText = data.response || '';

      // If fast task and model returned CoT <think>...</think>, strip it
      let thinking = null;
      const thinkMatch = rawText.match(/<think>([\s\S]*?)<\/think>/i);
      if (thinkMatch) {
        thinking = thinkMatch[1].trim();
        if (taskType === 'FAST_PARAPHRASE') {
          rawText = rawText.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
        }
      }

      return {
        ok: true,
        text: rawText.trim(),
        thinking,
        model: selectedModel,
        tier: routeConfig.tier
      };
    } catch (err) {
      // Silent degradation: NEVER leak console errors; pass clean error description to caller
      return { ok: false, fallback: true, error: err && err.message ? err.message : 'silent_failover' };
    }
  }

  return {
    FAST_SLM_REGEX,
    DEEP_REASONING_REGEX,
    classifyModel,
    routeTask,
    executeRoutedInference
  };
});

