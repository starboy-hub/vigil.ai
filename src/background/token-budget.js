/**
 * VIGIL Security Policy: Token Budget Enforcement for Agentic AI
 *
 * Problem: Autonomous AI agents (AutoGPT, Devins, Claude Code, Tool Use agents)
 * can enter infinite reasoning loops, catastrophic recursion, or prompt injection
 * reflection traps, consuming hundreds of thousands of tokens and exhausting API quotas
 * or incurring immense cloud bills in minutes.
 *
 * Solution: Client-side and native desktop token budgeting with per-session quotas,
 * 24-hour rolling daily limits, runaway loop heuristics, and configurable hard blocking
 * vs soft telemetry alerting.
 */
(function (root) {
  'use strict';

  const DEFAULT_CONFIG = {
    sessionLimit: 50000,       // Max tokens per agent session
    dailyLimit: 250000,        // Max tokens per 24h rolling window
    enforcementMode: 'hard_block', // 'hard_block' | 'soft_alert'
    alertThreshold: 0.80,      // Alert at 80% quota consumption
    loopThresholdCount: 10,    // Requests within loopWindowMs to trigger loop alert
    loopWindowMs: 5000         // 5 second detection window for runaway loops
  };

  const ACCOUNT_MAX_AGE_MS = 30 * 86400000; // accounts idle 30 days are evicted
  const MAX_ACCOUNTS = 200;                 // retention cap by most-recent activity

  /**
   * Estimates token count for text or structured payload.
   * Based on standard BPE tokenizer averages (~4 chars/token in English/code,
   * adjusted for punctuation, whitespaces, and JSON overhead).
   */
  function estimateTokens(input) {
    if (!input) return 0;
    let str = typeof input === 'string' ? input : JSON.stringify(input);
    if (!str || str.length === 0) return 0;

    // Fast heuristic: base 3.8 chars per token + word & symbol adjustment
    const charCount = str.length;
    const words = str.trim().split(/\s+/).filter(Boolean).length;
    const specialChars = (str.match(/[{}[\]()<>=:;,."`\\/]/g) || []).length;

    // Weighted estimation
    const estimated = Math.ceil((charCount * 0.22) + (words * 0.15) + (specialChars * 0.1));
    return Math.max(1, estimated);
  }

  class TokenBudgetManager {
    constructor(config = {}) {
      this.config = { ...DEFAULT_CONFIG, ...config };
      this.accounts = new Map();
      this.requestHistory = new Map(); // agentId -> array of timestamps
      this.isStorageLoaded = false;
      // Persisted accounts must be loaded before any _persist write, or an
      // early recordUsage would overwrite stored quota state with the
      // (empty) in-memory map.
      this._storageReady = this._initStorage();
    }

    _initStorage() {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        return new Promise((resolve) => {
          try {
            chrome.storage.local.get(
              ['vigil_token_budgets', 'vigil_token_config'],
              (res) => {
                if (res && res.vigil_token_config) {
                  this.config = { ...this.config, ...res.vigil_token_config };
                }
                const budgets = res && res.vigil_token_budgets;
                if (budgets) {
                  for (const [id, acc] of Object.entries(budgets)) {
                    this.accounts.set(id, acc);
                  }
                  this._pruneAccounts();
                }
                this.isStorageLoaded = true;
                resolve();
              }
            );
          } catch {
            this.isStorageLoaded = true;
            resolve();
          }
        });
      }
      this.isStorageLoaded = true;
      return Promise.resolve();
    }

    async _persist() {
      try { await this._storageReady; } catch (e) { /* storage unavailable */ }
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        try {
          this._pruneAccounts();
          const serialized = {};
          for (const [id, acc] of this.accounts.entries()) {
            serialized[id] = acc;
          }
          chrome.storage.local.set({
            vigil_token_budgets: serialized,
            vigil_token_config: this.config
          });
        } catch {
          // Ignore extension context invalidated
        }
      }
    }

    // Storage GC: accounts idle for 30 days are evicted, and at most
    // MAX_ACCOUNTS (by most-recent activity) are retained — one entry per
    // agentId would otherwise grow without bound.
    _pruneAccounts() {
      const now = Date.now();
      for (const [id, acc] of this.accounts.entries()) {
        const last = Math.max(acc.lastActivityAt || 0, acc.lastResetTimestamp || 0);
        if (now - last > ACCOUNT_MAX_AGE_MS) this.accounts.delete(id);
      }
      if (this.accounts.size > MAX_ACCOUNTS) {
        const sorted = [...this.accounts.entries()]
          .sort((a, b) => Math.max(a[1].lastActivityAt || 0, a[1].lastResetTimestamp || 0) - Math.max(b[1].lastActivityAt || 0, b[1].lastResetTimestamp || 0));
        while (sorted.length > MAX_ACCOUNTS) {
          const [id] = sorted.shift();
          this.accounts.delete(id);
        }
      }
    }

    _getOrCreateAccount(agentId) {
      const now = Date.now();
      let acc = this.accounts.get(agentId);
      if (!acc) {
        acc = {
          agentId,
          sessionTokens: 0,
          dailyTokens: 0,
          lastResetTimestamp: now,
          totalRequests: 0,
          blockedRequests: 0,
          alertsCount: 0,
          history: []
        };
        this.accounts.set(agentId, acc);
      }

      // Check 24-hour daily rollover
      if (now - acc.lastResetTimestamp >= 86400000) {
        acc.dailyTokens = 0;
        acc.lastResetTimestamp = now;
      }

      return acc;
    }

    /**
     * Checks if agent is exhibiting rapid repetitive runaway behavior
     */
    _checkRunawayLoop(agentId) {
      const now = Date.now();
      let history = this.requestHistory.get(agentId) || [];
      history = history.filter(ts => now - ts < this.config.loopWindowMs);
      history.push(now);
      this.requestHistory.set(agentId, history);

      return history.length >= this.config.loopThresholdCount;
    }

    /**
     * Read-only runaway check: pre-flight probes must not advance the burst
     * counter, or repeated probing alone can hard-block a legitimate request.
     */
    _peekRunawayLoop(agentId) {
      const now = Date.now();
      const history = (this.requestHistory.get(agentId) || []).filter(ts => now - ts < this.config.loopWindowMs);
      return history.length >= this.config.loopThresholdCount;
    }

    /**
     * Pre-flight budget check without committing token consumption (and
     * without any runaway-loop side effect — only recordUsage counts a request)
     */
    checkBudget(agentId, tokensOrInput, options = {}) {
      const tokens = typeof tokensOrInput === 'number' ? tokensOrInput : estimateTokens(tokensOrInput);
      const acc = this._getOrCreateAccount(agentId);

      const willExceedSession = (acc.sessionTokens + tokens) > this.config.sessionLimit;
      const willExceedDaily = (acc.dailyTokens + tokens) > this.config.dailyLimit;
      const isLoop = options.countRequest ? this._checkRunawayLoop(agentId) : this._peekRunawayLoop(agentId);

      const exceeded = willExceedSession || willExceedDaily || isLoop;
      const hardBlocked = exceeded && this.config.enforcementMode === 'hard_block';
      const softAlert = exceeded && this.config.enforcementMode === 'soft_alert';

      let reason = null;
      if (isLoop) {
        reason = `Runaway API loop detected (${this.config.loopThresholdCount}+ requests in ${this.config.loopWindowMs / 1000}s)`;
      } else if (willExceedSession) {
        reason = `Session token limit reached (${acc.sessionTokens + tokens} / ${this.config.sessionLimit})`;
      } else if (willExceedDaily) {
        reason = `24h rolling daily token limit reached (${acc.dailyTokens + tokens} / ${this.config.dailyLimit})`;
      }

      const sessionRemaining = Math.max(0, this.config.sessionLimit - acc.sessionTokens);
      const dailyRemaining = Math.max(0, this.config.dailyLimit - acc.dailyTokens);
      const sessionPct = Math.min(100, Math.round((acc.sessionTokens / this.config.sessionLimit) * 100));
      const dailyPct = Math.min(100, Math.round((acc.dailyTokens / this.config.dailyLimit) * 100));

      const warningThreshold = this.config.alertThreshold * 100;
      const nearLimitWarning = !exceeded && (sessionPct >= warningThreshold || dailyPct >= warningThreshold);

      return {
        allowed: !hardBlocked,
        hardBlocked,
        softAlert,
        nearLimitWarning,
        agentId,
        estimatedTokens: tokens,
        sessionTokens: acc.sessionTokens,
        sessionLimit: this.config.sessionLimit,
        sessionRemaining,
        dailyTokens: acc.dailyTokens,
        dailyLimit: this.config.dailyLimit,
        dailyRemaining,
        sessionPercentage: sessionPct,
        dailyPercentage: dailyPct,
        enforcementMode: this.config.enforcementMode,
        isRunawayLoop: isLoop,
        reason
      };
    }

    /**
     * Records token usage and enforces budget policies
     */
    recordUsage(agentId, tokensOrInput) {
      const tokens = typeof tokensOrInput === 'number' ? tokensOrInput : estimateTokens(tokensOrInput);
      const verdict = this.checkBudget(agentId, tokens, { countRequest: true });
      const acc = this._getOrCreateAccount(agentId);

      if (verdict.hardBlocked) {
        acc.blockedRequests = (acc.blockedRequests || 0) + 1;
        this._persist();
        return {
          ...verdict,
          committed: false
        };
      }

      // Usage permitted (either clean or soft alert)
      acc.sessionTokens += tokens;
      acc.dailyTokens += tokens;
      acc.totalRequests += 1;
      acc.lastActivityAt = Date.now();

      // Recalculate accurate post-commit values
      verdict.sessionTokens = acc.sessionTokens;
      verdict.dailyTokens = acc.dailyTokens;
      verdict.sessionRemaining = Math.max(0, this.config.sessionLimit - acc.sessionTokens);
      verdict.dailyRemaining = Math.max(0, this.config.dailyLimit - acc.dailyTokens);
      verdict.sessionPercentage = Math.min(100, Math.round((acc.sessionTokens / this.config.sessionLimit) * 100));
      verdict.dailyPercentage = Math.min(100, Math.round((acc.dailyTokens / this.config.dailyLimit) * 100));
      verdict.committed = true;

      const warningThreshold = this.config.alertThreshold * 100;
      verdict.nearLimitWarning = !verdict.hardBlocked && !verdict.softAlert && (verdict.sessionPercentage >= warningThreshold || verdict.dailyPercentage >= warningThreshold);

      if (verdict.softAlert || verdict.nearLimitWarning) {
        acc.alertsCount = (acc.alertsCount || 0) + 1;
      }

      this._persist();
      return verdict;
    }

    /**
     * Resets session quota for an agent
     */
    resetSession(agentId) {
      const acc = this.accounts.get(agentId);
      if (acc) {
        acc.sessionTokens = 0;
        this._persist();
        return true;
      }
      return false;
    }

    /**
     * Resets 24h daily quota for an agent
     */
    resetDaily(agentId) {
      const acc = this.accounts.get(agentId);
      if (acc) {
        acc.dailyTokens = 0;
        acc.lastResetTimestamp = Date.now();
        this._persist();
        return true;
      }
      return false;
    }

    /**
     * Updates configuration limits
     */
    setLimits(newConfig = {}) {
      if (typeof newConfig.sessionLimit === 'number') this.config.sessionLimit = newConfig.sessionLimit;
      if (typeof newConfig.dailyLimit === 'number') this.config.dailyLimit = newConfig.dailyLimit;
      if (newConfig.enforcementMode === 'hard_block' || newConfig.enforcementMode === 'soft_alert') {
        this.config.enforcementMode = newConfig.enforcementMode;
      }
      if (typeof newConfig.alertThreshold === 'number') this.config.alertThreshold = newConfig.alertThreshold;
      if (typeof newConfig.loopThresholdCount === 'number') this.config.loopThresholdCount = newConfig.loopThresholdCount;
      if (typeof newConfig.loopWindowMs === 'number') this.config.loopWindowMs = newConfig.loopWindowMs;

      this._persist();
      return { ...this.config };
    }

    /**
     * Retrieves account status or global overview
     */
    getStatus(agentId) {
      if (agentId) {
        const acc = this._getOrCreateAccount(agentId);
        return {
          config: { ...this.config },
          account: {
            ...acc,
            sessionRemaining: Math.max(0, this.config.sessionLimit - acc.sessionTokens),
            dailyRemaining: Math.max(0, this.config.dailyLimit - acc.dailyTokens),
            sessionPercentage: Math.min(100, Math.round((acc.sessionTokens / this.config.sessionLimit) * 100)),
            dailyPercentage: Math.min(100, Math.round((acc.dailyTokens / this.config.dailyLimit) * 100))
          }
        };
      }

      const allAccounts = {};
      for (const [id, acc] of this.accounts.entries()) {
        allAccounts[id] = {
          ...acc,
          sessionRemaining: Math.max(0, this.config.sessionLimit - acc.sessionTokens),
          dailyRemaining: Math.max(0, this.config.dailyLimit - acc.dailyTokens),
          sessionPercentage: Math.min(100, Math.round((acc.sessionTokens / this.config.sessionLimit) * 100)),
          dailyPercentage: Math.min(100, Math.round((acc.dailyTokens / this.config.dailyLimit) * 100))
        };
      }

      return {
        config: { ...this.config },
        accounts: allAccounts
      };
    }
  }

  // Singleton instance
  const tokenBudgetManager = new TokenBudgetManager();

  const TokenBudgetModule = {
    TokenBudgetManager,
    tokenBudgetManager,
    estimateTokens,
    DEFAULT_CONFIG
  };

  // UMD / CommonJS export
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = TokenBudgetModule;
  }
  if (root) {
    root.TokenBudgetModule = TokenBudgetModule;
    root.tokenBudgetManager = tokenBudgetManager;
    root.estimateTokens = estimateTokens;
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
