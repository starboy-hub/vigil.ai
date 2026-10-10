/**
 * VIGIL Blueprint #13: Prompt Git (Conversation Version Control)
 *
 * Problem: Users, AI engineers, and security red-teamers iterate extensively on
 * system prompts, adversarial vectors, and conversational contexts, but lack
 * Git-style version control. Exploring alternative conversational paths loses previous
 * states, and there is no way to perform branching, checkouts, or semantic diffs.
 *
 * Solution: An embedded Directed Acyclic Graph (DAG) commit store for prompts.
 * Prompts are tracked as cryptographic commits with parent hashing, named branches,
 * tags, detached HEAD checkouts, line-by-line diffing, and semantic security delta analysis.
 */
(function (root) {
  'use strict';

  const STORAGE_KEY = 'vigil_prompt_git_repos';

  function utf8Bytes(str) {
    if (typeof TextEncoder !== 'undefined') {
      return Array.from(new TextEncoder().encode(str));
    }
    // Minimal UTF-8 encoder for environments without TextEncoder
    const out = [];
    for (let i = 0; i < str.length; i++) {
      let c = str.codePointAt(i);
      if (c > 0xffff) i++;
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return out;
  }

  function sha256(str) {
    if (typeof require === 'function') {
      try {
        const crypto = require('crypto');
        return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
      } catch {
        // Fall back to JS
      }
    }

    // Pure-JS SHA-256 over UTF-8 BYTES: prompts are user text and must hash
    // byte-faithfully (the previous charCodeAt & 0xff path truncated every
    // non-ASCII character to its low byte, causing digest collisions).
    const bytes = utf8Bytes(str);

    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }

    const bitLength = bytes.length * 8;
    const words = [];
    let hash = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const k = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    for (let i = 0; i < bytes.length; i++) {
      words[i >> 2] |= bytes[i] << ((3 - (i % 4)) * 8);
    }
    words[(bytes.length >> 2)] |= 0x80 << ((3 - (bytes.length % 4)) * 8);
    const wordCount = (((bitLength + 64) >> 9) + 1) << 4;
    words[wordCount - 1] = bitLength;

    const w = new Array(64);
    for (let chunk = 0; chunk < wordCount; chunk += 16) {
      let [a, b, c, d, e, f, g, h] = hash;
      for (let j = 0; j < 64; j++) {
        if (j < 16) w[j] = (words[chunk + j] || 0) | 0;
        else {
          const s0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
          const s1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
          w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
        }
        const s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        const ch = (e & f) ^ ((~e) & g);
        const temp1 = (h + s1 + ch + k[j] + w[j]) | 0;
        const s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (s0 + maj) | 0;

        h = g; g = f; f = e; e = (d + temp1) | 0;
        d = c; c = b; b = a; a = (temp1 + temp2) | 0;
      }
      hash[0] = (hash[0] + a) | 0; hash[1] = (hash[1] + b) | 0; hash[2] = (hash[2] + c) | 0; hash[3] = (hash[3] + d) | 0;
      hash[4] = (hash[4] + e) | 0; hash[5] = (hash[5] + f) | 0; hash[6] = (hash[6] + g) | 0; hash[7] = (hash[7] + h) | 0;
    }

    let result = '';
    for (let j = 0; j < 8; j++) {
      result += ((hash[j] >>> 0).toString(16)).padStart(8, '0');
    }
    return result;
  }

  class PromptGitEngine {
    constructor(options = {}) {
      this.storage = options.storage || null;
      this.activeRepoId = options.defaultRepoId || 'default';
      this.repos = {};
      this.initRepo(this.activeRepoId);
    }

    /**
     * Initializes a fresh repository DAG if it doesn't exist
     */
    initRepo(repoId = 'default') {
      if (!this.repos[repoId]) {
        this.repos[repoId] = {
          id: repoId,
          head: 'refs/heads/main',
          branches: {
            'main': null
          },
          tags: {},
          commits: {}
        };
      }
      return this.repos[repoId];
    }

    getRepo(repoId = null) {
      const id = repoId || this.activeRepoId;
      return this.repos[id] || this.initRepo(id);
    }

    /**
     * Resolves the commit ID pointed to by HEAD
     */
    getHeadCommit(repoId = null) {
      const repo = this.getRepo(repoId);
      if (repo.head.startsWith('refs/heads/')) {
        const branchName = repo.head.replace('refs/heads/', '');
        return repo.branches[branchName] || null;
      }
      return repo.head || null; // Detached HEAD
    }

    getCurrentBranch(repoId = null) {
      const repo = this.getRepo(repoId);
      if (repo.head.startsWith('refs/heads/')) {
        return repo.head.replace('refs/heads/', '');
      }
      return null; // Detached HEAD
    }

    /**
     * Computes deterministic SHA-256 commit hash
     */
    _hashCommit(parents, timestamp, message, prompt, author) {
      const parentStr = Array.isArray(parents) ? parents.join(',') : (parents || '');
      const raw = `${parentStr}|${timestamp}|${message}|${prompt}|${author}`;
      return sha256(raw).slice(0, 40);
    }

    /**
     * Creates a new Commit in the DAG
     */
    async commit(prompt, message = 'Update prompt', options = {}) {
      if (typeof prompt !== 'string') {
        throw new TypeError('Prompt content must be a string');
      }

      const repo = this.getRepo(options.repoId);
      const parentId = this.getHeadCommit(options.repoId);
      const parents = parentId ? [parentId] : [];
      const timestamp = options.timestamp || new Date().toISOString();
      const author = options.author || 'local_user';

      const commitId = this._hashCommit(parents, timestamp, message, prompt, author);

      const commitObj = {
        id: commitId,
        parents,
        timestamp,
        message,
        prompt,
        author,
        metadata: {
          charLength: prompt.length,
          estimatedTokens: Math.max(1, Math.ceil(prompt.length / 4)),
          tags: options.tags || []
        }
      };

      repo.commits[commitId] = commitObj;

      // Advance branch pointer or detached HEAD
      if (repo.head.startsWith('refs/heads/')) {
        const branchName = repo.head.replace('refs/heads/', '');
        repo.branches[branchName] = commitId;
      } else {
        repo.head = commitId;
      }

      await this._persist();
      return commitObj;
    }

    /**
     * Creates a new branch pointing to a start commit or HEAD
     */
    async branch(name, startPoint = null, options = {}) {
      if (!name || !/^[a-zA-Z0-9_/-]+$/.test(name)) {
        throw new Error('Invalid branch name. Must be alphanumeric with dash/underscore/slash.');
      }

      const repo = this.getRepo(options.repoId);
      if (repo.branches[name] !== undefined) {
        throw new Error(`Branch '${name}' already exists.`);
      }

      const targetCommit = startPoint || this.getHeadCommit(options.repoId);
      repo.branches[name] = targetCommit;

      await this._persist();
      return {
        name,
        commitId: targetCommit
      };
    }

    /**
     * Switches HEAD to a branch or a detached commit
     */
    async checkout(target, options = {}) {
      const repo = this.getRepo(options.repoId);

      if (repo.branches[target] !== undefined) {
        // Checkout named branch
        repo.head = 'refs/heads/' + target;
        const commitId = repo.branches[target];
        const commitObj = commitId ? repo.commits[commitId] : null;
        await this._persist();
        return {
          branch: target,
          isDetached: false,
          commit: commitObj
        };
      } else if (repo.commits[target]) {
        // Checkout detached commit
        repo.head = target;
        await this._persist();
        return {
          branch: null,
          isDetached: true,
          commit: repo.commits[target]
        };
      } else {
        throw new Error(`Target '${target}' does not exist as a branch or commit.`);
      }
    }

    /**
     * Traverses the commit DAG backward from HEAD or specified branch
     */
    log(options = {}) {
      const repo = this.getRepo(options.repoId);
      let startCommitId = null;

      if (options.branch) {
        startCommitId = repo.branches[options.branch];
      } else {
        startCommitId = this.getHeadCommit(options.repoId);
      }

      if (!startCommitId || !repo.commits[startCommitId]) {
        return [];
      }

      const history = [];
      const queue = [startCommitId];
      const visited = new Set();
      const limit = options.limit || 50;

      while (queue.length > 0 && history.length < limit) {
        const currentId = queue.shift();
        if (visited.has(currentId)) continue;
        visited.add(currentId);

        const currentCommit = repo.commits[currentId];
        if (!currentCommit) continue;

        history.push(currentCommit);

        // Queue parent commits for traversal
        if (Array.isArray(currentCommit.parents)) {
          for (const p of currentCommit.parents) {
            if (!visited.has(p)) queue.push(p);
          }
        }
      }

      return history;
    }

    /**
     * Computes textual and semantic diff between two commits
     */
    diff(commitIdA, commitIdB, options = {}) {
      const repo = this.getRepo(options.repoId);
      const commitA = repo.commits[commitIdA];
      const commitB = repo.commits[commitIdB];

      if (!commitA || !commitB) {
        throw new Error('Both commits must exist to compute a diff');
      }

      const textA = commitA.prompt || '';
      const textB = commitB.prompt || '';

      const linesA = textA.split('\n');
      const linesB = textB.split('\n');

      const hunks = [];
      const maxLines = Math.max(linesA.length, linesB.length);

      for (let i = 0; i < maxLines; i++) {
        const lineA = linesA[i];
        const lineB = linesB[i];

        if (lineA === lineB) {
          hunks.push({ type: 'unchanged', text: lineA });
        } else {
          if (lineA !== undefined) hunks.push({ type: 'deletion', text: lineA });
          if (lineB !== undefined) hunks.push({ type: 'addition', text: lineB });
        }
      }

      // Semantic Security Diff Analysis
      const securityKeywords = ['ignore', 'system', 'instructions', 'jailbreak', 'bypass', 'unrestricted', 'dan', 'filter'];
      const extractSecTokens = (txt) => {
        const words = txt.toLowerCase().match(/\b[a-z]{3,}\b/g) || [];
        return words.filter(w => securityKeywords.includes(w));
      };

      const secA = extractSecTokens(textA);
      const secB = extractSecTokens(textB);

      const addedSecurityTokens = secB.filter(x => !secA.includes(x));
      const removedSecurityTokens = secA.filter(x => !secB.includes(x));

      return {
        commitA: { id: commitA.id, message: commitA.message, timestamp: commitA.timestamp },
        commitB: { id: commitB.id, message: commitB.message, timestamp: commitB.timestamp },
        textualDiff: hunks,
        semanticDelta: {
          charDelta: textB.length - textA.length,
          tokenDelta: Math.ceil(textB.length / 4) - Math.ceil(textA.length / 4),
          addedSecurityTokens,
          removedSecurityTokens
        }
      };
    }

    /**
     * Nearest common ancestor of two commits (merge base). BFS from one side
     * against the full ancestor set of the other.
     */
    findMergeBase(aId, bId, repoId = null) {
      const repo = this.getRepo(repoId);
      if (!aId || !bId || !repo.commits[aId] || !repo.commits[bId]) return null;

      const ancestorsOfA = new Set();
      const queue = [aId];
      while (queue.length) {
        const id = queue.shift();
        if (ancestorsOfA.has(id)) continue;
        ancestorsOfA.add(id);
        const c = repo.commits[id];
        if (c && Array.isArray(c.parents)) queue.push(...c.parents);
      }

      const seen = new Set();
      const q2 = [bId];
      while (q2.length) {
        const id = q2.shift();
        if (seen.has(id)) continue;
        seen.add(id);
        if (ancestorsOfA.has(id)) return id;
        const c = repo.commits[id];
        if (c && Array.isArray(c.parents)) q2.push(...c.parents);
      }
      return null;
    }

    /**
     * Line-level 3-way content merge of base/A/B prompts. Returns
     * { merged, conflicts } — a line both sides changed differently is a
     * conflict; a line only one side changed takes that side's version.
     */
    _threeWayContentMerge(basePrompt, aPrompt, bPrompt) {
      const base = String(basePrompt || '').split('\n');
      const a = String(aPrompt || '').split('\n');
      const b = String(bPrompt || '').split('\n');

      if (a.join('\n') === base.join('\n')) return { merged: bPrompt, conflicts: [] };
      if (b.join('\n') === base.join('\n')) return { merged: aPrompt, conflicts: [] };

      const len = Math.max(a.length, b.length, base.length);
      const conflicts = [];
      const merged = [];
      for (let i = 0; i < len; i++) {
        const baseLine = base[i] ?? '';
        const aLine = a[i] ?? '';
        const bLine = b[i] ?? '';
        const aChanged = aLine !== baseLine;
        const bChanged = bLine !== baseLine;
        if (aChanged && bChanged && aLine !== bLine) {
          conflicts.push({ line: i + 1, base: baseLine, current: aLine, source: bLine });
          merged.push(`<<<<<<< ${aLine} ======= ${bLine} >>>>>>>`);
        } else if (bChanged) {
          merged.push(bLine);
        } else {
          merged.push(aLine);
        }
      }
      return { merged: merged.join('\n'), conflicts };
    }

    /**
     * 3-Way or Fast-Forward Merge of a source branch into the active branch.
     * Conflicting edits (both branches changed the same lines differently) are
     * reported and REFUSE the merge instead of silently taking one side.
     */
    async merge(sourceBranch, message = null, options = {}) {
      const repo = this.getRepo(options.repoId);
      const currentBranch = this.getCurrentBranch(options.repoId);

      if (!currentBranch) {
        throw new Error('Cannot merge while in detached HEAD state');
      }

      const currentHead = repo.branches[currentBranch];
      const sourceHead = repo.branches[sourceBranch];

      if (!sourceHead) {
        throw new Error(`Source branch '${sourceBranch}' does not exist or has no commits`);
      }

      if (currentHead === sourceHead) {
        return { merged: false, reason: 'Already up to date' };
      }

      // Fast-forward merge if current branch has no commits
      if (!currentHead) {
        repo.branches[currentBranch] = sourceHead;
        await this._persist();
        return { merged: true, fastForward: true, commitId: sourceHead };
      }

      // 3-Way content merge against the common ancestor
      const commitA = repo.commits[currentHead];
      const commitB = repo.commits[sourceHead];
      const baseId = this.findMergeBase(currentHead, sourceHead, options.repoId);
      const basePrompt = baseId ? repo.commits[baseId].prompt : '';

      const { merged: mergePrompt, conflicts } = this._threeWayContentMerge(basePrompt, commitA.prompt, commitB.prompt);

      if (conflicts.length > 0) {
        return {
          merged: false,
          conflicts,
          reason: `Merge conflicts detected on ${conflicts.length} line(s) — resolve manually and commit`
        };
      }

      const mergeMessage = message || `Merge branch '${sourceBranch}' into '${currentBranch}'`;
      const timestamp = new Date().toISOString();
      const parents = [currentHead, sourceHead];
      const commitId = this._hashCommit(parents, timestamp, mergeMessage, mergePrompt, 'merge_tool');

      const mergeCommit = {
        id: commitId,
        parents,
        timestamp,
        message: mergeMessage,
        prompt: mergePrompt,
        author: 'merge_engine',
        metadata: {
          charLength: mergePrompt.length,
          estimatedTokens: Math.ceil(mergePrompt.length / 4),
          mergeSource: sourceBranch,
          mergeTarget: currentBranch,
          mergeBase: baseId
        }
      };

      repo.commits[commitId] = mergeCommit;
      repo.branches[currentBranch] = commitId;
      this._pruneUnreachable(repo);

      await this._persist();
      return {
        merged: true,
        fastForward: false,
        commitId,
        commit: mergeCommit
      };
    }

    /**
     * Storage GC: removes commits unreachable from any branch head or tag.
     * Branch/checkout churn otherwise accumulates dead nodes forever.
     */
    _pruneUnreachable(repo) {
      const total = Object.keys(repo.commits).length;
      if (total <= 300) return 0;

      const reachable = new Set();
      const roots = [...Object.values(repo.branches).filter(Boolean), ...Object.values(repo.tags || {}).filter(Boolean)];
      const queue = [...roots];
      while (queue.length) {
        const id = queue.shift();
        if (!id || reachable.has(id) || !repo.commits[id]) continue;
        reachable.add(id);
        const c = repo.commits[id];
        if (Array.isArray(c.parents)) queue.push(...c.parents);
      }

      let pruned = 0;
      for (const id of Object.keys(repo.commits)) {
        if (!reachable.has(id)) {
          delete repo.commits[id];
          pruned++;
        }
      }
      return pruned;
    }

    /**
     * Returns repository status and branches
     */
    getStatus(repoId = null) {
      const repo = this.getRepo(repoId);
      const currentBranch = this.getCurrentBranch(repoId);
      const headCommitId = this.getHeadCommit(repoId);

      return {
        repoId: repo.id,
        currentBranch,
        isDetached: currentBranch === null,
        headCommitId,
        headCommit: headCommitId ? repo.commits[headCommitId] : null,
        branches: Object.keys(repo.branches),
        totalCommits: Object.keys(repo.commits).length
      };
    }

    /**
     * Storage persistence helpers
     */
    async _persist() {
      if (!this.storage) return;
      try {
        await this.storage.set({ [STORAGE_KEY]: this.repos });
      } catch {
        // Storage write ignored in memory mode
      }
    }

    async loadFromStorage() {
      if (!this.storage) return;
      try {
        const stored = await this.storage.get([STORAGE_KEY]);
        const data = stored && stored[STORAGE_KEY];
        if (data) {
          this.repos = data;
        }
      } catch {
        // Ignore read error
      }
    }

    exportRepository(repoId = null) {
      return JSON.parse(JSON.stringify(this.getRepo(repoId)));
    }

    importRepository(repoData) {
      if (!repoData || !repoData.id || !repoData.commits) {
        throw new Error('Invalid repository payload');
      }
      this.repos[repoData.id] = repoData;
      return true;
    }
  }

  const promptGitEngine = new PromptGitEngine();

  const PromptGitModule = {
    PromptGitEngine,
    promptGitEngine,
    STORAGE_KEY
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = PromptGitModule;
  }
  if (root) {
    root.VIGIL_PROMPT_GIT = PromptGitModule;
    root.promptGitEngine = promptGitEngine;
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this);
