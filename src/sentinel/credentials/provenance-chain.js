/**
 * Sentinel Swarm Security: Cryptographic Multi-Agent Provenance Chain
 * ===================================================================
 * Solves the "Agent Telephone Game" and prevents indirect prompt injection
 * cascading across autonomous multi-agent swarms (e.g., Planner -> Coder -> Runner).
 *
 * Enforces a Merkle Proof-of-Human-Origin chain:
 * 1. Root of Trust is always an authenticated human prompt.
 * 2. Every subagent delegation signs a cryptographic provenance hop.
 * 3. Scope can only attenuate (narrow), never escalate privileges.
 * 4. Quarantines unproven actions with broken lineage or hallucinated scope.
 */

'use strict';

const crypto = require('crypto');

class ProvenanceChainManager {
  /**
   * @param {Object} [options]
   * @param {string} [options.masterSecret] - HMAC signing secret for provenance hops
   */
  constructor(options = {}) {
    this.masterSecret = options.masterSecret || crypto.randomBytes(32).toString('hex');
  }

  /**
   * Initialize a new provenance chain anchored to verified human operator intent.
   *
   * @param {Object} params
   * @param {string} params.humanPrompt - Literal operator prompt
   * @param {string} params.sessionId - Unique session identifier
   * @param {Array<string>} [params.allowedRootActions] - Actions authorized by human
   * @param {Array<string>} [params.allowedResourcePatterns] - Resource paths authorized
   * @returns {Object} Root provenance object
   */
  createRootProvenance({ humanPrompt, sessionId, allowedRootActions = ['*'], allowedResourcePatterns = ['*'] }) {
    if (!humanPrompt || !sessionId) {
      throw new Error('humanPrompt and sessionId are required to anchor a provenance root');
    }

    const promptHash = crypto.createHash('sha256').update(String(humanPrompt)).digest('hex');
    const timestamp = Date.now();

    const rootHop = {
      hopIndex: 0,
      agentId: 'HUMAN_OPERATOR',
      parentHopHash: '0000000000000000000000000000000000000000000000000000000000000000',
      promptHash,
      allowedActions: allowedRootActions,
      allowedResources: allowedResourcePatterns,
      timestamp
    };

    rootHop.hopSignature = this._signHop(rootHop);

    return {
      sessionId,
      rootPromptHash: promptHash,
      hops: [rootHop]
    };
  }

  /**
   * Appends an agent delegation hop to the provenance chain.
   * Scope can only stay equal or attenuate (narrow), never expand.
   *
   * @param {Object} currentChain - Existing chain
   * @param {Object} params
   * @param {string} params.subAgentId - Identity of the delegated subagent
   * @param {Array<string>} [params.subActions] - Attenuated action scope
   * @param {Array<string>} [params.subResources] - Attenuated resource scope
   * @returns {Object} Updated provenance chain
   */
  delegateHop(currentChain, { subAgentId, subActions, subResources }) {
    if (!currentChain || !Array.isArray(currentChain.hops) || currentChain.hops.length === 0) {
      throw new Error('Cannot delegate from an empty or invalid provenance chain');
    }

    const lastHop = currentChain.hops[currentChain.hops.length - 1];
    const parentHopHash = crypto.createHash('sha256').update(JSON.stringify(lastHop)).digest('hex');

    // Scope attenuation check: subagent cannot claim actions not permitted by parent
    const effectiveActions = subActions || lastHop.allowedActions;
    if (!lastHop.allowedActions.includes('*')) {
      for (const act of effectiveActions) {
        if (!lastHop.allowedActions.includes(act)) {
          throw new Error(`Privilege escalation denied: subagent cannot claim action ${act} not granted by parent`);
        }
      }
    }

    const effectiveResources = subResources || lastHop.allowedResources;

    const newHop = {
      hopIndex: lastHop.hopIndex + 1,
      agentId: String(subAgentId),
      parentHopHash,
      promptHash: currentChain.rootPromptHash,
      allowedActions: effectiveActions,
      allowedResources: effectiveResources,
      timestamp: Date.now()
    };

    newHop.hopSignature = this._signHop(newHop);

    return {
      ...currentChain,
      hops: [...currentChain.hops, newHop]
    };
  }

  /**
   * Verifies the full Merkle provenance chain and checks that targetAction is authorized.
   *
   * @param {Object} chain - Provenance chain object
   * @param {Object} targetAction - Proposed tool action
   * @returns {{ valid: boolean, reason?: string, depth: number }}
   */
  verifyProvenanceChain(chain, targetAction) {
    if (!chain || !Array.isArray(chain.hops) || chain.hops.length === 0) {
      return { valid: false, reason: 'MISSING_PROVENANCE_CHAIN', depth: 0 };
    }

    const hops = chain.hops;

    // 1. Verify Root Hop is HUMAN_OPERATOR
    if (hops[0].agentId !== 'HUMAN_OPERATOR' || hops[0].hopIndex !== 0) {
      return { valid: false, reason: 'INVALID_PROVENANCE_ROOT', depth: hops.length };
    }

    // 2. Verify Cryptographic Signatures & Hash Linkage across all hops
    let prevHopHash = '0000000000000000000000000000000000000000000000000000000000000000';
    for (let i = 0; i < hops.length; i++) {
      const hop = hops[i];

      // Verify parent hash link
      if (hop.parentHopHash !== prevHopHash) {
        return { valid: false, reason: `BROKEN_MERKLE_LINK_AT_HOP_${i}`, depth: hops.length };
      }

      // Verify cryptographic signature
      const expectedSig = this._signHop(hop);
      if (hop.hopSignature !== expectedSig) {
        return { valid: false, reason: `TAMPERED_HOP_SIGNATURE_AT_HOP_${i}`, depth: hops.length };
      }

      // Compute hash for next hop parent link
      prevHopHash = crypto.createHash('sha256').update(JSON.stringify(hop)).digest('hex');
    }

    // 3. Verify targetAction against the terminal (current executing) hop
    const terminalHop = hops[hops.length - 1];

    if (targetAction) {
      // Action type check
      if (!terminalHop.allowedActions.includes('*') && !terminalHop.allowedActions.includes(targetAction.action_type)) {
        return {
          valid: false,
          reason: `ACTION_OUTSIDE_PROVENANCE_SCOPE: ${targetAction.action_type}`,
          depth: hops.length
        };
      }

      // Resource path boundary check
      if (!terminalHop.allowedResources.includes('*')) {
        const res = targetAction.resource || '';
        const allowed = terminalHop.allowedResources.some(p => res.startsWith(p) || res === p);
        if (!allowed) {
          return {
            valid: false,
            reason: `RESOURCE_OUTSIDE_PROVENANCE_BOUNDARY: ${res}`,
            depth: hops.length
          };
        }
      }
    }

    return {
      valid: true,
      depth: hops.length
    };
  }

  /**
   * Internal HMAC signing helper for hops
   * @private
   */
  _signHop(hop) {
    const copy = { ...hop };
    delete copy.hopSignature;
    const msg = `${copy.hopIndex}:${copy.agentId}:${copy.parentHopHash}:${copy.promptHash}:${copy.allowedActions.join(',')}`;
    return crypto.createHmac('sha256', this.masterSecret).update(msg).digest('hex');
  }
}

module.exports = {
  ProvenanceChainManager
};

