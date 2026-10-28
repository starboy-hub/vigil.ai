/**
 * Sentinel Swarm Security: Provenance Chain Tests
 * ===============================================
 * Verifies Merkle Proof-of-Human-Origin across multi-agent handoffs,
 * privilege attenuation, broken lineage detection, and boundary enforcement.
 */

'use strict';

const { ProvenanceChainManager } = require('../src/sentinel/credentials/provenance-chain');

describe('Sentinel Swarm Security: Cryptographic Multi-Agent Provenance Chain', () => {
  let manager;

  beforeEach(() => {
    manager = new ProvenanceChainManager({
      masterSecret: 'test-provenance-master-key-2026'
    });
  });

  describe('1. Root Anchoring to Human Operator', () => {
    test('creates valid human-anchored root provenance hop', () => {
      const root = manager.createRootProvenance({
        humanPrompt: 'Fix bug in calculateTax and run tests',
        sessionId: 'session-xyz',
        allowedRootActions: ['fs:read', 'fs:write', 'shell:exec'],
        allowedResourcePatterns: ['src/', 'tests/']
      });

      expect(root.sessionId).toBe('session-xyz');
      expect(root.hops.length).toBe(1);
      expect(root.hops[0].agentId).toBe('HUMAN_OPERATOR');
      expect(root.hops[0].hopIndex).toBe(0);
      expect(root.hops[0].hopSignature).toBeDefined();

      const verify = manager.verifyProvenanceChain(root);
      expect(verify.valid).toBe(true);
      expect(verify.depth).toBe(1);
    });
  });

  describe('2. Multi-Agent Delegation & Attenuation', () => {
    test('verifies unbroken 3-agent delegation pipeline (Human -> Orchestrator -> Coder -> TestRunner)', () => {
      const root = manager.createRootProvenance({
        humanPrompt: 'Implement feature and test',
        sessionId: 'session-chain',
        allowedRootActions: ['fs:read', 'fs:write', 'shell:exec'],
        allowedResourcePatterns: ['src/', 'tests/']
      });

      // Hop 1: Delegate to Orchestrator Agent
      const chain1 = manager.delegateHop(root, {
        subAgentId: 'agent-orchestrator'
      });

      // Hop 2: Delegate to Coder Agent (Attenuated: only write to src/)
      const chain2 = manager.delegateHop(chain1, {
        subAgentId: 'agent-coder',
        subActions: ['fs:read', 'fs:write'],
        subResources: ['src/']
      });

      // Hop 3: Delegate to TestRunner Agent (Attenuated: only read src/ and exec tests)
      const chain3 = manager.delegateHop(chain2, {
        subAgentId: 'agent-test-runner',
        subActions: ['fs:read'],
        subResources: ['src/']
      });

      expect(chain3.hops.length).toBe(4);

      // Valid tool call in terminal scope
      const validAction = {
        action_type: 'fs:read',
        resource: 'src/utils.js'
      };

      const verify = manager.verifyProvenanceChain(chain3, validAction);
      expect(verify.valid).toBe(true);
      expect(verify.depth).toBe(4);
    });

    test('denies privilege escalation when subagent attempts to expand scope', () => {
      const root = manager.createRootProvenance({
        humanPrompt: 'Read documentation only',
        sessionId: 'session-escalation',
        allowedRootActions: ['fs:read'],
        allowedResourcePatterns: ['docs/']
      });

      // Subagent tries to grant itself shell:exec permission
      expect(() => {
        manager.delegateHop(root, {
          subAgentId: 'sub-agent-rogue',
          subActions: ['fs:read', 'shell:exec']
        });
      }).toThrow(/Privilege escalation denied/);
    });
  });

  describe('3. Tamper & Lineage Break Detection', () => {
    test('detects broken Merkle link when intermediate hop is altered', () => {
      const root = manager.createRootProvenance({
        humanPrompt: 'Safe task',
        sessionId: 'session-tamper',
        allowedRootActions: ['*']
      });

      const chain = manager.delegateHop(root, { subAgentId: 'agent-1' });

      // Tamper with parent hop hash
      chain.hops[1].parentHopHash = '1111111111111111111111111111111111111111111111111111111111111111';

      const verify = manager.verifyProvenanceChain(chain);
      expect(verify.valid).toBe(false);
      expect(verify.reason).toContain('BROKEN_MERKLE_LINK');
    });

    test('detects tampered signature in hop credentials', () => {
      const root = manager.createRootProvenance({
        humanPrompt: 'Safe task',
        sessionId: 'session-tamper-sig',
        allowedRootActions: ['*']
      });

      root.hops[0].allowedActions = ['fs:read', 'shell:exec']; // Tampered allowed actions

      const verify = manager.verifyProvenanceChain(root);
      expect(verify.valid).toBe(false);
      expect(verify.reason).toContain('TAMPERED_HOP_SIGNATURE');
    });

    test('denies action that exceeds terminal resource boundary', () => {
      const root = manager.createRootProvenance({
        humanPrompt: 'Edit src only',
        sessionId: 'session-boundary',
        allowedRootActions: ['fs:write'],
        allowedResourcePatterns: ['src/']
      });

      const chain = manager.delegateHop(root, {
        subAgentId: 'agent-writer',
        subActions: ['fs:write'],
        subResources: ['src/']
      });

      // Target action tries to write to outside directory
      const outOfBoundsAction = {
        action_type: 'fs:write',
        resource: 'package.json'
      };

      const verify = manager.verifyProvenanceChain(chain, outOfBoundsAction);
      expect(verify.valid).toBe(false);
      expect(verify.reason).toContain('RESOURCE_OUTSIDE_PROVENANCE_BOUNDARY');
    });
  });
});

