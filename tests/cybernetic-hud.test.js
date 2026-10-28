/**
 * Cybernetic Defense Matrix HUD Tests
 * ===================================
 * Verifies graph topology initialization, live telemetry event recording,
 * threat level state transitions, pulse physics, and canvas render loops.
 */

'use strict';

const {
  CyberneticHud,
  NODE_TYPES,
  THREAT_LEVELS
} = require('../src/popup/hud/cybernetic-hud');

describe('VIGIL Cybernetic Defense Matrix HUD', () => {
  let hud;

  beforeEach(() => {
    hud = new CyberneticHud({ width: 600, height: 400 });
  });

  describe('1. Defense Topology Graph Structure', () => {
    test('initializes default sovereign defense nodes and communication edges', () => {
      expect(hud.nodes.has('human')).toBe(true);
      expect(hud.nodes.has('agent')).toBe(true);
      expect(hud.nodes.has('capability')).toBe(true);
      expect(hud.nodes.has('policy')).toBe(true);
      expect(hud.nodes.has('sandbox')).toBe(true);
      expect(hud.nodes.has('canary')).toBe(true);
      expect(hud.edges.length).toBeGreaterThanOrEqual(5);
    });

    test('adds custom node and establishes edge conduit', () => {
      hud.addNode('subagent-coder', NODE_TYPES.AGENT, 250, 150);
      hud.connectNodes('agent', 'subagent-coder', 'PROVENANCE_DELEGATION');

      expect(hud.nodes.has('subagent-coder')).toBe(true);
      const edge = hud.edges.find(e => e.sourceId === 'agent' && e.targetId === 'subagent-coder');
      expect(edge).toBeDefined();
      expect(edge.channelType).toBe('PROVENANCE_DELEGATION');
    });
  });

  describe('2. Telemetry Event Stream & Threat State Machine', () => {
    test('records allowed tool execution and emits active packet pulse', () => {
      expect(hud.metrics.totalInspectedCalls).toBe(0);
      expect(hud.metrics.threatLevel).toBe(THREAT_LEVELS.NOMINAL);

      hud.recordEvent({
        type: 'TOOL_ALLOWED',
        sourceNode: 'agent',
        targetNode: 'capability',
        severity: 'INFO'
      });

      expect(hud.metrics.totalInspectedCalls).toBe(1);
      expect(hud.activePulses.length).toBe(1);
      expect(hud.metrics.threatLevel).toBe(THREAT_LEVELS.NOMINAL);
    });

    test('transitions threat level to DEFENSE_ACTIVE on deflected attacks', () => {
      hud.recordEvent({
        type: 'ATTACK_DEFLECTED',
        sourceNode: 'agent',
        targetNode: 'policy',
        severity: 'WARN'
      });

      expect(hud.metrics.deflectedAttacks).toBe(1);
      expect(hud.metrics.threatLevel).toBe(THREAT_LEVELS.DEFENSE_ACTIVE);

      const policyNode = hud.nodes.get('policy');
      expect(policyNode.pulseAlpha).toBe(1.0);
      expect(policyNode.tripped).toBe(true);
    });

    test('transitions threat level to CRITICAL_BREACH when canary tripwire triggers', () => {
      hud.recordEvent({
        type: 'CANARY_TRIPPED',
        sourceNode: 'agent',
        targetNode: 'canary',
        severity: 'CRITICAL'
      });

      expect(hud.metrics.activeCanaries).toBe(1);
      expect(hud.metrics.threatLevel).toBe(THREAT_LEVELS.CRITICAL_BREACH);
    });
  });

  describe('3. Animation Physics & Canvas Rendering', () => {
    test('update advances pulse progress and evicts completed packets', () => {
      hud.recordEvent({ type: 'TOOL_ALLOWED' });
      expect(hud.activePulses.length).toBe(1);
      expect(hud.activePulses[0].progress).toBe(0);

      // Simulate 25 frames
      for (let i = 0; i < 25; i++) {
        hud.update();
      }

      // Pulse should have reached progress >= 1.0 and been evicted
      expect(hud.activePulses.length).toBe(0);
    });

    test('renders complete HUD frame cleanly to canvas 2D context', () => {
      const mockCtx = {
        fillStyle: '',
        strokeStyle: '',
        lineWidth: 1,
        font: '',
        textAlign: '',
        fillRect: jest.fn(),
        strokeRect: jest.fn(),
        beginPath: jest.fn(),
        moveTo: jest.fn(),
        lineTo: jest.fn(),
        stroke: jest.fn(),
        arc: jest.fn(),
        fill: jest.fn(),
        fillText: jest.fn(),
        setLineDash: jest.fn()
      };

      const mockCanvas = {
        getContext: jest.fn(() => mockCtx)
      };

      hud.canvas = mockCanvas;
      hud.render();

      expect(mockCanvas.getContext).toHaveBeenCalledWith('2d');
      expect(mockCtx.fillRect).toHaveBeenCalled();
      expect(mockCtx.strokeRect).toHaveBeenCalled();
      expect(mockCtx.fillText).toHaveBeenCalled();
    });
  });
});

