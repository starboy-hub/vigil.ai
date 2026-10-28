/**
 * VIGIL Cybernetic Defense Matrix HUD
 * ===================================
 * Real-time interactive neural topology HUD visualizing:
 * 1. Active Autonomous Agents & Subagents
 * 2. Cryptographic Capability Gates
 * 3. Provenance Merkle Lineage Flows
 * 4. Real-time Threat Deflection & Canary Tripping
 * 5. Kernel Sandbox Confinement State
 */

(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VIGIL_CYBERNETIC_HUD = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Component Node Archetypes
  const NODE_TYPES = Object.freeze({
    OPERATOR: { id: 'OPERATOR', label: 'Human Operator', color: '#06B6D4' },       // Cyan
    AGENT: { id: 'AGENT', label: 'Autonomous Agent', color: '#8B5CF6' },           // Purple
    CAPABILITY: { id: 'CAPABILITY', label: 'Capability Gate', color: '#10B981' },   // Emerald
    POLICY: { id: 'POLICY', label: 'Sentinel Policy', color: '#3B82F6' },          // Blue
    SANDBOX: { id: 'SANDBOX', label: 'Kernel Sandbox', color: '#F59E0B' },         // Amber
    THREAT_SENSOR: { id: 'THREAT_SENSOR', label: 'Vision / Canary', color: '#EF4444' } // Red
  });

  const THREAT_LEVELS = Object.freeze({
    NOMINAL: 'NOMINAL',
    ELEVATED: 'ELEVATED',
    DEFENSE_ACTIVE: 'DEFENSE_ACTIVE',
    CRITICAL_BREACH: 'CRITICAL_BREACH'
  });

  class CyberneticHud {
    /**
     * @param {Object} [options]
     * @param {HTMLCanvasElement} [options.canvas] - Target HTML5 canvas
     * @param {number} [options.width=600]
     * @param {number} [options.height=400]
     */
    constructor(options = {}) {
      this.canvas = options.canvas || null;
      this.width = options.width || 600;
      this.height = options.height || 400;

      this.nodes = new Map();
      this.edges = [];
      this.activePulses = [];
      this.metrics = {
        totalInspectedCalls: 0,
        deflectedAttacks: 0,
        activeCanaries: 0,
        quarantineCount: 0,
        threatLevel: THREAT_LEVELS.NOMINAL,
        lastEventTimestamp: Date.now()
      };

      this._initDefaultTopology();
    }

    /**
     * Set up default sovereign defense topology nodes
     * @private
     */
    _initDefaultTopology() {
      this.addNode('human', NODE_TYPES.OPERATOR, 80, 200);
      this.addNode('agent', NODE_TYPES.AGENT, 200, 120);
      this.addNode('capability', NODE_TYPES.CAPABILITY, 320, 120);
      this.addNode('policy', NODE_TYPES.POLICY, 440, 200);
      this.addNode('sandbox', NODE_TYPES.SANDBOX, 520, 300);
      this.addNode('canary', NODE_TYPES.THREAT_SENSOR, 200, 300);

      this.connectNodes('human', 'agent', 'PROVENANCE_ROOT');
      this.connectNodes('agent', 'capability', 'TOKEN_CHECK');
      this.connectNodes('capability', 'policy', 'POLICY_GATE');
      this.connectNodes('policy', 'sandbox', 'EXEC_CONFINED');
      this.connectNodes('canary', 'policy', 'THREAT_TELEMETRY');
    }

    /**
     * Adds a node to the defense topology
     */
    addNode(id, type, x, y) {
      this.nodes.set(id, {
        id,
        type: type.id,
        label: type.label,
        color: type.color,
        x: x || Math.random() * (this.width - 100) + 50,
        y: y || Math.random() * (this.height - 100) + 50,
        radius: 18,
        pulseAlpha: 0,
        tripped: false
      });
      return this;
    }

    /**
     * Connects two nodes with a telemetry conduit edge
     */
    connectNodes(sourceId, targetId, channelType = 'CHANNEL') {
      if (this.nodes.has(sourceId) && this.nodes.has(targetId)) {
        this.edges.push({
          sourceId,
          targetId,
          channelType,
          activityCounter: 0
        });
      }
      return this;
    }

    /**
     * Records a live defense or tool execution event and triggers visual pulses
     *
     * @param {Object} event
     * @param {string} event.type - e.g. 'TOOL_ALLOWED', 'TOOL_BLOCKED', 'CANARY_TRIPPED'
     * @param {string} [event.sourceNode='agent']
     * @param {string} [event.targetNode='policy']
     * @param {string} [event.severity='INFO']
     */
    recordEvent(event) {
      this.metrics.totalInspectedCalls++;
      this.metrics.lastEventTimestamp = Date.now();

      const source = this.nodes.get(event.sourceNode || 'agent');
      const target = this.nodes.get(event.targetNode || 'policy');

      if (event.type === 'TOOL_BLOCKED' || event.type === 'ATTACK_DEFLECTED') {
        this.metrics.deflectedAttacks++;
        this.metrics.threatLevel = THREAT_LEVELS.DEFENSE_ACTIVE;
        if (target) {
          target.tripped = true;
          target.pulseAlpha = 1.0;
        }
      } else if (event.type === 'CANARY_TRIPPED') {
        this.metrics.activeCanaries++;
        this.metrics.threatLevel = THREAT_LEVELS.CRITICAL_BREACH;
        const canaryNode = this.nodes.get('canary');
        if (canaryNode) {
          canaryNode.tripped = true;
          canaryNode.pulseAlpha = 1.0;
        }
      }

      // Add animated packet pulse
      if (source && target) {
        this.activePulses.push({
          x: source.x,
          y: source.y,
          targetX: target.x,
          targetY: target.y,
          progress: 0,
          color: event.severity === 'CRITICAL' ? '#EF4444' : '#10B981'
        });
      }
    }

    /**
     * Advances particle animations and physics step
     */
    update() {
      // Advance pulses
      for (let i = this.activePulses.length - 1; i >= 0; i--) {
        const pulse = this.activePulses[i];
        pulse.progress += 0.05;
        if (pulse.progress >= 1.0) {
          this.activePulses.splice(i, 1);
        }
      }

      // Fade out node alert glows
      this.nodes.forEach(node => {
        if (node.pulseAlpha > 0) {
          node.pulseAlpha = Math.max(0, node.pulseAlpha - 0.02);
        }
      });
    }

    /**
     * Renders HUD topology frame to canvas context
     */
    render() {
      if (!this.canvas || typeof this.canvas.getContext !== 'function') return;
      const ctx = this.canvas.getContext('2d');
      if (!ctx) return;

      // 1. Cybernetic Dark Grid Background
      ctx.fillStyle = '#0B0F19';
      ctx.fillRect(0, 0, this.width, this.height);

      // Grid lines
      ctx.strokeStyle = 'rgba(30, 41, 59, 0.4)';
      ctx.lineWidth = 1;
      for (let x = 0; x < this.width; x += 40) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, this.height);
        ctx.stroke();
      }
      for (let y = 0; y < this.height; y += 40) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(this.width, y);
        ctx.stroke();
      }

      // 2. Render Conduit Edges
      this.edges.forEach(edge => {
        const src = this.nodes.get(edge.sourceId);
        const tgt = this.nodes.get(edge.targetId);
        if (!src || !tgt) return;

        ctx.strokeStyle = 'rgba(71, 85, 105, 0.6)';
        ctx.lineWidth = 2;
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.stroke();
        ctx.setLineDash([]);
      });

      // 3. Render In-Flight Event Pulses
      this.activePulses.forEach(pulse => {
        const curX = pulse.x + (pulse.targetX - pulse.x) * pulse.progress;
        const curY = pulse.y + (pulse.targetY - pulse.y) * pulse.progress;

        ctx.fillStyle = pulse.color;
        ctx.beginPath();
        ctx.arc(curX, curY, 4, 0, Math.PI * 2);
        ctx.fill();
      });

      // 4. Render Nodes
      this.nodes.forEach(node => {
        // Glowing Aura on Alert
        if (node.pulseAlpha > 0) {
          ctx.fillStyle = `rgba(239, 68, 68, ${node.pulseAlpha * 0.4})`;
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 12, 0, Math.PI * 2);
          ctx.fill();
        }

        // Main Node Circle
        ctx.fillStyle = node.color;
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fill();

        ctx.strokeStyle = '#FFFFFF';
        ctx.lineWidth = 2;
        ctx.stroke();

        // Node Label
        ctx.fillStyle = '#E2E8F0';
        ctx.font = '11px monospace';
        ctx.textAlign = 'center';
        ctx.fillText(node.label, node.x, node.y + node.radius + 14);
      });

      // 5. Telemetry Status Bar
      ctx.fillStyle = 'rgba(15, 23, 42, 0.85)';
      ctx.fillRect(10, 10, 240, 75);
      ctx.strokeStyle = 'rgba(51, 65, 85, 0.8)';
      ctx.strokeRect(10, 10, 240, 75);

      ctx.font = 'bold 11px monospace';
      ctx.fillStyle = this.metrics.threatLevel === THREAT_LEVELS.NOMINAL ? '#10B981' : '#EF4444';
      ctx.textAlign = 'left';
      ctx.fillText(`STATUS: ${this.metrics.threatLevel}`, 20, 28);

      ctx.font = '10px monospace';
      ctx.fillStyle = '#94A3B8';
      ctx.fillText(`INSPECTED: ${this.metrics.totalInspectedCalls}`, 20, 44);
      ctx.fillText(`DEFLECTED: ${this.metrics.deflectedAttacks}`, 20, 58);
      ctx.fillText(`CANARIES ACTIVE: ${this.metrics.activeCanaries}`, 20, 72);
    }
  }

  return {
    CyberneticHud,
    NODE_TYPES,
    THREAT_LEVELS
  };
}));

