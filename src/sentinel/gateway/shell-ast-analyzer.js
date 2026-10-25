/**
 * Sentinel Shell AST & De-Obfuscation Analyzer
 * Part of Vigil AI + Sentinel
 *
 * De-obfuscates shell commands before execution by unrolling quote-splitting,
 * variable substitutions, base64 decoding pipelines, and identifying dynamic
 * evaluation primitives (eval, source, process substitution).
 */
'use strict';

const { REASON_CODES } = require('../constants.js');

class ShellAstAnalyzer {
  constructor() {
    this.destructivePatterns = [
      /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+|\s+-r\s+-f\s+)?\s*(\/\s*$|\/\*|\.\s*$)/,
      /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
      /\bmkfs\.[a-z0-9]+/,
      /\bdd\s+if=\/dev\/zero/,
      /\bchmod\s+(-R\s+)?777\s+\//
    ];
  }

  /**
   * De-obfuscates and analyzes a shell command string.
   * @param {string} rawCommand
   * @returns {object} Analysis result
   */
  analyze(rawCommand) {
    if (typeof rawCommand !== 'string') {
      return { isSafe: false, reasonCode: REASON_CODES.DENY_INVALID_SCHEMA };
    }

    const trimmed = rawCommand.replace(/[\u200B-\u200D\uFEFF]/g, '').trim();
    if (!trimmed) {
      return { isSafe: true, primaryBinary: '', normalizedCommand: '' };
    }

    // 1. Variable Assignment & Substitution Unrolling
    const resolvedVars = this._resolveVariables(trimmed);

    // 2. Quote & Escape Normalization
    const normalized = this._normalizeQuotes(resolvedVars);

    // 3. Encoded Pipeline Detection (base64 pipes to shell)
    const { decodedPipelines, hasDecodedDestructive } = this._detectEncodedPipelines(resolvedVars);

    // 4. Dynamic Evaluation Detection (eval, process substitution)
    const hasDynamicEvaluation = /\beval\s+["']?/.test(resolvedVars);
    const hasProcessSubstitution = /<\s*\(/.test(resolvedVars);

    // 5. Destructive Pattern Evaluation on normalized + decoded command
    let isDestructive = false;

    // Check direct normalized command
    for (const pat of this.destructivePatterns) {
      if (pat.test(normalized) || pat.test(resolvedVars)) {
        isDestructive = true;
        break;
      }
    }

    // Check decoded payloads
    if (!isDestructive && hasDecodedDestructive) {
      isDestructive = true;
    }

    // Identify primary binary
    const tokens = normalized.split(/\s+/).filter(Boolean);
    const primaryBinary = tokens.length > 0 ? tokens[0].replace(/^.*[\\/]/, '') : '';

    if (isDestructive) {
      return {
        isSafe: false,
        isDestructive: true,
        reasonCode: REASON_CODES.DENY_UNSAFE_SHELL_COMMAND,
        explanation: 'Destructive shell command detected through AST de-obfuscation.',
        normalizedCommand: normalized,
        decodedPipelines,
        hasDynamicEvaluation,
        hasProcessSubstitution,
        primaryBinary
      };
    }

    if (hasDynamicEvaluation || hasProcessSubstitution) {
      return {
        isSafe: false,
        isDestructive: false,
        reasonCode: REASON_CODES.DENY_SHELL_OBFUSCATION,
        explanation: 'Dynamic execution primitive (eval or process substitution) rejected.',
        normalizedCommand: normalized,
        decodedPipelines,
        hasDynamicEvaluation,
        hasProcessSubstitution,
        primaryBinary
      };
    }

    return {
      isSafe: true,
      isDestructive: false,
      reasonCode: REASON_CODES.ALLOW_SAFE_COMMAND,
      normalizedCommand: normalized,
      decodedPipelines,
      hasDynamicEvaluation,
      hasProcessSubstitution,
      primaryBinary
    };
  }

  /**
   * Unrolls static shell variable assignments (e.g. CMD="rm"; $CMD -rf /)
   * @private
   */
  _resolveVariables(command) {
    const varMap = new Map();
    // Match assignments like A="foo" or A='foo' or A=foo
    const assignRegex = /(?:^|[;\s])([A-Za-z_][A-Za-z0-9_]*)=["']?([^"';\s]+)["']?(?=[;\s]|$)/g;
    let match;
    while ((match = assignRegex.exec(command)) !== null) {
      varMap.set(match[1], match[2]);
    }

    if (varMap.size === 0) return command;

    let expanded = command;
    // Replace ${VAR} and $VAR with assigned values
    for (const [key, val] of varMap.entries()) {
      const curlyPattern = new RegExp(`\\$\\{${key}\\}`, 'g');
      const standardPattern = new RegExp(`\\$${key}\\b`, 'g');
      expanded = expanded.replace(curlyPattern, val).replace(standardPattern, val);
    }

    return expanded;
  }

  /**
   * Strips split quotes and backslash escapes in command position
   * @private
   */
  _normalizeQuotes(command) {
    let result = command;

    // Handle escaped characters like \r\m -> rm
    result = result.replace(/\\([a-zA-Z0-9_\-./])/g, '$1');

    // Handle adjacent quote concatenations: 'r''m' -> rm, "r""m" -> rm
    result = result.replace(/'([a-zA-Z0-9_\-./]+)'/g, '$1');
    result = result.replace(/"([a-zA-Z0-9_\-./]+)"/g, '$1');

    return result;
  }

  /**
   * Identifies base64 encoded strings piped to sh/bash and inspects decoded payload
   * @private
   */
  _detectEncodedPipelines(command) {
    const decodedPipelines = [];
    let hasDecodedDestructive = false;

    // Matches echo <base64> | base64 -d | sh
    const b64PipeRegex = /echo\s+["']?([A-Za-z0-9+/=]{8,})["']?\s*\|\s*base64\s+(-d|--decode)\s*\|\s*(sh|bash|zsh)/g;
    let match;
    while ((match = b64PipeRegex.exec(command)) !== null) {
      try {
        const decoded = Buffer.from(match[1], 'base64').toString('utf8');
        decodedPipelines.push(decoded);
        for (const pat of this.destructivePatterns) {
          if (pat.test(decoded)) {
            hasDecodedDestructive = true;
            break;
          }
        }
      } catch {
        // Non-decodable
      }
    }

    return { decodedPipelines, hasDecodedDestructive };
  }
}

module.exports = {
  ShellAstAnalyzer
};
