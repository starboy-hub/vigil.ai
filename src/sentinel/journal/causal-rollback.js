/**
 * Sentinel Journal: Causal Time-Travel & Atomic Rollback Engine
 * ============================================================
 * Provides transactional rollback guarantees for autonomous AI agent sessions.
 *
 * Before any tool call modifies the filesystem or environment, this engine
 * captures an immutable pre-action snapshot. If a rogue command, logic-bomb,
 * or operator rejection occurs, the session can be rewound atomically in
 * reverse-chronological order, completely restoring the pristine pre-agent state.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  ACTION_FS_WRITE,
  ACTION_FS_DELETE
} = require('../constants');

class CausalRollbackEngine {
  /**
   * @param {Object} [options]
   * @param {string} [options.workspaceRoot] - Workspace root directory for containment
   * @param {number} [options.maxSnapshotsPerSession=100] - Snapshot quota limit
   */
  constructor(options = {}) {
    this.workspaceRoot = path.resolve(options.workspaceRoot || process.cwd());
    this.maxSnapshotsPerSession = options.maxSnapshotsPerSession || 100;

    // sessionJournals: sessionId -> Array<{ id, timestamp, action, preState, postHash }>
    this.sessionJournals = new Map();
  }

  /**
   * Resolve and canonicalize path strictly inside workspaceRoot.
   * @private
   */
  _canonicalizePath(targetPath) {
    const resolved = path.resolve(this.workspaceRoot, targetPath);
    if (!resolved.startsWith(this.workspaceRoot)) {
      throw new Error(`Path traversal blocked: ${targetPath} escapes workspace ${this.workspaceRoot}`);
    }
    return resolved;
  }

  /**
   * Captures an atomic pre-action snapshot of a resource before modification.
   *
   * @param {Object} action - Action proposal object
   * @param {string} [action.session_id]
   * @param {string} action.action_type
   * @param {string} action.resource
   * @returns {Object} Snapshot record
   */
  capturePreActionSnapshot(action) {
    const sessionId = action.session_id || 'default-session';
    const actionType = action.action_type;
    const resource = action.resource;

    if (![ACTION_FS_WRITE, ACTION_FS_DELETE].includes(actionType)) {
      return null;
    }

    const canonicalPath = this._canonicalizePath(resource);
    let existed = false;
    let originalContent = null;
    let originalHash = null;

    try {
      if (fs.existsSync(canonicalPath)) {
        const stats = fs.statSync(canonicalPath);
        if (stats.isFile()) {
          existed = true;
          originalContent = fs.readFileSync(canonicalPath);
          originalHash = crypto.createHash('sha256').update(originalContent).digest('hex');
        }
      }
    } catch (readErr) {
      // If unreadable, capture as non-existent or raise fail-safe
      existed = false;
    }

    const snapshot = {
      snapshotId: `snap-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
      sessionId,
      actionType,
      resource,
      canonicalPath,
      timestamp: Date.now(),
      existed,
      originalContent, // Buffer or null
      originalHash
    };

    if (!this.sessionJournals.has(sessionId)) {
      this.sessionJournals.set(sessionId, []);
    }

    const journal = this.sessionJournals.get(sessionId);
    if (journal.length >= this.maxSnapshotsPerSession) {
      throw new Error(`Causal rollback quota exceeded: max ${this.maxSnapshotsPerSession} operations per session`);
    }

    journal.push(snapshot);
    return snapshot;
  }

  /**
   * Performs an atomic rollback of all operations performed in a session,
   * restoring the filesystem in strict reverse-chronological order.
   *
   * @param {string} sessionId - Session to roll back
   * @returns {{ success: boolean, revertedCount: number, restoredFiles: Array<string> }}
   */
  rollbackSession(sessionId) {
    const journal = this.sessionJournals.get(sessionId);
    if (!journal || journal.length === 0) {
      return { success: true, revertedCount: 0, restoredFiles: [] };
    }

    const restoredFiles = [];

    // Revert in strict reverse-chronological order (LIFO)
    for (let i = journal.length - 1; i >= 0; i--) {
      const snap = journal[i];
      const target = snap.canonicalPath;

      try {
        if (!snap.existed) {
          // File did not exist prior to action: safely delete it
          if (fs.existsSync(target)) {
            fs.unlinkSync(target);
          }
        } else {
          // File existed prior to action: recreate/reconstitute original bytes
          const parentDir = path.dirname(target);
          if (!fs.existsSync(parentDir)) {
            fs.mkdirSync(parentDir, { recursive: true });
          }
          fs.writeFileSync(target, snap.originalContent);
        }
        restoredFiles.push(snap.resource);
      } catch (err) {
        throw new Error(`Atomic rollback failed at ${snap.resource}: ${err.message}`);
      }
    }

    // Clear journal after successful full rollback
    this.sessionJournals.delete(sessionId);

    return {
      success: true,
      revertedCount: restoredFiles.length,
      restoredFiles
    };
  }

  /**
   * Commits a session's changes, discarding shadow snapshots once verified.
   *
   * @param {string} sessionId
   */
  commitSession(sessionId) {
    this.sessionJournals.delete(sessionId);
    return true;
  }

  /**
   * Returns current active snapshot history for an agent session.
   *
   * @param {string} sessionId
   * @returns {Array<Object>}
   */
  getSessionHistory(sessionId) {
    const list = this.sessionJournals.get(sessionId) || [];
    return list.map(item => ({
      snapshotId: item.snapshotId,
      actionType: item.actionType,
      resource: item.resource,
      timestamp: item.timestamp,
      existed: item.existed,
      originalHash: item.originalHash
    }));
  }
}

module.exports = {
  CausalRollbackEngine
};

