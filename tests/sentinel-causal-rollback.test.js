/**
 * Sentinel Journal: Causal Time-Travel & Atomic Rollback Tests
 * ============================================================
 * Verifies transactional pre-action snapshotting and atomic reverse-chronological
 * rollback across file creation, modification, and deletion.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { CausalRollbackEngine } = require('../src/sentinel/journal/causal-rollback');
const { ACTION_FS_WRITE, ACTION_FS_DELETE } = require('../src/sentinel/constants');

describe('Sentinel Journal: Causal Time-Travel & Atomic Rollback Engine', () => {
  let tempDir;
  let engine;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-rollback-test-'));
    engine = new CausalRollbackEngine({
      workspaceRoot: tempDir,
      maxSnapshotsPerSession: 10
    });
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup best effort
    }
  });

  test('captures snapshot of existing file and restores original bytes upon rollback', () => {
    const filePath = path.join(tempDir, 'config.json');
    const originalText = '{"port": 3000, "env": "production"}';
    fs.writeFileSync(filePath, originalText);

    const action = {
      session_id: 'sess-001',
      action_type: ACTION_FS_WRITE,
      resource: 'config.json'
    };

    // 1. Capture snapshot before modification
    const snap = engine.capturePreActionSnapshot(action);
    expect(snap.existed).toBe(true);
    expect(snap.originalContent.toString('utf8')).toBe(originalText);

    // 2. Simulate agent modifying the file
    fs.writeFileSync(filePath, '{"port": 9999, "hacked": true}');
    expect(fs.readFileSync(filePath, 'utf8')).toContain('hacked');

    // 3. Rollback
    const result = engine.rollbackSession('sess-001');
    expect(result.success).toBe(true);
    expect(result.revertedCount).toBe(1);

    // File must be back to pristine original content
    expect(fs.readFileSync(filePath, 'utf8')).toBe(originalText);
  });

  test('deletes newly created files upon rollback', () => {
    const action = {
      session_id: 'sess-002',
      action_type: ACTION_FS_WRITE,
      resource: 'unwanted_agent_output.txt'
    };

    // Snapshot before file exists
    const snap = engine.capturePreActionSnapshot(action);
    expect(snap.existed).toBe(false);

    // Agent creates file
    const targetFile = path.join(tempDir, 'unwanted_agent_output.txt');
    fs.writeFileSync(targetFile, 'Malicious payload or accidental clutter');
    expect(fs.existsSync(targetFile)).toBe(true);

    // Rollback must unlink the newly created file
    const result = engine.rollbackSession('sess-002');
    expect(result.success).toBe(true);
    expect(fs.existsSync(targetFile)).toBe(false);
  });

  test('reconstitutes deleted files with identical hash upon rollback', () => {
    const importantFile = path.join(tempDir, 'database.sqlite');
    const secretData = 'CRITICAL DATABASE BYTES 12345';
    fs.writeFileSync(importantFile, secretData);

    const action = {
      session_id: 'sess-003',
      action_type: ACTION_FS_DELETE,
      resource: 'database.sqlite'
    };

    engine.capturePreActionSnapshot(action);

    // Agent deletes file
    fs.unlinkSync(importantFile);
    expect(fs.existsSync(importantFile)).toBe(false);

    // Rollback reconstitutes deleted file
    const result = engine.rollbackSession('sess-003');
    expect(result.success).toBe(true);
    expect(fs.existsSync(importantFile)).toBe(true);
    expect(fs.readFileSync(importantFile, 'utf8')).toBe(secretData);
  });

  test('reverses multi-step execution in strict reverse-chronological order (LIFO)', () => {
    // Step 1: Modify file A
    const fileA = path.join(tempDir, 'a.txt');
    fs.writeFileSync(fileA, 'initial A');
    engine.capturePreActionSnapshot({ session_id: 'sess-multi', action_type: ACTION_FS_WRITE, resource: 'a.txt' });
    fs.writeFileSync(fileA, 'modified A');

    // Step 2: Create file B
    const fileB = path.join(tempDir, 'b.txt');
    engine.capturePreActionSnapshot({ session_id: 'sess-multi', action_type: ACTION_FS_WRITE, resource: 'b.txt' });
    fs.writeFileSync(fileB, 'new B');

    // Step 3: Delete file C
    const fileC = path.join(tempDir, 'c.txt');
    fs.writeFileSync(fileC, 'initial C');
    engine.capturePreActionSnapshot({ session_id: 'sess-multi', action_type: ACTION_FS_DELETE, resource: 'c.txt' });
    fs.unlinkSync(fileC);

    expect(fs.readFileSync(fileA, 'utf8')).toBe('modified A');
    expect(fs.existsSync(fileB)).toBe(true);
    expect(fs.existsSync(fileC)).toBe(false);

    // Execute Atomic Rollback
    const result = engine.rollbackSession('sess-multi');
    expect(result.revertedCount).toBe(3);

    // All 3 files must be restored to initial state
    expect(fs.readFileSync(fileA, 'utf8')).toBe('initial A');
    expect(fs.existsSync(fileB)).toBe(false);
    expect(fs.existsSync(fileC)).toBe(true);
    expect(fs.readFileSync(fileC, 'utf8')).toBe('initial C');
  });

  test('blocks path traversal attempts escaping workspace boundary', () => {
    const action = {
      session_id: 'sess-escape',
      action_type: ACTION_FS_WRITE,
      resource: '../../etc/passwd'
    };

    expect(() => {
      engine.capturePreActionSnapshot(action);
    }).toThrow(/escapes workspace/);
  });

  test('commitSession clears snapshots after verification', () => {
    engine.capturePreActionSnapshot({
      session_id: 'sess-commit',
      action_type: ACTION_FS_WRITE,
      resource: 'test.txt'
    });

    expect(engine.getSessionHistory('sess-commit').length).toBe(1);
    engine.commitSession('sess-commit');
    expect(engine.getSessionHistory('sess-commit').length).toBe(0);
  });
});

