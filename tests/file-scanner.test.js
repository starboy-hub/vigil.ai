/**
 * @jest-environment jsdom
 */

const { isTextFile, scanFileForLeaks } = require('../src/content/modules/rag-file-scanner.js');

describe('VIGIL RAG Document & File Scanner Module', () => {
  test('isTextFile identifies code, data, and markup files correctly', () => {
    expect(isTextFile({ name: 'document.txt', type: 'text/plain' })).toBe(true);
    expect(isTextFile({ name: 'export.csv', type: 'text/csv' })).toBe(true);
    expect(isTextFile({ name: 'config.json', type: 'application/json' })).toBe(true);
    expect(isTextFile({ name: 'script.py', type: '' })).toBe(true);
    expect(isTextFile({ name: 'archive.zip', type: 'application/zip' })).toBe(false);
    expect(isTextFile({ name: 'image.png', type: 'image/png' })).toBe(false);
  });

  test('scanFileForLeaks flags files containing AWS key or developer secret', async () => {
    const mockFile = {
      name: 'credentials.txt',
      type: 'text/plain',
      slice: () => new Blob(['AWS_ACCESS_KEY_ID=FAKE_AWS_KEY\nSECRET=FAKE_GITHUB_TOKEN'])
    };

    const mockSecretsEngine = {
      scanSecrets: (text) => {
        const hits = [];
        if (text.includes('AKIA') || text.includes('FAKE_AWS_KEY')) hits.push({ type: 'AWS Access Key ID' });
        if (text.includes('ghp_') || text.includes('FAKE_GITHUB_TOKEN')) hits.push({ type: 'GitHub Personal Access Token' });
        return hits;
      }
    };

    const mockFakeEngine = { FAKE_DATA: {} };

    const result = await scanFileForLeaks(mockFile, mockSecretsEngine, mockFakeEngine);
    expect(result.file).toBe('credentials.txt');
    expect(result.hasLeak).toBe(true);
    expect(result.secretsCount).toBe(2);
    expect(result.secretsTypes).toContain('AWS Access Key ID');
  });

  test('scanFileForLeaks returns clean result for non-sensitive text file', async () => {
    const mockFile = {
      name: 'notes.txt',
      type: 'text/plain',
      slice: () => new Blob(['Just a regular meeting notes file without any secrets.'])
    };

    const mockSecretsEngine = { scanSecrets: () => [] };
    const mockFakeEngine = { FAKE_DATA: {} };

    const result = await scanFileForLeaks(mockFile, mockSecretsEngine, mockFakeEngine);
    expect(result.file).toBe('notes.txt');
    expect(result.hasLeak).toBe(false);
    expect(result.secretsCount).toBe(0);
  });
});
