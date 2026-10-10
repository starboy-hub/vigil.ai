/**
 * Tests for the VIGIL Swarm Relay — submit/pull roundtrip, merge caps, auth
 */
const { createRelayServer, mergeSignatures, signaturesSince } = require('../relay/relay.js');
const http = require('http');

function makePersist() {
  const mem = { signatures: [] };
  return {
    mem,
    load: () => JSON.parse(JSON.stringify(mem)),
    save: (db) => { mem.signatures = db.signatures; }
  };
}

describe('relay merge logic (pure)', () => {
  test('mergeSignatures dedups by value and caps total', () => {
    const existing = [{ value: 'a' }, { value: 'b' }];
    const { merged, added } = mergeSignatures(existing, [{ value: 'b' }, { value: 'c' }], 50000);
    expect(added).toBe(1);
    expect(merged.map(s => s.value)).toEqual(['a', 'b', 'c']);
  });

  test('mergeSignatures enforces the cap', () => {
    const existing = [{ value: 'a' }];
    const incoming = Array.from({ length: 10 }, (_, i) => ({ value: 'v' + i }));
    const { merged, added } = mergeSignatures(existing, incoming, 5);
    expect(merged.length).toBe(5);
    expect(added).toBe(4);
  });

  test('signaturesSince filters by addedAt', () => {
    const sigs = [{ value: 'old', addedAt: '2026-01-01' }, { value: 'new', addedAt: '2026-06-01' }];
    expect(signaturesSince(sigs, '2026-03-01')).toEqual([{ value: 'new', addedAt: '2026-06-01' }]);
    expect(signaturesSince(sigs, '')).toHaveLength(2);
  });
});

describe('relay server (live roundtrip)', () => {
  let server, port;
  const persist = makePersist();

  beforeAll((done) => {
    server = createRelayServer({ token: '', max: 50000 }, persist);
    server.listen(0, '127.0.0.1', () => { port = server.address().port; done(); });
  });
  afterAll((done) => { server.close(done); });

  function post(path, body) {
    return new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json' } }, (res) => {
        let data = '';
        res.on('data', c => { data += c; });
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(data || '{}') }));
      });
      req.on('error', reject);
      req.end(JSON.stringify(body));
    });
  }

  function get(path) {
    return new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port, path }, (res) => {
        let data = '';
        res.on('data', c => { data += c; });
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(data || '{}') }));
      }).on('error', reject);
    });
  }

  test('submit a pack, pull it back, health reports count', async () => {
    const submit = await post('/submit', { vigilThreatPack: true, signatures: [{ value: 'hash-relay-1' }, { value: 'hash-relay-2' }] });
    expect(submit.body.ok).toBe(true);
    expect(submit.body.added).toBe(2);

    const pull = await get('/packs');
    expect(pull.body.count).toBe(2);
    expect(pull.body.signatures.some(s => s.value === 'hash-relay-1')).toBe(true);

    const health = await get('/health');
    expect(health.body.ok).toBe(true);
    expect(health.body.signatures).toBe(2);
  });

  test('rejects non-pack submissions', async () => {
    const r = await post('/submit', { hello: 'world' });
    expect(r.status).toBe(400);
  });

  test('no message text can ever enter the relay (structurally dropped)', async () => {
    await post('/submit', { vigilThreatPack: true, signatures: [{ value: 'ok-hash', message: 'please store my secret text' }] });
    const pull = await get('/packs');
    expect(JSON.stringify(pull.body)).not.toContain('please store my secret text');
  });
});
