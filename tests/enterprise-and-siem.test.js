const VIGIL_SIEM = require('../src/shared/siem-exporter');
const VIGIL_ENTERPRISE = require('../src/background/enterprise-policy');

describe('VIGIL Enterprise SIEM & Policy Engine', () => {
  const sampleHistory = [
    { timestamp: '2026-10-03T20:00:00.000Z', site: 'example.com', summary: 'Outbound PII (Email)', count: 2, severity: 'high' },
    { timestamp: '2026-10-03T21:00:00.000Z', site: 'test.org', summary: 'AWS Secret Key Detected', count: 1, severity: 'critical' }
  ];

  test('formatCEF generates valid Common Event Format telemetry lines', () => {
    const cef = VIGIL_SIEM.formatCEF(sampleHistory);
    expect(cef).toContain('CEF:0|VIGIL|VIGIL-Enterprise|11.0.0|ALERT-1|Outbound PII (Email)|6|');
    expect(cef).toContain('CEF:0|VIGIL|VIGIL-Enterprise|11.0.0|ALERT-2|AWS Secret Key Detected|8|');
    expect(cef).toContain('dhost=example.com');
  });

  test('formatOCSF generates valid OCSF v1.1.0 data security objects', () => {
    const ocsf = VIGIL_SIEM.formatOCSF(sampleHistory);
    expect(ocsf).toHaveLength(2);
    expect(ocsf[0].class_uid).toBe(3002);
    expect(ocsf[0].metadata.product.name).toBe('VIGIL Enterprise Guardian');
    expect(ocsf[1].unmapped_data.domain).toBe('test.org');
  });

  test('formatJSON exports standard SIEM JSON envelope', () => {
    const json = VIGIL_SIEM.formatJSON(sampleHistory);
    expect(json.schema).toBe('VIGIL_ENTERPRISE_SIEM_v1');
    expect(json.total_events).toBe(2);
    expect(json.events[0].domain).toBe('example.com');
  });

  test('VIGIL_ENTERPRISE loads policy safely', async () => {
    const policy = await VIGIL_ENTERPRISE.loadManagedPolicy();
    expect(policy).toBeNull();
  });
});
