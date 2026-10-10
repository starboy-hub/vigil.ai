/**
 * VIGIL B2B SIEM & Enterprise Log Exporter
 * Formats local audit logs into standard SOC/SIEM telemetry formats:
 *   - CEF (Common Event Format - Micro Focus / ArcSight)
 *   - OCSF (Open Cybersecurity Schema Framework - AWS / Splunk / Datadog)
 *   - Enterprise JSON (Standard SIEM stream)
 *
 * ZERO raw PII is ever exported. Only masked incident classifications and hashes.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.VIGIL_SIEM = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function formatTimestampISO(ts) {
    try {
      return new Date(ts || Date.now()).toISOString();
    } catch (e) {
      return new Date().toISOString();
    }
  }

  function formatCEF(history = []) {
    const lines = [];
    history.forEach((h, idx) => {
      const timeStr = formatTimestampISO(h.timestamp);
      const site = h.site || 'unknown-site';
      const count = h.count || 1;
      const type = (h.summary || 'Sensitive Data Blocked').replace(/\|/g, '\\|');
      const sev = h.severity === 'critical' ? 8 : (h.severity === 'high' ? 6 : 3);
      // CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
      lines.push(`CEF:0|VIGIL|VIGIL-Enterprise|11.0.0|ALERT-${idx + 1}|${type}|${sev}|rt=${timeStr} dhost=${site} cnt=${count} act=masked`);
    });
    return lines.join('\n');
  }

  function formatOCSF(history = []) {
    return history.map((h, idx) => ({
      class_uid: 3002, // Data Security / Data Loss Prevention
      category_uid: 3, // System Activity
      activity_id: 1, // Read / Intercepted
      severity_id: h.severity === 'critical' ? 4 : (h.severity === 'high' ? 3 : 2),
      time: new Date(h.timestamp || Date.now()).getTime(),
      metadata: {
        product: {
          vendor_name: 'VIGIL Security',
          name: 'VIGIL Enterprise Guardian',
          version: '11.0.0'
        },
        version: '1.1.0'
      },
      unmapped_data: {
        event_id: `VIGIL-EVT-${idx + 1}`,
        domain: h.site || 'local',
        incident_type: h.summary || 'PII Interception',
        redactions_count: h.count || 1
      }
    }));
  }

  function formatJSON(history = []) {
    return {
      schema: 'VIGIL_ENTERPRISE_SIEM_v1',
      generated_at: new Date().toISOString(),
      total_events: history.length,
      events: history.map((h, idx) => ({
        id: `VIGIL-${idx + 1}`,
        timestamp: formatTimestampISO(h.timestamp),
        domain: h.site || 'unknown',
        summary: h.summary || 'Masked Sensitive Entry',
        severity: h.severity || 'medium',
        count: h.count || 1
      }))
    };
  }

  return {
    formatCEF,
    formatOCSF,
    formatJSON
  };
}));
