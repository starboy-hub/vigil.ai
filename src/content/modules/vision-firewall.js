/**
 * VIGIL Vision & Canvas Injection Firewall
 * Inspects canvas elements, embedded SVG text, and visual image layers
 * for indirect prompt injections targeting web-browsing AI agents.
 */
(function (root) {
  'use strict';

  function inspectCanvasElement(canvas) {
    if (!canvas || typeof canvas.getContext !== 'function') return null;
    try {
      const ctx = canvas.getContext('2d');
      if (!ctx) return null;
      // Extract text content if drawn or accessible via accessibility ARIA
      const textAttr = canvas.getAttribute('aria-label') || canvas.getAttribute('alt') || canvas.textContent || '';
      return textAttr.trim();
    } catch (e) {
      return null;
    }
  }

  function scanVisualElements(doc = document) {
    const findings = [];
    const elements = doc.querySelectorAll('canvas, svg, img[alt], [data-vigil-vision]');
    elements.forEach(el => {
      let text = '';
      if (el.tagName === 'CANVAS') text = inspectCanvasElement(el);
      else if (el.tagName === 'SVG') text = el.textContent || '';
      else if (el.tagName === 'IMG') text = el.getAttribute('alt') || el.getAttribute('title') || '';

      if (text && text.length >= 20) {
        if (typeof VIGIL_INJECTION !== 'undefined') {
          const res = VIGIL_INJECTION.analyzeInjection(text);
          if (res && (res.level === 'suspicious' || res.level === 'dangerous')) {
            findings.push({ element: el, level: res.level, signals: res.signals, textSnippet: text.slice(0, 100) });
          }
        }
      }
    });
    return findings;
  }

  const VIGIL_VISION = {
    inspectCanvasElement,
    scanVisualElements
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_VISION;
  else root.VIGIL_VISION = VIGIL_VISION;
})(typeof self !== 'undefined' ? self : this);
