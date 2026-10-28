/**
 * VIGIL Vision & Canvas Injection Firewall
 * ========================================
 * Multimodal visual security layer protecting browser-based AI agents
 * (e.g., Computer-Use agents, multimodal vision models) against:
 * 1. Indirect prompt injection embedded in HTML5 Canvas, SVG, or images
 * 2. Invisible/camouflaged visual text (microscopic, zero-contrast, off-screen)
 * 3. Accidental capture and exfiltration of sensitive PII/secrets via canvas screenshots
 * 4. Screen-capture frame surveillance via canvas export interception
 */

(function (root, factory) {
  'use strict';
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    const exports = factory();
    root.VIGIL_VISION = exports;
    root.VIGIL_VISION_FIREWALL = exports;
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Suspicious visual prompt injection patterns
  const INJECTION_PATTERNS = [
    /\b(?:ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?)\b/i,
    /\b(?:system\s+prompt\s*:)\b/i,
    /\b(?:you\s+are\s+now\s+in\s+developer\s+mode)\b/i,
    /\b(?:disregard\s+(?:all\s+)?safety\s+guidelines)\b/i,
    /\b(?:override\s+system\s+instructions?)\b/i,
    /\b(?:send\s+(?:all\s+)?cookies\s+to\b)/i,
    /\b(?:curl\s+https?:\/\/[\w.-]+)/i,
    /\b(?:eval\s*\(|new\s+Function\s*\()/i,
    /\b(?:exfiltrate\s+sensitive\s+data)\b/i
  ];

  // Sensitive PII / Credential patterns
  const SENSITIVE_PATTERNS = [
    { type: 'API_KEY', regex: /\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{30,}|AKIA[0-9A-Z]{16})\b/ },
    { type: 'CREDIT_CARD', regex: /\b(?:\d{4}[ -]?){3}\d{4}\b/ },
    { type: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/ },
    { type: 'PRIVATE_KEY', regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/ }
  ];

  /**
   * Parse numeric font size in pixels from canvas font string (e.g. "bold 2px sans-serif")
   */
  function parseFontSizePx(fontStr) {
    if (!fontStr || typeof fontStr !== 'string') return 16;
    const match = fontStr.match(/(\d+(?:\.\d+)?)\s*(px|pt|em|rem)?/i);
    if (!match) return 16;
    const val = parseFloat(match[1]);
    const unit = (match[2] || 'px').toLowerCase();
    if (unit === 'pt') return val * 1.333;
    if (unit === 'em' || unit === 'rem') return val * 16;
    return val;
  }

  /**
   * Determine if drawn text font is microscopically small (< 4px)
   */
  function isMicroscopicFont(fontStr) {
    const size = parseFontSizePx(fontStr);
    return size > 0 && size < 4;
  }

  /**
   * Check if drawing coordinates place text entirely off-screen relative to canvas dimensions
   */
  function isOffscreenDraw(x, y, canvasWidth, canvasHeight) {
    if (x < -100 || y < -100) return true;
    if (canvasWidth > 0 && x > canvasWidth + 100) return true;
    if (canvasHeight > 0 && y > canvasHeight + 100) return true;
    return false;
  }

  /**
   * Parse RGB/RGBA or Hex color into { r, g, b, a }
   */
  function parseColor(colorStr) {
    if (!colorStr || typeof colorStr !== 'string') return { r: 0, g: 0, b: 0, a: 1 };
    const str = colorStr.trim().toLowerCase();

    if (str.startsWith('#')) {
      const hex = str.slice(1);
      if (hex.length === 3) {
        return {
          r: parseInt(hex[0] + hex[0], 16),
          g: parseInt(hex[1] + hex[1], 16),
          b: parseInt(hex[2] + hex[2], 16),
          a: 1
        };
      }
      if (hex.length === 6) {
        return {
          r: parseInt(hex.slice(0, 2), 16),
          g: parseInt(hex.slice(2, 4), 16),
          b: parseInt(hex.slice(4, 6), 16),
          a: 1
        };
      }
    }

    const rgbaMatch = str.match(/rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*([\d.]+))?\s*\)/);
    if (rgbaMatch) {
      return {
        r: parseInt(rgbaMatch[1], 10),
        g: parseInt(rgbaMatch[2], 10),
        b: parseInt(rgbaMatch[3], 10),
        a: rgbaMatch[4] !== undefined ? parseFloat(rgbaMatch[4]) : 1
      };
    }

    return { r: 0, g: 0, b: 0, a: 1 };
  }

  /**
   * Calculate relative luminance delta between two colors
   */
  function isLowContrast(textColorStr, bgColorStr) {
    const fg = parseColor(textColorStr);
    const bg = parseColor(bgColorStr || '#ffffff');

    // Transparent or nearly transparent text
    if (fg.a < 0.08) return true;

    // Euclidean distance in RGB color space
    const delta = Math.sqrt(
      Math.pow(fg.r - bg.r, 2) +
      Math.pow(fg.g - bg.g, 2) +
      Math.pow(fg.b - bg.b, 2)
    );

    return delta < 15; // Indistinguishable to human eye, but readable by OCR/vision models
  }

  /**
   * Analyze text for visual prompt injections
   */
  function analyzeTextInjection(text) {
    if (!text || typeof text !== 'string') return { isInjection: false, matchedPatterns: [] };
    const matches = [];
    for (const pat of INJECTION_PATTERNS) {
      if (pat.test(text)) {
        matches.push(pat.source);
      }
    }
    return {
      isInjection: matches.length > 0,
      matchedPatterns: matches
    };
  }

  /**
   * Check text for sensitive credentials and PII
   */
  function detectSensitiveData(text) {
    if (!text || typeof text !== 'string') return { hasSensitiveData: false, findings: [] };
    const findings = [];
    for (const pat of SENSITIVE_PATTERNS) {
      if (pat.regex.test(text)) {
        findings.push(pat.type);
      }
    }
    return {
      hasSensitiveData: findings.length > 0,
      findings
    };
  }

  /**
   * Inspect a single canvas element for static accessibility anomalies or size tricks
   */
  function inspectCanvasElement(canvas) {
    if (!canvas) return null;
    try {
      const ariaText = canvas.getAttribute('aria-label') || canvas.getAttribute('alt') || canvas.textContent || '';
      const width = canvas.width || 0;
      const height = canvas.height || 0;

      const isMicro = width > 0 && height > 0 && (width < 32 || height < 32);
      const isExtremeAspect = width > 0 && height > 0 && ((width / height > 15) || (height / width > 15));

      const injectionCheck = analyzeTextInjection(ariaText);
      const sensitiveCheck = detectSensitiveData(ariaText);

      const hasViolation = isMicro || isExtremeAspect || injectionCheck.isInjection || sensitiveCheck.hasSensitiveData;

      return {
        hasVisualInjection: hasViolation,
        isMicro,
        isExtremeAspect,
        injectionDetected: injectionCheck.isInjection,
        sensitiveDetected: sensitiveCheck.hasSensitiveData,
        textSnippet: ariaText.slice(0, 100),
        reason: isMicro
          ? 'Concealed micro-graphic canvas layer'
          : isExtremeAspect
          ? 'Extreme aspect-ratio hidden visual layer'
          : injectionCheck.isInjection
          ? 'Prompt injection in canvas accessibility metadata'
          : sensitiveCheck.hasSensitiveData
          ? 'Sensitive credential pattern detected in canvas metadata'
          : 'Clean canvas'
      };
    } catch {
      return null;
    }
  }

  /**
   * Redact sensitive regions on a canvas by drawing an opaque privacy box over them
   *
   * @param {HTMLCanvasElement} canvas
   * @param {Array<{ x: number, y: number, width: number, height: number, label?: string }>} regions
   * @param {string} [fillColor='#111827']
   */
  function redactBoundingBoxes(canvas, regions = [], fillColor = '#111827') {
    if (!canvas || !canvas.getContext || !Array.isArray(regions) || regions.length === 0) {
      return false;
    }
    const ctx = canvas.getContext('2d');
    if (!ctx) return false;

    ctx.save();
    for (const box of regions) {
      const { x, y, width, height, label } = box;
      if (width <= 0 || height <= 0) continue;

      ctx.fillStyle = fillColor;
      ctx.fillRect(x, y, width, height);

      // Add clean redaction label if room exists
      if (width >= 40 && height >= 12) {
        ctx.fillStyle = '#EF4444';
        ctx.font = '10px monospace';
        ctx.fillText(`[REDACTED: ${label || 'PII'}]`, x + 4, y + Math.min(height - 4, 12));
      }
    }
    ctx.restore();
    return true;
  }

  /**
   * Scan visual elements across a document
   */
  function scanVisualElements(doc = (typeof document !== 'undefined' ? document : null)) {
    if (!doc || typeof doc.querySelectorAll !== 'function') return [];
    const findings = [];
    const elements = doc.querySelectorAll('canvas, svg, img[alt], [data-vigil-vision]');

    elements.forEach(el => {
      let text = '';
      if (el.tagName === 'CANVAS') {
        const report = inspectCanvasElement(el);
        if (report && report.hasVisualInjection) {
          findings.push({
            element: el,
            level: 'dangerous',
            reason: report.reason,
            textSnippet: report.textSnippet
          });
        }
        return;
      } else if (el.tagName === 'SVG') {
        text = el.textContent || '';
      } else if (el.tagName === 'IMG') {
        text = el.getAttribute('alt') || el.getAttribute('title') || '';
      }

      if (text && text.length >= 10) {
        const inj = analyzeTextInjection(text);
        if (inj.isInjection) {
          findings.push({
            element: el,
            level: 'dangerous',
            reason: 'Visual prompt injection in image/SVG metadata',
            signals: inj.matchedPatterns,
            textSnippet: text.slice(0, 100)
          });
        }
      }
    });

    return findings;
  }

  /**
   * Active Firewall: Hooks HTML5 Canvas context and export methods
   * to catch real-time visual injections and prevent screen-capture exfiltration.
   */
  class VisionFirewall {
    constructor(options = {}) {
      this.redactSensitive = options.redactSensitive !== false;
      this.blockInjections = options.blockInjections !== false;
      this.onViolation = typeof options.onViolation === 'function' ? options.onViolation : null;
      this.activeHooks = false;
      this._originalMethods = {};
      this.detectedEvents = [];
    }

    /**
     * Install canvas rendering and export hooks on the target global environment
     */
    install(globalEnv = (typeof window !== 'undefined' ? window : (typeof global !== 'undefined' ? global : null))) {
      if (!globalEnv || this.activeHooks) return;

      const CanvasProto = globalEnv.HTMLCanvasElement && globalEnv.HTMLCanvasElement.prototype;
      const CtxProto = (globalEnv.CanvasRenderingContext2D && globalEnv.CanvasRenderingContext2D.prototype) ||
                       (globalEnv.CanvasRenderingContext2D_Mock && globalEnv.CanvasRenderingContext2D_Mock.prototype);

      if (!CanvasProto && !CtxProto) return;

      const self = this;

      // 1. Hook CanvasRenderingContext2D text methods
      if (CtxProto) {
        if (CtxProto.fillText && !this._originalMethods.fillText) {
          this._originalMethods.fillText = CtxProto.fillText;
          CtxProto.fillText = function (text, x, y, maxWidth) {
            const canvas = this.canvas;
            const strText = String(text || '');

            // Check for microscopic font
            if (isMicroscopicFont(this.font)) {
              self._recordViolation(canvas, 'MICROSCOPIC_TEXT', `Concealed microscopic text drawn: "${strText.slice(0, 50)}"`);
            }

            // Check for off-screen draw
            if (canvas && isOffscreenDraw(x, y, canvas.width, canvas.height)) {
              self._recordViolation(canvas, 'OFFSCREEN_TEXT', `Off-screen text drawn at (${x}, ${y}): "${strText.slice(0, 50)}"`);
            }

            // Check for prompt injection
            const inj = analyzeTextInjection(strText);
            if (inj.isInjection) {
              self._recordViolation(canvas, 'PROMPT_INJECTION', `Visual prompt injection drawn: "${strText.slice(0, 50)}"`);
              if (self.blockInjections) {
                // Drop text rendering to neutralize visual injection attack
                return;
              }
            }

            // Check for sensitive credential data
            const sens = detectSensitiveData(strText);
            if (sens.hasSensitiveData) {
              self._recordViolation(canvas, 'SENSITIVE_DATA', `Sensitive ${sens.findings.join(', ')} drawn on canvas`);
            }

            return self._originalMethods.fillText.apply(this, arguments);
          };
        }

        if (CtxProto.strokeText && !this._originalMethods.strokeText) {
          this._originalMethods.strokeText = CtxProto.strokeText;
          CtxProto.strokeText = function (text, _x, _y, _maxWidth) {
            const canvas = this.canvas;
            const strText = String(text || '');
            const inj = analyzeTextInjection(strText);
            if (inj.isInjection) {
              self._recordViolation(canvas, 'PROMPT_INJECTION', `Visual strokeText injection: "${strText.slice(0, 50)}"`);
              if (self.blockInjections) return;
            }
            return self._originalMethods.strokeText.apply(this, arguments);
          };
        }
      }

      // 2. Hook Canvas export methods to sanitize / redact before export
      if (CanvasProto) {
        if (CanvasProto.toDataURL && !this._originalMethods.toDataURL) {
          this._originalMethods.toDataURL = CanvasProto.toDataURL;
          CanvasProto.toDataURL = function () {
            if (this._vigilHasInjection && self.blockInjections) {
              // Return sanitized blank 1x1 png if canvas is flagged for active injection
              return 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAA';
            }
            return self._originalMethods.toDataURL.apply(this, arguments);
          };
        }
      }

      this.activeHooks = true;
    }

    /**
     * Restore original unhooked prototype methods
     */
    uninstall(globalEnv = (typeof window !== 'undefined' ? window : (typeof global !== 'undefined' ? global : null))) {
      if (!globalEnv || !this.activeHooks) return;

      const CanvasProto = globalEnv.HTMLCanvasElement && globalEnv.HTMLCanvasElement.prototype;
      const CtxProto = (globalEnv.CanvasRenderingContext2D && globalEnv.CanvasRenderingContext2D.prototype) ||
                       (globalEnv.CanvasRenderingContext2D_Mock && globalEnv.CanvasRenderingContext2D_Mock.prototype);

      if (CtxProto) {
        if (this._originalMethods.fillText) {
          CtxProto.fillText = this._originalMethods.fillText;
        }
        if (this._originalMethods.strokeText) {
          CtxProto.strokeText = this._originalMethods.strokeText;
        }
      }

      if (CanvasProto) {
        if (this._originalMethods.toDataURL) {
          CanvasProto.toDataURL = this._originalMethods.toDataURL;
        }
      }

      this._originalMethods = {};
      this.activeHooks = false;
    }

    /**
     * Internal violation recorder
     * @private
     */
    _recordViolation(canvas, type, message) {
      if (canvas) {
        canvas._vigilHasInjection = true;
        canvas._vigilViolationType = type;
      }
      const event = {
        type,
        message,
        timestamp: Date.now()
      };
      this.detectedEvents.push(event);
      if (this.onViolation) {
        this.onViolation(event);
      }
    }
  }

  return {
    parseFontSizePx,
    isMicroscopicFont,
    isOffscreenDraw,
    isLowContrast,
    analyzeTextInjection,
    detectSensitiveData,
    inspectCanvasElement,
    redactBoundingBoxes,
    scanVisualElements,
    VisionFirewall
  };
}));
