/**
 * VIGIL streaming rewriters — re-hydrate pseudonyms in AI responses.
 *
 * The agent firewall tokenizes protected values on the way OUT ([VIGIL-1] …).
 * When the AI's answer streams back, those tokens must become the real values
 * again BEFORE the user sees them — and a token can be split across two
 * network chunks or two SSE events (each delta is a fragment of the text),
 * so naive per-chunk replacement silently misses the splits.
 *
 * Two pure, testable rewriters, both push/flush pumps — push(chunk) returns
 * the text that is safe to emit NOW, flush() drains what was held back:
 *
 *   - createSseRewriter: text/event-stream. Buffers incomplete SSE events,
 *     rewrites ONLY inside `data:` payloads (JSON content/text fields or raw
 *     text), and carries a tail between events when it could be the start of
 *     a token completing in the next one.
 *   - createTextRewriter: any other streamed body, same carry logic.
 *
 * Holdback rule (both): after rewriting, emit everything EXCEPT the longest
 * suffix that is a proper prefix of some token — an arbitrary tail is emitted
 * immediately, a possible partial token is carried. JSON payloads that match
 * nothing keep their bytes identical.
 */
'use strict';

const DONE_LINE = /^data:\s*\[DONE\]\s*$/;

function makeMappings(list) {
  return (list || []).filter(m => m && m.token && typeof m.original === 'string');
}

function makeReplacer(mappings) {
  const pairs = mappings.map(m => [m.token, m.original]);
  return (text) => {
    let out = text;
    for (const [token, original] of pairs) out = out.split(token).join(original);
    return out;
  };
}

// Longest suffix of `text` that is a proper prefix of some token — the part
// that must NOT be emitted yet because a token may complete in the next chunk.
function longestSuffixKeep(text, tokens) {
  if (!tokens.length || !text.length) return 0;
  const max = Math.min(text.length, Math.max(...tokens.map(t => t.length)) - 1);
  for (let k = max; k >= 1; k--) {
    const suffix = text.slice(text.length - k);
    if (tokens.some(t => t.startsWith(suffix))) return k;
  }
  return 0;
}

function createSseRewriter(opts) {
  const mappings = makeMappings(opts && opts.mappings);
  const replaceAll = makeReplacer(mappings);
  const tokens = mappings.map(m => m.token);
  const maxBufferLimit = (opts && opts.maxBuffer) || (64 * 1024);
  const failClosedPolicy = (opts && opts.failClosed) || 'error-frame'; // 'error-frame' | 'throw'
  let carry = '';
  let buffer = '';
  let faulted = false;

  // Rewrite one content fragment, carrying a possible partial token
  const rewriteContent = (s) => {
    if (faulted) return '';
    const replaced = replaceAll(carry + s);
    const keep = longestSuffixKeep(replaced, tokens);
    carry = replaced.slice(replaced.length - keep);
    return replaced.slice(0, replaced.length - keep);
  };

  const transformFrame = (frame) => {
    if (!frame || faulted) return '';
    return frame.split('\n').map((line) => {
      if (!/^data:\s?/.test(line) || DONE_LINE.test(line)) return line;
      const payload = line.replace(/^data:\s?/, '');
      let obj = null;
      try { obj = JSON.parse(payload); } catch (e) { obj = null; }
      if (obj === null || typeof obj !== 'object') return 'data: ' + rewriteContent(payload);
      let changed = false;
      const walk = (node) => {
        if (Array.isArray(node)) { node.forEach(walk); return; }
        if (node && typeof node === 'object') {
          for (const key of Object.keys(node)) {
            const v = node[key];
            if ((key === 'content' || key === 'text') && typeof v === 'string') {
              const next = rewriteContent(v);
              if (next !== v) { node[key] = next; changed = true; }
            } else if (v && typeof v === 'object') {
              walk(v);
            }
          }
        }
      };
      walk(obj);
      return 'data: ' + (changed ? JSON.stringify(obj) : payload);
    }).join('\n');
  };

  return {
    push(chunk) {
      if (faulted) return '';
      buffer += String(chunk || '');
      let out = '';
      let idx;

      // Extract and transform complete frames delimited by \n\n
      while ((idx = buffer.indexOf('\n\n')) !== -1) {
        const frame = buffer.slice(0, idx + 2);
        buffer = buffer.slice(idx + 2);
        out += transformFrame(frame);
      }

      // Explicit fail-closed policy on oversized incomplete frames:
      // A single incomplete event that exceeds maxBufferLimit cannot be parsed
      // safely without unbounded buffering or slicing across secrets.
      // Therefore, fail closed: purge buffer/carry and emit error or throw.
      if (buffer.length > maxBufferLimit) {
        faulted = true;
        buffer = '';
        carry = '';
        if (failClosedPolicy === 'throw') {
          throw new RangeError(`SSE frame exceeded buffer limit of ${maxBufferLimit} bytes`);
        }
        return out + 'event: error\ndata: {"error":"FRAME_EXCEEDED_BUFFER_LIMIT","code":413}\n\n';
      }

      return out;
    },

    flush() {
      if (faulted) return '';
      let out = '';
      if (buffer.length > 0) {
        if (buffer.length > maxBufferLimit) {
          faulted = true;
          buffer = '';
          carry = '';
          if (failClosedPolicy === 'throw') {
            throw new RangeError(`SSE frame exceeded buffer limit of ${maxBufferLimit} bytes`);
          }
          return 'event: error\ndata: {"error":"FRAME_EXCEEDED_BUFFER_LIMIT","code":413}\n\n';
        }
        out = transformFrame(buffer);
        buffer = '';
      }
      out += carry;
      carry = '';
      return out;
    },

    isFaulted() {
      return faulted;
    }
  };
}

function createTextRewriter(opts) {
  const mappings = makeMappings(opts && opts.mappings);
  const replaceAll = makeReplacer(mappings);
  const tokens = mappings.map(m => m.token);
  let buffer = '';
  return {
    push(chunk) {
      buffer += String(chunk);
      const replaced = replaceAll(buffer);
      const keep = longestSuffixKeep(replaced, tokens);
      buffer = replaced.slice(replaced.length - keep);
      return replaced.slice(0, replaced.length - keep);
    },
    flush() {
      const out = replaceAll(buffer);
      buffer = '';
      return out;
    }
  };
}

module.exports = { createSseRewriter, createTextRewriter, makeReplacer, longestSuffixKeep };
