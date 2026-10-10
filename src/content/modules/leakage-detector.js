/**
 * VIGIL Blueprint #11: Training Data Leakage Detector (Inbound)
 *
 * Problem: LLMs frequently regurgitate copyrighted code, GPL copyleft snippets,
 * or memorized training data without attribution, creating copyleft legal contamination
 * risk for commercial developers.
 *
 * Solution: Locality-sensitive hashing (64-bit SimHash over token shingles)
 * compares inbound model code responses against known copyleft/GPL licenses
 * and proprietary codebase fingerprints in sub-millisecond local time.
 */
(function (root) {
  'use strict';

  const DEFAULT_MAX_HAMMING_DISTANCE = 8; // <= 8 bits difference (~87.5%+ similarity)
  const MIN_TEXT_LENGTH = 50;

  // 64-bit FNV-1a hash using native BigInt
  const FNV_OFFSET_64 = 0xcbf29ce484222325n;
  const FNV_PRIME_64 = 0x100000001b3n;
  const MASK_64 = 0xffffffffffffffffn;

  function fnv1a64(str) {
    let hash = FNV_OFFSET_64;
    for (let i = 0; i < str.length; i++) {
      hash ^= BigInt(str.charCodeAt(i));
      hash = (hash * FNV_PRIME_64) & MASK_64;
    }
    return hash;
  }

  /**
   * Generates sliding window n-gram token shingles from text.
   */
  function extractShingles(text, n = 3) {
    if (!text || typeof text !== 'string') return [];
    const clean = text.toLowerCase().replace(/[^\p{L}\p{N}\s]/gu, ' ').trim();
    const tokens = clean.split(/\s+/).filter(Boolean);

    if (tokens.length < n) {
      // Fallback: character 4-grams if tokens are short
      const chars = clean.replace(/\s+/g, '');
      const charShingles = [];
      for (let i = 0; i <= chars.length - 4; i++) {
        charShingles.push(chars.slice(i, i + 4));
      }
      return charShingles.length > 0 ? charShingles : [clean];
    }

    const shingles = [];
    for (let i = 0; i <= tokens.length - n; i++) {
      shingles.push(tokens.slice(i, i + n).join(' '));
    }
    return shingles;
  }

  /**
   * Computes 64-bit SimHash over token shingles.
   * Returns BigInt.
   */
  function simhash64(text) {
    const shingles = extractShingles(text);
    if (shingles.length === 0) return 0n;

    const v = new Int32Array(64);
    for (const shingle of shingles) {
      const h = fnv1a64(shingle);
      for (let i = 0; i < 64; i++) {
        const bit = Number((h >> BigInt(i)) & 1n);
        if (bit === 1) v[i]++;
        else v[i]--;
      }
    }

    let result = 0n;
    for (let i = 0; i < 64; i++) {
      if (v[i] > 0) {
        result |= (1n << BigInt(i));
      }
    }
    return result;
  }

  function simhashToHex(hash) {
    const b = typeof hash === 'bigint' ? hash : BigInt(hash);
    return '0x' + b.toString(16).padStart(16, '0');
  }

  function hexToSimhash(hex) {
    if (typeof hex === 'bigint') return hex;
    return BigInt(hex);
  }

  /**
   * Calculates Hamming distance between two 64-bit SimHashes.
   */
  function hammingDistance(hashA, hashB) {
    const a = typeof hashA === 'bigint' ? hashA : BigInt(hashA);
    const b = typeof hashB === 'bigint' ? hashB : BigInt(hashB);
    let xor = (a ^ b) & MASK_64;
    let dist = 0;
    while (xor > 0n) {
      if ((xor & 1n) === 1n) dist++;
      xor >>= 1n;
    }
    return dist;
  }

  function calculateSimilarity(hashA, hashB) {
    const dist = hammingDistance(hashA, hashB);
    return +(1 - dist / 64).toFixed(4);
  }

  // Pre-calibrated canonical copyleft & training data fingerprints
  const DEFAULT_FINGERPRINT_CORPUS = [
    {
      id: 'gpl_v3',
      name: 'GNU General Public License (v3)',
      category: 'COPYLEFT_GPL',
      text: 'This program is free software you can redistribute it and or modify it under the terms of the GNU General Public License as published by the Free Software Foundation either version 3 of the License or at your option any later version This program is distributed in the hope that it will be useful but WITHOUT ANY WARRANTY without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE See the GNU General Public License for more details'
    },
    {
      id: 'gpl_v2',
      name: 'GNU General Public License (v2)',
      category: 'COPYLEFT_GPL',
      text: 'This program is free software you can redistribute it and or modify it under the terms of the GNU General Public License as published by the Free Software Foundation either version 2 of the License or at your option any later version This program is distributed in the hope that it will be useful but WITHOUT ANY WARRANTY without even the implied warranty of MERCHANTABILITY'
    },
    {
      id: 'agpl_v3',
      name: 'GNU Affero General Public License (v3)',
      category: 'COPYLEFT_AGPL',
      text: 'GNU Affero General Public License If you modify the Program your modified version must prominently offer all users interacting with it remotely through a computer network an opportunity to receive the Corresponding Source of your version by providing access to the Corresponding Source from a network server at no charge'
    },
    {
      id: 'linux_kernel_gpl',
      name: 'Linux Kernel Copyleft Header',
      category: 'COPYLEFT_GPL',
      text: 'SPDX-License-Identifier GPL-2.0-only WITH Linux-syscall-note This file is part of the Linux kernel You may redistribute it under the terms of the GNU General Public License version 2 as published by the Free Software Foundation'
    },
    {
      id: 'linux_spdx_gpl',
      name: 'Linux Kernel Copyleft Header',
      category: 'COPYLEFT_GPL',
      text: 'SPDX-License-Identifier GPL-2.0-only WITH Linux-syscall-note This file is part of the Linux kernel You may redistribute it under the terms of the GNU General Public License version 2'
    },
    {
      id: 'busybox_gpl',
      name: 'BusyBox Copyleft License Header',
      category: 'COPYLEFT_GPL',
      text: 'BusyBox is licensed under the GNU General Public License version 2 The full text of the license is available in the LICENSE file You may not distribute binaries without accompanying complete machine readable source code'
    },
    {
      id: 'spdx_gpl_headers',
      name: 'SPDX GPL Identifier Block',
      category: 'COPYLEFT_GPL',
      text: 'SPDX-License-Identifier GPL-3.0-or-later Copyright-year Free Software Foundation this file is part of a free software program you can redistribute and or modify it under the terms of the GNU General Public License'
    },
    {
      id: 'fsf_classic_header',
      name: 'FSF Classic Copyright Header',
      category: 'COPYLEFT_GPL',
      text: 'Copyright Free Software Foundation Inc address 51 Franklin Street Fifth Floor Boston MA USA everyone is permitted to copy and distribute verbatim copies of this license document but changing it is not allowed'
    },
    {
      id: 'mpl_mozilla',
      name: 'Mozilla Public License Notice',
      category: 'COPYLEFT_MPL',
      text: 'This Source Code Form is subject to the terms of the Mozilla Public License MPL If a copy of the MPL was not distributed with this file You can obtain one at mozilla org MPL You may obtain a copy of the License at'
    },
    {
      id: 'lgpl_library_notice',
      name: 'GNU Lesser General Public License Notice',
      category: 'COPYLEFT_LGPL',
      text: 'GNU Lesser General Public License this library is free software you can redistribute it and or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation'
    },
    {
      id: 'apache_notice_redistribution',
      name: 'Apache License Redistribution Notice',
      category: 'PERMISSIVE_NOTICE',
      text: 'Licensed under the Apache License Version you may not use this file except in compliance with the License You may obtain a copy of the License at Unless required by applicable law or agreed to in writing software distributed under the License is distributed on an AS IS BASIS'
    }
  ];

  const BUILTIN_FINGERPRINTS = DEFAULT_FINGERPRINT_CORPUS.map((fp) => ({
    id: fp.id,
    name: fp.name,
    category: fp.category,
    hash: simhash64(fp.text),
    hashHex: simhashToHex(simhash64(fp.text))
  }));

  function extractCommentBlocks(code) {
    if (!code || typeof code !== 'string') return [];
    const comments = [];
    // Block comments: /* ... */
    const blockMatches = code.match(/\/\*[\s\S]*?\*\//g);
    if (blockMatches) comments.push(...blockMatches);
    // Line comments: consecutive // or # lines
    const lines = code.split('\n');
    let currentLineComment = [];
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || (trimmed.startsWith('#') && !/^#(include|define|ifdef|ifndef|pragma|endif|elif)\b/.test(trimmed))) {
        currentLineComment.push(trimmed.replace(/^(\/\/|#+)\s*/, ''));
      } else {
        if (currentLineComment.length > 0) {
          comments.push(currentLineComment.join(' '));
          currentLineComment = [];
        }
      }
    }
    if (currentLineComment.length > 0) {
      comments.push(currentLineComment.join(' '));
    }
    return comments;
  }

  function checkSingleBlock(text, registry, maxDistance) {
    const textHash = simhash64(text);
    let bestMatch = null;
    let minDistance = 64;

    for (const fp of registry) {
      const targetHash = typeof fp.hash === 'bigint' ? fp.hash : hexToSimhash(fp.hashHex || fp.hash);
      const dist = hammingDistance(textHash, targetHash);
      if (dist < minDistance) {
        minDistance = dist;
        bestMatch = fp;
      }
    }

    const similarity = +(1 - minDistance / 64).toFixed(4);
    const isLeakage = minDistance <= maxDistance;

    return {
      isLeakage,
      matchedId: isLeakage && bestMatch ? bestMatch.id : null,
      license: isLeakage && bestMatch ? bestMatch.name : null,
      category: isLeakage && bestMatch ? bestMatch.category : null,
      distance: minDistance,
      similarity,
      hashHex: simhashToHex(textHash),
      warning: isLeakage && bestMatch
        ? `Inbound code matches ${bestMatch.name} (${(similarity * 100).toFixed(1)}% similarity). Copyleft license conditions may apply.`
        : null
    };
  }

  /**
   * Inspects inbound text or code block against registered training data & copyleft fingerprints.
   */
  function checkLeakage(text, customFingerprints = [], maxDistance = DEFAULT_MAX_HAMMING_DISTANCE) {
    if (!text || typeof text !== 'string' || text.trim().length < MIN_TEXT_LENGTH) {
      return { isLeakage: false, reason: 'text_too_short' };
    }

    const registry = [...BUILTIN_FINGERPRINTS, ...(customFingerprints || [])];

    // 1. Direct inspection of entire text
    const directResult = checkSingleBlock(text, registry, maxDistance);
    if (directResult.isLeakage) {
      return directResult;
    }

    // 2. Fallback inspection of extracted code comment blocks
    const comments = extractCommentBlocks(text);
    for (const comment of comments) {
      if (comment.length >= 35) {
        const commentResult = checkSingleBlock(comment, registry, maxDistance);
        if (commentResult.isLeakage) {
          return commentResult;
        }
      }
    }

    return directResult;
  }

  /**
   * Registers a custom code or license fingerprint.
   */
  function registerFingerprint(id, name, category, text) {
    if (!id || !name || !text) return null;
    const hash = simhash64(text);
    return {
      id,
      name,
      category: category || 'CUSTOM_CODE',
      hash,
      hashHex: simhashToHex(hash)
    };
  }

  const VIGIL_LEAKAGE = {
    simhash64,
    simhashToHex,
    hexToSimhash,
    hammingDistance,
    calculateSimilarity,
    extractShingles,
    checkLeakage,
    registerFingerprint,
    BUILTIN_FINGERPRINTS,
    DEFAULT_MAX_HAMMING_DISTANCE,
    MIN_TEXT_LENGTH
  };

  root.VIGIL_LEAKAGE = VIGIL_LEAKAGE;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = VIGIL_LEAKAGE;
  }
})(typeof self !== 'undefined' ? self : globalThis);
