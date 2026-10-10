const VIGIL_LEAKAGE = require('../src/content/modules/leakage-detector.js');

describe('Blueprint #11: Training Data Leakage Detector (Inbound)', () => {
  describe('1. 64-Bit SimHash & Token Shingling', () => {
    test('extractShingles generates overlapping n-grams', () => {
      const text = 'The quick brown fox jumps over the lazy dog';
      const shingles = VIGIL_LEAKAGE.extractShingles(text, 3);
      expect(shingles.length).toBeGreaterThan(0);
      expect(shingles[0]).toBe('the quick brown');
      expect(shingles[1]).toBe('quick brown fox');
    });

    test('simhash64 computes deterministic 64-bit BigInt fingerprint', () => {
      const text = 'Standard copyleft licensing terms and conditions for open source software distribution';
      const h1 = VIGIL_LEAKAGE.simhash64(text);
      const h2 = VIGIL_LEAKAGE.simhash64(text);
      expect(typeof h1).toBe('bigint');
      expect(h1).toBe(h2);
    });

    test('simhashToHex and hexToSimhash roundtrip accurately', () => {
      const text = 'Arbitrary test code for roundtrip verification';
      const hash = VIGIL_LEAKAGE.simhash64(text);
      const hex = VIGIL_LEAKAGE.simhashToHex(hash);
      expect(hex).toMatch(/^0x[0-9a-f]{16}$/i);
      const recovered = VIGIL_LEAKAGE.hexToSimhash(hex);
      expect(recovered).toBe(hash);
    });

    test('minor whitespace and punctuation perturbations produce near-identical SimHash', () => {
      const orig = 'This program is free software: you can redistribute it and or modify it under the terms of the GNU General Public License.';
      const perturbed = '  This program is   free software! You can redistribute it and / or modify it under the terms of the GNU General Public License...  ';

      const h1 = VIGIL_LEAKAGE.simhash64(orig);
      const h2 = VIGIL_LEAKAGE.simhash64(perturbed);
      const dist = VIGIL_LEAKAGE.hammingDistance(h1, h2);

      expect(dist).toBeLessThanOrEqual(2);
      expect(VIGIL_LEAKAGE.calculateSimilarity(h1, h2)).toBeGreaterThanOrEqual(0.95);
    });
  });

  describe('2. Hamming Distance & Bit Operations', () => {
    test('accurately calculates bitwise popcount Hamming distance', () => {
      expect(VIGIL_LEAKAGE.hammingDistance(0n, 0n)).toBe(0);
      expect(VIGIL_LEAKAGE.hammingDistance(0n, 1n)).toBe(1);
      expect(VIGIL_LEAKAGE.hammingDistance(0n, 3n)).toBe(2);
      expect(VIGIL_LEAKAGE.hammingDistance(0n, 0xffffffffffffffffn)).toBe(64);
    });
  });

  describe('3. Inbound Copyleft / GPL Regurgitation Detection', () => {
    test('detects near-verbatim GNU General Public License (v3) regurgitation', () => {
      const aiResponse = `
        /*
         * This program is free software: you can redistribute it and/or modify
         * it under the terms of the GNU General Public License as published by
         * the Free Software Foundation, either version 3 of the License, or
         * (at your option) any later version.
         *
         * This program is distributed in the hope that it will be useful,
         * but WITHOUT ANY WARRANTY; without even the implied warranty of
         * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
         * GNU General Public License for more details.
         */
        int main() { return 0; }
      `;

      const result = VIGIL_LEAKAGE.checkLeakage(aiResponse);
      expect(result.isLeakage).toBe(true);
      expect(result.license).toContain('GNU General Public License');
      expect(result.category).toBe('COPYLEFT_GPL');
      expect(result.similarity).toBeGreaterThanOrEqual(0.90);
      expect(result.warning).toContain('Copyleft license conditions may apply');
    });

    test('detects Linux kernel copyleft header regurgitation', () => {
      const aiResponse = `
        // SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
        // This file is part of the Linux kernel.
        // You may redistribute it under the terms of the GNU General Public License version 2.
        #include <linux/types.h>
      `;

      const result = VIGIL_LEAKAGE.checkLeakage(aiResponse);
      expect(result.isLeakage).toBe(true);
      expect(result.license).toBe('Linux Kernel Copyleft Header');
      expect(result.category).toBe('COPYLEFT_GPL');
    });

    test('detects BusyBox copyleft license notice', () => {
      const aiResponse = `
        /*
         * BusyBox is licensed under the GNU General Public License version 2.
         * The full text of the license is available in the LICENSE file.
         * You may not distribute binaries without accompanying complete machine readable source code.
         */
      `;

      const result = VIGIL_LEAKAGE.checkLeakage(aiResponse);
      expect(result.isLeakage).toBe(true);
      expect(result.license).toBe('BusyBox Copyleft License Header');
    });
  });

  describe('4. Benign Proprietary / Permissive Code Stability (Zero False Positives)', () => {
    test('permissive MIT code or generic algorithms do not trigger copyleft alert', () => {
      const mitSnippet = `
        import React, { useState } from 'react';
        export default function Counter() {
          const [count, setCount] = useState(0);
          return (
            <div className="counter-container">
              <h1>Count: {count}</h1>
              <button onClick={() => setCount(c => c + 1)}>Increment</button>
            </div>
          );
        }
      `;

      const result = VIGIL_LEAKAGE.checkLeakage(mitSnippet);
      expect(result.isLeakage).toBe(false);
      expect(result.license).toBeNull();
    });

    test('skips short code fragments (< 50 chars)', () => {
      const shortSnippet = 'const x = 42; return x * 2;';
      const result = VIGIL_LEAKAGE.checkLeakage(shortSnippet);
      expect(result.isLeakage).toBe(false);
      expect(result.reason).toBe('text_too_short');
    });
  });

  describe('5. Custom Enterprise Codebase Fingerprints', () => {
    test('allows registering and matching proprietary internal codebase fingerprints', () => {
      const proprietaryHeader = `
        CONFIDENTIAL AND PROPRIETARY - ACME CORPORATION GLOBAL CORE
        PROPERTY OF ACME CORP. ALL RIGHTS RESERVED. DO NOT DISTRIBUTE.
        INTERNAL MEMORY ENCRYPTION PIPELINE V12.8.
      `;

      const fp = VIGIL_LEAKAGE.registerFingerprint(
        'acme_core_header',
        'Acme Confidential Memory Core',
        'PROPRIETARY_IP',
        proprietaryHeader
      );

      expect(fp).toBeDefined();
      expect(fp.id).toBe('acme_core_header');

      const aiResponseWithLeak = `
        /*
         * CONFIDENTIAL AND PROPRIETARY - ACME CORPORATION GLOBAL CORE
         * PROPERTY OF ACME CORP. ALL RIGHTS RESERVED. DO NOT DISTRIBUTE.
         * INTERNAL MEMORY ENCRYPTION PIPELINE V12.8.
         */
        function initializeAcmeKeys() { return true; }
      `;

      const result = VIGIL_LEAKAGE.checkLeakage(aiResponseWithLeak, [fp]);
      expect(result.isLeakage).toBe(true);
      expect(result.matchedId).toBe('acme_core_header');
      expect(result.license).toBe('Acme Confidential Memory Core');
      expect(result.category).toBe('PROPRIETARY_IP');
      expect(result.similarity).toBeGreaterThanOrEqual(0.90);
    });
  });
});
