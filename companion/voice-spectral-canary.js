/**
 * VIGIL Voice Clone Audio Spectral Canary
 * Analyzes audio frequency spectrum (FFT) for synthetic voice artifacts,
 * unnatural pitch variance, and high-frequency jitter typical of AI voice clones.
 */
(function (root) {
  'use strict';

  function analyzeAudioSpectrum(freqData) {
    if (!freqData || freqData.length === 0) return { isSynthetic: false, score: 0 };
    let sum = 0, peakCount = 0;
    const len = freqData.length;

    for (let i = 0; i < len; i++) {
      sum += freqData[i];
      if (i > 0 && freqData[i] > 200 && Math.abs(freqData[i] - freqData[i - 1]) > 50) {
        peakCount++;
      }
    }
    const avg = sum / len;
    // Synthetic vocoders often produce sharp unnatural harmonic peaks in 4kHz - 8kHz band
    const highBandAvg = freqData.slice(Math.floor(len * 0.5)).reduce((a, b) => a + b, 0) / (len * 0.5);
    const score = Math.min(100, Math.round((highBandAvg / (avg || 1)) * 30 + peakCount * 2));
    const isSynthetic = score >= 75;

    return {
      isSynthetic,
      score,
      verdict: isSynthetic ? 'synthetic-voice-clone' : 'authentic-human-voice'
    };
  }

  const VIGIL_VOICE_SPECTRAL = {
    analyzeAudioSpectrum
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = VIGIL_VOICE_SPECTRAL;
  else root.VIGIL_VOICE_SPECTRAL = VIGIL_VOICE_SPECTRAL;
})(typeof self !== 'undefined' ? self : this);
