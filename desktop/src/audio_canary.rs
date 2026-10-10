use rustfft::{num_complex::Complex, FftPlanner};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VoiceCanaryResult {
    pub is_synthetic: bool,
    pub score: u32,
    pub verdict: String,
    pub high_band_ratio: f32,
    pub peak_count: usize,
}

pub struct VoiceSpectralCanary {
    fft_size: usize,
}

impl VoiceSpectralCanary {
    pub fn new(fft_size: usize) -> Self {
        Self { fft_size }
    }

    /// Analyzes raw float audio samples using 1024-point FFT
    pub fn analyze_samples(&self, samples: &[f32]) -> VoiceCanaryResult {
        if samples.is_empty() {
            return VoiceCanaryResult {
                is_synthetic: false,
                score: 0,
                verdict: "authentic-human-voice".to_string(),
                high_band_ratio: 0.0,
                peak_count: 0,
            };
        }

        let len = samples.len().min(self.fft_size);
        let mut planner = FftPlanner::new();
        let fft = planner.plan_fft_forward(len);

        let mut buffer: Vec<Complex<f32>> = samples[..len]
            .iter()
            .map(|&s| Complex::new(s, 0.0))
            .collect();

        fft.process(&mut buffer);

        let magnitudes: Vec<f32> = buffer.iter().map(|c| c.norm()).collect();
        let total_sum: f32 = magnitudes.iter().sum();
        let avg_mag = total_sum / (magnitudes.len() as f32 + 1e-6);

        let half_len = magnitudes.len() / 2;
        let high_band_start = (half_len as f32 * 0.5) as usize; // 4kHz-8kHz equivalent band
        let high_band_sum: f32 = magnitudes[high_band_start..half_len].iter().sum();
        let high_band_avg = high_band_sum / ((half_len - high_band_start) as f32 + 1e-6);

        let mut peak_count = 0;
        for i in 1..half_len {
            let diff = (magnitudes[i] - magnitudes[i - 1]).abs();
            if magnitudes[i] > avg_mag * 1.5 && diff > avg_mag * 0.8 {
                peak_count += 1;
            }
        }

        let high_band_ratio = high_band_avg / (avg_mag + 1e-6);
        let score = (high_band_ratio * 30.0 + (peak_count as f32) * 2.0).min(100.0) as u32;
        let is_synthetic = score >= 75;

        VoiceCanaryResult {
            is_synthetic,
            score,
            verdict: if is_synthetic {
                "synthetic-voice-clone".to_string()
            } else {
                "authentic-human-voice".to_string()
            },
            high_band_ratio,
            peak_count,
        }
    }
}
