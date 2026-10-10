//! VIGIL Blueprint #6/#16 companion: perceptual image hashing (pHash).
//!
//! Computes a 64-bit DCT-based perceptual hash over a 32x32 grayscale
//! downsample of an image. Perceptually similar images (re-encoded, slightly
//! cropped, re-compressed deepfakes) produce hashes with small Hamming
//! distance; the JS side cross-references a local blocklist of known
//! synthetic-media hashes.

/// Nearest-neighbor downsample of a grayscale buffer to exactly 32x32.
pub fn downsample_to_32(gray: &[u8], width: usize, height: usize) -> Option<Vec<f64>> {
    if width == 0 || height == 0 || gray.len() < width * height {
        return None;
    }
    let mut out = vec![0f64; 32 * 32];
    for y in 0..32 {
        for x in 0..32 {
            let sx = x * width / 32;
            let sy = y * height / 32;
            out[y * 32 + x] = gray[sy * width + sx] as f64;
        }
    }
    Some(out)
}

/// 1-D DCT-II over a slice (unnormalized, as used by pHash).
fn dct_1d(input: &[f64]) -> Vec<f64> {
    let n = input.len();
    let mut out = vec![0f64; n];
    for k in 0..n {
        let mut sum = 0f64;
        for (i, &v) in input.iter().enumerate() {
            sum += v * ((std::f64::consts::PI * ((2 * i + 1) as f64) * (k as f64)) / (2.0 * n as f64)).cos();
        }
        out[k] = sum;
    }
    out
}

/// Computes the 64-bit perceptual hash: 2D DCT on the 32x32 grayscale block,
/// top-left 8x8 low-frequency coefficients (DC excluded), bits = coefficient
/// > median.
pub fn perceptual_hash(gray: &[u8], width: usize, height: usize) -> Option<u64> {
    let small = downsample_to_32(gray, width, height)?;

    // Rows then columns
    let mut rows = vec![vec![0f64; 32]; 32];
    for y in 0..32 {
        rows[y] = dct_1d(&small[y * 32..(y + 1) * 32]);
    }
    let mut freq = vec![0f64; 32 * 32];
    for x in 0..32 {
        let col: Vec<f64> = (0..32).map(|y| rows[y][x]).collect();
        let col_dct = dct_1d(&col);
        for y in 0..32 {
            freq[y * 32 + x] = col_dct[y];
        }
    }

    // Top-left 8x8 low frequencies, skip DC term at [0][0]
    let mut coeffs = [0f64; 64];
    let mut idx = 0;
    for y in 0..8 {
        for x in 0..8 {
            if x == 0 && y == 0 {
                continue;
            }
            coeffs[idx] = freq[y * 32 + x];
            idx += 1;
        }
    }
    // 63 coefficients: median over all of them; keep bits stable by sorting
    let mut sorted = coeffs;
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = sorted[31];

    let mut hash: u64 = 0;
    let mut bit = 0;
    for y in 0..8 {
        for x in 0..8 {
            if x == 0 && y == 0 {
                continue;
            }
            if freq[y * 32 + x] > median {
                hash |= 1u64 << bit;
            }
            bit += 1;
        }
    }
    Some(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat(v: u8) -> (Vec<u8>, usize, usize) {
        (vec![v; 32 * 32], 32, 32)
    }

    fn gradient() -> (Vec<u8>, usize, usize) {
        let mut px = vec![0u8; 32 * 32];
        for y in 0..32 {
            for x in 0..32 {
                px[y * 32 + x] = ((x * 8 + y * 4) % 256) as u8;
            }
        }
        (px, 32, 32)
    }

    #[test]
    fn test_identical_image_same_hash() {
        let (px, w, h) = gradient();
        let a = perceptual_hash(&px, w, h).unwrap();
        let b = perceptual_hash(&px, w, h).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_slight_brightness_shift_small_hamming() {
        let (px, w, h) = gradient();
        let a = perceptual_hash(&px, w, h).unwrap();
        let shifted: Vec<u8> = px.iter().map(|v| v.saturating_add(12)).collect();
        let b = perceptual_hash(&shifted, w, h).unwrap();
        let hamming = (a ^ b).count_ones();
        assert!(hamming <= 12, "brightness shift must be perceptually close: {}", hamming);
    }

    #[test]
    fn test_different_images_far_apart() {
        let (flat_px, w, h) = flat(128);
        let (grad_px, _, _) = gradient();
        let a = perceptual_hash(&flat_px, w, h).unwrap();
        let b = perceptual_hash(&grad_px, w, h).unwrap();
        let hamming = (a ^ b).count_ones();
        assert!(hamming >= 20, "flat vs gradient must be far apart: {}", hamming);
    }

    #[test]
    fn test_rejects_invalid_buffers() {
        assert!(perceptual_hash(&[], 0, 0).is_none());
        assert!(perceptual_hash(&[1, 2, 3], 16, 16).is_none());
    }
}
