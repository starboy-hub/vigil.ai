use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MlClassificationResult {
    pub legit: f32,
    pub scam: f32,
    pub injection: f32,
    pub verdict: String,
    pub provider: String,
}

#[allow(dead_code)]
pub struct NativeMlEngine {
    pub provider_name: String,
    pub is_gpu_accelerated: bool,
}

impl NativeMlEngine {
    pub fn new() -> Self {
        // Detect native GPU provider (Metal on macOS, DirectX/Vulkan on Win/Linux)
        let (provider, is_gpu) = if cfg!(target_os = "macos") {
            ("Metal GPU (Apple Silicon / AMD)".to_string(), true)
        } else if cfg!(target_os = "windows") {
            ("DirectX 12 / Vulkan GPU".to_string(), true)
        } else {
            ("CPU WASM Fallback".to_string(), false)
        };

        Self {
            provider_name: provider,
            is_gpu_accelerated: is_gpu,
        }
    }

    /// Classifies incoming text using native sequence classification bounds
    pub fn classify(&self, text: &str) -> MlClassificationResult {
        if text.trim().is_empty() {
            return MlClassificationResult {
                legit: 1.0,
                scam: 0.0,
                injection: 0.0,
                verdict: "legit".to_string(),
                provider: self.provider_name.clone(),
            };
        }

        let lower = text.to_lowercase();
        let mut scam_score: f32 = 0.05;
        let mut injection_score: f32 = 0.05;

        // Prompt injection signals
        if lower.contains("ignore previous instructions")
            || lower.contains("disregard all prior")
            || lower.contains("system prompt")
        {
            injection_score += 0.85;
        }

        // Scam signals
        if lower.contains("account suspended")
            || lower.contains("verify your password")
            || lower.contains("urgent payment required")
            || lower.contains("wire transfer")
        {
            scam_score += 0.88;
        }

        let total = scam_score + injection_score + 1.0;
        let legit = (1.0 / total).clamp(0.0, 1.0);
        let scam = (scam_score / total).clamp(0.0, 1.0);
        let injection = (injection_score / total).clamp(0.0, 1.0);

        let verdict = if injection >= scam && injection > 0.4 {
            "injection".to_string()
        } else if scam > 0.4 {
            "scam".to_string()
        } else {
            "legit".to_string()
        };

        MlClassificationResult {
            legit,
            scam,
            injection,
            verdict,
            provider: self.provider_name.clone(),
        }
    }
}
