//! Time-based risk score decay.
//!
//! Stale risk evidence decays exponentially so that historical minor anomalies
//! don't permanently elevate a long-running process's risk level.

/// Decay manager with configurable half-life (default: 300 seconds / 5 minutes).
#[derive(Debug, Clone)]
pub struct RiskDecay {
    half_life_secs: f64,
}

impl Default for RiskDecay {
    fn default() -> Self {
        Self {
            half_life_secs: 300.0, // 5 minutes half-life
        }
    }
}

impl RiskDecay {
    pub fn new(half_life_secs: f64) -> Self {
        Self { half_life_secs }
    }

    /// Calculate decayed score given initial score and elapsed seconds.
    pub fn decay(&self, initial_score: u32, elapsed_secs: f64) -> u32 {
        if initial_score == 0 || elapsed_secs <= 0.0 {
            return initial_score;
        }

        // N(t) = N0 * 0.5^(t / t_half)
        let decay_factor = (0.5f64).powf(elapsed_secs / self.half_life_secs);
        let decayed = (initial_score as f64) * decay_factor;
        decayed.round() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_decay() {
        let decay = RiskDecay::new(300.0);
        assert_eq!(decay.decay(100, 0.0), 100);
        assert_eq!(decay.decay(100, 300.0), 50);
        assert_eq!(decay.decay(100, 600.0), 25);
        assert_eq!(decay.decay(0, 100.0), 0);
    }
}
