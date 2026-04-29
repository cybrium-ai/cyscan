//! Endpoint posture scoring — weighted by severity.

use super::EndpointCheck;

/// Compute a 0-100 score from the check results.
/// Weights: critical=15, high=10, medium=5, low=2
pub fn compute(checks: &[EndpointCheck]) -> u32 {
    if checks.is_empty() {
        return 100;
    }

    let mut total_weight: u32 = 0;
    let mut earned: u32 = 0;

    for check in checks {
        let weight = match check.severity.as_str() {
            "critical" => 15,
            "high"     => 10,
            "medium"   => 5,
            "low"      => 2,
            _          => 3,
        };
        total_weight += weight;
        if check.passed {
            earned += weight;
        }
    }

    if total_weight == 0 {
        return 100;
    }

    ((earned as f64 / total_weight as f64) * 100.0).round() as u32
}
