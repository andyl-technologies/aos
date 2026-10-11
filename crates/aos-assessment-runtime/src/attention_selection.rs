//! Immutable package and severity facts for reviewed notification selection.
//!
//! The reproduced assessment supplies these facts when an alert is committed.
//! Historical events never consult a newer inventory or assessment head. CVSS
//! bands describe supplied base scores, not exposure, exploitability or risk.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use aos_assessment::advisory::AdvisorySeverity;
use serde::{Deserialize, Serialize};

use crate::validation::{sorted, text};

/// Orders the FIRST CVSS v3/v4 qualitative base-score bands.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeverityBand {
    /// A supplied supported score is exactly zero.
    None,
    /// A supplied supported score is between 0.1 and 3.9.
    Low,
    /// A supplied supported score is between 4.0 and 6.9.
    Medium,
    /// A supplied supported score is between 7.0 and 8.9.
    High,
    /// A supplied supported score is between 9.0 and 10.0.
    Critical,
}

/// Retains selection facts with an exact immutable alert revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttentionSelectionContext {
    /// Exact publisher-scoped coordinate of the containing inventory subject.
    pub package_coordinate: String,
    /// Distinct supported source bands; conflicting sources remain distinct.
    pub severity_bands: Vec<SeverityBand>,
    /// Whether any source severity is missing, unsupported or unparseable.
    pub unknown_severity: bool,
}

impl AttentionSelectionContext {
    /// Projects supplied CVSS base scores without computing vectors or merging sources.
    #[must_use]
    pub fn from_severities(coordinate: String, severities: &[AdvisorySeverity]) -> Self {
        let mut bands = BTreeSet::new();
        let mut unknown = severities.is_empty();
        for severity in severities {
            let band = match severity.scheme.as_str() {
                "CVSS_V3" | "CVSS_V4" => severity.base_score.as_deref().and_then(score_band),
                _ => None,
            };
            match band {
                Some(band) => {
                    bands.insert(band);
                }
                None => unknown = true,
            }
        }
        Self {
            package_coordinate: coordinate,
            severity_bands: bands.into_iter().collect(),
            unknown_severity: unknown,
        }
    }

    /// Checks finite, canonical selection facts independently of source authority.
    ///
    /// # Errors
    /// Returns an error for malformed coordinates or contradictory severity facts.
    pub fn validate(&self) -> Result<()> {
        text(
            &self.package_coordinate,
            1024,
            "notification package coordinate",
        )?;
        ensure!(self.severity_bands.len() <= 5, "excessive severity bands");
        sorted(&self.severity_bands, "notification severity bands")?;
        ensure!(
            !self.severity_bands.is_empty() || self.unknown_severity,
            "missing severity must remain unknown"
        );
        Ok(())
    }
}

// CVSS scores use one decimal place. Reject exponent notation, signs, whitespace,
// alternate precision and out-of-range scores instead of rounding or coercing.
fn score_band(score: &str) -> Option<SeverityBand> {
    let (whole, fraction) = score.split_once('.')?;
    if !matches!(
        whole,
        "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10"
    ) || fraction.len() != 1
        || !fraction.as_bytes()[0].is_ascii_digit()
    {
        return None;
    }
    let tenths = whole.parse::<u16>().ok()? * 10 + u16::from(fraction.as_bytes()[0] - b'0');
    match tenths {
        0 => Some(SeverityBand::None),
        1..=39 => Some(SeverityBand::Low),
        40..=69 => Some(SeverityBand::Medium),
        70..=89 => Some(SeverityBand::High),
        90..=100 => Some(SeverityBand::Critical),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
