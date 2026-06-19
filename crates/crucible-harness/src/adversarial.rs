//! Adversarial determinism comparison utilities.
//!
//! This module hosts the comparison core for the future host-hostile runner: once
//! each run has produced a canonical log hash and final fingerprint, the verdict
//! is a pure byte comparison independent of host timing.

use std::error::Error;
use std::fmt;

/// One hostile host profile used for an adversarial run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostileProfile {
    /// Stable profile name used in diagnostics.
    pub name: String,
}

/// One completed run under a hostile host profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdversarialRun {
    /// Hostile profile used for this run.
    pub profile: HostileProfile,
    /// Canonical event-log bytes or a content hash of those bytes.
    pub canonical_log: Vec<u8>,
    /// Final execution fingerprint bytes.
    pub final_fingerprint: Vec<u8>,
}

/// A failed adversarial comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdversarialComparisonError {
    /// No runs were provided, so no comparison can be made.
    EmptyCorpus,
    /// A run diverged from the first run in the corpus.
    Mismatch(AdversarialMismatch),
}

/// The first run that diverged from the baseline adversarial run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdversarialMismatch {
    /// Baseline hostile profile.
    pub baseline_profile: String,
    /// Divergent hostile profile.
    pub divergent_profile: String,
    /// The field that differed.
    pub kind: AdversarialMismatchKind,
}

/// The adversarial output field that differed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdversarialMismatchKind {
    /// The canonical log bytes or log hash differed.
    CanonicalLog,
    /// The final fingerprint bytes differed.
    FinalFingerprint,
}

impl fmt::Display for AdversarialComparisonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCorpus => write!(
                formatter,
                "adversarial comparison requires at least one run"
            ),
            Self::Mismatch(mismatch) => write!(
                formatter,
                "adversarial run `{}` diverged from baseline `{}` in {:?}",
                mismatch.divergent_profile, mismatch.baseline_profile, mismatch.kind
            ),
        }
    }
}

impl Error for AdversarialComparisonError {}

/// Compares adversarial runs against the first run as a deterministic baseline.
///
/// # Errors
///
/// Returns [`AdversarialComparisonError::EmptyCorpus`] when no runs are supplied,
/// or [`AdversarialComparisonError::Mismatch`] for the first canonical-log or
/// final-fingerprint difference.
pub fn compare_adversarial_runs(runs: &[AdversarialRun]) -> Result<(), AdversarialComparisonError> {
    let Some(baseline) = runs.first() else {
        return Err(AdversarialComparisonError::EmptyCorpus);
    };

    for run in &runs[1..] {
        if run.canonical_log != baseline.canonical_log {
            return Err(AdversarialComparisonError::Mismatch(AdversarialMismatch {
                baseline_profile: baseline.profile.name.clone(),
                divergent_profile: run.profile.name.clone(),
                kind: AdversarialMismatchKind::CanonicalLog,
            }));
        }

        if run.final_fingerprint != baseline.final_fingerprint {
            return Err(AdversarialComparisonError::Mismatch(AdversarialMismatch {
                baseline_profile: baseline.profile.name.clone(),
                divergent_profile: run.profile.name.clone(),
                kind: AdversarialMismatchKind::FinalFingerprint,
            }));
        }
    }

    Ok(())
}
