//! Divergence localization helpers for harness diagnostics.
//!
//! The module provides the deterministic comparison core shared by
//! `gate:divergence-bisect` without owning VM resume itself. Higher layers supply
//! the probe that answers whether two resumed states still match at an icount.

use std::error::Error;
use std::fmt;

use crate::fingerprint::{FingerprintStream, compare_fingerprint_streams};

/// Coarse localization of the first differing fingerprint sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DivergenceReport {
    /// Index of the first differing fingerprint sample.
    pub sample_index: usize,
    /// Stable node identifier associated with the differing sample when known.
    pub node: Option<String>,
    /// Last icount known to agree before the differing sample.
    pub previous_matching_icount: Option<u64>,
    /// Icount at the first differing fingerprint sample when known.
    pub first_different_sample_icount: Option<u64>,
}

/// An invalid fine-bisection window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BisectionWindowError {
    /// Last known matching icount.
    pub low_matching_icount: u64,
    /// First known differing icount.
    pub high_different_icount: u64,
}

impl fmt::Display for BisectionWindowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid bisection window: low={} must be below high={}",
            self.low_matching_icount, self.high_different_icount
        )
    }
}

impl Error for BisectionWindowError {}

/// Locates the first differing fingerprint sample, if the streams differ.
#[must_use]
pub fn locate_first_divergence(
    left: &FingerprintStream,
    right: &FingerprintStream,
) -> Option<DivergenceReport> {
    let mismatch = compare_fingerprint_streams(left, right).err()?;
    let previous_matching_icount = mismatch
        .sample_index
        .checked_sub(1)
        .and_then(|index| left.samples.get(index))
        .map(|sample| sample.icount);
    let left_sample = left.samples.get(mismatch.sample_index);
    let right_sample = right.samples.get(mismatch.sample_index);
    let node = left_sample
        .or(right_sample)
        .map(|sample| sample.node.clone());
    let first_different_sample_icount = match (left_sample, right_sample) {
        (Some(left), Some(right)) => Some(left.icount.min(right.icount)),
        (Some(sample), None) | (None, Some(sample)) => Some(sample.icount),
        (None, None) => previous_matching_icount,
    };

    Some(DivergenceReport {
        sample_index: mismatch.sample_index,
        node,
        previous_matching_icount,
        first_different_sample_icount,
    })
}

/// Refines a known `(last matching, first differing]` icount window.
///
/// The `matches_at` probe must return `true` when the two replayed states still
/// match at `icount` and `false` when they differ.
///
/// # Errors
///
/// Returns [`BisectionWindowError`] when `low_matching_icount` is greater than or
/// equal to `high_different_icount`.
pub fn bisect_first_different_icount<F>(
    mut low_matching_icount: u64,
    mut high_different_icount: u64,
    mut matches_at: F,
) -> Result<u64, BisectionWindowError>
where
    F: FnMut(u64) -> bool,
{
    if low_matching_icount >= high_different_icount {
        return Err(BisectionWindowError {
            low_matching_icount,
            high_different_icount,
        });
    }

    while high_different_icount - low_matching_icount > 1 {
        let midpoint = low_matching_icount + ((high_different_icount - low_matching_icount) / 2);
        if matches_at(midpoint) {
            low_matching_icount = midpoint;
        } else {
            high_different_icount = midpoint;
        }
    }

    Ok(high_different_icount)
}
