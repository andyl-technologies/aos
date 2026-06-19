//! Execution-fingerprint comparison utilities for harness gates.
//!
//! The types in this module model the comparison surface shared by
//! `gate:single-vm-fingerprint`, `gate:adversarial-determinism`, and divergence
//! bisection. They do not sample a VM themselves; they compare already-captured,
//! canonical fingerprint streams.

use std::error::Error;
use std::fmt;

/// One canonical fingerprint sample captured at a deterministic icount boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintSample {
    /// Monotonic sample number within the stream.
    pub seq: u64,
    /// Stable node identifier associated with this sample.
    pub node: String,
    /// Node-local instruction count at the sample point.
    pub icount: u64,
    /// Rolling fingerprint bytes after incorporating this sample.
    pub rolling_fingerprint: Vec<u8>,
}

/// The ordered fingerprint stream for one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintStream {
    /// Samples in canonical comparison order.
    pub samples: Vec<FingerprintSample>,
    /// Final run fingerprint bytes.
    pub final_fingerprint: Vec<u8>,
}

/// A deterministic fingerprint-stream mismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintMismatch {
    /// The sample index where comparison first failed.
    pub sample_index: usize,
    /// The class and payload of the mismatch.
    pub kind: FingerprintMismatchKind,
}

/// The specific way two fingerprint streams differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FingerprintMismatchKind {
    /// A sample at the same index differs.
    Sample {
        /// Sample from the left-hand stream.
        left: FingerprintSample,
        /// Sample from the right-hand stream.
        right: FingerprintSample,
    },
    /// One stream ended before the other.
    Length {
        /// Number of samples in the left-hand stream.
        left_len: usize,
        /// Number of samples in the right-hand stream.
        right_len: usize,
    },
    /// Samples matched, but final run fingerprints differ.
    Final {
        /// Final fingerprint bytes from the left-hand stream.
        left: Vec<u8>,
        /// Final fingerprint bytes from the right-hand stream.
        right: Vec<u8>,
    },
}

impl fmt::Display for FingerprintMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            FingerprintMismatchKind::Sample { left, right } => write!(
                formatter,
                "fingerprint sample {} differs: left seq={} node={} icount={}, right seq={} node={} icount={}",
                self.sample_index,
                left.seq,
                left.node,
                left.icount,
                right.seq,
                right.node,
                right.icount
            ),
            FingerprintMismatchKind::Length {
                left_len,
                right_len,
            } => write!(
                formatter,
                "fingerprint streams differ in length at sample {}: left={}, right={}",
                self.sample_index, left_len, right_len
            ),
            FingerprintMismatchKind::Final { .. } => write!(
                formatter,
                "fingerprint streams have matching samples but different final fingerprints"
            ),
        }
    }
}

impl Error for FingerprintMismatch {}

/// Compares two fingerprint streams in canonical order.
///
/// # Errors
///
/// Returns [`FingerprintMismatch`] at the first sample, length, or final
/// fingerprint difference.
pub fn compare_fingerprint_streams(
    left: &FingerprintStream,
    right: &FingerprintStream,
) -> Result<(), FingerprintMismatch> {
    for (sample_index, (left_sample, right_sample)) in
        left.samples.iter().zip(right.samples.iter()).enumerate()
    {
        if left_sample != right_sample {
            return Err(FingerprintMismatch {
                sample_index,
                kind: FingerprintMismatchKind::Sample {
                    left: left_sample.clone(),
                    right: right_sample.clone(),
                },
            });
        }
    }

    if left.samples.len() != right.samples.len() {
        return Err(FingerprintMismatch {
            sample_index: left.samples.len().min(right.samples.len()),
            kind: FingerprintMismatchKind::Length {
                left_len: left.samples.len(),
                right_len: right.samples.len(),
            },
        });
    }

    if left.final_fingerprint != right.final_fingerprint {
        return Err(FingerprintMismatch {
            sample_index: left.samples.len(),
            kind: FingerprintMismatchKind::Final {
                left: left.final_fingerprint.clone(),
                right: right.final_fingerprint.clone(),
            },
        });
    }

    Ok(())
}
