//! Execution-fingerprint stream comparison.
//!
//! This module compares ordered, already-captured fingerprint streams and
//! reports the first definition, sample, length, or final-fingerprint mismatch.

use std::error::Error;
use std::fmt;

use super::definition::{FingerprintDefinition, FingerprintDigest, FingerprintSampleTrigger};
use super::hasher::FingerprintHasher;

/// One canonical fingerprint sample captured at a deterministic icount boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintSample {
    /// Monotonic sample number within the stream.
    pub seq: u64,
    /// Stable node identifier associated with this sample.
    pub node: String,
    /// Node-local instruction count at the sample point.
    pub icount: u64,
    /// The deterministic reason this sample was taken.
    pub trigger: FingerprintSampleTrigger,
    /// Rolling fingerprint bytes after incorporating this sample.
    pub rolling_fingerprint: FingerprintDigest,
}

/// The ordered fingerprint stream for one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintStream {
    /// Digest of the content-addressed fingerprint definition used by this run.
    pub definition_digest: FingerprintDigest,
    /// Samples in canonical comparison order.
    pub samples: Vec<FingerprintSample>,
    /// Final run fingerprint bytes.
    pub final_fingerprint: FingerprintDigest,
}

impl FingerprintStream {
    /// Builds a stream from samples and the canonical content-addressed definition.
    ///
    /// The final run fingerprint is the last sample's rolling fingerprint, or
    /// the definition-specific seed fingerprint when the stream is empty.
    #[must_use]
    pub fn from_samples(
        definition: &FingerprintDefinition,
        samples: Vec<FingerprintSample>,
    ) -> Self {
        let definition_digest = definition.digest();
        let final_fingerprint = samples
            .last()
            .map(|sample| sample.rolling_fingerprint.clone())
            .unwrap_or_else(|| initial_rolling_fingerprint(definition));
        Self {
            definition_digest,
            samples,
            final_fingerprint,
        }
    }
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
    /// The two streams used different fingerprint definitions.
    Definition {
        /// Definition digest from the left-hand stream.
        left: FingerprintDigest,
        /// Definition digest from the right-hand stream.
        right: FingerprintDigest,
    },
    /// A sample at the same index differs.
    Sample {
        /// Sample from the left-hand stream.
        left: Box<FingerprintSample>,
        /// Sample from the right-hand stream.
        right: Box<FingerprintSample>,
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
        left: FingerprintDigest,
        /// Final fingerprint bytes from the right-hand stream.
        right: FingerprintDigest,
    },
}

impl fmt::Display for FingerprintMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            FingerprintMismatchKind::Definition { .. } => {
                write!(formatter, "fingerprint streams use different definitions")
            }
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

/// Computes the definition-specific initial rolling fingerprint.
#[must_use]
pub fn initial_rolling_fingerprint(definition: &FingerprintDefinition) -> FingerprintDigest {
    let mut hasher = FingerprintHasher::new();
    hasher.write_tag("fingerprint-stream-seed");
    hasher.write_bytes(&definition.digest());
    hasher.finish()
}

/// Compares two fingerprint streams in canonical order.
///
/// # Errors
///
/// Returns [`FingerprintMismatch`] at the first definition, sample, length, or
/// final fingerprint difference.
pub fn compare_fingerprint_streams(
    left: &FingerprintStream,
    right: &FingerprintStream,
) -> Result<(), FingerprintMismatch> {
    if left.definition_digest != right.definition_digest {
        return Err(FingerprintMismatch {
            sample_index: 0,
            kind: FingerprintMismatchKind::Definition {
                left: left.definition_digest.clone(),
                right: right.definition_digest.clone(),
            },
        });
    }

    for (sample_index, (left_sample, right_sample)) in
        left.samples.iter().zip(right.samples.iter()).enumerate()
    {
        if left_sample != right_sample {
            return Err(FingerprintMismatch {
                sample_index,
                kind: FingerprintMismatchKind::Sample {
                    left: Box::new(left_sample.clone()),
                    right: Box::new(right_sample.clone()),
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
