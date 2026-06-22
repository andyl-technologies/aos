//! Stream comparison and mismatch localization for the single-VM gate.

use std::error::Error;
use std::fmt;

use super::types::{SingleVmFingerprintSample, SingleVmFingerprintStream};

/// The specific way two single-VM fingerprint streams differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintMismatch {
    /// The sample index where comparison first failed.
    pub sample_index: usize,
    /// The class and payload of the mismatch.
    pub kind: SingleVmFingerprintMismatchKind,
    /// Last icount known to match before this mismatch.
    pub previous_matching_icount: Option<u64>,
    /// First icount known to differ, when the mismatch is tied to the run axis.
    pub first_different_icount: Option<u64>,
}

impl fmt::Display for SingleVmFingerprintMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            SingleVmFingerprintMismatchKind::Definition { .. } => {
                write!(formatter, "fingerprint definitions differ")
            }
            SingleVmFingerprintMismatchKind::Sample { first, second } => write!(
                formatter,
                "fingerprint sample {} differs: first seq={} node={} icount={}, second seq={} node={} icount={}",
                self.sample_index,
                first.seq,
                first.node,
                first.icount,
                second.seq,
                second.node,
                second.icount
            ),
            SingleVmFingerprintMismatchKind::Length {
                first_len,
                second_len,
            } => write!(
                formatter,
                "fingerprint streams differ in length at sample {}: first={}, second={}",
                self.sample_index, first_len, second_len
            ),
            SingleVmFingerprintMismatchKind::Final { .. } => write!(
                formatter,
                "fingerprint streams have matching samples but different final fingerprints"
            ),
        }
    }
}

impl Error for SingleVmFingerprintMismatch {}

/// The payload for a single-VM fingerprint mismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SingleVmFingerprintMismatchKind {
    /// The streams used different content-addressed fingerprint definitions.
    Definition {
        /// Definition digest from the first run.
        first: Vec<u8>,
        /// Definition digest from the second run.
        second: Vec<u8>,
    },
    /// A sample at the same index differs.
    Sample {
        /// Sample from the first run.
        first: Box<SingleVmFingerprintSample>,
        /// Sample from the second run.
        second: Box<SingleVmFingerprintSample>,
    },
    /// One stream ended before the other.
    Length {
        /// Number of samples in the first run.
        first_len: usize,
        /// Number of samples in the second run.
        second_len: usize,
    },
    /// Samples matched, but final run fingerprints differ.
    Final {
        /// Final fingerprint icount from the first run.
        first_icount: u64,
        /// Final fingerprint icount from the second run.
        second_icount: u64,
        /// Final fingerprint bytes from the first run.
        first: Vec<u8>,
        /// Final fingerprint bytes from the second run.
        second: Vec<u8>,
    },
}

/// Compares two single-VM fingerprint streams in canonical order.
///
/// # Errors
///
/// Returns [`SingleVmFingerprintMismatch`] at the first definition, sample,
/// length, or final-fingerprint difference.
pub fn compare_single_vm_fingerprint_streams(
    first: &SingleVmFingerprintStream,
    second: &SingleVmFingerprintStream,
    run_horizon_icount: u64,
) -> Result<(), SingleVmFingerprintMismatch> {
    if first.definition_digest != second.definition_digest {
        return Err(SingleVmFingerprintMismatch {
            sample_index: 0,
            kind: SingleVmFingerprintMismatchKind::Definition {
                first: first.definition_digest.clone(),
                second: second.definition_digest.clone(),
            },
            previous_matching_icount: None,
            first_different_icount: None,
        });
    }

    for (sample_index, (first_sample, second_sample)) in
        first.samples.iter().zip(second.samples.iter()).enumerate()
    {
        if first_sample != second_sample {
            return Err(SingleVmFingerprintMismatch {
                sample_index,
                kind: SingleVmFingerprintMismatchKind::Sample {
                    first: Box::new(first_sample.clone()),
                    second: Box::new(second_sample.clone()),
                },
                previous_matching_icount: previous_icount(first, sample_index),
                first_different_icount: Some(first_sample.icount.min(second_sample.icount)),
            });
        }
    }

    if first.samples.len() != second.samples.len() {
        let sample_index = first.samples.len().min(second.samples.len());
        let first_different_icount = first
            .samples
            .get(sample_index)
            .or_else(|| second.samples.get(sample_index))
            .map(|sample| sample.icount)
            .or(Some(run_horizon_icount));
        return Err(SingleVmFingerprintMismatch {
            sample_index,
            kind: SingleVmFingerprintMismatchKind::Length {
                first_len: first.samples.len(),
                second_len: second.samples.len(),
            },
            previous_matching_icount: previous_icount(first, sample_index),
            first_different_icount,
        });
    }

    if first.final_icount != second.final_icount
        || first.final_fingerprint != second.final_fingerprint
    {
        return Err(SingleVmFingerprintMismatch {
            sample_index: first.samples.len(),
            kind: SingleVmFingerprintMismatchKind::Final {
                first_icount: first.final_icount,
                second_icount: second.final_icount,
                first: first.final_fingerprint.clone(),
                second: second.final_fingerprint.clone(),
            },
            previous_matching_icount: first.samples.last().map(|sample| sample.icount),
            first_different_icount: Some(
                first
                    .final_icount
                    .min(second.final_icount)
                    .max(run_horizon_icount),
            ),
        });
    }

    Ok(())
}

fn previous_icount(stream: &SingleVmFingerprintStream, sample_index: usize) -> Option<u64> {
    sample_index
        .checked_sub(1)
        .and_then(|index| stream.samples.get(index))
        .map(|sample| sample.icount)
}
