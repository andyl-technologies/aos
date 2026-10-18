//! ABI golden-vector comparison for harness conformance gates.
//!
//! The runner in this module compares live encodings against frozen golden
//! vectors. It deliberately treats version drift separately from byte drift so
//! later ABI gates can fail with precise diagnostics.
//!
//! Golden-vector record sketch:
//!
//! ```text
//! name
//! expected-version actual-version
//! expected-bytes actual-bytes
//! ```

use std::error::Error;
use std::fmt;

/// A frozen ABI vector and the live encoding produced for the same logical value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoldenVectorCase {
    /// Stable vector name used in diagnostics.
    pub name: String,
    /// Expected ABI version recorded with the golden vector.
    pub expected_version: u32,
    /// Actual ABI version reported by the live encoder.
    pub actual_version: u32,
    /// Frozen canonical bytes.
    pub expected_bytes: Vec<u8>,
    /// Live canonical bytes.
    pub actual_bytes: Vec<u8>,
}

/// The first ABI golden-vector mismatch in a corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoldenVectorMismatch {
    /// Stable vector name whose live encoding differs.
    pub name: String,
    /// The mismatch class.
    pub kind: GoldenVectorMismatchKind,
}

/// The specific ABI vector field that differed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GoldenVectorMismatchKind {
    /// ABI version changed without an accepted vector update.
    Version {
        /// Expected ABI version recorded with the vector.
        expected: u32,
        /// Actual ABI version reported by the live encoder.
        actual: u32,
    },
    /// Encoded bytes changed while the version matched.
    Bytes {
        /// Number of bytes in the golden vector.
        expected_len: usize,
        /// Number of bytes in the live encoding.
        actual_len: usize,
    },
}

impl fmt::Display for GoldenVectorMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            GoldenVectorMismatchKind::Version { expected, actual } => write!(
                formatter,
                "ABI vector `{}` changed version: expected {}, actual {}",
                self.name, expected, actual
            ),
            GoldenVectorMismatchKind::Bytes {
                expected_len,
                actual_len,
            } => write!(
                formatter,
                "ABI vector `{}` changed bytes: expected {} bytes, actual {} bytes",
                self.name, expected_len, actual_len
            ),
        }
    }
}

impl Error for GoldenVectorMismatch {}

/// Runs ABI golden-vector comparisons in corpus order.
///
/// # Errors
///
/// Returns [`GoldenVectorMismatch`] for the first version or byte mismatch.
pub fn run_golden_vectors(cases: &[GoldenVectorCase]) -> Result<(), GoldenVectorMismatch> {
    for case in cases {
        if case.expected_version != case.actual_version {
            return Err(GoldenVectorMismatch {
                name: case.name.clone(),
                kind: GoldenVectorMismatchKind::Version {
                    expected: case.expected_version,
                    actual: case.actual_version,
                },
            });
        }

        if case.expected_bytes != case.actual_bytes {
            return Err(GoldenVectorMismatch {
                name: case.name.clone(),
                kind: GoldenVectorMismatchKind::Bytes {
                    expected_len: case.expected_bytes.len(),
                    actual_len: case.actual_bytes.len(),
                },
            });
        }
    }

    Ok(())
}
