//! Public data types for divergence diagnostics.

use std::error::Error;
use std::fmt;

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

/// One side of a divergence comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DivergenceSide {
    /// The baseline or left-hand run.
    Left,
    /// The perturbed or right-hand run.
    Right,
}

/// A register value captured in a both-sides divergence state dump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DivergenceRegister {
    /// Stable register name.
    pub name: String,
    /// Canonical little-endian register bytes.
    pub bytes: Vec<u8>,
}

/// A memory region captured in a both-sides divergence state dump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DivergenceMemoryRegion {
    /// Stable region name.
    pub name: String,
    /// Guest physical start address for the region.
    pub start: u64,
    /// Canonical bytes for the captured region.
    pub bytes: Vec<u8>,
}

/// A deterministic state dump emitted by divergence bisection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DivergenceStateDump {
    /// Icount where this dump was captured.
    pub icount: u64,
    /// Full register file in stable order.
    pub registers: Vec<DivergenceRegister>,
    /// Memory regions relevant to the divergence in stable order.
    pub memory_regions: Vec<DivergenceMemoryRegion>,
    /// Last canonical events leading to this point.
    pub last_canonical_events: Vec<String>,
}

/// Left and right state dumps captured at the same icount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DivergenceStatePair {
    /// Baseline run dump.
    pub left: DivergenceStateDump,
    /// Perturbed run dump.
    pub right: DivergenceStateDump,
}

/// Deterministic diff summary between two state dumps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DivergenceStateDiff {
    /// Register names whose canonical bytes differ.
    pub registers: Vec<String>,
    /// Memory region labels whose canonical bytes differ.
    pub memory_regions: Vec<String>,
    /// Whether the recent canonical event suffix differs.
    pub canonical_events_differ: bool,
}

/// A canonical decision-trace entry used to localize schedule mismatches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionTraceEntry {
    /// Stable decision index in the schedule.
    pub index: usize,
    /// Stable node identifier associated with the decision when known.
    pub node: Option<String>,
    /// Icount associated with the decision when known.
    pub icount: Option<u64>,
    /// Human-readable decision summary for diagnostics.
    pub summary: String,
    /// Canonical bytes for equality and first-mismatch localization.
    pub canonical_bytes: Vec<u8>,
}

/// The first differing schedule entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionTraceMismatch {
    /// Index where the schedules first differ.
    pub index: usize,
    /// Entry from the baseline schedule, or `None` if it ended first.
    pub left: Option<DecisionTraceEntry>,
    /// Entry from the perturbed schedule, or `None` if it ended first.
    pub right: Option<DecisionTraceEntry>,
}

/// Full result of a deterministic divergence bisection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DivergenceBisectionReport {
    /// Index of the first differing fingerprint sample.
    pub sample_index: usize,
    /// Stable node identifier responsible for the coarse mismatch when known.
    pub node: Option<String>,
    /// Last icount known to match before the differing sample.
    pub previous_matching_icount: Option<u64>,
    /// Icount of the first differing sample before fine bisection.
    pub first_different_sample_icount: u64,
    /// Exact first differing instruction count.
    pub first_different_icount: u64,
    /// First differing schedule decision when a trace is available.
    pub first_different_decision: Option<DecisionTraceMismatch>,
    /// Both-sides dump at the refined last matching icount, when one exists.
    pub last_matching_state: Option<DivergenceStatePair>,
    /// Both-sides dump at the exact first differing icount.
    pub first_different_state: DivergenceStatePair,
    /// Deterministic diff summary for the exact first differing state.
    pub first_different_state_diff: DivergenceStateDiff,
}

/// The reason a fine-bisection window is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BisectionWindowErrorKind {
    /// The low endpoint is not below the high endpoint.
    EmptyOrReversed,
    /// The low endpoint already differs, so it is not a matching lower bound.
    LowAlreadyDifferent,
    /// The high endpoint still matches, so it is not a differing upper bound.
    HighStillMatching,
}

/// An invalid fine-bisection window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BisectionWindowError {
    /// Last known matching icount.
    pub low_matching_icount: u64,
    /// First known differing icount.
    pub high_different_icount: u64,
    /// Why the bisection window is invalid.
    pub kind: BisectionWindowErrorKind,
}

impl fmt::Display for BisectionWindowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid bisection window: low={} high={} ({:?})",
            self.low_matching_icount, self.high_different_icount, self.kind
        )
    }
}

impl Error for BisectionWindowError {}

/// A refined icount bisection window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcountBisection {
    /// Last icount where the two sides still match.
    pub last_matching_icount: u64,
    /// First icount where the two sides differ.
    pub first_different_icount: u64,
}

/// A failed divergence-bisection run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DivergenceBisectionError {
    /// The two fingerprint streams match and cannot seed bisection.
    MatchingStreams,
    /// The streams use different fingerprint definitions.
    DefinitionMismatch,
    /// The sample stream matches but the final run fingerprint differs.
    FinalFingerprintMismatch,
    /// The first differing sample did not carry an icount.
    MissingDifferentSampleIcount,
    /// The coarse window was invalid for binary search.
    InvalidWindow(BisectionWindowError),
    /// A state dump contains duplicate register or memory keys.
    MalformedStateDump {
        /// Side whose dump is malformed.
        side: DivergenceSide,
        /// Icount where the dump was captured.
        icount: u64,
        /// Malformed field name.
        field: &'static str,
        /// Duplicate stable key.
        key: String,
    },
}

impl fmt::Display for DivergenceBisectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MatchingStreams => write!(formatter, "fingerprint streams do not diverge"),
            Self::DefinitionMismatch => write!(
                formatter,
                "fingerprint streams use different definitions and cannot be icount-bisected"
            ),
            Self::FinalFingerprintMismatch => write!(
                formatter,
                "fingerprint streams differ only in the final fingerprint and cannot be icount-bisected"
            ),
            Self::MissingDifferentSampleIcount => write!(
                formatter,
                "first differing fingerprint sample does not carry an icount"
            ),
            Self::InvalidWindow(error) => write!(formatter, "{error}"),
            Self::MalformedStateDump {
                side,
                icount,
                field,
                key,
            } => write!(
                formatter,
                "malformed {side:?} state dump at icount {icount}: duplicate {field} key {key}"
            ),
        }
    }
}

impl Error for DivergenceBisectionError {}
