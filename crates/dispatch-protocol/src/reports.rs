//! Typed search evidence remains distinct from independently checked assignments.

use dispatch_model::Rational;
use serde::{Deserialize, Serialize};

/// Preserves a backend's numerical claims and their formulation assumptions.
///
/// This report does not constitute an independently checked optimality proof.
/// Its objective tier, candidate restrictions, build identity, and tolerance are
/// supplied by the enclosing search-evidence and terminal-result records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundReport {
    /// A reported lower bound in the selected minimized objective tier.
    pub lower_bound: Option<Rational>,
    /// The incumbent value used when the backend calculated its gap.
    pub incumbent: Option<Rational>,
    /// The backend's reported absolute gap, when available.
    pub absolute_gap: Option<Rational>,
    /// The backend's reported relative gap, without assuming a shared formula.
    pub relative_gap: Option<Rational>,
    /// Describes the normalization and units of the bound and incumbent.
    pub units: String,
    /// Identifies rounding, quantization, and other formulation transformations.
    pub compilation: Vec<String>,
}
