//! Stable failure codes for canonical evidence admission.

use serde::{Deserialize, Serialize};

/// Gives a stable machine-readable meaning to a diagnostic.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticCode {
    /// The schema discriminator does not match the selected format.
    UnsupportedSchema,
    /// A required format feature is unknown to the validator.
    UnsupportedRequiredFeature,
    /// A document exceeds an effective versioned limit.
    LimitExceeded,
    /// A semantically unordered list is not in canonical order.
    NonCanonicalOrder,
    /// A value does not satisfy its closed schema.
    ValueTypeMismatch,
}
