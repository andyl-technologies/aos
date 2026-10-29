//! Error type shared by the method classifier and hard-cut manifest checks.

/// A validation failure in a method classification or hard-cut manifest.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ControlError {
    /// A caller supplied an invalid bounded identifier or field value.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Name of the rejected field.
        field: &'static str,
        /// Stable explanation suitable for an API error.
        reason: String,
    },
}
