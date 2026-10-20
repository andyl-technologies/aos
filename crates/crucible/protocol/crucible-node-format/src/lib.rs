//! Portable values, identities, and closed schemas for the Crucible node contract.
//!
//! Module map: [`values`] defines bounded wire scalars, [`time`] owns checked coordinator
//! coordinates, [`schema`] describes portable graph and binding records, and
//! [`canonical`] implements strict JSON decoding and CNP/1 content identity.
//! These records describe claims; they do not authenticate custody, resolve
//! referenced content, or establish that a provider is qualified.
//!
//! Spec index: RFC-0025 files 00, 01, 02, 03, 04, 05, 06, 08, 09.

#![forbid(unsafe_code)]

pub mod canonical;
pub mod schema;
pub mod time;
pub mod values;

pub use schema::*;
pub use time::*;
pub use values::*;

/// Reports an invalid portable value or identity operation.
#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    /// A field violates its closed schema or canonical representation.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Names the rejected field.
        field: &'static str,
        /// Explains the failed invariant.
        reason: String,
    },
    /// Checked time or length arithmetic overflowed.
    #[error("contract arithmetic overflow")]
    Overflow,
    /// Input cannot be decoded as the requested JSON schema.
    #[error("invalid contract JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Validates local schema invariants without granting execution authority.
pub trait Validate {
    /// Checks bounds, closed vocabulary, ordering, and nested values.
    ///
    /// # Errors
    /// Returns an error when a local schema invariant is violated. Referenced
    /// content availability, negotiated extensions, and graph-wide constraints
    /// require additional host admission checks.
    fn validate(&self) -> Result<(), ContractError>;
}

pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> ContractError {
    ContractError::Invalid {
        field,
        reason: reason.into(),
    }
}
