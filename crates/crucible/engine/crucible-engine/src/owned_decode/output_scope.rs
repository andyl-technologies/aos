//! Required original authority for operational returned output ownership.

use super::{
    DecodeAdmissionError, DecodeBudget, DecodeCustody, current_budget, current_child_budget,
};

#[derive(Debug)]
struct MissingOriginalAuthority;

impl std::fmt::Display for MissingOriginalAuthority {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("admitted output requires an original resource authority")
    }
}

impl std::error::Error for MissingOriginalAuthority {}

/// Creates an independent output account under the current original authority.
///
/// Operational output APIs use this boundary to distinguish admitted ownership
/// from ordinary component formatting. It never invents an allowance when no
/// original owner has installed a scope.
///
/// # Errors
/// Refuses missing original authority, exhausted metadata credit, or account
/// allocation failure before any output fields are copied.
pub fn require_current_child_budget() -> Result<DecodeBudget, DecodeAdmissionError> {
    current_child_budget()?.ok_or_else(|| DecodeAdmissionError::new(MissingOriginalAuthority))
}

/// Retains the successful current account for already admitted owned fields.
///
/// This does not create new credit for existing allocations. It transfers the
/// account that admitted those fields into their final returned container.
///
/// # Errors
/// Refuses missing original authority or an earlier current-account failure.
pub fn require_current_custody() -> Result<DecodeCustody, DecodeAdmissionError> {
    let budget =
        current_budget().ok_or_else(|| DecodeAdmissionError::new(MissingOriginalAuthority))?;
    budget.check()?;
    Ok(budget.custody())
}
