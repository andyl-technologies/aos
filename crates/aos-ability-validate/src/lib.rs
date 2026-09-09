//! Pure semantic validation for AOS ability contracts.
//!
//! Validation turns unchecked portable documents into checked values without
//! acquiring runtime resources or performing effects. The checked wrappers
//! retain the exact canonical documents that were validated.

#![forbid(unsafe_code)]

mod authority;
mod binding;
mod effect;
mod error;
mod graph;
mod output;
mod projection;
mod schema;
mod transition_authority;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
mod regression_tests;

pub use authority::{InvocationAuthorizationError, ValueAuthorizationError};
pub use binding::PreparedBindingCandidates;
pub use error::ValidationErrors;
pub use graph::{
    BindingAuthorityKind, BindingValidationInputs, CheckedBindingPlan, CheckedEffectPlan,
    ValidationContext,
};
pub use output::{InputValidationError, OutputValidationError, ProviderReadinessError};
pub use schema::{SchemaPath, validate_value};
pub use transition_authority::{
    CheckedTransitionAuthority, TransitionAuthorityError, TransitionAuthorityInputs,
};
