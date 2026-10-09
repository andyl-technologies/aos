//! Portable resource-assignment models and independent exact verification.
//!
//! [`Problem`] describes finite placement choices, resource accounting, topology,
//! constraints, and lexicographic objectives. [`validate`] freezes a structurally
//! valid problem; [`evaluate`] and [`verify`] interpret it without starting a
//! solver. The numeric module preserves exact integer and rational quantities
//! across language boundaries. No result grants reservation or execution authority.

mod accounting;
mod evaluation;
mod numbers;
mod schema;
mod validation;

pub use evaluation::{
    ComponentDebt, Evaluation, ResourceLoad, VerificationClass, VerificationError,
    VerifiedAssignment, Violation, evaluate, verify,
};
pub use numbers::{Integer, Quantity, Rational};
pub use schema::*;
pub use validation::{MAX_EVALUATION_BITS, ModelError, ModelErrorKind, ValidatedProblem, validate};
