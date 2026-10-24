//! Portable module options, declarations, and checked activation graphs.
//!
//! [`option`] and [`schema`] define the native module type vocabulary;
//! [`value`] preserves bounded literals and [`identity`] bounded local names.
//! [`graph`] validates fully resolved operations and typed edges before any
//! activation effects. [`transaction_blob`] defines durable content references;
//! [`limits`] and [`diagnostic`] carry module admission rules.
//!
//! Artifact identity and realized consumption evidence belong to the independent
//! [`aos_artifact_evidence`] library. This crate performs no package lookup, Nix
//! evaluation, resource acquisition, or runtime effects.

#![forbid(unsafe_code)]

pub mod diagnostic;
pub mod graph;
pub mod identity;
pub mod limits;
pub mod option;
pub mod schema;
pub mod transaction_blob;
pub mod value;

pub use diagnostic::DiagnosticCode;
pub use identity::{LocalKey, RelativePath, TransactionId};
pub use limits::{ABILITY_LIMITS_V1, LimitProfile, MAX_SAFE_INTEGER};
pub use option::{OptionEnumValue, OptionType, OptionVisibility};
pub use schema::*;
pub use transaction_blob::*;
pub use value::*;
