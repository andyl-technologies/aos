//! Inert models and authorization binding for the RFC-0021 `aos sandbox` surface.
//!
//! This module owns grammar validation, stable output/exit policy, and a
//! crate-private binding from authenticated transport evidence through current
//! protected authorization. The routing envelope retains only Controller-adopted
//! requests with sealed authority. Protocol owns untrusted bounded public request
//! DATA and client proposals; neither boundary registers a route or dispatches effects.

#[cfg(target_os = "linux")]
pub(crate) mod authorization_adapter;
#[cfg(target_os = "linux")]
pub use authorization_adapter::PublicApiAuditMethodV1;
pub mod execution;
pub mod grammar;
pub mod observation_adapter;
pub mod output;
pub mod provenance;
#[cfg(target_os = "linux")]
pub mod public_mutation;
pub mod requests;
pub mod routing;

pub use execution::*;
pub use grammar::*;
pub use observation_adapter::*;
pub use output::*;
pub use provenance::*;
#[cfg(target_os = "linux")]
pub use public_mutation::*;
pub use requests::*;
pub use routing::*;
