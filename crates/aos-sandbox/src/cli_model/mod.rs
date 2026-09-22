//! Inert models and authorization binding for the RFC-0021 `aos sandbox` surface.
//!
//! This module owns grammar validation, stable output/exit policy, and a
//! crate-private binding from authenticated transport evidence through current
//! protected authorization. The dormant routing module accepts parser output
//! and constructs typed in-process requests, but registers no controller route,
//! dispatches no effect, and invokes no service.

#[cfg(target_os = "linux")]
pub(crate) mod authorization_adapter;
pub mod continuation;
pub mod execution;
pub mod grammar;
pub mod observation_adapter;
pub mod output;
pub mod proto_json;
pub mod provenance;
pub mod requests;
pub mod routing;

pub use continuation::*;
pub use execution::*;
pub use grammar::*;
pub use observation_adapter::*;
pub use output::*;
pub use proto_json::*;
pub use provenance::*;
pub use requests::*;
pub use routing::*;
