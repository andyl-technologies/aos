//! Inert models and authorization binding for the RFC-0021 `aos sandbox` surface.
//!
//! This module owns grammar validation, stable output/exit policy, and a
//! crate-private binding from authenticated transport evidence through current
//! protected authorization. It does not parse process arguments, register
//! commands or routes, dispatch effects, invoke services, or define a second
//! resource schema. A future activated CLI adapter can translate its checked
//! values to the established public protobuf client.

pub(crate) mod authorization_adapter;
pub mod execution;
pub mod grammar;
pub mod observation_adapter;
pub mod output;
pub mod proto_json;
pub mod provenance;
pub mod requests;

pub use execution::*;
pub use grammar::*;
pub use observation_adapter::*;
pub use output::*;
pub use proto_json::*;
pub use provenance::*;
pub use requests::*;
