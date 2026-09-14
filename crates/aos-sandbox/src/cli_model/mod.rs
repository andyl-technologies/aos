//! Inert, pure models for the RFC-0021 `aos sandbox` command surface.
//!
//! This module owns grammar validation and stable output/exit policy only. It
//! does not parse process arguments, perform I/O, invoke services, or define a
//! second resource schema. A future CLI adapter can translate its checked
//! values to the established public protobuf client.

pub mod execution;
pub mod grammar;
pub mod output;
pub mod proto_json;
pub mod provenance;
pub mod requests;

pub use execution::*;
pub use grammar::*;
pub use output::*;
pub use proto_json::*;
pub use provenance::*;
pub use requests::*;
