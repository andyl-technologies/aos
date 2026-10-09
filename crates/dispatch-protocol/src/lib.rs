//! Portable model interchange and bounded process protocols for Dispatch.
//!
//! [`wire`] contains checked-in Protobuf messages, [`framing`] supplies reusable
//! synchronous and asynchronous transports, and [`negotiation`] checks version
//! and generation bindings. [`json`] imports exact typed data without silently
//! accepting duplicate keys. [`canonical`] commits immutable validated models.

#![forbid(unsafe_code)]

pub mod canonical;
pub mod framing;
pub mod json;
pub mod negotiation;
pub mod reports;
pub mod request;
pub mod wire;

mod error;
mod preflight;

pub use error::ProtocolError;

/// Bounds frames before peers have negotiated their resource limits.
pub const INITIAL_MAX_FRAME_BYTES: u32 = 65_536;

/// Identifies the supported private worker protocol.
pub const WORKER_VERSION: wire::Version = wire::Version { major: 1, minor: 0 };

/// Identifies the supported allocation model semantics.
pub const MODEL_VERSION: wire::Version = wire::Version { major: 1, minor: 0 };
