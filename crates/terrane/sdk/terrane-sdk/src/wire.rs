//! Generates the Distribution contract without mixing wire data with authority.
//!
//! [`v1`] contains the RFC's protobuf messages, borrowed views and canonical
//! ProtoJSON codecs. With the native binding enabled, `services` supplies
//! generated clients and native service traits. Implementing
//! a trait or decoding a message establishes no authorization, verified content
//! identity, native custody or publication acknowledgement.

/// Checks complete canonical ref records against their redundant wire summaries.
pub mod refs;

/// Receives ordered pack frames without admitting or acknowledging their bytes.
pub mod upload;

/// Maps classified service outcomes to structured protocol errors.
pub mod status;

/// Authenticates native capability headers without granting repository access.
#[cfg(feature = "tokio")]
pub mod authentication;

/// Binds complete native services to bounded loopback or TLS 1.3 listeners.
#[cfg(feature = "tokio")]
pub mod transport;

/// Contains generated `terrane.v1` protobuf and ProtoJSON data contracts.
#[allow(
    clippy::derivable_impls,
    clippy::match_single_binding,
    reason = "The schema generator uses uniform enum defaults and field dispatch, including empty messages."
)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/terrane.v1.rs"));
}

/// Contains native service contracts over the same portable message types.
#[cfg(feature = "tokio")]
#[allow(
    clippy::match_single_binding,
    reason = "Generated service dispatch retains a uniform fallback for method categories with no members."
)]
pub mod services {
    include!(concat!(env!("OUT_DIR"), "/native/terrane.v1.rs"));
}

/// Retains the compiled schema for interoperability and descriptor inspection.
pub const DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/terrane.v1.bin"));
