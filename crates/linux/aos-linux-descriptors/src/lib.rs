//! Linux descriptor, peer identity and immutable-credential mechanics.
//!
//! This crate owns native process pins, connected Unix endpoint correlation,
//! bounded kernel-boot identity, positional hashing and sealed read-only files.
//! Kernel evidence grants no application role, service policy or authority.
//! Callers retain their real descriptors and independently apply those policies.

#![cfg(target_os = "linux")]

mod error;
mod immutable_file_error;
pub use error::{Error, Result};
pub use immutable_file_error::ImmutableFileError;
pub mod boot;
pub mod credential;
pub mod native;
pub mod object_context;
pub mod pidfd;
pub mod positional_hash;
pub mod unix_stream;
