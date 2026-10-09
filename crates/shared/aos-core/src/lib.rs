//! Portable primitives shared by AOS applications and data formats.
//!
//! This crate owns strict canonical [`json`], typed content [`digest`] values,
//! bounded document decoding in [`limits`], and bounded local names in
//! [`identity`]. It performs no filesystem, network, process, clock, credential,
//! or terminal I/O. Domain schemas and execution policy belong to their owners.

#![forbid(unsafe_code)]

pub mod digest;
pub mod identity;
pub mod json;
pub mod limits;

pub use digest::Sha256Digest;
