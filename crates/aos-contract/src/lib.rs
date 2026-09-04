//! Shared pure primitives for versioned AOS data contracts.
//!
//! This crate owns the canonical JSON dialect, typed content identities, and
//! bounded decoding used by contracts that cross AOS trust boundaries. It
//! performs no filesystem, network, process, clock, or credential I/O.
//!
//! # Module map
//!
//! - [`canonical`] parses strict JSON and produces canonical bytes.
//! - [`digest`] defines typed, domain-separated SHA-256 identities.
//! - [`limits`] applies explicit byte and structural limits before decoding.

#![forbid(unsafe_code)]

pub mod canonical;
pub mod digest;
pub mod limits;

pub use digest::Sha256Digest;
