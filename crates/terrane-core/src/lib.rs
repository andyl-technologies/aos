//! Owns Terrane's pure formats and identity-producing algorithms.
//!
//! This crate uses only `core` and `alloc` and performs no I/O, clock reads,
//! environment access, or task spawning (CRATE-1, CRATE-21). The [`boundary`]
//! module contains the T0 prolly-boundary experiment for specification 06.
//! Identity formats, codecs, tree operations, and token verification from
//! specification 04-09, 22, and 31 are added by their implementation tasks;
//! the foundation does not claim those conformance gates (CRATE-2, CRATE-4).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod boundary;
pub mod cbor;
pub mod chunking;
pub mod codec;
pub mod identity;
pub mod tree_format;
