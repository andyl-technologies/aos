//! Owns host-cache policy and checked sealed-object publication (specification 14).
//!
//! The cache retains encoded content through the existing store interface.
//! Publication verifies assembled plaintext separately from manifest identity.
//! Kernel mechanisms remain in the Linux adapter crate (CRATE-10).

pub mod cache;
pub mod publication;
