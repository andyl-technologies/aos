//! Reconstructs inert native eleven owners with separately admitted alias groups.
//!
//! Historical keys, proofs and registration data never create a current native
//! issuer. Fresh service enrollment remains source-installed and independently
//! authenticated after the complete signed archive and target context checks.

mod boot;
mod bytes;
pub mod policy;
mod proof;
mod shared;

pub mod identity;
pub mod token;

pub mod registrar;

pub mod bootstrap;

pub mod blob;

pub mod connection;
pub mod outer;
pub mod service;
