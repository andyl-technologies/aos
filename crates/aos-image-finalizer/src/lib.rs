//! External final-byte assembly contracts for production AOS images.
//!
//! Nix emits a closed [`assembly::UnsignedImageAssemblyV1`] containing only
//! deterministic inputs, public trust material, and exact AOS-built tools.
//! Effectful coordinator code signs and assembles those inputs outside the Nix
//! store, then records a [`result::FinalizedImageSetV1`]. This crate validates
//! both sides of that boundary and never represents private key material.
//!
//! # Module map
//!
//! - [`assembly`] defines the unsigned, public-only input closure.
//! - [`capture`] captures a Nix assembly without following filesystem links.
//! - [`input`] revalidates captured files and tools at their point of use.
//! - [`module_signature`] verifies the kernel's appended PKCS#7 format.
//! - [`request`] constrains signing requests supplied by the coordinator.
//! - [`signer`] defines the effect boundary used by external key providers.
//! - [`tools`] invokes only assembly-pinned executables with bounded evidence.
//! - [`result`] defines the complete two-slot, four-format finalized output.

#![forbid(unsafe_code)]

pub mod assembly;
pub mod capture;
pub mod input;
pub mod module_signature;
pub mod request;
pub mod result;
pub mod signer;
pub mod tools;
