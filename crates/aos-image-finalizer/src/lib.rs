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
//! - [`bundle`] seals image metadata and the signed recovery bundle.
//! - [`capture`] captures a Nix assembly without following filesystem links.
//! - [`filesystem`] reconstructs deterministic EROFS and initrd bytes.
//! - [`disk`] constructs and verifies the canonical GPT/ESP layout.
//! - [`finalize`] sequences effectful signing and reconstruction stages.
//! - [`formats`] derives download encodings and proves round-trip identity.
//! - [`input`] revalidates captured files and tools at their point of use.
//! - [`module_signature`] verifies the kernel's appended PKCS#7 format.
//! - [`pcr`] constructs and independently verifies signed PCR policy JSON.
//! - [`pipeline`] produces the complete finalized image set in one operation.
//! - [`request`] constrains signing requests supplied by the coordinator.
//! - [`recovery`] binds normal slots into signed recovery initrds.
//! - [`signer`] defines the effect boundary used by external key providers.
//! - [`tools`] invokes only assembly-pinned executables with bounded evidence.
//! - [`uki`] assembles and verifies signed normal/recovery EFI artifacts.
//! - [`verity`] derives and independently verifies finalized dm-verity data.
//! - [`result`] defines the complete two-slot, four-format finalized output.

#![forbid(unsafe_code)]

pub mod assembly;
pub mod bundle;
pub mod capture;
pub mod disk;
pub mod filesystem;
pub mod finalize;
pub mod formats;
pub mod input;
pub mod module_signature;
pub mod pcr;
pub mod pipeline;
pub mod recovery;
pub mod request;
pub mod result;
pub mod signer;
pub mod tools;
pub mod uki;
pub mod verity;
