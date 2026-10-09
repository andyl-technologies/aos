//! Retained boot operations for AOS image activation and initrd recovery.
//!
//! The `commands` module exposes installed entry points with `boot-tools` enabled.
//! Image staging,
//! measurement evidence, paired recovery payloads, firmware selection, and
//! journal-owned store transport share one implementation here. [`preparation`]
//! executes authenticated transaction-scoped preparation artifacts.
//!
//! Systemd service and credential operations belong to `aos-activation-systemd`.
//! Executable names and durable boot formats remain independent of Cargo names.

#![forbid(unsafe_code)]

#[cfg(feature = "boot-tools")]
pub mod commands;
pub mod preparation;

#[cfg(feature = "boot-tools")]
mod boot_platform;
#[cfg(feature = "boot-tools")]
mod boot_storage;
#[cfg(feature = "boot-tools")]
mod image_profile;
#[cfg(feature = "boot-tools")]
mod image_stage;
#[cfg(feature = "boot-tools")]
mod initrd_archive;
#[cfg(feature = "boot-tools")]
mod initrd_store;
#[cfg(feature = "boot-tools")]
mod measurement_index;
mod process;
#[cfg(feature = "boot-tools")]
mod recovery;
#[cfg(feature = "boot-tools")]
mod store_closure;
