//! Checked block-storage resource providers.
//!
//! The shared engine validates the command-handler protocol and delegates only
//! exact device inspection and mutation to the cryptsetup, util-linux, and
//! OpenZFS backends. Each backend is exposed as a separate package-owned executable.

#![forbid(unsafe_code)]

pub mod cryptsetup;
pub mod engine;
pub mod process;
pub mod state;
pub mod storage_format;
pub mod storage_provisioning;
pub mod zfs_dataset;
pub mod zfs_memory;
pub mod zfs_pool;
