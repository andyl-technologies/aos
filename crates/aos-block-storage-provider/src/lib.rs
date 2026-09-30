//! Checked block-storage resource providers.
//!
//! Native invocation handlers own exact device inspection and mutation through
//! retained cryptsetup, util-linux, systemd, and OpenZFS executables. Pool imports
//! and dataset mounts are removable leases; committed disk layouts retain their
//! durable provenance until an explicit factory reset.

#![forbid(unsafe_code)]

pub mod boot_transaction_storage;
pub mod native_provisioning_marker;
pub mod native_storage_format;
pub mod native_storage_provisioning;
pub mod process;
pub mod zfs_maintenance;
pub mod zfs_memory;

pub mod native_cryptsetup;
pub mod native_state;

pub mod native_zfs_dataset;
pub mod native_zfs_pool;
