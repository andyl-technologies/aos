//! Projects the installed runtime's resource manifest and selected worker mask.
//!
//! These values describe existing retained callbacks, mapping and descriptors.
//! They issue no ownership, allocation credit or permission to install a worker.
// SPDX-License-Identifier: GPL-2.0-only

use super::worker_quiescence::{WORKER_FINGERPRINT, WORKER_REQUIRED};
use super::{PluginRuntimeInstallError, RequiredOwnedCallbacksRegistered};
use crate::{PluginArgs, QemuPluginId};

pub(super) const PLUGIN_RESOURCE_MANIFEST_VERSION: u32 = 3;
pub(super) const PLUGIN_RESOURCE_REQUIRED: u64 = (1_u64 << 10) - 1;
const PLUGIN_RESOURCE_COVERAGE: u64 = 1_u64 << 10;
const PLUGIN_RESOURCE_WHITEBOX: u64 = 1_u64 << 11;
pub(super) const PLUGIN_RESOURCE_FINGERPRINT: u64 = 1_u64 << 12;
const PLUGIN_RESOURCE_APP_RANDOM: u64 = 1_u64 << 14;
pub(super) const PLUGIN_CALLBACK_REQUIRED: u64 = ((1_u64 << 12) - 1) & !(1_u64 << 1);
const PLUGIN_CALLBACK_TB_TRANSLATION: u64 = 1_u64 << 12;
const PLUGIN_CALLBACK_FLUSH: u64 = 1_u64 << 13;

/// Projects the selected workers without changing their retained owner.
pub(super) fn plugin_worker_mask(args: &PluginArgs) -> u64 {
    WORKER_REQUIRED | (u64::from(args.fingerprint().is_on()) * WORKER_FINGERPRINT)
}

/// Projects the installed callback resources for native registration.
///
/// # Errors
/// Refuses a missing registered wake descriptor or an unrepresentable ABI size.
pub(super) fn plugin_resource_manifest(
    plugin_id: QemuPluginId,
    args: &PluginArgs,
    callbacks: &RequiredOwnedCallbacksRegistered,
) -> Result<crate::QemuPluginResourceManifest, PluginRuntimeInstallError> {
    let setup = callbacks.setup();
    let node_count = setup.mapped_region().header_snapshot().node_count;
    let wake_fd = setup
        .registered_wake_fd()
        .ok_or(PluginRuntimeInstallError::ResourceManifestShape)?
        .as_raw_fd();
    let struct_size = u32::try_from(std::mem::size_of::<crate::QemuPluginResourceManifest>())
        .map_err(|_error| PluginRuntimeInstallError::ResourceManifestShape)?;

    let mut resource_mask = PLUGIN_RESOURCE_REQUIRED;
    let mut callback_mask = PLUGIN_CALLBACK_REQUIRED;
    let worker_mask = callbacks.state.as_ref().get_ref().workers.worker_mask();
    if args.coverage().is_on() {
        resource_mask |= PLUGIN_RESOURCE_COVERAGE;
        callback_mask |= PLUGIN_CALLBACK_TB_TRANSLATION | PLUGIN_CALLBACK_FLUSH;
    }
    if args.whitebox().is_on() {
        resource_mask |= PLUGIN_RESOURCE_WHITEBOX;
        callback_mask |= PLUGIN_CALLBACK_TB_TRANSLATION;
    }
    if args.fingerprint().is_on() {
        resource_mask |= PLUGIN_RESOURCE_FINGERPRINT;
    }
    if args.app_random().is_some() {
        resource_mask |= PLUGIN_RESOURCE_APP_RANDOM;
    }

    Ok(crate::QemuPluginResourceManifest {
        schema_version: PLUGIN_RESOURCE_MANIFEST_VERSION,
        struct_size,
        process_generation: args.process_generation(),
        plugin_id,
        resource_mask,
        callback_mask,
        worker_mask,
        shmem_device: setup.shared_memory_device(),
        shmem_inode: setup.shared_memory_inode(),
        shmem_length: setup.mapped_region().region_len(),
        slot_index: args.slot(),
        node_count,
        control_fd: args.sim_fd(),
        wake_fd,
    })
}
