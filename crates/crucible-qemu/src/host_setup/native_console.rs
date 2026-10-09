//! Installed console admission from the actual spawn owner and committed setup.
//!
//! Capability bytes are accepted only after original READY reception. Native
//! resolution belongs to the matching installed implementation; this host join
//! checks its immutable released projection against the sealed launch plan and
//! real descriptor backing. It grants no runnable or restored phase by itself.

use crucible_protocol::native_console::{
    NativeConsoleCapability, NativeConsoleError, NativeConsoleSetupPlan,
};
use crucible_shmem::{MappedSetupRegion, SetupRegionBackingIdentity};

use super::QemuHostPluginSetupError;

/// Retains one original installation, without fabricating a phase receipt.
#[derive(Debug)]
pub(crate) struct InstalledConsoleAdmission {
    pub(crate) plan: NativeConsoleSetupPlan,
    pub(crate) capability: NativeConsoleCapability,
    pub(crate) backing: SetupRegionBackingIdentity,
}

pub(crate) fn accept_installation(
    region: &MappedSetupRegion,
    slot: u32,
    expected_process: u64,
    declared: Option<&NativeConsoleSetupPlan>,
) -> Result<Option<InstalledConsoleAdmission>, NativeConsoleError> {
    let Some(declared) = declared else {
        return Ok(None);
    };
    let plan = declared.plan();
    if expected_process == 0 || plan.slot != slot || plan.streams.len() != 1 {
        return Err(NativeConsoleError::Binding);
    }
    let stream = &plan.streams[0];
    if stream.stream != 1 || stream.device_identity != stream.device.fixed_console_identity() {
        return Err(NativeConsoleError::Plan);
    }

    let backing = region.backing_identity();
    let mut physical_region = [0; 16];
    physical_region[..8].copy_from_slice(&backing.device().to_le_bytes());
    physical_region[8..].copy_from_slice(&backing.inode().to_le_bytes());
    let capability = region.native_console_segment(slot)?.capability.copy()?;
    if capability.slot != slot
        || capability.region != physical_region
        || capability.process != expected_process
        || capability.plan_hash != plan.digest()?
        || capability.resolved_streams != plan.resolved_streams_digest()?
    {
        return Err(NativeConsoleError::Binding);
    }
    Ok(Some(InstalledConsoleAdmission {
        plan: declared.clone(),
        capability,
        backing,
    }))
}

#[cfg(test)]
mod tests;

/// Encodes a console-bearing plan once before any transfer or admission effect.
///
/// Ordinary no-console completion keeps its original encode point/order. The
/// digest only binds the transferred body to the real command; it grants no
/// native phase or runtime authority.
pub(super) fn encoded_console_plan_if_bound(
    plan: &crucible_protocol::plugin_setup_plan::PluginSetupPlan,
    expected: Option<[u8; 32]>,
) -> Result<Option<Vec<u8>>, QemuHostPluginSetupError> {
    if expected.is_none() && plan.native_console_plan().is_none() {
        return Ok(None);
    }
    let bytes = plan
        .encode()
        .map_err(|source| QemuHostPluginSetupError::PluginSetupPlan { source })?;
    let observed = *blake3::hash(&bytes).as_bytes();
    if expected != Some(observed) {
        return Err(QemuHostPluginSetupError::NativeConsoleLaunchPlan { expected, observed });
    }
    Ok(Some(bytes))
}
