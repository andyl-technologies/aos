//! Closed native console plan derived from the actual launch topology.
//!
//! The fixed backend and stream binding describe intended installation. Native
//! QOM resolution, committed READY and original phase owners must authenticate
//! it before any byte can be accepted; this plan grants none of those owners.

use crucible_protocol::native_console::{
    NativeConsoleDevice, NativeConsolePlan, NativeConsoleSetupPlan, NativeConsoleStream,
};
use crucible_shmem::FaultCapabilityScope;

use super::QemuLaunchCommandError;

pub(super) const NATIVE_CONSOLE_CHARDEV_ARGUMENT: &str = "crucible-console,id=crucible-console";

// The issued-body inventory is independent of the byte-ring capacity. Both
// bounds are encoded in setup and hashed with the command, before guest start.
const ISSUED_AUTHORIZATION_CAPACITY: u32 = 256;
const AUTHORIZATION_BYTE_ALLOWANCE: u32 = 4096;

pub(super) fn closed_launch_plan(
    architecture: FaultCapabilityScope,
    vcpus: u16,
    slot: u32,
) -> Result<NativeConsoleSetupPlan, QemuLaunchCommandError> {
    if !(1..=64).contains(&vcpus) {
        return Err(QemuLaunchCommandError::InvalidNativeConsoleProfile);
    }
    let device = match architecture {
        FaultCapabilityScope::X86_64 => NativeConsoleDevice::Serial16550,
        FaultCapabilityScope::Aarch64 => NativeConsoleDevice::Pl011,
        _ => return Err(QemuLaunchCommandError::InvalidNativeConsoleProfile),
    };
    let owner_mask = if vcpus == 64 {
        u64::MAX
    } else {
        (1_u64 << vcpus) - 1
    };
    let plan = NativeConsolePlan {
        slot,
        logical_generation: 0,
        node_sequence_base: 0,
        streams: vec![NativeConsoleStream {
            stream: 1,
            device,
            device_identity: device.fixed_console_identity(),
            owner_mask,
            sequence_base: 0,
        }],
    };
    NativeConsoleSetupPlan::new(
        plan,
        ISSUED_AUTHORIZATION_CAPACITY,
        AUTHORIZATION_BYTE_ALLOWANCE,
    )
    .map_err(|_source| QemuLaunchCommandError::InvalidNativeConsoleProfile)
}

#[cfg(test)]
mod tests;
