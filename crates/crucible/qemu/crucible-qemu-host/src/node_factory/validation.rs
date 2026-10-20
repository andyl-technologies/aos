//! Shared-memory slot validation for QEMU node assembly.

use super::*;

pub(super) fn validate_setup_slot_matches_config(
    setup: &QemuHostPluginSetup,
    shmem_config: &QemuQuantumShmemConfig,
) -> Result<(), QemuNodeFactoryError> {
    let setup_slot = setup.negotiated_handshake().slot_index;
    if setup_slot != shmem_config.vm_slot {
        return Err(QemuNodeFactoryError::SetupSlotMismatch {
            setup_slot,
            shmem_slot: shmem_config.vm_slot,
        });
    }
    Ok(())
}
