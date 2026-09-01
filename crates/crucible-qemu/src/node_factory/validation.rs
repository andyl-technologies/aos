//! Restore authorization and shared-memory slot validation.

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

pub(super) fn validate_runtime_restore_authorization(
    authorization: QemuLoadvmCommandAuthorization,
    admission: QemuNodeRestoreAdmission,
) -> Result<(), QemuNodeFactoryError> {
    let purpose = authorization.purpose();
    match (purpose, admission) {
        (
            QemuLoadvmCommandPurpose::RuntimeRealization,
            QemuNodeRestoreAdmission::ReplayOracle(admission),
        ) => {
            let _admitted_runtime_hash = admission.runtime_hash();
            Ok(())
        }
        (
            QemuLoadvmCommandPurpose::RuntimeRealization,
            QemuNodeRestoreAdmission::CapturedExact { execution_binding },
        ) => {
            let _execution_binding = execution_binding;
            Ok(())
        }
        (
            QemuLoadvmCommandPurpose::BakedGenesisRealization,
            QemuNodeRestoreAdmission::BakedGenesis { world_id },
        ) => {
            let _admitted_world_id = world_id;
            Ok(())
        }
        (
            QemuLoadvmCommandPurpose::ReplayOracleProbe,
            QemuNodeRestoreAdmission::ReplayOracleProbe,
        ) => Ok(()),
        (purpose, _) => Err(QemuNodeFactoryError::VmStateRestoreAuthorization { purpose }),
    }
}
