//! Exact inventory custody for the strict-child native kernel fixture.
//!
//! The wrapper preserves the original registry admission and retirement route.
//! Only initial validation is specialized; no live capability is advertised.

use super::*;
use crucible_protocol::ram_control::{RamControlError, RamControlFaultActorReport};
use crucible_qemu::ram_control::{
    RamControlClient, RamControlRegistrar, RamControlRetirementAuthority, RamInventoryAdmission,
};

pub(super) struct NativeInitialRegistrar {
    registry: HostOperationalRegistry,
    admitted: Mutex<Option<(HostRamTarget, HostResourceVector)>>,
}

impl NativeInitialRegistrar {
    pub(super) fn new(registry: HostOperationalRegistry) -> Self {
        Self {
            registry,
            admitted: Mutex::new(None),
        }
    }
}

impl RamControlRegistrar for NativeInitialRegistrar {
    fn admit_inventory(
        &self,
        admission: RamInventoryAdmission<'_>,
    ) -> Result<HostResourceVector, RamControlError> {
        let mut admitted = self
            .admitted
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        if admitted.is_some() {
            return Err(RamControlError::AuthorityMismatch);
        }
        let resources = self.registry.admit_inventory(admission)?;
        *admitted = Some((admission.target, resources));
        Ok(resources)
    }

    fn register(
        &self,
        target: HostRamTarget,
        policy: HostRamPolicy,
        resources: HostResourceVector,
        supervisor: HostOperationSupervisor,
        client: Option<RamControlClient>,
    ) -> Result<(), RamControlError> {
        let admitted = self
            .admitted
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        if *admitted != Some((target, resources)) {
            return Err(RamControlError::AuthorityMismatch);
        }
        self.registry
            .register_native_resident_initial(target, policy, resources, supervisor, client)
    }

    fn fault_actor_status(
        &self,
        target: HostRamTarget,
    ) -> Result<Option<RamControlFaultActorReport>, RamControlError> {
        self.registry.fault_actor_status(target)
    }

    fn native_paging_health(
        &self,
        target: HostRamTarget,
    ) -> Result<
        (
            Option<crucible_protocol::ram_control::RamControlFaultActorReport>,
            Option<crucible_protocol::ram_control::RamControlOperationFailure>,
        ),
        RamControlError,
    > {
        self.registry.native_paging_health(target)
    }

    fn retirement_authority(
        &self,
        target: HostRamTarget,
    ) -> Result<Arc<dyn RamControlRetirementAuthority>, RamControlError> {
        self.registry.retirement_authority(target)
    }

    fn retire_after_cleanup(&self, target: HostRamTarget) -> Result<(), RamControlError> {
        self.registry.retire_after_cleanup(target)
    }

    fn prepare_retirement_after_cleanup(
        &self,
        target: HostRamTarget,
    ) -> Result<(), RamControlError> {
        self.registry.prepare_retirement_after_cleanup(target)
    }

    fn retire_unpublished_after_cleanup(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), RamControlError> {
        self.registry
            .retire_unpublished_after_cleanup(target, resources)
    }

    fn quarantine_unpublished(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), RamControlError> {
        self.registry.quarantine_unpublished(target, resources)
    }
}
