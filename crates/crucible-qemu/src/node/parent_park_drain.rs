//! Verifies the fixed family parent's actual retained Node registration.
//!
//! A matching target is a necessary ownership check before stage publication;
//! it does not issue a phase, native hold, process contract or original guard.

use crucible_linux_resource::ram_policy::{HostRamPolicyError, HostRamTarget};

use super::QemuNode;

impl QemuNode {
    /// Checks the family issuer's parent against this Node's actual RAM owner.
    ///
    /// The fixed factory selects the expected target from its private admitted
    /// initial assignment. This comparison exposes no target or account getter
    /// and performs no stage publication or native effect.
    ///
    /// # Errors
    /// Refuses an absent registration or any different parent incarnation,
    /// mapping generation, owner, node, daemon epoch or template designation.
    pub fn verify_original_park_parent(
        &self,
        expected: &HostRamTarget,
    ) -> Result<(), HostRamPolicyError> {
        let registration = self
            .host_io_runtime
            .ram_control_registration()
            .ok_or(HostRamPolicyError::NotCurrent)?;
        if registration.target != *expected {
            return Err(HostRamPolicyError::NotCurrent);
        }
        Ok(())
    }
}

impl QemuNode {
    pub(crate) fn verify_original_park_binding(
        &self,
        host: &crate::LinuxQemuAttemptHostOwner,
        decoder: &crate::OriginalActorParkCaller,
        original: &std::sync::Arc<crucible_linux_resource::host_supervision::HostOperationGuard>,
    ) -> Result<(), crate::OriginalActorParkQuiescenceError> {
        use crate::OriginalActorParkQuiescenceError;

        let binding = self.original_native_binding.as_ref().ok_or_else(|| {
            OriginalActorParkQuiescenceError::Binding {
                first: crate::OriginalActorAccountError::Unavailable,
                original_after: original.wait_slice().err(),
            }
        })?;
        host.verify_original_park_binding(binding, decoder, original)
            .map_err(|first| OriginalActorParkQuiescenceError::Binding {
                first,
                original_after: original.wait_slice().err(),
            })?;
        host.process_contract()
            .map_err(|first| OriginalActorParkQuiescenceError::Contract {
                first,
                original_after: original.wait_slice().err(),
            })?;
        Ok(())
    }

    pub(crate) fn enter_original_park_quiescence(
        &self,
        host: &crate::LinuxQemuAttemptHostOwner,
        decoder: &crate::OriginalActorParkCaller,
        original: &std::sync::Arc<crucible_linux_resource::host_supervision::HostOperationGuard>,
    ) -> Result<crate::OriginalActorParkQuiescence, crate::OriginalActorParkQuiescenceError> {
        let binding = self.original_native_binding.as_ref().ok_or_else(|| {
            crate::OriginalActorParkQuiescenceError::Binding {
                first: crate::OriginalActorAccountError::Unavailable,
                original_after: original.wait_slice().err(),
            }
        })?;
        host.enter_original_park_quiescence(binding, decoder, original)
    }

    pub(crate) fn pause_for_parent_park(
        &mut self,
        actor: &crucible_linux_resource::host_supervision::HostOperationGuard,
        family: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<u64, crate::OriginalParkSourceError> {
        self.host_io_runtime
            .quiesce_for_parent_park_under_originals(actor, family)?;
        Ok(self
            .channels
            .qmp_machine_control
            .parent_park_stopped_generation(actor, family)?)
    }
}

impl QemuNode {
    pub(crate) fn prepare_original_park_imports(
        &self,
        host: &crate::LinuxQemuAttemptHostOwner,
        decoder: &crate::OriginalActorParkCaller,
        original: &std::sync::Arc<crucible_linux_resource::host_supervision::HostOperationGuard>,
        actor: &crucible_linux_resource::host_supervision::HostOperationGuard,
        family: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<crate::OriginalActorParkImports, crate::OriginalActorParkImportError> {
        let binding = self
            .original_native_binding
            .as_ref()
            .ok_or(crate::OriginalActorAccountError::Unavailable)?;
        host.verify_original_park_binding(binding, decoder, original)?;
        decoder.prepare_park_imports(original, actor, family, host.process_contract()?)
    }

    pub(crate) fn acquire_parent_park(
        &mut self,
        imports: &crate::OriginalActorParkImports,
        correlation: u64,
        stopped: u64,
        actor: &crucible_linux_resource::host_supervision::HostOperationGuard,
        family: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<crate::QmpParentParkDrainReceipt, crate::QmpError> {
        use crate::qmp::parent_park_drain::ParentParkDrainRequest;
        self.channels
            .qmp_machine_control
            .parent_park_import(imports, actor, family)?;
        self.channels.qmp_machine_control.parent_park_command(
            ParentParkDrainRequest::Acquire {
                correlation,
                stopped,
                basis: &imports.basis_name,
                cancellation: &imports.cancellation_name,
            },
            actor,
            family,
        )
    }

    pub(crate) fn retained_parent_park(
        &mut self,
        retained: &crate::QmpParentParkDrainReceipt,
        relinquish: bool,
        actor: &crucible_linux_resource::host_supervision::HostOperationGuard,
        family: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<crate::QmpParentParkDrainReceipt, crate::QmpError> {
        use crate::qmp::parent_park_drain::ParentParkDrainRequest;
        let request = if relinquish {
            ParentParkDrainRequest::Relinquish {
                correlation: retained.request_correlation,
                stopped: retained.stopped_generation,
                generation: retained.generation,
            }
        } else {
            ParentParkDrainRequest::Query {
                correlation: retained.request_correlation,
                stopped: retained.stopped_generation,
                generation: retained.generation,
            }
        };
        self.channels
            .qmp_machine_control
            .parent_park_command(request, actor, family)
    }
}
