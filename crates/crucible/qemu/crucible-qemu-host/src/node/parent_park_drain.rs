//! Verifies the fixed family parent's actual retained Node registration.
//!
//! A matching target is a necessary ownership check before stage publication;
//! it does not issue a phase, native hold, process contract or original guard.

use crucible_host_resources::ram_policy::{HostRamPolicyError, HostRamTarget};

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
        original: &std::sync::Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
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
        original: &std::sync::Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
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
        actor: &crucible_host_resources::host_supervision::HostOperationGuard,
        family: &crucible_host_resources::host_supervision::HostOperationGuard,
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
        original: &std::sync::Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
        actor: &crucible_host_resources::host_supervision::HostOperationGuard,
        family: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<crate::OriginalActorParkImports, crate::OriginalActorParkImportError> {
        let binding = self
            .original_native_binding
            .as_ref()
            .ok_or(crate::OriginalActorAccountError::Unavailable)?;
        host.verify_original_park_binding(binding, decoder, original)?;
        decoder.prepare_park_imports(original, actor, family, host.process_contract()?)
    }

    pub(crate) fn begin_parent_park(
        &mut self,
        imports: &crate::OriginalActorParkImports,
        correlation: u64,
        stopped: u64,
        actor: &crucible_host_resources::host_supervision::HostOperationGuard,
        family: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<crate::QmpParentParkResult, crate::QmpError> {
        use crate::qmp::parent_park_drain::ParentParkRequest;
        let source_action = self
            .host_io_runtime
            .begin_parent_park_action(correlation, actor, family)
            .map_err(|error| crate::QmpError::OperationalRuntime {
                operation: "retain canonical parent Park request",
                source: error,
            })?;
        self.channels
            .qmp_machine_control
            .prepare_parent_park_begin(source_action, stopped, actor, family)?;
        self.channels
            .qmp_machine_control
            .parent_park_import(imports, actor, family)?;
        let current = self
            .host_io_runtime
            .current_parent_park_action()
            .map_err(|error| crate::QmpError::OperationalRuntime {
                operation: "recheck canonical parent Park request after imports",
                source: error,
            })?;
        if current != source_action {
            return Err(crate::QmpError::InvalidBound {
                operation: "parent Park canonical request changed during imports",
            });
        }
        self.channels.qmp_machine_control.parent_park_begin(
            ParentParkRequest::Begin {
                binding: source_action,
                stopped,
                basis: &imports.basis_name,
                cancellation: &imports.cancellation_name,
            },
            actor,
            family,
        )
    }

    pub(crate) fn return_parent_park(
        &mut self,
        cleanup: &crate::OriginalParentParkCleanup,
    ) -> Result<crate::QmpParentParkResult, crate::QmpError> {
        let native_binding =
            self.original_native_binding
                .as_ref()
                .ok_or(crate::QmpError::InvalidBound {
                    operation: "parent Park Cleanup lacks actual Node binding",
                })?;
        cleanup
            .verify_node(native_binding)
            .map_err(|_| crate::QmpError::InvalidBound {
                operation: "parent Park Cleanup belongs to another original account",
            })?;
        // Read the retained selector by identity. Cancellation may prohibit new
        // work, but cannot substitute another request or prevent owned cleanup.
        let binding = self.host_io_runtime.retained_parent_park_action().ok_or(
            crate::QmpError::InvalidBound {
                operation: "parent Park retained selector absent",
            },
        )?;
        let receipt = self
            .channels
            .qmp_machine_control
            .parent_park_return(binding, cleanup.guard())?;
        self.settle_parent_park_receipt(receipt)
    }

    pub(crate) fn return_parent_park_under_originals(
        &mut self,
        actor: &crucible_host_resources::host_supervision::HostOperationGuard,
        family: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<crate::QmpParentParkResult, crate::QmpError> {
        let binding = self.host_io_runtime.retained_parent_park_action().ok_or(
            crate::QmpError::InvalidBound {
                operation: "parent Park retained selector absent",
            },
        )?;
        let receipt = self
            .channels
            .qmp_machine_control
            .parent_park_return_under_originals(binding, actor, family)?;
        self.settle_parent_park_receipt(receipt)
    }

    fn settle_parent_park_receipt(
        &mut self,
        mut receipt: crate::QmpParentParkResult,
    ) -> Result<crate::QmpParentParkResult, crate::QmpError> {
        if let Some(closed) = receipt.closed_request {
            match self.host_io_runtime.finish_parent_park_action(&closed) {
                Ok(returned) => receipt.host_memberships_returned = returned,
                Err(first) => receipt.host_return_after = Some(first),
            }
        }
        Ok(receipt)
    }
}
