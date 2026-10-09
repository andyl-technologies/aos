//! Actual Runtime custody for the Repair terminal continuation.
//!
//! The move-only frame retains the original runtime writer and physical root
//! descriptors. Its dispatch exclusion survives an unacknowledged drop; only
//! exact durable sidecar settlement may reopen ordinary method admission.

use sha2::{Digest as _, Sha256};

use super::{StorageBrokerRuntime, StorageRuntimeError, boottime_now_nanoseconds};
use crate::guest_root_inventory::{
    ProtectedGuestRootTemplateV1, attach_guest_root_publication_readback_v1,
};

pub(crate) struct OperatorRepairRuntimeHoldV4<'runtime> {
    runtime: &'runtime mut StorageBrokerRuntime,
    state_cut: [u8; 32],
    live_cut: [u8; 32],
}

impl StorageBrokerRuntime {
    /// Reinstalls the actual dispatch exclusion for an unresolved sidecar hold.
    pub(crate) fn retain_operator_terminal_exclusion(&self) -> Result<(), StorageRuntimeError> {
        self.worker_dispatch.begin_terminal_hold()
            .map_err(|_| StorageRuntimeError::Recovery)
    }

    pub(crate) fn hold_operator_terminal_inventory_v4<'runtime>(
        &'runtime mut self,
        expected: &[u8],
        deadline: u64,
        template: Option<&ProtectedGuestRootTemplateV1>,
        owner: &mut crate::operator_recovery::StorageOperatorRecoveryOwnerV1,
    ) -> Result<OperatorRepairRuntimeHoldV4<'runtime>, StorageRuntimeError> {
        let now = boottime_now_nanoseconds()?;
        let cutoff = deadline.checked_sub(1_000_000_000)
            .ok_or(StorageRuntimeError::Recovery)?;
        if self.requires_reopen()
            || (!self.readiness.permits_catalog_methods() && !self.has_deferred_operator_debt_v4())
            || now >= cutoff
            || !self.workspaces.as_ref()
                .is_some_and(|catalog| catalog.is_terminally_materialized())
        {
            return Err(StorageRuntimeError::Recovery);
        }
        self.worker_dispatch.begin_terminal_hold()
            .map_err(|_| StorageRuntimeError::Recovery)?;

        let cold_cut = if self.has_deferred_operator_debt_v4() {
            let startup = self.operator_startup.as_ref()
                .ok_or(StorageRuntimeError::Recovery)?;
            let refreshed = owner.refresh_operator_repair_startup_custody_v4(&startup.custody)?;
            if !matches!(&refreshed, crate::operator_recovery::OperatorRepairStartupCustodyV4::Unresolved(_)) {
                return Err(StorageRuntimeError::Recovery);
            }
            owner.recheck_operator_repair_startup_custody_v4(&refreshed)?;
            self.operator_startup.as_mut()
                .ok_or(StorageRuntimeError::Recovery)?.custody = refreshed;
            let cut = self.operator_startup_lower_cut_v4()?;
            if self.operator_startup.as_ref().and_then(|startup| startup.lower_cut) != Some(cut) {
                return Err(StorageRuntimeError::Recovery);
            }
            Some(cut)
        } else {
            None
        };

        // This private reobservation is reached only under the actual Runtime
        // borrow and TerminalHeld gate. Ordinary Inventory remains excluded.
        let workspace = self.reobserve_workspace_inventory(deadline, cutoff)?;
        let inventory = self.complete_inventory_from_workspace_bytes(workspace)?;
        let inventory = match template {
            Some(template) => attach_guest_root_publication_readback_v1(&inventory, template)
                .map_err(|_| StorageRuntimeError::Recovery)?,
            None => inventory,
        };
        if let Some(before) = cold_cut {
            let after = self.operator_startup_lower_cut_v4()?;
            let startup = self.operator_startup.as_ref()
                .ok_or(StorageRuntimeError::Recovery)?;
            owner.recheck_operator_repair_startup_custody_v4(&startup.custody)?;
            if before != after {
                return Err(StorageRuntimeError::Recovery);
            }
        }
        if inventory != expected || boottime_now_nanoseconds()? >= deadline {
            return Err(StorageRuntimeError::Recovery);
        }

        let (state_cut, live_cut) = self.operator_terminal_runtime_cuts_v4(&inventory)?;
        Ok(OperatorRepairRuntimeHoldV4 {
            runtime: self,
            state_cut,
            live_cut,
        })
    }

    fn operator_terminal_runtime_cuts_v4(
        &self,
        inventory: &[u8],
    ) -> Result<([u8; 32], [u8; 32]), StorageRuntimeError> {
        let (plan, physical) = self.coordinator.workspace_catalog_activation_plan()
            .map_err(StorageRuntimeError::Admission)?;
        if physical.is_none() {
            return Err(StorageRuntimeError::Recovery);
        }
        let snapshot = self.workspaces.as_ref()
            .ok_or(StorageRuntimeError::Recovery)?.snapshot();
        let custody = self.pin_io.catalog_binding()
            .map_err(|_| StorageRuntimeError::WorkspacePinScope)?;

        let mut cut = Sha256::new();
        cut.update(b"aos.sandbox.operator-repair-storage-state-cut.v4\0");
        cut.update(self.configuration_binding.as_bytes());
        cut.update(plan.transaction_sequence().to_be_bytes());
        cut.update(plan.transaction_snapshot_digest().as_bytes());
        cut.update(plan.plan_digest().as_bytes());
        cut.update(plan.physical_head().0.to_be_bytes());
        cut.update(plan.physical_head().1.as_bytes());
        cut.update(snapshot.journal_sequence().to_be_bytes());
        cut.update(snapshot.digest().as_bytes());
        cut.update(snapshot.catalog_generation()
            .ok_or(StorageRuntimeError::Recovery)?.to_be_bytes());
        cut.update(snapshot.identity_pool().range_start().to_be_bytes());
        cut.update(snapshot.identity_pool().range_size().to_be_bytes());
        cut.update(custody.kernel_boot_id());
        cut.update(custody.mount_namespace_device().to_be_bytes());
        cut.update(custody.mount_namespace_inode().to_be_bytes());
        cut.update(custody.pin_root_mount_id().to_be_bytes());
        cut.update(custody.pin_root_device().to_be_bytes());
        cut.update(custody.pin_root_inode().to_be_bytes());
        cut.update(aos_sandbox_protocol::operator_storage_repair_terminal_v4::inventory_digest_v4(inventory));
        let state_cut: [u8; 32] = cut.finalize().into();

        let mut live = Sha256::new();
        live.update(b"aos.sandbox.operator-repair-storage-live-cut.v4\0");
        live.update(state_cut);
        live.update(self.broker_instance_id);
        Ok((state_cut, live.finalize().into()))
    }
}

impl OperatorRepairRuntimeHoldV4<'_> {
    pub(crate) fn state_cut(&self) -> [u8; 32] {
        self.state_cut
    }

    pub(crate) fn live_cut(&self) -> [u8; 32] {
        self.live_cut
    }

    /// Reopens only after the actual sidecar owner durably settles the exact ACK.
    pub(crate) fn release_after_settlement(
        self,
        settlement: crate::operator_recovery::DurableRepairSettlementV4,
    ) -> Result<(), StorageRuntimeError> {
        if settlement.state_cut() != self.state_cut {
            return Err(StorageRuntimeError::Recovery);
        }

        if self.runtime.has_deferred_operator_debt_v4() {
            let startup = self.runtime.operator_startup.as_ref()
                .ok_or(StorageRuntimeError::Recovery)?;
            let crate::operator_recovery::OperatorRepairStartupCustodyV4::Unresolved(debt) = &startup.custody else {
                return Err(StorageRuntimeError::Recovery);
            };
            if !settlement.matches_debt(debt) {
                return Err(StorageRuntimeError::Recovery);
            }
            let expected = startup.lower_cut.ok_or(StorageRuntimeError::Recovery)?;
            if self.runtime.operator_startup_lower_cut_v4()? != expected {
                return Err(StorageRuntimeError::Recovery);
            }
            self.runtime.worker_dispatch.settle_terminal_hold()
                .map_err(|_| StorageRuntimeError::Recovery)?;
            self.runtime.resume_operator_startup_v4()
        } else {
            self.runtime.worker_dispatch.settle_terminal_hold()
                .map_err(|_| StorageRuntimeError::Recovery)
        }
    }
}
