//! Fresh physical custody for an originally captured hot-fork continuation.
//!
//! The sealed parent plan survives; its physical AUTHs do not. The actual child
//! runtime and capability must name the original fork basis before this owner
//! can publish Restore. Native INITIALIZE and CLOSED ownership remain separate
//! requirements, never deductions from the host's canonical prefix.

use std::sync::{Arc, Mutex};

use crucible_protocol::native_console::{NativeConsolePhase, NativeConsoleSetupPlan};
use crucible_shmem::MappedSetupRegion;

use super::*;

#[cfg(test)]
pub(crate) mod tests;

impl ConsoleLaunchCustody {
    pub(crate) fn rebind_hot_fork_child(
        &self,
        region: MappedSetupRegion,
        request: crate::QmpHotForkRequest,
        saved: &ConsoleOriginContinuation,
    ) -> Result<Self, ConsoleOwnerError> {
        let parent = self.lock()?;
        let mut logical_plan = self.sealed_plan.plan().clone();
        logical_plan.slot = 0;
        if self.original_launch_body().owner.process != request.parent_process_generation()
            || request.child_process_generation() == 0
            || request.child_process_generation() == request.parent_process_generation()
            || logical_plan.encode()? != saved.plan
            || !parent.issued.is_empty()
            || parent.clamp.is_some()
            || parent.pending_node_restore.is_some()
            || region.backing_identity() == self.backing
        {
            return Err(NativeConsoleError::Binding.into());
        }
        drop(parent);

        // This comparison uses the actual child process generation from the
        // original typed fork request, not a value copied from capability.
        let installed = crate::host_setup::native_console::accept_installation(
            &region,
            self.slot,
            request.child_process_generation(),
            Some(&self.sealed_plan),
        )?
        .ok_or(NativeConsoleError::Binding)?;
        let capacity = self.sealed_plan.issued_authorization_capacity();
        let admission = ConsoleAdmission {
            issued_authorization_capacity: NonZeroU32::new(capacity)
                .ok_or(NativeConsoleError::Field)?,
            receipt_storage_bytes: u64::from(capacity)
                * std::mem::size_of::<IssuedConsoleAuthorization>() as u64,
        };
        let body_template = NativeConsoleAuthorization {
            publication: 2,
            owner: NativeConsoleOwner {
                slot: self.slot,
                region: installed.capability.region,
                process: installed.capability.process,
                authorization: 1,
            },
            logical_generation: self.sealed_plan.plan().logical_generation,
            advance: 0,
            prior_sequence: saved.sequence,
            prior_ring_end: saved.ring_end,
            allowance: self.sealed_plan.authorization_allowance(),
            phase_token: 0,
            phase: NativeConsolePhase::Restore,
        };
        let owner =
            HostConsoleOwner::new(admission, body_template, self.sealed_plan.plan().clone())?;
        // This fresh owner remains inside the private stopped-child receipt.
        // It is not attached to the runnable channel until Restore acceptance;
        // the original claimed request installs the captured logical custody.
        Ok(Self {
            backing: installed.backing,
            slot: self.slot,
            shared: Arc::new(Mutex::new(owner)),
            region: Arc::new(region),
            #[cfg(test)]
            fixture_table: None,
            body_template,
            sealed_plan: NativeConsoleSetupPlan::decode(&self.sealed_plan.encode()?)?,
        })
    }

    /// Uses the sole claimed Restore producer under the retained child handoff.
    pub(crate) fn arm_hot_fork_restore(
        &self,
        saved: &ConsoleOriginContinuation,
        target: u64,
    ) -> Result<ConsoleRestorePublication, ConsoleOwnerError> {
        self.arm_bound_stopped_restore(&self.region, &saved.node, saved, target)
    }

    /// Transfers ready visibility only after native acceptance, without a later
    /// fallible decoder or allocation after physical prefix consumption.
    pub(crate) fn accept_hot_fork_restored(
        &self,
        boundary: crate::mapped_quantum::restore::QemuLogicalTimeRestoreBoundary,
        calibration: crate::QemuLogicalTimeCalibration,
        saved: &ConsoleOriginContinuation,
    ) -> Result<crucible::NodeCounter, ConsoleOwnerError> {
        let mut owner = self.lock()?;
        if owner.pending_node_restore.as_ref() != Some(saved) {
            return Err(NativeConsoleError::Binding.into());
        }
        owner.accept_restored(&self.region, boundary, calibration)?;
        owner.pending_node_restore = None;
        Ok(saved.ready_counter)
    }

    /// Compares the retained launch owner without consulting mutable wire tables.
    pub(crate) fn same_launch(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }

    pub(crate) fn hot_fork_region(&self) -> &MappedSetupRegion {
        &self.region
    }
}
