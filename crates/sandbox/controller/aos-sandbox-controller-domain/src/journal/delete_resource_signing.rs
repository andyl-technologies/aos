//! Supplies current cleanup models through the actual protected C writer.
//!
//! These crate-private DATA projections grant no C17, Root approval or signing
//! authority. The closed Delete construction interval pays their source-bound
//! layout before invoking the canonical selection on this same native state.

use super::*;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector, SandboxId};
use aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier;
use crate::policy_compiler::provisioning_current::current_cleanup_assignment::{
    CurrentCleanupAssignmentDataV2, current_cleanup_assignment_rows_data_v2,
};

impl Journal {
    pub(crate) fn delete_resource_current_assignment_receiving_demand_v2(&self,
        verifier: &OwnershipAuthorityVerifier,
    ) -> Result<ResourceVector, JournalError> {
        self.ensure_protected_authority()?;
        let state = self.native.state();
        let bytes = state.iter().try_fold(0usize, |total, ((_, key), value)|
            total.checked_add(key.len())?.checked_add(value.len()))
            .ok_or(JournalError::JournalTooLarge)?;
        let verification = verifier.response_receiving_dynamic_bytes_v2(bytes)
            .ok_or(JournalError::JournalTooLarge)?;
        let extra = verification.checked_add(std::mem::size_of::<CurrentCleanupAssignmentDataV2>()
            .checked_mul(3).ok_or(JournalError::JournalTooLarge)?)
            .and_then(|n| u64::try_from(n).ok()).ok_or(JournalError::JournalTooLarge)?;
        crate::cold_launch_publication::completion::create_stopped_controller_receiving_demand_v1(state)
            .ok_or(JournalError::JournalTooLarge)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, extra))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(crate) fn current_delete_resource_assignment_data_v2(&self, sandbox: SandboxId)
        -> Result<CurrentCleanupAssignmentDataV2, Box<dyn std::error::Error + Send + Sync>> {
        self.ensure_protected_authority()?;
        current_cleanup_assignment_rows_data_v2(self.historical_read_view_v1().rows_data_v2(), sandbox)
    }
}
