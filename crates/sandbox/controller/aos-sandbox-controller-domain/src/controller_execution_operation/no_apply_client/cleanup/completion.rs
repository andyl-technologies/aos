//! Hands the exact recovered public response across genuine Source disposal.
//!
//! Only the same native C append after completed Root48 creates this owner.
//! Its newer full C cut includes the one Recover metadata successor; the old
//! Create terminal and Root ACK remain unchanged historical settlement facts.

use super::*;
use aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2 as Cut;
use aos_sandbox_protocol::host_execution_no_apply::closed_controller::ControllerCreateFailureAckDataV2 as Ack;

/// Retains the genuine post-ACK native Recover metadata append and response.
///
/// The concrete SDK and Runtime must retire all remaining matching prefixes
/// before the actual Source/C18 completion releases this public response.
#[must_use]
pub struct ControllerExecutionNoApplyRecoveredMetadataV2 {
    journal: crate::journal::ExecutionObservationJournalIdentityV4,
    target: OperationId,
    operation: OperationId,
    ack: Ack,
    cut: Cut,
    response: aos_sandbox_api::aos::sandbox::v1::Operation,
}

impl ControllerExecutionNoApplyRecoveredMetadataV2 {
    pub(in crate::controller_execution_operation::no_apply_client) fn from_native_v2(
        journal: crate::journal::ExecutionObservationJournalIdentityV4,
        target: OperationId,
        operation: OperationId,
        ack: Ack,
        cut: Cut,
        response: aos_sandbox_api::aos::sandbox::v1::Operation,
    ) -> Self {
        Self {
            journal,
            target,
            operation,
            ack,
            cut,
            response,
        }
    }

    pub(in crate::controller_execution_operation::no_apply_client) fn require_retired_identity_v2(
        &self,
        journal: &crate::journal::ExecutionObservationJournalIdentityV4,
        operation: OperationId,
        ack: Ack,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.journal.is_same_original_v4(journal) || self.target != operation || self.ack != ack
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_execution_operation::no_apply_client) fn current_controller_cut_v2(
        &self,
    ) -> Cut {
        self.cut
    }

    pub(in crate::controller_execution_operation::no_apply_client) fn recovery_operation_data_v2(
        &self,
    ) -> OperationId {
        self.operation
    }

    fn require_current(&self, controller: &Journal) -> Result<(), ResourceReservationErrorV1> {
        if !self
            .journal
            .is_same_original_v4(&controller.execution_observation_identity_v4())
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        super::super::settlement::require_controller_cut_current_v2(controller, self.cut)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        crate::reconciler::require_closed_no_apply_terminal_ack_data_v2(controller, self.ack)
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }
}

impl ControllerExecutionNoApplyClientLoanV2<'_, '_, '_> {
    /// Completes the exact kind3 metadata append after real Root confirmation.
    ///
    /// # Errors
    /// Retains incomplete Root/Host/C/Source, another purpose or entry, changed
    /// protected rows, native append/readback failure and independently owed posts.
    #[doc(hidden)]
    pub fn complete_recovery_metadata_once_v2(
        &mut self,
        root: &crate::normal_root::RootExecutionNoApplyClientOriginalV2,
    ) -> Result<ControllerExecutionNoApplyRecoveredMetadataV2, ResourceReservationErrorV1> {
        self.run_recovery_metadata_append_once_v2(root)
    }
}

impl ControllerExecutionPositiveDisposalV1<'_> {
    /// Completes real Source/C18 disposal before releasing the Recover response.
    ///
    /// The caller must already have retired the SDK/Core and actual Runtime
    /// inputs. This releases a checked public response, never an Apply grant.
    /// The Node independently compares the exact stored terminal and projection.
    ///
    /// # Errors
    /// Refuses another original, Root ACK, target or current C cut. Lower
    /// disposal guards retain an abandoned or failed native prefix.
    #[doc(hidden)]
    pub fn complete_recovery_after_disposal_v2(
        self,
        controller: &Journal,
        disposed: ControllerExecutionNoApplyDisposedOriginalV2,
        metadata: ControllerExecutionNoApplyRecoveredMetadataV2,
    ) -> Result<
        (
            aos_sandbox_api::aos::sandbox::v1::Operation,
            ControllerExecutionNoApplyCompletionV2,
        ),
        ResourceReservationErrorV1,
    > {
        disposed.require_disposal_v2(&self)?;
        disposed.require_recovery_metadata_v2(&metadata)?;
        metadata.require_current(controller)?;
        let terminal = disposed.into_recovery_completion_v2(&metadata)?;
        self.complete_after_disposal_v1();
        Ok((metadata.response, terminal))
    }
}
