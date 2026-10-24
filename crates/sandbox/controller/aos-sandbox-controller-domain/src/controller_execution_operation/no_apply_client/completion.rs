//! Releases a terminal witness only after actual NoApply and Source/C18 disposal.
//!
//! Root confirmation, all five real Host turns and exact native C terminal
//! custody first issue a private retirement association. Core/SDK prefixes drop
//! under the matching resource-disposal loan; actual Source D-positive then
//! releases the kernel witness. No receipt, error string or DATA constructor
//! can select this terminal transition.

use aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2 as Cut;
use aos_sandbox_protocol::host_execution_no_apply::closed_controller::ControllerCreateFailureAckDataV2 as Ack;

use super::*;

struct Identity {
    journal: crate::journal::ExecutionObservationJournalIdentityV4,
    operation: OperationId,
    execution: aos_sandbox_model::ExecutionId,
    ack: Ack,
    current_cut: Cut,
    recovery_operation: Option<OperationId>,
}

impl Identity {
    fn require_disposal(
        &self,
        disposal: &ControllerExecutionPositiveDisposalV1<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if disposal.operation != self.operation
            || !self.journal.is_same_original_v4(disposal.journal_identity)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

/// Retains the genuine completed NoApply association before native Source disposal.
#[must_use = "retain the association until matching SDK/Core prefixes have retired"]
pub struct ControllerExecutionNoApplyTerminalRetirementV2 {
    identity: Identity,
}

/// Records disposed Core custody, pending upper retirement and Source completion.
///
/// The concrete SDK retirement caller also drops its entire SDK prefix before
/// returning this association. Runtime must then retire its remaining inputs
/// before completing the genuine Source/C18 token.
#[must_use = "complete the matching real Source/C18 disposal before releasing terminal proof"]
pub struct ControllerExecutionNoApplyDisposedOriginalV2 {
    identity: Identity,
}

/// Proves completed NoApply and Source disposition for one unchanged actual C owner.
///
/// The reconciler independently validates that owner's full cut and exact
/// terminal relation. This value cannot append, retry or issue effect authority.
#[must_use = "hand the witness to the terminal reconciler without another C mutation"]
pub struct ControllerExecutionNoApplyCompletionV2 {
    identity: Identity,
}

impl ControllerExecutionNoApplyClientLoanV2<'_, '_, '_> {
    /// Issues one retirement association after genuine causal Root confirmation.
    ///
    /// # Errors
    /// Refuses incomplete/failed native Host turns, terminal C, Root response,
    /// own posts, another completed Root ACK or reentry. No prefix is reset.
    #[doc(hidden)]
    pub fn positive_no_apply_retirement_once_v2(
        &mut self,
        root: &crate::normal_root::RootExecutionNoApplyClientOriginalV2,
    ) -> Result<ControllerExecutionNoApplyTerminalRetirementV2, ResourceReservationErrorV1> {
        self.native()?;
        if self.native.active != 5 || self.native.retirement_issued {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let ack = self.controller_acknowledgement_data_v2()?;
        root.require_completed_controller_acknowledgement_v2(&ack)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let identity = Identity {
            journal: self.controller.execution_observation_identity_v4(),
            operation: self.source.operation_v1(),
            execution: aos_sandbox_model::ExecutionId::from_bytes(
                self.native.source.fields().execution,
            ),
            ack,
            current_cut: ack.controller_cut,
            recovery_operation: None,
        };
        self.native.retirement_issued = true;
        Ok(ControllerExecutionNoApplyTerminalRetirementV2 { identity })
    }
}

impl ControllerExecutionNoApplyTerminalRetirementV2 {
    /// Drops only this actual completed Core prefix under the same resource disposal.
    ///
    /// The SDK must independently require all five completed flights and its
    /// actual Root completion, then drop its whole original before returning
    /// this disposed association to Runtime. Failure never replaces originals.
    ///
    /// # Errors
    /// Refuses foreign Source/C, another operation, incomplete or failed native
    /// custody, another actual ACK or an already retired original.
    pub fn retire_core_before_native_disposal_v2(
        self,
        original: &mut ControllerExecutionNoApplyOriginalV2,
        disposal: &ControllerExecutionPositiveDisposalV1<'_>,
    ) -> Result<ControllerExecutionNoApplyDisposedOriginalV2, ResourceReservationErrorV1> {
        self.identity.require_disposal(disposal)?;
        if original.failure_v2().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let native = original
            .native
            .as_deref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if native.active != 5
            || !native.retirement_issued
            || native.source.fields().create_operation != *self.identity.operation.as_bytes()
            || native
                .settlement
                .as_deref()
                .and_then(|original| original.ack_data_v2())
                != Some(self.identity.ack)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        drop(std::mem::replace(
            original,
            ControllerExecutionNoApplyOriginalV2::new(),
        ));
        Ok(ControllerExecutionNoApplyDisposedOriginalV2 {
            identity: self.identity,
        })
    }
}

impl ControllerExecutionNoApplyDisposedOriginalV2 {
    pub(in crate::controller_execution_operation::no_apply_client) fn require_recovery_metadata_v2(
        &self, metadata: &ControllerExecutionNoApplyRecoveredMetadataV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        metadata.require_retired_identity_v2(&self.identity.journal, self.identity.operation, self.identity.ack)
    }

    pub(in crate::controller_execution_operation::no_apply_client) fn into_recovery_completion_v2(
        mut self, metadata: &ControllerExecutionNoApplyRecoveredMetadataV2,
    ) -> Result<ControllerExecutionNoApplyCompletionV2, ResourceReservationErrorV1> {
        self.require_recovery_metadata_v2(metadata)?;
        // The only permitted post-ACK advance is the actual native one-row
        // kind3 metadata successor certified by this opaque same-owner value.
        self.identity.current_cut = metadata.current_controller_cut_v2();
        self.identity.recovery_operation = Some(metadata.recovery_operation_data_v2());
        Ok(ControllerExecutionNoApplyCompletionV2 { identity: self.identity })
    }

    /// Checks a retained Runtime prefix before its exact NoApply disposal.
    ///
    /// This matches genuine native NoApply, actual Source/C and execution;
    /// it grants no new request, allocation, financial credit or effect.
    ///
    /// # Errors
    /// Refuses another Source/C original, operation or execution.
    pub fn require_resource_disposal_for_execution_v2(
        &self,
        disposal: &ControllerExecutionPositiveDisposalV1<'_>,
        execution: aos_sandbox_model::ExecutionId,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.identity.require_disposal(disposal)?;
        if self.identity.execution != execution {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_execution_operation) fn require_disposal_v2(
        &self,
        disposal: &ControllerExecutionPositiveDisposalV1<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.identity.require_disposal(disposal)
    }

    pub(in crate::controller_execution_operation) fn into_completion_v2(
        self,
    ) -> ControllerExecutionNoApplyCompletionV2 {
        ControllerExecutionNoApplyCompletionV2 {
            identity: self.identity,
        }
    }
}

impl ControllerExecutionNoApplyCompletionV2 {
    pub(crate) fn require_recovery_current_v2(
        &self, controller: &Journal, operation: OperationId,
    ) -> Result<(), ReconcilerError> {
        if self.identity.recovery_operation != Some(operation) {
            return Err(ReconcilerError::InvalidExecutorOutput("NoApply completion belongs to another Recover"));
        }
        self.require_current_v2(controller, self.identity.operation)
    }

    pub(crate) fn require_current_v2(
        &self,
        controller: &Journal,
        operation: OperationId,
    ) -> Result<(), ReconcilerError> {
        let identity = &self.identity;
        controller.ensure_protected_authority()?;
        if identity.operation != operation
            || identity.ack.operation != operation
            || !identity
                .journal
                .is_same_original_v4(&controller.execution_observation_identity_v4())
        {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "NoApply completion belongs to another original",
            ));
        }
        let expected = identity.current_cut;
        let actual = Cut::from_rows_data_v2(
            expected.names(),
            controller.snapshot_sequence(),
            expected.end(),
            controller.all_records(),
        )
        .map_err(|_| ReconcilerError::InvalidExecutorOutput("NoApply current cut is malformed"))?;
        if actual != expected {
            return Err(ReconcilerError::InvalidExecutorOutput(
                "NoApply Controller cut advanced before terminal handoff",
            ));
        }
        crate::reconciler::require_closed_no_apply_terminal_ack_data_v2(controller, identity.ack)
    }
}
