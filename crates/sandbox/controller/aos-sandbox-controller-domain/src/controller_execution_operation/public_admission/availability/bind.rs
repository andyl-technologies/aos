//! Extends the same held client pair through exact accepted-Create binding.

use aos_sandbox_protocol::host_execution_no_apply::{
    BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2, BeforeArgumentNoApplySourceDataV2,
};

use super::*;

/// Retains the actual pair's association with its genuine positive disposal.
///
/// Only the continuously held borrower can create this association after all
/// four lower native turns and canonical accepted source complete. It grants
/// no money, execution, current lease or stand-alone permission to reset an SDK
/// prefix. Retirement additionally needs the real same-Source/C18 disposal.
#[must_use = "retain the association until the genuine positive Source/C18 disposal"]
pub struct ControllerExecutionAvailabilityPositiveRetirementV2 {
    operation: OperationId,
    journal: crate::journal::ExecutionObservationJournalIdentityV4,
    accepted_source: BeforeArgumentNoApplySourceDataV2,
    original_cutoff: u64,
    host_session: [u8; 32],
}

impl ControllerExecutionAvailabilityPositiveRetirementV2 {
    // This readonly association comes only from completed actual four-flight
    // custody. It does not complete that custody or create an Apply grant.
    pub(in crate::controller_execution_operation) fn no_apply_source_data_v2(
        &self, controller: &Journal, operation: OperationId,
    ) -> Result<(BeforeArgumentNoApplySourceDataV2, u64, [u8; 32]), ResourceReservationErrorV1> {
        if self.operation != operation || !self.journal.is_same_original_v4(
            &controller.execution_observation_identity_v4()) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok((self.accepted_source, self.original_cutoff, self.host_session))
    }

    /// Compares the actual Source/C18 disposal with this original association.
    ///
    /// # Errors
    /// Refuses another operation or a different actual Controller Journal owner.
    /// Copied identifiers or a successful reply cannot construct either input.
    pub fn require_positive_disposal_v2(&self,
        disposal: &ControllerExecutionPositiveDisposalV1<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if disposal.operation_v1() != self.operation
            || !self.journal.is_same_original_v4(disposal.journal_identity) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }
}

impl ControllerExecutionAvailabilityClientLoanV2<'_> {
    /// Retains the one actual disposal association after both bind completions.
    ///
    /// # Errors
    /// Refuses failed/incomplete native/source/admission/IO originals or reentry.
    #[doc(hidden)]
    pub fn positive_retirement_original_once_v2(&mut self)
        -> Result<ControllerExecutionAvailabilityPositiveRetirementV2, ResourceReservationErrorV1> {
        let accepted = self.finish_accepted_bind_once_v2()?;
        let operation = match accepted {
            crate::AcceptOutcome::Accepted(operation) | crate::AcceptOutcome::Replay(operation) => operation,
        };
        let journal = self.controller.execution_observation_identity_v4();
        let accepted_source = self.accepted_bind_source_data_v2()?;
        let original_cutoff = self.original_cutoff_data_v2()?;
        if self.scope.prefix.journal_identity.as_ref()
            .is_none_or(|identity| !identity.is_same_original_v4(&journal)) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let original = self.scope.prefix.availability.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        if original.retirement_issued { return Err(ResourceReservationErrorV1::Conflict); }
        original.retirement_issued = true;
        let host_session = original.host.completed_session_binding_data_v2()?;
        Ok(ControllerExecutionAvailabilityPositiveRetirementV2 {
            operation, journal, accepted_source, original_cutoff, host_session,
        })
    }

    /// Prepares the protected accepted source without releasing either Session.
    ///
    /// The actual accepted Create operation is the bind request ID. It is
    /// distinct from the retained preaccept nonce in each Session namespace;
    /// no new request entropy, relative deadline or native owner is introduced.
    ///
    /// # Errors
    /// Refuses missing canonical admission, repeat entry, changed current source
    /// or a collision with the original preaccept request identity.
    #[doc(hidden)]
    pub fn prepare_accepted_bind_once_v2(&mut self) -> Result<(), ResourceReservationErrorV1> {
        if self.active != 2 {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.original_v2()?;
        self.scope
            .prepare_availability_accepted_source_once_v2(self.controller)?;
        let source = self
            .scope
            .availability_accepted_wire_data_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        if source.fields().create_operation == self.proposal_data_v2()?.fields().nonce {
            self.scope.prefix.first.get_or_insert(First::Availability);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.active = 3;
        Ok(())
    }

    /// Borrows the same source DATA for both finite accepted-bind encoders.
    ///
    /// # Errors
    /// Refuses a different finite phase or unavailable protected source join.
    #[doc(hidden)]
    pub fn accepted_bind_source_data_v2(
        &self,
    ) -> Result<BeforeArgumentNoApplySourceDataV2, ResourceReservationErrorV1> {
        if !matches!(self.active, 3 | 4 | 5) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.original_v2()?;
        self.scope
            .availability_accepted_wire_data_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn availability_request_id_data_v2(
        &self,
    ) -> Result<[u8; 16], ResourceReservationErrorV1> {
        if matches!(self.active, 0 | 1) {
            Ok(self.proposal_data_v2()?.fields().nonce)
        } else {
            Ok(self
                .accepted_bind_source_data_v2()?
                .fields()
                .create_operation)
        }
    }

    pub(crate) fn availability_accepted_source_data_v2(
        &self,
    ) -> Result<Option<[u8; BEFORE_ARGUMENT_NO_APPLY_SOURCE_BYTES_V2]>, ResourceReservationErrorV1>
    {
        if matches!(self.active, 0 | 1) {
            Ok(None)
        } else {
            Ok(Some(
                self.accepted_bind_source_data_v2()?.encode_canonical(),
            ))
        }
    }

    /// Confirms both native bind completions under the continuously held pair.
    ///
    /// # Errors
    /// Refuses either missing protected terminal/native post, a changed original
    /// cutoff/first clock, or any retained source/IO/financial failure.
    #[doc(hidden)]
    pub fn finish_accepted_bind_once_v2(
        &self,
    ) -> Result<crate::AcceptOutcome, ResourceReservationErrorV1> {
        if self.active != 5 {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let source = self.accepted_bind_source_data_v2()?;
        self.original_v2()?
            .io
            .require_completed_accepted_bind_data_v2(source)?;
        self.scope
            .prefix
            .accepted_outcome
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }
}

impl ExecutionPublicAdmissionScopeV2 {
    pub(crate) fn require_accepted_availability_handoff_v2(
        &self,
    ) -> Result<(), ResourceReservationErrorV1> {
        let source = self
            .availability_accepted_wire_data_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let original = self
            .prefix
            .availability
            .as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if original.failure_v2().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        original.io.require_completed_accepted_bind_data_v2(source)
    }
}
