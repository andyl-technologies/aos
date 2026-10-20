//! Borrows completed live custody before the next native purpose can pay.
//!
//! This is deliberately separate from the full semantic TerminalOriginal.
//! No graph, native observation or new clock is reconstructed here. A genuine
//! next Start must fund and perform its full fresh historical Source/C fold
//! before authorization or any Source mutation can use those semantic facts.

use super::*;

/// Borrows only the actual stored positive Create predecessor for prepayment.
///
/// It permits no Source or Controller append, launch, authorization, renewed
/// Create deadline or public success. The next native purpose and its real
/// closed Root client must join the same originals independently.
#[doc(hidden)]
pub struct CreateStoppedTerminalCustodyV1<'attempt> {
    attempt: &'attempt CreateStoppedCompletionAttemptV1,
}

impl CreateStoppedTerminalCustodyV1<'_> {
    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn require_start_history_v1(
        &self, parent: aos_sandbox_core::OperationId, controller: &Journal,
        read: &mut crate::lifecycle::LifecycleHistoricalReadOriginalV1,
    ) -> Result<(), SourceAdmissionErrorV1> {
        let key = self.attempt.final_completing_key_v1()?;
        read.historical_once_v1(parent, &key)?;
        let (terminal, _) = read.operation_v1()?;
        let (historical, record) = read.historical_operation_v1()?;
        self.attempt.require_final_rows_with_lifecycle_v1(parent, controller, historical, record, terminal)
    }

    pub(crate) fn association_v1(&self)
        -> Result<CreateStoppedCompletionAssociationV1, ResourceReservationErrorV1>
    {
        self.attempt.completion.association.as_ref()
            .map(CreateStoppedCompletionAssociationV1::duplicate_v1)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    // This checks the same actual completed native turn and retained positive
    // disposition without creating the separately paid semantic replay proof.
    pub(crate) fn require_same_complete_v1(
        &self, expected: &CreateStoppedCompletionAssociationV1,
        original: &CreateProvisioningOriginalsV1, controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.attempt.require_stored_terminal_custody_v1(expected, original, controller)
    }

    pub(crate) fn parent_operation_v1(&self)
        -> Result<aos_sandbox_core::OperationId, ResourceReservationErrorV1>
    {
        self.attempt.completion.parent.ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(crate) fn q04_v1(&self) -> Result<&Q04CutIdentityV1, ResourceReservationErrorV1> {
        self.attempt.completion.association.as_ref().map(|value| &value.actual.q04)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }
}

impl CreateStoppedCompletionAttemptV1 {
    /// Borrows stored completed custody before a new purpose pays for replay.
    ///
    /// This performs no IO, clock capture, graph parse or allocation. It checks
    /// the actual positive live completion and same Source/Controller instance
    /// affinity. It grants no historical semantic proof: the existing full
    /// terminal getter remains mandatory under the next paid native interval.
    ///
    /// # Errors
    /// Refuses an unfinished, ambiguous, substituted or unhealthy predecessor.
    #[doc(hidden)]
    pub fn borrow_create_stopped_terminal_custody_v1<'attempt>(
        &'attempt self, original: &CreateProvisioningOriginalsV1,
        controller: &Journal, source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<CreateStoppedTerminalCustodyV1<'attempt>, ResourceReservationErrorV1> {
        let association = self.completion.association.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let identity = self.completion.journal_identity.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        controller.require_completed_create_controller_instance_v1(identity)?;
        let source_identity = self.completion.terminal.identity.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        source.journal_ref_v1().require_completed_source_instance_v1(source_identity)?;
        let custody = CreateStoppedTerminalCustodyV1 { attempt: self };
        custody.require_same_complete_v1(association, original, controller)?;
        Ok(custody)
    }
}


impl CreateStoppedTerminalCustodyV1<'_> {
    /// Measures the actual completed attempt's co-resident memory for new work.
    ///
    /// It includes the retained Completing models, association allocation and
    /// actual successful Source snapshot backing. Native buffers/files were
    /// positively disposed before this custody could exist. The next owner's
    /// Action, Root client, old C23/SDK and shared native profile are separate.
    /// This passive DATA supplies no capacity or semantic permission.
    ///
    /// # Errors
    /// Refuses unfinished payload retirement or unrepresentable resident bytes.
    #[doc(hidden)]
    pub fn completed_resident_receiving_demand_v1(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1>
    {
        let state = &self.attempt.completion;
        if state.first.is_some() || !matches!(state.disposal, Some(Ok(())))
            || !matches!(state.final_relation, Some(Ok(())))
            || !matches!(state.payload_retirement, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let source = self.attempt.pre_ack.source.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let expected = state.terminal.expected.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let committed = state.terminal.committed.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let bytes = std::mem::size_of::<CreateStoppedCompletionAttemptV1>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<AssociationDataV1>()
                .checked_add(2 * std::mem::size_of::<usize>())?))
            .and_then(|bytes| bytes.checked_add(crate::lifecycle::create_operation_resident_bytes_v1(&source.operation)?))
            .and_then(|bytes| bytes.checked_add(crate::lifecycle::create_operation_resident_bytes_v1(expected)?))
            .and_then(|bytes| bytes.checked_add(committed.completed_resident_backing_bytes_v1()?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, bytes))
    }
}

impl CreateStoppedCompletionAttemptV1 {
    // After the new native entry, old profile0/1 are intentionally unavailable.
    // This only re-lends historical input to the SAME privately joined new
    // entry. It cannot create TerminalOriginal or authorize a Source mutation.
    pub(in crate::controller_resource_reservation::create_intake::provisioning::receiving) fn borrow_paid_start_history_custody_v1<'attempt>(
        &'attempt self,
        next:&crate::controller_resource_reservation::create_intake::provisioning::StartNativeStateV1,
        controller:&Journal,source:&ProtectedSourceDomainJournalOwnerV1,
    )->Result<CreateStoppedTerminalCustodyV1<'attempt>,ResourceReservationErrorV1> {
        next.require_current_v1(controller)?;
        let expected=next.predecessor_association_v1()?;
        self.require_stored_terminal_association_v1(expected)?;
        let identity=self.completion.journal_identity.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        controller.require_completed_create_controller_instance_v1(identity)?;
        let source_identity=self.completion.terminal.identity.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        source.journal_ref_v1().require_completed_source_instance_v1(source_identity)?;
        if next.q04_v1()?!=self.completion.association.as_ref().map(|value|&value.actual.q04)
            .ok_or(ResourceReservationErrorV1::Conflict)? {return Err(ResourceReservationErrorV1::Conflict);}
        Ok(CreateStoppedTerminalCustodyV1{attempt:self})
    }
}
