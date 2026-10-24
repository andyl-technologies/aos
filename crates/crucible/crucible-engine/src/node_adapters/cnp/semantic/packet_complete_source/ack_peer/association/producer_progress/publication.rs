//! Lends the genuine report and retains the concrete publisher root under one read.

use super::*;
use crate::node_contract::{
    OriginalRestoredProducerReportFence, OriginalRestoredProducerReportReadScope,
};

impl PacketCompleteSemanticSource {
    /// Lends the real retained report beside its Outcome under the same read.
    ///
    /// C's actual Core placement adapter supplies the committed-root loan.
    /// A portable receipt, Outcome, status or matching number cannot do so.
    ///
    /// # Errors
    /// Refuses another phase/admission, changed completion, callback failure,
    /// changed root or any failed current/final read fence.
    pub(crate) fn with_original_restored_producer_report_data(
        &self,
        controller: &mut CnpController,
        inputs: &OriginalInstalledRestorationObservationSigningInputs<'_>,
        claim: &OriginalRestoredProducerExecutionClaim<'_>,
        original: &OperationAdmission,
        inspect: &mut dyn FnMut(
            &OriginalRestoredProducerReportReadScope<'_>,
        ) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        if claim.phase_data() != ProducerExecutionPhase::Publication {
            return Err(RuntimeError::ForeignAuthority);
        }
        let completion = read::run_phase_data(
            self,
            controller,
            inputs,
            claim,
            original,
            |attempt, controller, _, recheck| {
                let reference = attempt
                    .report_reference
                    .as_ref()
                    .ok_or(RuntimeError::OwnerUnavailable)?;
                reference
                    .verify(&attempt.report_bytes)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                let fence = ReportFence {
                    source: self,
                    controller,
                    claim,
                    attempt,
                    reference,
                    bytes: &attempt.report_bytes,
                    outcome: attempt
                        .outcome
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?,
                    current: RefCell::new(recheck),
                };
                let scope =
                    OriginalRestoredProducerReportReadScope::from_source_data(&fence, claim)?;
                inspect(&scope)?;
                fence.authenticate_current_data()
            },
            |_, _, _, _, _| Ok(()),
        )?;
        claim.retain_source_phase_completion_data(&completion)
    }
}

struct ReportFence<'a> {
    source: &'a PacketCompleteSemanticSource,
    controller: &'a CnpController,
    claim: &'a OriginalRestoredProducerExecutionClaim<'a>,
    attempt: &'a ProducerProgressAttempt,
    reference: &'a ContentRef,
    bytes: &'a [u8],
    outcome: &'a OperationOutcome,
    current: RefCell<&'a mut dyn FnMut() -> Result<(), RuntimeError>>,
}

impl OriginalRestoredProducerReportFence for ReportFence<'_> {
    fn report_data(&self) -> (&ContentRef, &[u8]) {
        (self.reference, self.bytes)
    }

    fn outcome_data(&self) -> &OperationOutcome {
        self.outcome
    }

    fn authenticate_current_data(&self) -> Result<(), RuntimeError> {
        self.claim
            .authenticate_current_data(self.source, self.controller)?;
        if self.claim.phase_data() != ProducerExecutionPhase::Publication
            || self.claim.slot_data() != self.attempt.slot
            || !matches!(self.attempt.stage.get(), Stage::Completed | Stage::Durable)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.current
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?()?;
        Ok(())
    }

    fn retain_committed_root_data(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), RuntimeError> {
        self.authenticate_current_data()?;
        reference
            .verify(bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if reference.media_type != "application/json"
            || NodeRuntime::capture_reference_storage(reference)?
                > proof::reference_storage_data(self.attempt.row.maximum)?
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut retained = self
            .attempt
            .durable_root
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        match retained.as_ref() {
            Some(previous) if previous != reference => return Err(RuntimeError::ForeignAuthority),
            Some(_) => {}
            None => *retained = Some(reference.clone()),
        }
        // The root is retained before any subsequent fence can fail. Only the
        // actual Core adapter invokes this trait after C's Committed placement
        // and same-placement root loan, never from a caller-supplied receipt.
        drop(retained);
        self.authenticate_current_data()
    }
}

pub(super) fn counter_scratch_data() -> usize {
    use std::cell::{BorrowError, BorrowMutError};
    size_of::<ReportFence<'static>>()
        + size_of::<OriginalRestoredProducerReportReadScope<'static>>()
        + size_of::<Result<OriginalRestoredProducerReportReadScope<'static>, RuntimeError>>()
        + size_of::<&dyn OriginalRestoredProducerReportFence>()
        + size_of::<
            &mut dyn FnMut(
                &OriginalRestoredProducerReportReadScope<'_>,
            ) -> Result<(), RuntimeError>,
        >()
        + size_of::<RefCell<&mut dyn FnMut() -> Result<(), RuntimeError>>>()
        + size_of::<RefMut<'static, &'static mut dyn FnMut() -> Result<(), RuntimeError>>>()
        + size_of::<
            Result<
                RefMut<'static, &'static mut dyn FnMut() -> Result<(), RuntimeError>>,
                BorrowMutError,
            >,
        >()
        + size_of::<(&ContentRef, &[u8])>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<(), crucible_node_format::ContractError>>()
        + size_of::<&OperationOutcome>()
        + size_of::<&ProducerProgressAttempt>()
        + size_of::<&OriginalRestoredProducerExecutionClaim<'static>>()
        + size_of::<Ref<'static, Option<ContentRef>>>()
        + size_of::<Result<Ref<'static, Option<ContentRef>>, BorrowError>>()
}

pub(super) fn retain_report_data(
    attempt: &mut ProducerProgressAttempt,
) -> Result<(), RuntimeError> {
    let original = attempt
        .admission
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?;
    let (begin_original, begin_terminal, _) = attempt
        .begin
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?
        .completed_pair_data()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let (poll_original, poll_terminal, _) = attempt
        .poll
        .as_ref()
        .ok_or(RuntimeError::OwnerUnavailable)?
        .completed_pair_data()
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let report = PacketRestoredProducerOperationReportData {
        operation: original.token().operation(),
        begin_original,
        begin_terminal,
        poll_original,
        poll_terminal,
        measurement: attempt
            .completed_measurement
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?,
        restored: attempt
            .completed_record
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?,
        producer: attempt.producer_data()?,
        input_authorization: &attempt
            .authorization
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .reference,
    };
    attempt.report_value =
        Some(serde_json::to_value(&report).map_err(|_| RuntimeError::InvalidReceipt)?);
    attempt.report_bytes = canonical::canonical_json(
        attempt
            .report_value
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?,
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    if attempt.report_bytes.len() > attempt.row.provider.maximum_report_encoded_bytes_data() {
        return Err(RuntimeError::ResourceLimit);
    }
    attempt.report_reference = Some(
        canonical::content_ref(&attempt.report_bytes, "application/json")
            .map_err(|_| RuntimeError::InvalidReceipt)?,
    );
    Ok(())
}
