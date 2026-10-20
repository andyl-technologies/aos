//! Commits the genuine Stop's healthy or residual terminal projection.
//!
//! The same Source/Controller native turn owns both bookends. The final
//! syscall gate uses a distinct paid sample on that original metadata lineage;
//! it grants no new Host effect deadline and cannot waive a Q04 hold.

use super::*;
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{CommitResult, JournalError, JournalTransaction, LifecycleTerminalMetadataOriginalV4};
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::lifecycle::LifecycleRecordDigestV1;

const CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::Conflict;
type Pair = RetainedKernelPairedClockAttemptV1<SourceGenesisErrorV1>;

#[derive(Clone, Copy)]
enum First { Entry, Models, Funding, Source, Receipt, Preparation, AppendFunding, Append, After }

pub(super) struct StopControllerTerminalOriginalV4 {
    entered: bool,
    turn: source::StopSourceTurnOriginalV4,
    entry: Option<Result<()>>,
    models: Option<Result<ResourceVector>>,
    funding: Option<Result<()>>,
    funding_original: bool,
    source: Option<std::result::Result<(), JournalError>>,
    receipt: Option<std::result::Result<StopTerminalReceiptV5,
        aos_sandbox_protocol::domain_ledger::effect_history::EffectHistoryDataError>>,
    residual: bool,
    metadata: LifecycleTerminalMetadataOriginalV4,
    preparation: Option<std::result::Result<(), JournalError>>,
    append_demand: Option<std::result::Result<ResourceVector, crate::journal::JournalAppendReceivingDemandErrorV1>>,
    append_funding: Option<Result<()>>,
    append_original: bool,
    gate: StopTerminalFinalGateV4,
    append: Option<std::result::Result<CommitResult, JournalError>>,
    after: Option<Result<()>>,
    first: Option<First>,
}

pub(crate) struct StopTerminalAppendContextV4<'turn> {
    operation: OperationId,
    bank: &'turn Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: &'turn ProductionControllerNormalRootProfileV1,
    native: &'turn ControllerCreateProvisioningReceivingV1,
    source: &'turn Journal,
    turn: &'turn source::StopSourceTurnOriginalV4,
    record: LifecycleRecordDigestV1,
    metadata: &'turn LifecycleTerminalMetadataOriginalV4,
    append_funded: &'turn Option<Result<()>>,
    gate: &'turn mut StopTerminalFinalGateV4,
    before: RawPairedClockSample,
    residual: bool,
}

enum StopTerminalReceiptV5 {
    Healthy([u8; aos_sandbox_protocol::domain_ledger::effect_history::LIFECYCLE_EFFECT_RECEIPT_BYTES_V1]),
    Residual([u8; aos_sandbox_protocol::domain_ledger::effect_history::STOP_RESIDUAL_LIFECYCLE_RECEIPT_BYTES_V4]),
}

impl StopTerminalReceiptV5 {
    fn as_bytes(&self) -> &[u8] {
        match self { Self::Healthy(bytes) => bytes, Self::Residual(bytes) => bytes }
    }
}

struct StopTerminalFinalGateV4 {
    clock: Pair,
    sample: Option<std::result::Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    continuity: Option<std::result::Result<(), aos_sandbox_model::OwnershipLeaseVerificationError>>,
}

impl StopControllerTerminalOriginalV4 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            turn: source::StopSourceTurnOriginalV4::new(source::StopSourcePurposeV4::Terminal),
            entry: None, models: None, funding: None, funding_original: false,
            source: None, receipt: None, residual: false, metadata: LifecycleTerminalMetadataOriginalV4::new(),
            preparation: None, append_demand: None, append_funding: None, append_original: false,
            gate: StopTerminalFinalGateV4 { clock: Default::default(), sample: None, continuity: None },
            append: None, after: None, first: None,
        }
    }

    fn fixed_demand_v4() -> Result<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<StopTerminalAppendContextV4<'static>>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(Pair::dominant_requested_bytes_v1()?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(CLOSED)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, u64::try_from(Pair::MAXIMUM_RETAINED_FILES_V1).map_err(|_| CLOSED)?)
            .with(D::MetadataEntries, u64::try_from(Pair::receiving_metadata_cells_v1().ok_or(CLOSED)?).map_err(|_| CLOSED)?))
    }

    fn run_once_v4(&mut self, operation: OperationId,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        native: &mut ControllerCreateProvisioningReceivingV1,
        resident: ResourceVector,
        expected: &PublicMutationEffectHistoryV1,
        observation: crate::lifecycle::LifecycleEffectObservationV1,
        record: LifecycleRecordDigestV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<()> {
        if self.entered { return Err(CLOSED); }
        self.entered = true;
        self.residual = observation.capture_stop_residual_v4().is_some();
        self.entry = Some((|| {
            self.turn.enter_once_v4(operation, bank, profile, native,
                resident.checked_add(Self::fixed_demand_v4()?)?, controller, source)
        })());
        if !matches!(self.entry, Some(Ok(()))) { self.first = Some(First::Entry); }
        let mut frontier = First::Entry;
        let primary = (|| {
            if self.first.is_some() { return Err(CLOSED); }
            frontier = First::Models;
            self.models = Some((|| {
                self.turn.paid_models_v4()?
                    .checked_add(Self::fixed_demand_v4()?)?
                    .checked_add(crate::journal::stop_terminal_receiving_demand_v5(controller, operation, self.residual)?)?
                    .checked_add(controller.create_storage_semantic_append_demand_v1()?).map_err(Into::into)
            })());
            let complete = self.models.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or_else(|| { self.first = Some(First::Models); CLOSED })?;
            frontier = First::Funding;
            self.funding = Some((|| {
                bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .require_lifecycle_stop_complete_v4(native, controller, profile, complete)
            })());
            if !matches!(self.funding, Some(Ok(()))) {
                self.funding_original = native.failure().is_some();
                self.first = Some(First::Funding); return Err(CLOSED);
            }
            frontier = First::Source;
            self.source = Some(self.turn.require_terminal_source_v4(operation, bank, profile,
                native, controller, source.journal_ref_v1(), record, self.residual));
            if !matches!(self.source, Some(Ok(()))) { self.first = Some(First::Source); return Err(CLOSED); }
            frontier = First::Receipt;
            self.receipt = Some(match observation.capture_stop_residual_v4() {
                Some(residual) => aos_sandbox_protocol::domain_ledger::effect_history::encode_stop_residual_lifecycle_receipt_v4(
                    operation, record.digest(), &residual).map(StopTerminalReceiptV5::Residual),
                None => Ok(StopTerminalReceiptV5::Healthy(
                    aos_sandbox_protocol::domain_ledger::effect_history::encode_lifecycle_effect_receipt_v1(operation, record.digest()))),
            });
            let receipt = self.receipt.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| { self.first = Some(First::Receipt); CLOSED })?;
            let fence = self.turn.stop_fence_data_v4()?;
            let before = self.turn.sample_data_v4()?;
            frontier = First::Preparation;
            self.preparation = Some(if self.residual {
                self.metadata.prepare_stop_residual_once_v4(controller, operation, expected, fence, receipt.as_bytes(), before)
            } else {
                self.metadata.prepare_stop_success_once_v5(controller, operation, expected, fence, receipt.as_bytes(), before)
            });
            if !matches!(self.preparation, Some(Ok(()))) { self.first = Some(First::Preparation); return Err(CLOSED); }
            frontier = First::AppendFunding;
            self.append_demand = Some(controller.append_receiving_demand_v1(
                self.metadata.transaction_v2()?.records().iter().map(|row|
                    aos_sandbox_journal::geometry::RecordShape { key_bytes: row.key().len(),
                        value_bytes: row.value().map(<[u8]>::len) })));
            self.append_funding = Some((|| {
                let demand = *self.append_demand.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
                bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .require_lifecycle_stop_complete_v4(native, controller, profile, complete.checked_add(demand)?)
            })());
            if !matches!(self.append_funding, Some(Ok(()))) {
                self.append_original = native.failure().is_some();
                self.first = Some(First::AppendFunding); return Err(CLOSED);
            }
            frontier = First::Append;
            self.append = Some((|| {
                let transaction = self.metadata.transaction_v2()?;
                let context = StopTerminalAppendContextV4 { operation, bank, profile, native,
                    source: source.journal_ref_v1(), turn: &self.turn, record,
                    metadata: &self.metadata, append_funded: &self.append_funding,
                    gate: &mut self.gate, before, residual: self.residual };
                let mut loan = crate::reconciler::provisioning::ProvisioningAppendLoanV1::stop_terminal_v4(context, transaction);
                controller.commit_create_provisioning_v1(transaction, &mut loan)
            })());
            if !matches!(self.append, Some(Ok(_))) { self.first = Some(First::Append); return Err(CLOSED); }
            Ok(())
        })();
        if primary.is_err() { self.first.get_or_insert(frontier); }
        // No fallible primary path may bypass these reached Source/C/native
        // afters or the distinct retained final paired-clock destination.
        self.after = Some(self.turn.finish_once_v4(bank, profile, native, controller, source));
        if !matches!(self.after, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        if self.first.is_some() { Err(CLOSED) } else { primary }
    }

    fn completed_healthy_v5(&self) -> bool {
        self.entered && !self.residual && self.first.is_none()
            && matches!(self.source, Some(Ok(())))
            && matches!(self.preparation, Some(Ok(())))
            && matches!(self.append_funding, Some(Ok(())))
            && matches!(self.append, Some(Ok(_)))
            && matches!(self.after, Some(Ok(())))
    }

    pub(super) fn failure_v4<'owner>(&'owner self, native: &'owner ControllerCreateProvisioningReceivingV1)
        -> Option<&'owner (dyn Error + 'static)> {
        let cause: Option<&(dyn Error + 'static)> = match self.first? {
            First::Entry => self.turn.failure_v4(native).or_else(|| error(&self.entry)),
            First::Models => error(&self.models),
            First::Funding => if self.funding_original { native.failure() } else { error(&self.funding) },
            First::Source => error(&self.source),
            First::Receipt => error(&self.receipt),
            First::Preparation => self.metadata.failure().or_else(|| error(&self.preparation)),
            First::AppendFunding => if self.append_original { native.failure() } else {
                error(&self.append_demand).or_else(|| error(&self.append_funding)) },
            First::Append => self.gate.clock.failure().or_else(|| error(&self.gate.sample))
                .or_else(|| error(&self.gate.continuity)).or_else(|| error(&self.append)),
            First::After => self.turn.failure_v4(native).or_else(|| error(&self.after)),
        };
        cause.or(Some(&CLOSED))
    }
}

impl StopTerminalAppendContextV4<'_> {
    pub(crate) fn require_transition_v4(&self, controller: &Journal, transaction: &JournalTransaction)
        -> std::result::Result<(), JournalError> {
        if !matches!(self.append_funded, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        self.turn.require_terminal_source_v4(self.operation, self.bank, self.profile,
            self.native, controller, self.source, self.record, self.residual)?;
        self.metadata.require_before_v2(controller, transaction)
    }

    pub(crate) fn final_crossing_v4(&mut self, controller: &Journal) -> std::result::Result<(), JournalError> {
        self.require_transition_v4(controller, self.metadata.transaction_v2()?)?;
        if self.gate.sample.is_some() { return Err(JournalError::ProtectedBoundary); }
        self.gate.sample = Some(self.gate.clock.observe_once(Some(self.before)));
        self.gate.continuity = Some(self.before.validate_later_sample(
            *self.gate.sample.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?));
        if matches!(self.gate.continuity, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }
}

impl ControllerLifecycleStopOriginalV4 {
    /// Rejoins only a positively finished healthy Stop before physical disposal.
    ///
    /// The private Runtime caller also retains its actual adjacent Inventory,
    /// authenticated outcomes and SDK posts. Residual cleanup never selects
    /// this route, and no accounting state or spent traffic is reset here.
    ///
    /// # Errors
    /// Refuses residual/failed/unfinished terminal custody or a changed same-B
    /// native writer, Launch, profile or completed original association.
    pub fn require_healthy_stop_disposal_v5(&self, controller: &Journal) -> Result<()> {
        if self.failure_v4().is_some() || !matches!(self.residual_result, Some(Ok(())))
            || !self.terminal.completed_healthy_v5()
            || self.residual_observation.as_ref().and_then(|value| value.as_ref().ok())
                .is_none_or(|observation| observation.capture_stop_residual_v4().is_some())
        { return Err(CLOSED); }
        let native = self.native.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CLOSED)?;
        self.bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
            .require_lifecycle_stop_native_completed_v5(native, controller, self.profile.as_ref())
    }

    /// Publishes healthy or residual Stop from its same native Source/C originals.
    ///
    /// Only the private actual Runtime post borrower calls this after its SDK
    /// outcome, currentness and all posts have completed. No supplied receipt
    /// can choose success or waive the current Source debt and exact C CAS.
    ///
    /// # Errors
    /// Retains incomplete native provenance, changed debt/fence, financial,
    /// exact three-row CAS, final gate or independently owed post refusal.
    pub fn commit_stop_terminal_once_v5(&mut self, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<()> {
        if !matches!(self.residual_result, Some(Ok(()))) || self.failure_v4().is_some() {
            return Err(CLOSED);
        }
        let record = self.residual_record.ok_or(CLOSED)?;
        let observation = self.residual_observation.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(CLOSED)?;
        let expected = self.accepted.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(Option::as_ref).ok_or(CLOSED)?;
        let native = self.native.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)?;
        self.terminal.run_once_v4(self.operation, &self.bank, self.profile.as_ref(), native,
            self.residual_complete.ok_or(CLOSED)?, expected, observation, record, controller, source)
    }
}

fn error<T, E: Error + 'static>(value: &Option<std::result::Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
