//! Retains finite Stop metadata turns on the original Controller ledger.
//!
//! Public Stop acceptance has already committed desired state. These turns
//! prepare only its ordinary Source cursor. They grant no Host effect scope:
//! later dispatch still needs its genuine current signed Stop template.

use super::*;
use std::cell::{Ref, RefCell};

use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1;
use aos_sandbox_model::{OwnershipLeaseVerificationError, RawPairedClockSample};
use aos_sandbox_protocol::domain_ledger::effect_history::EffectHistoryDataError;

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::source_provisioning::SourceProvisioningIdentityV1;
use crate::lifecycle::protected_journal::LifecycleProtectedJournalProjectionV1;
use crate::lifecycle::{
    CurrentLifecycleOperationV1, LifecycleHistoricalReadOriginalV1, LifecycleJournalVerifierV1,
    LifecycleMethodSemanticCommitV1, LifecycleOperationDecodeOriginalV1, LifecycleOperationV1,
    LifecyclePhaseV1, LifecycleProtectedJournalErrorV1, LifecycleProtectedJournalKeyV1,
    LifecycleProtectedJournalOwnerV1, LifecyclePublicMutationAdmissionErrorV1,
    LifecyclePublicOperationErrorV1, LifecycleRecordDigestV1, LifecycleTimeV1,
    PreparedSourceLifecycleAdmissionV1, SourceLifecycleAdmissionCommitV1,
};
use crate::protected_domain_journal::ResidentDomainCommitFailureV1;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;

mod inactive_turn;
pub(super) use inactive_turn::StopSourceTurnSlotV4;

pub(super) type Pair = RetainedKernelPairedClockAttemptV1<SourceGenesisErrorV1>;
const CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::Conflict;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum StopSourcePurposeV4 {
    Admission,
    BindPlan,
    InitialProgress,
    SemanticReadiness,
    SemanticCommit,
    Completing,
    HostDispatch,
    Residual,
    Success,
    Terminal,
}

#[derive(Clone, Copy)]
enum StopSourceEntryV5 {
    Ordinary,
    FreshCleanup,
}

impl StopSourcePurposeV4 {
    fn committed_v4(self) -> bool {
        matches!(self, Self::SemanticCommit | Self::Completing | Self::HostDispatch | Self::Residual | Self::Success | Self::Terminal)
    }

    fn mutates_source_v4(self) -> bool {
        !matches!(self, Self::HostDispatch | Self::Terminal)
    }
}

#[derive(Debug, thiserror::Error)]
enum StopSourceCauseV4 {
    #[error(transparent)]
    Receiving(#[from] ResourceReservationErrorV1),
    #[error(transparent)]
    Journal(#[from] crate::JournalError),
    #[error(transparent)]
    History(#[from] EffectHistoryDataError),
    #[error(transparent)]
    Admission(#[from] LifecyclePublicMutationAdmissionErrorV1),
    #[error(transparent)]
    Operation(#[from] LifecyclePublicOperationErrorV1),
}

#[derive(Clone, Copy)]
enum First {
    Entry,
    Native,
    Clock,
    Models,
    Funding,
    Context,
    Projection,
    Expected,
    WriterModels,
    WriterFunding,
    Semantic,
    Prepared,
    Binding,
    Commit,
    SourceAfter,
    ControllerAfter,
    ClockAfter,
    Continuity,
    Disposal,
    Retirement,
    DispatchModels,
    DispatchFunding,
    DispatchData,
    DispatchReadback,
    Reentry,
}

pub(super) struct StopSourceTurnOriginalV4 {
    purpose: StopSourcePurposeV4,
    residual: Option<crate::lifecycle::LifecycleEffectObservationV1>,
    final_record: Option<LifecycleRecordDigestV1>,
    entered: bool,
    entry: Option<Result<()>>,
    entry_original: bool,
    controller_entered: bool,
    native: Option<Result<SourceProvisioningCurrentnessOriginalV1>>,
    before_clock: Pair,
    after_clock: Pair,
    before: Option<std::result::Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after: Option<std::result::Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    continuity: Option<std::result::Result<(), OwnershipLeaseVerificationError>>,
    models: Option<Result<ResourceVector>>,
    funding: Option<Result<()>>,
    funding_original: bool,
    context: Option<std::result::Result<Option<PublicMutationEffectHistoryV1>, ReconcilerError>>,
    read: LifecycleHistoricalReadOriginalV1,
    projection: Option<std::result::Result<(), crate::JournalError>>,
    identity: Option<SourceProvisioningIdentityV1>,
    expected: Option<std::result::Result<LifecycleOperationV1, StopSourceCauseV4>>,
    writer_models: Option<Result<ResourceVector>>,
    writer_funding: Option<Result<()>>,
    writer_funding_original: bool,
    semantic: Option<std::result::Result<LifecycleMethodSemanticCommitV1, LifecyclePublicMutationAdmissionErrorV1>>,
    prepared: Option<std::result::Result<PreparedSourceLifecycleAdmissionV1, LifecycleProtectedJournalErrorV1>>,
    binding: Option<Result<()>>,
    committed: Option<std::result::Result<SourceLifecycleAdmissionCommitV1, ResidentDomainCommitFailureV1>>,
    admission_decode: RefCell<LifecycleOperationDecodeOriginalV1>,
    source_after: Option<std::result::Result<(), crate::JournalError>>,
    controller_after: Option<Result<()>>,
    disposal: Option<Result<()>>,
    retirement: Option<Result<usize>>,
    completed: bool,
    dispatch_entered: bool,
    dispatch_models: Option<Result<ResourceVector>>,
    dispatch_funding: Option<Result<()>>,
    dispatch_data: Option<std::result::Result<
        aos_sandbox_protocol::domain_ledger::stop_dispatch::LifecycleStopDispatchDataV1,
        aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError>>,
    dispatch_readback: Option<std::result::Result<(), crate::JournalError>>,
    first: Option<First>,
}

// Only the private Source22 driver receives these disjoint retained originals.
// It can hold a closed append authorization beside the SAME mutable Source
// owner without aliasing the enclosing Stop turn or lending ordinary authority.
pub(super) struct StopCleanupSourceNativePartsV1<'held> {
    pub(super) read: &'held LifecycleHistoricalReadOriginalV1,
    pub(super) native: &'held mut SourceProvisioningCurrentnessOriginalV1,
    pub(super) identity: &'held mut SourceProvisioningIdentityV1,
    pub(super) first: RawPairedClockSample,
}

impl StopSourceTurnOriginalV4 {
    pub(super) fn new(purpose: StopSourcePurposeV4) -> Self {
        Self {
            purpose,
            residual: None,
            final_record: None,
            entered: false,
            entry: None,
            entry_original: false,
            controller_entered: false,
            native: None,
            before_clock: Default::default(),
            after_clock: Default::default(),
            before: None,
            after: None,
            continuity: None,
            models: None,
            funding: None,
            funding_original: false,
            context: None,
            read: LifecycleHistoricalReadOriginalV1::new(),
            projection: None,
            identity: None,
            expected: None,
            writer_models: None,
            writer_funding: None,
            writer_funding_original: false,
            semantic: None,
            prepared: None,
            binding: None,
            committed: None,
            admission_decode: RefCell::new(LifecycleOperationDecodeOriginalV1::new()),
            source_after: None,
            controller_after: None,
            disposal: None,
            retirement: None,
            completed: false,
            dispatch_entered: false,
            dispatch_models: None,
            dispatch_funding: None,
            dispatch_data: None,
            dispatch_readback: None,
            first: None,
        }
    }

    pub(super) fn fixed_demand_v4() -> Result<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(Pair::dominant_requested_bytes_v1()?.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(LifecycleHistoricalReadOriginalV1::carrier_receiving_bytes_v1()?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(CLOSED)?;
        let files = Pair::MAXIMUM_RETAINED_FILES_V1.checked_mul(2)
            .and_then(|files| u64::try_from(files).ok()).ok_or(CLOSED)?;
        let names = Pair::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(2))
            .and_then(|names| u64::try_from(names).ok()).ok_or(CLOSED)?;
        ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, files).with(D::MetadataEntries, names)
            .checked_add(SourceProvisioningCurrentnessOriginalV1::receiving_demand_v1()?)
            .map_err(Into::into)
    }

    pub(super) fn run_once_v4(
        &mut self,
        operation: OperationId,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        controller_native: &mut ControllerCreateProvisioningReceivingV1,
        resident: ResourceVector,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<()> {
        if self.entered { self.first.get_or_insert(First::Reentry); return Err(CLOSED); }
        let _ = self.enter_once_v4(operation, bank, profile, controller_native,
            resident, controller, source);
        self.prepare_metadata_once_v4(operation, bank, profile, controller_native, controller, source);
        self.finish_once_v4(bank, profile, controller_native, controller, source)
    }

    pub(super) fn enter_once_v4(
        &mut self,
        operation: OperationId,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        controller_native: &mut ControllerCreateProvisioningReceivingV1,
        resident: ResourceVector,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<()> {
        self.enter_source_engine_v5(operation, bank, profile, controller_native,
            resident, controller, source, StopSourceEntryV5::Ordinary)
    }

    pub(super) fn enter_cleanup_once_v1(
        &mut self, operation: OperationId,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        controller_native: &mut ControllerCreateProvisioningReceivingV1,
        resident: ResourceVector, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<()> {
        if self.purpose != StopSourcePurposeV4::HostDispatch { return Err(CLOSED); }
        self.enter_source_engine_v5(operation, bank, profile, controller_native,
            resident, controller, source, StopSourceEntryV5::FreshCleanup)
    }

    fn enter_source_engine_v5(
        &mut self, operation: OperationId,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        controller_native: &mut ControllerCreateProvisioningReceivingV1,
        resident: ResourceVector, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        entry: StopSourceEntryV5,
    ) -> Result<()> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.entered = true;
        self.entry = Some(begin_controller_turn_v4(bank, profile, controller_native,
            resident, controller, entry, &mut self.controller_entered));
        if !matches!(self.entry, Some(Ok(()))) {
            self.entry_original = controller_native.failure().is_some();
            self.first = Some(First::Entry);
        }
        self.enter_source_after_controller_v4(operation, bank, profile,
            controller_native, resident, controller, source)
    }

    // The inline Host/residual turns and the paid ordinary slots meet here.
    // A slot has already entered the SAME Controller interval before its
    // destination allocation; this continuation never repeats that entry.
    fn enter_source_after_controller_v4(
        &mut self, operation: OperationId,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        controller_native: &mut ControllerCreateProvisioningReceivingV1,
        resident: ResourceVector, controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<()> {
        if self.first.is_none() {
            self.native = Some((|| {
                let complete = resident.checked_add(Self::fixed_demand_v4()?)?;
                bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .begin_provisioning_source_native_v1(controller_native, controller,
                        source.journal(), profile, complete)
            })());
            if self.native.as_ref().and_then(|result| result.as_ref().ok())
                .is_none_or(|native| native.failure().is_some()) {
                self.first = Some(First::Native);
            }
        }
        if self.first.is_none() {
            self.before = Some(self.before_clock.observe_once(None));
            if !matches!(self.before, Some(Ok(_))) { self.first = Some(First::Clock); }
        }
        if self.first.is_none() {
            self.models = Some((|| {
                let graph = crate::lifecycle::retained_lifecycle_replay_receiving_demand_v1(
                    source.journal_ref_v1().all_records()).ok_or(CLOSED)?;
                let future = if self.purpose.mutates_source_v4() {
                    crate::lifecycle::stop_source_receiving_demand_v4(
                        source.journal_ref_v1(), self.purpose.committed_v4())?
                } else { ResourceVector::ZERO };
                let accepted = crate::reconciler::accepted_public_effect_models_receiving_bytes_retaining_v4(controller)?;
                let bytes = u64::try_from(accepted).map_err(|_| CLOSED)?;
                Ok(resident.checked_add(Self::fixed_demand_v4()?)?
                    .checked_add(graph)?.checked_add(future)?
                    .checked_add(crate::runtime_authority::current_publication_receiving_demand_v2(controller)
                        .ok_or(CLOSED)?)?
                    .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?)
            })());
            if !matches!(self.models, Some(Ok(_))) { self.first = Some(First::Models); }
        }
        if let Some(Ok(complete)) = self.models.as_ref() {
            self.funding = Some((|| {
                bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .require_lifecycle_stop_complete_v4(controller_native, controller, profile, *complete)
            })());
            if !matches!(self.funding, Some(Ok(()))) {
                self.funding_original = controller_native.failure().is_some();
                self.first.get_or_insert(First::Funding);
            }
        }
        if self.first.is_none() {
            self.context = Some(crate::reconciler::accepted_stop_effect_from_journal_v4(controller, operation));
            if !matches!(self.context, Some(Ok(Some(_)))) { self.first = Some(First::Context); }
        }
        if self.first.is_none() {
            self.projection = Some(self.read.observe_optional_operation_once_v4(source.journal_ref_v1(), operation));
            if !matches!(self.projection, Some(Ok(()))) { self.first = Some(First::Projection); }
        }
        if self.first.is_none() {
            self.expected = Some((|| {
                let context = self.context.as_ref().and_then(|result| result.as_ref().ok())
                    .and_then(Option::as_ref).ok_or(CLOSED)?;
                let request = context.validated_request()?;
                if !matches!(request, aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1::Stop(_)) {
                    return Err(CLOSED.into());
                }
                controller.require_public_mutation_targets_live_v2(context.project(), &request)?;
                self.identity = Some(source.journal_ref_v1().source_provisioning_identity_v1()?);
                let node = bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .current_lifecycle_stop_node_v4(controller_native, controller, profile)?;
                let admission = crate::lifecycle::lifecycle_public_mutation_admission_v1(
                    controller, operation, context.project(), node, &request)?;
                Ok(crate::lifecycle::lifecycle_operation_from_public_mutation_v1(operation,
                    context.caller(), context.project(), context.accepted_wall_seconds(),
                    context.canonical_request(), &request, admission)?)
            })());
            if !matches!(self.expected, Some(Ok(_))) { self.first = Some(First::Expected); }
        }
        if self.first.is_none() {
            self.writer_models = Some((|| {
                let (_, verifier) = self.read.projection_ready_v1()?;
                let writer = if self.purpose.mutates_source_v4() {
                    verifier.writer_clone_receiving_demand_v1().ok_or(CLOSED)?
                } else { ResourceVector::ZERO };
                Ok(self.models.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)?
                    .checked_add(writer)?)
            })());
            if !matches!(self.writer_models, Some(Ok(_))) { self.first = Some(First::WriterModels); }
        }
        if let Some(Ok(complete)) = self.writer_models.as_ref() {
            self.writer_funding = Some((|| {
                bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .require_lifecycle_stop_complete_v4(controller_native, controller, profile, *complete)
            })());
            if !matches!(self.writer_funding, Some(Ok(()))) {
                self.writer_funding_original = controller_native.failure().is_some();
                self.first.get_or_insert(First::WriterFunding);
            }
        }
        if self.first.is_none() { Ok(()) } else { Err(CLOSED) }
    }

    fn prepare_metadata_once_v4(
        &mut self, operation: OperationId,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        controller_native: &mut ControllerCreateProvisioningReceivingV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) {
        if self.first.is_none() && self.purpose == StopSourcePurposeV4::SemanticCommit {
            self.semantic = Some((|| {
                let (operation, _) = self.read.operation_v1()
                    .map_err(|_| LifecyclePublicMutationAdmissionErrorV1::InvalidIdentity)?;
                let at = self.started_at_v4()
                    .map_err(|_| LifecyclePublicMutationAdmissionErrorV1::InvalidIdentity)?;
                crate::lifecycle::lifecycle_desired_state_semantic_commit_v1(controller, operation, at)
            })());
            if !matches!(self.semantic, Some(Ok(_))) { self.first = Some(First::Semantic); }
        }
        if self.first.is_none() {
            let original = StopSourceAuthorizationV4 { state: self, operation, bank, profile,
                controller_native, controller };
            self.prepared = Some((|| {
                LifecycleProtectedJournalOwnerV1::claim_original_stop_source_v4(source, original)?
                    .prepare_original_stop_source_v4(&original)
            })());
            if !matches!(self.prepared, Some(Ok(_))) { self.first = Some(First::Prepared); }
        }
        if self.first.is_none() {
            self.final_record = self.prepared.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|prepared| match prepared {
                    PreparedSourceLifecycleAdmissionV1::Replay(_) => None,
                    PreparedSourceLifecycleAdmissionV1::Prepared { record, .. } => *record,
                });
            self.binding = Some((|| {
                let transaction = self.prepared.as_ref().and_then(|result| result.as_ref().ok())
                    .and_then(PreparedSourceLifecycleAdmissionV1::transaction_v1);
                let Some(transaction) = transaction else { return Ok(()); };
                let native = self.native.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)?;
                bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .bind_provisioning_source_native_v1(native, controller_native, controller,
                        source.journal(), profile, transaction)
            })());
            if !matches!(self.binding, Some(Ok(()))) { self.first = Some(First::Binding); }
        }
        if self.first.is_none() {
            let original = StopSourceAuthorizationV4 { state: self, operation, bank, profile,
                controller_native, controller };
            self.committed = Some((|| {
                let mut owner = LifecycleProtectedJournalOwnerV1::claim_original_stop_source_v4(source, original)
                    .map_err(|cause| ResidentDomainCommitFailureV1::Before(cause.into()))?;
                let prepared = self.prepared.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or_else(|| ResidentDomainCommitFailureV1::Before(crate::JournalError::ProtectedBoundary.into()))?;
                owner.commit_original_stop_source_v4(prepared, &original)
            })());
            if !matches!(self.committed, Some(Ok(_))) { self.first = Some(First::Commit); }
        }

    }

    pub(super) fn finish_once_v4(
        &mut self, bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        controller_native: &mut ControllerCreateProvisioningReceivingV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<()> {
        self.finish_posts_once_v4(bank, profile, controller_native, controller, source)?;
        self.dispose_after_posts_once_v4(bank, profile, controller_native, controller, source)
    }

    // The cleanup owner retains the same reached Source/C destinations while
    // its SDK/model prefix retires. Ordinary turns still call both phases
    // consecutively through finish_once_v4.
    pub(super) fn finish_posts_once_v4(
        &mut self, bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        controller_native: &mut ControllerCreateProvisioningReceivingV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<()> {
        if self.source_after.is_some() || self.controller_after.is_some() || self.after.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        // Source/C afters and the distinct final clock are independently owed
        // once their corresponding before entered, including body refusals.
        if let Some(Ok(native)) = self.native.as_mut() {
            self.source_after = Some(source.journal_ref_v1().finish_source_provisioning_native_v1(native));
            if !matches!(self.source_after, Some(Ok(()))) { self.first.get_or_insert(First::SourceAfter); }
        }
        if self.controller_entered {
            self.controller_after = Some(finish_controller_turn_v4(
                bank, profile, controller_native, controller));
            if !matches!(self.controller_after, Some(Ok(()))) { self.first.get_or_insert(First::ControllerAfter); }
        }
        if self.native.as_ref().is_some_and(std::result::Result::is_ok) {
            self.after = Some(self.after_clock.observe_once(
                self.before.as_ref().and_then(|result| result.as_ref().ok()).copied()));
            if !matches!(self.after, Some(Ok(_))) { self.first.get_or_insert(First::ClockAfter); }
            if let (Some(Ok(before)), Some(Ok(after))) = (self.before.as_ref(), self.after.as_ref()) {
                self.continuity = Some(before.validate_later_sample(*after));
                if !matches!(self.continuity, Some(Ok(()))) { self.first.get_or_insert(First::Continuity); }
            }
        }
        if self.first.is_none() { Ok(()) } else { Err(CLOSED) }
    }

    pub(super) fn dispose_after_posts_once_v4(
        &mut self, bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        controller_native: &ControllerCreateProvisioningReceivingV1,
        controller: &Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<()> {
        if self.first.is_some() || self.disposal.is_some()
            || !matches!(self.source_after, Some(Ok(())))
            || !matches!(self.controller_after, Some(Ok(())))
            || !matches!(self.continuity, Some(Ok(())))
        { return Err(CLOSED); }
        if self.first.is_none() {
            self.disposal = Some((|| {
                let native = self.native.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)?;
                bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .dispose_provisioning_source_native_v1(native, controller_native, controller,
                        source.journal(), profile)
            })());
            if !matches!(self.disposal, Some(Ok(()))) { self.first = Some(First::Disposal); }
        }
        if self.first.is_none() && !matches!(self.purpose,
            StopSourcePurposeV4::HostDispatch | StopSourcePurposeV4::Terminal) {
            self.retirement = Some((|| {
                let committed = self.committed.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CLOSED)?;
                committed.retire_completed_payloads_v1();
                let resident = committed.completed_resident_backing_bytes_v1().ok_or(CLOSED)?;
                self.expected = None;
                self.context = None;
                self.semantic = None;
                self.prepared = None;
                self.read = LifecycleHistoricalReadOriginalV1::new();
                *self.admission_decode.get_mut() = LifecycleOperationDecodeOriginalV1::new();
                Ok(resident)
            })());
            if !matches!(self.retirement, Some(Ok(_))) { self.first = Some(First::Retirement); }
        }
        self.completed = self.first.is_none();
        if self.completed { Ok(()) } else { Err(CLOSED) }
    }

    // Only the closed Source22 positive disposer calls this after its actual
    // A8/C terminal/Recover conjunction. It retains the genuine lower native
    // owner while the full upper read/model/clock prefix is physically dropped.
    pub(super) fn take_cleanup_native_after_posts_v1(&mut self)
        -> Result<SourceProvisioningCurrentnessOriginalV1> {
        if self.purpose != StopSourcePurposeV4::HostDispatch || self.first.is_some()
            || self.completed || self.disposal.is_some()
            || !matches!(self.source_after, Some(Ok(())))
            || !matches!(self.controller_after, Some(Ok(())))
            || !matches!(self.continuity, Some(Ok(())))
            || !matches!(self.native, Some(Ok(_))) {
            return Err(CLOSED);
        }
        match self.native.take() {
            Some(Ok(native)) => Ok(native),
            original => {
                self.native = original;
                Err(CLOSED)
            }
        }
    }

    pub(super) fn cleanup_after_clock_data_v1(&self) -> Result<RawPairedClockSample> {
        if self.purpose != StopSourcePurposeV4::HostDispatch || self.first.is_some()
            || !matches!(self.source_after, Some(Ok(())))
            || !matches!(self.controller_after, Some(Ok(())))
            || !matches!(self.continuity, Some(Ok(()))) {
            return Err(CLOSED);
        }
        self.after.as_ref().and_then(|value| value.as_ref().ok()).copied().ok_or(CLOSED)
    }

    pub(super) fn current_host_operation_v4(
        &self,
    ) -> std::result::Result<CurrentLifecycleOperationV1<'_>, crate::JournalError> {
        if self.source_after.is_some() || self.controller_after.is_some() {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        self.host_operation_model_v4()
    }

    pub(super) fn bind_host_dispatch_once_v1(
        &mut self, operation: OperationId,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        controller_native: &mut ControllerCreateProvisioningReceivingV1,
        controller: &mut Journal, source: &mut ProtectedSourceDomainJournalOwnerV1,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        complete: ResourceVector, sdk_replay: ResourceVector,
    ) -> Result<ResourceVector> {
        if self.dispatch_entered || self.purpose != StopSourcePurposeV4::HostDispatch
            || self.first.is_some() || self.source_after.is_some()
        {
            self.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.dispatch_entered = true;
        self.dispatch_models = Some((|| {
            let (_, verifier) = self.read.projection_ready_v1()?;
            Ok(complete.checked_add(verifier.writer_clone_receiving_demand_v1().ok_or(CLOSED)?)?
                .checked_add(LifecycleProtectedJournalOwnerV1::stop_dispatch_receiving_demand_v1(
                    source.journal_ref_v1(), request.canonical_packet().len())?)?
                // One canonical request graph is retained by the SDK; Source
                // preflight/replay additionally use the same priced model recipe.
                .checked_add(sdk_replay)?.checked_add(sdk_replay)?)
        })());
        if !matches!(self.dispatch_models, Some(Ok(_))) { self.first = Some(First::DispatchModels); }
        if self.first.is_none() {
            self.dispatch_funding = Some((|| {
                let complete = self.dispatch_models.as_ref().and_then(|value| value.as_ref().ok())
                    .copied().ok_or(CLOSED)?;
                bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .require_lifecycle_stop_complete_v4(controller_native, controller, profile, complete)
            })());
            if !matches!(self.dispatch_funding, Some(Ok(()))) { self.first = Some(First::DispatchFunding); }
        }
        if self.first.is_none() {
            self.dispatch_data = Some((|| {
                let (current, record) = self.read.operation_v1()
                    .map_err(|_| aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError::InvalidModel)?;
                let (projection, _) = self.read.projection_ready_v1()
                    .map_err(|_| aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError::InvalidModel)?;
                aos_sandbox_protocol::domain_ledger::stop_dispatch::LifecycleStopDispatchDataV1::from_prepared_request_data_v1(
                    current.operation_id(), record.digest(), projection.root(), request)
            })());
            if !matches!(self.dispatch_data, Some(Ok(_))) { self.first = Some(First::DispatchData); }
        }
        if self.first.is_none() {
            self.prepared = Some((|| {
                let original = StopSourceAuthorizationV4 { state: self, operation, bank, profile,
                    controller_native, controller };
                let data = self.dispatch_data.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
                LifecycleProtectedJournalOwnerV1::claim_original_stop_source_v4(source, original)?
                    .prepare_original_stop_dispatch_v1(&original, data.clone())
            })());
            if !matches!(self.prepared, Some(Ok(_))) { self.first = Some(First::Prepared); }
        }
        if self.first.is_none() {
            self.binding = Some((|| {
                let transaction = self.prepared.as_ref().and_then(|value| value.as_ref().ok())
                    .and_then(PreparedSourceLifecycleAdmissionV1::transaction_v1).ok_or(CLOSED)?;
                let native = self.native.as_mut().and_then(|value| value.as_mut().ok()).ok_or(CLOSED)?;
                bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                    .bind_provisioning_source_native_v1(native, controller_native, controller,
                        source.journal(), profile, transaction)
            })());
            if !matches!(self.binding, Some(Ok(()))) { self.first = Some(First::Binding); }
        }
        if self.first.is_none() {
            self.committed = Some((|| {
                let original = StopSourceAuthorizationV4 { state: self, operation, bank, profile,
                    controller_native, controller };
                let mut owner = LifecycleProtectedJournalOwnerV1::claim_original_stop_source_v4(source, original)
                    .map_err(|cause| ResidentDomainCommitFailureV1::Before(cause.into()))?;
                let prepared = self.prepared.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or_else(|| ResidentDomainCommitFailureV1::Before(crate::JournalError::ProtectedBoundary.into()))?;
                owner.commit_original_stop_source_v4(prepared, &original)
            })());
            if !matches!(self.committed, Some(Ok(_))) { self.first = Some(First::Commit); }
        }
        if self.first.is_none() {
            self.dispatch_readback = Some((|| {
                let transaction = self.prepared.as_ref().and_then(|value| value.as_ref().ok())
                    .and_then(PreparedSourceLifecycleAdmissionV1::transaction_v1)
                    .ok_or(crate::JournalError::ProtectedBoundary)?;
                let native = self.native.as_mut().and_then(|value| value.as_mut().ok())
                    .ok_or(crate::JournalError::ProtectedBoundary)?;
                let predecessor = self.identity.as_ref().ok_or(crate::JournalError::ProtectedBoundary)?;
                let successor = source.journal_ref_v1().stop_dispatch_source_successor_v1(native, predecessor, transaction)?;
                self.identity = Some(successor);
                Ok(())
            })());
            if !matches!(self.dispatch_readback, Some(Ok(()))) { self.first = Some(First::DispatchReadback); }
        }
        if self.first.is_some() { return Err(CLOSED); }
        self.dispatch_models.as_ref().and_then(|value| value.as_ref().ok()).copied().ok_or(CLOSED)
    }

    pub(super) fn completed_host_operation_v4(&self)
        -> std::result::Result<CurrentLifecycleOperationV1<'_>, crate::JournalError> {
        if !self.completed || !matches!(self.disposal, Some(Ok(()))) {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        self.host_operation_model_v4()
    }

    fn host_operation_model_v4(&self)
        -> std::result::Result<CurrentLifecycleOperationV1<'_>, crate::JournalError> {
        if self.purpose != StopSourcePurposeV4::HostDispatch || self.first.is_some()
            || !matches!(self.writer_funding, Some(Ok(())))
        {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        let (operation, record) = self.read.operation_v1()?;
        let expected = self.expected.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(crate::JournalError::ProtectedBoundary)?;
        crate::lifecycle::require_same_lifecycle_admission_v1(expected, operation)
            .map_err(|_| crate::JournalError::ProtectedBoundary)?;
        if operation.phase() != LifecyclePhaseV1::Completing
            || !matches!(operation.intent(), crate::lifecycle::LifecycleIntentV1::Stop { .. })
        {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        let (projection, _) = self.read.projection_ready_v1()?;
        Ok(CurrentLifecycleOperationV1::from_protected_current(operation.clone(), record, projection.root()))
    }

    pub(super) fn inventory_challenge_data_v5(&self, nonce: [u8; 32], boot: [u8; 16])
        -> std::result::Result<crate::lifecycle::LifecycleBootInventoryBootstrapChallengeV1,
            LifecycleProtectedJournalErrorV1> {
        let current = self.current_host_operation_v4().map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        let (projection, _) = self.read.projection_ready_v1()
            .map_err(|_| LifecycleProtectedJournalErrorV1::NonCanonicalRecord)?;
        LifecycleProtectedJournalOwnerV1::stop_inventory_challenge_data_v5(&current, projection, nonce, boot)
    }

    pub(super) fn retain_residual_observation_v4(&mut self,
        observation: crate::lifecycle::LifecycleEffectObservationV1,
    ) -> Result<()> {
        if self.entered || self.residual.is_some() || self.purpose != StopSourcePurposeV4::Residual
        { return Err(CLOSED); }
        if observation.capture_stop_residual_v4().is_none() {
            self.purpose = StopSourcePurposeV4::Success;
        }
        self.residual = Some(observation);
        Ok(())
    }

    pub(super) fn completed_record_v4(&self) -> Result<LifecycleRecordDigestV1> {
        if !self.completed || self.first.is_some() { return Err(CLOSED); }
        self.final_record.ok_or(CLOSED)
    }

    pub(super) fn stop_fence_data_v4(&self) -> Result<crate::lifecycle::LiveRuntimeFenceV1> {
        if self.first.is_some() || self.source_after.is_some()
            || self.purpose != StopSourcePurposeV4::Terminal
            || !matches!(self.writer_funding, Some(Ok(())))
        { return Err(CLOSED); }
        let (operation, _) = self.read.operation_v1()?;
        match operation.intent() {
            crate::lifecycle::LifecycleIntentV1::Stop { fence, .. } => Ok(*fence),
            _ => Err(CLOSED),
        }
    }

    pub(super) fn require_terminal_source_v4(
        &self, operation: OperationId,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        native: &ControllerCreateProvisioningReceivingV1,
        controller: &Journal, source: &Journal, expected: LifecycleRecordDigestV1,
        residual: bool,
    ) -> std::result::Result<(), crate::JournalError> {
        if self.purpose != StopSourcePurposeV4::Terminal {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        let original = StopSourceAuthorizationV4 { state: self, operation, bank, profile,
            controller_native: native, controller };
        original.require_current_v4()?;
        original.require_source_prefix_v4(source)?;
        let (current, record) = self.read.operation_v1()?;
        if record != expected || current.operation_id() != operation
            || (if residual { current.phase() != LifecyclePhaseV1::Residual }
                else { current.phase() != LifecyclePhaseV1::Terminal
                    || current.terminal_result() != Some(crate::lifecycle::LifecycleTerminalResultV1::Succeeded) })
            || !matches!(current.intent(), crate::lifecycle::LifecycleIntentV1::Stop { .. })
        { return Err(crate::JournalError::ProtectedBoundary); }
        Ok(())
    }

    pub(super) fn sample_data_v4(&self) -> Result<RawPairedClockSample> {
        if self.first.is_some() || self.source_after.is_some() { return Err(CLOSED); }
        self.before.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)
    }

    pub(super) fn require_cleanup_source_current_v1(
        &self, operation: OperationId,
        bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
        profile: &ProductionControllerNormalRootProfileV1,
        native: &ControllerCreateProvisioningReceivingV1,
        controller: &Journal, source: &Journal,
    ) -> std::result::Result<(), crate::JournalError> {
        if self.purpose != StopSourcePurposeV4::HostDispatch {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        let original = StopSourceAuthorizationV4 {
            state: self, operation, bank, profile, controller_native: native, controller,
        };
        original.require_current_v4()?;
        original.require_source_prefix_v4(source)
    }

    pub(super) fn cleanup_source_parent_data_v1(&self, operation: OperationId)
        -> Result<[u8; 32]> {
        if self.purpose != StopSourcePurposeV4::HostDispatch || self.first.is_some()
            || self.source_after.is_some() { return Err(CLOSED); }
        let (current, record) = self.read.operation_v1()?;
        if current.operation_id() != operation
            || !matches!(current.intent(), crate::lifecycle::LifecycleIntentV1::Stop { .. })
        { return Err(CLOSED); }
        Ok(*record.digest().as_bytes())
    }

    pub(super) fn cleanup_native_parts_v1(&mut self) -> Result<StopCleanupSourceNativePartsV1<'_>> {
        if self.purpose != StopSourcePurposeV4::HostDispatch || self.first.is_some()
            || self.source_after.is_some() || self.controller_after.is_some()
            || !matches!(self.funding, Some(Ok(())))
            || !matches!(self.writer_funding, Some(Ok(())))
        { return Err(CLOSED); }
        let first = self.sample_data_v4()?;
        let native = self.native.as_mut().and_then(|value| value.as_mut().ok()).ok_or(CLOSED)?;
        if native.failure().is_some() { return Err(CLOSED); }
        Ok(StopCleanupSourceNativePartsV1 {
            read: &self.read, native, identity: self.identity.as_mut().ok_or(CLOSED)?, first,
        })
    }

    pub(super) fn paid_models_v4(&self) -> Result<ResourceVector> {
        if self.first.is_some() || self.source_after.is_some() { return Err(CLOSED); }
        self.writer_models.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)
    }

    fn started_at_v4(&self) -> std::result::Result<LifecycleTimeV1, crate::JournalError> {
        let sample = self.before.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(crate::JournalError::ProtectedBoundary)?;
        let nanos = u64::try_from(sample.wall_seconds()).ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000_000))
            .ok_or(crate::JournalError::ProtectedBoundary)?;
        LifecycleTimeV1::new(nanos).map_err(|_| crate::JournalError::ProtectedBoundary)
    }

    pub(super) fn resident_bytes_v4(&self) -> Result<usize> {
        if !self.completed { return Err(CLOSED); }
        self.retirement.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(CLOSED)
    }

    pub(super) fn failure_v4<'owner>(
        &'owner self,
        controller: &'owner ControllerCreateProvisioningReceivingV1,
    ) -> Option<&'owner (dyn Error + 'static)> {
        match self.first? {
            First::Entry => selected_error(self.entry_original, controller, &self.entry),
            First::Native => self.native.as_ref().and_then(|result| match result {
                Ok(native) => native.failure(), Err(cause) => Some(cause as _),
            }),
            First::Clock => self.before_clock.failure().or_else(|| error(&self.before)),
            First::Models => error(&self.models),
            First::Funding => selected_error(self.funding_original, controller, &self.funding),
            First::Context => error(&self.context).or(Some(&CLOSED)),
            First::Projection => self.read.failure().or_else(|| error(&self.projection)),
            First::Expected => error(&self.expected),
            First::WriterModels => error(&self.writer_models),
            First::WriterFunding => selected_error(self.writer_funding_original, controller, &self.writer_funding),
            First::Semantic => error(&self.semantic),
            First::Prepared => error(&self.prepared),
            First::Binding => error(&self.binding),
            First::Commit => error(&self.committed),
            First::SourceAfter => self.native.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|native| native.failure()).or_else(|| error(&self.source_after)),
            First::ControllerAfter => controller.failure().or_else(|| error(&self.controller_after)),
            First::ClockAfter => self.after_clock.failure().or_else(|| error(&self.after)),
            First::Continuity => error(&self.continuity),
            First::Disposal => error(&self.disposal),
            First::Retirement => error(&self.retirement),
            First::DispatchModels => error(&self.dispatch_models),
            First::DispatchFunding => controller.failure().or_else(|| error(&self.dispatch_funding)),
            First::DispatchData => error(&self.dispatch_data),
            First::DispatchReadback => self.native.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|native| native.failure()).or_else(|| error(&self.dispatch_readback)),
            First::Reentry => Some(&CLOSED),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct StopSourceAuthorizationV4<'owner> {
    state: &'owner StopSourceTurnOriginalV4,
    operation: OperationId,
    bank: &'owner Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: &'owner ProductionControllerNormalRootProfileV1,
    controller_native: &'owner ControllerCreateProvisioningReceivingV1,
    controller: &'owner Journal,
}

impl StopSourceAuthorizationV4<'_> {
    pub(crate) fn require_current_v4(&self) -> std::result::Result<(), crate::JournalError> {
        if self.state.first.is_some() || self.state.source_after.is_some()
            || !matches!(self.state.funding, Some(Ok(())))
            || !matches!(self.state.writer_funding, Some(Ok(())))
            || self.state.context.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(Option::as_ref).is_none()
            || !matches!(self.state.expected, Some(Ok(_)))
            || self.state.native.as_ref().and_then(|result| result.as_ref().ok())
                .is_none_or(|native| native.failure().is_some())
        {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        self.bank.lock().map_err(|_| crate::JournalError::ProtectedBoundary)?
            .require_lifecycle_stop_native_current_v4(self.controller_native, self.controller, self.profile)
            .map_err(|_| crate::JournalError::ProtectedBoundary)
    }

    pub(crate) fn require_source_prefix_v4(&self, source: &Journal)
        -> std::result::Result<(), crate::JournalError>
    {
        source.require_current_source_provisioning_identity_v1(
            self.state.identity.as_ref().ok_or(crate::JournalError::ProtectedBoundary)?)
    }

    pub(crate) fn projection_v4(&self) -> std::result::Result<(
        &LifecycleProtectedJournalProjectionV1, &LifecycleJournalVerifierV1,
    ), crate::JournalError> {
        self.state.read.projection_ready_v1()
    }

    pub(crate) fn expected_operation_v4(&self)
        -> std::result::Result<&LifecycleOperationV1, crate::JournalError>
    {
        self.state.expected.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(crate::JournalError::ProtectedBoundary)
    }

    pub(crate) fn operation_v4(&self) -> OperationId { self.operation }

    pub(crate) fn purpose_v4(&self) -> StopSourcePurposeV4 { self.state.purpose }

    pub(crate) fn started_at_v4(&self) -> std::result::Result<LifecycleTimeV1, crate::JournalError> {
        self.state.started_at_v4()
    }

    pub(crate) fn residual_observation_v4(&self)
        -> std::result::Result<crate::lifecycle::LifecycleEffectObservationV1, crate::JournalError> {
        self.require_current_v4()?;
        if !matches!(self.state.purpose, StopSourcePurposeV4::Residual | StopSourcePurposeV4::Success) {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        self.state.residual.ok_or(crate::JournalError::ProtectedBoundary)
    }

    pub(crate) fn semantic_v4(&self)
        -> std::result::Result<&LifecycleMethodSemanticCommitV1, crate::JournalError>
    {
        self.state.semantic.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(crate::JournalError::ProtectedBoundary)
    }

    pub(crate) fn transaction_v4(&self) -> std::result::Result<[u8; 16], crate::JournalError> {
        if self.state.purpose == StopSourcePurposeV4::Admission { return Ok(self.operation.into_bytes()); }
        let (_, record) = self.state.read.operation_v1()?;
        use crate::lifecycle::{lifecycle_initial_reservation_transaction_id_v1,
            lifecycle_plan_binding_transaction_id_v1, lifecycle_progress_transaction_id_v1};
        Ok(match self.state.purpose {
            StopSourcePurposeV4::Admission => return Err(crate::JournalError::ProtectedBoundary),
            StopSourcePurposeV4::BindPlan => lifecycle_plan_binding_transaction_id_v1(self.operation, record.digest()),
            StopSourcePurposeV4::InitialProgress => lifecycle_initial_reservation_transaction_id_v1(self.operation, record.digest()),
            StopSourcePurposeV4::SemanticReadiness => lifecycle_progress_transaction_id_v1(self.operation, record.digest(), b"commit-readiness"),
            StopSourcePurposeV4::SemanticCommit => lifecycle_progress_transaction_id_v1(self.operation, record.digest(), b"semantic-commit"),
            StopSourcePurposeV4::Completing => lifecycle_progress_transaction_id_v1(self.operation, record.digest(), b"postcommit-progress"),
            StopSourcePurposeV4::Residual => lifecycle_progress_transaction_id_v1(self.operation, record.digest(), b"runtime-stop-residual"),
            StopSourcePurposeV4::Success => lifecycle_progress_transaction_id_v1(self.operation, record.digest(), b"runtime-stop-success"),
            StopSourcePurposeV4::HostDispatch | StopSourcePurposeV4::Terminal => return Err(crate::JournalError::ProtectedBoundary),
        })
    }

    pub(crate) fn current_data_v4(&self)
        -> std::result::Result<Option<(LifecycleProtectedJournalKeyV1, LifecycleOperationV1,
            LifecycleRecordDigestV1, aos_sandbox_model::ObjectDigest)>, LifecycleProtectedJournalErrorV1>
    {
        self.require_current_v4()?;
        let Some((key, model, record)) = self.state.read.optional_selection_v4()? else {
            return Ok(None);
        };
        crate::lifecycle::require_same_lifecycle_admission_v1(self.expected_operation_v4()?, model)?;
        let (projection, _) = self.projection_v4()?;
        Ok(Some((key.clone(), model.clone(), record, projection.root())))
    }

    pub(crate) fn decode_admission_operation_v4(&self, body: &[u8])
        -> std::result::Result<Ref<'_, LifecycleOperationDecodeOriginalV1>, LifecycleProtectedJournalErrorV1>
    {
        let invalid = || LifecycleProtectedJournalErrorV1::NonCanonicalRecord;
        let mut original = self.state.admission_decode.try_borrow_mut().map_err(|_| invalid())?;
        if original.completed().is_some() { *original = LifecycleOperationDecodeOriginalV1::new(); }
        original.decode_once(body).map_err(|_| invalid())?;
        drop(original);
        self.state.admission_decode.try_borrow().map_err(|_| invalid())
    }
}

// Entry precedes the ordinary slot allocation. Inline turns use this same
// purpose-closed native engine; neither path infers payment from a DTO.
fn begin_controller_turn_v4(
    bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: &ProductionControllerNormalRootProfileV1,
    controller_native: &mut ControllerCreateProvisioningReceivingV1,
    resident: ResourceVector,
    controller: &mut Journal,
    entry: StopSourceEntryV5,
    controller_entered: &mut bool,
) -> Result<()> {
    let complete = resident.checked_add(StopSourceTurnOriginalV4::fixed_demand_v4()?)?;
    let bank = bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
    bank.begin_next_lifecycle_stop_native_v4(controller_native, controller, profile,
        complete, controller_entered)?;
    if matches!(entry, StopSourceEntryV5::FreshCleanup) {
        bank.arm_stop_cleanup_source_turn_v1(controller_native, controller, profile)?;
    }
    Ok(())
}

fn finish_controller_turn_v4(
    bank: &Arc<Mutex<ControllerResourceBankOpeningV1>>,
    profile: &ProductionControllerNormalRootProfileV1,
    controller_native: &mut ControllerCreateProvisioningReceivingV1,
    controller: &mut Journal,
) -> Result<()> {
    bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
        .finish_lifecycle_stop_native_once_v4(controller_native, controller, profile)
}

fn error<T, E: Error + 'static>(value: &Option<std::result::Result<T, E>>)
    -> Option<&(dyn Error + 'static)>
{
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn selected_error<'owner>(selected: bool,
    controller: &'owner ControllerCreateProvisioningReceivingV1,
    returned: &'owner Option<Result<()>>,
) -> Option<&'owner (dyn Error + 'static)> {
    if selected { controller.failure() } else { error(returned) }
}
