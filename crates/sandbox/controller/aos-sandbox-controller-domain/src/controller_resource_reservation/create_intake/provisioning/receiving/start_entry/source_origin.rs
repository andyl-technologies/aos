//! Retains Start Source admission and its closed canonical progress turns.
//!
//! Native custody and original accepted bounds precede every schema/model
//! growth. The first turn issues its exact Source Intent; later turns require
//! the privately retained actual completed Host association. Neither can
//! publish Host authority, renew a horizon or admit another operation.

mod runner;
mod progress;
mod append_clock;
use append_clock::StartSourceAppendClockV2;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum StartSourcePurposeV2 {
    Admission,
    BindPlan,
    InitialProgress,
    SemanticReadiness,
    SemanticCommit,
    Completing,
    Terminal,
}

impl StartSourcePurposeV2 {
    fn expected_phase_v2(self) -> LifecyclePhaseV1 {
        match self {
            Self::Admission | Self::BindPlan | Self::InitialProgress => LifecyclePhaseV1::Accepted,
            Self::SemanticReadiness => LifecyclePhaseV1::Prepared,
            Self::SemanticCommit => LifecyclePhaseV1::ReadyToCommit,
            Self::Completing => LifecyclePhaseV1::Committed,
            Self::Terminal => LifecyclePhaseV1::Completing,
        }
    }

    fn destination_phase_v2(self) -> LifecyclePhaseV1 {
        match self {
            Self::Admission | Self::BindPlan => LifecyclePhaseV1::Accepted,
            Self::InitialProgress => LifecyclePhaseV1::Prepared,
            Self::SemanticReadiness => LifecyclePhaseV1::ReadyToCommit,
            Self::SemanticCommit => LifecyclePhaseV1::Committed,
            Self::Completing => LifecyclePhaseV1::Completing,
            Self::Terminal => LifecyclePhaseV1::Terminal,
        }
    }
}

use super::*;
use aos_sandbox_model::{RawPairedClockSample,ResourceId};
use aos_sandbox_broker::source_receiving::SourceProvisioningCurrentnessOriginalV1;
use aos_sandbox_protocol::domain_ledger::operation::StartNativeOriginDataV1;
use aos_sandbox_protocol::domain_ledger::effect_history::PublicMutationEffectHistoryV1;
use crate::journal::source_provisioning::SourceProvisioningIdentityV1;
use crate::lifecycle::{LifecycleOperationV1,LifecycleIntentV1,LifecyclePhaseV1,
    PreparedSourceLifecycleAdmissionV1,SourceLifecycleAdmissionCommitV1,LifecycleProtectedJournalKeyV1};
use super::super::source::SourceAdmissionErrorV1;

#[derive(Clone,Copy)]
enum First { Next,Native,Clock,Time,Models,Funding,Replay,WriterModels,WriterFunding,Context,Expected,ExpectedOrigin,Semantic,Prepared,Binding,Commit,
    SourceAfter,NativeAfter,AfterClock,AfterTime,Disposal,Retirement,Reentry }

pub(super) struct StartSourceOriginOriginalV1 {
    purpose: StartSourcePurposeV2,
    entered:bool,
    controller_entered:bool,
    next:Option<Result<(),ResourceReservationErrorV1>>,
    native:Option<Result<SourceProvisioningCurrentnessOriginalV1,ResourceReservationErrorV1>>,
    before_clock:PairOriginal,
    after_clock:PairOriginal,
    append_clock: std::cell::RefCell<StartSourceAppendClockV2>,
    append_clock_retained: Option<StartSourceAppendClockV2>,
    before:Option<Result<RawPairedClockSample,SourceGenesisErrorV1>>,
    time:Option<Result<(),ResourceReservationErrorV1>>,
    models:Option<Result<ResourceVector,ResourceReservationErrorV1>>,
    funding:Option<Result<(),ResourceReservationErrorV1>>,
    read:crate::lifecycle::LifecycleHistoricalReadOriginalV1,
    replay:Option<Result<(),crate::JournalError>>,
    writer_models:Option<Result<ResourceVector,ResourceReservationErrorV1>>,
    writer_funding:Option<Result<(),ResourceReservationErrorV1>>,
    admission_decode:std::cell::RefCell<crate::lifecycle::LifecycleOperationDecodeOriginalV1>,
    context:Option<Result<PublicMutationEffectHistoryV1,crate::ReconcilerError>>,
    expected:Option<Result<LifecycleOperationV1,SourceAdmissionErrorV1>>,
    expected_origin:Option<Result<(),aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError>>,
    semantic: Option<Result<crate::lifecycle::LifecycleMethodSemanticCommitV1, SourceAdmissionErrorV1>>,
    identity:Option<SourceProvisioningIdentityV1>,
    prepared:Option<Result<PreparedSourceLifecycleAdmissionV1,crate::lifecycle::LifecycleProtectedJournalErrorV1>>,
    binding:Option<Result<(),ResourceReservationErrorV1>>,
    committed:Option<Result<SourceLifecycleAdmissionCommitV1,crate::protected_domain_journal::ResidentDomainCommitFailureV1>>,
    completed_record: Option<crate::lifecycle::LifecycleRecordDigestV1>,
    source_after:Option<Result<(),crate::JournalError>>,
    controller_after:Option<Result<(),ResourceReservationErrorV1>>,
    after:Option<Result<RawPairedClockSample,SourceGenesisErrorV1>>,
    after_time:Option<Result<(),ResourceReservationErrorV1>>,
    disposal:Option<Result<(),ResourceReservationErrorV1>>,
    retirement:Option<Result<(),ResourceReservationErrorV1>>,
    base:Option<ResourceVector>,
    fence:Option<Result<(),crate::JournalError>>,
    first:Option<First>,
}

impl StartSourceOriginOriginalV1 {
    pub(super) fn new()->Self { Self::for_purpose_v2(StartSourcePurposeV2::Admission) }

    pub(super) fn for_purpose_v2(purpose: StartSourcePurposeV2) -> Self {Self {purpose,entered:false,controller_entered:false,next:None,native:None,before_clock:Default::default(),
        after_clock:Default::default(),append_clock:Default::default(),append_clock_retained:None,before:None,time:None,models:None,funding:None,
        read:crate::lifecycle::LifecycleHistoricalReadOriginalV1::new(),replay:None,writer_models:None,writer_funding:None,
        admission_decode:std::cell::RefCell::new(crate::lifecycle::LifecycleOperationDecodeOriginalV1::new()),context:None,
        expected:None,expected_origin:None,semantic:None,identity:None,prepared:None,binding:None,committed:None,completed_record:None,source_after:None,
        controller_after:None,after:None,after_time:None,disposal:None,retirement:None,base:None,fence:None,first:None}}

    pub(super) fn entered_v2(&self) -> bool { self.entered }

    pub(super) fn completed_record_v2(&self) -> Result<crate::lifecycle::LifecycleRecordDigestV1, ResourceReservationErrorV1> {
        if !self.completed_v1() { return Err(CLOSED); }
        self.completed_record.ok_or(CLOSED)
    }

    pub(super) fn retain_fence_v1(&mut self,result:Result<(),crate::JournalError>) {
        if self.fence.is_some() {std::process::abort();}
        self.fence=Some(result);
    }

    // Mechanical affinity only. Root independently replays the full current
    // Source under its own genuine Host R scope; this cannot lend a writer.
    pub(super) fn require_completed_source_affinity_v1(&self,source:&Journal)
        ->Result<(),ResourceReservationErrorV1> {
        if !self.completed_v1() {return Err(CLOSED);}
        source.require_completed_source_instance_v1(self.identity.as_ref().ok_or(CLOSED)?)?;
        Ok(())
    }

    pub(super) fn completed_v1(&self)->bool {
        self.first.is_none() && matches!(self.disposal,Some(Ok(()))) && matches!(self.retirement,Some(Ok(())))
    }

    pub(super) fn require_sample_v1(origin:StartNativeOriginDataV1,sample:RawPairedClockSample)
        ->Result<(),ResourceReservationErrorV1> {
        origin.first_native_clock_v1().validate_later_sample(sample)
            .map_err(|_|CLOSED)?;
        if sample.boottime_nanoseconds()>=origin.cutoff_v1()
            || origin.accepted_v1().cutoff_for_sample_data_v1(sample).is_none() {return Err(CLOSED);}
        Ok(())
    }

    pub(super) fn fixed_demand_v1()->Result<ResourceVector,ResourceReservationErrorV1> {
        let bytes=std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes|bytes.checked_add(PairOriginal::dominant_requested_bytes_v1()?.checked_mul(3)?))
            .and_then(|bytes|bytes.checked_add(std::mem::size_of::<crate::lifecycle::LifecycleProtectedJournalOwnerV1<'_>>().checked_mul(2)?))
            .and_then(|bytes|bytes.checked_add(std::mem::size_of::<usize>().checked_mul(2)?))
            .and_then(|bytes|u64::try_from(bytes).ok()).ok_or(CLOSED)?;
        let files=PairOriginal::MAXIMUM_RETAINED_FILES_V1.checked_mul(3)
            .and_then(|files|u64::try_from(files).ok()).ok_or(CLOSED)?;
        let names=PairOriginal::receiving_metadata_cells_v1().and_then(|names|names.checked_mul(3))
            .and_then(|names|u64::try_from(names).ok()).ok_or(CLOSED)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes,bytes).with(D::OpenFiles,files).with(D::MetadataEntries,names))
    }

    pub(super) fn has_selected_failure_v1(&self)->bool {self.first.is_some()}

    pub(super) fn native_failure_is_selected_v1(&self)->bool {
        matches!(self.first,Some(First::Next|First::Native|First::Funding|First::WriterFunding|First::NativeAfter))
    }

    pub(super) fn fmt_selected_decoder_failure_v1(&self,formatter:&mut std::fmt::Formatter<'_>)->Option<std::fmt::Result> {
        if !matches!(self.first,Some(First::Prepared)) {return None;}
        let original=self.admission_decode.try_borrow().ok()?;
        let cause=original.failure_view_v1()?;
        Some(std::fmt::Display::fmt(cause,formatter))
    }

    pub(super) fn failure<'a>(&'a self,native:Option<&'a(dyn Error+'static)>)->Option<&'a(dyn Error+'static)> {
        match self.first? {
            First::Next=>native.or_else(||self.next.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::Native=>native.or_else(||self.native.as_ref()?.as_ref().err().map(|cause|cause as _))
                .or_else(||self.native.as_ref()?.as_ref().ok()?.failure()),
            First::Clock=>self.before_clock.failure().or_else(||self.before.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::Time=>self.time.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Models=>self.models.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Funding=>native.or_else(||self.funding.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::Replay=>self.read.failure().or_else(||self.replay.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::WriterModels=>self.writer_models.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::WriterFunding=>native.or_else(||self.writer_funding.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::Context=>self.context.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Expected=>self.expected.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::ExpectedOrigin=>self.expected_origin.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Semantic => self.semantic.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Prepared=>self.prepared.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Binding=>self.binding.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Commit=>self.append_clock_retained.as_ref().and_then(StartSourceAppendClockV2::failure)
                .or_else(|| self.committed.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::SourceAfter=>self.native.as_ref().and_then(|value|value.as_ref().ok()).and_then(|native|native.failure())
                .or_else(||self.source_after.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::NativeAfter=>native.or_else(||self.controller_after.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::AfterClock=>self.after_clock.failure().or_else(||self.after.as_ref()?.as_ref().err().map(|cause|cause as _)),
            First::AfterTime=>self.after_time.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Disposal=>self.disposal.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Retirement=>self.retirement.as_ref()?.as_ref().err().map(|cause|cause as _),
            First::Reentry=>Some(&CLOSED),
        }
    }
}

pub(crate) struct StartSourceAdmissionAuthorizationV1<'turn> {
    state:&'turn StartSourceOriginOriginalV1,
    native:&'turn StartNativeStateV1,
    controller:&'turn Journal,
    plan:&'turn Arc<crate::OperationPlan>,
    origin:StartNativeOriginDataV1,
    completion: Option<&'turn super::terminal::StartTerminalMaterialV2>,
}

impl StartSourceAdmissionAuthorizationV1<'_> {
    pub(crate) fn require_current_v1(&self)->Result<(),crate::JournalError> {
        self.native.require_current_v1(self.controller).map_err(|_|crate::JournalError::ProtectedBoundary)?;
        if !self.state.entered || self.state.source_after.is_some() || self.state.first.is_some()
            || self.state.append_clock_retained.is_some()
            || !matches!(self.state.funding,Some(Ok(()))) || !matches!(self.state.writer_funding,Some(Ok(())))
            || !matches!(self.state.expected,Some(Ok(_))) || !matches!(self.state.expected_origin,Some(Ok(())))
            || self.state.identity.is_none()
            || self.state.native.as_ref().and_then(|value|value.as_ref().ok()).is_none_or(|native|native.failure().is_some()) {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        let before=*self.state.before.as_ref().and_then(|value|value.as_ref().ok()).ok_or(crate::JournalError::ProtectedBoundary)?;
        StartSourceOriginOriginalV1::require_sample_v1(self.origin,before)
            .map_err(|_|crate::JournalError::ProtectedBoundary)?;
        let expected=self.expected_operation_v1();
        if expected.operation_id()!=self.plan.operation_id() || expected.project()!=self.q04_v1().project()
            || !matches!(expected.intent(),LifecycleIntentV1::Start{sandbox,..} if *sandbox==self.q04_v1().sandbox())
            || expected.start_native_origin_v1()!=Some(self.origin) || expected.phase()!=self.state.purpose.expected_phase_v2() {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        if self.state.purpose != StartSourcePurposeV2::Admission {
            let material = self.completion.ok_or(crate::JournalError::ProtectedBoundary)?;
            material.require_original_v2(self.plan, self.origin)?;
            material.require_native_v2(self.native)?;
        }
        self.plan.require_accepted_start_data_v1(self.controller)
            .map_err(|_|crate::JournalError::ProtectedBoundary)?;
        Ok(())
    }
    pub(crate) fn require_source_prefix_v1(&self,source:&Journal)->Result<(),crate::JournalError> {
        source.require_current_source_provisioning_identity_v1(self.source_identity_v1())
    }
    pub(crate) fn projection_v1(&self)->Result<(
        &crate::lifecycle::protected_journal::LifecycleProtectedJournalProjectionV1,
        &crate::lifecycle::LifecycleJournalVerifierV1),crate::JournalError> {
        self.state.read.projection_ready_v1()
    }
    pub(crate) fn decode_admission_operation_v1(&self,body:&[u8])
        ->Result<std::cell::Ref<'_,crate::lifecycle::LifecycleOperationDecodeOriginalV1>,crate::lifecycle::LifecycleProtectedJournalErrorV1> {
        let invalid=||crate::lifecycle::LifecycleProtectedJournalErrorV1::NonCanonicalRecord;
        let mut original=self.state.admission_decode.try_borrow_mut().map_err(|_|invalid())?;
        if original.completed().is_some() { *original=crate::lifecycle::LifecycleOperationDecodeOriginalV1::new(); }
        original.decode_once(body).map_err(|_|invalid())?;
        drop(original);
        self.state.admission_decode.try_borrow().map_err(|_|invalid())
    }

    pub(crate) fn expected_operation_v1(&self)->&LifecycleOperationV1 {
        match self.state.expected.as_ref().and_then(|value|value.as_ref().ok()) {
            Some(value)=>value,None=>std::process::abort(),
        }
    }
    pub(crate) fn expected_key_v1(&self)->Result<LifecycleProtectedJournalKeyV1,crate::JournalError> {
        crate::lifecycle::lifecycle_protected_key_v1(crate::lifecycle::provisioning_operation_record_kind_v1(self.state.purpose.destination_phase_v2()),
            self.q04_v1().project(),ResourceId::from_bytes(self.q04_v1().sandbox().into_bytes()),self.plan.operation_id())
            .map_err(|_|crate::JournalError::ProtectedBoundary)
    }
    pub(crate) fn transaction_id_v1(&self)->Result<[u8;16],crate::JournalError> {
        use crate::lifecycle::{lifecycle_plan_binding_transaction_id_v1,
            lifecycle_initial_reservation_transaction_id_v1, lifecycle_progress_transaction_id_v1};
        let operation = self.plan.operation_id();
        if self.state.purpose == StartSourcePurposeV2::Admission { return Ok(operation.into_bytes()); }
        let (_, record) = self.state.read.operation_v1()?;
        Ok(match self.state.purpose {
            StartSourcePurposeV2::Admission => return Err(crate::JournalError::ProtectedBoundary),
            StartSourcePurposeV2::BindPlan => lifecycle_plan_binding_transaction_id_v1(operation, record.digest()),
            StartSourcePurposeV2::InitialProgress => lifecycle_initial_reservation_transaction_id_v1(operation, record.digest()),
            StartSourcePurposeV2::SemanticReadiness => lifecycle_progress_transaction_id_v1(operation, record.digest(), b"semantic-readiness"),
            StartSourcePurposeV2::SemanticCommit => lifecycle_progress_transaction_id_v1(operation, record.digest(), b"semantic-commit"),
            StartSourcePurposeV2::Completing => lifecycle_progress_transaction_id_v1(operation, record.digest(), b"postcommit-progress"),
            StartSourcePurposeV2::Terminal => lifecycle_progress_transaction_id_v1(operation, record.digest(), b"observed-effect-progress"),
        })
    }
    pub(crate) fn q04_v1(&self)->&Q04CutIdentityV1 {
        match self.native.q04_v1() {Ok(value)=>value,Err(_)=>std::process::abort()}
    }
    pub(crate) fn source_identity_v1(&self)->&SourceProvisioningIdentityV1 {
        match self.state.identity.as_ref() {Some(value)=>value,None=>std::process::abort()}
    }
}

const CLOSED:ResourceReservationErrorV1=ResourceReservationErrorV1::Conflict;
