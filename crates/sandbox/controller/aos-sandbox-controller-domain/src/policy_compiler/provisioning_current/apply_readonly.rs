//! Holds Apply's independent Controller model and exact Storage Session cut.
//!
//! The same fixed/native/semantic reader supplies both targets. Controller's
//! canonical readonly Journal is moved from that completed reader. Session
//! retains its exact marked C8 transaction and complete authenticated history;
//! no incoming packet can substitute a native cut or construct a writer.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{OperationId, ProjectId, SandboxId, RawPairedClockSample, RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
    controller_use::ControllerSessionReservedBodyDataV1,
};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{Journal, JournalError, RootReadonlyJournalModelOriginalsV1 as Model};
use crate::normal_root::{NormalRootStartupErrorV1, RootApplyStageReceivingV1, RootHostLaunchStageReceivingV1};
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1,
    create_storage_current::controller_readonly::native_read::{
        RootFixedNativeReadOriginalsV1 as Reader, RootFixedNativeReadbackV1,
        RootCreateStoppedHistoricalOriginalV2,
    }};
use super::{RootContinuationHorizonDataV1, RootContinuationClockGateV1};

type Cause = Box<dyn Error>;

// Each branch borrows a genuine armed purpose. The common reader cannot
// accept an amount, callback or an untyped purpose as authority.
enum ReadonlyReceivingV2<'held, 'flight, 'startup> {
    Apply(&'held mut RootApplyStageReceivingV1<'flight, 'startup>),
    Host(&'held mut RootHostLaunchStageReceivingV1<'flight, 'startup>),
}

macro_rules! readonly_stage {
    ($name:ident) => {
        fn $name(&mut self, demand: RootContinuationDemandV1) -> Result<(), NormalRootStartupErrorV1> {
            match self {
                Self::Apply(stage) => stage.$name(demand),
                Self::Host(stage) => stage.$name(demand),
            }
        }
    };
}

impl ReadonlyReceivingV2<'_, '_, '_> {
    fn controller_identity_v1(&self) -> (u32, u32) {
        match self {
            Self::Apply(stage) => stage.controller_identity_v1(),
            Self::Host(stage) => stage.controller_identity_v1(),
        }
    }

    readonly_stage!(admit_controller_fixed_once_v1);
    readonly_stage!(admit_controller_native_once_v1);
    readonly_stage!(admit_controller_semantic_once_v1);
    readonly_stage!(admit_storage_fixed_once_v1);
    readonly_stage!(admit_storage_native_once_v1);
    readonly_stage!(admit_storage_semantic_once_v1);
}

#[derive(Clone, Copy)]
struct HistoricalTargetV2 {
    parent: OperationId,
    project: ProjectId,
    sandbox: SandboxId,
}

struct NativeV1 {
    controller: Reader,
    session: Reader,
    controller_model: Option<Box<Model>>,
    controller_position: Option<(u64, u64)>,
    historical: Option<RootCreateStoppedHistoricalOriginalV2>,
    session_reserved: Option<Result<ControllerSessionReservedBodyDataV1, Cause>>,
    clock: RootContinuationClockGateV1,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    primary: Option<Result<(), Cause>>,
    posts: Option<Result<(), JournalError>>,
}

impl NativeV1 {
    fn new(horizon: RootContinuationHorizonDataV1, historical: Option<HistoricalTargetV2>) -> Self {
        let controller = match historical {
            Some(target) => Reader::controller_create_stopped_history_v2(target.parent, target.project, target.sandbox),
            None => Reader::controller_current_v1(),
        };
        Self { controller, session: Reader::default(),
            controller_model: None, controller_position: None, historical: None, session_reserved: None,
            clock: RootContinuationClockGateV1::new(horizon), after_clock: Default::default(),
            after: None, primary: None, posts: None }
    }

    fn fixed_demand_v1(historical: bool) -> Result<ResourceVector, JournalError> {
        let context = if historical {
            size_of::<RootHostReadonlyContextV2>()
        } else {
            size_of::<RootApplyReadonlyContextV1>()
        };
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| context.checked_mul(2).and_then(|context| bytes.checked_add(context)))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<ReadonlyReceivingV2<'_, '_, '_>>()))
            .and_then(|bytes| bytes.checked_add(RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        Reader::controller_current_fixed_demand_v1()?
            .checked_add(RootContinuationClockGateV1::receiving_demand_v1()?)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
                .with(D::OpenFiles, RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64)))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    fn observe_inner(&mut self, stage: &mut ReadonlyReceivingV2<'_, '_, '_>, lane: [u8; 16],
        historical: Option<HistoricalTargetV2>)
        -> Result<(), Cause>
    {
        let uid = stage.controller_identity_v1().0;
        self.clock.check_next_once_v1()?;
        self.controller.capture_once(uid);
        self.controller.require_captured_v1()?;
        stage.admit_controller_native_once_v1(demand(self.controller.replay_demand_v1()?))?;
        self.clock.check_next_once_v1()?;
        self.controller.audit_once();
        let semantic = self.controller.additional_semantic_demand_v1()?
            .checked_add(Model::receiving_demand_v1(&self.controller)?)?;
        stage.admit_controller_semantic_once_v1(demand(semantic))?;
        self.clock.check_next_once_v1()?;
        self.controller.replay_once();
        let actual = self.controller.replay_native_v1()?;
        self.controller_position = Some((actual.next, actual.end));
        self.session_reserved = Some(session_reserved_v1(actual.state, lane));
        self.session_reserved.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;

        // Adoption requires the real Controller native post first. Its own
        // separately prepaid model-parent post remains owed around all joins.
        self.controller.finish_post_once();
        self.controller.terminal_native_v1()?;
        if historical.is_some() {
            self.historical = Some(self.controller.take_create_stopped_historical_v2()?);
            self.historical.as_ref().ok_or(JournalError::ProtectedBoundary)?
                .require_cut_v2(&self.controller.terminal_native_v1()?)?;
        }
        self.controller_model = Some(Box::new(Model::new()));
        self.controller_model.as_mut().ok_or(JournalError::ProtectedBoundary)?
            .adopt_once(&mut self.controller);
        self.controller_model.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v1()?;

        stage.admit_storage_fixed_once_v1(demand(Reader::fixed_demand_v1()?))?;
        self.clock.check_next_once_v1()?;
        self.session.capture_once(uid);
        self.session.require_captured_v1()?;
        stage.admit_storage_native_once_v1(demand(self.session.replay_demand_v1()?))?;
        self.clock.check_next_once_v1()?;
        // The fixed Session target uses the existing indexed SessionSchema,
        // whose complete codec/index geometry was paid by replay_demand_v1.
        // The full-cold audit belongs only to C/Source/Cache targets.
        stage.admit_storage_semantic_once_v1(demand(ResourceVector::ZERO))?;
        let reserved = self.session_reserved.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.clock.check_next_once_v1()?;
        self.session.replay_marked_once_v1((reserved.after_next, reserved.after_end));
        let actual = self.session.replay_native_v1()?;
        if actual.names != reserved.names { return Err(JournalError::ProtectedBoundary.into()); }
        Ok(())
    }

    fn require_body_v1(&self) -> Result<(), JournalError> {
        if !matches!(self.primary, Some(Ok(()))) || self.posts.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.controller_model.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v1()?;
        self.session.replay_native_v1().map(|_| ())
    }

    fn finish_after_once_v1(&mut self) {
        // Every actually entered native destination is observed independently
        // even if a funding gate, decoder, semantic join or body already failed.
        self.controller.finish_post_once();
        self.session.finish_post_once();
        if let Some(model) = &mut self.controller_model { model.finish_parent_post_once_v1(); }
        self.after = Some(self.after_clock.observe_once(None));
        self.posts = Some((|| {
            if !matches!(self.primary, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
            let model = self.controller_model.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            model.require_parent_post_v1()?;
            self.session.terminal_native_v1()?;
            let sample = *self.after.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            self.clock.require_final_sample_v1(sample)
        })());
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.controller.failure().or_else(|| self.clock.failure())
            .or_else(|| cause_box(&self.session_reserved))
            .or_else(|| self.controller_model.as_ref().and_then(|model| model.failure()))
            .or_else(|| self.session.failure()).or_else(|| cause_box(&self.primary))
            .or_else(|| self.controller_model.as_ref().and_then(|model| model.parent_post_failure_v1()))
            .or_else(|| self.controller.post_failure()).or_else(|| self.session.post_failure())
            .or_else(|| self.after_clock.failure()).or_else(|| cause(&self.after)).or_else(|| cause(&self.posts))
    }
}

/// Holds only native readers funded by the genuine new Apply stage borrower.
pub(crate) struct RootApplyReadonlyContextV1 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<NativeV1>>,
    reentered: bool,
}

impl RootApplyReadonlyContextV1 {
    pub(crate) fn new() -> Self {
        Self { geometry: None, funding: None, native: None, reentered: false }
    }

    pub(crate) fn observe_once_v1(&mut self, stage: &mut RootApplyStageReceivingV1<'_, '_>,
        lane: [u8; 16], horizon: RootContinuationHorizonDataV1)
    {
        self.observe_selected_once_v2(ReadonlyReceivingV2::Apply(stage), lane, horizon, None);
    }

    fn observe_selected_once_v2(&mut self, mut stage: ReadonlyReceivingV2<'_, '_, '_>,
        lane: [u8; 16], horizon: RootContinuationHorizonDataV1, historical: Option<HistoricalTargetV2>)
    {
        if self.geometry.is_some() { self.reentered = true; return; }
        self.geometry = Some(NativeV1::fixed_demand_v1(historical.is_some()));
        let Some(Ok(fixed)) = self.geometry else { return; };
        self.funding = Some(stage.admit_controller_fixed_once_v1(demand(fixed)));
        if !matches!(self.funding, Some(Ok(()))) { return; }
        self.native = Some(Box::new(NativeV1::new(horizon, historical)));
        if let Some(native) = &mut self.native {
            native.primary = Some(native.observe_inner(&mut stage, lane, historical));
        }
    }

    pub(crate) fn controller_mut_v1(&mut self) -> Result<&mut Journal, JournalError> {
        self.require_body_v1()?;
        self.native.as_mut().and_then(|native| native.controller_model.as_mut())
            .ok_or(JournalError::ProtectedBoundary)?.journal_mut_v1()
    }

    pub(crate) fn controller_state_v1(&self)
        -> Result<&std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>, JournalError>
    {
        self.require_body_v1()?;
        self.native.as_ref().and_then(|native| native.controller_model.as_ref())
            .ok_or(JournalError::ProtectedBoundary)?.raw_state_v1()
    }

    pub(crate) fn session_v1(&self) -> Result<RootFixedNativeReadbackV1<'_>, JournalError> {
        self.require_body_v1()?;
        self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?.session.replay_native_v1()
    }

    pub(crate) fn controller_position_v1(&self) -> Result<(u64, u64), JournalError> {
        self.require_body_v1()?;
        self.native.as_ref().and_then(|native| native.controller_position).ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn compiler_input_bytes_v1(&self) -> Result<u64, JournalError> {
        self.controller_state_v1()?.iter().try_fold(0_u64, |sum, ((_, key), bytes)| {
            let row = key.len().checked_add(bytes.len()).and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(JournalError::JournalTooLarge)?;
            sum.checked_add(row).ok_or(JournalError::JournalTooLarge)
        })
    }

    pub(crate) fn completed_clock_v1(&self) -> Result<RawPairedClockSample, JournalError> {
        self.require_complete_v1()?;
        self.native.as_ref().and_then(|native| native.after.as_ref()).and_then(|sample| sample.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn require_body_v1(&self) -> Result<(), JournalError> {
        if self.reentered || !matches!(self.funding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_body_v1()
    }

    pub(crate) fn finish_after_once_v1(&mut self) {
        match self.native.as_mut() {
            Some(native) if native.posts.is_none() => native.finish_after_once_v1(),
            _ => self.reentered = true,
        }
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), JournalError> {
        if self.reentered || !matches!(self.funding, Some(Ok(())))
            || self.native.as_ref().is_none_or(|native| !matches!(native.posts, Some(Ok(()))))
        { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.geometry).or_else(|| cause(&self.funding))
            .or_else(|| self.native.as_ref().and_then(|native| native.failure()))
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}

/// Retains Host's actual full C replay and strict historical transaction check.
///
/// A current Sandbox projection may already describe a later Start. Historical
/// STOPPED comes only from the observed atomic terminal transaction, while the
/// current model and old prepared Session cut remain independently checked.
pub(crate) struct RootHostReadonlyContextV2 {
    original: RootApplyReadonlyContextV1,
}

impl RootHostReadonlyContextV2 {
    pub(crate) fn new() -> Self {
        Self { original: RootApplyReadonlyContextV1::new() }
    }

    pub(crate) fn observe_once_v2(&mut self, stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        lane: [u8; 16], parent: OperationId, project: ProjectId, sandbox: SandboxId,
        horizon: RootContinuationHorizonDataV1)
    {
        self.original.observe_selected_once_v2(ReadonlyReceivingV2::Host(stage), lane, horizon,
            Some(HistoricalTargetV2 { parent, project, sandbox }));
    }

    pub(crate) fn controller_mut_v2(&mut self) -> Result<&mut Journal, JournalError> {
        self.original.controller_mut_v1()
    }

    pub(crate) fn controller_state_v2(&self)
        -> Result<&std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>, JournalError>
    {
        self.original.controller_state_v1()
    }

    pub(crate) fn controller_with_historical_v2(&mut self)
        -> Result<(&mut Journal, &RootCreateStoppedHistoricalOriginalV2), JournalError>
    {
        self.original.require_body_v1()?;
        let native = self.original.native.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        let historical = native.historical.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let controller = native.controller_model.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        Ok((controller.journal_mut_v1()?, historical))
    }

    pub(crate) fn historical_v2(&self) -> Result<&RootCreateStoppedHistoricalOriginalV2, JournalError> {
        self.original.require_body_v1()?;
        self.original.native.as_ref().and_then(|native| native.historical.as_ref())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn session_v2(&self) -> Result<RootFixedNativeReadbackV1<'_>, JournalError> {
        self.original.session_v1()
    }

    pub(crate) fn controller_position_v2(&self) -> Result<(u64, u64), JournalError> {
        self.original.controller_position_v1()
    }

    pub(crate) fn compiler_input_bytes_v2(&self) -> Result<u64, JournalError> {
        self.original.compiler_input_bytes_v1()
    }

    pub(crate) fn finish_after_once_v2(&mut self) {
        self.original.finish_after_once_v1();
    }

    pub(crate) fn require_complete_v2(&self) -> Result<(), JournalError> {
        self.original.require_complete_v1()?;
        // The body-only accessor deliberately closes when its owed posts
        // enter. Completion checks their actual positive native disposition,
        // then borrows only the receipt already produced by that same reader.
        self.original.native.as_ref().and_then(|native| native.historical.as_ref())
            .map(|_| ()).ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn completed_clock_v2(&self) -> Result<RawPairedClockSample, JournalError> {
        self.original.completed_clock_v1()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

fn session_reserved_v1(state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    lane: [u8; 16]) -> Result<ControllerSessionReservedBodyDataV1, Cause>
{
    let key = KeyV1::new(lane, OwnerV1::Controller, 8)?;
    let raw = state.get(&(RecordNamespace::CreateStorageHistory, key.encode().to_vec()))
        .ok_or(JournalError::ProtectedBoundary)?;
    let record = RecordEnvelopeV1::decode(raw, key, PhaseV1::new(OwnerV1::Controller, 7)?)?;
    Ok(ControllerSessionReservedBodyDataV1::decode(record.body())?)
}

fn demand(demand: ResourceVector) -> RootContinuationDemandV1 { RootContinuationDemandV1::from_demand_v1(demand) }
fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
const CLOSED: JournalError = JournalError::ProtectedBoundary;

fn cause_box<T>(value: &Option<Result<T, Cause>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause.as_ref())
}
