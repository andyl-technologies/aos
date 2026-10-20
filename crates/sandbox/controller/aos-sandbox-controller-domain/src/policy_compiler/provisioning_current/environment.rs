//! Retains the Environment purpose's fresh Controller and Source readonly cut.
//!
//! The genuine Environment stage borrower pays each fixed, captured and audited
//! frontier before growth. Both readers run the common full cold replay and
//! their independently owed mount/name posts. Only then can existing canonical
//! selectors borrow the same readonly Journal models. This owner does not
//! select an execution, validate a template, publish a generation or issue a
//! lease; those comparisons remain with the actual Environment producer.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use super::horizon::{RootContinuationHorizonDataV1, RootContinuationClockGateV1};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{Journal, JournalError, RootReadonlyJournalModelOriginalsV1 as Model};
use crate::normal_root::{NormalRootStartupErrorV1 as FundingError, RootEnvironmentStageReceivingV1};
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1,
    create_storage_current::controller_readonly::native_read::RootFixedNativeReadOriginalsV1 as Reader};

#[derive(Debug, thiserror::Error)]
enum StopV1 {
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Funding(#[from] FundingError),
    #[error(transparent)]
    Clock(#[from] SourceGenesisErrorV1),
}

#[derive(Clone, Copy)]
enum FirstV1 {
    BeforeClock,
    Controller,
    Source,
    Funding,
    ControllerPost,
    SourcePost,
    AfterClock,
    ControllerModel,
    SourceModel,
}

struct NativeV1 {
    frontier_clock: RootContinuationClockGateV1,
    controller: Reader,
    source: Reader,
    before_clock: RetainedKernelPairedClockAttemptV1,
    before: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    final_clock: RetainedKernelPairedClockAttemptV1,
    final_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    controller_model: Option<Box<Model>>,
    source_model: Option<Box<Model>>,
    primary: Option<Result<(), StopV1>>,
    posts: Option<Result<(), StopV1>>,
    first: Option<FirstV1>,
}

impl NativeV1 {
    fn new(horizon: RootContinuationHorizonDataV1) -> Self {
        Self {
            frontier_clock: RootContinuationClockGateV1::new(horizon),
            controller: Reader::controller_current_v1(),
            source: Reader::source_release_v1(),
            before_clock: Default::default(), before: None,
            after_clock: Default::default(), after: None,
            final_clock: Default::default(), final_sample: None,
            controller_model: None, source_model: None,
            primary: None, posts: None, first: None,
        }
    }

    fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * size_of::<RootEnvironmentReadonlyContextV1>()))
            .and_then(|bytes| bytes.checked_add(
                RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?.checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Reader::controller_current_fixed_demand_v1()?.checked_add(RootContinuationClockGateV1::receiving_demand_v1()?)
            .map_err(|_| JournalError::JournalTooLarge)?.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, bytes)
            .with(D::OpenFiles, u64::try_from(
                3 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
                .map_err(|_| JournalError::JournalTooLarge)?))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    fn observe_inner(&mut self, stage: &mut RootEnvironmentStageReceivingV1<'_, '_>)
        -> Result<(), StopV1> {
        self.first = Some(FirstV1::BeforeClock);
        self.before = Some(self.before_clock.observe_once(None));
        positive(&self.before)?;
        self.frontier_clock.check_next_once_v1()?;
        let uid = stage.controller_identity_v1().0;

        self.first = Some(FirstV1::Controller);
        self.controller.capture_once(uid);
        self.controller.require_captured_v1()?;
        let native_demand = self.controller.replay_demand_v1()?;
        self.first = Some(FirstV1::Funding);
        stage.admit_controller_native_once_v1(demand(native_demand))?;
        self.first = Some(FirstV1::Controller);
        self.frontier_clock.check_next_once_v1()?;
        self.controller.audit_once();
        let semantic = self.controller.additional_semantic_demand_v1()?
            .checked_add(Model::receiving_demand_v1(&self.controller)?)
            .map_err(|_| JournalError::JournalTooLarge)?;
        self.first = Some(FirstV1::Funding);
        stage.admit_controller_semantic_once_v1(demand(semantic))?;
        self.first = Some(FirstV1::Controller);
        self.frontier_clock.check_next_once_v1()?;
        self.controller.replay_once();
        self.controller.replay_native_v1()?;

        self.first = Some(FirstV1::Source);
        let fixed = Reader::source_release_fixed_demand_v1()?;
        self.first = Some(FirstV1::Funding);
        stage.admit_source_fixed_once_v1(demand(fixed))?;
        self.first = Some(FirstV1::Source);
        self.frontier_clock.check_next_once_v1()?;
        self.source.capture_once(uid);
        self.source.require_captured_v1()?;
        let native_demand = self.source.replay_demand_v1()?;
        self.first = Some(FirstV1::Funding);
        stage.admit_source_native_once_v1(demand(native_demand))?;
        self.first = Some(FirstV1::Source);
        self.frontier_clock.check_next_once_v1()?;
        self.source.audit_once();
        let semantic = self.source.additional_semantic_demand_v1()?
            .checked_add(Model::receiving_demand_v1(&self.source)?)
            .map_err(|_| JournalError::JournalTooLarge)?;
        self.first = Some(FirstV1::Funding);
        stage.admit_source_semantic_once_v1(demand(semantic))?;
        self.first = Some(FirstV1::Source);
        self.frontier_clock.check_next_once_v1()?;
        self.source.replay_once();
        self.source.replay_native_v1()?;
        self.first = None;
        Ok(())
    }

    fn finish_posts(&mut self) {
        // Both methods are intrinsic once-only negative-capable posts; an
        // unentered second reader performs no native work.
        self.controller.finish_post_once();
        self.source.finish_post_once();
        self.after = Some(self.after_clock.observe_once(
            self.before.as_ref().and_then(|value| value.as_ref().ok()).copied()));
        self.posts = Some((|| {
            self.controller.terminal_native_v1()?;
            self.source.terminal_native_v1()?;
            self.frontier_clock.require_final_sample_v1(*positive(&self.after)?)?;
            Ok(())
        })());
        if !matches!(self.primary, Some(Ok(()))) {
            return;
        }
        self.first = if self.controller.post_failure().is_some() {
            Some(FirstV1::ControllerPost)
        } else if self.source.post_failure().is_some() {
            Some(FirstV1::SourcePost)
        } else if !matches!(self.after, Some(Ok(_))) {
            Some(FirstV1::AfterClock)
        } else {
            None
        };
    }

    fn materialize_once(&mut self) {
        if !matches!(self.primary, Some(Ok(()))) || !matches!(self.posts, Some(Ok(()))) {
            return;
        }
        self.first = Some(FirstV1::ControllerModel);
        self.controller_model = Some(Box::new(Model::new()));
        if let Some(model) = &mut self.controller_model {
            model.adopt_once(&mut self.controller);
            if model.require_complete_v1().is_err() {
                return;
            }
        }
        self.first = Some(FirstV1::SourceModel);
        self.source_model = Some(Box::new(Model::new()));
        if let Some(model) = &mut self.source_model {
            model.adopt_once(&mut self.source);
            if model.require_complete_v1().is_err() {
                return;
            }
        }
        self.first = None;
    }

    fn finish_models_after_once_v1(&mut self) -> Result<(), JournalError> {
        if let Some(model) = &mut self.controller_model { model.finish_parent_post_once_v1(); }
        if let Some(model) = &mut self.source_model { model.finish_parent_post_once_v1(); }
        self.final_sample = Some(self.final_clock.observe_once(
            self.after.as_ref().and_then(|value| value.as_ref().ok()).copied()));
        self.require_complete_v1()?;
        self.controller_model.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_parent_post_v1()?;
        self.source_model.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_parent_post_v1()?;
        self.frontier_clock.require_final_sample_v1(*positive(&self.final_sample)?)
    }

    fn final_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.controller_model.as_ref().and_then(|model| model.parent_post_failure_v1())
            .or_else(|| self.source_model.as_ref().and_then(|model| model.parent_post_failure_v1()))
            .or_else(|| self.final_clock.failure()).or_else(|| cause(&self.final_sample))
    }

    fn require_complete_v1(&self) -> Result<(), JournalError> {
        if !matches!(self.primary, Some(Ok(()))) || !matches!(self.posts, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.controller_model.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v1()?;
        self.source_model.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v1()
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first {
            Some(FirstV1::BeforeClock) => self.before_clock.failure().or_else(|| cause(&self.before)),
            Some(FirstV1::Controller) => self.controller.failure(),
            Some(FirstV1::Source) => self.source.failure(),
            Some(FirstV1::Funding) => cause(&self.primary),
            Some(FirstV1::ControllerPost) => self.controller.post_failure(),
            Some(FirstV1::SourcePost) => self.source.post_failure(),
            Some(FirstV1::AfterClock) => self.after_clock.failure().or_else(|| cause(&self.after)),
            Some(FirstV1::ControllerModel) => self.controller_model.as_ref().and_then(|model| model.failure()),
            Some(FirstV1::SourceModel) => self.source_model.as_ref().and_then(|model| model.failure()),
            None => None,
        };
        selected.or_else(|| self.frontier_clock.failure()).or_else(|| cause(&self.primary)).or_else(|| cause(&self.posts))
            .or_else(|| self.final_failure_v1())
    }
}

/// Retains only the two native readers needed by the Environment purpose.
pub(crate) struct RootEnvironmentReadonlyContextV1 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), FundingError>>,
    native: Option<Box<NativeV1>>,
    final_result: Option<Result<(), JournalError>>,
    wall_narrowing: Option<Result<(), JournalError>>,
    reentered: bool,
}

impl RootEnvironmentReadonlyContextV1 {
    pub(crate) fn new() -> Self {
        Self { geometry: None, funding: None, native: None, final_result: None,
            wall_narrowing: None, reentered: false }
    }

    pub(crate) fn observe_once(&mut self, stage: &mut RootEnvironmentStageReceivingV1<'_, '_>,
        horizon: RootContinuationHorizonDataV1) {
        if self.geometry.is_some() {
            self.reentered = true;
            return;
        }
        self.geometry = Some(NativeV1::fixed_demand_v1());
        let Some(Ok(fixed)) = self.geometry else { return; };
        self.funding = Some(stage.admit_controller_fixed_once_v1(demand(fixed)));
        if !matches!(self.funding, Some(Ok(()))) {
            return;
        }
        self.native = Some(Box::new(NativeV1::new(horizon)));
        if let Some(native) = &mut self.native {
            native.primary = Some(native.observe_inner(stage));
            native.finish_posts();
            native.materialize_once();
        }
    }

    /// Narrows this same completed reader with genuine later policy expiry DATA.
    ///
    /// The issuer supplies its actual verified policy/lease minimum. The same
    /// saved gate checks the actual retained after sample and all later posts;
    /// an expired bound stays selected ahead of a later independently owed post.
    pub(crate) fn narrow_wall_expiry_data_v1(&mut self, expires: i64)
        -> Result<(), JournalError> {
        self.require_complete_v1()?;
        self.wall_narrowing = Some((|| {
            let native = self.native.as_mut().ok_or(JournalError::ProtectedBoundary)?;
            native.frontier_clock.narrow_wall_expiry_data_v1(expires);
            let sample = native.after.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(JournalError::ProtectedBoundary)?;
            native.frontier_clock.require_final_sample_v1(sample)
        })());
        if matches!(self.wall_narrowing, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    // Canonical selectors receive the same two readonly Journals. No raw map,
    // accepted execution, spec descriptor or policy result can be supplied here.
    pub(crate) fn models_mut_v1(&mut self) -> Result<(&mut Journal, &mut Journal), JournalError> {
        self.require_complete_v1()?;
        let native = self.native.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        let controller = native.controller_model.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        let source = native.source_model.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        Ok((controller.journal_mut_v1()?, source.journal_mut_v1()?))
    }

    // Only the same completed readonly model supplies the Source rows to the
    // shared fresh Cache/compiler precursor. The issuer must retain this
    // context through finish_models_after_once_v1 and its final complete gate.
    pub(crate) fn compiler_controller_state_v1(&self) -> Result<&std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>, JournalError> {
        self.require_complete_v1()?;
        self.native.as_ref().and_then(|native| native.controller_model.as_ref())
            .ok_or(JournalError::ProtectedBoundary)?.raw_state_v1()
    }

    pub(crate) fn compiler_input_bytes_v1(&self) -> Result<u64, JournalError> {
        self.require_complete_v1()?;
        let native = self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let mut bytes = 0_u64;
        for model in [&native.controller_model, &native.source_model] {
            for ((_, key), value) in model.as_ref().ok_or(JournalError::ProtectedBoundary)?.raw_state_v1()? {
                let one = key.len().checked_add(value.len()).and_then(|value| u64::try_from(value).ok())
                    .ok_or(JournalError::JournalTooLarge)?;
                bytes = bytes.checked_add(one).ok_or(JournalError::JournalTooLarge)?;
            }
        }
        Ok(bytes)
    }

    pub(super) fn source_state_v1(&self)
        -> Result<&aos_sandbox_ledger_replay::cache_current::State, JournalError>
    {
        self.require_complete_v1()?;
        self.native.as_ref().and_then(|native| native.source_model.as_ref())
            .ok_or(JournalError::ProtectedBoundary)?.raw_state_v1()
    }

    pub(crate) fn clock_v1(&self) -> Result<RawPairedClockSample, JournalError> {
        self.require_complete_v1()?;
        let native = self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        native.after.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Finishes the separately prepaid native/model and clock posts.
    /// The actual Environment body calls this after either selector/artifact
    /// outcome; an earlier body error must keep chronological priority.
    pub(crate) fn finish_models_after_once_v1(&mut self) {
        if self.final_result.is_some() {
            self.reentered = true;
            return;
        }
        self.final_result = Some(match self.native.as_mut() {
            Some(native) => native.finish_models_after_once_v1(),
            None => Err(JournalError::ProtectedBoundary),
        });
    }

    pub(crate) fn final_require_complete_v1(&self) -> Result<(), JournalError> {
        self.require_complete_v1()?;
        if matches!(self.final_result, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn completed_clock_v1(&self) -> Result<RawPairedClockSample, JournalError> {
        self.final_require_complete_v1()?;
        let native = self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        native.final_sample.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn funding_failure_is_selected_v1(&self) -> bool {
        matches!(self.funding, Some(Err(_))) || self.native.as_ref()
            .is_some_and(|native| matches!(native.first, Some(FirstV1::Funding)))
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), JournalError> {
        if self.reentered || !matches!(self.funding, Some(Ok(())))
            || matches!(self.wall_narrowing, Some(Err(_))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?.require_complete_v1()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.geometry).or_else(|| cause(&self.funding))
            .or_else(|| cause(&self.wall_narrowing))
            .or_else(|| self.native.as_ref().and_then(|native| native.failure()))
            .or_else(|| cause(&self.final_result))
            .or_else(|| self.reentered.then_some(&CONTEXT_CLOSED as &(dyn Error + 'static)))
    }
}

fn demand(value: ResourceVector) -> RootContinuationDemandV1 {
    RootContinuationDemandV1::from_demand_v1(value)
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|error| error as _)
}

const CONTEXT_CLOSED: JournalError = JournalError::ProtectedBoundary;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dormant_native_and_unfunded_headers_expose_no_readonly_model() {
        let mut context = RootEnvironmentReadonlyContextV1::new();
        assert!(context.models_mut_v1().is_err());
        assert!(context.clock_v1().is_err());
        assert!(context.native.is_none());
        context.finish_models_after_once_v1();
        assert!(context.final_require_complete_v1().is_err());
        assert!(context.completed_clock_v1().is_err());
        assert!(context.native.is_none());
    }
}
