//! Verifies retained policy inputs against the same genuine Initial pair.
//!
//! Raw signed packets remain untrusted DATA. The actual completed issuer owner,
//! cumulative financial Stage, live writer bookends and original Open interval
//! surround the sole canonical verifier; all failed observations remain held.

use std::error::Error;

use aos_sandbox_broker::receiving::{RootObservationErrorV1, RootSelectedStartupBorrowV1,
    RootUpperMutationGuardV1};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::readback::HistoryPairReadbackDataV1;

use crate::native::{PolicyNativeJournalErrorV1 as NativeError,
    startup::RootCurrentWritersPredecessorV1};
use crate::root_policy_inputs_data::{RootCurrentPolicyInputDataV1, RootPolicyInputErrorV1,
    RootSignedProjectSourcesDataV1, RootSignedSourcesDataErrorV1,
    verify_root_signed_project_sources_data_v1};

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_open::{RootInitialClockErrorV1, RootInitialOpenErrorV1,
    RootInitialOpenPreparedOriginalV1, ROOT_RECORD_BYTES};
use super::initial_pins::RootInitialPinsOriginalV1;
use super::initial_receiving::RootInitialStageOriginalV1;
use super::initial_writer_sample::RootInitialWriterSampleOriginalV1;
use super::owned::RootCurrentAcceptedOriginalsV1;
use super::writers::RootCurrentWritersOriginalV1;

/// Preserves actual same-original or incomplete policy-input custody refusal.
#[derive(Debug, thiserror::Error)]
pub enum RootInitialPolicyInputsErrorV1 {
    /// Retains an actual Open, receiving, writer or clock refusal.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// Actual issuer custody, signed-input verification or a post is incomplete.
    #[error("Root current signed-input verification is incomplete")]
    Incomplete,
}

type E = RootInitialPolicyInputsErrorV1;
type Readback = HistoryPairReadbackDataV1<ROOT_RECORD_BYTES>;

pub(super) struct RootInitialPolicyInputsOriginalV1 {
    stage: RootInitialStageOriginalV1,
    entry_refusal: Option<RootObservationErrorV1>,
    before_writers: RootInitialWriterSampleOriginalV1,
    before: Option<Result<Readback, RootInitialOpenErrorV1>>,
    shape: Option<Result<(), RootPolicyInputErrorV1>>,
    heads: Option<Result<(), RootPolicyInputErrorV1>>,
    clock: Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    cutoff: Option<Result<(), RootInitialOpenErrorV1>>,
    verified: Option<Result<RootSignedProjectSourcesDataV1, RootSignedSourcesDataErrorV1>>,
    production: Option<Result<(), E>>,
    after_writers: RootInitialWriterSampleOriginalV1,
    readback: Option<Result<Readback, RootInitialOpenErrorV1>>,
    peer_history: Option<RootCurrentHistoryPostOriginalV1>,
    peer_arm: Option<Result<(), RootObservationErrorV1>>,
    peer: Option<Result<(), RootObservationErrorV1>>,
    final_clock: Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    final_cutoff: Option<Result<(), RootInitialOpenErrorV1>>,
    entered: bool,
    closed: bool,
}

impl RootInitialPolicyInputsOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            stage: RootInitialStageOriginalV1::new(),
            entry_refusal: None,
            before_writers: RootInitialWriterSampleOriginalV1::new(),
            before: None,
            shape: None,
            heads: None,
            clock: None,
            cutoff: None,
            verified: None,
            production: None,
            after_writers: RootInitialWriterSampleOriginalV1::new(),
            readback: None,
            peer_history: None,
            peer_arm: None,
            peer: None,
            final_clock: None,
            final_cutoff: None,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn claim_entry_once_v1(&mut self) -> Result<(), RootObservationErrorV1> {
        if self.entered || self.closed {
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.entered = true;
        Ok(())
    }

    pub(super) fn refuse_unentered_once_v1(&mut self) {
        if self.entered {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.refuse_entry_v1(RootObservationErrorV1::Service);
    }

    pub(super) fn refuse_entry_v1(&mut self, error: RootObservationErrorV1) {
        self.entry_refusal.get_or_insert(error);
        self.closed = true;
    }

    pub(super) fn begin_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        pins: &RootInitialPinsOriginalV1,
        mut predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        let (initial, financial) = predecessor.split_initial_v1();
        if !self.entered || self.closed || self.stage.entered || initial.failure().is_some() {
            initial.latch_root_refusal_v1();
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.stage.entered = true;
        self.stage.financial = Some(financial.clone());
        self.stage.permit = Some((|| {
            pins.require_complete_v1().map_err(|_| NativeError::boundary())?;
            let body = open.body_v1().map_err(|_| NativeError::boundary())?;
            let enrollment = initial.enrollment_v1().ok_or_else(NativeError::boundary)?;
            if !matches!(initial.recipient_binding_result_v1(), Some(Ok(())))
                || (body.root_recipient, body.root_producer)
                    != (enrollment.recipient_invocation, enrollment.identity.native_fields().invocation)
                || !pins.same_financial_v1(financial)
                || !startup.same_financial_original_data_v1(financial)
            {
                return Err(NativeError::boundary());
            }
            let base = pins.completed_prefix_v1().map_err(|_| NativeError::boundary())?;
            let complete = base.checked_add(Self::dominant_demand_v1()?)
                .map_err(|_| NativeError::geometry())?;
            if financial.require_receiving_demand_under_upper_exclusion_v1(exclusion, complete).is_err() {
                return Err(NativeError::Financial(financial.clone()));
            }
            Ok(complete)
        })());
        self.stage.finish_v1(initial, startup, exclusion)
    }

    pub(super) fn verify_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), E> {
        if !self.entered || self.closed || self.production.is_some()
            || self.after_writers.entered_v1() || self.peer_arm.is_some()
        {
            self.closed = true;
            return Err(E::Incomplete);
        }
        self.production = Some(self.verify_inner_v1(writers, open, data));
        positive(&self.production).map(|_| ())
    }

    fn verify_inner_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        data: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), E> {
        self.stage.require_complete_v1()?;
        let (authority, policy) = writers.opened_pair_view_v1()
            .map_err(RootInitialOpenErrorV1::from)?;
        self.before_writers.capture_once_v1(authority, policy, open);
        self.before = Some(open.readback_current_v1(authority, policy));
        self.before_writers.require_complete_v1()?;
        positive(&self.before)?;

        self.shape = Some(data.require_shape().map(|_| ()));
        positive(&self.shape)?;
        self.heads = Some(data.require_current_heads_data_v1(policy.historical_read_view_v1()));
        positive(&self.heads)?;
        self.clock = Some(aos_sandbox_broker::kernel_clock::ordinary_kernel_pair());
        self.cutoff = Some(require_clock_v1(&self.clock, open));
        positive(&self.cutoff)?;
        let now = positive(&self.clock)?.wall_seconds();
        let project = data.project_input_data_v1().ok_or(E::Incomplete)?;
        self.verified = Some(verify_root_signed_project_sources_data_v1(
            policy.historical_read_view_v1(), project, data.deployment_inputs_data_v1(), now,
        ));
        positive(&self.verified).map(|_| ())
    }

    pub(super) fn observe_native_posts_once_v1(
        &mut self,
        writers: &RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        if !self.entered || self.after_writers.entered_v1() {
            self.closed = true;
            return;
        }
        match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => {
                self.after_writers.capture_once_v1(authority, policy, open);
                self.readback = Some(open.readback_current_v1(authority, policy));
            }
            Err(error) => {
                self.after_writers.refuse_pair_v1(error);
                self.readback = Some(Err(RootInitialOpenErrorV1::Boundary));
            }
        }
    }

    pub(super) fn arm_peer_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), ()> {
        if !self.entered || !self.after_writers.entered_v1()
            || self.peer_arm.is_some() || self.peer.is_some()
        {
            self.closed = true;
            return Err(());
        }
        self.peer_history = Some(RootCurrentHistoryPostOriginalV1::arm_once_v1(predecessor, startup, exclusion));
        self.peer_arm = Some(match &self.peer_history {
            Some(history) => history.require_armed_v1(),
            None => Err(RootObservationErrorV1::Service),
        });
        if matches!(self.peer_arm, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    pub(super) fn refuse_peer_arm_once_v1(&mut self) {
        self.closed = true;
        if self.entered && self.after_writers.entered_v1()
            && self.peer_arm.is_none() && self.peer.is_none()
        {
            self.peer_arm = Some(Err(RootObservationErrorV1::Service));
        }
    }

    pub(super) fn park_peer_refusal_v1(&mut self, error: RootObservationErrorV1) {
        if self.peer_arm.is_some() {
            self.closed = true;
        } else {
            self.peer_arm = Some(Err(error));
        }
    }

    pub(super) fn observe_peer_and_clock_once_v1(
        &mut self,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        open: &RootInitialOpenPreparedOriginalV1,
    ) {
        if !self.entered || self.peer_arm.is_none() || self.peer.is_some()
            || self.final_clock.is_some() || self.final_cutoff.is_some()
            || !self.after_writers.entered_v1()
        {
            self.closed = true;
            return;
        }
        self.peer = Some(match &mut self.peer_history {
            Some(history) => match history.borrow_accepted_v1(&originals.peer, &originals.stream) {
                Ok(mut accepted) => accepted.observe_shared_once_v1(),
                Err(error) => Err(error),
            },
            None => Err(RootObservationErrorV1::Service),
        });
        if matches!(self.peer, Some(Ok(()))) {
            drop(self.peer_history.take());
        }
        self.final_clock = Some(aos_sandbox_broker::kernel_clock::ordinary_kernel_pair());
        self.final_cutoff = Some(require_clock_v1(&self.final_clock, open));
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), E> {
        if !self.entered || self.closed || self.failure_v1().is_some() {
            return Err(E::Incomplete);
        }
        self.stage.require_complete_v1()?;
        positive(&self.production)?;
        self.after_writers.require_complete_v1()?;
        positive(&self.readback)?;
        positive(&self.peer_arm)?;
        positive(&self.peer)?;
        positive(&self.final_cutoff).map(|_| ())
    }

    pub(super) fn verified_v1(&self) -> Result<&RootSignedProjectSourcesDataV1, E> {
        self.require_complete_v1()?;
        positive(&self.verified)
    }

    pub(super) fn completed_prefix_v1(&self) -> Result<ResourceVector, E> {
        self.require_complete_v1()?;
        Ok(self.stage.require_complete_v1()?)
    }

    pub(super) fn same_financial_v1(
        &self,
        financial: &aos_sandbox_broker::receiving::RootJournalFinancialOriginalV1,
    ) -> bool {
        match &self.stage.financial {
            Some(original) => original.same_original_data_v1(financial),
            None => false,
        }
    }

    pub(super) fn entered_v1(&self) -> bool {
        self.entered
    }

    pub(super) fn dominant_demand_v1() -> Result<ResourceVector, NativeError> {
        let memory = crate::signed_inputs::fixed_root_startup_decoding_bytes_v1()
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(64 * 1024))
            .ok_or_else(NativeError::geometry)?;
        let memory = u64::try_from(memory).map_err(|_| NativeError::geometry())?;
        let returns = crate::root_policy_inputs_data::verification_return_control_bytes_v1()
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(NativeError::geometry)?;
        let before = RootInitialWriterSampleOriginalV1::additional_native_demand_v1()?;
        ResourceVector::ZERO
            .with(D::MemoryBytes, memory.checked_add(returns).ok_or_else(NativeError::geometry)?)
            .with(D::OutputBytes, memory)
            .checked_add(before).map_err(|_| NativeError::geometry())
    }

    pub(super) fn owed_names_demand_v1() -> Result<ResourceVector, NativeError> {
        RootInitialWriterSampleOriginalV1::additional_native_demand_v1()
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.stage.failure_v1()
            .or_else(|| self.entry_refusal.as_ref().map(|error| error as _))
            .or_else(|| self.before_writers.failure_v1())
            .or_else(|| cause(&self.before))
            .or_else(|| cause(&self.shape))
            .or_else(|| cause(&self.heads))
            .or_else(|| cause(&self.clock))
            .or_else(|| cause(&self.cutoff))
            .or_else(|| cause(&self.verified))
            .or_else(|| cause(&self.production))
            .or_else(|| self.after_writers.failure_v1())
            .or_else(|| cause(&self.readback))
            .or_else(|| self.peer_history.as_ref().and_then(RootCurrentHistoryPostOriginalV1::failure_v1))
            .or_else(|| cause(&self.peer_arm))
            .or_else(|| cause(&self.peer))
            .or_else(|| cause(&self.final_clock))
            .or_else(|| cause(&self.final_cutoff))
    }
}

fn require_clock_v1(
    sample: &Option<Result<RawPairedClockSample, RootInitialClockErrorV1>>,
    open: &RootInitialOpenPreparedOriginalV1,
) -> Result<(), RootInitialOpenErrorV1> {
    let current = *sample.as_ref().and_then(|result| result.as_ref().ok())
        .ok_or(RootInitialOpenErrorV1::Boundary)?;
    let body = open.body_v1()?;
    open.clock_original_v1().require_current_v1(current, body.cutoff)?;
    Ok(())
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::Incomplete)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
