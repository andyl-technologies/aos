//! Admits the next genuine method58 before releasing a terminal Stage.
//!
//! The existing consumed control original pays this finite transition. The
//! same held journals, canonical signed-admission engine and State reservation
//! remain continuously owned through independent posts. Only the actual owned
//! reservation crosses the old Stage's physical drop; it contains no old OFD or
//! Stage Arc. A failed or ambiguous attempt cannot be verified or issued again.

use std::sync::{Arc, Mutex};
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_controller_domain::journal::JournalAppendReceivingDemandErrorV1;
use aos_sandbox_broker::{BrokerEffectClockComparisonV3, BrokerSignedAdmissionOriginalV4};
use aos_sandbox_model::{RawPairedClockSample, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};
use crate::plan::{HostCatalog, HostComponentControlStartupV2, HostExecutionRequestBindingV2};
use crate::state::HostStateStore;
use crate::worker::HostWorker;
use crate::{HostError, Result};
use super::super::{HostBroker, HostExecutionGrantReservationV1};
use super::HostLaunchOriginalV2;
use super::super::argument_handoff::{ArgumentClockV2, ArgumentStageOriginalV2, ArgumentStateWritesV2};
use super::execution_monitor::{MonitorBookendsV5, MonitorFailureGuardV5};

// Entry and post-await plus the two existing reserve/check-before-effect
// callbacks. The final independently owed pair has its own native destination.
type TransitionBookendsV5 = MonitorBookendsV5<4>;

/// Carries only actual fixed and captured claim representation requirements.
pub(crate) struct HostExecutionTransitionShapeV5 {
    fixed: ResourceVector,
    claim: Option<std::result::Result<ResourceVector, JournalAppendReceivingDemandErrorV1>>,
}

impl HostExecutionTransitionShapeV5 {
    pub(crate) fn receiving_demand_v5(&self) -> Result<ResourceVector> { Ok(self.fixed) }

    pub(crate) fn claim_demand_v5(&self) -> Result<ResourceVector> {
        self.claim.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or_else(refused)
    }
}

/// Continuously borrows the genuine old Stage while its control pair is admitted.
pub(crate) struct HostExecutionTransitionParentV5<'original> {
    _stage: &'original ArgumentStageOriginalV2,
    launch: HostExecutionRequestBindingV2,
    accept: HostExecutionRequestBindingV2,
    observe: HostExecutionRequestBindingV2,
}

impl HostExecutionTransitionParentV5<'_> {
    pub(crate) fn original_bindings_v5(&self) -> (HostExecutionRequestBindingV2,
        HostExecutionRequestBindingV2, HostExecutionRequestBindingV2) {
        (self.launch, self.accept, self.observe)
    }
}

#[derive(Clone, Copy)]
enum TransitionFailureV5 {
    Forecast, Extension, Clock, SourceCutoff, Before, NamesBefore, ArgumentBefore,
    Admission, NamesAfter, ArgumentAfter, After, StateDisposal, Disposal,
}

/// Retains the actual once-verified reservation across the old physical drop.
pub(super) struct HostExecutionTransitionOriginalV5 {
    request: HostExecutionRequestBindingV2,
    cutoff: u64,
    shape: HostExecutionTransitionShapeV5,

    extension: Option<Result<()>>,
    signed: BrokerSignedAdmissionOriginalV4,
    reservation: Option<Result<HostExecutionGrantReservationV1>>,
    claim_failure: Option<aos_sandbox_controller_domain::runtime_execution::DormantRuntimeExecutionOwnerErrorV1>,
    source_cutoff: Option<std::result::Result<u64, super::super::argument_handoff::ArgumentStageErrorV2>>,

    writes: Arc<Mutex<ArgumentStateWritesV2>>,
    bookends: TransitionBookendsV5,

    first: Option<TransitionFailureV5>,
    financial_selected: bool,
    write_selected: bool,
    state_disposal: Option<Result<()>>,
    positive: bool,
    transferred: bool,
}

impl HostExecutionTransitionOriginalV5 {
    fn new(request: &AuthenticatedBrokerMethodRequestV1, cutoff: u64,
        shape: HostExecutionTransitionShapeV5) -> Self {
        Self { request: binding(request), cutoff, shape, extension: None,
            signed: BrokerSignedAdmissionOriginalV4::new(), reservation: None, claim_failure: None, source_cutoff: None,
            writes: Arc::new(Mutex::new(ArgumentStateWritesV2::new())),
            bookends: TransitionBookendsV5::new(), first: None, financial_selected: false,
            write_selected: false, state_disposal: None, positive: false, transferred: false }
    }

    fn sample(&mut self, clock: &mut ArgumentClockV2) -> Result<RawPairedClockSample> {
        let cutoff = self.cutoff;
        let comparison = self.reservation.as_ref().and_then(|result| result.as_ref().ok())
            .map(|scope| BrokerEffectClockComparisonV3::from_effect(&scope.effect));
        let result = self.bookends.sample_clock_contract_v3(clock, |sample| {
            if sample.boottime_nanoseconds() >= cutoff { return Err(refused()); }
            if let Some(comparison) = &comparison { comparison.require_fresh(sample)?; }
            Ok(())
        });
        if result.is_err() { self.first.get_or_insert(TransitionFailureV5::Clock); }
        result
    }

    pub(super) fn failed_v5(&self) -> bool { self.first.is_some() }

    pub(super) fn require_request_v5(&self, request: &AuthenticatedBrokerMethodRequestV1) -> Result<()> {
        if !self.positive || self.first.is_some() || self.request != binding(request)
            || request.method() != BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2
        { return Err(refused()); }
        Ok(())
    }

    pub(super) fn reservation_v5(&self) -> Result<&HostExecutionGrantReservationV1> {
        if !self.positive || self.first.is_some() || self.transferred { return Err(refused()); }
        self.reservation.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(refused)
    }

    pub(super) fn require_transferred_v5(&self, request: &AuthenticatedBrokerMethodRequestV1) -> Result<()> {
        self.require_request_v5(request)?;
        if !self.transferred || self.reservation.is_some() { return Err(refused()); }
        self.bookends.require_native_positive_v3()?;
        let writes = self.writes.lock().map_err(|_| refused())?;
        writes.require_positive_disposal_v2()?;
        if Arc::strong_count(&self.writes) != 1 { return Err(refused()); }
        Ok(())
    }

    // This is ownership transfer of the existing verified reservation. No
    // signature is verified again and no State CAS is reissued at the opener.
    pub(super) fn take_reservation_v5(&mut self, request: &AuthenticatedBrokerMethodRequestV1)
        -> Result<HostExecutionGrantReservationV1> {
        self.require_request_v5(request)?;
        if self.transferred { return Err(refused()); }
        match self.reservation.take() {
            Some(Ok(reservation)) => { self.transferred = true; Ok(reservation) }
            retained => { self.reservation = retained; Err(refused()) }
        }
    }

    pub(super) fn format_failure_v5(&self, component: &HostComponentControlStartupV2,
        formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.write_selected && matches!(self.first, Some(TransitionFailureV5::Admission | TransitionFailureV5::StateDisposal)) {
            let writes = self.writes.lock().map_err(|_| std::fmt::Error)?;
            if let Some(cause) = writes.failure() { return std::fmt::Display::fmt(cause, formatter); }
        }
        let cause: Option<&dyn std::error::Error> = match self.first {
            Some(TransitionFailureV5::Forecast) => self.shape.claim.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(TransitionFailureV5::Extension) if self.financial_selected => Some(component.failure()),
            Some(TransitionFailureV5::Extension) => self.extension.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(TransitionFailureV5::Clock) => self.bookends.clock_failure_v3().map(|cause| cause as _),
            Some(TransitionFailureV5::SourceCutoff) => self.source_cutoff.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(TransitionFailureV5::Admission) => self.claim_failure.as_ref().map(|cause| cause as _)
                .or_else(|| self.signed.failure().map(|cause| cause as _))
                .or_else(|| self.reservation.as_ref()?.as_ref().err().map(|cause| cause as _)),
            Some(TransitionFailureV5::Before | TransitionFailureV5::After | TransitionFailureV5::Disposal) => Some(component.failure()),
            Some(TransitionFailureV5::StateDisposal) => self.state_disposal.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(TransitionFailureV5::NamesBefore | TransitionFailureV5::NamesAfter) => {
                let index = usize::from(matches!(self.first, Some(TransitionFailureV5::NamesAfter)));
                self.bookends.names[index].iter().find_map(|names| names.failure().map(|cause| cause as _))
                    .or_else(|| self.bookends.name_results[index].iter().find_map(|result|
                        result.as_ref()?.as_ref().err().map(|cause| cause as _)))
            }
            Some(TransitionFailureV5::ArgumentBefore | TransitionFailureV5::ArgumentAfter) => {
                let index = usize::from(matches!(self.first, Some(TransitionFailureV5::ArgumentAfter)));
                self.bookends.argument_names[index].failure().map(|cause| cause as _)
                    .or_else(|| self.bookends.argument_results[index].as_ref()?.as_ref().err().map(|cause| cause as _))
            }
            None => None,
        };
        match cause { Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("next execution retains its original admission custody") }
    }
}

impl HostLaunchOriginalV2 {
    // Only the actual new paid argument Stage may take the continuously owned
    // verified reservation; the private fields remain inaccessible to callers.
    pub(in crate::broker) fn take_next_execution_reservation_v5(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<Option<HostExecutionGrantReservationV1>> {
        self.next_execution.as_mut().map(|transition| transition.take_reservation_v5(request)).transpose()
    }

    pub(in crate::broker) fn retire_next_execution_preparation_v5(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        if let Some(transition) = self.next_execution.as_ref() {
            transition.require_transferred_v5(request)?;
            // The real58 response CAS/readback/Sent and native Stage drop all
            // passed. Only completed storage drops; the control debt remains.
            drop(self.next_execution.take());
            self.next_execution_funding = None;
            self.next_execution_funding_selected = false;
        }
        Ok(())
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(in crate::broker) async fn prepare_next_execution_transition_v5(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1, protected_boot: [u8; 16], deadline: u64,
    ) -> Result<()> {
        if request.method() != BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 {
            return Ok(());
        }
        let Some(launch) = self.launch_original.as_ref().cloned() else { return Ok(()); };
        let mut held = launch.lock().map_err(|_| refused())?;
        if let Some(prior) = held.next_execution.as_ref() {
            // A negative/ambiguous original cannot be replayed. A completed
            // preparation may survive a later funding refusal at the opener.
            prior.require_request_v5(request)?;
            if held.capture.is_some() { return Err(refused()); }
            return Ok(());
        }
        if matches!(held.next_execution_funding, Some(Err(_))) { return Err(refused()); }
        let Some(resident) = held.capture.as_ref() else { return Ok(()); };
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.authorization().is_none() || !self.state_healthy
            || !held.authenticated_sent || held.first.is_some()
            || resident.monitor_failed_data_v5()
            || self.argument_stages.iter().any(Option::is_some)
            || self.active_argument_writes.is_some() || self.active_launch_writes.is_some()
        { return Err(refused()); }
        let stage = Arc::clone(resident.stage_for_terminal_disposal_v3());
        let mut original_stage = stage.lock().map_err(|_| refused())?;
        original_stage.require_terminal_storage_disposal_v3()?;
        let mut failure_guard = MonitorFailureGuardV5 {
            unknown: resident.query_association_v3()?.4, positive: false,
        };
        let (accept, observe) = resident.terminal_bindings_v3()?;
        let parent = HostExecutionTransitionParentV5 { _stage: &original_stage,
            launch: HostExecutionRequestBindingV2 { id: held.request.0,
                session: held.request.1, signed: held.request.2 }, accept, observe };
        let verification = self.authority.execution_signed_admission_receiving_bytes_v5(
            request.authorization().ok_or_else(refused)?).ok_or(HostError::ResourceExhausted)?;
        let carriers = std::mem::size_of::<HostExecutionTransitionOriginalV5>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<HostExecutionTransitionParentV5<'_>>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<HostExecutionTransitionShapeV5>()))
            .ok_or(HostError::ResourceExhausted)?;
        let fixed = super::execution_query::execution_preparation_fixed_demand_v5(
            carriers, request.exact_body().len(), verification)?
            .checked_add(self.state.execution_prepare_receiving_demand_v5()
                .ok_or(HostError::ResourceExhausted)?)
            .map_err(|_| HostError::ResourceExhausted)?;
        let shape = HostExecutionTransitionShapeV5 { fixed, claim: None };
        let control = self.component_control.as_ref().cloned().ok_or_else(refused)?;
        let mut component = control.lock().map_err(|_| refused())?;
        let mut receiving = match component.begin_execution_transition_preparation_v5(request, &shape, &parent,
            &mut held.next_execution_funding_selected) {
            Ok(receiving) => { held.next_execution_funding = Some(Ok(())); receiving }
            Err(cause) => {
                held.next_execution_funding = Some(Err(cause));
                return Err(refused());
            }
        };
        held.next_execution = Some(Box::new(HostExecutionTransitionOriginalV5::new(request, deadline, shape)));
        let original = held.next_execution.as_mut().ok_or_else(refused)?;
        let ArgumentStageOriginalV2 { owner, argument, accepted, .. } = &mut *original_stage;
        let owner = owner.as_mut().ok_or_else(refused)?;
        let argument = argument.as_mut().ok_or_else(refused)?;
        let clock = accepted.as_mut().ok_or_else(refused)?.transition_clock_v5(&stage, accept, request)?;
        original.shape.claim = Some(owner.initial_claim_receiving_demand_v2());
        if original.shape.claim.as_ref().is_some_and(std::result::Result::is_err) {
            original.first.get_or_insert(TransitionFailureV5::Forecast);
        }
        original.extension = Some(receiving.extend_execution_transition_v5(&original.shape));
        if !matches!(original.extension, Some(Ok(()))) {
            // Snapshot only the source selected at this returned frontier.
            original.financial_selected = matches!(original.shape.claim, Some(Ok(_)));
            original.first.get_or_insert(TransitionFailureV5::Extension);
            return Err(refused());
        }
        let preparation = (|| -> Result<()> {
            let entry = original.sample(clock)?;
            original.source_cutoff = Some((|| {
                let source = super::super::argument_handoff::original_argument_source_v2(
                    request, entry.boottime_nanoseconds())?;
                let cutoff = source.deadline_boottime_nanoseconds().min(deadline);
                if cutoff <= entry.boottime_nanoseconds() { return Err(refused().into()); }
                Ok(cutoff)
            })());
            match original.source_cutoff.as_ref() {
                Some(Ok(cutoff)) => original.cutoff = *cutoff,
                _ => { original.first.get_or_insert(TransitionFailureV5::SourceCutoff); return Err(refused()); }
            }
            Ok(())
        })();
        if preparation.is_err() {
            let cutoff = original.cutoff;
            let _ = original.bookends.finish_entered_clock_post_v3(clock, |sample| {
                if sample.boottime_nanoseconds() >= cutoff { return Err(refused()); }
                Ok(())
            });
            return Err(refused());
        }
        original.bookends.before = Some(receiving.observe_before_once_v5().await);
        if !matches!(original.bookends.before, Some(Ok(()))) { original.first.get_or_insert(TransitionFailureV5::Before); }
        if original.first.is_none() && original.sample(clock).is_ok() {
            let _ = owner.observe_execution_names_v2(&mut original.bookends.names[0], &mut original.bookends.name_results[0]);
            original.bookends.argument_results[0] = Some(argument.observe_names_before_v2(&mut original.bookends.argument_names[0]));
            if !original.bookends.name_results[0].iter().all(|result| matches!(result, Some(Ok(())))) {
                original.first.get_or_insert(TransitionFailureV5::NamesBefore);
            } else if !matches!(original.bookends.argument_results[0], Some(Ok(()))) {
                original.first.get_or_insert(TransitionFailureV5::ArgumentBefore);
            }
            if original.first.is_none() {
                self.active_argument_writes = Some(Arc::clone(&original.writes));
                original.reservation = Some((|| {
                    let claim = match owner.claim() {
                        Ok(claim) => claim,
                        Err(cause) => { original.claim_failure = Some(cause); return Err(refused()); }
                    };
                    if claim.host_verifier().boot_id() != protected_boot { return Err(refused()); }
                    let cutoff = original.cutoff;
                    let bookends = &mut original.bookends;
                    self.reserve_host_prepare_transition_retaining_v5(&claim, request, protected_boot,
                        || bookends.sample_clock_contract_v3(clock, |sample| {
                            if sample.boottime_nanoseconds() >= cutoff { return Err(refused()); }
                            Ok(())
                        }), &mut original.signed)
                })());
                self.active_argument_writes = None;
                if original.bookends.clock_first.is_some() { original.first.get_or_insert(TransitionFailureV5::Clock); }
                if original.reservation.as_ref().is_some_and(std::result::Result::is_err) {
                    original.write_selected = original.writes.lock().map_err(|_| refused())?.failure().is_some();
                    original.first.get_or_insert(TransitionFailureV5::Admission);
                }
            }
        }
        // All of these are independently owed after native before entry, even
        // when signature verification or the actual reservation CAS refused.
        let _ = owner.observe_execution_names_post_v2(&mut original.bookends.names[1], &mut original.bookends.name_results[1]);
        original.bookends.argument_results[1] = Some(argument.observe_names_post_v2(&mut original.bookends.argument_names[1]));
        if !original.bookends.name_results[1].iter().all(|result| matches!(result, Some(Ok(())))) {
            original.first.get_or_insert(TransitionFailureV5::NamesAfter);
        } else if !matches!(original.bookends.argument_results[1], Some(Ok(()))) {
            original.first.get_or_insert(TransitionFailureV5::ArgumentAfter);
        }
        original.bookends.after = Some(receiving.observe_after_once_v5().await);
        if !matches!(original.bookends.after, Some(Ok(()))) { original.first.get_or_insert(TransitionFailureV5::After); }
        let cutoff = original.cutoff;
        let comparison = original.reservation.as_ref().and_then(|result| result.as_ref().ok())
            .map(|scope| BrokerEffectClockComparisonV3::from_effect(&scope.effect));
        original.bookends.final_sample = original.bookends.sample_post_clock_contract_v3(clock, |sample| {
            if sample.boottime_nanoseconds() >= cutoff { return Err(refused()); }
            if let Some(comparison) = &comparison { comparison.require_fresh(sample)?; }
            Ok(())
        }).ok();
        if original.bookends.final_sample.is_none() { original.first.get_or_insert(TransitionFailureV5::Clock); }
        if original.first.is_some() { return Err(refused()); }
        original.state_disposal = Some((|| {
            original.writes.lock().map_err(|_| refused())?.require_positive_disposal_v2()?;
            if Arc::strong_count(&original.writes) != 1 { return Err(refused()); }
            Ok(())
        })());
        if !matches!(original.state_disposal, Some(Ok(()))) {
            original.first.get_or_insert(TransitionFailureV5::StateDisposal);
            original.write_selected = original.writes.lock().is_ok_and(|writes| writes.failure().is_some());
            return Err(refused());
        }
        original.bookends.native = Some(receiving.dispose_positive_once_v5());
        if !matches!(original.bookends.native, Some(Ok(()))) {
            original.first.get_or_insert(TransitionFailureV5::Disposal); return Err(refused());
        }
        original.bookends.require_native_positive_v3()?;
        if !matches!(original.reservation, Some(Ok(_))) { return Err(refused()); }
        for names in original.bookends.names.iter_mut().flatten() { names.settle_positive_once_v1(); }
        for names in &mut original.bookends.argument_names { names.settle_positive_once_v1(); }
        original.positive = true;
        // Drop the temporary Stage alias before the shared actual try_unwrap.
        drop(receiving);
        drop(original_stage);
        drop(stage);
        drop(component);
        drop(held);
        let disposed = self.dispose_terminal_stage_before_next_execution_v5(&launch, request);
        failure_guard.positive = disposed.is_ok();
        disposed
    }
}

fn binding(request: &AuthenticatedBrokerMethodRequestV1) -> HostExecutionRequestBindingV2 {
    HostExecutionRequestBindingV2 { id: request.request_id(), session: request.session_binding(),
        signed: request.signed_request_digest() }
}

fn refused() -> HostError {
    HostError::Fence("next execution retains its original transition custody")
}
