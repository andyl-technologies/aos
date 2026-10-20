//! Verifies one fresh Capture Stop before entering the existing Stop reducer.
//!
//! The consumed control original pays the same native observation pair, held
//! journal bookends, canonical Stop decoder and signed admission engine before
//! entry. No State reservation or effect is made here. The actual admission and
//! its original clock move once into the existing Stop; uncertainty stays held.

use std::sync::{Arc, Mutex};
use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_controller_domain::journal::JournalAppendReceivingDemandErrorV1;
use aos_sandbox_broker::{BrokerEffectClockComparisonV3, BrokerSignedAdmissionOriginalV4, VerifiedBrokerAdmission};
use aos_sandbox_model::{ProtocolVersion, RawPairedClockSample, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::ValidatedRuntimeRequest;
use crate::plan::{HostCatalog, HostComponentControlStartupV2, HostExecutionRequestBindingV2};
use crate::state::HostStateStore;
use crate::worker::HostWorker;
use crate::{HostError, Result};
use super::super::argument_handoff::{ArgumentClockV2, ArgumentStageOriginalV2};
use super::super::HostBroker;
use super::capture_stop::HostCaptureFailedStageV4;
use super::execution_monitor::MonitorBookendsV5;

// Entry and post-native-before; the final native clock has its own destination.
type StopAdmissionBookendsV4 = MonitorBookendsV5<2>;

pub(crate) struct HostCaptureStopAdmissionShapeV4 {
    fixed: ResourceVector,
    claim: Option<std::result::Result<ResourceVector, JournalAppendReceivingDemandErrorV1>>,
}

impl HostCaptureStopAdmissionShapeV4 {
    pub(crate) fn receiving_demand_v4(&self) -> ResourceVector { self.fixed }

    pub(crate) fn claim_demand_v4(&self) -> Result<ResourceVector> {
        self.claim.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or_else(refused)
    }
}

/// Borrows the real failed Stage while its finite verification interval is paid.
pub(crate) struct HostCaptureStopAdmissionParentV4<'held> {
    _stage: &'held ArgumentStageOriginalV2,
    failed: &'held HostCaptureFailedStageV4,
    launch: HostExecutionRequestBindingV2,
}

impl HostCaptureStopAdmissionParentV4<'_> {
    pub(crate) fn require_failed_v4(&self) -> Result<()> {
        self.failed.require_failed_resident_v4()
    }

    pub(crate) fn bindings_v4(&self)
        -> (HostExecutionRequestBindingV2, HostExecutionRequestBindingV2)
    {
        (self.launch, self.failed.accept_v4())
    }
}

#[derive(Clone, Copy)]
enum FirstV4 {
    Forecast, Extension, Clock, Decode, Before, NamesBefore, ArgumentBefore,
    Claim, Admission, NamesAfter, ArgumentAfter, After, Disposal,
}

pub(super) struct HostCaptureStopAdmissionOriginalV4 {
    request: HostExecutionRequestBindingV2,
    cutoff: u64,
    shape: HostCaptureStopAdmissionShapeV4,
    extension: Option<Result<()>>,
    clock: Option<ArgumentClockV2>,
    bookends: StopAdmissionBookendsV4,
    decoded: Option<std::result::Result<ValidatedRuntimeRequest, aos_sandbox_protocol::ProtocolValidationError>>,
    signed: BrokerSignedAdmissionOriginalV4,
    admission: Option<Result<VerifiedBrokerAdmission>>,
    claim_failure: Option<aos_sandbox_controller_domain::runtime_execution::DormantRuntimeExecutionOwnerErrorV1>,
    admission_clock: Option<RawPairedClockSample>,
    first: Option<FirstV4>,
    positive: bool,
    transferred: bool,
}

impl HostCaptureStopAdmissionOriginalV4 {
    fn new(request: &AuthenticatedBrokerMethodRequestV1,
        shape: HostCaptureStopAdmissionShapeV4) -> Self
    {
        Self { request: binding(request), cutoff: request.deadline_boottime_nanoseconds(),
            shape, extension: None, clock: None,
            bookends: StopAdmissionBookendsV4::new(), decoded: None,
            signed: BrokerSignedAdmissionOriginalV4::new(), admission: None,
            claim_failure: None, admission_clock: None, first: None, positive: false,
            transferred: false }
    }

    fn sample(&mut self) -> Result<RawPairedClockSample> {
        let cutoff = self.cutoff;
        let comparison = self.admission.as_ref().and_then(|result| result.as_ref().ok())
            .map(|admitted| BrokerEffectClockComparisonV3::from_effect(&admitted.effect));
        let outcome = self.bookends.sample_clock_contract_v3(self.clock.as_mut().ok_or_else(refused)?, |sample| {
            if sample.boottime_nanoseconds() >= cutoff { return Err(refused()); }
            if let Some(comparison) = &comparison { comparison.require_fresh(sample)?; }
            Ok(())
        });
        if outcome.is_err() { self.first.get_or_insert(FirstV4::Clock); }
        outcome
    }

    fn finish_clock_post(&mut self) {
        let cutoff = self.cutoff;
        let comparison = self.admission.as_ref().and_then(|result| result.as_ref().ok())
            .map(|admitted| BrokerEffectClockComparisonV3::from_effect(&admitted.effect));
        let Some(clock) = self.clock.as_mut() else { return; };
        let outcome = self.bookends.finish_entered_clock_post_v3(clock, |sample| {
            if sample.boottime_nanoseconds() >= cutoff { return Err(refused()); }
            if let Some(comparison) = &comparison { comparison.require_fresh(sample)?; }
            Ok(())
        });
        if outcome.is_err() { self.first.get_or_insert(FirstV4::Clock); }
    }

    pub(super) fn format_failure_v4(&self, component: &HostComponentControlStartupV2,
        formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        let cause: Option<&dyn std::error::Error> = match self.first {
            Some(FirstV4::Forecast) => self.shape.claim.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(FirstV4::Extension) => component.capture_stop_admission_failure_v4(self.request, false)
                .or_else(|| self.extension.as_ref()?.as_ref().err().map(|cause| cause as _)),
            Some(FirstV4::Clock) => self.bookends.clock_failure_v3(),
            Some(FirstV4::Decode) => self.decoded.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(FirstV4::Claim) => self.claim_failure.as_ref().map(|cause| cause as _),
            Some(FirstV4::Admission) => self.signed.failure()
                .or_else(|| self.admission.as_ref()?.as_ref().err().map(|cause| cause as _)),
            Some(FirstV4::Disposal) => self.bookends.native.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Some(FirstV4::Before | FirstV4::After) => {
                let after = !matches!(self.first, Some(FirstV4::Before));
                component.capture_stop_admission_failure_v4(self.request, after)
                    .or_else(|| {
                        let result = if after { self.bookends.after.as_ref() } else { self.bookends.before.as_ref() };
                        result.and_then(|result| result.as_ref().err()).map(|cause| cause as _)
                    })
            }
            Some(FirstV4::NamesBefore | FirstV4::NamesAfter) => {
                let index = usize::from(matches!(self.first, Some(FirstV4::NamesAfter)));
                self.bookends.names[index].iter().find_map(|names| names.failure().map(|cause| cause as _))
                    .or_else(|| self.bookends.name_results[index].iter().find_map(|result|
                        result.as_ref()?.as_ref().err().map(|cause| cause as _)))
            }
            Some(FirstV4::ArgumentBefore | FirstV4::ArgumentAfter) => {
                let index = usize::from(matches!(self.first, Some(FirstV4::ArgumentAfter)));
                self.bookends.argument_names[index].failure().map(|cause| cause as _)
                    .or_else(|| self.bookends.argument_results[index].as_ref()?.as_ref().err().map(|cause| cause as _))
            }
            None => None,
        };
        match cause { Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("fresh Stop retains its original verification custody") }
    }
}

impl super::HostLaunchOriginalV2 {
    pub(in crate::broker) fn take_capture_stop_admission_clock_v4(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<ArgumentClockV2> {
        let original = self.stop_admission.as_mut().ok_or_else(refused)?;
        if !original.positive || !original.transferred || original.first.is_some()
            || original.request != binding(request)
        { return Err(refused()); }
        original.clock.take().ok_or_else(refused)
    }

    pub(in crate::broker) fn format_stop_admission_failure_v4(
        &self, component: &HostComponentControlStartupV2,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> Option<std::fmt::Result> {
        if let Some(original) = self.stop_admission.as_ref().filter(|original| original.first.is_some()) {
            return Some(original.format_failure_v4(component, formatter));
        }
        if let Some(Err(cause)) = self.stop_admission_funding.as_ref() {
            if let Some(request) = self.stop_admission_request {
                if let Some(actual) = component.capture_stop_admission_failure_v4(request, false) {
                    return Some(std::fmt::Display::fmt(actual, formatter));
                }
            }
            return Some(std::fmt::Display::fmt(cause, formatter));
        }
        None
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(in crate::broker) fn has_failed_capture_stop_parent_v4(&self) -> Result<bool> {
        let Some(launch) = self.launch_original.as_ref() else { return Ok(false); };
        Ok(launch.lock().map_err(|_| refused())?.failed_capture_stop_stage_v4()?.is_some())
    }

    pub(in crate::broker) async fn admit_failed_capture_stop_once_v4(
        &mut self, request: &AuthenticatedBrokerMethodRequestV1, protocol: ProtocolVersion,
    ) -> Result<(ValidatedRuntimeRequest, VerifiedBrokerAdmission, RawPairedClockSample)>
    where W: Sync,
    {
        use aos_sandbox_protocol::storage_capture_session::stop_cleanup::MAXIMUM_CANONICAL_CAPTURE_STOP_BODY_BYTES_V4;
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.method() != BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME
            || request.authorization().is_none() || !super::super::is_exact_host_protocol(protocol)
            || request.exact_body().len() > MAXIMUM_CANONICAL_CAPTURE_STOP_BODY_BYTES_V4
            || !self.state_healthy
        { return Err(refused()); }
        let launch = self.launch_original.as_ref().cloned().ok_or_else(refused)?;
        let mut held = launch.lock().map_err(|_| refused())?;
        held.require_failed_capture_stop_parent_v4()?;
        if held.stop_admission.is_some() || held.stop_admission_funding.is_some() { return Err(refused()); }
        let (stage, failed) = held.failed_capture_stop_stage_v4()?.ok_or_else(refused)?;
        let control = self.component_control.as_ref().cloned().ok_or_else(refused)?;
        let mut component = control.lock().map_err(|_| refused())?;
        let mut old = stage.lock().map_err(|_| refused())?;
        let parent = HostCaptureStopAdmissionParentV4 { _stage: &old, failed: &failed,
            launch: HostExecutionRequestBindingV2 { id: held.request.0, session: held.request.1, signed: held.request.2 } };
        let boot = old.protected_boot_data_v4().ok_or_else(refused)?;
        let verification = self.authority.execution_signed_admission_receiving_bytes_v5(
            request.authorization().ok_or_else(refused)?).ok_or(HostError::ResourceExhausted)?;
        let carriers = std::mem::size_of::<HostCaptureStopAdmissionOriginalV4>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<HostCaptureStopAdmissionParentV4<'_>>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<HostCaptureStopAdmissionShapeV4>()))
            .ok_or(HostError::ResourceExhausted)?;
        let fixed = super::execution_query::execution_preparation_fixed_demand_v5(
            carriers, request.exact_body().len(), verification)?
            .checked_add(ArgumentClockV2::receiving_demand_v2().ok_or(HostError::ResourceExhausted)?)
            .map_err(|_| HostError::ResourceExhausted)?;
        let shape = HostCaptureStopAdmissionShapeV4 { fixed, claim: None };
        held.stop_admission_request = Some(binding(request));
        let mut receiving = match component.begin_capture_stop_admission_v4(request, &parent, &shape) {
            Ok(receiving) => { held.stop_admission_funding = Some(Ok(())); receiving }
            Err(cause) => { held.stop_admission_funding = Some(Err(cause)); return Err(refused()); }
        };
        held.stop_admission = Some(Box::new(HostCaptureStopAdmissionOriginalV4::new(request, shape)));
        let original = held.stop_admission.as_mut().ok_or_else(refused)?;
        let ArgumentStageOriginalV2 { owner, argument, .. } = &mut *old;
        let owner = owner.as_mut().ok_or_else(refused)?;
        let argument = argument.as_mut().ok_or_else(refused)?;
        original.shape.claim = Some(owner.initial_claim_receiving_demand_v2());
        if matches!(original.shape.claim, Some(Err(_))) { original.first.get_or_insert(FirstV4::Forecast); }
        original.extension = Some(receiving.extend_capture_stop_admission_v4(binding(request), &original.shape));
        if !matches!(original.extension, Some(Ok(()))) {
            original.first.get_or_insert(FirstV4::Extension);
            return Err(refused());
        }
        original.clock = Some(ArgumentClockV2::capture(boot));
        // Primary clock IO itself owes the separate final clock, even if its
        // contract or the canonical decoder fails before native-before entry.
        let preparation = (|| -> Result<()> {
            let sample = original.sample()?;
            original.decoded = Some(aos_sandbox_protocol::decode_canonical_capture_stop_request_v4(
                request.exact_body(), request.peer(), request.peer_policy(), sample.boottime_nanoseconds()));
            if !matches!(original.decoded, Some(Ok(_))) {
                original.first.get_or_insert(FirstV4::Decode);
                return Err(refused());
            }
            Ok(())
        })();
        if preparation.is_err() {
            original.finish_clock_post();
            return Err(refused());
        }
        original.bookends.before = Some(receiving.observe_before_once_v5().await);
        if !matches!(original.bookends.before, Some(Ok(()))) { original.first.get_or_insert(FirstV4::Before); }
        if original.first.is_none() && original.sample().is_ok() {
            let _ = owner.observe_execution_names_v2(&mut original.bookends.names[0], &mut original.bookends.name_results[0]);
            original.bookends.argument_results[0] = Some(argument.observe_names_before_v2(&mut original.bookends.argument_names[0]));
            if !original.bookends.name_results[0].iter().all(|result| matches!(result, Some(Ok(())))) {
                original.first.get_or_insert(FirstV4::NamesBefore);
            } else if !matches!(original.bookends.argument_results[0], Some(Ok(()))) {
                original.first.get_or_insert(FirstV4::ArgumentBefore);
            }
            if original.first.is_none() {
                original.admission = Some((|| {
                    let claim = match owner.claim() {
                        Ok(claim) => claim,
                        Err(cause) => { original.claim_failure = Some(cause); original.first.get_or_insert(FirstV4::Claim); return Err(refused()); }
                    };
                    if claim.host_verifier().boot_id() != boot { return Err(refused()); }
                    let decoded = original.decoded.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(refused)?;
                    if decoded.header().protocol_version() != protocol
                        || decoded.header().request_id() != &request.request_id()
                        || decoded.header().deadline_boottime_nanoseconds() != original.cutoff
                        || self.state.effect(&request.request_id()).is_some()
                    { return Err(refused()); }
                    let sample = original.bookends.samples.iter().flatten()
                        .filter_map(|result| result.as_ref().ok()).last().copied().ok_or_else(refused)?;
                    original.admission_clock = Some(sample);
                    self.authority.admit_stop_retaining_v4(request.authorization().ok_or_else(refused)?,
                        decoded, request.exact_body(), protocol, &sample,
                        self.state.prior_authorization(decoded.fence().sandbox_id()), &mut original.signed)
                        .map_err(HostError::from)
                })());
                if !matches!(original.admission, Some(Ok(_))) { original.first.get_or_insert(FirstV4::Admission); }
            }
        }
        // These destinations are owed from native-before entry independently
        // of decoder, claim, signature, clock or primary native refusal.
        let _ = owner.observe_execution_names_post_v2(&mut original.bookends.names[1], &mut original.bookends.name_results[1]);
        original.bookends.argument_results[1] = Some(argument.observe_names_post_v2(&mut original.bookends.argument_names[1]));
        if !original.bookends.name_results[1].iter().all(|result| matches!(result, Some(Ok(())))) {
            original.first.get_or_insert(FirstV4::NamesAfter);
        } else if !matches!(original.bookends.argument_results[1], Some(Ok(()))) {
            original.first.get_or_insert(FirstV4::ArgumentAfter);
        }
        original.bookends.after = Some(receiving.observe_after_once_v5().await);
        if !matches!(original.bookends.after, Some(Ok(()))) { original.first.get_or_insert(FirstV4::After); }
        original.finish_clock_post();
        if original.first.is_some() { return Err(refused()); }
        original.bookends.native = Some(receiving.dispose_positive_once_v5());
        if !matches!(original.bookends.native, Some(Ok(()))) {
            original.first.get_or_insert(FirstV4::Disposal); return Err(refused());
        }
        original.bookends.require_native_positive_v3()?;
        for names in original.bookends.names.iter_mut().flatten() { names.settle_positive_once_v1(); }
        for names in &mut original.bookends.argument_names { names.settle_positive_once_v1(); }
        if !matches!(original.decoded, Some(Ok(_)))
            || !matches!(original.admission, Some(Ok(_))) || original.admission_clock.is_none()
        { return Err(refused()); }
        original.positive = true;
        // Only actual owned proof moves; this is not another verifier or a
        // dispatch constructor from transport authentication or receipt DATA.
        let decoded = match original.decoded.take() {
            Some(Ok(decoded)) => decoded,
            retained => { original.decoded = retained; return Err(refused()); }
        };
        let admitted = match original.admission.take() {
            Some(Ok(admitted)) => admitted,
            retained => { original.admission = retained; return Err(refused()); }
        };
        original.transferred = true;
        Ok((decoded, admitted, original.admission_clock.ok_or_else(refused)?))
    }
}

fn binding(request: &AuthenticatedBrokerMethodRequestV1) -> HostExecutionRequestBindingV2 {
    HostExecutionRequestBindingV2 { id: request.request_id(), session: request.session_binding(),
        signed: request.signed_request_digest() }
}

fn refused() -> HostError {
    HostError::Fence("fresh Capture Stop retains its original paid verification custody")
}
