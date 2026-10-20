//! Serves fresh authenticated QueryExecution27 on the actual resident writer.
//!
//! A query owns its fresh read admission and clock. It cannot renew the original
//! execution permission, issue a child or adopt Source DATA as native readiness.
//! The image-funded occupied Launch ledger pays before every growth/native cut;
//! its same journals and all ambiguous earlier originals remain resident.

use std::sync::{Arc, Mutex};
use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox::journal::JournalAppendReceivingDemandErrorV1;
use aos_sandbox::runtime_execution::{DormantRuntimeExecutionOwnerV1, DormantRuntimeExecutionOwnerErrorV1};
use aos_sandbox_broker::{BrokerEffectClockComparisonV3, paired_clock::PairedClockIncrementalSamplesV3};
use aos_sandbox_core::{OperationId, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_core::runtime_backend::{DurableExecutionEffectV1, EffectOperationV1};
use aos_sandbox_protocol::authenticated_session::all_methods::{AuthenticatedBrokerMethodRequestV1,
    AuthenticatedBrokerRequestDirectionV1};
use aos_sandbox_protocol::host_execution::ValidatedHostExecutionQueryV1;
use buffa::Message as _;
use crate::execution_effect::HostExecutionEffectErrorV1;
use crate::live_agent::argument_attempt::HostArgumentAttemptOpeningV2;
use crate::plan::{HostCatalog, HostComponentControlStartupV2, HostExecutionRequestBindingV2,
    ExecutionQueryReservationV3};
use crate::state::HostStateStore;
use crate::worker::HostWorker;
use crate::{HostError, Result};
use super::super::{HostBroker, HostExecutionGrantReservationV1, HostExecutionGrantRequestV1};
use super::super::argument_handoff::{ArgumentClockV2, ArgumentStageOriginalV2, ArgumentStateWritesV2};
use super::execution_monitor::{MonitorBookendsV5, MonitorFailureGuardV5};

// Entry, post-await, two actual reserve/check-before-effect calls, pre-commit,
// and independently owed final posts. This is distinct from monitor ordinals.
const QUERY_CLOCK_SAMPLES_V3: usize = 6;
type QueryBookendsV3 = MonitorBookendsV5<QUERY_CLOCK_SAMPLES_V3>;

#[derive(Debug, thiserror::Error)]
enum QueryErrorV3 {
    #[error(transparent)] Host(#[from] HostError),
    #[error(transparent)] Owner(#[from] DormantRuntimeExecutionOwnerErrorV1),
    #[error(transparent)] Append(#[from] JournalAppendReceivingDemandErrorV1),
    #[error(transparent)] Effect(#[from] HostExecutionEffectErrorV1),
    #[error(transparent)] Protocol(#[from] aos_sandbox_protocol::ProtocolValidationError),
}

#[derive(Clone, Copy)]
enum FailureSiteV3 {
    JournalForecast,
    StateForecast,
    Extension,
    Clock,
    Entry,
    Before,
    NamesBefore,
    ArgumentBefore,
    Admission,
    Primary,
    NamesAfter,
    ArgumentAfter,
    After,
    Native,
    Retirement,
}

/// Keeps one fresh authenticated query through real CAS/readback/Sent.
pub(in crate::broker) struct HostExecutionQueryOriginalV3 {
    token: ExecutionQueryReservationV3,
    request: HostExecutionRequestBindingV2,
    sequence: u64,
    query: ValidatedHostExecutionQueryV1,
    cutoff: u64,
    complete_demand: ResourceVector,
    first: Option<FailureSiteV3>,
    journal_forecast: Option<std::result::Result<ResourceVector, JournalAppendReceivingDemandErrorV1>>,
    state_forecast: Option<Result<ResourceVector>>,
    extension: Option<Result<()>>,
    entry: Option<Result<()>>,
    admission: Option<Result<HostExecutionGrantReservationV1>>,
    signed_admission: aos_sandbox_broker::BrokerSignedAdmissionOriginalV4,
    primary: Option<std::result::Result<(), QueryErrorV3>>,
    retirement: Option<Result<()>>,
    body: Option<Vec<u8>>,
    write_failure_selected: bool,
    financial_failure_selected: bool,
    writes: Arc<Mutex<ArgumentStateWritesV2>>,
    bookends: QueryBookendsV3,
}

impl HostExecutionQueryOriginalV3 {
    fn new(token: ExecutionQueryReservationV3, request: &AuthenticatedBrokerMethodRequestV1,
        query: ValidatedHostExecutionQueryV1, cutoff: u64, complete_demand: ResourceVector) -> Self {
        Self { token, request: binding(request), sequence: request.client_sequence(), query, cutoff,
            complete_demand, first: None, journal_forecast: None, state_forecast: None,
            extension: None, entry: None, admission: None,
            signed_admission: aos_sandbox_broker::BrokerSignedAdmissionOriginalV4::new(), primary: None, retirement: None, body: None, write_failure_selected: false, financial_failure_selected: false,
            writes: Arc::new(Mutex::new(ArgumentStateWritesV2::new())),
            bookends: QueryBookendsV3::new() }
    }

    fn sample(&mut self, clock: &mut ArgumentClockV2) -> Result<RawPairedClockSample> {
        let comparison = self.admission.as_ref().and_then(|result| result.as_ref().ok())
            .map(|reservation| BrokerEffectClockComparisonV3::from_effect(&reservation.effect));
        let cutoff = self.cutoff;
        let result = self.bookends.sample_clock_contract_v3(clock, |sample| {
            if sample.boottime_nanoseconds() >= cutoff { return Err(refused()); }
            if let Some(comparison) = &comparison { comparison.require_fresh(sample)?; }
            Ok(())
        });
        if result.is_err() { self.first.get_or_insert(FailureSiteV3::Clock); }
        result
    }

    fn require_positive(&self) -> Result<()> {
        if self.first.is_some() || !matches!(self.primary, Some(Ok(()))) { return Err(refused()); }
        self.bookends.require_native_positive_v3()?;
        let scope = self.admission.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(refused)?;
        let sample = self.bookends.final_sample.as_ref().ok_or_else(refused)?;
        BrokerEffectClockComparisonV3::from_effect(&scope.effect).require_fresh(sample)?;
        if sample.boottime_nanoseconds() >= self.cutoff { return Err(refused()); }
        Ok(())
    }

    pub(in crate::broker) fn first_failure_v3<'original>(&'original self,
        component: &'original HostComponentControlStartupV2,
    ) -> Option<&'original (dyn std::error::Error + 'original)> {
        match self.first? {
            FailureSiteV3::JournalForecast => self.journal_forecast.as_ref()?.as_ref().err().map(|cause| cause as _),
            FailureSiteV3::StateForecast => self.state_forecast.as_ref()?.as_ref().err().map(|cause| cause as _),
            FailureSiteV3::Extension => {
                if self.financial_failure_selected { component.execution_query_receiving_failure_v3() }
                else { self.extension.as_ref()?.as_ref().err().map(|cause| cause as _) }
            },
            FailureSiteV3::Entry => {
                if self.financial_failure_selected { component.execution_query_receiving_failure_v3() }
                else { self.entry.as_ref()?.as_ref().err().map(|cause| cause as _) }
            },
            FailureSiteV3::Clock => self.bookends.clock_failure_v3(),
            FailureSiteV3::Before | FailureSiteV3::After | FailureSiteV3::Native => Some(component.failure()),
            FailureSiteV3::NamesBefore | FailureSiteV3::NamesAfter => {
                let index = usize::from(matches!(self.first, Some(FailureSiteV3::NamesAfter)));
                self.bookends.names[index].iter().find_map(|names| names.failure()).or_else(||
                    self.bookends.name_results[index].iter().find_map(|result| result.as_ref()?.as_ref().err().map(|cause| cause as _)))
            }
            FailureSiteV3::ArgumentBefore | FailureSiteV3::ArgumentAfter => {
                let index = usize::from(matches!(self.first, Some(FailureSiteV3::ArgumentAfter)));
                self.bookends.argument_names[index].failure().or_else(||
                    self.bookends.argument_results[index].as_ref()?.as_ref().err().map(|cause| cause as _))
            }
            FailureSiteV3::Admission => self.signed_admission.failure()
                .or_else(|| self.admission.as_ref()?.as_ref().err().map(|cause| cause as _)),
            FailureSiteV3::Primary => self.primary.as_ref()?.as_ref().err().map(|cause| cause as _),
            FailureSiteV3::Retirement => self.retirement.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }

    pub(in crate::broker) fn format_failure_v3(&self, component: &HostComponentControlStartupV2,
        formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.write_failure_selected && matches!(self.first, Some(FailureSiteV3::Admission | FailureSiteV3::Primary)) {
            let writes = self.writes.lock().map_err(|_| std::fmt::Error)?;
            if let Some(cause) = writes.failure() { return std::fmt::Display::fmt(cause, formatter); }
        }
        match self.first_failure_v3(component) {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("resident query retains authenticated response custody"),
        }
    }

    fn fixed_demand(body: usize, verification: usize) -> Result<ResourceVector> {
        let carriers = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(ExecutionQueryReservationV3::receiving_bytes_v3()?))
            .ok_or(HostError::ResourceExhausted)?;
        execution_preparation_fixed_demand_v5(carriers, body, verification)
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(crate) async fn query_resident_execution_v3(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1, protected_boot: [u8; 16], deadline: u64,
    ) -> Result<Vec<u8>> {
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.method() != BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION
            || !self.state_healthy || self.active_argument_writes.is_some()
        { return Err(refused()); }
        let query = *request.host_execution_query_data_v3().ok_or_else(refused)?;
        let selector = *query.monitor_v3().ok_or_else(refused)?;
        let (stage, accept, observe, execution, unknown, launch_binding) = {
            let launch = self.launch_original.as_ref().ok_or_else(refused)?.lock().map_err(|_| refused())?;
            if !launch.authenticated_sent || launch.first.is_some() || launch.next_execution.is_some() { return Err(refused()); }
            let (stage, accept, observe, execution, unknown) = launch.capture.as_ref().ok_or_else(refused)?.query_association_v3()?;
            (stage, accept, observe, execution, unknown, HostExecutionRequestBindingV2 {
                id: launch.request.0, session: launch.request.1, signed: launch.request.2 })
        };
        let control = self.component_control.as_ref().cloned().ok_or_else(refused)?;
        let mut component = control.lock().map_err(|_| refused())?;
        let mut held = stage.lock().map_err(|_| refused())?;
        let ArgumentStageOriginalV2 { owner, argument, accepted, .. } = &mut *held;
        let owner = owner.as_mut().ok_or_else(refused)?;
        let argument = argument.as_mut().ok_or_else(refused)?;
        let (first, spec_bytes, ongoing, destination) = accepted.as_mut().ok_or_else(refused)?.query_parts_v3()?;
        let historical = execution != query.execution_id();
        if !historical { ongoing.require_query_original_data_v3(&query, first)?; }
        // The payer stays bound to the current resident originals. The target
        // of an old read is independently checked under fresh Query permission;
        // its historical source cannot substitute for the current ledger owner.
        let payer_source = ongoing.source_digest_v5();
        let mut failure_guard = MonitorFailureGuardV5 { unknown, positive: false };
        let clock = ongoing.borrow_query_admission_clock_v3(&stage, accept, request)?;
        let artifacts = request.authorization().ok_or_else(refused)?;
        let verification = self.authority.execution_signed_admission_receiving_bytes_v5(artifacts)
            .ok_or(HostError::ResourceExhausted)?;
        let (native, maximum) = component.execution_monitor_native_demand_v5()?;
        let fixed = HostExecutionQueryOriginalV3::fixed_demand(request.exact_body().len(), verification)?
            .checked_add(native).map_err(|_| HostError::ResourceExhausted)?;
        let token = component.prepare_execution_query_receiving_v3(launch_binding, accept, observe,
            request, payer_source, execution, fixed)?;
        *destination = Some(Box::new(HostExecutionQueryOriginalV3::new(token, request, query,
            deadline.min(query.header().deadline_boottime_nanoseconds()), fixed)));
        let original = destination.as_mut().ok_or_else(refused)?;
        original.journal_forecast = Some(if historical {
            owner.execution_historical_query_receiving_demand_v5(query.execution_id())
        } else { owner.execution_monitor_query_receiving_demand_v3(spec_bytes) });
        if original.journal_forecast.as_ref().is_some_and(std::result::Result::is_err) {
            original.first.get_or_insert(FailureSiteV3::JournalForecast);
        }
        original.state_forecast = Some(self.state.execution_query_receiving_demand_v3().ok_or(HostError::ResourceExhausted));
        if original.state_forecast.as_ref().is_some_and(std::result::Result::is_err) {
            original.first.get_or_insert(FailureSiteV3::StateForecast);
        }
        original.extension = Some((|| {
            let journal = original.journal_forecast.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(refused)?;
            let state = original.state_forecast.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(refused)?;
            let complete = fixed.checked_add(*journal).and_then(|demand| demand.checked_add(*state))
                .map_err(|_| HostError::ResourceExhausted)?;
            component.extend_execution_query_receiving_v3(&original.token, complete)?;
            original.complete_demand = complete;
            Ok(())
        })());
        if !matches!(original.extension, Some(Ok(()))) {
            original.financial_failure_selected = component.execution_query_receiving_failure_v3().is_some();
            original.first.get_or_insert(FailureSiteV3::Extension); return Err(refused());
        }
        if original.sample(clock).is_err() {
            let cutoff = original.cutoff;
            let _ = original.bookends.finish_entered_clock_post_v3(clock, |sample| {
                if sample.boottime_nanoseconds() >= cutoff { return Err(refused()); }
                Ok(())
            });
            return Err(refused());
        }
        let mut receiving = match component.begin_execution_query_receiving_v3(&original.token, maximum,
            &mut original.financial_failure_selected) {
            Ok(receiving) => receiving,
            Err(cause) => { original.entry = Some(Err(cause));
                original.first.get_or_insert(FailureSiteV3::Entry);
                let cutoff = original.cutoff;
                let _ = original.bookends.finish_entered_clock_post_v3(clock, |sample| {
                    if sample.boottime_nanoseconds() >= cutoff { return Err(refused()); }
                    Ok(())
                });
                return Err(refused()); }
        };
        original.entry = Some(Ok(()));
        original.bookends.before = Some(receiving.observe_before_v2().await);
        if !matches!(original.bookends.before, Some(Ok(()))) { original.first.get_or_insert(FailureSiteV3::Before); }
        if original.first.is_none() && original.sample(clock).is_ok() {
            let _ = owner.observe_execution_names_v2(&mut original.bookends.names[0], &mut original.bookends.name_results[0]);
            original.bookends.argument_results[0] = Some(argument.observe_names_before_v2(&mut original.bookends.argument_names[0]));
            if !original.bookends.name_results[0].iter().all(|result| matches!(result, Some(Ok(())))) {
                original.first.get_or_insert(FailureSiteV3::NamesBefore);
            } else if !matches!(original.bookends.argument_results[0], Some(Ok(()))) {
                original.first.get_or_insert(FailureSiteV3::ArgumentBefore);
            }
            if original.first.is_none() {
                original.primary = Some((|| {
                    let claim = owner.claim()?;
                    if claim.host_verifier().boot_id() != protected_boot { return Err(refused().into()); }
                    self.active_argument_writes = Some(Arc::clone(&original.writes));
                    // The two fields are borrowed separately so the same
                    // prearmed clock and typed admission destination survive
                    // every failed verification prefix without a callback heap.
                    let cutoff = original.cutoff;
                    let bookends = &mut original.bookends;
                    let admission = self.reserve_host_execution_query_retaining_v3(&claim, request, protected_boot,
                        || bookends.sample_clock_contract_v3(clock, |sample| {
                            if sample.boottime_nanoseconds() >= cutoff { return Err(refused()); }
                            Ok(())
                        }), &mut original.signed_admission);
                    if bookends.clock_first.is_some() { original.first.get_or_insert(FailureSiteV3::Clock); }
                    original.admission = Some(admission);
                    if original.admission.as_ref().is_some_and(std::result::Result::is_err) {
                        original.write_failure_selected = original.writes.lock().map_err(|_| refused())?.failure().is_some();
                        original.first.get_or_insert(FailureSiteV3::Admission); return Err(refused().into());
                    }
                    original.sample(clock)?;
                    let scope = original.admission.as_ref().and_then(|result| result.as_ref().ok()).ok_or_else(refused)?;
                    let HostExecutionGrantRequestV1::Query(actual) = scope.request() else { return Err(refused().into()); };
                    if *actual != original.query || !scope.matches(request.method(), request.request_id(), request.exact_body(), &claim) {
                        return Err(refused().into());
                    }
                    let effect = if historical {
                        self.state.require_historical_execution_query_v5(&original.query, &self.authority)?;
                        claim.terminal_execution_effect_data_v5(original.query.execution_id())?
                    } else { claim.latest_effect_data_v3()? }.ok_or_else(refused)?;
                    validate_latest(&effect, &original.query)?;
                    let mut body = crate::execution_effect::outcome(
                        *effect.issue().idempotency().operation().as_bytes(), original.query.execution_id(),
                        effect.issue().idempotency().request_digest(), Some(&effect), &claim)?;
                    body.query_binding_version = 3;
                    body.backend_operation_sequence = effect.issue().sequence().get();
                    if selector.source_kind_v3() == 2 && !body.terminal_guest_result.is_empty() {
                        // An old112 marker is insufficient. Only the sealed
                        // Native reader can lend this exact extended value.
                        let marker = claim.capture_terminal_marker_v3(&effect)?.ok_or_else(refused)?;
                        body.capture_terminal_marker = marker.canonical_bytes_v3().to_vec();
                    }
                    let encoded = body.encode_to_vec();
                    aos_sandbox_protocol::host_execution::decode_host_execution_monitor_outcome_v3(&encoded, &original.query)?;
                    let completed = self.complete_host_execution_reservation(scope, &claim, &encoded);
                    if completed.is_err() {
                        // No writer runs in the independently owed posts. A
                        // new failure here belongs to this exact returned cut.
                        original.write_failure_selected = original.writes.lock().map_err(|_| refused())?.failure().is_some();
                    }
                    completed?;
                    original.body = Some(encoded);
                    Ok(())
                })());
                self.active_argument_writes = None;
                if original.primary.as_ref().is_some_and(std::result::Result::is_err) {
                    original.first.get_or_insert(FailureSiteV3::Primary);
                }
            }
        }
        // The new read scope never suppresses independently owed negative-
        // capable posts after a read, State write or currentness refusal.
        let _ = owner.observe_execution_names_post_v2(&mut original.bookends.names[1], &mut original.bookends.name_results[1]);
        original.bookends.argument_results[1] = Some(argument.observe_names_post_v2(&mut original.bookends.argument_names[1]));
        if !original.bookends.name_results[1].iter().all(|result| matches!(result, Some(Ok(())))) {
            original.first.get_or_insert(FailureSiteV3::NamesAfter);
        } else if !matches!(original.bookends.argument_results[1], Some(Ok(()))) {
            original.first.get_or_insert(FailureSiteV3::ArgumentAfter);
        }
        original.bookends.after = Some(receiving.observe_after_v2().await);
        if !matches!(original.bookends.after, Some(Ok(()))) { original.first.get_or_insert(FailureSiteV3::After); }
        original.bookends.native = Some(receiving.finish_native_v2());
        if !matches!(original.bookends.native, Some(Ok(()))) { original.first.get_or_insert(FailureSiteV3::Native); }
        let comparison = original.admission.as_ref().and_then(|result| result.as_ref().ok())
            .map(|scope| BrokerEffectClockComparisonV3::from_effect(&scope.effect));
        let cutoff = original.cutoff;
        original.bookends.final_sample = original.bookends.sample_post_clock_contract_v3(clock, |sample| {
            if sample.boottime_nanoseconds() >= cutoff { return Err(refused()); }
            if let Some(comparison) = &comparison { comparison.require_fresh(sample)?; }
            Ok(())
        }).ok();
        if original.bookends.final_sample.is_none() { original.first.get_or_insert(FailureSiteV3::Clock); }
        original.require_positive()?;
        let body = original.body.take().ok_or_else(refused)?;
        receiving.retain_pending_authenticated_v2()?;
        failure_guard.positive = true;
        Ok(body)
    }

    // Only the existing real protected Session CAS/readback/Sent completion
    // calls this sealed port. No deadline/permission is renewed here.
    pub(crate) fn retire_authenticated_execution_query_v3(&mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<()> {
        let stage = {
            let launch = self.launch_original.as_ref().ok_or_else(refused)?.lock().map_err(|_| refused())?;
            launch.capture.as_ref().ok_or_else(refused)?.query_association_v3()?.0
        };
        let mut component = self.component_control.as_ref().ok_or_else(refused)?.lock().map_err(|_| refused())?;
        let mut held = stage.lock().map_err(|_| refused())?;
        let destination = held.accepted.as_mut().ok_or_else(refused)?.query_destination_v3();
        let original = destination.as_mut().ok_or_else(refused)?;
        original.retirement = Some((|| {
            if original.request != binding(request) || original.sequence != request.client_sequence()
                || request.host_execution_query_data_v3() != Some(&original.query) || original.body.is_some()
            { return Err(refused()); }
            original.require_positive()?;
            let writes = Arc::get_mut(&mut original.writes).ok_or_else(refused)?;
            let writes = writes.get_mut().map_err(|_| refused())?;
            writes.require_positive_disposal_v2()?;
            Ok(())
        })());
        if !matches!(original.retirement, Some(Ok(()))) {
            original.first.get_or_insert(FailureSiteV3::Retirement); return Err(refused());
        }
        for names in original.bookends.names.iter_mut().flatten() { names.settle_positive_once_v1(); }
        for names in &mut original.bookends.argument_names { names.settle_positive_once_v1(); }
        let identity = original.token.duplicate_disposal_identity_v3();
        let kept = aos_sandbox_core::component_receiving::without_operation_traffic_v1(original.complete_demand)
            .with(D::OpenFiles, 0);
        drop(destination.take());
        component.finish_execution_query_storage_disposal_v3(&ExecutionQueryStorageDisposedV3 { identity, kept })
    }
}

fn validate_latest(effect: &DurableExecutionEffectV1, query: &ValidatedHostExecutionQueryV1)
    -> std::result::Result<(), QueryErrorV3> {
    let selector = *query.monitor_v3().ok_or_else(refused)?;
    if effect.admission().execution() != query.execution_id()
        || effect.admission().specification_digest() != query.specification_digest()
        || effect.admission().currentness().runtime().handle() != selector.runtime_v3()
        || effect.issue().operation() != EffectOperationV1::Observe { return Err(refused().into()); }
    let (operation, source) = if effect.issue().idempotency().operation() == selector.first_observe_v3() {
        (selector.first_observe_v3(), query.source_commitment())
    } else {
        let lineage = selector.lineage_for_sequence_v3(OperationId::from_bytes(query.operation_id()),
            query.execution_id(), effect.issue().sequence())?;
        (lineage.operation_v5(), lineage.commitment_v5())
    };
    if effect.issue().idempotency().operation() != operation
        || effect.issue().idempotency().request_digest() != source { return Err(refused().into()); }
    Ok(())
}

/// Preserves the same resource identity after actual positive query storage drop.
pub(crate) struct ExecutionQueryStorageDisposedV3 {
    identity: ExecutionQueryReservationV3,
    kept: ResourceVector,
}

impl ExecutionQueryStorageDisposedV3 {
    pub(crate) fn borrow_original_v3(&self) -> (&ExecutionQueryReservationV3, ResourceVector) {
        (&self.identity, self.kept)
    }
}

fn binding(request: &AuthenticatedBrokerMethodRequestV1) -> HostExecutionRequestBindingV2 {
    HostExecutionRequestBindingV2 { id: request.request_id(), session: request.session_binding(), signed: request.signed_request_digest() }
}

fn refused() -> HostError { HostError::Fence("fresh resident QueryExecution retains unresolved custody") }

// Shared passive geometry for the two genuine held-writer preparations.
pub(in crate::broker) fn execution_preparation_fixed_demand_v5(
carriers: usize, body: usize, verification: usize,
) -> Result<ResourceVector> {
    let bytes = carriers.checked_add(2 * std::mem::size_of::<Mutex<ArgumentStateWritesV2>>())
        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<MonitorFailureGuardV5>()))
        .and_then(|bytes| bytes.checked_add(10 * std::mem::size_of::<std::fs::Metadata>()))
        .and_then(|bytes| bytes.checked_add(PairedClockIncrementalSamplesV3::receiving_bytes_v3()?.checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(body.checked_mul(8)?))
        .and_then(|bytes| bytes.checked_add(verification))
        .ok_or(HostError::ResourceExhausted)?;
    let fixed = ResourceVector::ZERO.with(D::MemoryBytes,
        u64::try_from(bytes).map_err(|_| HostError::ResourceExhausted)?)
        // A refused primary retains both boot files while the
        // independently owed final pair opens its own two files.
        .with(D::OpenFiles, 5);
    [DormantRuntimeExecutionOwnerV1::execution_currentness_demand_v2(),
        DormantRuntimeExecutionOwnerV1::execution_currentness_post_demand_v2(),
        HostArgumentAttemptOpeningV2::names_receiving_demand_v2(),
        HostArgumentAttemptOpeningV2::names_post_receiving_demand_v2()]
        .into_iter().try_fold(fixed, |total, term| total.checked_add(
            term.ok_or(HostError::ResourceExhausted)?).map_err(|_| HostError::ResourceExhausted))
}
