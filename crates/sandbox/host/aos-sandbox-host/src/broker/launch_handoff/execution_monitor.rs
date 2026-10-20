//! Drives a finite Observe child under the same original execution permission.
//!
//! The existing runtime ledger owns sequence, prepare/issue and completion.
//! The Launch retains the same accepted Stage and occupied20. A signed Guest
//! packet stays parked until the actual native pair, five names and original
//! ongoing clock checks finish. Neither a timer nor a financial amount grants
//! execution, cancellation, replacement lease or physical Capture completion.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use aos_sandbox_controller_domain::journal::{JournalAppendReceivingDemandErrorV1,
    ProtectedJournalCurrentnessOriginalsV1 as Names};
use aos_sandbox_controller_domain::runtime_execution::{DormantRuntimeExecutionOwnerV1,
    DormantRuntimeExecutionOwnerErrorV1, DormantRuntimeExecutionClaimV1};
use aos_sandbox_broker::paired_clock::PairedClockIncrementalSamplesV3;
use aos_sandbox_model::{ObjectDigest, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_model::runtime_backend::{DurableExecutionEffectV1, EffectOperationV1, EffectPhaseV1};
use aos_sandbox_protocol::host_execution::monitor::ExecutionMonitorLineageDataV5;
use crate::execution_effect::{self, HostExecutionEffectErrorV1};
use crate::live_agent::{HostAgentLiveSessionV1, HostAgentLiveErrorV1};
use crate::live_agent::deferred_completion::AgentDeferredCompletionOriginalV5;
use crate::live_agent::execution_original::AgentExecutionOriginalV2;
use crate::live_agent::argument_attempt::HostArgumentAttemptOpeningV2;
use crate::plan::{HostCatalog, HostExecutionReceivingLoanV2, ExecutionMonitorReservationV5};
use crate::state::HostStateStore;
use crate::worker::HostWorker;
use crate::{HostError, Result};
use super::super::HostBroker;
use super::super::argument_handoff::{ArgumentClockV2, ArgumentStageOriginalV2};
use super::super::accepted_execution::ongoing::HostExecutionMonitorPermissionV5;

// Entry, post-await before names, two possible native writes, and final posts.
const MAXIMUM_CLOCK_SAMPLES_V5: usize = 3 + crate::live_agent::MAXIMUM_EFFECT_WRITE_ATTEMPTS_V4;
const MONITOR_PERIOD_NANOSECONDS_V5: u64 = 1_000_000_000;

#[derive(Debug, thiserror::Error)]
pub(super) enum MonitorErrorV5 {
    #[error(transparent)] Host(#[from] HostError),
    #[error(transparent)] Owner(#[from] DormantRuntimeExecutionOwnerErrorV1),
    #[error(transparent)] Append(#[from] JournalAppendReceivingDemandErrorV1),
    #[error(transparent)] Effect(#[from] HostExecutionEffectErrorV1),
    #[error(transparent)] Agent(#[from] HostAgentLiveErrorV1),
    #[error(transparent)] Protocol(#[from] aos_sandbox_protocol::ProtocolValidationError),
}

/// Retains completed child DATA after its actual native storage retires.
pub(in crate::broker) struct MonitorCompletedDataV5 {
    pub(super) lineage: ExecutionMonitorLineageDataV5,
    pub(in crate::broker) effect: DurableExecutionEffectV1,
    pub(in crate::broker) next_due: u64,
    pub(in crate::broker) terminal: bool,
    pub(in crate::broker) terminal_native: Option<super::super::accepted_execution::terminal_disposal::HostGuestTerminalNativeV3>,
}

pub(in crate::broker) struct MonitorBookendsV5<const SAMPLES: usize = MAXIMUM_CLOCK_SAMPLES_V5> {
    pub(super) clock: PairedClockIncrementalSamplesV3,
    post_clock: PairedClockIncrementalSamplesV3,
    post_result: Option<std::result::Result<RawPairedClockSample, MonitorErrorV5>>,
    pub(super) samples: [Option<std::result::Result<RawPairedClockSample, MonitorErrorV5>>; SAMPLES],
    pub(super) samples_used: usize,
    pub(super) names: [[Names; 4]; 2],
    pub(super) name_results: [[Option<std::result::Result<(), aos_sandbox_controller_domain::JournalError>>; 4]; 2],
    pub(super) argument_names: [Names; 2],
    pub(super) argument_results: [Option<std::result::Result<(), aos_sandbox_controller_domain::JournalError>>; 2],
    pub(super) before: Option<Result<()>>,
    pub(super) after: Option<Result<()>>,
    pub(super) native: Option<Result<()>>,
    pub(super) final_sample: Option<RawPairedClockSample>,
    pub(super) clock_first: Option<usize>,
}

impl<const SAMPLES: usize> MonitorBookendsV5<SAMPLES> {
    pub(in crate::broker) fn new() -> Self {
        Self { clock: PairedClockIncrementalSamplesV3::new(SAMPLES),
            post_clock: PairedClockIncrementalSamplesV3::new(1), post_result: None,
            samples: std::array::from_fn(|_| None), samples_used: 0,
            names: std::array::from_fn(|_| std::array::from_fn(|_| Names::new())),
            name_results: std::array::from_fn(|_| std::array::from_fn(|_| None)),
            argument_names: std::array::from_fn(|_| Names::new()),
            argument_results: std::array::from_fn(|_| None),
            before: None, after: None, native: None, final_sample: None, clock_first: None }
    }

    // This is an entry marker for the independently owed clock post. It
    // lends no sample, permission, native result or mutable field access.
    pub(in crate::broker) fn has_entered_clock_v4(&self) -> bool {
        self.samples_used != 0
    }

    pub(super) fn sample(&mut self, clock: &mut ArgumentClockV2,
        permission: &HostExecutionMonitorPermissionV5<'_>) -> Result<RawPairedClockSample> {
        self.sample_clock_contract_v3(clock, |sample| permission.require_clock_v5(sample))
    }

    pub(in crate::broker) fn sample_clock_contract_v3(&mut self, clock: &mut ArgumentClockV2,
        mut contract: impl FnMut(&RawPairedClockSample) -> Result<()>) -> Result<RawPairedClockSample> {
        let index = self.samples_used;
        let destination = self.samples.get_mut(index).ok_or_else(refused)?;
        if destination.is_some() { return Err(refused()); }
        self.samples_used += 1;
        *destination = Some((|| {
            let sample = clock.sample_monitor_lane_v5(&mut self.clock)?;
            contract(&sample)?;
            clock.retire_positive_monitor_sample_v5(&mut self.clock, sample)?;
            Ok(sample)
        })());
        if destination.as_ref().is_some_and(std::result::Result::is_err) {
            self.clock_first.get_or_insert(index);
        }
        destination.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or_else(refused)
    }

    pub(super) fn sample_post_v3(&mut self, clock: &mut ArgumentClockV2,
        permission: &HostExecutionMonitorPermissionV5<'_>) -> Result<RawPairedClockSample> {
        self.sample_post_clock_contract_v3(clock, |sample| permission.require_clock_v5(sample))
    }

    pub(super) fn sample_post_clock_contract_v3(&mut self, clock: &mut ArgumentClockV2,
        mut contract: impl FnMut(&RawPairedClockSample) -> Result<()>) -> Result<RawPairedClockSample> {
        if self.post_result.is_some() { return Err(refused()); }
        self.post_result = Some((|| {
            let sample = clock.sample_monitor_owed_post_lane_v3(&mut self.post_clock)?;
            contract(&sample)?;
            clock.retire_positive_monitor_sample_v5(&mut self.post_clock, sample)?;
            Ok(sample)
        })());
        self.post_result.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or_else(refused)
    }

    // A primary paired sample itself enters native IO before any PID1/name
    // scope. Its separately prepaid final destination is owed even if that
    // sample, its contract or later pre-entry preparation refused.
    pub(in crate::broker) fn finish_entered_clock_post_v3(&mut self, clock: &mut ArgumentClockV2,
        contract: impl FnMut(&RawPairedClockSample) -> Result<()>) -> Result<()> {
        if self.samples_used == 0 { return Ok(()); }
        self.final_sample = self.sample_post_clock_contract_v3(clock, contract).ok();
        if self.final_sample.is_none() { return Err(refused()); }
        Ok(())
    }

    pub(in crate::broker) fn clock_failure_v3(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(index) = self.clock_first {
            self.clock.failure().or_else(|| self.samples.get(index)?.as_ref()?.as_ref().err().map(|cause| cause as _))
        } else {
            self.post_clock.failure().or_else(|| self.post_result.as_ref()?.as_ref().err().map(|cause| cause as _))
        }
    }

    pub(super) fn require_positive(&self, permission: &HostExecutionMonitorPermissionV5<'_>) -> Result<()> {
        self.require_native_positive_v3()?;
        permission.require_clock_v5(self.final_sample.as_ref().ok_or_else(refused)?)
    }

    pub(super) fn require_native_positive_v3(&self) -> Result<()> {
        if !matches!(self.before, Some(Ok(()))) || !matches!(self.after, Some(Ok(())))
            || !matches!(self.native, Some(Ok(()))) || self.clock.failure().is_some()
            || self.post_clock.failure().is_some() || !matches!(self.post_result, Some(Ok(_)))
            || !self.names.iter().flatten().all(Names::is_complete)
            || !self.name_results.iter().flatten().all(|result| matches!(result, Some(Ok(()))))
            || !self.argument_names.iter().all(Names::is_complete)
            || !self.argument_results.iter().all(|result| matches!(result, Some(Ok(()))))
            || self.samples.iter().flatten().any(std::result::Result::is_err)
        { return Err(refused()); }
        if self.final_sample.is_none() { return Err(refused()); }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum MonitorFailureSiteV5 {
    Forecast, Extension, Clock, Deadline, Lineage, Entry, Before, NamesBefore, ArgumentBefore,
    Primary, NamesAfter, ArgumentAfter, After, Native, Final, Terminal,
}

pub(super) struct MonitorFailureGuardV5 {
    pub(super) unknown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(super) positive: bool,
}
impl Drop for MonitorFailureGuardV5 {
    fn drop(&mut self) {
        if !self.positive { self.unknown.store(true, Ordering::Release); }
    }
}

/// Parks one paid monitor interval on the actual retained accepted Stage.
pub(in crate::broker) struct HostExecutionMonitorOriginalV5 {
    reservation: ExecutionMonitorReservationV5,
    first: Option<MonitorFailureSiteV5>,
    entry: Option<Result<()>>,
    primary_native_append: bool,
    final_native_append: bool,
    forecast: Option<std::result::Result<ResourceVector, MonitorErrorV5>>,
    extension: Option<Result<()>>,
    lineage: Option<std::result::Result<ExecutionMonitorLineageDataV5, MonitorErrorV5>>,
    deadline: Option<Result<Instant>>,
    bookends: MonitorBookendsV5,
    guest: AgentExecutionOriginalV2,
    deferred: AgentDeferredCompletionOriginalV5,
    primary: Option<std::result::Result<DurableExecutionEffectV1, MonitorErrorV5>>,
    final_result: Option<std::result::Result<DurableExecutionEffectV1, MonitorErrorV5>>,
    terminal_native: Option<super::super::accepted_execution::terminal_disposal::HostGuestTerminalNativeV3>,
    terminal: Option<std::result::Result<bool, aos_sandbox_protocol::execution_evidence::RuntimeExecutionEvidenceError>>,
}

// Only the actual owning driver below constructs this continuously borrowed
// permission. The deterministic lineage is DATA and cannot construct this type.
/// Borrows the original signed execution permission for one exact ledger child.
pub(crate) struct HostExecutionMonitorRequestV5<'permission> {
    permission: &'permission HostExecutionMonitorPermissionV5<'permission>,
    lineage: ExecutionMonitorLineageDataV5,
}

impl HostExecutionMonitorRequestV5<'_> {
    pub(crate) fn lineage_v5(&self) -> &ExecutionMonitorLineageDataV5 { &self.lineage }
    pub(crate) fn original_source_commitment_v5(&self) -> Result<ObjectDigest> {
        self.permission.original_source_commitment_v5()
    }
    pub(crate) fn require_claim_binding_v5(&self, claim: &DormantRuntimeExecutionClaimV1<'_>) -> Result<()> {
        self.permission.require_claim_binding_v5(claim)?;
        if claim.next_effect_sequence().map_err(|_| refused())? != self.lineage.sequence_v5()
            || claim.currentness().runtime().handle() != self.lineage.runtime_v5()
            || self.permission.source_digest_v5() != self.lineage.source_v5()
            || self.permission.lifetime_v5().execution_v2() != self.lineage.execution_v5()
        { return Err(refused()); }
        Ok(())
    }
}

pub(super) trait NativeMonitorPostsV5 {
    fn require_positive(&self, ordinal: u64) -> Result<()>;
}
impl NativeMonitorPostsV5 for HostExecutionReceivingLoanV2<'_> {
    fn require_positive(&self, ordinal: u64) -> Result<()> {
        self.require_monitor_posts_positive_v5(ordinal)
    }
}

/// Borrows the real completed native bookends before the final child commit.
pub(crate) struct ExecutionMonitorPostsPositiveV5<'posts> {
    bookends: &'posts MonitorBookendsV5,
    native: &'posts dyn NativeMonitorPostsV5,
    request: &'posts HostExecutionMonitorRequestV5<'posts>,
    issued: &'posts DurableExecutionEffectV1,
}

impl ExecutionMonitorPostsPositiveV5<'_> {
    pub(crate) fn require_pending_v5(&self, issued: &DurableExecutionEffectV1)
        -> std::result::Result<(), HostAgentLiveErrorV1> {
        self.bookends.require_positive(self.request.permission)
            .and_then(|()| self.native.require_positive(self.request.lineage.sequence_v5().get()))
            .map_err(|_| HostAgentLiveErrorV1::RecoveryRequired)?;
        if issued != self.issued || issued.phase() != EffectPhaseV1::Issued
            || issued.issue().operation() != EffectOperationV1::Observe
            || issued.issue().sequence() != self.request.lineage.sequence_v5()
            || issued.issue().idempotency().operation() != self.request.lineage.operation_v5()
            || issued.issue().idempotency().request_digest() != self.request.lineage.commitment_v5()
        { return Err(HostAgentLiveErrorV1::Binding); }
        Ok(())
    }
}

impl HostExecutionMonitorOriginalV5 {
    fn new(reservation: ExecutionMonitorReservationV5) -> Self {
        Self { reservation, first: None, entry: None, primary_native_append: false,
            final_native_append: false, forecast: None, extension: None, lineage: None, deadline: None,
            bookends: MonitorBookendsV5::new(), guest: AgentExecutionOriginalV2::new(),
            deferred: AgentDeferredCompletionOriginalV5::new(), primary: None, final_result: None, terminal_native: None, terminal: None }
    }

    pub(super) fn first_failure_v5<'owner>(&'owner self,
        owner: &'owner DormantRuntimeExecutionOwnerV1,
        component: &'owner crate::plan::HostComponentControlStartupV2,
    ) -> Option<&'owner (dyn std::error::Error + 'owner)> {
        match self.first? {
            MonitorFailureSiteV5::Forecast => self.forecast.as_ref()?.as_ref().err().map(|cause| cause as _),
            MonitorFailureSiteV5::Extension => self.extension.as_ref()?.as_ref().err().map(|cause| cause as _),
            MonitorFailureSiteV5::Clock => self.bookends.clock_failure_v3(),
            MonitorFailureSiteV5::Deadline => self.deadline.as_ref()?.as_ref().err().map(|cause| cause as _),
            MonitorFailureSiteV5::Lineage => self.lineage.as_ref()?.as_ref().err().map(|cause| cause as _),
            MonitorFailureSiteV5::Entry => self.entry.as_ref()?.as_ref().err().map(|cause| cause as _),
            MonitorFailureSiteV5::Before | MonitorFailureSiteV5::After | MonitorFailureSiteV5::Native =>
                Some(component.failure()),
            MonitorFailureSiteV5::NamesBefore | MonitorFailureSiteV5::NamesAfter => {
                let index = usize::from(matches!(self.first, Some(MonitorFailureSiteV5::NamesAfter)));
                self.bookends.names[index].iter().find_map(Names::failure)
                    .or_else(|| self.bookends.name_results[index].iter()
                        .find_map(|result| result.as_ref()?.as_ref().err().map(|cause| cause as _)))
            }
            MonitorFailureSiteV5::ArgumentBefore | MonitorFailureSiteV5::ArgumentAfter => {
                let index = usize::from(matches!(self.first, Some(MonitorFailureSiteV5::ArgumentAfter)));
                self.bookends.argument_names[index].failure().or_else(||
                    self.bookends.argument_results[index].as_ref()?.as_ref().err().map(|cause| cause as _))
            }
            MonitorFailureSiteV5::Primary => {
                let returned = self.primary.as_ref()?.as_ref().err()?;
                if self.primary_native_append {
                    return owner.execution_monitor_append_failure_v5().or(Some(returned as _));
                }
                if matches!(returned, MonitorErrorV5::Effect(HostExecutionEffectErrorV1::Agent(
                    HostAgentLiveErrorV1::RecoveryRequired))) {
                    return self.guest.failure().or(Some(returned as _));
                }
                Some(returned as _)
            }
            MonitorFailureSiteV5::Final => {
                let returned = self.final_result.as_ref()?.as_ref().err()?;
                if self.final_native_append {
                    owner.execution_monitor_append_failure_v5().or(Some(returned as _))
                } else { Some(returned as _) }
            }
            MonitorFailureSiteV5::Terminal => self.terminal.as_ref()?.as_ref().err().map(|cause| cause as _),
        }
    }

    fn fixed_demand(specification_bytes: usize) -> Result<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(ExecutionMonitorReservationV5::receiving_bytes_v5()?))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<crate::DormantHostBrokerCallErrorV1>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<MonitorFailureGuardV5>()))
            // The actual two held-journal forecasts retain each metadata/error
            // result before returning; no descriptor is opened by metadata.
            .and_then(|bytes| bytes.checked_add(10 * std::mem::size_of::<std::fs::Metadata>()))
            .and_then(|bytes| bytes.checked_add(PairedClockIncrementalSamplesV3::receiving_bytes_v3()?.checked_mul(2)?))
            .ok_or(HostError::ResourceExhausted)?;
        let demand = ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| HostError::ResourceExhausted)?)
            // A refused primary retains both boot files while the
            // independently owed final pair opens its own two files.
            .with(D::OpenFiles, 5).with(D::MetadataEntries, 1);
        [AgentExecutionOriginalV2::monitor_receiving_demand_v5(),
            AgentDeferredCompletionOriginalV5::receiving_demand_v5(specification_bytes),
            DormantRuntimeExecutionOwnerV1::execution_currentness_demand_v2(),
            DormantRuntimeExecutionOwnerV1::execution_currentness_post_demand_v2(),
            HostArgumentAttemptOpeningV2::names_receiving_demand_v2(),
            HostArgumentAttemptOpeningV2::names_post_receiving_demand_v2()]
            .into_iter().try_fold(demand, |total, term| total.checked_add(
                term.ok_or(HostError::ResourceExhausted)?).map_err(|_| HostError::ResourceExhausted))
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    /// Borrows an inert scheduling cutoff without clock IO or effect authority.
    pub(crate) fn resident_execution_monitor_due_data_v5(&self) -> Option<u64> {
        let launch = self.launch_original.as_ref()?.lock().ok()?;
        let resident = launch.capture.as_ref()?;
        let (stage, _, _, _, _) = resident.monitor_association_v5().ok()?;
        let held = stage.lock().ok()?;
        held.accepted.as_ref()?.monitor_due_data_v5()
    }

    /// Keeps the same original unresolved when its live Agent is unavailable.
    pub(crate) fn retain_resident_monitor_unavailable_v5(&mut self) {
        if let Some(launch) = self.launch_original.as_ref().and_then(|launch| launch.lock().ok()) {
            if let Some(resident) = launch.capture.as_ref() {
                resident.retain_monitor_unknown_v5();
            }
        }
    }

    /// Drives one actual paid Observe child from the same occupied resident.
    ///
    /// # Errors
    /// Retains native/financial/clock/Agent failures and leaves the original
    /// unresolved on any refusal, cancellation or ambiguous durable commit.
    pub(crate) async fn monitor_resident_execution_once_v5(
        &mut self, agent: &mut HostAgentLiveSessionV1,
    ) -> Result<()> {
        let (stage, accept, observe, unknown, execution, launch_binding) = {
            let launch = self.launch_original.as_ref().ok_or_else(refused)?
                .lock().map_err(|_| refused())?;
            if !launch.authenticated_sent || launch.first.is_some()
                || launch.agent_binding != Some(agent.session_binding())
            { return Err(refused()); }
            let (stage, accept, observe, unknown, execution) = launch.capture.as_ref()
                .ok_or_else(refused)?.monitor_association_v5()?;
            (stage, accept, observe, unknown, execution, crate::plan::HostExecutionRequestBindingV2 {
                id: launch.request.0, session: launch.request.1, signed: launch.request.2 })
        };
        if self.resident_capture_terminal_due_data_v3()? {
            return self.finish_resident_capture_terminal_v3(agent).await;
        }
        let mut failure_guard = MonitorFailureGuardV5 { unknown: std::sync::Arc::clone(&unknown), positive: false };
        let component = self.component_control.as_ref().ok_or_else(refused)?;
        let mut component = component.lock().map_err(|_| refused())?;
        let mut held = stage.lock().map_err(|_| refused())?;
        let ArgumentStageOriginalV2 { owner, argument, accepted, .. } = &mut *held;
        let owner = owner.as_mut().ok_or_else(refused)?;
        let argument = argument.as_mut().ok_or_else(refused)?;
        let (first_observe, specification_bytes, ongoing, destination, last) = accepted.as_mut()
            .ok_or_else(refused)?.monitor_parts_v5()?;
        let (permission, clock) = ongoing.borrow_monitor_v5(&stage, accept)?;
        if permission.lifetime_v5().execution_v2() != execution { return Err(refused()); }
        let (native_demand, maximum) = component.execution_monitor_native_demand_v5()?;
        let fixed = HostExecutionMonitorOriginalV5::fixed_demand(specification_bytes)?
            .checked_add(native_demand).map_err(|_| HostError::ResourceExhausted)?;
        let token = component.prepare_execution_monitor_receiving_v5(launch_binding,
            accept, observe, permission.source_digest_v5(), execution, fixed)?;
        *destination = Some(Box::new(HostExecutionMonitorOriginalV5::new(token)));
        let original = destination.as_mut().ok_or_else(refused)?;
        original.forecast = Some(owner.execution_monitor_receiving_demand_v5(specification_bytes)
            .map_err(Into::into));
        if original.forecast.as_ref().is_some_and(std::result::Result::is_err) {
            original.first.get_or_insert(MonitorFailureSiteV5::Forecast);
        }
        let forecast = original.forecast.as_ref().and_then(|result| result.as_ref().ok()).copied();
        original.extension = Some(match forecast {
            Some(forecast) => fixed.checked_add(forecast).map_err(|_| HostError::ResourceExhausted)
                .and_then(|complete| component.extend_execution_monitor_receiving_v5(
                    &original.reservation, complete)),
            None => Err(refused()),
        });
        if !matches!(original.extension, Some(Ok(()))) {
            original.first.get_or_insert(MonitorFailureSiteV5::Extension);
            unknown.store(true, Ordering::Release);
            return Err(refused());
        }
        let preparation = (|| -> Result<(ExecutionMonitorLineageDataV5, Instant)> {
            let instant_origin = Instant::now();
            let sample = original.bookends.sample(clock, &permission).map_err(|cause| {
                original.first.get_or_insert(MonitorFailureSiteV5::Clock); cause
            })?;
            original.deadline = Some((|| {
                let remaining = permission.deadline_v5().checked_sub(sample.boottime_nanoseconds())
                    .ok_or_else(refused)?;
                instant_origin.checked_add(Duration::from_nanos(remaining))
                    .ok_or(HostError::ResourceExhausted)
            })());
            let deadline = match original.deadline.as_ref() {
                Some(Ok(deadline)) => *deadline,
                _ => { original.first.get_or_insert(MonitorFailureSiteV5::Deadline); return Err(refused()); }
            };
            original.lineage = Some((|| {
                let claim = owner.claim()?;
                permission.require_claim_binding_v5(&claim)?;
                if let Some(previous) = last.as_ref() {
                    if claim.load_effect(previous.lineage.operation_v5().as_bytes())?.as_ref()
                        != Some(&previous.effect)
                    { return Err(refused().into()); }
                }
                let sequence = claim.next_effect_sequence()?;
                let lineage = ExecutionMonitorLineageDataV5::from_original_source_data_v5(
                    permission.lifetime_v5().original_create_operation_v2(), execution,
                    permission.source_digest_v5(), claim.currentness().runtime().handle(),
                    sequence, first_observe)?;
                if claim.load_effect(lineage.operation_v5().as_bytes())?.is_some() {
                    return Err(refused().into());
                }
                Ok(lineage)
            })());
            let lineage = match original.lineage.as_ref().and_then(|result| result.as_ref().ok()).copied() {
                Some(lineage) => lineage,
                None => { original.first.get_or_insert(MonitorFailureSiteV5::Lineage); return Err(refused()); }
            };
            Ok((lineage, deadline))
        })();
        let (lineage, deadline) = match preparation {
            Ok(prepared) => prepared,
            Err(_) => {
                let _ = original.bookends.finish_entered_clock_post_v3(clock,
                    |sample| permission.require_clock_v5(sample));
                unknown.store(true, Ordering::Release);
                return Err(refused());
            }
        };
        let mut receiving = match component.begin_execution_monitor_receiving_v5(
            &original.reservation, lineage.sequence_v5().get(), maximum) {
            Ok(receiving) => receiving,
            Err(cause) => { original.entry = Some(Err(cause));
                original.first.get_or_insert(MonitorFailureSiteV5::Entry);
                let _ = original.bookends.finish_entered_clock_post_v3(clock,
                    |sample| permission.require_clock_v5(sample));
                return Err(refused()); }
        };
        original.entry = Some(Ok(()));
        original.bookends.before = Some(receiving.observe_before_v2().await);
        if !matches!(original.bookends.before, Some(Ok(()))) {
            original.first.get_or_insert(MonitorFailureSiteV5::Before);
        }
        let entry = if matches!(original.bookends.before, Some(Ok(()))) {
            original.bookends.sample(clock, &permission).map(|_| ())
        } else { Err(refused()) };
        if entry.is_err() && matches!(original.bookends.before, Some(Ok(()))) {
            original.first.get_or_insert(MonitorFailureSiteV5::Clock);
        }
        if entry.is_ok() {
            let _ = owner.observe_execution_names_v2(&mut original.bookends.names[0],
                &mut original.bookends.name_results[0]);
            original.bookends.argument_results[0] = Some(argument.observe_names_before_v2(
                &mut original.bookends.argument_names[0]));
            if !original.bookends.name_results[0].iter().all(|result| matches!(result, Some(Ok(())))) {
                original.first.get_or_insert(MonitorFailureSiteV5::NamesBefore);
            } else if !matches!(original.bookends.argument_results[0], Some(Ok(()))) {
                original.first.get_or_insert(MonitorFailureSiteV5::ArgumentBefore);
            }
            original.primary = Some((|| {
                if !original.bookends.name_results[0].iter().all(|result| matches!(result, Some(Ok(()))))
                    || !matches!(original.bookends.argument_results[0], Some(Ok(())))
                { return Err(refused().into()); }
                let mut claim = owner.claim()?;
                let request = HostExecutionMonitorRequestV5 { permission: &permission, lineage };
                let bookends = &mut original.bookends;
                let mut before_write = || bookends.sample(clock, &permission).map(|_| ())
                    .map_err(|_| HostAgentLiveErrorV1::RecoveryRequired);
                execution_effect::execute_monitored_effect_v5(&request, &mut claim, agent,
                    permission.deadline_v5(), deadline, &mut original.guest,
                    &mut original.deferred, &mut before_write).map_err(Into::into)
            })());
        }
        if original.primary.as_ref().is_some_and(std::result::Result::is_err) {
            original.primary_native_append = owner.execution_monitor_append_failure_v5().is_some();
            original.first.get_or_insert(MonitorFailureSiteV5::Primary);
        }
        // All entered primaries owe independent native/name/PID1 posts even
        // after the semantic result, append or original payer becomes unhealthy.
        let _ = owner.observe_execution_names_post_v2(&mut original.bookends.names[1],
            &mut original.bookends.name_results[1]);
        original.bookends.argument_results[1] = Some(argument.observe_names_post_v2(
            &mut original.bookends.argument_names[1]));
        if !original.bookends.name_results[1].iter().all(|result| matches!(result, Some(Ok(())))) {
            original.first.get_or_insert(MonitorFailureSiteV5::NamesAfter);
        } else if !matches!(original.bookends.argument_results[1], Some(Ok(()))) {
            original.first.get_or_insert(MonitorFailureSiteV5::ArgumentAfter);
        }
        original.bookends.after = Some(receiving.observe_after_v2().await);
        if !matches!(original.bookends.after, Some(Ok(()))) {
            original.first.get_or_insert(MonitorFailureSiteV5::After);
        }
        original.bookends.native = Some(receiving.finish_native_v2());
        if !matches!(original.bookends.native, Some(Ok(()))) {
            original.first.get_or_insert(MonitorFailureSiteV5::Native);
        }
        original.bookends.final_sample = original.bookends.sample_post_v3(clock, &permission).ok();
        if original.bookends.final_sample.is_none() {
            original.first.get_or_insert(MonitorFailureSiteV5::Clock);
        }
        if original.primary.as_ref().is_some_and(std::result::Result::is_ok)
            && matches!(original.bookends.native, Some(Ok(())))
        {
            original.final_result = Some((|| {
                let mut claim = owner.claim()?;
                original.bookends.require_positive(&permission)?;
                let issued = original.primary.as_ref().and_then(|result| result.as_ref().ok())
                    .ok_or_else(refused)?;
                let request = HostExecutionMonitorRequestV5 { permission: &permission, lineage };
                let posts = ExecutionMonitorPostsPositiveV5 { bookends: &original.bookends,
                    native: &receiving, request: &request, issued };
                let complete = agent.finish_deferred_monitor_completion_v5(
                    &mut claim, &mut original.deferred, &posts)?;
                original.terminal_native = super::super::accepted_execution::terminal_disposal::
                    HostGuestTerminalNativeV3::observe_actual_claim_v3(&claim, &complete)?;
                Ok(complete)
            })());
        }
        if original.final_result.as_ref().is_some_and(std::result::Result::is_err) {
            original.final_native_append = owner.execution_monitor_append_failure_v5().is_some();
            original.first.get_or_insert(MonitorFailureSiteV5::Final);
        }
        let complete = original.final_result.as_ref().and_then(|result| result.as_ref().ok());
        if complete.is_none() {
            unknown.store(true, Ordering::Release);
            return Err(refused());
        }
        let complete = complete.ok_or_else(refused)?;
        original.terminal = Some(match complete.completion() {
            Some(completion) => aos_sandbox_protocol::execution_evidence::completion_observes_terminal_execution(
                complete, completion),
            None => return Err(refused()),
        });
        let terminal = match original.terminal.as_ref().and_then(|result| result.as_ref().ok()).copied() {
            Some(terminal) => terminal,
            None => { original.first.get_or_insert(MonitorFailureSiteV5::Terminal);
                unknown.store(true, Ordering::Release); return Err(refused()); }
        };
        original.bookends.require_positive(&permission)?;
        receiving.require_monitor_posts_positive_v5(lineage.sequence_v5().get())?;
        if !original.guest.completed_positive_v2()
            || original.deferred.completed_v5() != Some(complete)
        { unknown.store(true, Ordering::Release); return Err(refused()); }
        let kept = aos_sandbox_model::component_receiving::without_operation_traffic_v1(
            fixed.checked_add(forecast.ok_or_else(refused)?)
                .map_err(|_| HostError::ResourceExhausted)?)
            // All interval-owned FDs close below. Keep its entire byte and
            // namespace invoice conservatively resident; there is no memory
            // credit from merely clearing raw buffers or copying a vector.
            .with(D::OpenFiles, 0);
        let completed = MonitorCompletedDataV5 { lineage, effect: complete.clone(), terminal,
            terminal_native: original.terminal_native.take(),
            next_due: original.bookends.final_sample.ok_or_else(refused)?
                .boottime_nanoseconds().checked_add(MONITOR_PERIOD_NANOSECONDS_V5)
                .ok_or(HostError::ResourceExhausted)?.min(permission.deadline_v5()) };
        // No native reference escapes: all results are owned, typed DATA.
        // Actual send guards are retired, both independent name scopes and
        // clock leaves are positive, and the same committed child is retained.
        for names in original.bookends.names.iter_mut().flatten() {
            names.settle_positive_once_v1();
        }
        for names in &mut original.bookends.argument_names { names.settle_positive_once_v1(); }
        let identity = original.reservation.duplicate_disposal_identity_v5();
        *last = Some(completed);
        drop(destination.take());
        let disposed = ExecutionMonitorStorageDisposedV5 { identity,
            ordinal: lineage.sequence_v5().get(), kept };
        receiving.finish_monitor_storage_disposal_v5(&disposed)?;
        failure_guard.positive = true;
        Ok(())
    }
}

// Constructed only after the actual parked original was positively checked
// and physically dropped above. It concerns resource storage alone; it grants
// no execution, scope extension, native sample or new financial operation.
/// Keeps the same resource identity after actual positive physical disposal.
pub(crate) struct ExecutionMonitorStorageDisposedV5 {
    pub(super) identity: ExecutionMonitorReservationV5,
    pub(super) ordinal: u64,
    pub(super) kept: ResourceVector,
}
impl ExecutionMonitorStorageDisposedV5 {
    pub(crate) fn require_ordinal_v5(&self, ordinal: u64)
        -> Result<(&ExecutionMonitorReservationV5, ResourceVector)> {
        if self.ordinal != ordinal { return Err(refused()); }
        Ok((&self.identity, self.kept))
    }
}

fn refused() -> HostError { HostError::Fence("same-original execution monitor is unresolved") }


#[cfg(test)]
mod clock_post_tests {
    use super::*;

    #[test]
    fn independent_post_enters_after_unaccepted_primary_contract_refusal() {
        let boot = aos_sandbox_linux::boot::KernelBootId::current().unwrap().into_bytes();
        let mut clock = ArgumentClockV2::capture(boot);
        let mut bookends = MonitorBookendsV5::<5>::new();

        assert!(bookends.sample_clock_contract_v3(&mut clock, |_| {
            Err(HostError::Fence("primary contract fixture"))
        }).is_err());
        bookends.finish_entered_clock_post_v3(&mut clock, |_| Ok(())).unwrap();
        let post = bookends.final_sample.unwrap();

        assert_eq!(post.host_boot_id(), boot);
        assert!(matches!(bookends.post_result, Some(Ok(actual)) if actual == post));
        assert!(matches!(bookends.samples[0], Some(Err(MonitorErrorV5::Host(
            HostError::Fence("primary contract fixture"))))));
        assert_eq!(bookends.clock_first, Some(0));
        assert!(bookends.clock_failure_v3().is_some());
        assert!(bookends.sample_clock_contract_v3(&mut clock, |_| Ok(())).is_err());
        assert!(bookends.sample_post_clock_contract_v3(&mut clock, |_| Ok(())).is_err());
    }

    #[test]
    fn independent_post_retains_its_own_boot_refusal_without_replacing_primary() {
        let mut clock = ArgumentClockV2::capture([0; 16]);
        let mut bookends = MonitorBookendsV5::<5>::new();

        assert!(bookends.sample_clock_contract_v3(&mut clock, |_| Ok(())).is_err());
        assert!(bookends.finish_entered_clock_post_v3(&mut clock, |_| Ok(())).is_err());

        assert!(matches!(bookends.samples[0], Some(Err(_))));
        assert!(matches!(bookends.post_result, Some(Err(_))));
        assert_eq!(bookends.clock_first, Some(0));
        assert!(bookends.clock_failure_v3().is_some());
    }
}
