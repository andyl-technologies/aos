//! Completes a fresh signed composite Stop on its actual resident Launch.
//!
//! The existing finite reducer and SDK engines perform every observation and
//! effect. This owner retains the old runtime pins and channel association
//! through native terminal checks, independent posts and authenticated Sent.
//! An Absent response alone never releases the old operation or namespaces.

use std::sync::{Arc, Mutex};

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::SeqpacketShutdownOriginalV4;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;

use super::launch_handoff::{HostLaunchOriginalV2, LaunchFirstV2};
use super::{HostBroker, RetainedRuntimePins, ValidatedRuntimeApplyResponse};
use crate::live_agent::HostAgentLiveSessionV1;
use crate::plan::{HostCatalog, HostExecutionReceivingLoanV2};
use crate::state::HostStateStore;
use crate::worker::{HostRuntimeIdentity, HostWorker, PinnedLeader};
use crate::{HostError, Result};

mod unsent_disposal;

#[derive(Clone, Copy)]
enum StopDisposalPurposeV1 {
    Authenticated,
    UnsentNativePositive,
}

/// Holds the namespace positively disposed by the same live resident Stop.
///
/// Live construction follows the actual owning drops and same Stop token.
/// Restart reconciliation retains its distinct native inventory original; no
/// DATA or historical row can construct this resident witness.
pub(crate) struct HostStoppedNamespaceOriginalV4 {
    scope: aos_sandbox_protocol::host_stopped_namespace::HostStoppedNamespaceDataV4,
}

impl HostStoppedNamespaceOriginalV4 {
    pub(crate) fn scope_v4(
        &self,
    ) -> &aos_sandbox_protocol::host_stopped_namespace::HostStoppedNamespaceDataV4 {
        &self.scope
    }

    fn receiving_bytes_v4() -> Option<usize> {
        // The retained broker slot and the pre-drop passive scope carrier coexist.
        std::mem::size_of::<Self>().checked_mul(3)
    }
}

type Native<T> = aos_sandbox_linux::Result<T>;
type RequestIdentity = ([u8; 16], [u8; 32], [u8; 32]);
// Two exact alias-close gates, entry/shutdown/open/send and pre-CAS, plus a separate
// independently owed final sampler. No ordinary16 or SDK22 slot is reused.
const CAPTURE_STOP_CLOCKS: usize = aos_sandbox_linux::seqpacket::capture_stop::CAPTURE_WRITER_ALIAS_COUNT_V4 + 5;
type CaptureStopBookendsV4 = super::launch_handoff::execution_monitor::MonitorBookendsV5<CAPTURE_STOP_CLOCKS>;

#[derive(Clone, Copy)]
enum CaptureStopFirstV4 { Clock, Native, Commit }


pub(super) struct HostResidentStopOriginalV4 {
    pub(super) stage: Arc<Mutex<HostLaunchOriginalV2>>,
    pub(super) source_launch: RequestIdentity,
    pub(super) runtime: HostRuntimeIdentity,
    pub(super) agent_binding: aos_sandbox_agent::AgentSessionBindingV1,
    supervisor_dead: Option<Native<bool>>,
    payload_dead: Option<Native<bool>>,
    observed_dead: Option<Native<bool>>,
    channel: SeqpacketShutdownOriginalV4,
    channel_result: Option<std::result::Result<bool, aos_sandbox_linux::seqpacket::SeqpacketError>>,
    pub(super) retained_agent: Option<HostAgentLiveSessionV1>,
    pub(super) authenticated_sent: bool,
    terminal_entered: bool,
    lineage: Option<Result<crate::state::GuardianLineage>>,
    namespace_scope_v4: Option<std::result::Result<
        aos_sandbox_protocol::host_stopped_namespace::HostStoppedNamespaceDataV4,
        aos_sandbox_protocol::ProtocolValidationError>>,
    native_completed: Option<HostResidentStopNativeCompletedV4>,
    pub(super) sdk_terminal: Option<Result<()>>,
    capture_stage: Option<Arc<Mutex<super::argument_handoff::ArgumentStageOriginalV2>>>,
    capture_failed: Option<super::HostCaptureFailedStageV4>,
    capture_bookends: Option<Box<CaptureStopBookendsV4>>,
    capture_terminal: Option<super::guardian_transaction::CompositeStopTerminalOriginalV4>,
    capture_result: Option<Result<()>>,
    capture_commit: Option<Result<Vec<u8>>>,
    capture_post: Option<Result<()>>,
    capture_first: Option<CaptureStopFirstV4>,
    pub(super) disposal_error: Option<HostError>,
    unsent_disposal: Option<unsent_disposal::UnsentStopDisposalOriginalV1>,
}

pub(crate) struct HostResidentStopNativeCompletedV4 {
    worker: std::sync::Weak<tokio::sync::Mutex<crate::worker::launch::HostLaunchWorkerOriginalV2>>,
    request: RequestIdentity,
}

impl HostResidentStopNativeCompletedV4 {
    pub(crate) fn request_identity_v4(&self) -> RequestIdentity {
        self.request
    }

    pub(crate) fn matches_worker_v4(
        &self,
        worker: &Arc<tokio::sync::Mutex<crate::worker::launch::HostLaunchWorkerOriginalV2>>,
        request: RequestIdentity,
    ) -> bool {
        self.request == request
            && self.worker.upgrade().is_some_and(|actual| Arc::ptr_eq(&actual, worker))
    }
}

impl HostResidentStopOriginalV4 {
    pub(super) fn new(
        stage: Arc<Mutex<HostLaunchOriginalV2>>,
        source_launch: RequestIdentity,
        runtime: HostRuntimeIdentity,
        agent_binding: aos_sandbox_agent::AgentSessionBindingV1,
    ) -> Self {
        Self {
            stage,
            source_launch,
            runtime,
            agent_binding,
            supervisor_dead: None,
            payload_dead: None,
            observed_dead: None,
            channel: SeqpacketShutdownOriginalV4::new(),
            channel_result: None,
            retained_agent: None,
            authenticated_sent: false,
            terminal_entered: false,
            lineage: None, namespace_scope_v4: None,
            native_completed: None,
            sdk_terminal: None,
            capture_stage: None, capture_failed: None, capture_bookends: None,
            capture_terminal: None, capture_result: None, capture_commit: None,
            capture_post: None, capture_first: None,
            disposal_error: None,
            unsent_disposal: None,
        }
    }

    pub(super) fn receiving_demand_v4() -> Option<ResourceVector> {
        let poll = SeqpacketShutdownOriginalV4::receiving_obligations_v4()?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(4 * std::mem::size_of::<usize>())?
            .checked_add(poll.0)?
            .checked_add(HostStoppedNamespaceOriginalV4::receiving_bytes_v4()?)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?))
    }

    // These independent observations are all prearmed before any sample. Each
    // real pidfd's death and exact channel hangup are monotone. Even an earlier
    // failed sample cannot suppress a later independently owed observation.
    fn capture_cleanup_demand_v4() -> Option<ResourceVector> {
        let carriers = std::mem::size_of::<CaptureStopBookendsV4>().checked_mul(2)?;
        let clock_and_names = super::launch_handoff::execution_query::execution_preparation_fixed_demand_v5(
            carriers, 0, 0,
        ).ok()?;
        clock_and_names.checked_add(
            crate::storage_existing_output::capture::StorageCaptureOriginalV2::stop_receiving_demand_v4()?,
        ).ok()
    }

    pub(super) fn observe_terminal_once_v4(
        &mut self,
        pins: &RetainedRuntimePins,
        observed: &PinnedLeader,
        agent: &HostAgentLiveSessionV1,
    ) -> Result<()> {
        if self.terminal_entered
            || agent.session_binding() != self.agent_binding
            || pins.supervisor.handle() != observed.handle()
        {
            return Err(HostError::Fence("Stop terminal originals differ or already entered"));
        }
        self.terminal_entered = true;
        self.supervisor_dead = Some(pins.supervisor.pidfd().is_alive().map(|alive| !alive));
        self.payload_dead = Some(pins.payload.pidfd().is_alive().map(|alive| !alive));
        self.observed_dead = Some(observed.pidfd().is_alive().map(|alive| !alive));
        agent.observe_stop_channel_once_v4(&mut self.channel,
            &mut self.channel_result);
        self.require_terminal_positive_v4()
    }

    pub(super) fn require_terminal_positive_v4(&self) -> Result<()> {
        if !self.terminal_entered
            || !matches!(self.supervisor_dead, Some(Ok(true)))
            || !matches!(self.payload_dead, Some(Ok(true)))
            || !matches!(self.observed_dead, Some(Ok(true)))
            || !matches!(self.channel_result, Some(Ok(true)))
        {
            return Err(HostError::Fence("Stop lacks whole real process death and channel hangup"));
        }
        Ok(())
    }

    pub(super) fn format_capture_failure_v4(
        &self,
        stage: &HostLaunchOriginalV2,
        component: &crate::plan::HostComponentControlStartupV2,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> Option<std::fmt::Result> {
        let old_stage = self.capture_stage.as_ref()?;
        match stage.first {
            Some(LaunchFirstV2::Before | LaunchFirstV2::After | LaunchFirstV2::NativeFinish) => {
                let after = !matches!(stage.first, Some(LaunchFirstV2::Before));
                if let Some(cause) = component.capture_stop_failure_v4(stage.request, after) {
                    return Some(std::fmt::Display::fmt(cause, formatter));
                }
                if let Some(CaptureStopFirstV4::Clock) = self.capture_first {
                    if let Some(cause) = self.capture_bookends.as_ref().and_then(|bookends| bookends.clock_failure_v3()) {
                        return Some(std::fmt::Display::fmt(cause, formatter));
                    }
                }
            }
            Some(LaunchFirstV2::Opening) => {
                if let Some(cause) = component.capture_stop_failure_v4(stage.request, false) {
                    return Some(std::fmt::Display::fmt(cause, formatter));
                }
            }
            Some(LaunchFirstV2::Primary) => match self.capture_first {
                Some(CaptureStopFirstV4::Clock) => {
                    if let Some(cause) = self.capture_bookends.as_ref().and_then(|bookends| bookends.clock_failure_v3()) {
                        return Some(std::fmt::Display::fmt(cause, formatter));
                    }
                }
                Some(CaptureStopFirstV4::Native) => {
                    let old = match old_stage.lock() { Ok(old) => old, Err(_) => return Some(Err(std::fmt::Error)) };
                    let accepted = match old.accepted.as_ref() { Some(accepted) => accepted, None => return Some(Err(std::fmt::Error)) };
                    let clock = self.capture_bookends.as_ref().and_then(|bookends| bookends.clock_failure_v3());
                    return Some(accepted.format_capture_stop_native_failure_v4(clock, formatter));
                }
                Some(CaptureStopFirstV4::Commit) => {
                    // The same State writer retains its actual native prefix.
                    // Existing HostStageFailureBorrow resolves that source.
                    return None;
                }
                None => {}
            },
            _ => {}
        }
        None
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.unsent_disposal.as_ref().and_then(|original| original.failure_v1())
            .or_else(|| error(&self.lineage))
            .or_else(|| error(&self.supervisor_dead))
            .or_else(|| error(&self.payload_dead))
            .or_else(|| error(&self.observed_dead))
            .or_else(|| self.channel.failure())
            .or_else(|| error(&self.channel_result))
            .or_else(|| error(&self.namespace_scope_v4))
    }

    pub(super) fn unsent_disposal_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.unsent_disposal.as_ref().and_then(|original| original.failure_v1())
    }

    pub(super) fn format_unsent_disposal_failure_v1(
        &self,
        component: &crate::plan::HostComponentControlStartupV2,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> Option<std::fmt::Result> {
        self.unsent_disposal.as_ref()?.format_failure_v1(component, formatter)
    }
}

fn error<T, E: std::error::Error + 'static>(
    value: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(super) async fn execute_composite_stop_turn_v4(
        &mut self,
        request: &aos_sandbox_protocol::ValidatedRuntimeRequest,
        request_digest: [u8; 32],
        admitted: aos_sandbox_broker::VerifiedBrokerAdmission,
        admission_clock: &aos_sandbox_core::RawPairedClockSample,
        authenticated: Option<&AuthenticatedBrokerMethodRequestV1>,
        retained_agent: Option<&HostAgentLiveSessionV1>,
        trusted_clock: &mut (impl FnMut() -> Result<aos_sandbox_core::RawPairedClockSample> + Send),
    ) -> Result<ValidatedRuntimeApplyResponse>
    where
        W: Sync,
    {
        if request.host_stop_cleanup_v1().is_some() {
            return self
                .execute_fresh_stop_cleanup_v1(
                    request,
                    request_digest,
                    admitted,
                    admission_clock,
                    authenticated,
                    retained_agent,
                )
                .await;
        }
        let request_id = *request.header().request_id();
        let selected = self.component_control.is_some();
        let source = if selected {
            let source = self.launch_original.as_ref().cloned()
                .ok_or(HostError::Fence("selected Stop has no actual resident Launch"))?;
            let failed_capture = source.lock()
                .map_err(|_| HostError::Fence("Stop source Launch is poisoned"))?
                .failed_capture_stop_stage_v4()?;
            if self.active_argument_writes.is_some()
                || self.active_launch_writes.is_some()
                || self.argument_stages.iter().flatten().any(|actual| {
                    failed_capture.as_ref().is_none_or(|(stage, _)| !Arc::ptr_eq(actual, stage))
                })
                || self.live_agent.is_some()
                || self.runtime_pins.len() != 1
                || self.observed_leaders.len() != 1
                || !self.live_limit_attempts.is_empty()
                || !self.fuse_workers.is_empty()
            {
                return Err(HostError::Fence("selected Stop has unresolved native or execution custody"));
            }
            if failed_capture.is_none() {
                self.dispose_terminal_stage_before_stop_v3(&source, &admitted)?;
            }
            let held = source.lock().map_err(|_| HostError::Fence("Stop source Launch is poisoned"))?;
            if failed_capture.is_some() { held.require_failed_capture_stop_parent_v4()?; }
            else { held.require_resident_stop_parent_v4()?; }
            let agent = retained_agent.ok_or(HostError::Fence("Stop lacks its actual Services Agent"))?;
            if held.agent_binding != Some(agent.session_binding()) {
                return Err(HostError::Fence("Stop Agent differs from the actual resident Launch"));
            }
            let (runtime, pins) = self.runtime_pins.first_key_value()
                .ok_or(HostError::Fence("Stop runtime pins are absent"))?;
            if runtime.sandbox_id() != request.fence().sandbox_id()
                || runtime.incarnation_id() != request.fence().incarnation_id()
                || !self.observed_leaders.get(runtime).is_some_and(|leader|
                    leader.handle() == pins.supervisor.handle())
            {
                return Err(HostError::Fence("Stop request differs from the actual retained runtime"));
            }
            let parent = (held.request, *runtime, agent.session_binding(), failed_capture);
            drop(held);
            Some((source, parent))
        } else {
            None
        };

        let component = if selected {
            self.component_control.as_ref().cloned()
        } else {
            None
        };
        let mut component = match component.as_ref() {
            Some(component) => Some(component.lock()
                .map_err(|_| HostError::Fence("Stop intrinsic original is poisoned"))?),
            None => None,
        };
        let mut receiving = None;
        let mut stop = None;
        if let (Some(component), Some((source, (launch, runtime, binding, failed_capture)))) =
            (component.as_mut(), source.as_ref())
        {
            let authenticated = authenticated.ok_or(HostError::Fence("Stop Session original is absent"))?;
            if let Some((stage, failed)) = failed_capture.as_ref() {
                stage.lock().map_err(|_| HostError::Fence("failed Capture Stage is poisoned"))?
                    .accepted.as_mut().ok_or(HostError::Fence("failed Capture lacks actual Accept"))?
                    .prepare_capture_stop_financial_once_v4(failed, &admitted,
                        self.component_control.as_ref().ok_or(HostError::AgentLaunchQuarantined)?, component,
                        authenticated)?;
            }
            component.require_argument_boot_v2(admission_clock.host_boot_id())?;
            let (native, maximum) = if failed_capture.is_some() {
                component.capture_stop_observation_demand_v4()?
            } else { component.recurring_observation_demand_v4()? };
            // Derive only passive source-bound geometry here. Full history
            // authentication and all proposed HostState graphs begin after
            // this SAME Stop interval has admitted their complete demand.
            let state_demand = self.state.composite_stop_receiving_demand_v4()
                .ok_or(HostError::ResourceExhausted)?;
            let mut complete = HostLaunchOriginalV2::fixed_stop_demand_v4(authenticated)
                .and_then(|fixed| fixed.checked_add(state_demand).ok())
                .and_then(|fixed| fixed.checked_add(native).ok())
                .ok_or(HostError::ResourceExhausted)?;
            if failed_capture.is_some() {
                complete = complete.checked_add(HostResidentStopOriginalV4::capture_cleanup_demand_v4()
                    .ok_or(HostError::ResourceExhausted)?).map_err(|_| HostError::ResourceExhausted)?;
            }
            let loan = if let Some((stage, failed)) = failed_capture.as_ref() {
                let mut held = stage.lock().map_err(|_| HostError::Fence("failed Capture Stage is poisoned"))?;
                let (negative, parent, entry) = held.accepted.as_mut()
                    .ok_or(HostError::Fence("failed Capture Accept is absent"))?.capture_stop_inputs_v4(authenticated)?;
                match component.begin_capture_stop_receiving_v4(failed, negative, &parent,
                    authenticated, request, &admitted, complete, maximum) {
                    Ok(loan) => { *entry = Some(Ok(())); loan }
                    Err(cause) => {
                        *entry = Some(Err(cause));
                        return Err(HostError::Fence("Capture Stop receiving entry failed; actual return retained"));
                    }
                }
            } else {
                component.begin_resident_stop_receiving_v4(
                    crate::plan::HostExecutionRequestBindingV2 { id: launch.0, session: launch.1, signed: launch.2 },
                    authenticated, request, &admitted, complete, maximum,
                )?
            };
            let stage = Arc::new(Mutex::new(HostLaunchOriginalV2::new(
                authenticated, complete, admission_clock.host_boot_id(),
                admitted.effect.effect_deadline_boottime_nanoseconds(), None,
            )));
            let original = Arc::new(Mutex::new(HostResidentStopOriginalV4::new(
                stage, *launch, *runtime, *binding,
            )));
            if let Some((stage, failed)) = failed_capture.as_ref() {
                let mut stop = original.lock().map_err(|_| HostError::Fence("Stop original is poisoned"))?;
                stop.capture_stage = Some(Arc::clone(stage));
                stop.capture_failed = Some(failed.clone());
                stop.capture_bookends = Some(Box::new(CaptureStopBookendsV4::new()));
            }
            source.lock().map_err(|_| HostError::Fence("Stop source Launch is poisoned"))?
                .resident_stop = Some(Arc::clone(&original));
            receiving = Some(loan);
            stop = Some(original);
        }
        let stage = match stop.as_ref() {
            Some(stop) => Some(stop.lock().map_err(|_| HostError::Fence("Stop original is poisoned"))?.stage.clone()),
            None => None,
        };
        let mut prepared = Ok(());
        if let (Some(stage), Some(receiving)) = (stage.as_ref(), receiving.as_mut()) {
            let before = receiving.observe_before_v2().await;
            prepared = (|| -> Result<()> {
                let capture_stage = match stop.as_ref() {
                    Some(stop) => stop.lock().map_err(|_| HostError::Fence("Stop original is poisoned"))?
                        .capture_stage.as_ref().cloned(),
                    None => None,
                };
                let mut held = stage.lock().map_err(|_| HostError::Fence("Stop stage is poisoned"))?;
                if before.is_err() {
                    held.first.get_or_insert(LaunchFirstV2::Before);
                }
                held.before = Some(before);
                let prepared = if matches!(held.before, Some(Ok(()))) {
                    match capture_stage {
                        Some(stage) => {
                            // Move the actual paid verification clock first. A
                            // binding refusal leaves it on this same Stop owner.
                            let source = source.as_ref().ok_or(HostError::AgentLaunchQuarantined)?;
                            held.clock = Some(source.0.lock()
                                .map_err(|_| HostError::Fence("Stop admission Launch is poisoned"))?
                                .take_capture_stop_admission_clock_v4(
                                    authenticated.ok_or(HostError::AgentLaunchQuarantined)?)?);
                            held.clock.as_mut().ok_or(HostError::AgentLaunchQuarantined)?
                                .bind_retained_stop_effect_v4(&admitted.effect)?;
                            held.prepare_borrowed_stop_owner_v4(stage, receiving)
                        }
                        None => {
                            held.clock = Some(super::argument_handoff::ArgumentClockV2::capture_stop_effect_v4(
                                admission_clock.host_boot_id(), &admitted.effect,
                            ));
                            held.prepare_stop_opening_v4(receiving)
                        }
                    }
                } else {
                    Err(HostError::Fence("Stop before observation failed"))
                };
                prepared?;
                let guardian = self.guardian.as_ref().ok_or(HostError::AgentLaunchQuarantined)?;
                let worker = crate::worker::launch::HostLaunchWorkerOriginalV2::reserve_resident_stop_before_native_v4(
                    receiving, &mut held.complete, authenticated.ok_or(HostError::AgentLaunchQuarantined)?, guardian,
                )?;
                held.worker = Some(worker);
                self.active_launch_writes = held.writes.clone();
                Ok(())
            })();
        }

        let clock_stage = stage.clone();
        let mut effect_clock = || match clock_stage.as_ref() {
            Some(stage) => stage.lock().map_err(|_| HostError::Fence("Stop clock stage is poisoned"))?
                .clock.as_mut().ok_or(HostError::Fence("Stop clock is absent"))?.sample(),
            None => trusted_clock(),
        };
        let capture_clock_comparison =
            aos_sandbox_broker::BrokerEffectClockComparisonV3::from_effect(&admitted.effect);
        let primary = async {
            prepared?;
            if let Some(stop) = stop.as_ref() {
                let mut original = stop.lock()
                    .map_err(|_| HostError::Fence("Stop lineage original is poisoned"))?;
                original.lineage = Some(self.state.completed_guardian_lineage(
                    original.runtime.sandbox_id(), original.runtime.incarnation_id(), &self.authority,
                ));
                if !matches!(original.lineage,
                    Some(Ok(crate::state::GuardianLineage::Complete(lineage)))
                        if lineage.source_request_id == original.source_launch.0)
                {
                    return Err(HostError::Fence("Stop does not name its actual completed Launch lineage; original retained"));
                }
            }
            let mut worker_receiving = match (stage.as_ref(), receiving.as_mut(), authenticated) {
                (Some(stage), Some(receiving), Some(authenticated)) => {
                    let clock = super::launch_handoff::write_clock::HostLaunchWriteClockV2::borrow_v2(stage, authenticated)?;
                    let (worker, deadline) = {
                        let held = stage.lock().map_err(|_| HostError::Fence("Stop worker stage is poisoned"))?;
                        (held.worker.as_ref().cloned().ok_or(HostError::AgentLaunchQuarantined)?,
                            held.worker_deadline.ok_or(HostError::AgentLaunchQuarantined)?)
                    };
                    Some(crate::worker::launch::HostLaunchWorkerReceivingV2::new(
                        receiving, authenticated, worker, deadline, clock,
                    ).await?)
                }
                (None, None, _) => None,
                _ => return Err(HostError::Fence("Stop lost its actual closed worker borrower")),
            };
            let sealed_fence = self.authority.seal_fence(request.fence().sandbox_id(), &admitted.fence)?;
            let sealed_effect = self.authority.seal_effect(&request_id, &admitted.effect)?;
            let mut proposed = self.state.clone();
            let mut execution = self.prepare_composite_stop_receiving_v4(
                request.fence(), request_id, request_digest, worker_receiving.as_mut(),
            ).await?;
            if let (Some((source, _)), Some(stop)) = (source.as_ref(), stop.as_ref()) {
                let (boot, fence, anchor, launch) = {
                    let held = source.lock().map_err(|_| HostError::Fence("Stop source Launch is poisoned"))?;
                    let (boot, fence, anchor) = held.namespace_scope_v4
                        .ok_or(HostError::Fence("Stop lacks its actual typed Launch namespace"))?;
                    (boot, fence, anchor, held.request)
                };
                let signed = authenticated.ok_or(HostError::Fence("Stop Session original is absent"))?;
                let mut original = stop.lock().map_err(|_| HostError::Fence("Stop history owner is poisoned"))?;
                original.namespace_scope_v4 = Some(
                    aos_sandbox_protocol::host_stopped_namespace::HostStoppedNamespaceDataV4::from_data_v4(
                        boot, fence, anchor, launch,
                        (signed.request_id(), signed.session_binding(), signed.signed_request_digest()),
                    ));
                let scope = original.namespace_scope_v4.as_ref().and_then(|result| result.as_ref().ok())
                    .copied().ok_or(HostError::Fence("Stop historical scope is not canonical; cause retained"))?;
                execution.bind_resident_namespace_history_v6(scope)?;
            }
            let admission = proposed.admit_composite_stop(
                request.fence(), request_id, request_digest, execution,
                sealed_fence, &admitted, sealed_effect, &self.authority,
            )?;
            super::ensure_pending_runtime_admission(admission)?;
            self.commit_state(&proposed)?;
            if let Some(stage) = stage.as_ref() {
                let mut held = stage.lock().map_err(|_| HostError::Fence("Stop lease stage is poisoned"))?;
                held.lease = Some(admitted.verified_lease);
                held.intersection = Some(admitted.intersection);
            }
            let negative_capture = stop.as_ref().is_some_and(|stop| stop.lock()
                .is_ok_and(|stop| stop.capture_stage.is_some()));
            let mut terminal = None;
            let advanced = if negative_capture {
                self.advance_composite_stop_to_terminal_v5(
                    request.fence(), request_id, request_digest, &admitted.effect,
                    request.header().maximum_response_bytes(), &mut effect_clock,
                    worker_receiving.as_mut(), &mut terminal,
                ).await
            } else {
                self.advance_composite_stop_receiving_v4(
                    request.fence(), request_id, request_digest, &admitted.effect,
                    request.header().maximum_response_bytes(), &mut effect_clock,
                    worker_receiving.as_mut(),
                ).await
            };
            if let Some(terminal) = terminal {
                stop.as_ref().ok_or(HostError::AgentLaunchQuarantined)?.lock()
                    .map_err(|_| HostError::Fence("Stop original is poisoned"))?.capture_terminal = Some(terminal);
            }
            let mut body = advanced?;
            drop(worker_receiving);
            if let Some(stop) = stop.as_ref() {
                let mut original = stop.lock().map_err(|_| HostError::Fence("Stop terminal original is poisoned"))?;
                let pins = self.runtime_pins.get(&original.runtime)
                    .ok_or(HostError::Fence("Stop lost its actual runtime pins"))?;
                let observed = self.observed_leaders.get(&original.runtime)
                    .ok_or(HostError::Fence("Stop lost its actual observed leader"))?;
                original.observe_terminal_once_v4(pins, observed,
                    retained_agent.ok_or(HostError::Fence("Stop actual Agent is absent"))?)?;
                let stage = original.stage.lock()
                    .map_err(|_| HostError::Fence("Stop terminal stage is poisoned"))?;
                let worker = stage.worker.as_ref().cloned().ok_or(HostError::AgentLaunchQuarantined)?;
                let proof = HostResidentStopNativeCompletedV4 {
                    worker: Arc::downgrade(&worker), request: stage.request,
                };
                drop(stage);
                original.native_completed = Some(proof);
            }
            if let Some(stop) = stop.as_ref() {
                let (worker, proof) = {
                    let original = stop.lock().map_err(|_| HostError::Fence("Stop terminal original is poisoned"))?;
                    let stage = original.stage.lock().map_err(|_| HostError::Fence("Stop terminal stage is poisoned"))?;
                    let worker = stage.worker.as_ref().cloned().ok_or(HostError::AgentLaunchQuarantined)?;
                    let proof = original.native_completed.as_ref()
                        .ok_or(HostError::Fence("Stop native completion proof is absent"))?;
                    (worker, HostResidentStopNativeCompletedV4 {
                        worker: proof.worker.clone(), request: proof.request,
                    })
                };
                let result = crate::worker::launch::HostLaunchWorkerOriginalV2::finish_resident_stop_sdk_v4(
                    &worker, &proof,
                ).await;
                let mut original = stop.lock().map_err(|_| HostError::Fence("Stop terminal original is poisoned"))?;
                original.sdk_terminal = Some(result);
                if !matches!(original.sdk_terminal, Some(Ok(()))) {
                    return Err(HostError::Fence("Stop SDK native termination failed; original retained"));
                }
            }
            if negative_capture {
                let stop = stop.as_ref().ok_or(HostError::AgentLaunchQuarantined)?;
                let mut original = stop.lock().map_err(|_| HostError::Fence("Stop original is poisoned"))?;
                let old_stage = original.capture_stage.as_ref().cloned().ok_or(HostError::AgentLaunchQuarantined)?;
                let failed = original.capture_failed.as_ref().cloned().ok_or(HostError::AgentLaunchQuarantined)?;
                let stage = original.stage.clone();
                let mut current_stage = stage.lock().map_err(|_| HostError::Fence("Stop clock Stage is poisoned"))?;
                let mut old = old_stage.lock().map_err(|_| HostError::Fence("failed Capture Stage is poisoned"))?;
                let storage = old.accepted.as_mut().ok_or(HostError::AgentLaunchQuarantined)?
                    .capture_for_stop_v4()?;
                let worker = current_stage.worker.as_ref().cloned().ok_or(HostError::AgentLaunchQuarantined)?;
                let clock = current_stage.clock.as_mut().ok_or(HostError::AgentLaunchQuarantined)?;
                let comparison = &capture_clock_comparison;
                original.capture_first = Some(CaptureStopFirstV4::Clock);
                {
                    let bookends = original.capture_bookends.as_mut().ok_or(HostError::AgentLaunchQuarantined)?;
                    bookends.sample_clock_contract_v3(clock, |sample| { comparison.require_fresh(sample)?; Ok(()) })?;
                }
                original.capture_first = Some(CaptureStopFirstV4::Native);
                let proof = original.native_completed.as_ref().ok_or(HostError::AgentLaunchQuarantined)?;
                let proof = HostResidentStopNativeCompletedV4 { worker: proof.worker.clone(), request: proof.request };
                let runtime = aos_sandbox_core::ObjectDigest::from_bytes(super::runtime_handle(&original.runtime));
                let cleanup = {
                    let bookends = original.capture_bookends.as_mut().ok_or(HostError::AgentLaunchQuarantined)?;
                    let mut current = || bookends.sample_clock_contract_v3(clock,
                        |sample| { comparison.require_fresh(sample)?; Ok(()) }).map(|_| ());
                    storage.stop_contained_once_v4(&failed, &proof, &worker,
                        receiving.as_ref().ok_or(HostError::AgentLaunchQuarantined)?,
                        authenticated.ok_or(HostError::AgentLaunchQuarantined)?, &admitted.effect,
                        runtime, &mut current)
                };
                original.capture_result = Some(cleanup);
                if !matches!(original.capture_result, Some(Ok(()))) {
                    return Err(HostError::Fence("Capture Stop cleanup failed; every original remains held"));
                }
                original.capture_first = Some(CaptureStopFirstV4::Clock);
                original.capture_bookends.as_mut().ok_or(HostError::AgentLaunchQuarantined)?
                    .sample_clock_contract_v3(clock, |sample| { comparison.require_fresh(sample)?; Ok(()) })?;
                original.capture_first = Some(CaptureStopFirstV4::Commit);
                let committed = self.commit_capture_stop_terminal_v4(
                    original.capture_terminal.as_mut().ok_or(HostError::AgentLaunchQuarantined)?,
                    &admitted.effect, storage,
                );
                original.capture_commit = Some(committed);
                body = original.capture_commit.as_ref().and_then(|result| result.as_ref().ok())
                    .cloned().ok_or(HostError::Fence("Capture Stop terminal CAS failed; original retained"))?;
                original.capture_first = None;
            }
            Ok(ValidatedRuntimeApplyResponse {
                request_id, maximum_response_bytes: request.header().maximum_response_bytes(), body,
            })
        }.await;
        self.active_launch_writes = None;
        let Some(stage) = stage else { return primary; };
        {
            let mut held = stage.lock().map_err(|_| HostError::Fence("Stop stage is poisoned"))?;
            if primary.is_err() {
                held.first.get_or_insert(LaunchFirstV2::Primary);
            }
            held.primary = Some(primary);
            if held.has_stop_journal_owner_v4() {
                let _ = held.observe_names_once_v2(1);
            }
        }
        let active = receiving.as_mut().ok_or(HostError::Fence("Stop original loan is absent"))?;
        let after = active.observe_after_v2().await;
        if let Some(stop) = stop.as_ref() {
            let mut original = stop.lock().map_err(|_| HostError::Fence("Stop original is poisoned"))?;
            if original.capture_bookends.as_ref().is_some_and(|bookends| bookends.has_entered_clock_v4()) {
                let mut held = stage.lock().map_err(|_| HostError::Fence("Stop clock Stage is poisoned"))?;
                let clock = held.clock.as_mut().ok_or(HostError::AgentLaunchQuarantined)?;
                let comparison = &capture_clock_comparison;
                let post = original.capture_bookends.as_mut()
                    .ok_or(HostError::AgentLaunchQuarantined)?.finish_entered_clock_post_v3(clock,
                        |sample| { comparison.require_fresh(sample)?; Ok(()) });
                original.capture_post = Some(post);
                if !matches!(original.capture_post, Some(Ok(()))) {
                    original.capture_first.get_or_insert(CaptureStopFirstV4::Clock);
                    held.first.get_or_insert(LaunchFirstV2::After);
                }
            }
        }
        let mut held = stage.lock().map_err(|_| HostError::Fence("Stop stage is poisoned"))?;
        if after.is_err() {
            held.first.get_or_insert(LaunchFirstV2::After);
        }
        held.after = Some(after);
        if held.first.is_some() || !matches!(held.primary, Some(Ok(_))) {
            return Err(HostError::Fence("Stop failed; actual native originals remain resident"));
        }
        held.native_finish = Some(active.finish_native_v2());
        if !matches!(held.native_finish, Some(Ok(()))) {
            held.first.get_or_insert(LaunchFirstV2::NativeFinish);
            return Err(HostError::Fence("Stop native completion failed; actual custody remains"));
        }
        let Some(Ok(response)) = held.primary.take() else {
            std::process::abort();
        };
        drop(held);
        receiving.take().ok_or(HostError::Fence("Stop original loan disappeared"))?
            .retain_pending_authenticated_v2()?;
        Ok(response)
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(super) fn retain_authenticated_stop_response_v4(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<bool> {
        use sha2::{Digest as _, Sha256};
        let Some(source) = self.launch_original.as_ref() else { return Ok(false); };
        let source = source.lock().map_err(|_| HostError::Fence("Stop source Launch is poisoned"))?;
        let Some(stop) = source.resident_stop.as_ref() else { return Ok(false); };
        let mut stop = stop.lock().map_err(|_| HostError::Fence("Stop original is poisoned"))?;
        let stage = stop.stage.lock().map_err(|_| HostError::Fence("Stop stage is poisoned"))?;
        if stage.request.0 != request.request_id() { return Ok(false); }
        stage.require_same_request(request)?;
        let effect = self.state.effect(&request.request_id())
            .ok_or(HostError::Fence("Stop Sent lacks its durable effect"))?;
        let effect = self.authority.open_effect(&request.request_id(), effect)?;
        let digest: [u8; 32] = Sha256::digest(request.exact_body()).into();
        if effect.status() != aos_sandbox_broker::BrokerEffectStatusV1::Complete
            || effect.transport_request_digest().as_bytes() != &digest
            || stop.authenticated_sent || stage.first.is_some() || stage.primary.is_some()
            || !matches!(stage.before, Some(Ok(()))) || !matches!(stage.after, Some(Ok(())))
            || !matches!(stage.native_finish, Some(Ok(())))
            || !matches!(stop.sdk_terminal, Some(Ok(()))) || stop.native_completed.is_none()
        {
            return Err(HostError::Fence("Stop Sent cannot finalize incomplete native custody"));
        }
        stop.require_terminal_positive_v4()?;
        drop(stage);
        stop.authenticated_sent = true;
        Ok(true)
    }

    pub(crate) fn retire_authenticated_stopped_agent_v4(
        &mut self,
        incoming: &mut Option<HostAgentLiveSessionV1>,
    ) -> Result<bool> {
        if self.retire_authenticated_live_cleanup_agent_v1(incoming)? {
            return Ok(true);
        }
        self.retire_stopped_agent_with_failure_v1(incoming, StopDisposalPurposeV1::Authenticated)
    }

    fn retire_stopped_agent_with_failure_v1(
        &mut self,
        incoming: &mut Option<HostAgentLiveSessionV1>,
        purpose: StopDisposalPurposeV1,
    ) -> Result<bool> {
        let returned = self.retire_stopped_agent_inner_v1(incoming, purpose);
        let Err(cause) = returned else {
            return returned;
        };
        // A refused owning handoff keeps both the actual Agent and the exact
        // returned refusal on the same Stop, rather than losing the cause when
        // Services projects its transport error.
        if let Some(source) = self.launch_original.as_ref() {
            if let Ok(source) = source.lock() {
                if let Some(stop) = source.resident_stop.as_ref() {
                    if let Ok(mut stop) = stop.lock() {
                        if stop.disposal_error.is_none() {
                            stop.disposal_error = Some(cause);
                            return Err(HostError::Fence("Stop owning disposal failed; original cause retained"));
                        }
                    }
                }
            }
        }
        Err(cause)
    }

    fn retire_stopped_agent_inner_v1(
        &mut self,
        incoming: &mut Option<HostAgentLiveSessionV1>,
        purpose: StopDisposalPurposeV1,
    ) -> Result<bool> {
        let Some(source) = self.launch_original.as_ref().cloned() else { return Ok(false); };
        let stop = {
            let held = source.lock().map_err(|_| HostError::Fence("Stop source Launch is poisoned"))?;
            let Some(stop) = held.resident_stop.as_ref().cloned() else { return Ok(false); };
            stop
        };
        let component = self.component_control.as_ref().cloned()
            .ok_or(HostError::Fence("Stop disposal intrinsic original is absent"))?;
        let mut component = component.lock().map_err(|_| HostError::Fence("Stop disposal intrinsic original is poisoned"))?;
        let mut stop_original = stop.lock().map_err(|_| HostError::Fence("Stop original is poisoned"))?;
        match purpose {
            StopDisposalPurposeV1::Authenticated if !stop_original.authenticated_sent => {
                return Ok(false);
            }
            StopDisposalPurposeV1::UnsentNativePositive => {
                if stop_original.authenticated_sent {
                    return Err(HostError::Fence("unsent disposal cannot relabel authenticated Stop"));
                }
                stop_original.unsent_disposal.as_ref()
                    .ok_or(HostError::Fence("unsent Stop has no actual paid disposal interval"))?
                    .require_positive_v1()?;
            }
            _ => {}
        }
        if stop_original.retained_agent.is_some() {
            if stop_original.capture_stage.is_some() && incoming.is_none() {
                // Repeated service bookkeeping observes the same already held
                // residual owner. It performs no disposal or native reentry.
                return Ok(false);
            }
            return Err(HostError::Fence("Stop already holds its original Agent disposal prefix"));
        }
        // Move the actual Services owner before any fallible binding/native
        // validation. A negative handoff keeps it on this same occupied Stop.
        stop_original.retained_agent = incoming.take();
        let agent = stop_original.retained_agent.as_ref()
            .ok_or(HostError::Fence("Stop disposal actual Agent is absent"))?;
        if agent.session_binding() != stop_original.agent_binding {
            return Err(HostError::Fence("Stop disposal Agent differs from its original"));
        }
        stop_original.require_terminal_positive_v4()?;
        if stop_original.capture_stage.is_some() {
            // Runtime containment is terminal, but the old Stage, aliases,
            // incomplete Storage files/F and their cleanup debt remain owned.
            return Ok(false);
        }
        if !matches!(stop_original.sdk_terminal, Some(Ok(())))
            || self.runtime_pins.len() != 1 || self.observed_leaders.len() != 1
            || Arc::strong_count(&source) != 2 || Arc::strong_count(&stop) != 2
        {
            return Err(HostError::Fence("Stop disposal has another native owner or incomplete SDK"));
        }
        let runtime = stop_original.runtime;
        let launch = stop_original.source_launch;
        let stage = stop_original.stage.clone();
        let mut held = stage.lock().map_err(|_| HostError::Fence("Stop stage is poisoned"))?;
        if Arc::strong_count(&stage) != 2 || held.first.is_some()
            || !matches!(held.before, Some(Ok(()))) || !matches!(held.after, Some(Ok(())))
            || !matches!(held.native_finish, Some(Ok(()))) || held.primary.is_some()
            || held.names.iter().flatten().any(|names| !names.is_complete())
            || held.name_results.iter().flatten().any(|result| !matches!(result, Some(Ok(()))))
            || !self.runtime_pins.get(&runtime).zip(self.observed_leaders.get(&runtime))
                .is_some_and(|(pins, leader)| pins.supervisor.handle() == leader.handle())
        {
            return Err(HostError::Fence("Stop disposal native association or posts differ"));
        }
        let worker = held.worker.as_ref().ok_or(HostError::AgentLaunchQuarantined)?;
        if Arc::strong_count(worker) != 1 {
            return Err(HostError::Fence("Stop worker still has an active borrower"));
        }
        let worker = worker.try_lock().map_err(|_| HostError::Fence("Stop worker is still borrowed"))?;
        worker.require_resident_stop_parent_disposal_v4(
            stop_original.native_completed.as_ref().ok_or(HostError::AgentLaunchQuarantined)?,
        )?;
        drop(worker);
        let request = held.request;
        let namespace_scope = if self.fuse_workers.is_empty() && self.live_limit_attempts.is_empty() {
            let source = source.lock().map_err(|_| HostError::Fence("Stop source Launch is poisoned"))?;
            let (boot, fence, anchor) = source.namespace_scope_v4
                .ok_or(HostError::Fence("Stop lacks its actual typed Launch namespace"))?;
            if HostRuntimeIdentity::from(&fence) != runtime || source.request != launch {
                return Err(HostError::Fence("Stop namespace differs from its actual Launch"));
            }
            stop_original.namespace_scope_v4 = Some(
                aos_sandbox_protocol::host_stopped_namespace::HostStoppedNamespaceDataV4::from_data_v4(
                    boot, fence, anchor, launch, request,
                ));
            Some(stop_original.namespace_scope_v4.as_ref().and_then(|value| value.as_ref().ok()).copied()
                .ok_or(HostError::Fence("Stop namespace scope is not canonical; cause retained"))?)
        } else {
            // Stop may complete while another purpose retains unrelated native
            // custody. That supplies no whole-namespace disposal evidence.
            None
        };
        let launch_binding = crate::plan::HostExecutionRequestBindingV2 {
            id: launch.0, session: launch.1, signed: launch.2,
        };
        let completion = match purpose {
            StopDisposalPurposeV1::Authenticated => component
                .prepare_authenticated_resident_stop_disposal_identity_v4(
                    launch_binding,
                    crate::plan::HostExecutionRequestBindingV2 {
                        id: request.0, session: request.1, signed: request.2,
                    },
                )?,
            StopDisposalPurposeV1::UnsentNativePositive => component
                .prepare_unsent_stop_disposal_v1(
                    launch_binding,
                    stop_original.native_completed.as_ref()
                        .ok_or(HostError::AgentLaunchQuarantined)?,
                )?,
        };

        // Every fallible check and independent native post has completed while
        // all owners remained resident. No native operation follows the first
        // physical drop. Close this exact Agent, both actual runtime maps and
        // the complete Stop SDK/opening collectors before ending the old flight.
        drop(stop_original.retained_agent.take());
        drop(self.runtime_pins.remove(&runtime));
        drop(self.observed_leaders.remove(&runtime));
        let scratch = (held.worker.take(), held.opening.take(), held.owner.take(), held.setup.take(),
            held.clock.take(), held.writes.take(), held.catalog.take(), held.compilation.take(),
            held.guardian.take(), held.prepared_payload.take(), held.guardian_spec.take());
        drop(scratch);
        for interval in &mut held.names {
            for names in interval { names.settle_positive_once_v1(); }
        }
        drop(held);
        drop(stage);
        drop(stop_original);
        // This exclusive lock succeeded throughout the same synchronous
        // disposal turn; poisoning here cannot yield a retryable completion.
        match source.lock() {
            Ok(mut source) => source.resident_stop = None,
            Err(_) => std::process::abort(),
        }
        drop(self.launch_original.take());
        drop(stop);
        drop(source);
        completion.complete_after_disposal_v4();
        // Construct the opaque original only after the actual physical owning
        // drops and same-token completion. A durable Complete row cannot enter
        // this branch after restart or replace any of those native predicates.
        self.stopped_namespace_v4 = match purpose {
            StopDisposalPurposeV1::Authenticated => namespace_scope
                .map(|scope| HostStoppedNamespaceOriginalV4 { scope }),
            // A new Recover must run the full current paid historical census.
            // This physical old-owner closure supplies no authenticated answer.
            StopDisposalPurposeV1::UnsentNativePositive => None,
        };
        Ok(true)
    }
}
