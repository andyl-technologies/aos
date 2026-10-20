//! Runs fresh cleanup against one immutable authenticated Stop ancestry leaf.
//!
//! Current Root authority and the same current-Control financial original are
//! separate prerequisites. Two real native rounds prove present ownership (or
//! absence) before child admission. A second complete absence census and death
//! of every initially held PIDFD precede deferred completion. No old Launch,
//! Agent, namespace or Source original is reconstructed.

use super::launch_handoff::{HostLaunchOriginalV2, LaunchFirstV2};
use super::native_inventory::HostNativeInventoryOriginalV5;
use super::*;
use crate::plan::HostControlCleanupTokenV1;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use sha2::{Digest as _, Sha256};

type RequestIdentity = ([u8; 16], [u8; 32], [u8; 32]);
type WorkerOriginal = Arc<tokio::sync::Mutex<crate::worker::launch::HostLaunchWorkerOriginalV2>>;

struct LiveCleanupPinsDisposedV1 {
    runtime: crate::worker::HostRuntimeIdentity,
}

struct LiveCleanupResidentV1 {
    source: Option<Arc<Mutex<HostLaunchOriginalV2>>>,
    terminal: super::resident_stop::HostResidentStopOriginalV4,
    pins_disposed: Option<LiveCleanupPinsDisposedV1>,
    native_post: Option<Result<()>>,
}

#[derive(Clone, Copy)]
enum CleanupBodyFirstV1 {
    Initial,
    Terminal,
    Sdk,
    Stage,
    Resident,
}

pub(super) struct HostStopCleanupOriginalV1 {
    stage: Option<Arc<Mutex<HostLaunchOriginalV2>>>,
    live: Option<LiveCleanupResidentV1>,
    initial: Option<Box<HostNativeInventoryOriginalV5>>,
    terminal_census: Option<Box<HostNativeInventoryOriginalV5>>,
    terminal: Option<super::guardian_transaction::CompositeStopTerminalOriginalV4>,
    native_completed: Option<HostStopCleanupNativeCompletedV1>,
    sdk_terminal: Option<Result<()>>,
    sdk_posts: Option<Result<()>>,
    body_first: Option<CleanupBodyFirstV1>,
    fallback_before: Option<Result<()>>,
    fallback_after: Option<Result<()>>,
    native_after: Option<Result<()>>,
    token: Option<HostControlCleanupTokenV1>,
    round: usize,
    disposal_error: Option<HostError>,
}

/// Names only the same worker after whole fresh cleanup native termination.
pub(crate) struct HostStopCleanupNativeCompletedV1 {
    worker: std::sync::Weak<tokio::sync::Mutex<crate::worker::launch::HostLaunchWorkerOriginalV2>>,
    request: RequestIdentity,
}

impl HostStopCleanupNativeCompletedV1 {
    pub(crate) fn request_identity_v1(&self) -> RequestIdentity {
        self.request
    }

    pub(crate) fn matches_worker_v1(
        &self,
        worker: &WorkerOriginal,
        request: RequestIdentity,
    ) -> bool {
        self.request == request
            && self
                .worker
                .upgrade()
                .is_some_and(|actual| Arc::ptr_eq(&actual, worker))
    }

    fn borrow_v1(&self) -> Self {
        Self {
            worker: self.worker.clone(),
            request: self.request,
        }
    }
}

/// Borrows the whole actual authenticated terminal before native physical Drop.
pub(crate) struct HostStopCleanupTerminalPositiveV1<'original> {
    original: &'original HostStopCleanupOriginalV1,
}

impl HostStopCleanupTerminalPositiveV1<'_> {
    pub(crate) fn resident_launch_binding_v1(
        &self,
    ) -> Option<crate::plan::HostExecutionRequestBindingV2> {
        let live = self.original.live.as_ref()?;
        let (id, session, signed) = live.terminal.source_launch;
        Some(crate::plan::HostExecutionRequestBindingV2 {
            id,
            session,
            signed,
        })
    }
    pub(crate) fn require_control_original_v1(
        &self,
        token: &HostControlCleanupTokenV1,
    ) -> Result<()> {
        if self
            .original
            .token
            .as_ref()
            .is_none_or(|actual| !actual.rejoins_same_original_v1(token))
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn observation_round_v1(&self) -> usize {
        self.original.round
    }
}

impl HostStopCleanupOriginalV1 {
    pub(super) fn format_failure_v1(
        &self,
        control: &crate::plan::HostComponentControlStartupV2,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        let Some(stage) = self.stage.as_ref() else {
            return std::fmt::Display::fmt(control.failure(), formatter);
        };
        let stage = stage.lock().map_err(|_| std::fmt::Error)?;
        if stage.first.is_none()
            && let Some(cause) = self.disposal_error.as_ref()
        {
            return std::fmt::Display::fmt(cause, formatter);
        }
        if matches!(stage.first, Some(LaunchFirstV2::Primary)) {
            match self.body_first {
                Some(CleanupBodyFirstV1::Initial | CleanupBodyFirstV1::Terminal) => {
                    let native = match self.body_first {
                        Some(CleanupBodyFirstV1::Initial) => self.initial.as_ref(),
                        _ => self.terminal_census.as_ref(),
                    }
                    .ok_or(std::fmt::Error)?;
                    if native.original_failure_selected_v5() {
                        return std::fmt::Display::fmt(control.failure(), formatter);
                    }
                    return native.format_failure_v5(formatter);
                }
                Some(CleanupBodyFirstV1::Sdk) => {
                    let worker = stage.worker.as_ref().ok_or(std::fmt::Error)?;
                    let worker = worker.try_lock().map_err(|_| std::fmt::Error)?;
                    if let Some(formatted) = worker.format_cleanup_sdk_failure_v1(formatter) {
                        return formatted;
                    }
                    let cause = self
                        .sdk_terminal
                        .as_ref()
                        .and_then(|result| result.as_ref().err())
                        .or_else(|| {
                            self.sdk_posts
                                .as_ref()
                                .and_then(|result| result.as_ref().err())
                        })
                        .ok_or(std::fmt::Error)?;
                    return std::fmt::Display::fmt(cause, formatter);
                }
                Some(CleanupBodyFirstV1::Resident) => {
                    if let Some(cause) = self.live.as_ref().and_then(|live| live.terminal.failure())
                    {
                        return std::fmt::Display::fmt(cause, formatter);
                    }
                    if let Some(Err(cause)) = self
                        .live
                        .as_ref()
                        .and_then(|live| live.native_post.as_ref())
                    {
                        return std::fmt::Display::fmt(cause, formatter);
                    }
                }
                Some(CleanupBodyFirstV1::Stage) | None => {}
            }
            return super::launch_handoff::format_cleanup_stage_failure_v1(
                control, &stage, formatter,
            );
        }
        if !matches!(self.native_after, Some(Ok(()))) {
            for native in [self.initial.as_ref(), self.terminal_census.as_ref()]
                .into_iter()
                .flatten()
            {
                if native.failed_v5() {
                    if native.original_failure_selected_v5() {
                        return std::fmt::Display::fmt(control.failure(), formatter);
                    }
                    return native.format_failure_v5(formatter);
                }
            }
            return std::fmt::Display::fmt(control.failure(), formatter);
        }
        super::launch_handoff::format_cleanup_stage_failure_v1(control, &stage, formatter)
    }

    fn new(stage: Arc<Mutex<HostLaunchOriginalV2>>, round: usize) -> Self {
        Self {
            stage: Some(stage),
            live: None,
            initial: None,
            terminal_census: None,
            terminal: None,
            native_completed: None,
            sdk_terminal: None,
            sdk_posts: None,
            body_first: None,
            fallback_before: None,
            fallback_after: None,
            native_after: None,
            token: None,
            round,
            disposal_error: None,
        }
    }

    fn native_completed_v1(
        &mut self,
        worker: &WorkerOriginal,
        request: RequestIdentity,
    ) -> Result<()> {
        if self.native_completed.is_some() {
            return Err(refused());
        }
        self.initial
            .as_ref()
            .ok_or_else(refused)?
            .require_cleanup_native_completed_v1(
                self.terminal_census.as_ref().ok_or_else(refused)?,
            )?;
        self.native_completed = Some(HostStopCleanupNativeCompletedV1 {
            worker: Arc::downgrade(worker),
            request,
        });
        Ok(())
    }

    fn require_terminal_positive_v1(&self) -> Result<HostStopCleanupTerminalPositiveV1<'_>> {
        if self.token.is_none()
            || self.native_completed.is_none()
            || !matches!(self.sdk_terminal, Some(Ok(())))
            || !matches!(self.sdk_posts, Some(Ok(())))
            || !matches!(self.native_after, Some(Ok(())))
        {
            return Err(refused());
        }
        if let Some(live) = self.live.as_ref() {
            live.terminal.require_terminal_positive_v4()?;
            if live
                .pins_disposed
                .as_ref()
                .is_none_or(|proof| proof.runtime != live.terminal.runtime)
                || live
                    .terminal
                    .retained_agent
                    .as_ref()
                    .is_none_or(|agent| agent.session_binding() != live.terminal.agent_binding)
                || live.source.is_none()
            {
                return Err(refused());
            }
        }
        self.initial
            .as_ref()
            .ok_or_else(refused)?
            .require_cleanup_posts_completed_v1(
                self.terminal_census.as_ref().ok_or_else(refused)?,
            )?;
        let stage = self
            .stage
            .as_ref()
            .ok_or_else(refused)?
            .lock()
            .map_err(|_| refused())?;
        if stage.first.is_some()
            || stage.primary.is_some()
            || !matches!(stage.native_finish, Some(Ok(())))
            || !stage.authenticated_sent
            || !matches!(stage.opening_result, Some(Ok(())))
            || !stage
                .name_results
                .iter()
                .flatten()
                .all(|result| matches!(result, Some(Ok(()))))
        {
            return Err(refused());
        }
        Ok(HostStopCleanupTerminalPositiveV1 { original: self })
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    pub(super) fn retire_authenticated_live_cleanup_agent_v1(
        &mut self,
        incoming: &mut Option<crate::live_agent::HostAgentLiveSessionV1>,
    ) -> Result<bool> {
        let Some(capsule) = self.stop_cleanup_original.as_ref().cloned() else {
            return Ok(false);
        };
        {
            let mut held = capsule.lock().map_err(|_| refused())?;
            if held.live.is_none() {
                return Ok(false);
            }
            if !held
                .stage
                .as_ref()
                .ok_or_else(refused)?
                .lock()
                .map_err(|_| refused())?
                .authenticated_sent
            {
                return Ok(false);
            }
            let live = held.live.as_mut().ok_or_else(refused)?;
            if live.terminal.retained_agent.is_some() {
                return Err(refused());
            }
            // Move the actual Services owner before any fallible native join.
            // A refused handoff keeps that owner and exact cause in this flight.
            live.terminal.retained_agent = incoming.take();
            if live
                .terminal
                .retained_agent
                .as_ref()
                .is_none_or(|agent| agent.session_binding() != live.terminal.agent_binding)
            {
                held.disposal_error.get_or_insert_with(refused);
                return Err(refused());
            }
        }
        match self.retire_cleanup_native_after_sent_v1(Arc::clone(&capsule)) {
            Ok(completed) => Ok(completed),
            Err(cause) => {
                capsule
                    .lock()
                    .map_err(|_| refused())?
                    .disposal_error
                    .get_or_insert(cause);
                Err(refused())
            }
        }
    }

    fn observe_live_cleanup_posts_v1(
        &self,
        original: &mut HostStopCleanupOriginalV1,
        agent: Option<&crate::live_agent::HostAgentLiveSessionV1>,
    ) -> Result<()> {
        let Some(live) = original.live.as_mut() else {
            return Ok(());
        };
        if live.native_post.is_none() {
            let runtime = live.terminal.runtime;
            live.native_post = Some((|| {
                let pins = self.runtime_pins.get(&runtime).ok_or_else(refused)?;
                let leader = self.observed_leaders.get(&runtime).ok_or_else(refused)?;
                live.terminal
                    .observe_terminal_once_v4(pins, leader, agent.ok_or_else(refused)?)
            })());
        }
        if !matches!(live.native_post, Some(Ok(()))) {
            original
                .body_first
                .get_or_insert(CleanupBodyFirstV1::Resident);
            return Err(refused());
        }
        Ok(())
    }

    fn drop_live_cleanup_pins_after_posts_v1(
        &mut self,
        original: &mut HostStopCleanupOriginalV1,
    ) -> Result<()> {
        let Some(live) = original.live.as_mut() else {
            return Ok(());
        };
        live.terminal.require_terminal_positive_v4()?;
        let source = live.source.as_ref().ok_or_else(refused)?;
        if live.pins_disposed.is_some()
            || !matches!(live.native_post, Some(Ok(())))
            || !self
                .launch_original
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, source))
            || self.runtime_pins.len() != 1
            || self.observed_leaders.len() != 1
        {
            return Err(refused());
        }
        let runtime = live.terminal.runtime;
        if !self
            .runtime_pins
            .get(&runtime)
            .zip(self.observed_leaders.get(&runtime))
            .is_some_and(|(pins, leader)| pins.supervisor.handle() == leader.handle())
        {
            return Err(refused());
        }
        // Both exact held PIDFDs, the independent leader and Agent hangup are
        // terminal. Drop the actual namespace/cgroup/leader owners before the
        // new whole-namespace absence census; the old F remains charged.
        drop(self.runtime_pins.remove(&runtime));
        drop(self.observed_leaders.remove(&runtime));
        live.pins_disposed = Some(LiveCleanupPinsDisposedV1 { runtime });
        Ok(())
    }

    pub(crate) fn retain_sent_stop_cleanup_response_v1(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<()> {
        let Some(original) = self.stop_cleanup_original.as_ref() else {
            return Ok(());
        };
        let component = self.component_control.as_ref().ok_or_else(refused)?;
        let mut component = component.lock().map_err(|_| refused())?;
        let original = original.lock().map_err(|_| refused())?;
        let stage = original.stage.as_ref().ok_or_else(refused)?;
        let mut stage = stage.lock().map_err(|_| refused())?;
        if stage.request.0 != request.request_id() {
            return Err(refused());
        }
        stage.require_same_request(request)?;
        let effect = self.authority.open_effect(
            &request.request_id(),
            self.state
                .effect(&request.request_id())
                .ok_or_else(refused)?,
        )?;
        let aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1::Success { exact_body,.. }=outcome.result()
            else { return Err(refused()); };
        if effect.status() != aos_sandbox_broker::BrokerEffectStatusV1::Complete
            || effect.receipt() != exact_body.as_slice()
            || stage.first.is_some()
            || outcome.request().request_id() != request.request_id()
            || outcome.request().session_binding() != request.session_binding()
            || outcome.request().signed_request_digest() != request.signed_request_digest()
        {
            return Err(refused());
        }
        component.mark_cleanup_authenticated_sent_v1(
            original.token.as_ref().ok_or_else(refused)?,
            outcome,
        )?;
        stage.authenticated_sent = true;
        Ok(())
    }

    pub(super) fn retire_authenticated_cleanup_response_v1(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<bool> {
        let Some(original) = self.stop_cleanup_original.as_ref().cloned() else {
            return Ok(false);
        };
        {
            let held = original.lock().map_err(|_| refused())?;
            let stage = held
                .stage
                .as_ref()
                .ok_or_else(refused)?
                .lock()
                .map_err(|_| refused())?;
            stage.require_same_request(request)?;
            let mut component = self
                .component_control
                .as_ref()
                .ok_or_else(refused)?
                .lock()
                .map_err(|_| refused())?;
            component.require_cleanup_authenticated_response_v1(
                held.token.as_ref().ok_or_else(refused)?,
                request,
            )?;
            if held
                .live
                .as_ref()
                .is_some_and(|live| live.terminal.retained_agent.is_none())
            {
                // The exact authenticated response is complete. Services still
                // owns the actual Agent; its subsequent owning callback must
                // drop that original before either financial flight retires.
                return Ok(true);
            }
        }
        self.retire_cleanup_native_after_sent_v1(original)
    }

    fn retire_cleanup_native_after_sent_v1(
        &mut self,
        capsule: Arc<Mutex<HostStopCleanupOriginalV1>>,
    ) -> Result<bool> {
        let component = self
            .component_control
            .as_ref()
            .cloned()
            .ok_or_else(refused)?;
        let mut component = component.lock().map_err(|_| refused())?;
        let mut original = capsule.lock().map_err(|_| refused())?;
        {
            let stage = original
                .stage
                .as_ref()
                .ok_or_else(refused)?
                .lock()
                .map_err(|_| refused())?;
            if stage
                .worker
                .as_ref()
                .is_none_or(|worker| Arc::strong_count(worker) != 1)
                || stage
                    .writes
                    .as_ref()
                    .is_none_or(|writes| Arc::strong_count(writes) != 1)
            {
                return Err(refused());
            }
        }
        let token = original.token.as_ref().ok_or_else(refused)?;
        let posts = original.require_terminal_positive_v1()?;
        let disposal = component.prepare_stop_cleanup_disposal_v1(token, &posts)?;
        // The disposer borrows ONLY Control. No proof/token/Stage borrow crosses
        // this unique-owner physical Drop of the actual SDK and four journals.
        if let Some(live) = original.live.as_mut() {
            let source = live.source.as_ref().ok_or_else(refused)?;
            if !self
                .launch_original
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, source))
                || Arc::strong_count(source) != 2
                || !self.runtime_pins.is_empty()
                || !self.observed_leaders.is_empty()
            {
                return Err(refused());
            }
            source
                .lock()
                .map_err(|_| refused())?
                .borrow_live_cleanup_parent_v1()?;
        }
        // Removing this completed private terminal also releases its real
        // alias of the new Stage; its actual Agent is physically dropped here.
        let live = original.live.take();
        if let Some(mut live) = live {
            drop(live.terminal.retained_agent.take());
            drop(self.launch_original.take());
            drop(live.source.take());
            drop(live);
        }
        let stage = original.stage.take().ok_or_else(refused)?;
        match Arc::try_unwrap(stage) {
            Ok(stage) => drop(stage),
            Err(stage) => {
                original.stage = Some(stage);
                return Err(refused());
            }
        }
        drop(original.initial.take());
        drop(original.terminal_census.take());
        drop(original.native_completed.take());
        drop(original.token.take());
        disposal.complete_after_native_drop_v1()?;
        drop(original);
        self.stop_cleanup_original = None;
        Ok(true)
    }
}

impl<C: HostCatalog, S: HostStateStore, W: HostWorker> HostBroker<C, S, W> {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_fresh_stop_cleanup_v1(
        &mut self,
        request: &ValidatedRuntimeRequest,
        request_digest: [u8; 32],
        admitted: aos_sandbox_broker::VerifiedBrokerAdmission,
        admission_clock: &aos_sandbox_core::RawPairedClockSample,
        authenticated: Option<&AuthenticatedBrokerMethodRequestV1>,
        retained_agent: Option<&crate::live_agent::HostAgentLiveSessionV1>,
    ) -> Result<ValidatedRuntimeApplyResponse>
    where
        W: Sync,
    {
        let authenticated = authenticated.ok_or_else(refused)?;
        let subject = request.host_stop_cleanup_v1().ok_or_else(refused)?;
        let live_source = self.live_cleanup_source_v1()?;
        if let Some(source) = live_source.as_ref() {
            let held = source.lock().map_err(|_| refused())?;
            let parent = held.borrow_live_cleanup_parent_v1()?;
            if parent.namespace_scope_v1()? != subject.historical_scope_v1().launch_scope_v1()
                || held.agent_binding != retained_agent.map(|agent| agent.session_binding())
            {
                return Err(refused());
            }
            drop(held);
            // This existing disposer requires a genuinely positive completed
            // Capture and the exact freshly verified HostStop assignment.
            // Failed/aliased Capture ownership is never relabeled as cleanup.
            self.dispose_terminal_stage_before_stop_v3(source, &admitted)?;
        }
        if self.stop_cleanup_original.is_some()
            || (self.launch_original.is_some() && live_source.is_none())
            || self.argument_stages.iter().any(Option::is_some)
            || self.active_argument_writes.is_some()
            || self.active_launch_writes.is_some()
            || self.live_agent.is_some()
            || (live_source.is_none() && !self.runtime_pins.is_empty())
            || (live_source.is_none() && !self.observed_leaders.is_empty())
            || !self.live_limit_attempts.is_empty()
            || !self.fuse_workers.is_empty()
            || subject.current_boot_v1() != &admission_clock.host_boot_id()
            || <[u8; 32]>::from(Sha256::digest(authenticated.exact_body())) != request_digest
        {
            return Err(refused());
        }
        let component = self
            .component_control
            .as_ref()
            .cloned()
            .ok_or_else(refused)?;
        let mut component = component.lock().map_err(|_| refused())?;
        let entry = HostNativeInventoryOriginalV5::cleanup_entry_demand_v1(
            &self.state,
            authenticated.exact_body().len(),
        )?;
        let carrier = std::mem::size_of::<Mutex<HostStopCleanupOriginalV1>>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<usize>()))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(HostError::ResourceExhausted)?;
        let mut complete = HostLaunchOriginalV2::fixed_stop_demand_v4(authenticated)
            .and_then(|demand| {
                demand
                    .checked_add(self.state.composite_stop_receiving_demand_v4()?)
                    .ok()
            })
            .and_then(|demand| demand.checked_add(entry).ok())
            .and_then(|demand| demand.checked_add(entry).ok())
            .and_then(|demand| {
                demand
                    .checked_add(
                        crate::worker::HostOwnedRuntimeProofOriginalV8::cleanup_posts_demand_v1()?,
                    )
                    .ok()
            })
            .and_then(|demand| {
                demand.checked_add(
                    crate::worker::launch::HostLaunchWorkerOriginalV2::cleanup_sdk_posts_demand_v1()?,
                ).ok()
            })
            .and_then(|demand| {
                demand
                    .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, carrier))
                    .ok()
            })
            .ok_or(HostError::ResourceExhausted)?;
        let mut receiving = match live_source.as_ref() {
            Some(source) => {
                let held = source.lock().map_err(|_| refused())?;
                component.begin_stop_cleanup_receiving_v1(
                    authenticated,
                    request,
                    &admitted,
                    complete,
                    Some(&held.borrow_live_cleanup_parent_v1()?),
                )?
            }
            None => component.begin_stop_cleanup_receiving_v1(
                authenticated,
                request,
                &admitted,
                complete,
                None,
            )?,
        };
        let stage = Arc::new(Mutex::new(HostLaunchOriginalV2::new(
            authenticated,
            complete,
            admission_clock.host_boot_id(),
            admitted.effect.effect_deadline_boottime_nanoseconds(),
            None,
        )));
        let original = Arc::new(Mutex::new(HostStopCleanupOriginalV1::new(
            Arc::clone(&stage),
            receiving.observation_round_start_data_v1(),
        )));
        if let Some(source) = live_source.as_ref() {
            let held = source.lock().map_err(|_| refused())?;
            let runtime = *self.runtime_pins.first_key_value().ok_or_else(refused)?.0;
            original.lock().map_err(|_| refused())?.live = Some(LiveCleanupResidentV1 {
                source: Some(Arc::clone(source)),
                terminal: super::resident_stop::HostResidentStopOriginalV4::new(
                    Arc::clone(&stage),
                    held.request,
                    runtime,
                    held.agent_binding.ok_or_else(refused)?,
                ),
                pins_disposed: None,
                native_post: None,
            });
        }
        self.stop_cleanup_original = Some(Arc::clone(&original));
        let primary = async {
            {
                let initial = HostNativeInventoryOriginalV5::new_cleanup_before_native_v1(
                    &mut receiving,
                    authenticated,
                    request,
                    &mut complete,
                )?;
                original.lock().map_err(|_| refused())?.initial = Some(Box::new(initial));
                let worker = self.worker.retained_payload_worker().ok_or_else(refused)?;
                let mut held = original.lock().map_err(|_| refused())?;
                held.initial
                    .as_mut()
                    .ok_or_else(refused)?
                    .capture_cleanup_native_once_v1(
                        &mut receiving,
                        authenticated,
                        &admitted.effect,
                        &self.store,
                        &self.state,
                        &self.authority,
                        &worker,
                    )
                    .await?;
            }
            {
                let mut held = stage.lock().map_err(|_| refused())?;
                held.complete = complete;
                held.clock = Some(
                    super::argument_handoff::ArgumentClockV2::capture_stop_effect_v4(
                        admission_clock.host_boot_id(),
                        &admitted.effect,
                    ),
                );
                held.prepare_cleanup_stop_opening_v1(&mut receiving, authenticated)?;
                let guardian = self.guardian.as_ref().ok_or_else(refused)?;
                let worker=crate::worker::launch::HostLaunchWorkerOriginalV2::reserve_cleanup_stop_before_native_v1(
                    &mut receiving,&mut held.complete,authenticated,guardian)?;
                held.worker = Some(worker);
                complete = held.complete;
                self.active_launch_writes = held.writes.clone();
            }
            {
                let held = original.lock().map_err(|_| refused())?;
                let ownership = held
                    .initial
                    .as_ref()
                    .ok_or_else(refused)?
                    .borrow_cleanup_ownership_v1()?;
                let current = self
                    .state
                    .historical_namespace_candidate_v7(&self.authority)?;
                current.require_cleanup_subject_v2(request.host_stop_cleanup_v1().ok_or_else(refused)?)?;
                ownership.require_current_target_v1(&current, authenticated)?;
                let mut proposed = self.state.clone();
                let admission = proposed.admit_cleanup_stop_v1(
                    request,
                    authenticated,
                    request_digest,
                    &ownership,
                    self.authority
                        .seal_fence(request.fence().sandbox_id(), &admitted.fence)?,
                    &admitted,
                    self.authority
                        .seal_effect(request.header().request_id(), &admitted.effect)?,
                    &self.authority,
                )?;
                super::ensure_pending_runtime_admission(admission)?;
                self.commit_state(&proposed)?;
            }
            let (worker, deadline) = {
                let held = stage.lock().map_err(|_| refused())?;
                (
                    held.worker.as_ref().cloned().ok_or_else(refused)?,
                    held.worker_deadline.ok_or_else(refused)?,
                )
            };
            let clock = super::launch_handoff::write_clock::HostLaunchWriteClockV2::borrow_v2(
                &stage,
                authenticated,
            )?;
            let mut worker_receiving =
                crate::worker::launch::HostLaunchWorkerReceivingV2::new_cleanup_stop_v1(
                    &mut receiving,
                    authenticated,
                    Arc::clone(&worker),
                    deadline,
                    clock,
                )
                .await?;
            let clock_stage = Arc::clone(&stage);
            let mut effect_clock = move || {
                clock_stage
                    .lock()
                    .map_err(|_| refused())?
                    .clock
                    .as_mut()
                    .ok_or_else(refused)?
                    .sample()
            };
            let mut terminal = None;
            let body = self
                .advance_composite_stop_to_terminal_v5(
                    request.fence(),
                    *request.header().request_id(),
                    request_digest,
                    &admitted.effect,
                    request.header().maximum_response_bytes(),
                    &mut effect_clock,
                    Some(&mut worker_receiving),
                    &mut terminal,
                )
                .await?;
            drop(worker_receiving);
            original.lock().map_err(|_| refused())?.terminal = terminal;
            {
                let mut held = original.lock().map_err(|_| refused())?;
                self.observe_live_cleanup_posts_v1(&mut held, retained_agent)?;
                self.drop_live_cleanup_pins_after_posts_v1(&mut held)?;
            }
            {
                let census = HostNativeInventoryOriginalV5::new_cleanup_terminal_before_native_v1(
                    &mut receiving,
                    authenticated,
                    request,
                    &mut complete,
                )?;
                let mut held = original.lock().map_err(|_| refused())?;
                held.terminal_census = Some(Box::new(census));
                let worker_view = self.worker.retained_payload_worker().ok_or_else(refused)?;
                held.terminal_census
                    .as_mut()
                    .ok_or_else(refused)?
                    .capture_cleanup_native_once_v1(
                        &mut receiving,
                        authenticated,
                        &admitted.effect,
                        &self.store,
                        &self.state,
                        &self.authority,
                        &worker_view,
                    )
                    .await?;
                let initial_posts = held.initial
                    .as_mut()
                    .ok_or_else(refused)?
                    .finish_cleanup_initial_owners_once_v1(&worker_view);
                if initial_posts.is_err() {
                    held.body_first.get_or_insert(CleanupBodyFirstV1::Initial);
                }
                let sdk_posts = crate::worker::launch::HostLaunchWorkerOriginalV2::observe_cleanup_sdk_posts_once_v1(
                    &worker, &worker_view,
                ).await;
                if sdk_posts.is_err() {
                    held.body_first.get_or_insert(CleanupBodyFirstV1::Sdk);
                }
                held.sdk_posts = Some(sdk_posts);
                initial_posts?;
                if !matches!(held.sdk_posts, Some(Ok(()))) { return Err(refused()); }
                held.native_completed_v1(
                    &worker,
                    (
                        authenticated.request_id(),
                        authenticated.session_binding(),
                        authenticated.signed_request_digest(),
                    ),
                )?;
            }
            let completed = original
                .lock()
                .map_err(|_| refused())?
                .native_completed
                .as_ref()
                .ok_or_else(refused)?
                .borrow_v1();
            let sdk = crate::worker::launch::HostLaunchWorkerOriginalV2::finish_cleanup_stop_sdk_v1(
                &worker, &completed,
            ).await;
            {
                let mut held = original.lock().map_err(|_| refused())?;
                held.sdk_terminal = Some(sdk);
                if !matches!(held.sdk_terminal, Some(Ok(()))) {
                    held.body_first.get_or_insert(CleanupBodyFirstV1::Sdk);
                    return Err(refused());
                }
                worker
                    .lock()
                    .await
                    .require_cleanup_stop_parent_disposal_v1(&completed)?;
                self.commit_cleanup_stop_terminal_v1(
                    held.terminal.as_mut().ok_or_else(refused)?,
                    &admitted.effect,
                    &completed,
                    &mut effect_clock,
                )?;
            }
            Ok(ValidatedRuntimeApplyResponse {
                request_id: *request.header().request_id(),
                maximum_response_bytes: request.header().maximum_response_bytes(),
                body,
            })
        }
        .await;
        self.active_launch_writes = None;
        if primary.is_err() {
            let mut held = original.lock().map_err(|_| refused())?;
            if held.body_first.is_none() {
                // Freeze the actual body cause before negative-only fallback
                // observations can add failures to another native owner.
                held.body_first = Some(
                    if held
                        .initial
                        .as_ref()
                        .is_some_and(|initial| initial.cleanup_body_failed_v1())
                    {
                        CleanupBodyFirstV1::Initial
                    } else if held
                        .terminal_census
                        .as_ref()
                        .is_some_and(|terminal| terminal.cleanup_body_failed_v1())
                    {
                        CleanupBodyFirstV1::Terminal
                    } else {
                        CleanupBodyFirstV1::Stage
                    },
                );
            }
        }
        // Body or terminal-census failure cannot suppress posts on native
        // owners already reached by an earlier SDK effect. Positive disposal
        // remains below its genuine whole completion conjunction.
        {
            let mut held = original.lock().map_err(|_| refused())?;
            let _ = self.observe_live_cleanup_posts_v1(&mut held, retained_agent);
        }
        {
            let worker = stage
                .lock()
                .map_err(|_| refused())?
                .worker
                .as_ref()
                .cloned();
            let mut held = original.lock().map_err(|_| refused())?;
            if let Some(worker_view) = self.worker.retained_payload_worker() {
                if held.sdk_posts.is_none() {
                    if let Some(worker) = worker.as_ref() {
                        held.sdk_posts = Some(crate::worker::launch::HostLaunchWorkerOriginalV2::observe_cleanup_sdk_posts_once_v1(
                            worker, &worker_view,
                        ).await);
                    }
                }
                if let Some(initial) = held.initial.as_mut() {
                    if !initial.cleanup_initial_owner_posts_entered_v1() {
                        let _ = initial.finish_cleanup_initial_owners_once_v1(&worker_view);
                    }
                }
            }
        }
        {
            let mut held = stage.lock().map_err(|_| refused())?;
            if primary.is_err() {
                held.first.get_or_insert(LaunchFirstV2::Primary);
            }
            held.primary = Some(primary);
            if held.has_stop_journal_owner_v4() {
                let _ = held.observe_names_once_v2(1);
            }
        }
        // Even refusal before the first collector entered must reach its own
        // independently paid Source pair; the real first body cause stays above.
        if original.lock().map_err(|_| refused())?.initial.as_ref()
            .is_none_or(|initial|!initial.cleanup_before_entered_v1()) {
            original.lock().map_err(|_| refused())?.fallback_before =
                Some(receiving.observe_before_once_v5().await);
        }
        let after = receiving.observe_after_once_v5().await;
        {
            let mut held = original.lock().map_err(|_| refused())?;
            if let Some(initial) = held.initial.as_mut() {
                let native_after = initial
                    .finish_cleanup_native_post_once_v1(
                        after,
                        receiving.original_failure_entered_v5(),
                    )
                    .await;
                held.native_after = Some(native_after);
                if matches!(held.native_after, Some(Ok(()))) {
                    let HostStopCleanupOriginalV1 {
                        initial,
                        terminal_census,
                        ..
                    } = &mut *held;
                    if let Some(terminal) = terminal_census.as_mut() {
                        terminal
                            .dispose_cleanup_terminal_after_posts_v1(
                                initial.as_ref().ok_or_else(refused)?,
                            )
                            .await?;
                    }
                }
            } else {
                held.fallback_after = Some(after);
            }
        }
        let mut held = stage.lock().map_err(|_| refused())?;
        if held.first.is_some()
            || !matches!(held.primary, Some(Ok(_)))
            || !matches!(
                original.lock().map_err(|_| refused())?.native_after,
                Some(Ok(()))
            )
        {
            return Err(refused());
        }
        held.native_finish = Some(receiving.finish_cleanup_native_once_v1());
        if !matches!(held.native_finish, Some(Ok(()))) {
            held.first.get_or_insert(LaunchFirstV2::NativeFinish);
            return Err(refused());
        }
        let response = match held.primary.take() {
            Some(Ok(response)) => response,
            _ => return Err(refused()),
        };
        drop(held);
        original.lock().map_err(|_| refused())?.token =
            Some(receiving.retain_pending_authenticated_v1()?);
        Ok(response)
    }
}

fn refused() -> HostError {
    HostError::Fence(
        "fresh Stop cleanup conjunction refused; actual native/Source originals remain retained",
    )
}
