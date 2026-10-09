//! Session ownership, atomic admission, prepared inputs, and bounded shutdown.

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, Weak,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

use dispatch_model::Problem;
use tokio::{
    sync::{Notify, Semaphore, watch},
    time::Instant,
};

use crate::{
    CleanupReport, CloseMode, ExecutionProfile, JobStatus, RequiredGuarantees, RuntimeError,
    SessionLimits, SolveOptions, SolveResult,
    connection::ConnectedWorker,
    providers::{ExecutionProvider, ResourceGrant, WorkerLaunch},
};

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

/// Configures an application-owned execution session.
pub struct SessionBuilder {
    provider: Arc<dyn ExecutionProvider>,
    worker: WorkerLaunch,
    limits: SessionLimits,
    profile: ExecutionProfile,
    expected_build: Option<String>,
    capabilities: Option<dispatch_protocol::wire::Capabilities>,
    required: RequiredGuarantees,
}

impl SessionBuilder {
    /// Constructs a builder using explicit trusted executable configuration.
    pub fn new(provider: Arc<dyn ExecutionProvider>, worker: WorkerLaunch) -> Self {
        Self {
            provider,
            worker,
            limits: SessionLimits::default(),
            profile: ExecutionProfile::Warm,
            expected_build: None,
            capabilities: None,
            required: RequiredGuarantees::default(),
        }
    }

    /// Sets bounded session-local storage and concurrency.
    pub fn limits(mut self, limits: SessionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Selects warm reuse or fresh execution explicitly.
    pub fn profile(mut self, profile: ExecutionProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Pins a build identity without replacing capability negotiation.
    pub fn expected_backend_build(mut self, build: impl Into<String>) -> Self {
        self.expected_build = Some(build.into());
        self
    }

    /// Supplies trusted build-bound capability metadata for lazy startup.
    ///
    /// The application must obtain this manifest from trusted installation
    /// metadata. A live worker must confirm it before materializing any input.
    pub fn trusted_capabilities(
        mut self,
        capabilities: dispatch_protocol::wire::Capabilities,
    ) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    /// Requires guarantees without permitting best-effort substitution.
    pub fn required_guarantees(mut self, required: RequiredGuarantees) -> Self {
        self.required = required;
        self
    }

    /// Authorizes resources and initializes capability negotiation.
    ///
    /// # Errors
    /// Returns invalid-configuration, unavailable-provider, or guarantee errors.
    pub async fn start(mut self) -> Result<Session, RuntimeError> {
        if self.limits.max_workers == 0
            || self.limits.max_workers > Semaphore::MAX_PERMITS
            || self.limits.max_pending == 0
            || self.limits.max_retained_results == 0
            || self.limits.max_frame_bytes < 65_536
            || self.limits.result_retention.is_zero()
            || self.limits.cleanup_timeout.is_zero()
            || Instant::now()
                .checked_add(self.limits.result_retention)
                .is_none()
            || Instant::now()
                .checked_add(self.limits.cleanup_timeout)
                .is_none()
        {
            return Err(RuntimeError::Unsupported(
                "session limits must be positive and frames must accommodate negotiation".into(),
            ));
        }
        let grant = self.provider.grant();
        if (self.required.hard_cancellation && !grant.hard_cancellation)
            || (self.required.independent_memory && !grant.independent_memory)
            || (self.required.aggregate_accounting && !grant.aggregate_accounting)
            || (self.required.owner_cleanup && !grant.owner_cleanup)
        {
            return Err(RuntimeError::Unsupported(
                "provider cannot supply a required guarantee".into(),
            ));
        }
        let generation = NEXT_SESSION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| RuntimeError::Unsupported("session identity exhausted".into()))?;
        if let Some(capabilities) = &self.capabilities {
            if capabilities.backend_build_id.is_empty()
                || capabilities.protocol_version != Some(crate::connection::version())
                || capabilities.search_modes.is_empty()
                || self
                    .expected_build
                    .as_ref()
                    .is_some_and(|expected| *expected != capabilities.backend_build_id)
            {
                return Err(RuntimeError::Unsupported(
                    "invalid trusted capability manifest".into(),
                ));
            }
            self.expected_build = Some(capabilities.backend_build_id.clone());
        }
        if let Some(capabilities) = self.capabilities.as_mut() {
            let hello = dispatch_protocol::wire::Hello {
                protocol_versions: vec![crate::connection::version()],
                model_versions: vec![crate::connection::version()],
                limits: Some(crate::connection::default_wire_limits(
                    self.limits.max_frame_bytes,
                )),
                required_capabilities: Vec::new(),
            };
            capabilities.limits =
                Some(dispatch_protocol::negotiation::negotiate(&hello, capabilities)?.limits);
        }
        self.worker.session_generation = generation;
        self.worker.max_frame_bytes = self.limits.max_frame_bytes;
        let initial_frame_limit = self.limits.max_frame_bytes;
        let inner = Arc::new(Inner {
            provider: self.provider,
            worker: self.worker,
            grant,
            profile: self.profile,
            expected_build: self.expected_build,
            capabilities: self.capabilities,
            slots: Arc::new(Semaphore::new(self.limits.max_workers)),
            limits: self.limits,
            generation,
            next_worker: AtomicU64::new(1),
            state: Mutex::new(State::default()),
            changed: Notify::new(),
            cancel_all: watch::channel(false).0,
            frame_limit: AtomicU32::new(initial_frame_limit),
            negotiated_capabilities: OnceLock::new(),
        });
        // Without trusted metadata, perform a live handshake at initialization.
        // No allocation problem enters this probe worker.
        let capabilities = if let Some(capabilities) = &inner.capabilities {
            capabilities.clone()
        } else {
            let mut worker = tokio::time::timeout(
                inner.limits.cleanup_timeout,
                inner.acquire_worker(|| Ok(())),
            )
            .await
            .map_err(|_| RuntimeError::Unsupported("provider initialization timed out".into()))??;
            let capabilities = worker
                .worker
                .as_ref()
                .ok_or_else(|| RuntimeError::Unsupported("negotiation worker missing".into()))?
                .capabilities
                .clone();
            if inner.profile == ExecutionProfile::Warm {
                worker.reuse();
            } else {
                worker.retire().await;
            }
            capabilities
        };
        if let Some(limits) = &capabilities.limits {
            inner.frame_limit.store(
                limits.max_frame_bytes.min(inner.limits.max_frame_bytes),
                Ordering::Relaxed,
            );
        }
        let _ = inner.negotiated_capabilities.set(capabilities.clone());
        Ok(Session {
            owner: Arc::new(Owner {
                inner,
                capabilities,
            }),
        })
    }
}

/// Provides cheap cloned handles sharing one admission and accounting context.
#[derive(Clone)]
pub struct Session {
    owner: Arc<Owner>,
}

impl Session {
    /// Returns the authorized provider guarantees.
    pub fn grant(&self) -> &ResourceGrant {
        &self.owner.inner.grant
    }

    /// Returns the shared session-local storage and lifecycle bounds.
    pub fn limits(&self) -> &SessionLimits {
        &self.owner.inner.limits
    }

    /// Returns the explicitly selected execution lifecycle.
    pub fn profile(&self) -> ExecutionProfile {
        self.owner.inner.profile
    }

    /// Returns negotiated capabilities or the trusted lazy-start manifest.
    ///
    /// Lazy workers confirm the manifest before input materialization.
    pub fn capabilities(&self) -> &dispatch_protocol::wire::Capabilities {
        &self.owner.capabilities
    }

    /// Returns the session generation used to scope jobs and prepared handles.
    pub fn generation(&self) -> u64 {
        self.owner.inner.generation
    }

    /// Admits an immutable problem and starts its submission deadline.
    ///
    /// # Errors
    /// Returns closed-session, overload, invalid options, or serialization errors.
    pub fn submit(&self, problem: Problem, options: SolveOptions) -> Result<Job, RuntimeError> {
        let started = Instant::now();
        let bytes = crate::encoding::encode(&problem, self.owner.inner.encoding_limit())?;
        drop(problem);
        self.owner.inner.submit_bytes(bytes, options, started)
    }

    /// Retains immutable session input independently of any worker generation.
    ///
    /// # Errors
    /// Returns closed-session, overload, or serialization errors.
    pub async fn prepare(&self, problem: Problem) -> Result<PreparedInput, RuntimeError> {
        self.prepare_with_deadline(problem, Duration::from_secs(30))
            .await
    }

    /// Validates and retains session input under an explicit end-to-end budget.
    ///
    /// # Errors
    /// Returns admission, validation, cancellation, deadline, or execution errors.
    pub async fn prepare_with_deadline(
        &self,
        problem: Problem,
        timeout: Duration,
    ) -> Result<PreparedInput, RuntimeError> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            RuntimeError::Unsupported("preparation deadline exceeds clock range".into())
        })?;
        let basis = problem.observation_basis.clone();
        let bytes = crate::encoding::encode(&problem, self.owner.inner.encoding_limit())?;
        drop(problem);
        let inner = &self.owner.inner;
        let id = {
            let mut state = inner.lock()?;
            if state.closed {
                return Err(RuntimeError::Closed);
            }
            if state.prepared.len() + state.preparing >= inner.limits.max_prepared {
                return Err(RuntimeError::Overloaded("prepared input count"));
            }
            if state.pending >= inner.limits.max_pending {
                return Err(RuntimeError::Overloaded("pending requests"));
            }
            let retained = state
                .input_bytes
                .checked_add(bytes.capacity())
                .ok_or(RuntimeError::Overloaded("input bytes"))?;
            if retained > inner.limits.max_input_bytes {
                return Err(RuntimeError::Overloaded("input bytes"));
            }
            let id = state.next_id()?;
            state.input_bytes = retained;
            state.preparing += 1;
            state.pending += 1;
            state.active_jobs += 1;
            id
        };
        let input = Arc::new(Input {
            bytes,
            inner: Arc::downgrade(inner),
            binding: OnceLock::new(),
        });
        let mut accounting = PreparationAccounting {
            inner: inner.clone(),
            queued: true,
            finished: false,
        };
        let mut worker = None;
        let mut cancellation = inner.cancel_all.subscribe();
        let result = tokio::select! {
            _ = crate::scheduler::cancellation(&mut cancellation) => Err(RuntimeError::Closed),
            _ = tokio::time::sleep_until(deadline) => Err(RuntimeError::Unsupported("preparation deadline expired".into())),
            result = async {
                worker = Some(inner.acquire_worker(|| {
                    let mut state = inner.lock()?;
                    state.pending = state.pending.saturating_sub(1);
                    accounting.queued = false;
                    Ok(())
                }).await?);
                let worker = worker.as_mut().and_then(|lease| lease.worker.as_mut()).ok_or_else(|| RuntimeError::Unsupported("preparation worker missing".into()))?;
                worker.connection.control.begin_job().await?;
                worker.validate_input(inner.generation, input.bytes.clone()).await
            } => result,
        };
        if let Some(mut worker) = worker {
            if result.is_ok() && inner.profile == ExecutionProfile::Warm {
                worker.reuse();
            }
            // Cleanup has its own bounded supervision. It must not extend the
            // caller's preparation deadline while an owner is unresponsive.
            else {
                drop(worker);
            }
        }
        let result = {
            let mut state = inner.lock()?;
            state.preparing = state.preparing.saturating_sub(1);
            if accounting.queued {
                state.pending = state.pending.saturating_sub(1);
            }
            state.active_jobs = state.active_jobs.saturating_sub(1);
            accounting.finished = true;
            match result {
                Ok(digest) if !state.closed => {
                    let _ = input.binding.set(PreparedBinding {
                        digest: digest.clone(),
                        basis,
                    });
                    state.prepared.insert(id, input.clone());
                    Ok(PreparedInput {
                        session_generation: inner.generation,
                        id,
                        model_digest: digest,
                    })
                }
                Ok(_) => Err(RuntimeError::Closed),
                Err(error) => Err(error),
            }
        };
        inner.changed.notify_waiters();
        result
    }

    /// Submits a retained session input without double charging its bytes.
    ///
    /// # Errors
    /// Returns stale-handle, closed-session, overload, or invalid-options errors.
    pub fn submit_prepared(
        &self,
        handle: &PreparedInput,
        options: SolveOptions,
    ) -> Result<Job, RuntimeError> {
        let started = Instant::now();
        let inner = &self.owner.inner;
        if handle.session_generation != inner.generation {
            return Err(RuntimeError::StaleHandle);
        }
        let input = inner
            .lock()?
            .prepared
            .get(&handle.id)
            .cloned()
            .ok_or(RuntimeError::StaleHandle)?;
        inner.submit_input(input, options, started)
    }

    /// Releases a handle while allowing already accepted solves to retain input.
    ///
    /// # Errors
    /// Returns a stale-handle error for another session or released input.
    pub fn release(&self, handle: &PreparedInput) -> Result<(), RuntimeError> {
        let inner = &self.owner.inner;
        if handle.session_generation != inner.generation {
            return Err(RuntimeError::StaleHandle);
        }
        let input = inner
            .lock()?
            .prepared
            .remove(&handle.id)
            .ok_or(RuntimeError::StaleHandle)?;
        // Drop outside the state lock: the last input owner releases its charge.
        drop(input);
        Ok(())
    }

    /// Stops admission and drains or cancels accepted work within a close budget.
    ///
    /// # Errors
    /// Returns an error when session bookkeeping is unavailable.
    pub async fn close(
        &self,
        mode: CloseMode,
        timeout: Duration,
    ) -> Result<CleanupReport, RuntimeError> {
        let inner = &self.owner.inner;
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            RuntimeError::Unsupported("close deadline exceeds clock range".into())
        })?;
        {
            let mut state = inner.lock()?;
            state.closed = true;
            if matches!(mode, CloseMode::Cancel) {
                state.cancel_jobs();
                inner.cancel_all.send_replace(true);
            }
        }
        loop {
            let notified = inner.changed.notified();
            if inner.lock()?.active_jobs == 0 {
                break;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                inner.lock()?.cancel_jobs();
                inner.cancel_all.send_replace(true);
                break;
            }
        }
        let (idle, prepared, mut report) = {
            let mut state = inner.lock()?;
            let report = CleanupReport {
                completed: state.completed_jobs,
                unconfirmed: state.active_jobs,
                workers_unconfirmed: 0,
            };
            (
                std::mem::take(&mut state.idle),
                std::mem::take(&mut state.prepared),
                report,
            )
        };
        drop(prepared);
        for worker in idle {
            let control = worker.connection.control.clone();
            drop(worker);
            if !matches!(
                tokio::time::timeout_at(deadline, control.stop()).await,
                Ok(Ok(()))
            ) {
                crate::lease::quarantine(inner.clone(), control, None);
            }
        }
        report.workers_unconfirmed += inner.lock()?.unconfirmed_workers;
        Ok(report)
    }
}

/// References session-owned immutable input without carrying resource authority.
#[derive(Clone, Debug)]
pub struct PreparedInput {
    session_generation: u64,
    id: u64,
    model_digest: Vec<u8>,
}

impl PreparedInput {
    /// Returns the independently validated immutable input commitment.
    pub fn model_digest(&self) -> &[u8] {
        &self.model_digest
    }
}

/// Observes one accepted solve without controlling its lifetime by dropping it.
#[derive(Clone)]
pub struct Job {
    pub(crate) state: Arc<JobState>,
}

impl Job {
    /// Returns the session-local job identity.
    pub fn id(&self) -> u64 {
        self.state.id
    }

    /// Returns the current lifecycle without waiting.
    pub fn status(&self) -> JobStatus {
        match &*self.state.events.borrow() {
            JobEvent::Queued => JobStatus::Queued,
            JobEvent::Running => JobStatus::Running,
            JobEvent::Terminal(_) => JobStatus::Terminal,
            JobEvent::Expired => JobStatus::Expired,
        }
    }

    /// Requests cancellation; dropping this handle does not cancel computation.
    pub fn cancel(&self) -> bool {
        if matches!(self.status(), JobStatus::Terminal | JobStatus::Expired) {
            return false;
        }
        self.state.cancel.send_replace(true);
        true
    }

    /// Waits for a retained terminal result.
    ///
    /// # Errors
    /// Returns an expiry error if the terminal retention interval has ended.
    pub async fn wait(&self) -> Result<Arc<SolveResult>, RuntimeError> {
        let mut events = self.state.events.subscribe();
        loop {
            match &*events.borrow_and_update() {
                JobEvent::Terminal(result) => return Ok(result.clone()),
                JobEvent::Expired => return Err(RuntimeError::Expired),
                _ => {}
            }
            events.changed().await.map_err(|_| RuntimeError::Expired)?;
        }
    }
}

pub(crate) struct Inner {
    pub provider: Arc<dyn ExecutionProvider>,
    pub worker: WorkerLaunch,
    pub grant: ResourceGrant,
    pub profile: ExecutionProfile,
    pub expected_build: Option<String>,
    pub capabilities: Option<dispatch_protocol::wire::Capabilities>,
    pub limits: SessionLimits,
    pub generation: u64,
    pub next_worker: AtomicU64,
    pub slots: Arc<Semaphore>,
    pub state: Mutex<State>,
    pub changed: Notify,
    pub cancel_all: watch::Sender<bool>,
    pub frame_limit: AtomicU32,
    pub negotiated_capabilities: OnceLock<dispatch_protocol::wire::Capabilities>,
}

impl Inner {
    fn encoding_limit(&self) -> usize {
        self.limits
            .max_input_bytes
            .min(self.frame_limit.load(Ordering::Relaxed).saturating_sub(256) as usize)
    }
    pub fn lock(&self) -> Result<MutexGuard<'_, State>, RuntimeError> {
        self.state
            .lock()
            .map_err(|_| RuntimeError::Unsupported("session bookkeeping poisoned".into()))
    }

    pub async fn create_worker(
        &self,
        cleanup: &mut crate::lease::StartupCleanup,
    ) -> Result<ConnectedWorker, RuntimeError> {
        let generation = self
            .next_worker
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| RuntimeError::Unsupported("worker identity exhausted".into()))?;
        let mut launch = self.worker.clone();
        launch.worker_generation = generation;
        let connection = self.provider.launch(launch).await?;
        cleanup.control = Some(connection.control.clone());
        let worker = ConnectedWorker::negotiate(
            connection,
            self.generation,
            generation,
            self.limits.max_frame_bytes,
            self.expected_build.as_deref(),
        )
        .await?;
        if let Some(manifest) = &self.capabilities {
            let mut expected = manifest.clone();
            let mut actual = worker.capabilities.clone();
            expected.limits = None;
            actual.limits = None;
            if expected != actual {
                return Err(RuntimeError::Unsupported(
                    "live capabilities do not match trusted manifest".into(),
                ));
            }
        }
        Ok(worker)
    }

    fn submit_bytes(
        self: &Arc<Self>,
        bytes: Vec<u8>,
        options: SolveOptions,
        started: Instant,
    ) -> Result<Job, RuntimeError> {
        {
            let mut state = self.lock()?;
            let total = state
                .input_bytes
                .checked_add(bytes.capacity())
                .ok_or(RuntimeError::Overloaded("input bytes"))?;
            if total > self.limits.max_input_bytes {
                return Err(RuntimeError::Overloaded("input bytes"));
            }
            state.input_bytes = total;
        }
        let input = Arc::new(Input {
            bytes,
            inner: Arc::downgrade(self),
            binding: OnceLock::new(),
        });
        self.submit_input(input, options, started)
    }

    fn submit_input(
        self: &Arc<Self>,
        input: Arc<Input>,
        mut options: SolveOptions,
        started: Instant,
    ) -> Result<Job, RuntimeError> {
        if options.threads == 0 {
            return Err(RuntimeError::Unsupported(
                "native thread count must be positive".into(),
            ));
        }
        let deadline = started
            .checked_add(options.deadline)
            .ok_or_else(|| RuntimeError::Unsupported("deadline exceeds clock range".into()))?;
        let hint = match options.hint.take() {
            Some(hint) => {
                let bytes = crate::encoding::encode(&hint, self.encoding_limit())?;
                let mut state = self.lock()?;
                let total = state
                    .input_bytes
                    .checked_add(bytes.capacity())
                    .ok_or(RuntimeError::Overloaded("hint bytes"))?;
                if total > self.limits.max_input_bytes {
                    return Err(RuntimeError::Overloaded("hint bytes"));
                }
                state.input_bytes = total;
                Some(Arc::new(Input {
                    bytes,
                    inner: Arc::downgrade(self),
                    binding: OnceLock::new(),
                }))
            }
            None => None,
        };
        let frame_bytes = input
            .bytes
            .len()
            .checked_add(hint.as_ref().map_or(0, |hint| hint.bytes.len()))
            .and_then(|size| size.checked_add(256))
            .ok_or(RuntimeError::Overloaded("request frame bytes"))?;
        if frame_bytes > self.frame_limit.load(Ordering::Relaxed) as usize {
            return Err(RuntimeError::Overloaded("request frame bytes"));
        }
        let job = {
            let mut state = self.lock()?;
            if state.closed {
                return Err(RuntimeError::Closed);
            }
            if state.pending >= self.limits.max_pending {
                return Err(RuntimeError::Overloaded("pending requests"));
            }
            if state.retained >= self.limits.max_retained_results {
                return Err(RuntimeError::Overloaded("terminal reservations"));
            }
            let id = state.next_id()?;
            let (events, _) = watch::channel(JobEvent::Queued);
            let (cancel, _) = watch::channel(false);
            let job = Arc::new(JobState { id, events, cancel });
            state.pending += 1;
            state.retained += 1;
            state.active_jobs += 1;
            state.jobs.insert(id, Arc::downgrade(&job));
            job
        };
        tokio::spawn(crate::scheduler::execute(
            self.clone(),
            job.clone(),
            input,
            hint,
            options,
            deadline,
        ));
        Ok(Job { state: job })
    }
}

struct Owner {
    inner: Arc<Inner>,
    capabilities: dispatch_protocol::wire::Capabilities,
}

impl Drop for Owner {
    fn drop(&mut self) {
        let (idle, prepared) = if let Ok(mut state) = self.inner.state.lock() {
            state.closed = true;
            state.cancel_jobs();
            self.inner.cancel_all.send_replace(true);
            (
                std::mem::take(&mut state.idle),
                std::mem::take(&mut state.prepared),
            )
        } else {
            return;
        };
        drop(prepared);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            for worker in idle {
                let control = worker.connection.control.clone();
                drop(worker);
                runtime.spawn(crate::lease::cleanup(self.inner.clone(), control, None));
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct State {
    pub closed: bool,
    pub pending: usize,
    pub input_bytes: usize,
    pub retained: usize,
    pub active_jobs: usize,
    pub completed_jobs: usize,
    pub unconfirmed_workers: usize,
    next_id: u64,
    prepared: BTreeMap<u64, Arc<Input>>,
    preparing: usize,
    pub jobs: BTreeMap<u64, Weak<JobState>>,
    pub idle: Vec<ConnectedWorker>,
}

impl State {
    fn next_id(&mut self) -> Result<u64, RuntimeError> {
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| RuntimeError::Unsupported("job identity exhausted".into()))?;
        Ok(self.next_id)
    }

    fn cancel_jobs(&self) {
        for job in self.jobs.values().filter_map(Weak::upgrade) {
            job.cancel.send_replace(true);
        }
    }
}

pub(crate) struct Input {
    pub bytes: Vec<u8>,
    inner: Weak<Inner>,
    pub binding: OnceLock<PreparedBinding>,
}

pub(crate) struct PreparedBinding {
    pub digest: Vec<u8>,
    pub basis: std::collections::BTreeMap<String, String>,
}

struct PreparationAccounting {
    inner: Arc<Inner>,
    queued: bool,
    finished: bool,
}

impl Drop for PreparationAccounting {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Ok(mut state) = self.inner.state.lock() {
            state.preparing = state.preparing.saturating_sub(1);
            if self.queued {
                state.pending = state.pending.saturating_sub(1);
            }
            state.active_jobs = state.active_jobs.saturating_sub(1);
        }
        self.inner.changed.notify_waiters();
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade()
            && let Ok(mut state) = inner.state.lock()
        {
            state.input_bytes = state.input_bytes.saturating_sub(self.bytes.capacity());
        }
    }
}

pub(crate) struct JobState {
    pub id: u64,
    pub events: watch::Sender<JobEvent>,
    pub cancel: watch::Sender<bool>,
}

#[derive(Clone)]
pub(crate) enum JobEvent {
    Queued,
    Running,
    Terminal(Arc<SolveResult>),
    Expired,
}
