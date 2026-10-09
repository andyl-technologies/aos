//! Bounded owning daemon actor for portable submissions and native cleanup.

use super::{
    InstalledIoArtifact, InstalledNodeCatalog, InstalledNodeSelection, NodeObservedBackend,
};
use crate::node_scenario::{MAX_NODE_SCENARIO_BYTES, NodeRunConfiguration, NodeScenario};
use crate::supervision::ProcessDeadline;
use crucible_campaign::{
    CampaignRepository, ExecutionId,
    observed_node_attempt::{ObservedAttemptState, ObservedAttemptWorker},
};
use crucible_cas::content_store::{ContentId, ImmutableBlobBackend, MutableRefBackend};
use crucible_node_contract::ContentRef;

mod replay;
use std::{
    collections::{BTreeMap, BTreeSet},
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender},
    },
    task::{Context, Waker},
    thread,
    time::Duration,
};

/// Configures host installation and finite execution/transport capacity.
pub struct NodeObservationServiceConfig {
    /// Retains independently enrolled private operator artifact paths and identities.
    pub installed_artifacts: Vec<InstalledIoArtifact>,
    /// Names the actual operator-qualified source-built native companion.
    pub device_executable: PathBuf,
    /// Binds its expected installed artifact bytes independently of provider claims.
    pub expected_device: ContentRef,
    /// Selects the private child socket parent on this current machine.
    pub socket_parent: PathBuf,
    /// Bounds one native control operation.
    pub control_timeout: Duration,
    /// Bounds simultaneously retained native worlds, including cleanup custody.
    pub maximum_worlds: usize,
    /// Bounds portable requests waiting for actor admission.
    pub maximum_pending_requests: usize,
}

/// Reports refused service admission, unavailable custody, or actor failure.
#[derive(Clone, Debug, thiserror::Error)]
pub enum NodeObservationServiceError {
    /// The service or owning actor is shutting down.
    #[error("node observation service is unavailable")]
    Unavailable,
    /// Finite queued/live-world capacity has been exhausted.
    #[error("node observation service capacity exhausted")]
    Capacity,
    /// Portable input, native authority, or durable storage refused the request.
    #[error("node observation service refused: {0}")]
    Refused(String),
}

#[path = "service/conditional_preparation.rs"]
mod conditional_preparation;
use conditional_preparation::ledger::{ConditionalPreparationLedger, PreparationReservation};
pub use conditional_preparation::{
    ConditionalPreparationRecord, ConditionalPreparationRequest, ConditionalPreparationState,
};

type Reply = SyncSender<Result<ObservedAttemptState, NodeObservationServiceError>>;

enum Command {
    CacheReuse {
        request: super::NodeCacheReuseRequest,
        reply: SyncSender<Result<super::NodeCacheReuseReceipt, NodeObservationServiceError>>,
    },
    ConditionalPreparation {
        request: ConditionalPreparationRequest,
        reservation: PreparationReservation,
        ledger: ConditionalPreparationLedger,
    },
    Compile {
        selections: Vec<InstalledNodeSelection>,
        reply: SyncSender<Result<Vec<u8>, NodeObservationServiceError>>,
    },
    Submit {
        ledger: String,
        execution: ExecutionId,
        selections: Vec<InstalledNodeSelection>,
        scenario: Vec<u8>,
        configuration: Vec<u8>,
        reply: Reply,
    },
    ConditionalReplay {
        request: replay::ReplayRequest,
        reply: Reply,
    },
    State {
        execution: ExecutionId,
        reply: Reply,
    },
}

struct ActorWorker {
    worker: ObservedAttemptWorker<NodeObservedBackend>,
    request: crucible_campaign::observed_node_attempt::ObservedAttemptRequest,
    admission: super::NodeObservedAdmission,
    replay: Option<replay::ReplaySubmission>,
}

struct ActorStorage {
    preparations: Option<ConditionalPreparationLedger>,
    transcripts: Option<crucible::node_adapters::transcript::TranscriptArchive>,
    repository: Arc<CampaignRepository>,
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
}

struct ActorControl {
    receiver: Receiver<Command>,
    stopping: Arc<AtomicBool>,
    roots: Arc<Mutex<BTreeSet<ContentId>>>,
    retired: Arc<AtomicBool>,
}

/// Retains GC inventory independently of the service submission handle.
///
/// A daemon registers this owner before admitting observations and keeps it
/// registered until [`Self::is_retired`] confirms authentic native cleanup.
/// Dropping submission handles never unregisters this separately owned fence.
#[derive(Clone)]
pub struct NodeObservationRetention {
    roots: Arc<Mutex<BTreeSet<ContentId>>>,
    retired: Arc<AtomicBool>,
    preparations: Option<ConditionalPreparationLedger>,
}

impl NodeObservationRetention {
    /// Reads active and cleanup-only roots under the caller's GC ref fence.
    ///
    /// # Errors
    /// Refuses a poisoned root mutex rather than representing an empty inventory.
    pub fn retention_roots(&self) -> Result<BTreeSet<ContentId>, NodeObservationServiceError> {
        let mut roots = self
            .roots
            .lock()
            .map_err(|_| refused("operational retention fence is poisoned"))?
            .clone();
        if let Some(preparations) = &self.preparations {
            roots.extend(preparations.retention_roots()?);
        }
        Ok(roots)
    }

    /// Reports that admission stopped and every original native world was reclaimed.
    #[must_use]
    pub fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }
}

/// Hosts non-`Send` native worlds inside one long-lived owning daemon actor.
///
/// Requests and results contain portable bytes only. Dropping the service stops
/// admission and contains every accepted original world. The detached owning
/// actor remains alive while authentic complete native reclamation is pending;
/// borrower destruction cannot discard cleanup, inputs, or original operation
/// commitments. GC inventories [`Self::retention_roots`] under its ref fence.
pub struct NodeObservationService {
    commands: SyncSender<Command>,
    stopping: Arc<AtomicBool>,
    roots: Arc<Mutex<BTreeSet<ContentId>>>,
    retired: Arc<AtomicBool>,
    preparations: Option<ConditionalPreparationLedger>,
}

impl NodeObservationService {
    /// Starts the local owning actor and verifies its installed native catalog.
    ///
    /// # Errors
    /// Refuses invalid bounds, thread startup, unavailable custody, or installation
    /// measurement failure before returning a usable submission capability.
    pub fn start(
        configuration: NodeObservationServiceConfig,
        repository: Arc<CampaignRepository>,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservationServiceError> {
        Self::start_inner(configuration, None, repository, blobs, refs)
    }

    fn start_inner(
        configuration: NodeObservationServiceConfig,
        transcripts: Option<crucible::node_adapters::transcript::TranscriptArchive>,
        repository: Arc<CampaignRepository>,
        blobs: Arc<dyn ImmutableBlobBackend>,
        refs: Arc<dyn MutableRefBackend>,
    ) -> Result<Self, NodeObservationServiceError> {
        if configuration.maximum_pending_requests == 0
            || configuration.maximum_pending_requests > 64
            || configuration.maximum_worlds == 0
            || configuration.maximum_worlds > 64
        {
            return Err(NodeObservationServiceError::Capacity);
        }
        let preparations = if transcripts.is_some() {
            Some(ConditionalPreparationLedger::new(
                blobs.clone(),
                refs.clone(),
            )?)
        } else {
            None
        };
        let (commands, receiver) = mpsc::sync_channel(configuration.maximum_pending_requests);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let stopping = Arc::new(AtomicBool::new(false));
        let roots = Arc::new(Mutex::new(BTreeSet::new()));
        let actor_stopping = Arc::clone(&stopping);
        let actor_roots = Arc::clone(&roots);
        let retired = Arc::new(AtomicBool::new(false));
        let actor_retired = Arc::clone(&retired);
        let actor_preparations = preparations.clone();
        thread::Builder::new()
            .name("crucible-node-observer".into())
            .spawn(move || {
                let catalog = InstalledNodeCatalog::new(
                    configuration.device_executable,
                    configuration.expected_device,
                    configuration.socket_parent,
                    configuration.control_timeout,
                    configuration.maximum_worlds,
                )
                .and_then(|mut catalog| {
                    catalog.install_artifacts(configuration.installed_artifacts)?;
                    Ok(catalog)
                });
                match catalog {
                    Ok(catalog) => {
                        let _ = ready_sender.send(Ok(()));
                        run_actor(
                            catalog,
                            configuration.maximum_worlds,
                            ActorStorage {
                                preparations: actor_preparations,
                                transcripts,
                                repository,
                                blobs,
                                refs,
                            },
                            ActorControl {
                                receiver,
                                stopping: actor_stopping,
                                roots: actor_roots,
                                retired: actor_retired,
                            },
                        );
                    }
                    Err(error) => {
                        let _ = ready_sender.send(Err(refused(error)));
                    }
                }
            })
            .map_err(refused)?;
        ready_receiver
            .recv()
            .map_err(|_| NodeObservationServiceError::Unavailable)??;
        Ok(Self {
            commands,
            stopping,
            roots,
            retired,
            preparations,
        })
    }

    /// Compiles a portable scenario using this owning daemon's installed catalog.
    ///
    /// No native world is allocated. The profile binds this daemon executable,
    /// so remote clients cannot substitute their own host implementation artifact.
    ///
    /// # Errors
    /// Refuses oversized selections, unavailable actor, or unsupported profiles.
    pub fn compile(
        &self,
        selections: Vec<InstalledNodeSelection>,
    ) -> Result<Vec<u8>, NodeObservationServiceError> {
        if selections.is_empty() || selections.len() > 64 {
            return Err(NodeObservationServiceError::Capacity);
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.send(Command::Compile { selections, reply })?;
        response
            .recv()
            .map_err(|_| NodeObservationServiceError::Unavailable)?
    }

    /// Admits and durably reserves one new native observation on the owning actor.
    ///
    /// Existing reservations owned by another incarnation never authorize a new
    /// native dispatch. Current-actor retries return the original retained state.
    /// The returned reservation does not promise deterministic replay.
    ///
    /// # Errors
    /// Refuses excessive portable bytes/rosters, bounded queue exhaustion,
    /// unavailable actor custody, changed input identities, or native admission.
    pub fn submit(
        &self,
        ledger: String,
        execution: ExecutionId,
        selections: Vec<InstalledNodeSelection>,
        scenario: Vec<u8>,
        configuration: Vec<u8>,
    ) -> Result<ObservedAttemptState, NodeObservationServiceError> {
        if scenario.len() > MAX_NODE_SCENARIO_BYTES
            || configuration.len() > 4096
            || selections.len() > 64
            || ledger.len() > 128
        {
            return Err(NodeObservationServiceError::Capacity);
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.send(Command::Submit {
            ledger,
            execution,
            selections,
            scenario,
            configuration,
            reply,
        })?;
        response
            .recv()
            .map_err(|_| NodeObservationServiceError::Unavailable)?
    }

    /// Reuses an authenticated original result after complete deterministic admission.
    ///
    /// No new native execution, permit, snapshot or observation nonce is created.
    ///
    /// # Errors
    /// Refuses changed installation/inputs, incomplete or corrupt original closure,
    /// nonrepeatable coupled owners, excessive requests, or unavailable custody.
    pub fn reuse_cache(
        &self,
        request: super::NodeCacheReuseRequest,
    ) -> Result<super::NodeCacheReuseReceipt, NodeObservationServiceError> {
        request.validate()?;
        let (reply, response) = mpsc::sync_channel(1);
        self.send(Command::CacheReuse { request, reply })?;
        response
            .recv()
            .map_err(|_| NodeObservationServiceError::Unavailable)?
    }

    /// Reads original durable state without launching or resuming native work.
    ///
    /// # Errors
    /// Refuses absent execution records, unavailable actor, or corrupt storage.
    pub fn state(
        &self,
        execution: ExecutionId,
    ) -> Result<ObservedAttemptState, NodeObservationServiceError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.send(Command::State { execution, reply })?;
        response
            .recv()
            .map_err(|_| NodeObservationServiceError::Unavailable)?
    }

    /// Inventories active immutable evidence under the caller's GC ref fence.
    ///
    /// No actor round trip is required while GC owns its exclusive fence. The
    /// actor mutates this inventory only while holding repository GC exclusion,
    /// preserving the existing ref-before-operational-owner lock order.
    ///
    /// # Errors
    /// Refuses a poisoned operational ownership fence instead of claiming emptiness.
    pub fn retention_roots(&self) -> Result<BTreeSet<ContentId>, NodeObservationServiceError> {
        self.retention_owner().retention_roots()
    }

    /// Copies the independent GC owner for registration before admission.
    #[must_use]
    pub fn retention_owner(&self) -> NodeObservationRetention {
        NodeObservationRetention {
            roots: self.roots.clone(),
            retired: self.retired.clone(),
            preparations: self.preparations.clone(),
        }
    }

    fn send(&self, command: Command) -> Result<(), NodeObservationServiceError> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(NodeObservationServiceError::Unavailable);
        }
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => NodeObservationServiceError::Capacity,
                mpsc::TrySendError::Disconnected(_) => NodeObservationServiceError::Unavailable,
            })
    }
}

impl Drop for NodeObservationService {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
    }
}

fn run_actor(
    mut catalog: InstalledNodeCatalog,
    maximum_worlds: usize,
    storage: ActorStorage,
    control: ActorControl,
) {
    let ActorStorage { repository, .. } = &storage;
    let ActorControl {
        receiver,
        stopping,
        roots,
        retired,
    } = control;
    let mut workers: BTreeMap<ExecutionId, ActorWorker> = BTreeMap::new();
    let mut retired_roots: BTreeMap<ExecutionId, BTreeSet<ContentId>> = BTreeMap::new();
    let mut context = Context::from_waker(Waker::noop());
    loop {
        let turn_deadline = ProcessDeadline::after(Duration::from_millis(1));
        let command = match receiver.recv_timeout(Duration::from_millis(1)) {
            Ok(command) => Some(command),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => {
                stopping.store(true, Ordering::Release);
                None
            }
        };
        // Keep the catalog, original workers and native retirement actor outside
        // unwind scopes. Native callbacks may panic, but the owning thread must
        // still contain and reclaim the exact retained world.
        let gc = repository.acquire_gc_exclusion_guard();
        if gc.is_err() {
            stopping.store(true, Ordering::Release);
        }
        if let Some(command) = command
            && catch_unwind(AssertUnwindSafe(|| {
                if stopping.load(Ordering::Acquire) {
                    // Refusal may persist original preparation custody through
                    // user-supplied storage. Its unwind must also leave the
                    // catalog and original workers with this owning actor.
                    reply_refusal(command, NodeObservationServiceError::Unavailable);
                } else {
                    handle_command(
                        command,
                        &mut workers,
                        &mut catalog,
                        maximum_worlds.saturating_sub(retired_roots.len()),
                        &storage,
                    );
                }
            }))
            .is_err()
        {
            stopping.store(true, Ordering::Release);
        }
        for (execution, owned) in &mut workers {
            let shutting_down = stopping.load(Ordering::Acquire);
            if catch_unwind(AssertUnwindSafe(|| {
                if shutting_down {
                    let _ = owned.worker.cancel(*execution);
                } else {
                    let _ = owned.worker.poll(*execution);
                }
            }))
            .is_err()
            {
                stopping.store(true, Ordering::Release);
            }
        }
        // Transfer finished native runtimes into the already reserved queue,
        // while retaining their immutable roots separately. Keeping the backend
        // value itself would keep its reservation live and prevent retirement.
        let finished: Vec<_> = workers
            .iter()
            .filter_map(|(execution, owned)| {
                (owned.worker.active_executions() == 0).then_some(*execution)
            })
            .collect();
        for execution in finished {
            if let Some(owned) = workers.get(&execution) {
                retired_roots.insert(execution, owned.worker.retention_roots());
            }
            if catch_unwind(AssertUnwindSafe(|| {
                workers.remove(&execution);
            }))
            .is_err()
            {
                stopping.store(true, Ordering::Release);
            }
        }
        if catch_unwind(AssertUnwindSafe(|| {
            let _ = catalog.custody().poll_reclamation(&mut context);
        }))
        .is_err()
        {
            stopping.store(true, Ordering::Release);
        }
        let reclaimed = catalog.custody().reserved_worlds() == 0;
        if gc.is_ok() {
            if reclaimed {
                retired_roots.clear();
            }
            let retained = workers
                .values()
                .flat_map(|owned| owned.worker.retention_roots())
                .chain(
                    retired_roots
                        .values()
                        .flat_map(|roots| roots.iter().copied()),
                )
                .collect();
            match roots.lock() {
                Ok(mut roots) => *roots = retained,
                Err(_) => {
                    stopping.store(true, Ordering::Release);
                }
            }
        }
        if stopping.load(Ordering::Acquire) && workers.is_empty() && reclaimed {
            retired.store(true, Ordering::Release);
            break;
        }
        drop(gc);
        // A disconnected command channel is immediately ready. The retirement
        // actor still needs a bounded timer to avoid spinning on unavailable
        // storage or a native provider that repeatedly panics during cleanup.
        if let Some(deadline) = turn_deadline {
            deadline.pause(Duration::from_millis(1));
        } else {
            thread::sleep(Duration::from_millis(1));
        }
    }
}

fn handle_command(
    command: Command,
    workers: &mut BTreeMap<ExecutionId, ActorWorker>,
    catalog: &mut InstalledNodeCatalog,
    maximum_worlds: usize,
    storage: &ActorStorage,
) {
    let ActorStorage {
        repository,
        blobs,
        refs,
        ..
    } = storage;
    match command {
        Command::ConditionalPreparation {
            request,
            reservation,
            ledger,
        } => {
            let result =
                conditional_preparation::execution_id(&request.execution).and_then(|execution| {
                    replay::submit(
                        replay::ReplayRequest {
                            ledger: request.ledger,
                            execution,
                            sources: request.sources,
                            configuration: request.configuration.into_vec(),
                        },
                        workers,
                        catalog,
                        maximum_worlds,
                        storage,
                        Some(&reservation),
                    )
                });
            let outcome = match result {
                Ok(original) => ConditionalPreparationState::Admitted {
                    observed_request: crucible_node_contract::Bytes::new(
                        original.request().canonical_bytes(),
                    ),
                },
                Err(_) => ConditionalPreparationState::Unavailable {},
            };
            // Failure keeps the original durable AwaitingAdmission record. No
            // replacement nonce or source request can acquire its dispatch.
            let _ = ledger.complete(&reservation, outcome);
        }
        Command::ConditionalReplay { request, reply } => {
            let result = replay::submit(request, workers, catalog, maximum_worlds, storage, None);
            let _ = reply.send(result);
        }
        Command::CacheReuse { request, reply } => {
            let _ = reply.send(super::cache_reuse::reuse(catalog, repository, &request));
        }
        Command::Compile { selections, reply } => {
            let result = catalog
                .scenario(&selections)
                .and_then(|scenario| {
                    scenario
                        .canonical_bytes()
                        .map_err(super::NodeObservedError::from)
                })
                .map_err(refused);
            let _ = reply.send(result);
        }
        Command::State { execution, reply } => {
            let result = repository
                .observed_execution_state(execution)
                .map_err(refused)
                .and_then(|state| {
                    state
                        .ok_or_else(|| refused("execution has no authoritative observation record"))
                });
            let _ = reply.send(result);
        }
        Command::Submit {
            ledger,
            execution,
            selections,
            scenario,
            configuration,
            reply,
        } => {
            let result = (|| {
                let scenario = NodeScenario::from_json(&scenario).map_err(refused)?;
                let configuration =
                    NodeRunConfiguration::from_json(&configuration).map_err(refused)?;
                let regenerated = catalog.scenario(&selections).map_err(refused)?;
                if scenario.canonical_bytes().map_err(refused)?
                    != regenerated.canonical_bytes().map_err(refused)?
                {
                    return Err(refused(
                        "submitted scenario differs from complete installed selection",
                    ));
                }
                if let Some(owned) = workers.get_mut(&execution) {
                    if scenario.artifact().map_err(refused)?
                        != *owned.worker.backend().scenario_artifact()
                        || configuration.artifact(&scenario).map_err(refused)?
                            != *owned.worker.backend().configuration_artifact()
                    {
                        return Err(refused(
                            "execution retry changed original scenario/configuration bytes",
                        ));
                    }
                    return owned
                        .worker
                        .submit(&ledger, &owned.request, &owned.admission)
                        .map_err(refused);
                }
                if let Some(original) = repository
                    .observed_execution_state(execution)
                    .map_err(refused)?
                {
                    catalog
                        .authenticate_recorded(&scenario, &configuration, original.request())
                        .map_err(refused)?;
                    return Ok(original);
                }
                if workers.len() >= maximum_worlds {
                    return Err(NodeObservationServiceError::Capacity);
                }
                let backend = catalog
                    .prepare(
                        &selections,
                        scenario,
                        configuration,
                        execution,
                        blobs.clone(),
                        refs.clone(),
                    )
                    .map_err(refused)?;
                let scenario = backend.scenario_artifact();
                repository
                    .publish_scenario_artifact(
                        scenario.scenario(),
                        scenario.payload_schema(),
                        scenario.payload().to_vec(),
                    )
                    .map_err(refused)?;
                let configuration = backend.configuration_artifact();
                repository
                    .publish_configuration_artifact(
                        configuration.scenario(),
                        configuration.scenario_artifact(),
                        configuration.configuration(),
                        configuration.payload_schema(),
                        configuration.payload().to_vec(),
                    )
                    .map_err(refused)?;
                let request = backend.request(execution).map_err(refused)?;
                let admission = backend.admission().clone();
                let worker =
                    ObservedAttemptWorker::new(repository.clone(), backend, 1).map_err(refused)?;
                workers.insert(
                    execution,
                    ActorWorker {
                        worker,
                        request,
                        admission,
                        replay: None,
                    },
                );
                let owned = workers
                    .get_mut(&execution)
                    .ok_or_else(|| refused("new original worker custody disappeared"))?;
                owned
                    .worker
                    .submit(&ledger, &owned.request, &owned.admission)
                    .map_err(refused)
            })();
            let _ = reply.send(result);
        }
    }
}

fn reply_refusal(command: Command, error: NodeObservationServiceError) {
    match command {
        Command::CacheReuse { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        Command::ConditionalPreparation {
            reservation,
            ledger,
            ..
        } => {
            let _ = ledger.complete(&reservation, ConditionalPreparationState::Unavailable {});
        }
        Command::Compile { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        Command::State { reply, .. }
        | Command::Submit { reply, .. }
        | Command::ConditionalReplay { reply, .. } => {
            let _ = reply.send(Err(error));
        }
    }
}

fn refused(error: impl std::fmt::Display) -> NodeObservationServiceError {
    NodeObservationServiceError::Refused(error.to_string().chars().take(4096).collect())
}
