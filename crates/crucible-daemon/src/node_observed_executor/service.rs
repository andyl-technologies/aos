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

mod capability_preparation;
mod debug;
mod debug_preserving;
pub use debug_preserving::{
    NodePreservingDebugAction, NodePreservingDebugCapture, NodePreservingDebugRecord,
    NodePreservingDebugRequest, NodePreservingDebugResumeRequest, NodePreservingDebugState,
};
mod original_claim;
mod root_preparation;
use root_preparation::ledger::RootPreparationLedger;
pub use root_preparation::{
    RootFirstRefusal, RootGrantedOperation, RootPreparationAction, RootPreparationDiagnostic,
    RootPreparationRecord, RootPreparationRequest, RootPreparationState,
};
mod original_lineage;
mod replay;

#[cfg(test)]
#[path = "service/status_tests.rs"]
mod status_tests;

use capability_preparation::ledger::CapabilityPreparationLedger;
pub use capability_preparation::{
    CapabilityCandidateRecipe, CapabilityPreparationAction, CapabilityPreparationRecord,
    CapabilityPreparationRequest, CapabilityPreparationState,
};
use debug::{DebugLedger, DebugReservation, DebugWorker};
pub use debug::{
    NodeDebugRecord, NodeDebugResumeRequest, NodeDebugStartRequest, NodeDebugState, NodeDebugStop,
};
pub use original_lineage::OriginalLineageHostInstallation;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
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
    OriginalLineagePrepare {
        request: crate::node_control::NodeOriginalLineageRequest,
        reply: SyncSender<Result<(), NodeObservationServiceError>>,
    },
    PreservingDebugPrepare {
        request: NodePreservingDebugRequest,
        reservation: Box<debug_preserving::Reservation>,
        ledger: debug_preserving::Ledger,
    },
    PreservingDebugResume {
        request: NodePreservingDebugResumeRequest,
        reservation: Box<debug_preserving::Reservation>,
        ledger: debug_preserving::Ledger,
    },
    DebugStart {
        request: NodeDebugStartRequest,
        reservation: DebugReservation,
    },
    DebugResume {
        request: NodeDebugResumeRequest,
        reservation: DebugReservation,
    },
    RootPreparation {
        request: RootPreparationRequest,
        reservation: Box<root_preparation::ledger::RootReservation>,
        ledger: RootPreparationLedger,
    },
    CapabilityPreparation {
        request: CapabilityPreparationRequest,
        reservation: Box<capability_preparation::ledger::CapabilityReservation>,
        ledger: CapabilityPreparationLedger,
    },
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
}

struct ActorWorker {
    worker: ObservedAttemptWorker<NodeObservedBackend>,
    request: crucible_campaign::observed_node_attempt::ObservedAttemptRequest,
    admission: super::NodeObservedAdmission,
    replay: Option<replay::ReplaySubmission>,
}

struct RootWorker {
    worker: root_preparation::worker::Worker,
    reservation: Box<root_preparation::ledger::RootReservation>,
    ledger: RootPreparationLedger,
}

struct ActorStorage {
    root_installation: root_preparation::worker::Installation,
    capability_installation: capability_preparation::group::Installation,
    capability_archive: PathBuf,
    condition_archive: PathBuf,
    preparations: Option<ConditionalPreparationLedger>,
    capabilities: CapabilityPreparationLedger,
    debug: DebugLedger,
    preserving_debug: debug_preserving::Ledger,
    root_preparations: RootPreparationLedger,
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
    capabilities: CapabilityPreparationLedger,
    debug: DebugLedger,
    preserving_debug: debug_preserving::Ledger,
    root_preparations: RootPreparationLedger,
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
        roots.extend(self.capabilities.retention_roots()?);
        roots.extend(self.debug.retention_roots()?);
        roots.extend(self.preserving_debug.retention_roots()?);
        roots.extend(self.root_preparations.retention_roots()?);
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
    repository: Arc<CampaignRepository>,
    commands: SyncSender<Command>,
    stopping: Arc<AtomicBool>,
    roots: Arc<Mutex<BTreeSet<ContentId>>>,
    retired: Arc<AtomicBool>,
    preparations: Option<ConditionalPreparationLedger>,
    capabilities: CapabilityPreparationLedger,
    debug: DebugLedger,
    preserving_debug: debug_preserving::Ledger,
    root_preparations: RootPreparationLedger,
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
        Self::start_inner_original(configuration, transcripts, None, repository, blobs, refs)
    }

    fn start_inner_original(
        configuration: NodeObservationServiceConfig,
        transcripts: Option<crucible::node_adapters::transcript::TranscriptArchive>,
        original: Option<OriginalLineageHostInstallation>,
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
        let capabilities = CapabilityPreparationLedger::new(blobs.clone(), refs.clone())?;
        let actor_capabilities = capabilities.clone();
        let debug = DebugLedger::new(blobs.clone(), refs.clone())?;
        let actor_debug = debug.clone();
        let preserving_debug = debug_preserving::Ledger::new(blobs.clone(), refs.clone())?;
        let actor_preserving_debug = preserving_debug.clone();
        let root_preparations = RootPreparationLedger::new(blobs.clone(), refs.clone())?;
        let actor_root_preparations = root_preparations.clone();
        let root_installation =
            root_preparation::worker::Installation::from_configuration(&configuration)?;
        let capability_installation =
            capability_preparation::group::Installation::from_configuration(&configuration);
        let capability_archive = configuration.socket_parent.join("capability-clock-archive");
        let condition_archive = configuration
            .socket_parent
            .join("condition-preserving-archive");
        let (commands, receiver) = mpsc::sync_channel(configuration.maximum_pending_requests);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let stopping = Arc::new(AtomicBool::new(false));
        let roots = Arc::new(Mutex::new(BTreeSet::new()));
        let actor_stopping = Arc::clone(&stopping);
        let actor_roots = Arc::clone(&roots);
        let retired = Arc::new(AtomicBool::new(false));
        let actor_retired = Arc::clone(&retired);
        let actor_preparations = preparations.clone();
        let actor_repository = Arc::clone(&repository);
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
                    if let Some(original) = original {
                        catalog
                            .install_behavioral_acceptance(original.behavioral, original.limits)?;
                        catalog.install_original_lineage_authority(original.source)?;
                    }
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
                                capabilities: actor_capabilities,
                                debug: actor_debug,
                                preserving_debug: actor_preserving_debug,
                                root_preparations: actor_root_preparations,
                                root_installation,
                                capability_installation,
                                capability_archive,
                                condition_archive,
                                transcripts,
                                repository: actor_repository,
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
            repository,
            commands,
            stopping,
            roots,
            retired,
            preparations,
            capabilities,
            debug,
            preserving_debug,
            root_preparations,
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
        if self.stopping.load(Ordering::Acquire) {
            return Err(NodeObservationServiceError::Unavailable);
        }
        // Native polling can hold the owning actor across a complete transport
        // exchange. The repository authenticates the original reservation and
        // ledger under its own GC fence; reading it grants no dispatch permit.
        self.repository
            .observed_execution_state(execution)
            .map_err(refused)?
            .ok_or_else(|| refused("execution has no authoritative observation record"))
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
            capabilities: self.capabilities.clone(),
            debug: self.debug.clone(),
            preserving_debug: self.preserving_debug.clone(),
            root_preparations: self.root_preparations.clone(),
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
    let mut debug_workers: BTreeMap<ExecutionId, DebugWorker> = BTreeMap::new();
    let mut preserving_workers = debug_preserving::actor::Workers::new();
    let mut root_workers: BTreeMap<ExecutionId, RootWorker> = BTreeMap::new();
    let mut retired_roots: BTreeMap<ExecutionId, BTreeSet<ContentId>> = BTreeMap::new();
    let mut capability_lanes = capability_preparation::group::Lanes::new();
    // Original lifetime debit bounds map plus fallback together. Reserve the
    // complete fallback before accepting any fallible ownership transfer.
    let mut held_refusals =
        VecDeque::with_capacity(capability_preparation::ledger::MAXIMUM_RECORDS);
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
                    match command {
                        Command::CapabilityPreparation {
                            request,
                            reservation,
                            ledger,
                        } if capability_preparation::group::Lanes::selects(&request) => {
                            let occupied = workers.len()
                                + debug_workers.len()
                                + preserving_workers.len()
                                + root_workers.len()
                                + retired_roots.len()
                                + capability_lanes.len();
                            // Excess requests only reconcile their original
                            // data reservation. They never prepare native owners.
                            let available = if held_refusals.is_empty() {
                                maximum_worlds
                            } else {
                                0
                            };
                            let admission = crate::node_control::execution_id(&request.execution)
                                .map_err(refused)
                                .and_then(|execution| {
                                    require_grouped_preparation_capacity(
                                        &catalog, execution, available, occupied,
                                    )
                                });
                            let lane_stopping = if admission.is_err() {
                                Arc::new(AtomicBool::new(true))
                            } else {
                                stopping.clone()
                            };
                            let rejected = capability_lanes.start(
                                request,
                                *reservation,
                                ledger,
                                &storage,
                                lane_stopping,
                            );
                            if let Some(original) = rejected {
                                // Originals cannot be cloned or redispatched: the
                                // same 4096 lifetime debit covers map and fallback.
                                // This move uses already reserved holder capacity.
                                held_refusals.push_back(original);
                            }
                        }
                        command => handle_command(
                            command,
                            ActorOwners {
                                workers: &mut workers,
                                debug_workers: &mut debug_workers,
                                preserving_workers: &mut preserving_workers,
                                root_workers: &mut root_workers,
                            },
                            &mut catalog,
                            if held_refusals.is_empty() {
                                maximum_worlds
                                    .saturating_sub(retired_roots.len() + capability_lanes.len())
                            } else {
                                // Fence new owners, while existing-owner control
                                // still passes through the ordinary dispatcher.
                                0
                            },
                            &storage,
                        ),
                    }
                }
            }))
            .is_err()
        {
            stopping.store(true, Ordering::Release);
        }
        if catch_unwind(AssertUnwindSafe(|| {
            capability_lanes.poll(&mut held_refusals);
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
        debug::poll_owned(&mut debug_workers, &storage, &stopping);
        debug_preserving::actor::poll(&mut preserving_workers, &mut catalog, &storage, &stopping);
        let finished_debug: Vec<_> = debug_workers
            .iter()
            .filter_map(|(execution, owned)| {
                (owned.published
                    && (stopping.load(Ordering::Acquire)
                        || matches!(owned.outcome, Some(NodeDebugState::Resumed { .. }))))
                .then_some(*execution)
            })
            .collect();
        for execution in finished_debug {
            retired_roots.insert(execution, BTreeSet::new());
            if catch_unwind(AssertUnwindSafe(|| {
                debug_workers.remove(&execution);
            }))
            .is_err()
            {
                stopping.store(true, Ordering::Release);
            }
        }
        let mut completed_roots = Vec::new();
        for (execution, owned) in &mut root_workers {
            if catch_unwind(AssertUnwindSafe(|| {
                if let std::task::Poll::Ready(Ok(outcome)) = owned
                    .worker
                    .poll(&mut context, stopping.load(Ordering::Acquire))
                {
                    owned.ledger.complete(&owned.reservation, outcome)?;
                    completed_roots.push(*execution);
                }
                Ok::<(), NodeObservationServiceError>(())
            }))
            .is_err()
            {
                owned.worker.retain_unwind_diagnostic();
                stopping.store(true, Ordering::Release);
            }
        }
        for execution in completed_roots {
            root_workers.remove(&execution);
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
            if stopping.load(Ordering::Acquire) {
                catalog.retire_original_lineage_preparations();
            }
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
                    root_workers
                        .values()
                        .flat_map(|owned| owned.worker.retention_roots()),
                )
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
        if stopping.load(Ordering::Acquire)
            && workers.is_empty()
            && preserving_workers.is_empty()
            && debug_workers.is_empty()
            && root_workers.is_empty()
            && capability_lanes.is_empty()
            && held_refusals.is_empty()
            && reclaimed
        {
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

/// Borrows the original owner maps for one dispatch without moving their custody.
struct ActorOwners<'a> {
    workers: &'a mut BTreeMap<ExecutionId, ActorWorker>,
    debug_workers: &'a mut BTreeMap<ExecutionId, DebugWorker>,
    preserving_workers: &'a mut debug_preserving::actor::Workers,
    root_workers: &'a mut BTreeMap<ExecutionId, RootWorker>,
}

/// Rejects operational reuse of every retained original source nonce.
///
/// # Errors
/// Refuses a nonce owned by original-lineage custody, including a retired
/// capsule whose once-only dispatch tombstone remains in the catalog.
pub(in crate::node_observed_executor) fn require_unowned_original_lineage_execution(
    catalog: &InstalledNodeCatalog,
    execution: ExecutionId,
) -> Result<(), NodeObservationServiceError> {
    if catalog.owns_original_lineage_execution(execution) {
        return Err(refused(
            "execution belongs to original-lineage preparation custody",
        ));
    }
    Ok(())
}

/// Reserves actor capacity for complete inactive or refused original capsules.
pub(in crate::node_observed_executor) fn original_lineage_available_worlds(
    catalog: &InstalledNodeCatalog,
    maximum_worlds: usize,
) -> usize {
    maximum_worlds.saturating_sub(catalog.original_lineage_preparation_count())
}

/// Checks retained original ownership and shared capacity before a grouped lane.
///
/// # Errors
/// Refuses a source-owned original nonce or capacity already spent by complete
/// inactive/refused source capsules and other actor owners. No preparation or
/// thread is constructed by this check.
pub(in crate::node_observed_executor) fn require_grouped_preparation_capacity(
    catalog: &InstalledNodeCatalog,
    execution: ExecutionId,
    maximum_worlds: usize,
    occupied: usize,
) -> Result<(), NodeObservationServiceError> {
    require_unowned_original_lineage_execution(catalog, execution)?;
    if occupied >= original_lineage_available_worlds(catalog, maximum_worlds) {
        return Err(refused("finite native world capacity unavailable"));
    }
    Ok(())
}

fn handle_command(
    command: Command,
    owners: ActorOwners<'_>,
    catalog: &mut InstalledNodeCatalog,
    maximum_worlds: usize,
    storage: &ActorStorage,
) {
    let original_execution = match &command {
        Command::DebugStart { request, .. } => {
            crate::node_control::execution_id(&request.execution).ok()
        }
        Command::DebugResume { request, .. } => {
            crate::node_control::execution_id(&request.execution).ok()
        }
        Command::PreservingDebugPrepare { request, .. } => {
            crate::node_control::execution_id(&request.execution).ok()
        }
        Command::PreservingDebugResume { request, .. } => {
            crate::node_control::execution_id(&request.execution).ok()
        }
        Command::RootPreparation { request, .. } => {
            crate::node_control::execution_id(&request.execution).ok()
        }
        Command::CapabilityPreparation { request, .. } => {
            crate::node_control::execution_id(&request.execution).ok()
        }
        Command::ConditionalPreparation { request, .. } => {
            crate::node_control::execution_id(&request.execution).ok()
        }
        Command::OriginalLineagePrepare { request, .. } => {
            crate::node_control::execution_id(&request.execution).ok()
        }
        Command::Submit { execution, .. } => Some(*execution),
        Command::ConditionalReplay { request, .. } => Some(request.execution),
        Command::CacheReuse { .. } | Command::Compile { .. } => None,
    };
    if let Some(execution) = original_execution
        && let Err(error) = require_unowned_original_lineage_execution(catalog, execution)
    {
        reply_refusal(command, error);
        return;
    }
    // Inactive and refused source capsules spend the same actor world credit
    // as every ordinary route. Deduct them once before route-specific owners.
    let maximum_worlds = original_lineage_available_worlds(catalog, maximum_worlds);
    let ActorOwners {
        workers,
        debug_workers,
        preserving_workers,
        root_workers,
    } = owners;

    match command {
        Command::PreservingDebugPrepare {
            request,
            reservation,
            ..
        } => {
            debug_preserving::actor::prepare(
                request,
                *reservation,
                preserving_workers,
                workers.len() + debug_workers.len() + root_workers.len(),
                maximum_worlds,
                storage,
            );
        }
        Command::PreservingDebugResume {
            request,
            reservation,
            ..
        } => {
            debug_preserving::actor::resume(request, *reservation, preserving_workers, storage);
        }
        Command::DebugStart {
            request,
            reservation,
        } => {
            debug::start_owned(
                request,
                reservation,
                workers,
                debug_workers,
                catalog,
                maximum_worlds.saturating_sub(root_workers.len() + preserving_workers.len()),
                storage,
            );
        }
        Command::DebugResume {
            request,
            reservation,
        } => {
            debug::resume_owned(request, reservation, debug_workers, storage);
        }
        command => {
            handle_other_command(
                command,
                workers,
                root_workers,
                catalog,
                maximum_worlds.saturating_sub(debug_workers.len() + preserving_workers.len()),
                storage,
            );
        }
    }
}

fn handle_other_command(
    command: Command,
    workers: &mut BTreeMap<ExecutionId, ActorWorker>,
    root_workers: &mut BTreeMap<ExecutionId, RootWorker>,
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
    let binary_execution = match &command {
        Command::Submit { execution, .. } => Some(*execution),
        Command::ConditionalReplay { request, .. } => Some(request.execution),
        _ => None,
    };
    if binary_execution.is_some_and(|execution| catalog.owns_original_lineage_execution(execution))
    {
        reply_refusal(
            command,
            refused("execution belongs to original-lineage preparation custody"),
        );
        return;
    }
    let original_execution = match &command {
        Command::CapabilityPreparation { request, .. } => Some(request.execution.clone()),
        Command::ConditionalPreparation { request, .. } => Some(request.execution.clone()),
        Command::Submit { execution, .. } => {
            Some(capability_preparation::execution_text(*execution))
        }
        Command::ConditionalReplay { request, .. } => {
            Some(capability_preparation::execution_text(request.execution))
        }
        _ => None,
    };
    if let Some(execution) = original_execution {
        match storage.preserving_debug.owns(&execution) {
            Ok(false) => {}
            Ok(true) => {
                reply_refusal(
                    command,
                    refused("execution belongs to original preserving Debug custody"),
                );
                return;
            }
            Err(error) => {
                reply_refusal(command, error);
                return;
            }
        }
        match storage.root_preparations.owns(&execution) {
            Ok(false) => {}
            Ok(true) => {
                reply_refusal(
                    command,
                    refused("execution belongs to original Root custody"),
                );
                return;
            }
            Err(error) => {
                reply_refusal(command, error);
                return;
            }
        }
    }
    // Root workers retain their own native reservation until positive retirement.
    // Other routes cannot spend those same aggregate live-world slots.
    let available_worlds = maximum_worlds.saturating_sub(root_workers.len());
    match command {
        command @ (Command::DebugStart { .. }
        | Command::DebugResume { .. }
        | Command::PreservingDebugPrepare { .. }
        | Command::PreservingDebugResume { .. }) => {
            reply_refusal(command, refused("Debug command bypassed owning dispatch"));
        }
        Command::RootPreparation {
            request,
            reservation,
            ledger,
        } => {
            let result = (|| {
                let execution = root_preparation::execution_id(&request.execution)?;
                if workers.contains_key(&execution)
                    || repository
                        .observed_execution_state(execution)
                        .map_err(refused)?
                        .is_some()
                    || root_workers.len() + workers.len() >= maximum_worlds
                {
                    return Err(refused(
                        "Root original nonce or finite live-world capacity is occupied",
                    ));
                }
                let mut journal = root_preparation::diagnostics::Journal::new(
                    ledger.clone(),
                    &reservation.record,
                );
                journal.enter("construct_worker")?;
                let worker = root_preparation::worker::Worker::new(
                    request,
                    &storage.root_installation,
                    blobs.clone(),
                    refs.clone(),
                    journal,
                )?;
                Ok((execution, worker))
            })();
            match result {
                Ok((execution, worker)) => {
                    root_workers.insert(
                        execution,
                        RootWorker {
                            worker,
                            reservation,
                            ledger,
                        },
                    );
                }
                Err(error) => {
                    let _ = ledger.complete(
                        &reservation,
                        RootPreparationState::Unavailable {
                            reason: root_preparation::diagnostic(error),
                        },
                    );
                }
            }
        }
        Command::CapabilityPreparation {
            request,
            reservation,
            ledger,
        } => {
            let result = capability_preparation::execute(
                request,
                workers,
                catalog,
                available_worlds,
                storage,
            );
            let outcome = result.unwrap_or_else(|error| CapabilityPreparationState::Unavailable {
                reason: error.to_string(),
            });
            let _ = ledger.complete(&reservation, outcome);
        }
        Command::ConditionalPreparation {
            request,
            reservation,
            ledger,
        } => {
            let result =
                conditional_preparation::execution_id(&request.execution).and_then(|execution| {
                    if storage.capabilities.owns(&request.execution)? {
                        return Err(refused(
                            "execution nonce belongs to original capability custody",
                        ));
                    }
                    replay::submit(
                        replay::ReplayRequest {
                            ledger: request.ledger,
                            execution,
                            sources: request.sources,
                            configuration: request.configuration.into_vec(),
                        },
                        workers,
                        catalog,
                        available_worlds,
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
        Command::OriginalLineagePrepare { request, reply } => {
            let result = (|| {
                // Both independently installed authorities are mandatory before any archive body read.
                catalog
                    .require_original_lineage_authorities()
                    .map_err(refused)?;
                let execution =
                    crate::node_control::execution_id(&request.execution).map_err(refused)?;
                if workers.contains_key(&execution)
                    || root_workers.contains_key(&execution)
                    || repository
                        .observed_execution_state(execution)
                        .map_err(refused)?
                        .is_some()
                    || workers.len() + root_workers.len() >= maximum_worlds
                    || storage.capabilities.owns(&request.execution)?
                    || storage.root_preparations.owns(&request.execution)?
                    || storage.preserving_debug.owns(&request.execution)?
                {
                    return Err(refused(
                        "original-lineage nonce or complete world capacity occupied",
                    ));
                }
                let archive = storage
                    .transcripts
                    .as_ref()
                    .ok_or_else(|| refused("original-lineage archive not installed"))?;
                let configuration =
                    NodeRunConfiguration::from_json(request.configuration.as_slice())
                        .map_err(refused)?;
                // The global durable claim also fences pending Debug/Conditional
                // reservations and unresolved publication across actor restart.
                original_lineage::reserve_original_claim(&request, blobs.clone(), refs.clone())?;
                catalog
                    .prepare_original_lineage(archive, execution, request.sources, configuration)
                    .map_err(refused)
            })();
            let _ = reply.send(result);
        }
        Command::ConditionalReplay { request, reply } => {
            let result = storage
                .capabilities
                .owns(&capability_preparation::execution_text(request.execution))
                .and_then(|owned| {
                    if owned {
                        return Err(refused(
                            "execution nonce belongs to original capability custody",
                        ));
                    }
                    replay::submit(request, workers, catalog, available_worlds, storage, None)
                });
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
        Command::Submit {
            ledger,
            execution,
            selections,
            scenario,
            configuration,
            reply,
        } => {
            let result = (|| {
                if storage
                    .debug
                    .owns(&capability_preparation::execution_text(execution))?
                {
                    return Err(refused("execution belongs to original Debug custody"));
                }
                if storage
                    .capabilities
                    .owns(&capability_preparation::execution_text(execution))?
                {
                    return Err(refused(
                        "execution nonce belongs to original capability custody",
                    ));
                }
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
                if workers.len() >= available_worlds {
                    return Err(NodeObservationServiceError::Capacity);
                }
                let original_scope = crucible_node_contract::canonical::canonical_json(
                    &serde_json::json!({
                        "format": "crucible.ordinary-node-preparation-scope",
                        "version": 1,
                        "scenario": crucible_node_contract::Bytes::new(scenario.canonical_bytes().map_err(refused)?),
                        "configuration": configuration,
                    }),
                ).map_err(refused)?;
                let claims = original_claim::OriginalClaims::new(blobs.clone(), refs.clone())?;
                if claims.reserve(
                    &capability_preparation::execution_text(execution),
                    original_claim::Route::Ordinary,
                    &original_scope,
                )? != original_claim::Reservation::Original
                {
                    return Err(refused(
                        "ordinary preparation belongs to an original actor or unresolved claim",
                    ));
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
        Command::PreservingDebugPrepare {
            reservation,
            ledger,
            ..
        }
        | Command::PreservingDebugResume {
            reservation,
            ledger,
            ..
        } => {
            let _ = ledger.complete(
                &reservation,
                NodePreservingDebugState::Unknown {
                    reason: error.to_string(),
                },
                None,
            );
        }
        Command::DebugStart { .. } | Command::DebugResume { .. } => {
            // The durable original stays pending; restart cannot dispatch it.
        }
        Command::RootPreparation {
            reservation,
            ledger,
            ..
        } => {
            let _ = ledger.complete(
                &reservation,
                RootPreparationState::Unavailable {
                    reason: error.to_string(),
                },
            );
        }
        Command::CapabilityPreparation {
            reservation,
            ledger,
            ..
        } => {
            let _ = ledger.complete(
                &reservation,
                CapabilityPreparationState::Unavailable {
                    reason: error.to_string(),
                },
            );
        }
        Command::OriginalLineagePrepare { reply, .. } => {
            let _ = reply.send(Err(error));
        }
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
        Command::Submit { reply, .. } | Command::ConditionalReplay { reply, .. } => {
            let _ = reply.send(Err(error));
        }
    }
}

fn refused(error: impl std::fmt::Display) -> NodeObservationServiceError {
    NodeObservationServiceError::Refused(error.to_string().chars().take(4096).collect())
}
