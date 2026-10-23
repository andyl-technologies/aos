//! Serializes durable metadata pins and index repair in a physical native worker.
//!
//! A reservation snapshot precedes metadata synchronization. A second snapshot
//! records the actual manifest and whole-pack pins only after pack/index/parent
//! synchronization succeeds. Holds and source descriptors remain owned after a
//! cancelled request or late failure; recovery must reconcile them before reuse.

use super::{NativeCachePreparation, index_io::open_regular_at};
use crate::host_cache::owner::RETAINED_LEASE_DEADLINE;
use crate::{
    host_cache::{
        DerivedIndexRepair, NativeHostLayout, NativeHostMetadataReader, NativeManifestSource,
    },
    host_quota::{NativeProject, synchronized_allocated_bytes},
    publisher_local::client::Client,
};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, openat};
use std::{
    collections::BTreeMap,
    fs::{File, Metadata},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    sync::{Arc, Mutex, mpsc},
};
use terrane_format::identity::{Identity, IdentityKind};
use terrane_sdk::{
    host::{
        cache::{CacheState, HostDomainLocation, LeaseRecord, PinRecord, ReservationRecord},
        publication::PublicationClaim,
    },
    store::{ByteRange, TokioLocalFs},
};
use tokio::sync::oneshot;

mod cache_metadata;
mod executor;
pub(super) mod index_repair;
use index_repair::IndexRepairCustody;
mod manifest;
mod recovery_manifest;
pub(super) use executor::NativeOwnerExecutor;
pub(crate) use executor::{
    PublisherCacheRetirementTurn, PublisherCleanupTurn, PublisherCorruptionTurn,
    PublisherResumeTurn, PublisherRunningTurn,
};
pub(crate) use recovery_manifest::{
    AcceptedRecoveryManifestEffect, RecoveryManifestBackingRetention, RecoveryManifestBodyFailure,
    RecoveryManifestBodyRetention, RecoveryManifestEffect, RecoveryManifestEffectFailure,
    RecoveryRetainedManifest,
};

/// Retains a native queue for durable metadata pins and missing-index repair.
///
/// This owner admits verified encoded chunks and metadata pairs only after
/// actual recovery and acknowledged publisher Resume. Funded inline and manifest
/// publication, coordinated standalone transfer and bounded retained-range reads
/// use the same physical queue. Durable consumer leases use bounded immutable
/// read views, renewal, release grace and periodic expiry. Cache maintenance
/// coordinates original cached-body retirement and restoration; full tier
/// serving readiness remains separate. Sealed read integrity or custody failures
/// deny every registered alias of that incarnation and report through bounded
/// original custody, independently of command-queue capacity. The physical
/// owner quarantines the original inode and faults writes while retaining pins
/// and reservations for reconciliation.
/// Cold records remain untrusted candidates until recovery reconciles
/// them. Dropping an awaiting request does not cancel physical execution.
pub struct NativeMetadataOwner {
    #[cfg(feature = "surface-fuse")]
    pub(super) surface_policy: Option<super::SurfaceIndexPolicy>,
    /// Immutable validated request bounds copied before the worker starts.
    pub(super) admission_bounds: super::admission::AdmissionBounds,
    /// Copies the validated immutable profile for independent lower-tier verification.
    pub(super) chunk_profile: terrane_format::chunking::ChunkProfile,
    /// Bounded admission to physical work retained independently of reply waiters.
    pub(super) commands: Option<mpsc::SyncSender<Command>>,
    /// Shares the actual finite read budget with this worker's original views.
    pub(super) consumer_reads: Arc<super::consumer::ReadBudget>,
    worker: Option<std::thread::JoinHandle<()>>,
}

/// Transfers complete command ownership to the retained physical executor.
pub(super) enum Command {
    /// Checks the original acknowledged worker without admitting or releasing content.
    CheckRunning {
        response: oneshot::Sender<io::Result<()>>,
    },
    /// Observes current policy and freshly authenticated project usage.
    Status {
        response: oneshot::Sender<io::Result<super::NativeCacheStatus>>,
    },
    #[cfg(feature = "surface-fuse")]
    SurfaceExposure(super::surface_index::exposure::Request),
    #[cfg(feature = "surface-fuse")]
    ReconcileSurfaceExposure {
        id: String,
        generation: u64,
        response: oneshot::Sender<io::Result<bool>>,
    },
    #[cfg(feature = "surface-fuse")]
    ReconcileDrainingSurfaceExposures {
        response: oneshot::Sender<io::Result<super::NativeExposureReconciliation>>,
    },
    #[cfg(feature = "surface-fuse")]
    EvictSurfaceIndex {
        draining: bool,
        key: crate::structural_index::IndexKey,
        response: oneshot::Sender<io::Result<bool>>,
    },
    #[cfg(feature = "surface-fuse")]
    CacheSurfaceIndex {
        root: terrane_format::identity::Digest,
        nodes: BTreeMap<terrane_format::identity::Digest, Vec<u8>>,
        domain: Option<String>,
        response: oneshot::Sender<io::Result<super::NativeSurfaceIndex>>,
    },
    /// Selects and retires original cached allocations using measured project pressure.
    EvictCache {
        incoming: u64,
        response: oneshot::Sender<io::Result<super::NativeCacheEvictionReport>>,
    },
    /// Transfers an owned consumer lifecycle operation to the physical worker.
    Consumer(super::consumer::ConsumerCommand),
    /// Holds actual embedded policy only in explicitly enabled native fixtures.
    #[cfg(feature = "native-test-fixtures")]
    HoldPolicyForFixture {
        started: oneshot::Sender<io::Result<()>>,
        released: mpsc::Receiver<()>,
    },
    /// Retains one pinned range from a genuinely completed publication.
    RetainResidentChunk {
        identity: Identity,
        response: oneshot::Sender<io::Result<super::NativeResidentChunkSource>>,
    },
    /// Transfers a manifest identity to actual retained native reassembly.
    PublishManifest {
        identity: Identity,
        response: oneshot::Sender<io::Result<super::NativeManifestPublication>>,
    },
    /// Transfers the original completed publication into native cache ownership.
    CachePublication {
        resource: Arc<Mutex<super::publication::PublicationJob>>,
        response: oneshot::Sender<io::Result<super::NativeCacheHandoffReport>>,
    },
    /// Transfers an original completed chunk or metadata pair into cache custody.
    CacheAdmission {
        resource: Arc<Mutex<super::admission::AdmissionJob>>,
        response: oneshot::Sender<io::Result<super::NativeAdmissionHandoffReport>>,
    },
    /// Closes only external producer reads belonging to the original publication.
    ClosePublicationReads {
        resource: Arc<Mutex<super::publication::PublicationJob>>,
        response: oneshot::Sender<io::Result<super::NativeProducerReadClosure>>,
    },
    /// Finishes only a completed publication's actual original pending sources.
    FinishPublicationSources {
        resource: Arc<Mutex<super::publication::PublicationJob>>,
        response: oneshot::Sender<io::Result<super::NativeSourceCleanupReport>>,
    },
    /// Transfers bounded encoded inline content to actual sealed publication.
    PublishInline {
        descriptor: terrane_format::identity::Descriptor,
        encoded: Vec<u8>,
        response: oneshot::Sender<io::Result<super::NativeInlinePublication>>,
    },
    /// Selects and publishes verified inline bytes under original physical custody.
    PublishResidentInline {
        identity: Identity,
        response: oneshot::Sender<io::Result<super::NativeInlinePublication>>,
    },
    /// Transfers bounded untrusted chunk input to actual running admission.
    AdmitChunk {
        descriptor: terrane_format::identity::Descriptor,
        position: terrane_sdk::store::ChunkPosition,
        encoded: Vec<u8>,
        response: oneshot::Sender<io::Result<super::NativeChunkAdmission>>,
    },
    /// Transfers bounded untrusted metadata pair input to actual running admission.
    AdmitMetadata {
        expected_id: terrane_sdk::pack::PackId,
        pack: Vec<u8>,
        index: Vec<u8>,
        response: oneshot::Sender<io::Result<super::NativeMetadataAdmission>>,
    },
    /// Transfers genuine completion through the sole physical Resume turn.
    Resume {
        completed: Box<super::CompletedRecovery>,
        response: oneshot::Sender<io::Result<()>>,
    },
    /// Runs actual recovery without enabling Resume or service readiness.
    Recover {
        exposures: super::recovery::ExposureRecovery,
        response: oneshot::Sender<io::Result<super::CompletedRecovery>>,
    },
    /// Synchronizes and pins independently verified reconstruction metadata.
    Retain {
        identity: Identity,
        response: oneshot::Sender<io::Result<RetainedManifest>>,
    },
    /// Repairs one missing detached index under durable source custody.
    RepairIndex {
        source: Box<DerivedIndexRepair>,
        response: oneshot::Sender<io::Result<NativeIndexRepairReport>>,
    },
}

/// Records only a completed physical snapshot write and its retained incarnation.
///
/// Cold loads never produce this provenance. It is cleared before every write
/// attempt and recreated only after file/parent durability and currentness.
pub(super) struct SynchronizedState {
    /// Exact state observed after the actual completed writer.
    pub(super) state: CacheState,
    /// Actual owner generation acknowledged by that writer.
    pub(super) generation: u64,
    /// Device of the synchronized canonical snapshot.
    pub(super) device: u64,
    /// Inode of the synchronized canonical snapshot.
    pub(super) inode: u64,
}

impl SynchronizedState {
    fn matches_snapshot(&self, generation: u64, expected: &Metadata, actual: &Metadata) -> bool {
        self.generation == generation
            && (self.device, self.inode) == (expected.dev(), expected.ino())
            && same_file(expected, actual)
    }
}

/// Retains native proofs, exclusive state ownership and physical command resources.
pub(super) struct Custody {
    #[cfg(feature = "surface-fuse")]
    pub(super) surface_indexes:
        BTreeMap<crate::structural_index::IndexKey, super::surface_index::Job>,
    #[cfg(feature = "surface-fuse")]
    pub(super) surface_queue: Option<super::surface_index::pressure::Queue>,
    pub(super) preparation: NativeCachePreparation,
    pub(super) directory: File,
    pub(super) state: CacheState,
    pub(super) snapshot: Option<(File, Metadata)>,
    /// Provenance recorded only after an actual completed snapshot writer.
    pub(super) synchronized_state: Option<SynchronizedState>,
    /// Monotonic identity of this owner's prepared snapshot writes.
    pub(super) snapshot_sequence: u64,
    /// Atomic busy/abandoned state rejects receipts without Drop mutex locking.
    pub(super) snapshot_phase: Arc<std::sync::atomic::AtomicU8>,
    sources: BTreeMap<[u8; 16], Arc<NativeManifestSource>>,
    index_repairs: BTreeMap<[u8; 16], IndexRepairCustody>,
    pub(super) faulted: bool,
    /// Cancellation fault observed without taking an embedded mutex from Drop.
    pub(super) admission_fault: Arc<std::sync::atomic::AtomicBool>,
    pub(super) recovery_required: bool,
    pub(super) generation: u64,
    pub(super) recovery_id: Option<[u8; 16]>,
    /// Original cold candidates retained until complete verified reconciliation.
    pub(super) recovery_cold: Option<super::recovery_cold::ColdPolicy>,
    pub(super) snapshot_allocated_bytes: u64,
    pub(super) directory_allocated_bytes: u64,
}

/// Reports an actual index repair without granting serving or recovery authority.
///
/// The owner retains the source, durable pack pin and future hold independently
/// of this report. This describes one physical command, never complete inventory
/// reconciliation, writable readiness or permission to Resume.
pub struct NativeIndexRepairReport {
    pack_id: terrane_sdk::pack::PackId,
    synchronized_index_bytes: u64,
}

impl NativeIndexRepairReport {
    /// Returns the existing pack identifier whose detached index was repaired.
    pub fn pack_id(&self) -> terrane_sdk::pack::PackId {
        self.pack_id
    }

    /// Returns measured synchronized allocation for the canonical index alone.
    ///
    /// This excludes source, state and directory allocation, kernel reservations
    /// and logical future holds; it is not total tier charge.
    pub fn synchronized_index_bytes(&self) -> u64 {
        self.synchronized_index_bytes
    }
}

/// Proves actual synchronized metadata retention under one native owner.
///
/// Only the retained command worker constructs this receipt, after durable
/// reservation and pin snapshots, actual file/parent synchronization, fresh
/// authenticated quota reconciliation and source-incarnation checks. It is not
/// a serving handle or a completed startup-recovery receipt. No public file,
/// digest or boolean constructor exists. Its owner and source custody survive
/// destruction of the request waiter.
pub struct RetainedManifest {
    source: Arc<NativeManifestSource>,
    custody: Arc<Mutex<Custody>>,
    retention_id: [u8; 16],
    cache_incarnation: [u8; 16],
    session: Arc<Client<HostDomainLocation>>,
    synchronized_source_bytes: u64,
}

impl NativeMetadataOwner {
    /// Starts a bounded physical owner over already authenticated preparation.
    ///
    /// The dedicated thread retains all commands through actual completion. It
    /// takes exclusive custody of the configured existing `state/cache` inode;
    /// it never creates that operator-provisioned directory. Existing durable
    /// records load as candidates. Mutations require actual recovery first;
    /// unhandled records are never cleared merely to make startup succeed.
    ///
    /// # Errors
    /// Refuses unavailable thread/runtime resources, stale native preparation,
    /// unsafe/malformed state custody, another state writer and cold scratch.
    pub fn start(preparation: NativeCachePreparation) -> io::Result<Self> {
        #[cfg(feature = "surface-fuse")]
        let surface_policy = preparation.config.surface_index;
        let admission_bounds = super::admission::AdmissionBounds::new(&preparation.config)?;
        let chunk_profile = preparation.config.location.chunk_profile().clone();
        let consumer_reads = Arc::new(super::consumer::ReadBudget::new(
            preparation.config.queued_commands,
        ));
        let worker_reads = Arc::clone(&consumer_reads);
        let queue_capacity = preparation.config.queued_commands;
        let (commands, receive) = mpsc::sync_channel(preparation.config.queued_commands);
        let (ready, startup) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("terrane-metadata-owner".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                let custody = match runtime.block_on(Custody::open(preparation)) {
                    Ok(custody) => Arc::new(Mutex::new(custody)),
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                let mut executor = NativeOwnerExecutor::new(custody, worker_reads);
                if ready.send(Ok(())).is_err() {
                    return;
                }
                let mut maintenance: Option<(super::publication::eviction::DueRetirements, usize)> =
                    None;
                loop {
                    if let Err(error) = executor.quarantine_failed_encoded_reads() {
                        eprintln!(
                            "terrane: failed encoded quarantine retained for recovery: {error}"
                        );
                    }
                    if let Err(error) = executor.quarantine_failed_reads() {
                        eprintln!(
                            "terrane: failed sealed quarantine retained for recovery: {error}"
                        );
                    }
                    if maintenance.is_none()
                        && let Ok(due) = super::publication::eviction::due_retirements(&executor)
                        && !due.is_empty()
                    {
                        maintenance = Some((due, queue_capacity));
                    }
                    let command = if let Some((_, remaining)) = maintenance.as_mut() {
                        // Every command accepted before this due cut is among
                        // the first queue_capacity FIFO messages. Process that
                        // bounded batch before deleting: an early pin/read must
                        // get its real restoration turn even under queue delay.
                        if *remaining == 0 {
                            if let Some((due, _)) = maintenance.take() {
                                let _ = runtime.block_on(super::publication::eviction::finish_due(
                                    &mut executor,
                                    due,
                                ));
                            }
                            continue;
                        }
                        match receive.try_recv() {
                            Ok(command) => {
                                *remaining -= 1;
                                command
                            }
                            Err(mpsc::TryRecvError::Empty) => {
                                if let Some((due, _)) = maintenance.take() {
                                    let _ =
                                        runtime.block_on(super::publication::eviction::finish_due(
                                            &mut executor,
                                            due,
                                        ));
                                }
                                continue;
                            }
                            Err(mpsc::TryRecvError::Disconnected) => break,
                        }
                    } else {
                        match receive.recv_timeout(std::time::Duration::from_secs(1)) {
                            Ok(command) => command,
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                let _ = runtime
                                    .block_on(super::consumer::sweep_background(&mut executor));
                                continue;
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    };
                    let _ = runtime.block_on(super::consumer::sweep_background(&mut executor));
                    match command {
                        Command::CheckRunning { response } => {
                            let _ = response.send(super::health::check(&executor));
                        }
                        Command::Status { response } => {
                            let _ = response.send(super::status::observe(&executor));
                        }
                        #[cfg(feature = "surface-fuse")]
                        Command::SurfaceExposure(request) => {
                            runtime.block_on(super::surface_index::exposure::execute(
                                &executor, request,
                            ));
                        }
                        #[cfg(feature = "surface-fuse")]
                        Command::ReconcileSurfaceExposure {
                            id,
                            generation,
                            response,
                        } => {
                            let result =
                                runtime.block_on(super::surface_index::closure::reconcile(
                                    &executor, &id, generation,
                                ));
                            let _ = response.send(result);
                        }
                        #[cfg(feature = "surface-fuse")]
                        Command::ReconcileDrainingSurfaceExposures { response } => {
                            let result = runtime.block_on(
                                super::surface_index::closure::reconcile_draining(&executor),
                            );
                            let _ = response.send(result);
                        }
                        #[cfg(feature = "surface-fuse")]
                        Command::EvictSurfaceIndex {
                            key,
                            draining,
                            response,
                        } => {
                            let result = runtime.block_on(super::surface_index::eviction::retire(
                                &executor, key, draining,
                            ));
                            let _ = response.send(result);
                        }
                        #[cfg(feature = "surface-fuse")]
                        Command::CacheSurfaceIndex {
                            root,
                            nodes,
                            domain,
                            response,
                        } => {
                            let result = runtime.block_on(super::surface_index::admit(
                                &mut executor,
                                root,
                                nodes,
                                domain.as_deref(),
                            ));
                            let _ = response.send(result);
                        }
                        Command::EvictCache { incoming, response } => {
                            let result = runtime.block_on(super::publication::eviction::run(
                                &mut executor,
                                incoming,
                            ));
                            let _ = response.send(result);
                        }
                        Command::Consumer(command) => {
                            runtime.block_on(super::consumer::execute(&mut executor, command));
                        }
                        #[cfg(feature = "native-test-fixtures")]
                        Command::HoldPolicyForFixture { started, released } => {
                            match executor.custody().lock() {
                                Ok(_held) => {
                                    let _ = started.send(Ok(()));
                                    let _ = released.recv();
                                }
                                Err(_) => {
                                    let _ = started
                                        .send(Err(io::Error::other("fixture policy poisoned")));
                                }
                            }
                        }
                        Command::RetainResidentChunk { identity, response } => {
                            let result = runtime.block_on(
                                super::publication::retain_resident_chunk(&mut executor, identity),
                            );
                            let _ = response.send(result);
                        }
                        Command::CachePublication { resource, response } => {
                            let result = runtime.block_on(super::publication::handoff::execute(
                                &mut executor,
                                &resource,
                            ));
                            let _ = response.send(result);
                        }
                        Command::CacheAdmission { resource, response } => {
                            let result = runtime.block_on(super::admission::handoff::execute(
                                &mut executor,
                                &resource,
                            ));
                            let _ = response.send(result);
                        }
                        Command::ClosePublicationReads { resource, response } => {
                            let result =
                                super::publication::close_producer_reads(&mut executor, &resource);
                            let _ = response.send(result);
                        }
                        Command::FinishPublicationSources { resource, response } => {
                            let result =
                                super::publication::retirement::execute(&mut executor, &resource);
                            // An abandoned waiter must not hide the original
                            // physical failure from the dedicated VM witness.
                            #[cfg(feature = "native-test-fixtures")]
                            if let Err(error) = &result {
                                eprintln!("actual native source cleanup refused: {error:?}");
                            }
                            let _ = response.send(result);
                        }
                        Command::PublishManifest { identity, response } => {
                            let result = runtime.block_on(super::publication::run_manifest(
                                &mut executor,
                                identity,
                            ));
                            let _ = response.send(result);
                        }
                        Command::PublishInline {
                            descriptor,
                            encoded,
                            response,
                        } => {
                            let result = runtime.block_on(super::publication::run(
                                &mut executor,
                                descriptor,
                                encoded,
                            ));
                            let _ = response.send(result);
                        }
                        Command::PublishResidentInline { identity, response } => {
                            let result = runtime.block_on(super::publication::run_resident_inline(
                                &mut executor,
                                identity,
                            ));
                            let _ = response.send(result);
                        }
                        Command::AdmitChunk {
                            descriptor,
                            position,
                            encoded,
                            response,
                        } => {
                            let result = runtime.block_on(super::admission::chunk(
                                &mut executor,
                                descriptor,
                                position,
                                encoded,
                            ));
                            let _ = response.send(result);
                        }
                        Command::AdmitMetadata {
                            expected_id,
                            pack,
                            index,
                            response,
                        } => {
                            let result = runtime.block_on(super::admission::metadata(
                                &mut executor,
                                expected_id,
                                pack,
                                index,
                            ));
                            let _ = response.send(result);
                        }
                        Command::Resume {
                            completed,
                            response,
                        } => {
                            let result = runtime.block_on(executor.resume(completed));
                            // The executor retains the physical outcome before reply.
                            let _ = response.send(result);
                        }
                        Command::Recover {
                            exposures,
                            response,
                        } => {
                            let result = runtime.block_on(executor.recover(exposures));
                            let _ = response.send(result);
                        }
                        Command::Retain { identity, response } => {
                            let result = runtime.block_on(executor.retain_metadata(identity));
                            // An abandoned reply never releases the registry's source,
                            // durable pins, future hold or exclusive state custody.
                            let _ = response.send(result);
                        }
                        Command::RepairIndex { source, response } => {
                            let result = executor.check_recovery_phase().and_then(|()| {
                                runtime.block_on(index_repair::run(&executor, *source))
                            });
                            // Actual source/temporary custody and durable holds
                            // belong to the worker, never to this reply waiter.
                            let _ = response.send(result);
                        }
                    }
                }
            })?;
        let initialized = startup
            .recv()
            .map_err(|_| io::Error::other("metadata owner startup terminated"))
            .and_then(|result| result);
        if let Err(error) = initialized {
            drop(commands);
            let _ = worker.join();
            return Err(error);
        }
        Ok(Self {
            #[cfg(feature = "surface-fuse")]
            surface_policy,
            admission_bounds,
            chunk_profile,
            commands: Some(commands),
            consumer_reads,
            worker: Some(worker),
        })
    }

    /// Resumes the actual publisher through this owner's serialized physical queue.
    ///
    /// The consumed completion and acknowledged context remain with the worker
    /// even if this waiter disappears. Success grants no Store readiness or
    /// native admission; running mutations require a separate concrete turn.
    /// The completion is allocated before submission; a queue refusal returns
    /// that same allocation for a later explicit retry.
    ///
    /// # Errors
    /// Refuses a full or stopped queue, foreign or stale completion, repeated
    /// handoff, or failed/uncertain transport. Failures retain recovery custody.
    pub async fn resume_recovered(
        &self,
        completed: super::CompletedRecovery,
    ) -> Result<(), super::NativeResumeError> {
        use super::NativeResumeError;
        let completed = Box::new(completed);

        let Some(commands) = self.commands.as_ref() else {
            return Err(NativeResumeError::Unsubmitted {
                error: io::Error::other("metadata owner stopped"),
                completed,
            });
        };
        let (response, receive) = oneshot::channel();
        if let Err(error) = commands.try_send(Command::Resume {
            completed,
            response,
        }) {
            let (kind, command) = match error {
                mpsc::TrySendError::Full(command) => (io::ErrorKind::WouldBlock, command),
                mpsc::TrySendError::Disconnected(command) => (io::ErrorKind::BrokenPipe, command),
            };
            let Command::Resume { completed, .. } = command else {
                return Err(NativeResumeError::Accepted(io::Error::other(
                    "unexpected owner command",
                )));
            };
            return Err(NativeResumeError::Unsubmitted {
                error: io::Error::new(kind, "Resume was not submitted to the owner"),
                completed,
            });
        }
        receive
            .await
            .map_err(|_| {
                NativeResumeError::Accepted(io::Error::other(
                    "metadata owner terminated before Resume completion",
                ))
            })?
            .map_err(NativeResumeError::Accepted)
    }

    /// Retains verified reconstruction metadata before any dependent publication.
    ///
    /// Requests use the actual configured domain and profile; callers supply no
    /// paths, source files, callback or validity assertion. A full queue returns
    /// immediately. Cancellation after enqueue leaves physical execution owned.
    /// After Resume, the worker uses its original acknowledged Running context;
    /// it never reuses the completed recovery snapshot as a currentness predicate.
    ///
    /// # Errors
    /// Returns capacity, unavailable owner, metadata verification, synchronization,
    /// durable state or authenticated quota failures. No error grants a receipt.
    pub async fn retain_manifest(&self, identity: Identity) -> io::Result<RetainedManifest> {
        if identity.kind() != IdentityKind::Manifest {
            return Err(invalid("retention requires a manifest identity"));
        }
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::other("metadata owner stopped"))?
            .try_send(Command::Retain { identity, response })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "metadata owner queue is full")
                }
                mpsc::TrySendError::Disconnected(_) => io::Error::other("metadata owner stopped"),
            })?;
        receive
            .await
            .map_err(|_| io::Error::other("metadata owner terminated before completion"))?
    }

    /// Repairs a missing index from genuine same-owner verified pack evidence.
    ///
    /// The bounded physical queue owns the source after enqueue. A cancelled
    /// waiter cannot release its durable pack pin, future hold or failed scratch.
    /// Existing mismatching indexes are never replaced. Successful repair does
    /// not clear any other recovery issue or authorize publication or Resume.
    ///
    /// # Errors
    /// Refuses disabled/unfunded repair, stale or foreign source custody, a full
    /// queue, failed durability and unreconciled actual charges. Late failures
    /// fault the owner while retaining physical resources and durable records.
    pub async fn repair_missing_index(
        &self,
        source: DerivedIndexRepair,
    ) -> io::Result<NativeIndexRepairReport> {
        let (response, receive) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::other("metadata owner stopped"))?
            .try_send(Command::RepairIndex {
                source: Box::new(source),
                response,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "metadata owner queue is full")
                }
                mpsc::TrySendError::Disconnected(_) => io::Error::other("metadata owner stopped"),
            })?;
        receive
            .await
            .map_err(|_| io::Error::other("metadata owner terminated before index completion"))?
    }
}

impl Drop for NativeMetadataOwner {
    fn drop(&mut self) {
        // Close admission before waiting for all already owned physical work.
        self.commands.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl RetainedManifest {
    /// Checks native session object identity; it does not mint retention authority.
    pub(crate) fn matches_client(&self, client: &Client<HostDomainLocation>) -> bool {
        std::ptr::eq(self.session.as_ref(), client)
    }

    /// Borrows the exact canonical manifest claim bound to the durable pin.
    pub fn claim(&self) -> &PublicationClaim {
        self.source.claim()
    }

    /// Borrows the actual retained metadata-pack descriptor, without transferring custody.
    pub fn metadata_file(&self) -> &File {
        self.source.files().0
    }

    /// Returns the authoritative canonical manifest body range in that pack.
    pub fn manifest_range(&self) -> ByteRange {
        self.source.range()
    }

    /// Borrows the verified identity of the entire retained metadata pack.
    pub fn pack_identity(&self) -> &Identity {
        self.source.pack_identity()
    }

    /// Returns the existing random pack identifier selecting both canonical files.
    pub fn pack_id(&self) -> terrane_sdk::pack::PackId {
        self.source.pack_id()
    }

    /// Borrows the actual random pin and reservation identifier.
    pub fn retention_id(&self) -> &[u8; 16] {
        &self.retention_id
    }

    /// Borrows the real publisher client's stable cache incarnation.
    pub fn cache_incarnation(&self) -> &[u8; 16] {
        &self.cache_incarnation
    }

    /// Borrows actual domain-root and provisioning custody retained by the pin.
    pub fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        self.source.layout()
    }

    /// Returns synchronized pack/index allocation, counted once per native inode.
    ///
    /// This excludes state, directories, private publisher allocation and kernel
    /// reservations. It is not total tier usage or a future-capacity guarantee.
    pub fn synchronized_source_bytes(&self) -> u64 {
        self.synchronized_source_bytes
    }

    /// Returns the owner's latest synchronized snapshot and cache-directory allocation.
    ///
    /// This counts only those two native inodes. It excludes source packs,
    /// filesystem-wide metadata, publisher allocation and kernel reservations;
    /// shared policy allocation must not be counted again for each receipt.
    ///
    /// # Errors
    /// Refuses stale/faulted custody or an overflowing measured allocation sum.
    pub fn synchronized_policy_bytes(&self) -> io::Result<u64> {
        self.check_current()?;
        let custody = self
            .custody
            .lock()
            .map_err(|_| io::Error::other("metadata custody poisoned"))?;
        custody.check_current()?;
        if custody.faulted {
            return Err(invalid(
                "metadata allocation requires failed-operation recovery",
            ));
        }
        custody
            .snapshot_allocated_bytes
            .checked_add(custody.directory_allocated_bytes)
            .ok_or_else(|| invalid("policy allocation sum overflow"))
    }

    /// Rechecks original native pair custody without taking the policy lock.
    ///
    /// This retains the original reconstruction source and its shared corruption
    /// observation. Publication additionally checks durable pin registration
    /// through [`Self::check_current`].
    ///
    /// # Errors
    /// Refuses changed or permanently rejected original metadata backing.
    pub fn check_native_backing(&self) -> io::Result<()> {
        self.source.recheck()
    }

    /// Checks current native source and the actual durable pin-owner custody.
    ///
    /// This checks pin state before publication, never on an already sealed read.
    ///
    /// # Errors
    /// Refuses a faulted owner, stale process/root/source/snapshot, absent actual
    /// pin registration or another cache incarnation.
    pub fn check_current(&self) -> io::Result<()> {
        let custody = self
            .custody
            .lock()
            .map_err(|_| io::Error::other("metadata custody poisoned"))?;
        custody.check_current()?;
        if !Arc::ptr_eq(&self.session, &custody.preparation.publisher_session())
            || custody.faulted
            || custody.recovery_required
            || custody.snapshot.is_none()
            || !custody
                .sources
                .get(&self.retention_id)
                .is_some_and(|source| Arc::ptr_eq(source, &self.source))
            || custody.preparation.publisher().cache_incarnation() != &self.cache_incarnation
        {
            return Err(invalid("metadata retention custody is no longer current"));
        }
        self.check_registration(&custody)
    }

    /// Checks actual durable retention records without changing owner phase.
    ///
    /// # Errors
    /// Refuses a foreign source/session, missing pin/lease/hold or changed files.
    pub(in crate::host_cache::owner) fn check_registration(
        &self,
        custody: &Custody,
    ) -> io::Result<()> {
        if custody.snapshot.is_none()
            || !custody
                .sources
                .get(&self.retention_id)
                .is_some_and(|source| Arc::ptr_eq(source, &self.source))
            || !Arc::ptr_eq(&self.session, &custody.preparation.publisher_session())
            || custody.preparation.publisher().cache_incarnation() != &self.cache_incarnation
        {
            return Err(invalid("metadata registration differs from actual custody"));
        }
        let token = hex(&self.retention_id);
        let pin_owner = format!("metadata:{token}");
        if !custody.state.reservations.iter().any(|record| {
            record.id == token
                && record.owner == custody.preparation.config.quota_owner
                && record.bytes == custody.preparation.config.metadata_sync_hold_bytes
        }) || !custody
            .state
            .leases
            .iter()
            .any(|lease| lease.owner == pin_owner && lease.expires == RETAINED_LEASE_DEADLINE)
            || [
                hex(self.claim().descriptor().digest()),
                hex(self.pack_identity().digest()),
            ]
            .iter()
            .any(|hash| {
                !custody.state.pins.iter().any(|pin| {
                    pin.owner == pin_owner
                        && &pin.hash == hash
                        && pin.expires == RETAINED_LEASE_DEADLINE
                })
            })
        {
            return Err(invalid(
                "durable metadata pin, lease or reservation is absent",
            ));
        }
        self.source.recheck()
    }
}

impl Custody {
    async fn open(mut preparation: NativeCachePreparation) -> io::Result<Self> {
        preparation.recheck()?;
        let state = preparation
            .layout()
            .directories
            .get("state")
            .ok_or_else(|| invalid("retained state root is absent"))?;
        let directory = File::from(openat(
            state,
            "cache",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let metadata = directory.metadata()?;
        let project = NativeProject::inspect(&directory)?;
        if metadata.uid() != preparation.config.content_uid
            || metadata.gid() != preparation.config.state_gid
            || metadata.mode() & 0o7777 != 0o2770
            || project.project_id != preparation.config.project_id
            || !project.inherit
            || metadata.dev() != project.device
            || metadata.dev() != preparation.layout().directory_binding("state")?.0
        {
            return Err(invalid(
                "cache state directory differs from native role/project custody",
            ));
        }
        flock(&directory, FlockOperation::NonBlockingLockExclusive)?;
        for entry in rustix::fs::Dir::read_from(&directory)? {
            let entry = entry?;
            if !matches!(entry.file_name().to_bytes(), b"." | b".." | b"records.toml") {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "cold cache state scratch requires native recovery before metadata mutation",
                ));
            }
        }
        let mut custody = Self {
            #[cfg(feature = "surface-fuse")]
            surface_indexes: BTreeMap::new(),
            #[cfg(feature = "surface-fuse")]
            surface_queue: preparation
                .config
                .surface_index
                .map(|surface| {
                    super::surface_index::pressure::Queue::new(&preparation.config, surface)
                })
                .transpose()?,
            preparation,
            directory,
            state: CacheState::default(),
            snapshot: None,
            synchronized_state: None,
            snapshot_sequence: 0,
            snapshot_phase: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            sources: BTreeMap::new(),
            index_repairs: BTreeMap::new(),
            faulted: false,
            admission_fault: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            recovery_required: true,
            generation: 0,
            recovery_id: None,
            recovery_cold: None,
            snapshot_allocated_bytes: 0,
            directory_allocated_bytes: 0,
        };
        custody.capture_snapshot()?;
        let path = custody
            .preparation
            .config
            .location
            .root()
            .join("state/cache");
        let state = CacheState::load(&TokioLocalFs, &path, custody.preparation.config.state)
            .await
            .map_err(io::Error::other)?
            .unwrap_or_default();
        custody.state = state;
        custody.check_current()?;
        Ok(custody)
    }

    /// Checks current confinement, retained state directory and snapshot incarnation.
    ///
    /// # Errors
    /// Refuses stale native roots, replaced directories/snapshots and snapshots
    /// created outside the physical owner, and abandoned physical admission.
    pub(super) fn check_current(&self) -> io::Result<()> {
        if self
            .admission_fault
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(io::Error::other(
                "abandoned physical admission requires reconciliation",
            ));
        }
        if self
            .snapshot_phase
            .load(std::sync::atomic::Ordering::Acquire)
            != 0
        {
            return Err(io::Error::other(
                "state snapshot write is incomplete or abandoned",
            ));
        }
        self.preparation.confinement.check_current()?;
        self.preparation.layout().recheck()?;
        let root = self
            .preparation
            .layout()
            .directories
            .get("state")
            .ok_or_else(|| invalid("state root absent"))?;
        let current = File::from(openat(
            root,
            "cache",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let expected = self.directory.metadata()?;
        let actual = current.metadata()?;
        if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
            return Err(invalid("cache state directory replaced"));
        }
        if let Some((retained, expected)) = &self.snapshot {
            let current = File::from(openat(
                &self.directory,
                "records.toml",
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            if !same_file(expected, &retained.metadata()?)
                || !same_file(expected, &current.metadata()?)
            {
                return Err(invalid("durable cache snapshot replaced or modified"));
            }
        } else {
            match openat(
                &self.directory,
                "records.toml",
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(invalid("cache snapshot appeared outside its owner")),
            }
        }
        Ok(())
    }

    /// Retains the actual canonical snapshot after native custody checks.
    ///
    /// # Errors
    /// Refuses unavailable, replaced or incorrectly owned/projected snapshots.
    pub(super) fn capture_snapshot(&mut self) -> io::Result<()> {
        match open_regular_at(&self.directory, "records.toml") {
            Ok(file) => {
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || metadata.uid() != self.preparation.config.content_uid
                    || metadata.gid() != self.preparation.config.state_gid
                    || metadata.mode() & 0o002 != 0
                    || NativeProject::inspect(&file)?.project_id
                        != self.preparation.config.project_id
                {
                    return Err(invalid("cache snapshot has invalid native custody"));
                }
                self.snapshot = Some((file, metadata));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && self.snapshot.is_none() => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Requires the actual producer's synchronized snapshot of this bootstrap.
    ///
    /// # Errors
    /// Refuses cold/failed/abandoned writes, another generation or inode, and a
    /// prior synchronized state that does not contain the exact required hold.
    pub(super) fn check_synchronized_bootstrap(&self, id: &[u8; 16]) -> io::Result<()> {
        let cold = self
            .recovery_cold
            .as_ref()
            .ok_or_else(|| invalid("bootstrap lost original cold policy candidates"))?;
        self.check_synchronized_state(&cold.bootstrap(&self.preparation.config, id)?)
    }

    /// Requires this generation's completed writer to retain the exact policy.
    ///
    /// # Errors
    /// Refuses a cold, abandoned, changed or unsynchronized snapshot, another
    /// generation/inode, or any different retained or in-memory policy record.
    fn check_synchronized_state(&self, expected: &CacheState) -> io::Result<()> {
        self.check_current()?;
        let completed = self
            .synchronized_state
            .as_ref()
            .ok_or_else(|| invalid("snapshot has no completed native write"))?;
        let (snapshot, metadata) = self
            .snapshot
            .as_ref()
            .ok_or_else(|| invalid("synchronized policy snapshot is absent"))?;
        if !completed.matches_snapshot(self.generation, metadata, &snapshot.metadata()?) {
            return Err(invalid("write provenance differs from retained snapshot"));
        }
        super::recovery_manifest_state::require_same(&completed.state, expected)?;
        super::recovery_manifest_state::require_same(&self.state, expected)
    }

    /// Invalidates an older completion before any new durable command effects.
    ///
    /// # Errors
    /// Refuses exhaustion of the actual owner's monotonic command generation.
    pub(super) fn begin_mutation(&mut self) -> io::Result<()> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("native owner command generation overflow"))?;
        self.recovery_id = None;
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Compares retained inode custody and content-change metadata.
pub(super) fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod snapshot_provenance_tests {
    use super::*;

    #[test]
    fn previous_write_cannot_certify_new_generation_or_another_inode() {
        // Real ordinary files test identity only: no native preparation,
        // confinement, quota or bootstrap receipt is fabricated here.
        let mut random = [0_u8; 16];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut random)
            .unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("terrane-snapshot-provenance-{suffix}"));
        std::fs::create_dir(&path).unwrap();
        let first = File::create_new(path.join("first")).unwrap();
        let second = File::create_new(path.join("second")).unwrap();
        let observed = first.metadata().unwrap();
        let provenance = SynchronizedState {
            state: CacheState::default(),
            generation: 3,
            device: observed.dev(),
            inode: observed.ino(),
        };
        assert!(provenance.matches_snapshot(3, &observed, &first.metadata().unwrap()));
        assert!(!provenance.matches_snapshot(4, &observed, &first.metadata().unwrap()));
        assert!(!provenance.matches_snapshot(3, &observed, &second.metadata().unwrap()));
        drop(first);
        drop(second);
        std::fs::remove_dir_all(path).unwrap();
    }
}
