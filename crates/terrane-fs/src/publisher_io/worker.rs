//! Retains native publication ownership after callers cancel their waiters.

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use terrane::host::publication::{
    FsPublicationState, PublicationClaim, PublicationState, PublishedObject, Publisher,
    VerityBinding,
};
use terrane::store::TokioLocalFs;
use tokio::sync::{mpsc, oneshot};

use super::NativePublisher;
use super::bodies::BodyIo;
use terrane_core::chunking::ChunkProfile;

#[path = "inventory.rs"]
mod inventory;

#[path = "owned_commands.rs"]
mod owned_commands;
pub use owned_commands::{
    NativeBodyHandle, NativeBodyIncarnation, NativeBodyKey, NativeCommandContext,
    NativeCommandResult, NativeOperation,
};

type Response = oneshot::Sender<io::Result<NativePublishedObject>>;

/// Retains a fresh unnamed seal probe created only by the native command owner.
///
/// This is internal filesystem capability evidence, never a published object
/// or permission to serve bytes. Cache factories independently measure the
/// actual descriptor and match its device to their retained layout root.
pub struct NativeSealProbe {
    file: File,
    binding: VerityBinding,
}

impl NativeSealProbe {
    /// Borrows the actual read-only unnamed probe inode.
    pub fn handle(&self) -> &File {
        &self.file
    }

    /// Borrows the measurement obtained from the actual kernel probe.
    pub fn binding(&self) -> &VerityBinding {
        &self.binding
    }

    /// Transfers the read-only probe without granting serving authority.
    pub fn into_handle(self) -> File {
        self.file
    }
}

/// Carries a native backing descriptor minted only by the concrete worker.
///
/// Portable engine results and arbitrary adapter callbacks cannot construct this
/// type. Its private constructor follows actual kernel and state completion.
pub struct NativePublishedObject {
    object: PublishedObject<File>,
}

impl NativePublishedObject {
    /// Returns the measured binding recorded by the concrete native publisher.
    pub fn binding(&self) -> &VerityBinding {
        self.object.binding()
    }

    /// Transfers the verified read-only canonical descriptor to a consumer.
    pub fn into_handle(self) -> File {
        self.object.into_handle()
    }
}

enum Command {
    Publish {
        claim: PublicationClaim,
        source: File,
        response: Response,
    },
    Adopt {
        claim: PublicationClaim,
        response: Response,
    },
    Execute(Box<OwnedExecution>),
}

/// Keeps the fixed queue slots small without separating operation custody.
///
/// Allocation precedes queue submission. The worker consumes the same payload,
/// including its descriptors and response sender, after acceptance; cancellation
/// of the response waiter cannot reclaim accepted operation resources.
struct OwnedExecution {
    context: NativeCommandContext,
    operation: NativeOperation,
    response: oneshot::Sender<io::Result<NativeCommandResult>>,
}

#[path = "binding_repair.rs"]
mod binding_repair;

struct WorkerState {
    repair: binding_repair::RetainedBinding,
    inner: FsPublicationState<TokioLocalFs>,
    #[cfg(feature = "native-test-fixtures")]
    before_record: Option<WorkerGate>,
}

#[async_trait::async_trait]
impl PublicationState for WorkerState {
    async fn binding(&self, claim: &PublicationClaim) -> io::Result<Option<VerityBinding>> {
        self.repair
            .capture(&self.inner.binding_record_path(claim))?;
        self.inner.binding(claim).await
    }

    async fn record(
        &mut self,
        claim: &PublicationClaim,
        binding: &VerityBinding,
    ) -> io::Result<()> {
        #[cfg(feature = "native-test-fixtures")]
        if let Some(gate) = self.before_record.take() {
            gate.wait()?;
        }

        self.inner.record(claim, binding).await
    }

    fn forget_quarantined(&mut self, claim: &PublicationClaim) -> io::Result<()> {
        self.repair.remove(&self.inner.binding_record_path(claim))
    }
}

#[cfg(feature = "native-test-fixtures")]
pub(super) struct WorkerGate {
    arrived: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

#[cfg(feature = "native-test-fixtures")]
impl WorkerGate {
    pub(super) fn wait(self) -> io::Result<()> {
        self.arrived.send(()).map_err(io::Error::other)?;
        self.release
            .into_inner()
            .map_err(|_| io::Error::other("worker gate poisoned"))?
            .recv()
            .map_err(io::Error::other)
    }
}

/// Selects the registered wipe policy explicitly at native publisher startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeWipePolicy {
    /// Permits ordinary retirement without an erasure guarantee.
    None,
    /// Requires overwriting blocks before removal; incompatible with this seal.
    Zero,
    /// Requires extent discard before removal; not implemented by this owner.
    Discard,
    /// Requires a suitable memory-backed seal primitive; not implemented here.
    Volatile,
}

/// Defines a bounded retirement interval independently of pin-release grace.
#[derive(Clone, Copy, Debug)]
pub struct NativeRetirementPolicy(Duration);

impl NativeRetirementPolicy {
    /// Validates an explicit interval of at most five minutes.
    ///
    /// # Errors
    /// Rejects zero intervals and intervals exceeding 300 seconds.
    pub fn new(interval: Duration) -> io::Result<Self> {
        if interval.is_zero() || interval > Duration::from_secs(300) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "retirement interval must be nonzero and at most 300 seconds",
            ));
        }
        Ok(Self(interval))
    }

    /// Returns the configured bounded interval.
    pub fn interval(self) -> Duration {
        self.0
    }
}

/// Supplies trusted operator configuration for one fixed domain layout.
///
/// Request packets never contain these paths or ownership settings.
pub struct NativePublisherConfig {
    /// The disclosure domain bound to this owner.
    pub domain: String,
    /// The immutable configured chunk profile used to validate every claim.
    pub profile: ChunkProfile,
    /// The configured absolute domain root containing registered directories.
    pub layout_root: PathBuf,
    /// The explicit registered wipe policy; currently only none is supported.
    pub wipe: NativeWipePolicy,
    /// The separate bounded pending-retirement interval.
    pub retirement: NativeRetirementPolicy,
    /// The configured owner of encoded content directories.
    pub content_uid: u32,
    /// The configured shared encoded-content group.
    pub content_gid: u32,
}

/// Retains actual native directory and lock custody before startup effects.
///
/// Preparation performs no cleanup or content write. The value has no public
/// constructor or native-handle conversion; startup consumes these same guards.
/// It establishes directory custody, not complete host quota admission.
pub struct NativePublisherPrepared {
    configured_custody: Option<Arc<crate::configured::ConfiguredPublisherCustody>>,
    confinement: Arc<crate::quota_confinement::Installed>,
    config: NativePublisherConfig,
    native: NativePublisher,
    state_directory: PathBuf,
    retained_state: File,
    retained_layout: (Vec<File>, crate::host_quota::DomainProvisioningGuard),
    body_io: BodyIo,
    inventory: inventory::NativeInventory,
}

impl NativePublisherPrepared {
    /// Borrows the trusted operator settings whose actual roots are retained.
    pub fn configuration(&self) -> &NativePublisherConfig {
        &self.config
    }

    /// Attaches actual configured verifier custody to the accepted native owner.
    ///
    /// The typed receipt has no public constructor. Its authenticated domain,
    /// root incarnation and exact installed receipt must match these guards.
    ///
    /// # Errors
    /// Refuses duplicate attachment, a mismatching domain/root/receipt, changed
    /// native project assignments, or kernel inspection errors.
    pub(crate) fn retain_configured_custody(
        &mut self,
        custody: Arc<crate::configured::ConfiguredPublisherCustody>,
    ) -> io::Result<()> {
        if self.configured_custody.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "configured publisher custody already attached",
            ));
        }
        let root = self
            .retained_layout
            .0
            .first()
            .ok_or_else(|| io::Error::other("missing retained domain root"))?;
        custody.check_domain(&self.config.domain, root, &self.confinement)?;
        self.configured_custody = Some(custody);
        Ok(())
    }

    fn check_custody(&self) -> io::Result<()> {
        self.confinement.check_current()?;
        if let Some(custody) = &self.configured_custody {
            let root = self
                .retained_layout
                .0
                .first()
                .ok_or_else(|| io::Error::other("missing retained domain root"))?;
            custody.check_domain(&self.config.domain, root, &self.confinement)?;
        }
        Ok(())
    }
}

impl NativePublisherConfig {
    /// Retains checked directory and publisher exclusion without writing content.
    ///
    /// A service prepares every configured domain before consuming any result
    /// with `NativePublicationWorker::start_prepared`. Root guards prevent host
    /// provisioning changes during this interval and the complete worker lifetime.
    /// The actual installed confinement receipt remains retained through the
    /// prepared guards, worker, native adapter and every staged inode.
    ///
    /// # Errors
    /// Returns unsupported wipe policy, invalid domain or path, overlapping
    /// service identity, unsafe native directory custody, incompatible filesystem,
    /// conflicting publisher, changed confinement or provisioning-lock errors.
    /// No failure creates a
    /// sealed inode or staging subdirectory.
    pub fn prepare(
        self,
        confinement: Arc<crate::quota_confinement::Installed>,
    ) -> io::Result<NativePublisherPrepared> {
        confinement.check_current()?;
        if self.wipe != NativeWipePolicy::None {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native fs-verity publisher supports only explicitly configured wipe=none",
            ));
        }
        terrane_core::properties::Domain::parse(&self.domain)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if self.content_uid == rustix::process::geteuid().as_raw() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "publisher and encoded-content owners must use distinct identities",
            ));
        }
        let normalized: PathBuf = self.layout_root.components().collect();
        if !self.layout_root.is_absolute()
            || normalized.as_os_str() != self.layout_root.as_os_str()
            || self.layout_root.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "publisher layout must be an absolute normalized path",
            ));
        }
        let retained_layout = super::native::inspect_layout(&self)?;
        let inventory = inventory::NativeInventory::new(
            &self,
            retained_layout
                .0
                .first()
                .ok_or_else(|| io::Error::other("missing retained layout root"))?,
        )?;
        let body_io = BodyIo::open(&self)?;
        let native = NativePublisher::open_unrecovered(
            Arc::clone(&confinement),
            self.domain.clone(),
            &self.layout_root.join("sealed"),
            &self.layout_root.join("staging"),
            &self.layout_root.join("pending-delete"),
        )?;
        let state_directory = self.layout_root.join("state/publication");
        let retained_state = super::native::open_directory(&state_directory)?;
        Ok(NativePublisherPrepared {
            configured_custody: None,
            confinement,
            config: self,
            native,
            state_directory,
            retained_state,
            retained_layout,
            body_io,
            inventory,
        })
    }
}

/// Submits fixed publication commands to an independently owned native worker.
///
/// Cancellation drops only the response waiter. Once accepted, a command owns
/// its source, directory exclusions and actual state future through completion.
/// The worker serializes mutations and never receives paths or arbitrary callbacks.
#[derive(Clone)]
pub struct NativePublicationWorker {
    confinement: Arc<crate::quota_confinement::Installed>,
    sender: mpsc::Sender<Command>,
}

impl NativePublicationWorker {
    /// Starts a domain-bound publisher with an independently owned runtime.
    ///
    /// Manifest-backed commands remain unavailable until the cache supplies its
    /// durable metadata-retention receipt. This worker never fetches content.
    ///
    /// # Errors
    /// Returns unsafe directory custody, incompatible filesystem, duplicate
    /// publisher, runtime creation, state recovery or thread creation errors.
    /// Returns `Unsupported` for zero, discard or volatile policies before
    /// creating any sealed or staging inode; no policy silently becomes unlink.
    pub fn start(
        config: NativePublisherConfig,
        confinement: Arc<crate::quota_confinement::Installed>,
    ) -> io::Result<Self> {
        confinement.check_current()?;
        Self::start_prepared(config.prepare(confinement)?)
    }

    /// Starts an owner using the exact actual guards retained by preparation.
    ///
    /// Successful startup waits for real staging and embedded-state recovery.
    /// The worker retains its root/leaf guards through every accepted operation,
    /// including when the client drops its response waiter.
    ///
    /// # Errors
    /// Returns changed confinement, runtime/thread creation or actual
    /// staging/state recovery errors.
    pub fn start_prepared(prepared: NativePublisherPrepared) -> io::Result<Self> {
        prepared.check_custody()?;
        #[cfg(feature = "native-test-fixtures")]
        let started = Self::start_prepared_thread(prepared, None, None);
        #[cfg(not(feature = "native-test-fixtures"))]
        let started = Self::start_prepared_thread(prepared);
        let (worker, thread) = started?;
        drop(thread);
        Ok(worker)
    }

    #[cfg(feature = "native-test-fixtures")]
    fn start_thread(
        confinement: Arc<crate::quota_confinement::Installed>,
        config: NativePublisherConfig,
        before_record: Option<WorkerGate>,
        finish_first_unlink: Option<WorkerGate>,
    ) -> io::Result<(Self, std::thread::JoinHandle<()>)> {
        Self::start_prepared_thread(
            config.prepare(confinement)?,
            before_record,
            finish_first_unlink,
        )
    }

    fn start_prepared_thread(
        prepared: NativePublisherPrepared,
        #[cfg(feature = "native-test-fixtures")] before_record: Option<WorkerGate>,
        #[cfg(feature = "native-test-fixtures")] finish_first_unlink: Option<WorkerGate>,
    ) -> io::Result<(Self, std::thread::JoinHandle<()>)> {
        prepared.check_custody()?;
        let NativePublisherPrepared {
            configured_custody,
            confinement,
            config,
            mut native,
            state_directory,
            retained_state,
            retained_layout,
            body_io,
            inventory,
        } = prepared;
        #[cfg(feature = "native-test-fixtures")]
        let body_io = body_io.with_finish_gate(finish_first_unlink);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let state = FsPublicationState::new(TokioLocalFs, state_directory.clone());
        let (sender, mut receiver) = mpsc::channel(32);
        let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
        // A dedicated physical owner retains its own runtime. Cancellation or
        // shutdown of a caller's runtime cannot abort this owner while LocalFs
        // workers still use its directory and inode custody.
        let caller_confinement = Arc::clone(&confinement);
        let thread = std::thread::Builder::new()
            .name("terrane-publisher".into())
            .spawn(move || {
                let _retained_state = retained_state;
                let _retained_layout = retained_layout;
                runtime.block_on(async {
                    if let Err(error) = native.initialize_staging() {
                        let _disconnected = ready_sender.send(Err(error));
                        return;
                    }
                    let scratch = match inventory.startup_scratch() {
                        Ok(scratch) => scratch,
                        Err(error) => {
                            let _disconnected = ready_sender.send(Err(error));
                            return;
                        }
                    };
                    if let Err(error) = state.recover_temporary().await {
                        let _disconnected = ready_sender.send(Err(error));
                        return;
                    }
                    if let Err(error) = scratch.verify_removed() {
                        let _disconnected = ready_sender.send(Err(error));
                        return;
                    }
                    // Close retained unlinked scratch before acknowledging
                    // startup, so its allocation no longer burdens the tier.
                    drop(scratch);
                    if ready_sender.send(Ok(())).is_err() {
                        return;
                    }

                    let state = WorkerState {
                        repair: binding_repair::RetainedBinding::new(_retained_state),
                        inner: state,
                        #[cfg(feature = "native-test-fixtures")]
                        before_record,
                    };
                    let publisher = Publisher::new(native, state);
                    let mut owner = owned_commands::CommandOwner::new(
                        config,
                        publisher,
                        state_directory,
                        body_io,
                        inventory,
                        Arc::clone(&confinement),
                        configured_custody,
                    );
                    while let Some(command) = receiver.recv().await {
                        match command {
                            Command::Publish {
                                claim,
                                source,
                                response,
                            } => {
                                let result = async {
                                    owner.validate_claim(&claim)?;
                                    let object = owner.publisher()?.publish(&claim, source).await?;
                                    Ok(NativePublishedObject { object })
                                }
                                .await;
                                let _disconnected = response.send(result);
                            }
                            Command::Adopt { claim, response } => {
                                let result = async {
                                    owner.validate_claim(&claim)?;
                                    let object = owner.publisher()?.adopt(&claim).await?;
                                    Ok(NativePublishedObject { object })
                                }
                                .await;
                                let _disconnected = response.send(result);
                            }
                            Command::Execute(command) => {
                                let OwnedExecution {
                                    context,
                                    operation,
                                    response,
                                } = *command;

                                let result = owner.execute(context, operation).await;
                                let _disconnected = response.send(result);
                            }
                        }
                    }
                });
            })?;
        ready_receiver.recv().map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "publisher worker stopped during state recovery",
            )
        })??;
        Ok((
            Self {
                sender,
                confinement: caller_confinement,
            },
            thread,
        ))
    }

    /// Submits a fixed domain-bound native lifecycle command.
    ///
    /// Accepted work remains owned after cancellation or disconnection. Native
    /// cache composition must retain its actual decision exclusion and validate
    /// reconciliation before sending Resume; a wire request is not that proof.
    ///
    /// # Errors
    /// Returns worker shutdown, domain/incarnation/lifecycle rejection, failed
    /// verification or physical-operation failures. Unimplemented affected paths
    /// fail closed instead of issuing an inode or state-completion receipt.
    pub async fn execute(
        &self,
        context: NativeCommandContext,
        operation: NativeOperation,
    ) -> io::Result<NativeCommandResult> {
        self.confinement.check_current()?;
        let (response, received) = oneshot::channel();
        let command = Box::new(OwnedExecution {
            context,
            operation,
            response,
        });

        self.sender
            .send(Command::Execute(command))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "publisher worker stopped"))?;
        received.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "publisher worker stopped before command acknowledgment",
            )
        })?
    }

    /// Queues descriptor-only publication and awaits its durable result.
    ///
    /// # Errors
    /// Returns `Unsupported` for manifest claims without a retention receipt,
    /// worker shutdown, or the actual publication failure. A canceled waiter
    /// cannot release the worker's inodes or directory exclusions.
    pub async fn publish(
        &self,
        claim: PublicationClaim,
        source: File,
    ) -> io::Result<NativePublishedObject> {
        self.confinement.check_current()?;
        if claim.manifest().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "manifest publication requires a durable cache retention receipt",
            ));
        }
        let (response, received) = oneshot::channel();
        self.sender
            .send(Command::Publish {
                claim,
                source,
                response,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "publisher worker stopped"))?;
        received.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "publisher worker stopped before acknowledgment",
            )
        })?
    }

    /// Queues independent canonical-inode adoption after restart.
    ///
    /// # Errors
    /// Returns `Unsupported` for manifest claims without a retention receipt,
    /// worker shutdown, failed verification, or failed durable binding.
    pub async fn adopt(&self, claim: PublicationClaim) -> io::Result<NativePublishedObject> {
        self.confinement.check_current()?;
        if claim.manifest().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "manifest adoption requires a durable cache retention receipt",
            ));
        }
        let (response, received) = oneshot::channel();
        self.sender
            .send(Command::Adopt { claim, response })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "publisher worker stopped"))?;
        received.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "publisher worker stopped before acknowledgment",
            )
        })?
    }
}

#[cfg(feature = "native-test-fixtures")]
#[path = "worker_tests.rs"]
mod tests;

/// Runs one non-production native conformance fixture in an already confined process.
///
/// The dedicated example installs confinement before runtimes or worker threads.
/// The guest supervisor provisions fixed fixture roots and immutable encoded
/// inputs before launching the publisher identity; this dispatch never chowns.
///
/// # Errors
/// Rejects changed confinement or an unknown selector.
///
/// # Panics
/// Panics when a fixture's actual kernel, custody or durability assertion fails.
#[cfg(feature = "native-test-fixtures")]
pub fn run_native_fixture(
    selector: &str,
    confinement: Arc<crate::quota_confinement::Installed>,
) -> io::Result<()> {
    tests::run(selector, confinement)
}
