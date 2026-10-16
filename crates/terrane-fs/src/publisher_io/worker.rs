//! Retains native publication ownership after callers cancel their waiters.

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use terrane::host::publication::{
    FsPublicationState, PublicationClaim, PublicationState, PublishedObject, Publisher,
    VerityBinding,
};
use terrane::store::TokioLocalFs;
use tokio::sync::{mpsc, oneshot};

use super::NativePublisher;

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
    Execute {
        context: NativeCommandContext,
        operation: NativeOperation,
        response: oneshot::Sender<io::Result<NativeCommandResult>>,
    },
}

struct WorkerState {
    inner: FsPublicationState<TokioLocalFs>,
    #[cfg(test)]
    before_record: Option<WorkerGate>,
}

#[async_trait::async_trait]
impl PublicationState for WorkerState {
    async fn binding(&self, claim: &PublicationClaim) -> io::Result<Option<VerityBinding>> {
        self.inner.binding(claim).await
    }

    async fn record(
        &mut self,
        claim: &PublicationClaim,
        binding: &VerityBinding,
    ) -> io::Result<()> {
        #[cfg(test)]
        if let Some(gate) = self.before_record.take() {
            gate.wait()?;
        }

        self.inner.record(claim, binding).await
    }
}

#[cfg(test)]
struct WorkerGate {
    arrived: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

#[cfg(test)]
impl WorkerGate {
    fn wait(self) -> io::Result<()> {
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

/// Submits fixed publication commands to an independently owned native worker.
///
/// Cancellation drops only the response waiter. Once accepted, a command owns
/// its source, directory exclusions and actual state future through completion.
/// The worker serializes mutations and never receives paths or arbitrary callbacks.
#[derive(Clone)]
pub struct NativePublicationWorker {
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
    pub fn start(config: NativePublisherConfig) -> io::Result<Self> {
        #[cfg(test)]
        let started = Self::start_thread(config, None);
        #[cfg(not(test))]
        let started = Self::start_thread(config);
        let (worker, thread) = started?;
        drop(thread);
        Ok(worker)
    }

    fn start_thread(
        config: NativePublisherConfig,
        #[cfg(test)] before_record: Option<WorkerGate>,
    ) -> io::Result<(Self, std::thread::JoinHandle<()>)> {
        if config.wipe != NativeWipePolicy::None {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native fs-verity publisher supports only explicitly configured wipe=none",
            ));
        }
        let retained_layout = super::native::inspect_layout(&config)?;
        let domain = config.domain;
        let sealed = config.layout_root.join("sealed");
        let staging = config.layout_root.join("staging");
        let pending = config.layout_root.join("pending-delete");
        let state_directory = config.layout_root.join("state/publication");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let native = NativePublisher::open(domain.clone(), &sealed, &staging, &pending)?;
        let retained_state = super::native::open_directory(&state_directory)?;
        use std::os::unix::fs::PermissionsExt;
        if retained_state.metadata()?.permissions().mode() & 0o777 != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "publication state directory must be publisher-private mode 0700",
            ));
        }
        let state = FsPublicationState::new(TokioLocalFs, state_directory.clone());
        let (sender, mut receiver) = mpsc::channel(32);
        let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
        // A dedicated physical owner retains its own runtime. Cancellation or
        // shutdown of a caller's runtime cannot abort this owner while LocalFs
        // workers still use its directory and inode custody.
        let thread = std::thread::Builder::new()
            .name("terrane-publisher".into())
            .spawn(move || {
                let _retained_state = retained_state;
                let _retained_layout = retained_layout;
                runtime.block_on(async {
                    if let Err(error) = state.recover_temporary().await {
                        let _disconnected = ready_sender.send(Err(error));
                        return;
                    }
                    if ready_sender.send(Ok(())).is_err() {
                        return;
                    }

                    let state = WorkerState {
                        inner: state,
                        #[cfg(test)]
                        before_record,
                    };
                    let publisher = Publisher::new(native, state);
                    let mut owner = owned_commands::CommandOwner::new(
                        domain,
                        publisher,
                        state_directory,
                        config.retirement,
                    );
                    while let Some(command) = receiver.recv().await {
                        match command {
                            Command::Publish {
                                claim,
                                source,
                                response,
                            } => {
                                let result = async {
                                    let object = owner.publisher()?.publish(&claim, source).await?;
                                    Ok(NativePublishedObject { object })
                                }
                                .await;
                                let _disconnected = response.send(result);
                            }
                            Command::Adopt { claim, response } => {
                                let result = async {
                                    let object = owner.publisher()?.adopt(&claim).await?;
                                    Ok(NativePublishedObject { object })
                                }
                                .await;
                                let _disconnected = response.send(result);
                            }
                            Command::Execute {
                                context,
                                operation,
                                response,
                            } => {
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
        Ok((Self { sender }, thread))
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
        let (response, received) = oneshot::channel();
        self.sender
            .send(Command::Execute {
                context,
                operation,
                response,
            })
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

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
