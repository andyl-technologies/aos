//! Retains native publication ownership after callers cancel their waiters.

use std::fs::File;
use std::io;
use std::path::Path;

use terrane::host::publication::{FsPublicationState, PublicationClaim, PublishedObject, Publisher, VerityBinding};
use terrane::store::TokioLocalFs;
use tokio::sync::{mpsc, oneshot};

use super::NativePublisher;

type Response = oneshot::Sender<io::Result<NativePublishedObject>>;

/// Carries a native backing descriptor minted only by the concrete worker.
///
/// Portable engine results and arbitrary adapter callbacks cannot construct this
/// type. Its private constructor follows actual kernel and state completion.
pub struct NativePublishedObject {
    object: PublishedObject<File>,
}

impl NativePublishedObject {
    /// Returns the measured binding recorded by the concrete native publisher.
    pub fn binding(&self) -> &VerityBinding { self.object.binding() }

    /// Transfers the verified read-only canonical descriptor to a consumer.
    pub fn into_handle(self) -> File { self.object.into_handle() }
}

enum Command {
    Publish { claim: PublicationClaim, source: File, response: Response },
    Adopt { claim: PublicationClaim, response: Response },
}

/// Submits fixed publication commands to an independently owned native task.
///
/// Cancellation drops only the response waiter. Once accepted, a command owns
/// its source, directory exclusions and actual state future through completion.
/// The task serializes mutations and never receives paths or arbitrary callbacks.
#[derive(Clone)]
pub struct NativePublicationWorker {
    sender: mpsc::Sender<Command>,
}

impl NativePublicationWorker {
    /// Starts a domain-bound publisher with an independently owned runtime.
    ///
    /// The cache must durably retain canonical reconstruction metadata before
    /// submitting manifest-backed claims. This worker never fetches content.
    ///
    /// # Errors
    /// Returns unsafe directory custody, incompatible filesystem, duplicate
    /// publisher, runtime creation or thread creation errors before commands.
    pub fn start(domain: String, sealed: &Path, staging: &Path, pending: &Path,
        state_directory: &Path) -> io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let native = NativePublisher::open(domain, sealed, staging, pending)?;
        let retained_state = super::native::open_directory(state_directory)?;
        use std::os::unix::fs::PermissionsExt;
        if retained_state.metadata()?.permissions().mode() & 0o777 != 0o700 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "publication state directory must be publisher-private mode 0700"));
        }
        let state = FsPublicationState::new(TokioLocalFs, state_directory.to_path_buf());
        let (sender, mut receiver) = mpsc::channel(32);
        // A dedicated physical owner retains its own runtime. Cancellation or
        // shutdown of a caller's runtime cannot abort this owner while LocalFs
        // workers still use its directory and inode custody.
        let thread = std::thread::Builder::new().name("terrane-publisher".into()).spawn(move || {
            let _retained_state = retained_state;
            runtime.block_on(async {
                if state.recover_temporary().await.is_err() { return; }
                let mut publisher = Publisher::new(native, state);
                while let Some(command) = receiver.recv().await {
                    match command {
                        Command::Publish { claim, source, response } => {
                            let result = publisher.publish(&claim, source).await
                                .map(|object| NativePublishedObject { object });
                            let _disconnected = response.send(result);
                        }
                        Command::Adopt { claim, response } => {
                            let result = publisher.adopt(&claim).await
                                .map(|object| NativePublishedObject { object });
                            let _disconnected = response.send(result);
                        }
                    }
                }
            });
        })?;
        drop(thread);
        Ok(Self { sender })
    }

    /// Queues descriptor-only publication and awaits its durable result.
    ///
    /// # Errors
    /// Returns worker shutdown or the actual publication failure. A canceled
    /// waiter cannot release the worker's inodes or directory exclusions.
    pub async fn publish(&self, claim: PublicationClaim, source: File)
        -> io::Result<NativePublishedObject> {
        if claim.manifest().is_some() {
            return Err(io::Error::new(io::ErrorKind::Unsupported,
                "manifest publication requires a durable cache retention receipt"));
        }
        let (response, received) = oneshot::channel();
        self.sender.send(Command::Publish { claim, source, response }).await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "publisher worker stopped"))?;
        received.await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe,
            "publisher worker stopped before acknowledgment"))?
    }

    /// Queues independent canonical-inode adoption after restart.
    ///
    /// # Errors
    /// Returns worker shutdown, failed verification or failed durable binding.
    pub async fn adopt(&self, claim: PublicationClaim) -> io::Result<NativePublishedObject> {
        if claim.manifest().is_some() {
            return Err(io::Error::new(io::ErrorKind::Unsupported,
                "manifest adoption requires a durable cache retention receipt"));
        }
        let (response, received) = oneshot::channel();
        self.sender.send(Command::Adopt { claim, response }).await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "publisher worker stopped"))?;
        received.await.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe,
            "publisher worker stopped before acknowledgment"))?
    }
}
