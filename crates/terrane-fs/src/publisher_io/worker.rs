//! Retains native publication ownership after callers cancel their waiters.

use std::fs::File;
use std::io;
use std::path::Path;

use terrane::host::publication::{FsPublicationState, PublicationClaim, PublishedObject, Publisher};
use terrane::store::TokioLocalFs;
use tokio::sync::{mpsc, oneshot};

use super::NativePublisher;

type Response = oneshot::Sender<io::Result<PublishedObject<File>>>;

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
    /// Starts a domain-bound publisher on the current Tokio runtime.
    ///
    /// The cache must durably retain canonical reconstruction metadata before
    /// submitting manifest-backed claims. This worker never fetches content.
    ///
    /// # Errors
    /// Returns unsafe directory custody, incompatible filesystem, duplicate
    /// publisher or absent native runtime errors before accepting commands.
    pub fn start(domain: String, sealed: &Path, staging: &Path, pending: &Path,
        state_directory: &Path) -> io::Result<Self> {
        let runtime = tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let native = NativePublisher::open(domain, sealed, staging, pending)?;
        let retained_state = super::native::open_directory(state_directory)?;
        use std::os::unix::fs::PermissionsExt;
        if retained_state.metadata()?.permissions().mode() & 0o777 != 0o700 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "publication state directory must be publisher-private mode 0700"));
        }
        let state = FsPublicationState::new(TokioLocalFs, state_directory.to_path_buf());
        let (sender, mut receiver) = mpsc::channel(32);
        // The task owns the publisher and retained state directory, rather than
        // borrowing them from any request waiter. Dropping JoinHandle detaches
        // observation; it does not cancel this physical-operation owner.
        let task = runtime.spawn(async move {
            let _retained_state = retained_state;
            if state.recover_temporary().await.is_err() { return; }
            let mut publisher = Publisher::new(native, state);
            while let Some(command) = receiver.recv().await {
                match command {
                    Command::Publish { claim, source, response } => {
                        let result = publisher.publish(&claim, source).await;
                        let _disconnected = response.send(result);
                    }
                    Command::Adopt { claim, response } => {
                        let result = publisher.adopt(&claim).await;
                        let _disconnected = response.send(result);
                    }
                }
            }
        });
        drop(task);
        Ok(Self { sender })
    }

    /// Queues descriptor-only publication and awaits its durable result.
    ///
    /// # Errors
    /// Returns worker shutdown or the actual publication failure. A canceled
    /// waiter cannot release the worker's inodes or directory exclusions.
    pub async fn publish(&self, claim: PublicationClaim, source: File)
        -> io::Result<PublishedObject<File>> {
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
    pub async fn adopt(&self, claim: PublicationClaim) -> io::Result<PublishedObject<File>> {
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
