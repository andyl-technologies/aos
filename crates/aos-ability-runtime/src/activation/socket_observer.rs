//! Protected, bounded Unix transport for native activation instrumentation.
//!
//! Events are canonical JSON framed by a four-byte big-endian length. The
//! observer must acknowledge the domain-separated digest of those exact bytes;
//! an acknowledgement never supplies operation inputs or results.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use aos_contract::Sha256Digest;
use serde::Deserialize;

use super::{BoundaryEvent, BoundaryObserver};
use crate::adapter::CancellationToken;

const MAX_FRAME_BYTES: usize = 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const EVENT_DOMAIN: &str = "aos.activation.boundary";

/// Sends native boundary events to an explicitly selected root-owned endpoint.
pub struct SocketBoundaryObserver {
    socket: PathBuf,
    timeout: Duration,
}

impl SocketBoundaryObserver {
    /// Configures a protected endpoint and a finite per-event transport budget.
    ///
    /// The endpoint may be created later by a preceding service effect. Its
    /// ownership and peer credentials are checked for every event.
    ///
    /// # Errors
    /// Returns an error for noncanonical paths or a zero transport budget.
    pub fn new(socket: PathBuf, timeout: Duration) -> Result<Self> {
        ensure!(socket.is_absolute(), "observer socket must be absolute");
        ensure!(
            socket
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
                && socket.to_string_lossy()
                    == socket.components().collect::<PathBuf>().to_string_lossy(),
            "observer socket must be normalized"
        );
        ensure!(
            !timeout.is_zero(),
            "observer transport budget must be positive"
        );
        Ok(Self { socket, timeout })
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "local transport deadlines never enter desired state or journal identities"
    )]
    fn send(
        &self,
        event: &BoundaryEvent,
        cancellation: &CancellationToken,
        owner: u32,
        root_owner: u32,
    ) -> Result<()> {
        let started = Instant::now();
        let budget = Budget {
            started,
            timeout: self.timeout,
            cancellation,
        };
        budget.remaining()?;
        validate_socket(&self.socket, owner, root_owner)?;
        let payload = aos_contract::canonical::to_vec(event)?;
        ensure!(
            payload.len() <= MAX_FRAME_BYTES,
            "observer event exceeds frame limit"
        );
        let mut stream = connect(&self.socket, &budget)?;
        let peer = rustix::net::sockopt::socket_peercred(&stream)
            .context("reading observer peer credentials")?;
        ensure!(
            peer.uid.as_raw() == owner,
            "observer peer is not the trusted owner"
        );

        let length = u32::try_from(payload.len())?.to_be_bytes();
        write_controlled(&mut stream, &length, &budget)?;
        write_controlled(&mut stream, &payload, &budget)?;
        let mut length = [0; 4];
        read_controlled(&mut stream, &mut length, &budget)?;
        let length = usize::try_from(u32::from_be_bytes(length))?;
        ensure!(
            length <= MAX_FRAME_BYTES,
            "observer acknowledgement exceeds frame limit"
        );
        let mut acknowledgement = vec![0; length];
        read_controlled(&mut stream, &mut acknowledgement, &budget)?;
        let response: Acknowledgement = aos_contract::canonical::from_slice(
            &acknowledgement,
            "native boundary acknowledgement",
        )?;
        ensure!(
            aos_contract::canonical::to_vec(&response)? == acknowledgement,
            "observer acknowledgement is not canonical"
        );
        ensure!(
            response.schema == "aos.activation.boundary-ack"
                && response.action == "continue"
                && response.event_digest == Sha256Digest::separated(EVENT_DOMAIN, &payload),
            "observer acknowledgement does not match event"
        );
        Ok(())
    }
}

impl BoundaryObserver for SocketBoundaryObserver {
    fn boundary(&mut self, event: &BoundaryEvent, cancellation: &CancellationToken) -> Result<()> {
        self.send(event, cancellation, 0, 0)
    }
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Acknowledgement {
    schema: String,
    action: String,
    event_digest: Sha256Digest,
}

struct Budget<'a> {
    started: Instant,
    timeout: Duration,
    cancellation: &'a CancellationToken,
}

impl Budget<'_> {
    #[allow(
        clippy::disallowed_methods,
        reason = "local transport elapsed time only bounds instrumentation"
    )]
    fn remaining(&self) -> Result<Duration> {
        ensure!(
            !self.cancellation.is_cancelled(),
            "boundary observation cancelled"
        );
        let remaining = self
            .timeout
            .checked_sub(self.started.elapsed())
            .context("boundary observation deadline expired")?;
        ensure!(
            !remaining.is_zero(),
            "boundary observation deadline expired"
        );
        Ok(remaining.min(POLL_INTERVAL))
    }

    fn wait(&self) -> Result<()> {
        let remaining = self.remaining()?;
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: i64::from(remaining.subsec_nanos()),
        };
        match rustix::event::poll(&mut [], Some(&timeout)) {
            Ok(_) => Ok(()),
            Err(error) if error == rustix::io::Errno::INTR => Ok(()),
            Err(error) => Err(error).context("waiting for observer transport"),
        }
    }
}

fn validate_socket(path: &Path, owner: u32, root_owner: u32) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        let metadata =
            fs::symlink_metadata(&current).context("inspecting protected observer path")?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "observer path contains a symlink"
        );
        if current == path {
            ensure!(
                metadata.file_type().is_socket()
                    && metadata.uid() == owner
                    && metadata.mode() & 0o022 == 0,
                "observer socket is not protected"
            );
        } else {
            // Root-owned sticky ancestors permit private test allocations under
            // /tmp without granting another user control over the endpoint.
            let sticky_root = metadata.uid() == root_owner && metadata.mode() & 0o1000 != 0;
            ensure!(
                metadata.is_dir()
                    && (metadata.uid() == root_owner || metadata.uid() == owner)
                    && (metadata.mode() & 0o022 == 0 || sticky_root),
                "observer parent is not protected"
            );
        }
    }
    Ok(())
}

fn connect(path: &Path, budget: &Budget<'_>) -> Result<UnixStream> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, socket_with};
    let descriptor = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    let address = SocketAddrUnix::new(path)?;
    loop {
        budget.remaining()?;
        match rustix::net::connect(&descriptor, &address) {
            Ok(()) => return Ok(UnixStream::from(descriptor)),
            Err(error) if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::INTR => {
                budget.wait()?
            }
            Err(error) if error == rustix::io::Errno::INPROGRESS => loop {
                let timeout = budget.remaining()?;
                let timeout = rustix::event::Timespec {
                    tv_sec: 0,
                    tv_nsec: i64::from(timeout.subsec_nanos()),
                };
                let mut ready = [rustix::event::PollFd::new(
                    &descriptor,
                    rustix::event::PollFlags::OUT,
                )];
                match rustix::event::poll(&mut ready, Some(&timeout)) {
                    Ok(0) => continue,
                    Ok(_) => {
                        rustix::net::sockopt::socket_error(&descriptor)??;
                        return Ok(UnixStream::from(descriptor));
                    }
                    Err(error) if error == rustix::io::Errno::INTR => continue,
                    Err(error) => return Err(error).context("polling observer connection"),
                }
            },
            Err(error) => return Err(error).context("connecting observer socket"),
        }
    }
}

fn write_controlled(stream: &mut UnixStream, mut bytes: &[u8], budget: &Budget<'_>) -> Result<()> {
    while !bytes.is_empty() {
        budget.remaining()?;
        match stream.write(bytes) {
            Ok(0) => bail!("observer closed before receiving event"),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if retryable(&error) => budget.wait()?,
            Err(error) => return Err(error).context("writing observer event"),
        }
    }
    Ok(())
}

fn read_controlled(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    budget: &Budget<'_>,
) -> Result<()> {
    while !bytes.is_empty() {
        budget.remaining()?;
        match stream.read(bytes) {
            Ok(0) => bail!("observer closed before acknowledging event"),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if retryable(&error) => budget.wait()?,
            Err(error) => return Err(error).context("reading observer acknowledgement"),
        }
    }
    Ok(())
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    )
}

#[cfg(test)]
mod tests {
    use super::super::{Action, Boundary};
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::thread;

    fn event() -> BoundaryEvent {
        BoundaryEvent {
            schema: EVENT_DOMAIN.into(),
            transaction: "example".into(),
            effect: "files.write.example".into(),
            revision: "exact-revision".into(),
            action: Action::Apply,
            journal_sequence: 1,
            boundary: Boundary::IntentDurable,
        }
    }

    #[test]
    fn exact_event_requires_canonical_digest_bound_acknowledgement() -> Result<()> {
        let directory = tempfile::tempdir_in("/tmp")?;
        let socket = directory.path().join("observer.sock");
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let owner = fs::metadata(&socket)?.uid();
        let worker = thread::spawn(move || -> Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut length = [0; 4];
            stream.read_exact(&mut length)?;
            let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
            stream.read_exact(&mut bytes)?;
            assert_eq!(bytes, aos_contract::canonical::to_vec(&event())?);
            let ack = Acknowledgement {
                schema: "aos.activation.boundary-ack".into(),
                action: "continue".into(),
                event_digest: Sha256Digest::separated(EVENT_DOMAIN, &bytes),
            };
            let bytes = aos_contract::canonical::to_vec(&ack)?;
            stream.write_all(&(u32::try_from(bytes.len())?).to_be_bytes())?;
            stream.write_all(&bytes)?;
            Ok(())
        });
        let observer = SocketBoundaryObserver::new(socket, Duration::from_secs(1))?;
        observer.send(
            &event(),
            &CancellationToken::default(),
            owner,
            fs::metadata("/")?.uid(),
        )?;
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("observer test worker panicked"))??;
        Ok(())
    }

    #[test]
    fn stalled_acknowledgement_exhausts_transport_budget() -> Result<()> {
        let directory = tempfile::tempdir_in("/tmp")?;
        let socket = directory.path().join("observer.sock");
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let owner = fs::metadata(&socket)?.uid();
        let observer = SocketBoundaryObserver::new(socket, Duration::from_millis(20))?;
        assert!(
            observer
                .send(&event(), &CancellationToken::default(), owner, fs::metadata("/")?.uid())
                .is_err()
        );
        drop(listener);
        Ok(())
    }

    #[test]
    fn cancelled_observation_has_no_socket_side_effect() -> Result<()> {
        let observer = SocketBoundaryObserver::new(
            PathBuf::from("/run/absent-observer.sock"),
            Duration::from_secs(1),
        )?;
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let error = observer.send(&event(), &cancellation, 0, 0).unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        Ok(())
    }

    #[test]
    fn noncanonical_socket_paths_are_rejected() {
        for path in [
            "relative.sock",
            "/run/../observer.sock",
            "/run//observer.sock",
            "/run/./observer.sock",
        ] {
            assert!(
                SocketBoundaryObserver::new(PathBuf::from(path), Duration::from_secs(1)).is_err(),
                "{path}"
            );
        }
    }
}
