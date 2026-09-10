//! Optional protected observation of native execution boundaries.
//!
//! The production observer is disabled when its fixed root-owned configuration
//! file is absent. When enabled, it connects to one protected Unix socket and
//! exchanges canonical, length-framed boundary events for digest-bound continue
//! acknowledgements. The protocol carries execution identity and live budget,
//! never adapter requests, evidence, outputs, or commands that can select a
//! transaction result.
//!
//! The root-owned opt-in configuration is canonical JSON:
//!
//! ```json
//! {"schema":"aos.ability-execution-observer/v1","socket":"/run/aos-instrumentation/controller.sock"}
//! ```
//!
//! Each message is a four-byte big-endian length followed by canonical JSON.
//! Events identify the exact transaction, plan-qualified operation, attempt,
//! purpose, boundary, and live budget. The only accepted response is:
//!
//! ```json
//! {"action":"continue","event_digest":"sha256:<64 lowercase hex digits>","schema":"aos.ability-execution-boundary-ack/v1"}
//! ```

use std::cmp;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_runtime::adapter::{InvocationPurpose, RuntimeControl};
use aos_ability_runtime::execution::{
    Boundary, ExecutionBoundaryControl, ExecutionBoundaryObservation, ExecutionBoundaryObserver,
};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::native_ability_fs::RootedDirectory;

const CONFIG_PATH: &str = "/etc/aos/ability-execution-observer.json";
const CONFIG_SCHEMA: &str = "aos.ability-execution-observer/v1";
const EVENT_SCHEMA: &str = "aos.ability-execution-boundary-event/v1";
const ACK_SCHEMA: &str = "aos.ability-execution-boundary-ack/v1";
const EVENT_DIGEST_DOMAIN: &str = "aos.ability-execution-boundary-event/v1";
const SOCKET_ROOT: &str = "/run/aos-instrumentation";
const CONFIG_MAX_BYTES: u64 = 4 * 1024;
const FRAME_MAX_BYTES: usize = 16 * 1024;
const POLL_MILLIS: u64 = 50;
const SETUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Reports native execution boundaries through an explicitly enabled channel.
#[derive(Debug)]
pub(super) enum NativeExecutionBoundaryObserver {
    Disabled,
    Socket(SocketBoundaryObserver),
}

impl NativeExecutionBoundaryObserver {
    /// Loads the fixed protected observer configuration when it exists.
    ///
    /// # Errors
    ///
    /// Returns an error when an existing configuration or socket violates the
    /// protected path contract, cannot connect, or has a non-root peer.
    pub(super) fn load() -> Result<Self> {
        let config_path = Path::new(CONFIG_PATH);
        let present = match fs::symlink_metadata(config_path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", config_path.display()));
            }
        };
        if !present {
            return Ok(Self::Disabled);
        }
        ensure!(
            rustix::process::geteuid().as_raw() == 0,
            "native execution observation requires UID 0"
        );
        Self::load_optional_from(config_path, 0, 0, Path::new(SOCKET_ROOT))
    }

    fn load_optional_from(
        config_path: &Path,
        trusted_owner: u32,
        peer_owner: u32,
        socket_root: &Path,
    ) -> Result<Self> {
        match fs::symlink_metadata(config_path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Self::Disabled);
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", config_path.display()));
            }
        }
        Self::load_from(config_path, trusted_owner, peer_owner, socket_root)
    }

    fn load_from(
        config_path: &Path,
        trusted_owner: u32,
        peer_owner: u32,
        socket_root: &Path,
    ) -> Result<Self> {
        let parent_path = config_path
            .parent()
            .context("native execution observer configuration has no parent")?;
        let file_name = config_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("native execution observer configuration has no UTF-8 file name")?;
        let parent = RootedDirectory::open(
            parent_path,
            trusted_owner,
            "native execution observer configuration parent",
        )
        .context("opening native execution observer configuration parent")?;
        let bytes = parent
            .resolve(Path::new(file_name))
            .context("resolving native execution observer configuration")?
            .read(CONFIG_MAX_BYTES)
            .context("reading native execution observer configuration")?;
        let config: ObserverConfig =
            aos_contract::canonical::from_slice(&bytes, "native execution observer configuration")
                .context("decoding native execution observer configuration")?;
        ensure!(
            aos_contract::canonical::to_vec(&config)? == bytes,
            "native execution observer configuration is not canonical"
        );
        config.validate(socket_root)?;

        validate_socket_path(&config.socket, trusted_owner)?;
        let stream = connect_with_timeout(&config.socket, SETUP_TIMEOUT).with_context(|| {
            format!(
                "connecting native execution observer {}",
                config.socket.display()
            )
        })?;
        validate_peer(&stream, peer_owner)?;

        Ok(Self::Socket(SocketBoundaryObserver { stream }))
    }
}

impl ExecutionBoundaryObserver for NativeExecutionBoundaryObserver {
    fn observe(
        &mut self,
        observation: ExecutionBoundaryObservation<'_>,
        control: &dyn RuntimeControl,
    ) -> Result<ExecutionBoundaryControl> {
        match self {
            Self::Disabled => Ok(ExecutionBoundaryControl::Continue),
            Self::Socket(observer) => observer.observe(observation, control),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ObserverConfig {
    schema: String,
    socket: PathBuf,
}

impl ObserverConfig {
    fn validate(&self, socket_root: &Path) -> Result<()> {
        ensure!(self.schema == CONFIG_SCHEMA, "unsupported observer schema");
        let socket_text = self
            .socket
            .to_str()
            .context("native execution observer socket path is not UTF-8")?;
        ensure!(
            is_canonical_absolute(socket_text),
            "native execution observer socket is not a canonical absolute path"
        );
        ensure!(
            self.socket.parent() == Some(socket_root),
            "native execution observer socket must be a direct child of {}",
            socket_root.display()
        );
        let name = self
            .socket
            .file_name()
            .and_then(|name| name.to_str())
            .context("native execution observer socket has no UTF-8 file name")?;
        ensure!(
            !name.is_empty() && name != "." && name != ".." && !name.contains('/'),
            "native execution observer socket has an invalid name"
        );
        Ok(())
    }
}

fn is_canonical_absolute(path: &str) -> bool {
    path.starts_with('/')
        && path != "/"
        && !path.ends_with('/')
        && !path.contains("//")
        && !path
            .split('/')
            .any(|component| matches!(component, "." | ".."))
}

#[derive(Debug)]
pub(super) struct SocketBoundaryObserver {
    stream: UnixStream,
}

impl SocketBoundaryObserver {
    fn observe(
        &mut self,
        observation: ExecutionBoundaryObservation<'_>,
        control: &dyn RuntimeControl,
    ) -> Result<ExecutionBoundaryControl> {
        ensure_live_budget(control)?;
        let event = BoundaryEvent {
            schema: EVENT_SCHEMA,
            transaction: observation.transaction(),
            operation: observation.operation(),
            attempt: observation.attempt().get(),
            purpose: purpose_name(observation.purpose()),
            boundary: boundary_name(observation.boundary()),
            cancelled: control.is_cancelled(),
            attempt_remaining_millis: control.attempt_remaining_millis(),
            recovery_remaining_millis: control.recovery_remaining_millis(),
        };
        self.exchange(&event, control)
    }

    fn exchange(
        &mut self,
        event: &BoundaryEvent<'_>,
        control: &dyn RuntimeControl,
    ) -> Result<ExecutionBoundaryControl> {
        let event_bytes = aos_contract::canonical::to_vec(event)
            .context("encoding native execution boundary event")?;
        ensure!(
            event_bytes.len() <= FRAME_MAX_BYTES,
            "native execution boundary event exceeds its frame limit"
        );
        let event_digest = Sha256Digest::separated(EVENT_DIGEST_DOMAIN, &event_bytes);

        write_frame(&mut self.stream, &event_bytes, control)
            .context("publishing native execution boundary event")?;
        let acknowledgement = read_frame(&mut self.stream, control)
            .context("reading native execution boundary acknowledgement")?;
        let ack: BoundaryAcknowledgement = aos_contract::canonical::from_slice(
            &acknowledgement,
            "native execution boundary acknowledgement",
        )
        .context("decoding native execution boundary acknowledgement")?;
        ensure!(
            aos_contract::canonical::to_vec(&ack)? == acknowledgement,
            "native execution boundary acknowledgement is not canonical"
        );
        ensure!(
            ack.schema == ACK_SCHEMA,
            "unsupported acknowledgement schema"
        );
        ensure!(
            ack.event_digest == event_digest,
            "native execution boundary acknowledgement names another event"
        );
        ensure!(
            ack.action == "continue",
            "native execution boundary acknowledgement has an unsupported action"
        );
        ensure_live_budget(control)?;
        Ok(ExecutionBoundaryControl::Continue)
    }
}

#[derive(Serialize)]
struct BoundaryEvent<'a> {
    schema: &'static str,
    transaction: &'a aos_ability_model::TransactionId,
    operation: &'a aos_ability_model::OperationId,
    attempt: u32,
    purpose: &'static str,
    boundary: &'static str,
    cancelled: bool,
    attempt_remaining_millis: u64,
    recovery_remaining_millis: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundaryAcknowledgement {
    schema: String,
    event_digest: Sha256Digest,
    action: String,
}

fn validate_socket_path(path: &Path, trusted_owner: u32) -> Result<()> {
    let parent = path
        .parent()
        .context("native execution observer socket has no parent")?;
    RootedDirectory::open(
        parent,
        trusted_owner,
        "native execution observer socket parent",
    )
    .context("opening protected native execution observer socket parent")?;
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "inspecting native execution observer socket {}",
            path.display()
        )
    })?;
    ensure!(
        metadata.file_type().is_socket()
            && metadata.uid() == trusted_owner
            && metadata.mode() & 0o022 == 0,
        "native execution observer socket is not protected by its trusted owner"
    );
    Ok(())
}

#[allow(
    clippy::disallowed_methods,
    reason = "this native setup deadline bounds a local instrumentation connection and never enters deterministic state"
)]
fn connect_with_timeout(path: &Path, timeout: Duration) -> Result<UnixStream> {
    use rustix::net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with,
    };

    let descriptor = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .context("creating nonblocking native execution observer socket")?;
    let address =
        SocketAddrUnix::new(path).context("encoding native execution observer socket address")?;
    let started = Instant::now();
    loop {
        match connect(&descriptor, &address) {
            Ok(()) => break,
            Err(error) if error == rustix::io::Errno::INPROGRESS => {
                let remaining = timeout
                    .checked_sub(started.elapsed())
                    .context("native execution observer setup deadline expired")?;
                await_nonblocking_connect(&descriptor, remaining)?;
                break;
            }
            Err(error) if error == rustix::io::Errno::AGAIN => {
                let remaining = timeout
                    .checked_sub(started.elapsed())
                    .context("native execution observer setup deadline expired")?;
                wait_before_connect_retry(cmp::min(remaining, Duration::from_millis(10)))?;
            }
            Err(error) => {
                return Err(io::Error::from(error))
                    .context("connecting nonblocking native execution observer socket");
            }
        }
    }

    let stream = UnixStream::from(descriptor);
    stream
        .set_nonblocking(false)
        .context("restoring blocking observer frame transport")?;
    Ok(stream)
}

fn wait_before_connect_retry(timeout: Duration) -> Result<()> {
    use rustix::event::poll;

    let timeout = duration_timespec(timeout);
    match poll(&mut [], Some(&timeout)) {
        Ok(_) => Ok(()),
        Err(error) if error == rustix::io::Errno::INTR => Ok(()),
        Err(error) => Err(io::Error::from(error))
            .context("waiting to retry native execution observer connection"),
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "this native setup deadline bounds a local instrumentation connection and never enters deterministic state"
)]
fn await_nonblocking_connect(descriptor: &OwnedFd, timeout: Duration) -> Result<()> {
    use rustix::event::{PollFd, PollFlags, poll};

    let started = Instant::now();
    loop {
        let remaining = timeout
            .checked_sub(started.elapsed())
            .context("native execution observer setup deadline expired")?;
        let timeout = duration_timespec(remaining);
        let mut ready = [PollFd::new(descriptor, PollFlags::OUT)];
        match poll(&mut ready, Some(&timeout)) {
            Ok(0) => bail!("native execution observer setup deadline expired"),
            Ok(_) => {
                return match rustix::net::sockopt::socket_error(descriptor)
                    .context("reading native execution observer connect result")?
                {
                    Ok(()) => Ok(()),
                    Err(error) => Err(io::Error::from(error))
                        .context("native execution observer rejected the nonblocking connection"),
                };
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) => {
                return Err(io::Error::from(error))
                    .context("polling native execution observer connection");
            }
        }
    }
}

fn duration_timespec(duration: Duration) -> rustix::event::Timespec {
    rustix::event::Timespec {
        tv_sec: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        tv_nsec: i64::from(duration.subsec_nanos()),
    }
}

#[cfg(target_os = "linux")]
fn validate_peer(stream: &UnixStream, peer_owner: u32) -> Result<()> {
    let credentials = rustix::net::sockopt::socket_peercred(stream)
        .context("reading native execution observer peer credentials")?;
    ensure!(
        credentials.uid.as_raw() == peer_owner,
        "native execution observer peer is not the trusted owner"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_peer(_stream: &UnixStream, _peer_owner: u32) -> Result<()> {
    bail!("native execution observation requires peer credentials")
}

fn write_frame(
    stream: &mut UnixStream,
    payload: &[u8],
    control: &dyn RuntimeControl,
) -> Result<()> {
    let length = u32::try_from(payload.len()).context("encoding observer frame length")?;
    write_controlled(stream, &length.to_be_bytes(), control)?;
    write_controlled(stream, payload, control)
}

fn read_frame(stream: &mut UnixStream, control: &dyn RuntimeControl) -> Result<Vec<u8>> {
    let mut encoded_length = [0_u8; 4];
    read_controlled(stream, &mut encoded_length, control)?;
    let length = usize::try_from(u32::from_be_bytes(encoded_length))
        .context("decoding observer frame length")?;
    ensure!(
        length <= FRAME_MAX_BYTES,
        "native execution observer acknowledgement exceeds its frame limit"
    );
    let mut payload = vec![0_u8; length];
    read_controlled(stream, &mut payload, control)?;
    Ok(payload)
}

fn write_controlled(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    control: &dyn RuntimeControl,
) -> Result<()> {
    while !bytes.is_empty() {
        let timeout = poll_timeout(control)?;
        stream
            .set_write_timeout(Some(timeout))
            .context("setting observer write timeout")?;
        match stream.write(bytes) {
            Ok(0) => bail!("native execution observer closed while receiving an event"),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if retryable(&error) => {}
            Err(error) => return Err(error).context("writing observer frame"),
        }
    }
    Ok(())
}

fn read_controlled(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    control: &dyn RuntimeControl,
) -> Result<()> {
    while !bytes.is_empty() {
        let timeout = poll_timeout(control)?;
        stream
            .set_read_timeout(Some(timeout))
            .context("setting observer read timeout")?;
        match stream.read(bytes) {
            Ok(0) => bail!("native execution observer closed before acknowledging the event"),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if retryable(&error) => {}
            Err(error) => return Err(error).context("reading observer frame"),
        }
    }
    Ok(())
}

fn poll_timeout(control: &dyn RuntimeControl) -> Result<Duration> {
    ensure_live_budget(control)?;
    let remaining = cmp::min(
        control.attempt_remaining_millis(),
        control.recovery_remaining_millis(),
    );
    Ok(Duration::from_millis(cmp::min(remaining, POLL_MILLIS)))
}

fn ensure_live_budget(control: &dyn RuntimeControl) -> Result<()> {
    ensure!(
        !control.is_cancelled(),
        "native execution boundary observation was cancelled"
    );
    ensure!(
        control.attempt_remaining_millis() > 0 && control.recovery_remaining_millis() > 0,
        "native execution boundary observation exhausted its live budget"
    );
    Ok(())
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

const fn purpose_name(purpose: InvocationPurpose) -> &'static str {
    match purpose {
        InvocationPurpose::Effect => "effect",
        InvocationPurpose::Reconcile => "reconcile",
        InvocationPurpose::Cancel => "cancel",
        InvocationPurpose::Compensate => "compensate",
        InvocationPurpose::ReconcileCompensation => "reconcile-compensation",
    }
}

const fn boundary_name(boundary: Boundary) -> &'static str {
    match boundary {
        Boundary::EffectIntentDurable => "effect-intent-durable",
        Boundary::EffectReturned => "effect-returned",
        Boundary::EffectOutcomeDurable => "effect-outcome-durable",
        Boundary::ReconciliationIntentDurable => "reconciliation-intent-durable",
        Boundary::ReconciliationReturned => "reconciliation-returned",
        Boundary::ReconciliationOutcomeDurable => "reconciliation-outcome-durable",
        Boundary::CancellationIntentDurable => "cancellation-intent-durable",
        Boundary::CancellationReturned => "cancellation-returned",
        Boundary::CancellationOutcomeDurable => "cancellation-outcome-durable",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use aos_ability_model::{
        LocalKey, OperationId, PlanId, ScopePath, ScopedOperationKey, TransactionId,
    };
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn absent_configuration_has_no_socket_side_effect() -> Result<()> {
        let temporary = TempDir::new()?;
        let missing = temporary.path().join("missing/config.json");
        let observer = NativeExecutionBoundaryObserver::load_optional_from(
            &missing,
            current_uid(),
            current_uid(),
            &temporary.path().join("socket-root"),
        )?;

        assert!(matches!(
            observer,
            NativeExecutionBoundaryObserver::Disabled
        ));
        assert!(!temporary.path().join("missing").exists());
        assert!(!temporary.path().join("socket-root").exists());
        Ok(())
    }

    #[test]
    fn configuration_rejects_normalized_socket_spellings() {
        for socket in [
            "/run/aos-instrumentation/./observer.sock",
            "/run/aos-instrumentation//observer.sock",
            "/run/aos-instrumentation/../observer.sock",
        ] {
            let config = ObserverConfig {
                schema: CONFIG_SCHEMA.to_string(),
                socket: PathBuf::from(socket),
            };
            assert!(config.validate(Path::new(SOCKET_ROOT)).is_err(), "{socket}");
        }
    }

    #[test]
    fn protected_configuration_connects_to_the_exact_owner() -> Result<()> {
        let fixture = LoaderFixture::new()?;
        let observer = NativeExecutionBoundaryObserver::load_from(
            &fixture.config,
            current_uid(),
            current_uid(),
            &fixture.socket_root,
        )?;

        assert!(matches!(
            observer,
            NativeExecutionBoundaryObserver::Socket(_)
        ));
        Ok(())
    }

    #[test]
    fn protected_configuration_rejects_wrong_peer_credentials() -> Result<()> {
        let fixture = LoaderFixture::new()?;
        let error = NativeExecutionBoundaryObserver::load_from(
            &fixture.config,
            current_uid(),
            current_uid().saturating_add(1),
            &fixture.socket_root,
        )
        .expect_err("a peer with another UID must be rejected");

        assert!(error.to_string().contains("peer is not the trusted owner"));
        Ok(())
    }

    #[test]
    fn protected_configuration_rejects_symlink_and_writable_parent() -> Result<()> {
        let temporary = TempDir::new()?;
        let socket_root = temporary.path().join("sockets");
        fs::create_dir(&socket_root)?;
        fs::set_permissions(&socket_root, fs::Permissions::from_mode(0o700))?;
        let socket = socket_root.join("observer.sock");
        let _listener = UnixListener::bind(&socket)?;
        let bytes = config_bytes(&socket)?;

        let safe_parent = temporary.path().join("safe");
        fs::create_dir(&safe_parent)?;
        fs::set_permissions(&safe_parent, fs::Permissions::from_mode(0o700))?;
        let target = safe_parent.join("target.json");
        fs::write(&target, &bytes)?;
        let linked = safe_parent.join("linked.json");
        symlink(&target, &linked)?;
        assert!(
            NativeExecutionBoundaryObserver::load_from(
                &linked,
                current_uid(),
                current_uid(),
                &socket_root,
            )
            .is_err()
        );

        let writable_parent = temporary.path().join("writable");
        fs::create_dir(&writable_parent)?;
        fs::set_permissions(&writable_parent, fs::Permissions::from_mode(0o777))?;
        let config = writable_parent.join("config.json");
        fs::write(&config, bytes)?;
        assert!(
            NativeExecutionBoundaryObserver::load_from(
                &config,
                current_uid(),
                current_uid(),
                &socket_root,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn digest_bound_canonical_acknowledgement_continues() -> Result<()> {
        let (client, mut server) = UnixStream::pair()?;
        let server_thread = thread::spawn(move || -> Result<()> {
            let event = read_test_frame(&mut server)?;
            let parsed = aos_contract::canonical::require_canonical(
                &event,
                "test native execution boundary event",
            )?;
            ensure!(parsed["purpose"] == "effect");
            ensure!(parsed["boundary"] == "effect-returned");
            ensure!(parsed.get("transaction").is_some());
            ensure!(parsed.pointer("/operation/plan").is_some());
            for forbidden in ["request", "evidence", "outputs", "result"] {
                ensure!(parsed.get(forbidden).is_none());
            }
            let acknowledgement = BoundaryAcknowledgement {
                schema: ACK_SCHEMA.to_string(),
                event_digest: Sha256Digest::separated(EVENT_DIGEST_DOMAIN, &event),
                action: "continue".to_string(),
            };
            write_test_frame(
                &mut server,
                &aos_contract::canonical::to_vec(&acknowledgement)?,
            )
        });
        let mut observer = SocketBoundaryObserver { stream: client };
        let identity = TestIdentity::new()?;

        assert_eq!(
            observer.exchange(&identity.event(), &TimedControl::new(2_000))?,
            ExecutionBoundaryControl::Continue
        );
        server_thread
            .join()
            .map_err(|_| anyhow::anyhow!("server panicked"))??;
        Ok(())
    }

    #[test]
    fn wrong_acknowledgement_and_eof_fail_closed() -> Result<()> {
        for response in [Some(Sha256Digest::of_bytes(b"wrong")), None] {
            let (client, mut server) = UnixStream::pair()?;
            let server_thread = thread::spawn(move || -> Result<()> {
                let _event = read_test_frame(&mut server)?;
                if let Some(event_digest) = response {
                    let acknowledgement = BoundaryAcknowledgement {
                        schema: ACK_SCHEMA.to_string(),
                        event_digest,
                        action: "continue".to_string(),
                    };
                    write_test_frame(
                        &mut server,
                        &aos_contract::canonical::to_vec(&acknowledgement)?,
                    )?;
                }
                Ok(())
            });
            let mut observer = SocketBoundaryObserver { stream: client };
            let identity = TestIdentity::new()?;

            assert!(
                observer
                    .exchange(&identity.event(), &TimedControl::new(2_000))
                    .is_err()
            );
            server_thread
                .join()
                .map_err(|_| anyhow::anyhow!("server panicked"))??;
        }
        Ok(())
    }

    #[test]
    fn noncanonical_version_action_and_length_acks_fail_closed() -> Result<()> {
        for mode in 0..3 {
            let (client, mut server) = UnixStream::pair()?;
            let server_thread = thread::spawn(move || -> Result<()> {
                let event = read_test_frame(&mut server)?;
                let mut acknowledgement = BoundaryAcknowledgement {
                    schema: ACK_SCHEMA.to_string(),
                    event_digest: Sha256Digest::separated(EVENT_DIGEST_DOMAIN, &event),
                    action: "continue".to_string(),
                };
                match mode {
                    0 => acknowledgement.schema.push_str("-unknown"),
                    1 => acknowledgement.action = "complete".to_string(),
                    2 => {}
                    _ => unreachable!("bounded test mode"),
                }
                let mut response = aos_contract::canonical::to_vec(&acknowledgement)?;
                if mode == 2 {
                    response.insert(0, b' ');
                }
                write_test_frame(&mut server, &response)
            });
            let mut observer = SocketBoundaryObserver { stream: client };
            let identity = TestIdentity::new()?;

            assert!(
                observer
                    .exchange(&identity.event(), &TimedControl::new(2_000))
                    .is_err()
            );
            server_thread
                .join()
                .map_err(|_| anyhow::anyhow!("server panicked"))??;
        }

        let (client, mut server) = UnixStream::pair()?;
        let server_thread = thread::spawn(move || -> Result<()> {
            let _event = read_test_frame(&mut server)?;
            let length = u32::try_from(FRAME_MAX_BYTES + 1)?;
            server.write_all(&length.to_be_bytes())?;
            Ok(())
        });
        let mut observer = SocketBoundaryObserver { stream: client };
        let identity = TestIdentity::new()?;
        assert!(
            observer
                .exchange(&identity.event(), &TimedControl::new(2_000))
                .is_err()
        );
        server_thread
            .join()
            .map_err(|_| anyhow::anyhow!("server panicked"))??;
        Ok(())
    }

    #[test]
    fn stalled_ack_obeys_deadline_and_cancellation() -> Result<()> {
        for cancel in [false, true] {
            let (client, mut server) = UnixStream::pair()?;
            let server_thread = thread::spawn(move || -> Result<()> {
                let _event = read_test_frame(&mut server)?;
                thread::sleep(Duration::from_millis(500));
                Ok(())
            });
            let mut observer = SocketBoundaryObserver { stream: client };
            let identity = TestIdentity::new()?;
            let control = TimedControl::new(if cancel { 2_000 } else { 120 });
            if cancel {
                let cancelled = Arc::clone(&control.cancelled);
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(100));
                    cancelled.store(true, Ordering::Release);
                });
            }
            let started = Instant::now();

            assert!(observer.exchange(&identity.event(), &control).is_err());
            assert!(started.elapsed() < Duration::from_millis(350));
            server_thread
                .join()
                .map_err(|_| anyhow::anyhow!("server panicked"))??;
        }
        Ok(())
    }

    #[test]
    fn saturated_listener_backlog_obeys_setup_deadline() -> Result<()> {
        use rustix::net::{AddressFamily, SocketAddrUnix, SocketType, bind, listen, socket};

        let temporary = TempDir::new()?;
        let path = temporary.path().join("saturated.sock");
        let listener = socket(AddressFamily::UNIX, SocketType::STREAM, None)?;
        bind(&listener, &SocketAddrUnix::new(&path)?)?;
        listen(&listener, 0)?;
        let first = connect_with_timeout(&path, Duration::from_millis(100))?;
        let started = Instant::now();

        let error = connect_with_timeout(&path, Duration::from_millis(120))
            .expect_err("a saturated Unix listener must not block setup indefinitely");
        assert!(error.to_string().contains("deadline expired"));
        assert!(started.elapsed() < Duration::from_millis(350));
        drop(first);
        Ok(())
    }

    struct LoaderFixture {
        _temporary: TempDir,
        _listener: UnixListener,
        config: PathBuf,
        socket_root: PathBuf,
    }

    impl LoaderFixture {
        fn new() -> Result<Self> {
            let temporary = TempDir::new()?;
            let config_root = temporary.path().join("config");
            let socket_root = temporary.path().join("sockets");
            fs::create_dir(&config_root)?;
            fs::create_dir(&socket_root)?;
            fs::set_permissions(&config_root, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&socket_root, fs::Permissions::from_mode(0o700))?;
            let socket = socket_root.join("observer.sock");
            let listener = UnixListener::bind(&socket)?;
            let config = config_root.join("observer.json");
            fs::write(&config, config_bytes(&socket)?)?;
            Ok(Self {
                _temporary: temporary,
                _listener: listener,
                config,
                socket_root,
            })
        }
    }

    fn config_bytes(socket: &Path) -> Result<Vec<u8>> {
        aos_contract::canonical::to_vec(&ObserverConfig {
            schema: CONFIG_SCHEMA.to_string(),
            socket: socket.to_path_buf(),
        })
    }

    struct TestIdentity {
        transaction: TransactionId,
        operation: OperationId,
    }

    impl TestIdentity {
        fn new() -> Result<Self> {
            Ok(Self {
                transaction: TransactionId(LocalKey::new("transaction")?),
                operation: OperationId {
                    plan: PlanId(Sha256Digest::of_bytes(b"plan")),
                    operation: ScopedOperationKey {
                        scope: ScopePath::root(),
                        key: LocalKey::new("publish")?,
                    },
                },
            })
        }

        fn event(&self) -> BoundaryEvent<'_> {
            BoundaryEvent {
                schema: EVENT_SCHEMA,
                transaction: &self.transaction,
                operation: &self.operation,
                attempt: 1,
                purpose: "effect",
                boundary: "effect-returned",
                cancelled: false,
                attempt_remaining_millis: 1_000,
                recovery_remaining_millis: 1_000,
            }
        }
    }

    struct TimedControl {
        started: Instant,
        timeout_millis: u64,
        cancelled: Arc<AtomicBool>,
    }

    impl TimedControl {
        fn new(timeout_millis: u64) -> Self {
            Self {
                started: Instant::now(),
                timeout_millis,
                cancelled: Arc::new(AtomicBool::new(false)),
            }
        }

        fn remaining(&self) -> u64 {
            let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.timeout_millis.saturating_sub(elapsed)
        }
    }

    impl RuntimeControl for TimedControl {
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::Acquire)
        }

        fn elapsed_millis(&self) -> u64 {
            self.timeout_millis.saturating_sub(self.remaining())
        }

        fn attempt_remaining_millis(&self) -> u64 {
            self.remaining()
        }

        fn recovery_remaining_millis(&self) -> u64 {
            self.remaining()
        }
    }

    fn read_test_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
        let mut length = [0_u8; 4];
        stream.read_exact(&mut length)?;
        let mut bytes = vec![0_u8; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn write_test_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
        stream.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
        stream.write_all(bytes)?;
        Ok(())
    }

    fn current_uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }
}
