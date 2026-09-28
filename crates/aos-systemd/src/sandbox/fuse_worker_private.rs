//! Original fixed PID 1 private transport for worker descriptor delivery.
//!
//! System-bus monitors can retain forwarded descriptor copies. This client
//! therefore opens only PID 1's fixed private endpoint and retains its actual
//! socket, process pin and boot. Its compatibility handshake changes only this
//! authenticated Host connection's sender framing. Transport custody is not
//! Mount authority, endpoint nondelegation, or a Root resource-read grant.

use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::unix_stream::RetainedUnixStream;

use super::{
    ExactStartError, FuseWorkerUnitNameV1, FuseWorkerUnitObservationV1, FuseWorkerUnitSpecV1,
    invalid,
};
use crate::client::{JobOutcome, JobResult, SystemdClient};
use crate::error::{Error, Result};

const PRIVATE_SOCKET: &str = "/run/systemd/private";
const PRIVATE_SENDER: &str = ":1.0";
const SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Retains the original PID 1 connection used by the fixed worker launch role.
///
/// The sole constructor opens a fixed endpoint; no caller address, connection,
/// received descriptor or UID-only assertion is accepted. This wrapper exposes
/// neither a general Manager proxy nor its connection. PID 1 still independently
/// admits the image-owned fragment and executable for each actual launch.
#[must_use = "retain the original private PID 1 transport through worker readback"]
pub struct FixedFuseWorkerPid1ClientV1 {
    client: SystemdClient,
    peer: RetainedUnixStream,
    shutdown: ShutdownOriginalSocket,
    boot: KernelBootId,
    original: PidFdInfo,
    launch_consumed: AtomicBool,
    failed: AtomicBool,
}

impl FixedFuseWorkerPid1ClientV1 {
    /// Opens the fixed private endpoint and completes its worker-only handshake.
    ///
    /// No role descriptors are delivered during setup. An unexpected pre-handshake
    /// message, framing failure or ambiguous reply fails closed and tears down the
    /// same socket. The handshake is a compatibility prerequisite, not a claim
    /// that the worker image or a held Root/Mount dispatch is already admitted.
    ///
    /// # Errors
    ///
    /// Returns an error for a substituted or non-PID-1 peer, unsupported kernel
    /// pins, changed boot/process/socket, rejected role handshake, subscription
    /// failure, or setup exceeding the fixed deadline.
    pub async fn connect_fixed() -> Result<Self> {
        tokio::time::timeout(SETUP_TIMEOUT, Self::connect_original())
            .await
            .map_err(|_| Error::ExactUnitTimeout("worker private connection setup"))?
    }

    async fn connect_original() -> Result<Self> {
        let boot = KernelBootId::current().map_err(kernel_error)?;
        let socket = tokio::net::UnixStream::connect(PRIVATE_SOCKET)
            .await
            .map_err(zbus::Error::from)?;
        let shutdown = ShutdownOriginalSocket(socket.into_std().map_err(zbus::Error::from)?);
        let pin = shutdown
            .0
            .as_fd()
            .try_clone_to_owned()
            .map_err(zbus::Error::from)?;
        let peer = RetainedUnixStream::from_owned(pin).map_err(kernel_error)?;
        let original = peer.peer().pidfd().info().map_err(kernel_error)?;
        require_pid1(&peer, original)?;

        // The transport copy derives only from this original retained endpoint.
        // RetainedUnixStream verifies its SO_COOKIE before exposing the borrow.
        let duplicate = peer.duplicate().map_err(kernel_error)?;
        let descriptor = duplicate
            .as_fd()
            .try_clone_to_owned()
            .map_err(zbus::Error::from)?;
        let stream = tokio::net::UnixStream::from_std(UnixStream::from(descriptor))
            .map_err(zbus::Error::from)?;
        drop(duplicate);

        let connection = zbus::connection::Builder::unix_stream(stream)
            .p2p()
            .method_timeout(SETUP_TIMEOUT)
            .build()
            .await?;
        let reply = connection
            .call_method(
                Some("org.freedesktop.systemd1"),
                "/org/freedesktop/systemd1",
                Some("org.freedesktop.systemd1.Manager"),
                "OpenAosFuseWorkerPrivateTransportV1",
                &(),
            )
            .await?;
        require_role_reply(&reply)?;
        drop(reply);

        let client = SystemdClient::from_worker_private_connection(connection).await?;
        let retained = Self {
            client,
            peer,
            shutdown,
            boot,
            original,
            launch_consumed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
        };
        retained.recheck()?;
        Ok(retained)
    }

    /// Rechecks the same boot, live PID 1 pin, credentials and socket continuity.
    ///
    /// # Errors
    ///
    /// Returns an error for any changed kernel observation. This establishes
    /// transport continuity only, not per-message sender nondelegation or
    /// Controller/Mount/Root currentness.
    pub fn recheck(&self) -> Result<()> {
        if self.failed.load(Ordering::Acquire) {
            return Err(invalid("worker private transport is ambiguity-fenced"));
        }
        if KernelBootId::current().map_err(kernel_error)? != self.boot {
            return Err(invalid("worker private transport boot changed"));
        }
        let current = self.peer.peer().pidfd().info().map_err(kernel_error)?;
        require_pid1(&self.peer, current)?;
        if current != self.original {
            return Err(invalid("worker private PID 1 identity changed"));
        }
        // This fresh same-source duplicate verifies the retained SO_COOKIE.
        drop(self.peer.duplicate().map_err(kernel_error)?);
        Ok(())
    }

    /// Observes only a fixed worker locator over the same retained private peer.
    ///
    /// # Errors
    ///
    /// Returns an error for transport currentness, deadline, or manager failure.
    pub async fn observe_fuse_worker_unit_v1(
        &self,
        name: &FuseWorkerUnitNameV1,
    ) -> Result<Option<FuseWorkerUnitObservationV1>> {
        self.recheck()?;
        let observed = tokio::time::timeout(
            OPERATION_TIMEOUT,
            self.client.observe_fuse_worker_unit_v1(name),
        )
        .await
        .map_err(|_| Error::ExactUnitTimeout("worker private observation"))??;
        self.recheck()?;
        Ok(observed)
    }

    /// Delivers only the fixed five-role table over the original private peer.
    ///
    /// # Errors
    ///
    /// Returns an error for peer currentness, final caller admission, descriptor
    /// delivery, job completion or deadline. All post-submission errors remain
    /// ambiguous; no retry/rearm or reservation release is authorized here.
    ///
    /// # Panics
    ///
    /// Propagates a panic from the caller's guard before descriptor submission.
    pub async fn start_fuse_worker_unit_guarded_v1<E>(
        &self,
        spec: &FuseWorkerUnitSpecV1,
        guard: &mut (dyn FnMut() -> std::result::Result<(), E> + Send),
    ) -> std::result::Result<JobOutcome, ExactStartError<E>> {
        self.recheck().map_err(ExactStartError::Systemd)?;
        if self.launch_consumed.swap(true, Ordering::AcqRel) {
            return Err(ExactStartError::Systemd(invalid(
                "worker private transport already consumed its launch",
            )));
        }
        // The guard fences this original connection on future cancellation,
        // not just on an error which reaches the match below. This one-shot
        // transport state does not replace protected Host/Mount consumption.
        let mut flight = LaunchInFlight {
            client: self,
            completed: false,
        };
        let outcome = tokio::time::timeout(
            OPERATION_TIMEOUT,
            self.client.start_fuse_worker_unit_guarded_v1(spec, guard),
        )
        .await;
        let outcome = match outcome {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(error)) => {
                self.fence_ambiguous();
                return Err(error);
            }
            Err(_) => {
                self.fence_ambiguous();
                return Err(ExactStartError::Systemd(Error::ExactUnitTimeout(
                    "worker private launch",
                )));
            }
        };
        if outcome.result != JobResult::Done {
            return Err(ExactStartError::Systemd(invalid(
                "worker private launch did not complete",
            )));
        }
        self.recheck().map_err(ExactStartError::Systemd)?;
        flight.completed = true;
        Ok(outcome)
    }

    fn fence_ambiguous(&self) {
        self.failed.store(true, Ordering::Release);
        let _ = self.shutdown.0.shutdown(std::net::Shutdown::Both);
    }
}

struct LaunchInFlight<'client> {
    client: &'client FixedFuseWorkerPid1ClientV1,
    completed: bool,
}

impl Drop for LaunchInFlight<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.client.fence_ambiguous();
        }
    }
}

struct ShutdownOriginalSocket(UnixStream);

impl Drop for ShutdownOriginalSocket {
    fn drop(&mut self) {
        // Shutdown applies to the same socket including zbus's copy; it does
        // not wait for an async mutex or let cancellation preserve transport.
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

fn require_pid1(peer: &RetainedUnixStream, information: PidFdInfo) -> Result<()> {
    let credentials = peer.peer().credentials();
    let current = information
        .credentials()
        .ok_or_else(|| invalid("worker private PID 1 credentials are absent"))?;
    if credentials.pid().get() != 1
        || credentials.uid() != 0
        || credentials.gid() != 0
        || information.pid() != 1
        || information.thread_group_id() != 1
        || information.parent_pid() != 0
        || information.cgroup_id().is_none()
        || current.real_user_id() != 0
        || current.real_group_id() != 0
        || current.effective_user_id() != 0
        || current.effective_group_id() != 0
        || current.saved_user_id() != 0
        || current.saved_group_id() != 0
        || current.filesystem_user_id() != 0
        || current.filesystem_group_id() != 0
        || !peer.peer().is_alive().map_err(kernel_error)?
    {
        return Err(invalid(
            "worker private transport is not the original live PID 1",
        ));
    }
    Ok(())
}

fn kernel_error(error: aos_sandbox_linux::Error) -> Error {
    Error::WorkerPrivateKernel(error)
}

fn require_role_reply(reply: &zbus::Message) -> Result<()> {
    if reply.header().sender().map(|sender| sender.as_str()) != Some(PRIVATE_SENDER)
        || !reply.body().data().is_empty()
        || !reply.data().fds().is_empty()
    {
        return Err(invalid("worker private handshake returned a foreign reply"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original_call() -> zbus::Message {
        zbus::Message::method_call(
            "/org/freedesktop/systemd1",
            "OpenAosFuseWorkerPrivateTransportV1",
        )
        .unwrap()
        .build(&())
        .unwrap()
    }

    #[test]
    fn handshake_reply_requires_exact_private_sender_and_empty_body() {
        let call = original_call();
        let reply = zbus::Message::method_return(&call.header())
            .unwrap()
            .sender(PRIVATE_SENDER)
            .unwrap()
            .build(&())
            .unwrap();

        assert!(require_role_reply(&reply).is_ok());

        for sender in [":1.1", ":2.0"] {
            let reply = zbus::Message::method_return(&call.header())
                .unwrap()
                .sender(sender)
                .unwrap()
                .build(&())
                .unwrap();
            assert!(require_role_reply(&reply).is_err(), "{sender}");
        }
        let absent = zbus::Message::method_return(&call.header())
            .unwrap()
            .build(&())
            .unwrap();
        let body = zbus::Message::method_return(&call.header())
            .unwrap()
            .sender(PRIVATE_SENDER)
            .unwrap()
            .build(&"not a zero-input compatibility reply")
            .unwrap();

        assert!(require_role_reply(&absent).is_err());
        assert!(require_role_reply(&body).is_err());
    }

    #[test]
    fn handshake_reply_cannot_deliver_a_descriptor() {
        let call = original_call();
        let placeholder = std::fs::File::open("/dev/null").unwrap();
        let reply = zbus::Message::method_return(&call.header())
            .unwrap()
            .sender(PRIVATE_SENDER)
            .unwrap()
            .build(&zbus::zvariant::Fd::from(placeholder.as_fd()))
            .unwrap();

        assert!(require_role_reply(&reply).is_err());
    }
}
