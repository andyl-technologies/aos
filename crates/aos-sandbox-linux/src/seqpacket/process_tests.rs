//! Subprocess proof that delegated socket writers do not replace the establisher.
//!
//! The test executable runs a filtered connector fixture with a listener on
//! stdin and a private control socket on stderr. Harness stdout is discarded;
//! no multithreaded-process fork hooks or production descriptor APIs are added.

#![allow(
    clippy::expect_used,
    reason = "Subprocess fixture failures intentionally panic."
)]
#![allow(
    clippy::disallowed_methods,
    reason = "Host time bounds isolated test-process cleanup, not runtime or replay state."
)]

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::{ConnectionPeerIdentity, RecordSubjectListener, SeqpacketError};
use crate::Error;
use crate::uapi::{self, RawAncillary};

const FIXTURE_ENV: &str = "AOS_SEQPACKET_CONNECTOR_FIXTURE_V1";
const WAIT_LIMIT: Duration = Duration::from_secs(10);

struct Connector(Child);

impl Connector {
    fn wait_success(&mut self) {
        let deadline = Instant::now() + WAIT_LIMIT;
        loop {
            if let Some(status) = self.0.try_wait().expect("poll connector process") {
                assert!(status.success(), "connector failed: {status}");
                return;
            }
            assert!(Instant::now() < deadline, "connector did not exit");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl Drop for Connector {
    fn drop(&mut self) {
        // Bound the normal handshake with a deadline; on assertions or early
        // return, never leave the isolated fixture process alive or unreaped.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn receive_control(fd: BorrowedFd<'_>) -> (Vec<u8>, Vec<RawAncillary>) {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let mut payload = [0_u8; 32];
        match uapi::recv_seqpacket(fd, &mut payload, 0) {
            Ok(record) => {
                assert_eq!(record.flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC), 0);
                assert!(record.bytes > 0 && record.bytes <= payload.len());
                return (payload[..record.bytes].to_vec(), record.ancillary);
            }
            Err(Error::Syscall { source, .. })
                if matches!(source.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) => {}
            Err(error) => panic!("control receive failed: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "control receive deadline expired"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn spawn_connector(listener: BorrowedFd<'_>) -> (Connector, OwnedFd, OwnedFd) {
    let (parent_control, child_control) = uapi::seqpacket_pair().expect("create control pair");
    let child = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "seqpacket::process_tests::connector_fixture",
            "--nocapture",
        ])
        .env(FIXTURE_ENV, "1")
        .stdin(Stdio::from(
            listener.try_clone_to_owned().expect("duplicate listener"),
        ))
        .stderr(Stdio::from(child_control))
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn connector fixture");
    let connector = Connector(child);
    let (payload, ancillary) = receive_control(parent_control.as_fd());
    assert_eq!(payload, b"delegated");
    assert_eq!(
        ancillary.len(),
        1,
        "control must contain exactly one rights message"
    );
    let mut descriptors = match ancillary.into_iter().next() {
        Some(RawAncillary::Rights(descriptors)) => descriptors,
        other => panic!("unexpected control ancillary: {other:?}"),
    };
    assert_eq!(
        descriptors.len(),
        1,
        "control must delegate one client socket"
    );
    let delegated = descriptors.pop().expect("delegated client descriptor");
    (connector, parent_control, delegated)
}

fn finish_connector(connector: &mut Connector, control: BorrowedFd<'_>) {
    uapi::send_seqpacket(control, b"finish").expect("release connector");
    connector.wait_success();
}

#[test]
fn connector_fixture() {
    if std::env::var_os(FIXTURE_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    let stdin = std::io::stdin();
    let stderr = std::io::stderr();
    let client = uapi::connect_seqpacket_listener(stdin.as_fd()).expect("fixture connect");
    uapi::send_seqpacket_rights(stderr.as_fd(), b"delegated", &[client.as_fd()])
        .expect("delegate client socket");
    let (payload, ancillary) = receive_control(stderr.as_fd());
    assert_eq!(payload, b"finish");
    assert!(ancillary.is_empty());
    // Skip libtest's final output: stderr is solely this fixture's control IPC.
    std::process::exit(0);
}

#[test]
fn delegated_writer_has_its_own_record_identity_while_connector_remains_pinned() {
    let fd = uapi::seqpacket_listener().expect("create listener");
    uapi::enable_seqpacket_identity(fd.as_fd()).expect("configure listener before connect");
    let mut listener = RecordSubjectListener::from_owned(fd).expect("adopt listener");
    let (mut connector, control, delegated) = spawn_connector(listener.as_fd());
    let connector_pid = connector.0.id();
    assert_ne!(connector_pid, std::process::id());
    let mut accepted = listener.accept().expect("accept delegated connection");
    assert_eq!(accepted.peer().credentials().pid().get(), connector_pid);
    assert_eq!(accepted.peer().initial_info().pid(), connector_pid);

    uapi::send_seqpacket(delegated.as_fd(), b"actual writer").expect("write delegated client");
    let record = accepted
        .receive(128)
        .expect("receive delegated writer record");
    assert_eq!(record.payload(), b"actual writer");
    assert_eq!(
        record.subject().credentials().pid().get(),
        std::process::id()
    );
    assert_eq!(record.subject().initial_info().pid(), std::process::id());
    assert_eq!(accepted.peer().credentials().pid().get(), connector_pid);

    finish_connector(&mut connector, control.as_fd());
    assert!(
        !accepted
            .peer()
            .is_alive()
            .expect("connector pidfd liveness")
    );
}

#[test]
fn exited_connector_cannot_be_replaced_by_the_live_delegated_holder() {
    let listener = uapi::seqpacket_listener().expect("create listener");
    let (mut connector, control, delegated) = spawn_connector(listener.as_fd());
    finish_connector(&mut connector, control.as_fd());
    // The client file description is still live in this different process.
    uapi::send_seqpacket(delegated.as_fd(), b"holder still alive").expect("live delegated socket");
    let accepted =
        uapi::accept_record_subject_socket(listener.as_fd()).expect("accept after connector exit");
    let capture = ConnectionPeerIdentity::from_socket(accepted.as_fd());
    assert!(
        matches!(&capture, Err(SeqpacketError::Kernel(Error::Syscall { source, .. })) if source.raw_os_error() == Some(libc::ESRCH)),
        "dead connector must fail with ESRCH, not adopt the live holder: {capture:?}"
    );
}
