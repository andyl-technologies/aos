//! Real accepted-connection rejection without invoking broker effects.

// Host time bounds subprocess cleanup only, never runtime or replay semantics.
#![allow(clippy::disallowed_methods)]

use std::os::fd::OwnedFd;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use aos_sandbox_linux::cgroup::CgroupV2Root;
use rustix::net::{
    AddressFamily, SendFlags, SocketAddrUnix, SocketFlags, SocketType, bind, connect, listen, send,
    socket_with,
};

use super::*;
use crate::peer::ControllerPeerVerifier;
use crate::service::{ConnectionOutcome, MountService};
use crate::transport::ActivatedSeqpacketListener;

const CHILD_PATH: &str = "AOS_MOUNT_STALE_PEER_TEST_PATH";

/// Kills and reaps a still-running fixture on assertion failure.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn connect_client(path: &std::path::Path) -> OwnedFd {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    connect(&socket, &SocketAddrUnix::new(path).unwrap()).unwrap();
    socket
}

#[test]
fn exited_connector_fixture() {
    let Some(path) = std::env::var_os(CHILD_PATH) else {
        return;
    };
    let client = connect_client(std::path::Path::new(&path));
    assert_eq!(send(&client, b"untrusted", SendFlags::NOSIGNAL).unwrap(), 9);
    // Exiting the separate test process closes its endpoint. The queued
    // connection and data remain for the parent's later accept.
}

#[test]
fn stale_accepted_peer_is_nonfatal_and_next_connection_is_handled() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("service.sock");
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    bind(&socket, &SocketAddrUnix::new(&path).unwrap()).unwrap();
    listen(&socket, 4).unwrap();
    // Bound even an unexpected loss of the pending connection: accept must
    // fail rather than strand the test runner.
    rustix::net::sockopt::set_socket_timeout(
        &socket,
        rustix::net::sockopt::Timeout::Recv,
        Some(Duration::from_secs(10)),
    )
    .unwrap();
    let listener = ActivatedSeqpacketListener::from_owned(socket).unwrap();

    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "broker::tests::service_peer::exited_connector_fixture",
        ])
        .env(CHILD_PATH, &path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "connector fixture failed: {status}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "connector fixture deadline elapsed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let (broker, _fixture) = test_broker(
        open(&directory.path().join("journal")),
        ScriptedWorker::default(),
    );
    let root: OwnedFd = std::fs::File::open("/sys/fs/cgroup").unwrap().into();
    let verifier = ControllerPeerVerifier::new(CgroupV2Root::from_owned(root).unwrap());
    let mut service = MountService::new(broker, verifier, (0, 0));

    assert_eq!(
        service.serve_once(&listener).unwrap(),
        ConnectionOutcome::PeerRejected
    );
    // A second live but unauthenticated peer exercises the same service and
    // listener after stale-peer rejection. This test process is not the controller,
    // so no handshake, authority admission, or broker effect can execute.
    let client = connect_client(&path);
    assert_eq!(
        service.serve_once(&listener).unwrap(),
        ConnectionOutcome::PeerRejected
    );

    drop(client);
}
