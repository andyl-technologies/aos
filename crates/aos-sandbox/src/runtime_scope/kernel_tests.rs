//! Actual response-subject authentication across a delegated activated listener.
//!
//! Run serially: process spawning can transiently inherit unrelated descriptors.
//! This tests kernel identity, not the host's strong payload-init attestation.

#![allow(
    clippy::expect_used,
    reason = "Kernel fixture failures intentionally panic."
)]
#![allow(
    clippy::disallowed_methods,
    reason = "Host monotonic time only bounds subprocess fixture waits, not runtime state."
)]

use std::fs::File;
use std::io::{BufRead as _, Write as _};
use std::os::fd::AsFd as _;
use std::process::{Child, Command, Stdio};

use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};

use super::*;

fn identity() -> HostServiceIdentity {
    let root = CgroupV2Root::from_owned(File::open("/sys/fs/cgroup").expect("cgroup root").into())
        .expect("cgroup2 root");
    let membership = std::fs::read_to_string("/proc/self/cgroup").expect("own membership");
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .expect("unified hierarchy");
    HostServiceIdentity {
        uid: rustix::process::geteuid().as_raw(),
        gid: rustix::process::getegid().as_raw(),
        cgroup: root
            .resolve(Path::new(if relative.is_empty() { "." } else { relative }))
            .expect("current cgroup"),
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn activated_listener_authenticates_actual_responder_not_creator() {
    let directory = tempfile::tempdir().expect("socket directory");
    let path = directory.path().join("host.sock");
    let listener = RecordSubjectListener::bind(&path, 8).expect("parent-created listener");
    let listener_input = listener
        .as_fd()
        .try_clone_to_owned()
        .expect("delegate listener");
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "runtime_scope::kernel_tests::activated_responder_fixture",
                "--nocapture",
            ])
            .env("AOS_RUNTIME_SCOPE_RESPONDER_FIXTURE", "1")
            .stdin(Stdio::from(listener_input))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn responder"),
    );
    let mut output = std::io::BufReader::new(child.0.stdout.take().expect("responder stdout"));
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(output.read_line(&mut line).expect("readiness"), 0);
        if line.contains("runtime-responder-ready") {
            break;
        }
    }
    let fd = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("client socket");
    connect(&fd, &SocketAddrUnix::new(&path).expect("socket address")).expect("connect");
    let peer = rustix::net::sockopt::socket_peercred(&fd).expect("listener creator credentials");
    assert_eq!(peer.pid.as_raw_nonzero().get() as u32, std::process::id());
    assert_ne!(child.0.id(), std::process::id());
    let mut client = RuntimeScopeClient::from_connected(fd, identity()).expect("scope client");
    let deadline =
        transport::exchange_deadline(transport::boottime().expect("clock") + 10_000_000_000)
            .expect("deadline");
    transport::send(&mut client.socket, b"hello", deadline).expect("send hello");
    let hello =
        transport::receive(&mut client.socket, 64, Some(0), deadline).expect("actual reply");
    let (_, subject, _) = hello.into_parts();
    assert_eq!(subject.initial_info().pid(), child.0.id());
    let host = HostExecution::new(client.expected_host, subject).expect("child host identity");
    assert_eq!(host.recheck().expect("live host").pid(), child.0.id());
    transport::send(&mut client.socket, b"observe", deadline).expect("send request");
    let reply =
        transport::receive(&mut client.socket, 64, Some(0), deadline).expect("second reply");
    host.validate_response(reply.subject())
        .expect("same execution");
    let mut wrong = identity();
    wrong.uid ^= 1;
    assert!(matches!(
        validate_host_subject(&wrong, reply.subject()),
        Err(RuntimeScopeError::HostIdentity)
    ));
    child.0.kill().expect("stop host");
    child.0.wait().expect("reap host");
    assert!(
        host.recheck().is_err(),
        "retained host must fail after exit"
    );
}

#[test]
fn activated_responder_fixture() {
    if std::env::var_os("AOS_RUNTIME_SCOPE_RESPONDER_FIXTURE").is_none() {
        return;
    }
    let mut listener = RecordSubjectListener::from_owned(
        std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .expect("activated listener"),
    )
    .expect("adopt listener");
    println!("runtime-responder-ready");
    std::io::stdout().flush().expect("flush readiness");
    let end = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut socket = loop {
        match listener.accept() {
            Ok(socket) => break socket,
            Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                assert!(std::time::Instant::now() < end, "accept deadline");
                std::thread::yield_now();
            }
            Err(error) => panic!("accept: {error}"),
        }
    };
    for _ in 0..2 {
        loop {
            match socket.receive(64) {
                Ok(_) => break,
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => {
                    assert!(std::time::Instant::now() < end, "request deadline");
                    std::thread::yield_now();
                }
                Err(error) => panic!("receive: {error}"),
            }
        }
        socket.send(b"reply").expect("child-authored response");
    }
    while std::time::Instant::now() < end {
        std::thread::park_timeout(std::time::Duration::from_millis(10));
    }
}
