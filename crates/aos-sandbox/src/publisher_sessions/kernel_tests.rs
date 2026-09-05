//! Real listener, cgroup, and pidfd checks through the production preparation path.
//!
//! Kernel qualification runs with `--test-threads=1`. During process spawning,
//! fork/exec can transiently inherit unrelated close-on-exec descriptors, which
//! would perturb concurrent socket-close or journal-flock lifetime assertions.
//! Serial qualification isolates these execution-identity fixtures; ordinary
//! package tests do not enable this kernel-only module.

#![allow(
    clippy::expect_used,
    reason = "Kernel fixture failures intentionally panic."
)]

use std::fs::File;
use std::io::{BufRead as _, Write as _};
use std::os::fd::AsFd as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use aos_sandbox_linux::cgroup::CgroupV2Root;
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};

use super::*;

fn anchor() -> RetainedCgroupAnchor {
    let root = CgroupV2Root::from_owned(File::open("/sys/fs/cgroup").expect("cgroup root").into())
        .expect("cgroup2 root");
    let membership = std::fs::read_to_string("/proc/self/cgroup").expect("own membership");
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .expect("unified hierarchy");
    root.resolve(Path::new(if relative.is_empty() { "." } else { relative }))
        .expect("current cgroup")
}

fn scope() -> PublisherSessionScope {
    PublisherSessionScope {
        principal: PrincipalId::from_bytes([1; 16]),
        node: NodeId::from_bytes([2; 16]),
        project: ProjectId::from_bytes([3; 16]),
        cache_resource: ResourceId::from_bytes([4; 16]),
    }
}

fn prepared(
    table: &mut PublisherSessionRegistry,
) -> (PreparedPublisherSession<'_>, SeqpacketSocket) {
    let (mut listener, sender) = connection();
    let prepared = table
        .prepare(&mut listener, scope(), anchor())
        .expect("accept and prepare");
    (prepared, sender)
}

fn connection() -> (RecordSubjectListener, SeqpacketSocket) {
    let directory = tempfile::tempdir().expect("socket directory");
    let path = directory.path().join("publisher.sock");
    let listener = RecordSubjectListener::bind(&path, 8).expect("configured listener");
    (listener, connect_sender(&path))
}

fn connect_sender(path: &Path) -> SeqpacketSocket {
    let sender = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("client socket");
    connect(&sender, &SocketAddrUnix::new(path).expect("socket address")).expect("connect");
    let mut sender = SeqpacketSocket::from_owned(sender).expect("client transport");
    // No controller record can be queued before the test explicitly accepts and
    // sends its greeting, so client-side observation is configured in time.
    sender
        .enable_record_subjects()
        .expect("client record subjects");
    sender
}

#[test]
fn prepare_abort_closes_and_activation_authenticates_original_process() {
    let mut table = PublisherSessionRegistry::new(PublisherSessionLimits {
        maximum_sessions: 1,
    })
    .expect("table");
    let (pending, mut aborted_sender) = prepared(&mut table);
    let old_instance = pending.instance();
    drop(pending);
    assert!(aborted_sender.send(b"closed").is_err());
    assert!(table.slots.iter().all(Option::is_none));

    let (mut pending, mut sender) = prepared(&mut table);
    let instance = pending.instance();
    let binding = pending.channel_binding();
    assert_ne!(instance, old_instance);
    assert_eq!(pending.scope(), &scope());
    assert_eq!(
        pending.check_current().expect("current peer").pid(),
        pending.peer_info().pid()
    );
    pending
        .send_registration_greeting()
        .expect("fixed greeting");
    let greeting = sender.receive(24).expect("receive greeting");
    assert_eq!(&greeting.payload()[..8], b"AOSPUBI1");
    assert_eq!(&greeting.payload()[8..], instance.as_bytes());
    assert_eq!(pending.activate(), instance);
    sender.send(b"raw request bytes").expect("send");
    let record = table
        .receive(instance)
        .expect("authenticated original process");
    assert_eq!(record.payload(), b"raw request bytes");
    assert_eq!(record.instance(), instance);
    assert_eq!(record.channel_binding(), binding);
    assert_eq!(record.scope(), &scope());
    assert_eq!(record.process_info().pid(), std::process::id());
    assert_eq!(
        record.recheck().expect("same retained process").pid(),
        std::process::id()
    );
    let (mut listener, _queued_sender) = connection();
    assert!(matches!(
        table.prepare(&mut listener, scope(), anchor()),
        Err(PublisherSessionError::ServiceReserved)
    ));
    assert!(
        listener.accept().is_ok(),
        "reserved service is rejected before accept"
    );
}

#[test]
fn fatal_receive_retires_transport_but_keeps_live_execution_reservation() {
    let mut table = PublisherSessionRegistry::new(PublisherSessionLimits {
        maximum_sessions: 1,
    })
    .expect("table");
    let (pending, mut sender) = prepared(&mut table);
    let instance = pending.activate();
    assert!(matches!(
        table.receive(instance),
        Err(PublisherSessionError::Transport(SeqpacketError::WouldBlock))
    ));
    assert!(matches!(
        table.release_retired_after_exit(instance),
        Err(PublisherSessionError::NotRetired)
    ));
    sender
        .send(&vec![1; MAXIMUM_REQUEST_BYTES + 1])
        .expect("send oversized request");
    assert!(matches!(
        table.receive(instance),
        Err(PublisherSessionError::Transport(
            SeqpacketError::RecordTooLarge { .. }
        ))
    ));
    assert!(matches!(
        table.receive(instance),
        Err(PublisherSessionError::Retired)
    ));
    assert!(sender.send(b"closed").is_err());
    assert!(matches!(
        table.release_retired_after_exit(instance),
        Err(PublisherSessionError::ExecutionAlive)
    ));
    assert!(table.slots.iter().all(Option::is_some));
    let retained = table.slots[0].as_ref().expect("retained execution");
    assert!(
        retained
            .socket
            .peer()
            .is_alive()
            .expect("retained peer pin")
    );
    assert_eq!(retained.scope, scope());
    table.retire(instance).expect("idempotent retirement");

    let (mut listener, _queued_sender) = connection();
    assert!(matches!(
        table.prepare(&mut listener, scope(), anchor()),
        Err(PublisherSessionError::ServiceReserved)
    ));
    let other = PublisherSessionScope {
        principal: PrincipalId::from_bytes([9; 16]),
        ..scope()
    };
    assert!(matches!(
        table.prepare(&mut listener, other, anchor()),
        Err(PublisherSessionError::Capacity)
    ));
    assert!(
        listener.accept().is_ok(),
        "capacity rejection leaves the pending child untouched"
    );
}

#[test]
fn postcommit_prepared_retirement_keeps_exact_live_peer_pin() {
    let mut table = PublisherSessionRegistry::new(PublisherSessionLimits {
        maximum_sessions: 1,
    })
    .expect("table");
    let (pending, mut sender) = prepared(&mut table);
    let instance = pending.retire();
    assert!(sender.send(b"closed").is_err());
    assert!(matches!(
        table.receive(instance),
        Err(PublisherSessionError::Retired)
    ));
    assert!(matches!(
        table.release_retired_after_exit(instance),
        Err(PublisherSessionError::ExecutionAlive)
    ));
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_writer(path: Option<&Path>, input: Stdio) -> ChildGuard {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args([
            "--exact",
            "publisher_sessions::kernel_tests::writer_process_fixture",
            "--nocapture",
        ])
        .env("AOS_PUBLISHER_WRITER_FIXTURE", "1")
        .env_remove("AOS_PUBLISHER_WRITER_PATH")
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(path) = path {
        command.env("AOS_PUBLISHER_WRITER_PATH", path);
    }
    let mut child = ChildGuard(command.spawn().expect("spawn writer"));
    let mut output = std::io::BufReader::new(child.0.stdout.take().expect("writer stdout"));
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(
            output.read_line(&mut line).expect("writer readiness"),
            0,
            "writer exited before sending"
        );
        if line.contains("publisher-writer-ready") {
            break;
        }
    }
    child
}

#[test]
fn writer_process_fixture() {
    if std::env::var_os("AOS_PUBLISHER_WRITER_FIXTURE").is_none() {
        return;
    }
    let mut sender = match std::env::var_os("AOS_PUBLISHER_WRITER_PATH") {
        Some(path) => connect_sender(Path::new(&path)),
        None => SeqpacketSocket::from_owned(
            std::io::stdin()
                .as_fd()
                .try_clone_to_owned()
                .expect("delegated socket"),
        )
        .expect("delegated transport"),
    };
    sender.send(b"child publisher request").expect("child send");
    println!("publisher-writer-ready");
    std::io::stdout().flush().expect("flush readiness");
    // The parent kills and reaps the fixture after observing the live writer.
    // This ceiling also bounds the fixture if its parent fails unexpectedly.
    std::thread::sleep(std::time::Duration::from_secs(10));
}

#[test]
fn same_cgroup_delegated_writer_is_not_the_registered_execution() {
    let mut table = PublisherSessionRegistry::new(PublisherSessionLimits {
        maximum_sessions: 1,
    })
    .expect("table");
    let (pending, sender) = prepared(&mut table);
    let instance = pending.activate();
    let descriptor = sender
        .as_fd()
        .expect("client socket")
        .try_clone_to_owned()
        .expect("delegation descriptor");
    let _child = spawn_writer(None, Stdio::from(descriptor));
    assert!(matches!(
        table.receive(instance),
        Err(PublisherSessionError::ExecutionMismatch)
    ));
    assert!(matches!(
        table.receive(instance),
        Err(PublisherSessionError::Retired)
    ));
    assert!(matches!(
        table.release_retired_after_exit(instance),
        Err(PublisherSessionError::ExecutionAlive)
    ));
}

#[test]
fn retired_original_process_must_exit_before_its_reservation_is_released() {
    let directory = tempfile::tempdir().expect("socket directory");
    let path = directory.path().join("publisher.sock");
    let mut listener = RecordSubjectListener::bind(&path, 8).expect("configured listener");
    let mut child = spawn_writer(Some(&path), Stdio::null());
    let mut table = PublisherSessionRegistry::new(PublisherSessionLimits {
        maximum_sessions: 1,
    })
    .expect("table");
    let pending = table
        .prepare(&mut listener, scope(), anchor())
        .expect("register child execution");
    let instance = pending.activate();
    assert_eq!(
        table
            .receive(instance)
            .expect("original child record")
            .process_info()
            .pid(),
        child.0.id()
    );
    table.retire(instance).expect("retire child");
    assert!(matches!(
        table.release_retired_after_exit(instance),
        Err(PublisherSessionError::ExecutionAlive)
    ));
    child.0.kill().expect("stop fixture");
    child.0.wait().expect("reap fixture");
    assert_eq!(
        table
            .release_retired_after_exit(instance)
            .expect("release dead execution"),
        instance
    );
    assert!(table.slots.iter().all(Option::is_none));
    assert!(matches!(
        table.receive(instance),
        Err(PublisherSessionError::UnknownSession)
    ));
}
