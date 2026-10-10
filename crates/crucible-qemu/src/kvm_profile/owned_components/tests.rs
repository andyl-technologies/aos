//! Real child/peer/supervisor controls; portable allocation labels are modeled.
//!
//! Actual signed QEMU remains stopped TCG in these availability tests. No test
//! claims live KVM, original guest execution, or a qualified native-node profile.

// Panics are deliberate failures of actual peer/custody fixture assertions.
#![expect(
    clippy::unwrap_used,
    reason = "actual fixture setup and assertions deliberately panic on failure"
)]

use super::*;
use crucible::node_contract::{OwnerIdentity, RuntimeCustodyQueue};
use crucible_node_contract::{HashRef, Id, Phase, Position};
use std::task::{Context, Poll, Waker};

// The package check supplies a native source-built executable at runtime.
// Keeping the binding out of compiled code preserves the Apache-only output
// closure and prevents a historical QEMU store path from becoming a fallback.
fn configured_qemu(value: Option<std::ffi::OsString>) -> Result<std::path::PathBuf, &'static str> {
    use std::os::unix::fs::PermissionsExt;

    let path = std::path::PathBuf::from(value.ok_or("CRUCIBLE_NATIVE_PROBE_QEMU is required")?);
    if !path.is_absolute() {
        return Err("the configured QEMU executable must be absolute");
    }
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|_| "the configured QEMU executable is unavailable")?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("the configured QEMU executable must be a regular executable file");
    }
    Ok(path)
}

#[test]
fn explicit_native_fixture_binding_refuses_missing_relative_and_nonexecutable_paths() {
    assert!(configured_qemu(None).is_err());
    assert!(configured_qemu(Some("qemu-system-x86_64".into())).is_err());

    let directory = tempfile::tempdir().unwrap();
    assert!(configured_qemu(Some(directory.path().as_os_str().to_owned())).is_err());
    let absent = directory.path().join("absent");
    assert!(configured_qemu(Some(absent.as_os_str().to_owned())).is_err());
    let file = directory.path().join("not-executable");
    std::fs::write(&file, b"not a QEMU fixture").unwrap();
    assert!(configured_qemu(Some(file.as_os_str().to_owned())).is_err());
}

fn allocation() -> ActivationRecord {
    ActivationRecord {
        generation: 1.into(),
        activation_id: Id::new("test/component-allocation").unwrap(),
        world_binding_hash: HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.world-binding.v1".into(),
            digest: "a".repeat(64),
        },
        owners: vec![OwnerIdentity {
            owner: Id::new("test/component-owner").unwrap(),
            incarnation: Id::new("test/original-incarnation").unwrap(),
            generation: 1.into(),
        }],
        boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
    }
}

// Operational cleanup allowance verifies actual child/group death only.
#[expect(
    clippy::disallowed_methods,
    reason = "host cleanup test allowance, never modeled time"
)]
fn reclaim(queue: &RuntimeCustodyQueue) {
    let mut context = Context::from_waker(Waker::noop());
    let start = std::time::Instant::now();
    loop {
        match queue.poll_reclamation(&mut context) {
            Poll::Ready(Ok(())) => break,
            Poll::Ready(Err(error)) => panic!("actual native reclaim failed: {error:?}"),
            Poll::Pending => assert!(start.elapsed() < Duration::from_secs(5)),
        }
        std::thread::yield_now();
    }
    assert_eq!(queue.reserved_worlds(), 0);
}

fn diagnostic_owner(
    queue: &RuntimeCustodyQueue,
    maximum_commands: usize,
) -> (
    KvmOwnedComponents,
    tempfile::TempDir,
    std::path::PathBuf,
    UnixStream,
) {
    let mut custody =
        KvmComponentCustody::reserve(queue, allocation(), RuntimeLimits::default()).unwrap();
    custody.reserve_control(maximum_commands, 4).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("crucible-owned-tcg-control-")
        .tempdir()
        .unwrap();
    let socket = directory.path().join("control");
    let configured = configured_qemu(std::env::var_os("CRUCIBLE_NATIVE_PROBE_QEMU"))
        .unwrap_or_else(|error| panic!("explicit native fixture refused before Child: {error}"));
    let executable = File::open(configured).unwrap();
    let mut command = Command::new(format!("/proc/self/fd/{}", executable.as_raw_fd()));
    command
        .env_clear()
        .env("LC_ALL", "C")
        .args([
            "-M",
            "none",
            "-accel",
            "tcg",
            "-S",
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            "none",
            "-nodefaults",
            "-qmp",
        ])
        .arg(format!("unix:{},server=on,wait=off", socket.display()))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    custody.spawn_child(&mut command).unwrap();
    let stream = connect_original_endpoint(&mut custody, &socket).unwrap();
    let diagnostic_disconnect = stream.try_clone().unwrap();
    custody
        .authenticate_control_peer(stream, &executable)
        .unwrap();
    custody.connect_control(maximum_commands, 4).unwrap();
    (
        KvmOwnedComponents {
            custody,
            executable,
        },
        directory,
        socket,
        diagnostic_disconnect,
    )
}

#[test]
fn real_signed_tcg_peer_refusal_retains_original_and_supervised_process() {
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let (mut owner, _directory, _socket, _disconnect) = diagnostic_owner(&queue, 1);
    assert_eq!(queue.reserved_worlds(), 1);
    assert!(owner.original_process_id().is_some());
    assert_eq!(owner.allocation(), &allocation());
    let request = super::super::QmpKvmOriginalWindowRequest {
        operation: super::super::QmpKvmOriginalWindowOperation::Begin,
        generation: 1,
        start_ns: 0,
        end_ns: 100,
        stop_budget_ns: 0,
    };
    let submission = owner.submit_window(request).unwrap();
    assert!(matches!(submission.exchange, Err(QmpError::Command { .. })));
    assert!(matches!(
        owner.reconcile_window(&submission.token),
        Err(KvmComponentError::Exchange(QmpError::Command { .. }))
    ));
    owner
        .custody
        .control(|journal| {
            assert_eq!(journal.entries.len(), 1);
            let journal::Original::Window(original) = &journal.entries[0].original else {
                panic!("original changed kind")
            };
            assert_eq!(original.original(), &request);
            assert!(original.uncertain_effects());
            Ok(())
        })
        .unwrap();
    assert!(owner.observe_process_exit().unwrap().is_none());
    assert!(matches!(
        owner.submit_window(request),
        Err(KvmComponentError::ResourceLimit)
    ));
    assert_eq!(
        owner.capture_architectural_state().unwrap_err().effects,
        EffectKnowledge::None
    );

    drop(owner);
    assert_eq!(queue.retained_worlds(), 1);
    reclaim(&queue);
}

#[test]
fn foreign_real_socket_cannot_replace_original_authenticated_peer() {
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let (mut owner, _directory, _socket, _disconnect) = diagnostic_owner(&queue, 2);
    let original = owner.original_process_id();
    let (foreign, _other) = UnixStream::pair().unwrap();
    assert!(owner.reconnect(foreign).is_err());
    assert_eq!(owner.original_process_id(), original);
    assert!(owner.observe_process_exit().unwrap().is_none());
    drop(owner);
    reclaim(&queue);
}

#[test]
fn actual_same_child_reconnection_retains_original_journal_and_sticky_history() {
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let (mut owner, _directory, socket, disconnect) = diagnostic_owner(&queue, 2);
    let request = super::super::QmpKvmOriginalWindowRequest {
        operation: super::super::QmpKvmOriginalWindowOperation::Close,
        generation: 0,
        start_ns: 0,
        end_ns: 0,
        stop_budget_ns: 100,
    };
    let submission = owner.submit_window(request).unwrap();
    assert!(submission.exchange.is_err());
    // Fence the actual old socket so QEMU accepts a second connection; native
    // error itself is framed and does not cause this diagnostic disconnection.
    disconnect.shutdown(std::net::Shutdown::Both).unwrap();
    let stream = connect_original_endpoint(&mut owner.custody, &socket).unwrap();
    owner.reconnect(stream).unwrap();
    assert!(matches!(
        owner.reconcile_window(&submission.token),
        Err(KvmComponentError::Exchange(QmpError::Command { .. }))
    ));
    owner
        .custody
        .control(|journal| {
            let journal::Original::Window(original) = &journal.entries[0].original else {
                panic!("original changed kind")
            };
            assert_eq!(original.original(), &request);
            assert!(original.uncertain_effects());
            Ok(())
        })
        .unwrap();
    drop(owner);
    reclaim(&queue);
}

#[test]
fn full_supervisor_refuses_before_process_allocation() {
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let custody =
        KvmComponentCustody::reserve(&queue, allocation(), RuntimeLimits::default()).unwrap();
    assert!(KvmComponentCustody::reserve(&queue, allocation(), RuntimeLimits::default()).is_err());
    assert_eq!(queue.reserved_worlds(), 1);
    drop(custody);
    reclaim(&queue);
}

#[test]
fn original_attempt_credit_retains_every_snapshot_and_never_evicts_for_another_attempt() {
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let (mut owner, _directory, _socket, _disconnect) = diagnostic_owner(&queue, 2);
    let request = super::super::QmpKvmOriginalWindowRequest {
        operation: super::super::QmpKvmOriginalWindowOperation::Begin,
        generation: 1,
        start_ns: 0,
        end_ns: 100,
        stop_budget_ns: 0,
    };
    let submission = owner.submit_window(request).unwrap();
    // A wrong class has no native effect and cannot consume original retry credit.
    for _ in 0..4 {
        assert!(matches!(
            owner.reconcile_ack(&submission.token),
            Err(KvmComponentError::ForeignToken)
        ));
    }
    for _ in 0..3 {
        assert!(matches!(
            owner.reconcile_window(&submission.token),
            Err(KvmComponentError::Exchange(QmpError::Command { .. }))
        ));
    }
    let history = owner.observations(&submission.token).unwrap();
    assert_eq!(history.len(), 4);
    assert!(history.iter().all(|observation| matches!(
        observation,
        KvmComponentObservation::Window {
            state: None,
            uncertain: true
        }
    )));
    assert!(matches!(
        owner.reconcile_window(&submission.token),
        Err(KvmComponentError::ResourceLimit)
    ));
    assert_eq!(owner.observations(&submission.token).unwrap(), history);
    let changed = super::super::QmpKvmOriginalWindowRequest {
        end_ns: 200,
        ..request
    };
    assert!(matches!(
        owner.submit_window(changed),
        Err(KvmComponentError::Transition(_))
    ));
    assert!(owner.observe_process_exit().unwrap().is_none());
    drop(owner);
    reclaim(&queue);
}

#[test]
fn different_actual_owned_process_cannot_reconcile_an_original_token() {
    let queue = RuntimeCustodyQueue::new(2).unwrap();
    let (mut original, _first_directory, _first_socket, _first_disconnect) =
        diagnostic_owner(&queue, 2);
    let (mut foreign, _second_directory, _second_socket, _second_disconnect) =
        diagnostic_owner(&queue, 2);
    assert_ne!(
        original.original_process_id(),
        foreign.original_process_id()
    );
    let request = super::super::QmpKvmOriginalWindowRequest {
        operation: super::super::QmpKvmOriginalWindowOperation::Begin,
        generation: 1,
        start_ns: 0,
        end_ns: 100,
        stop_budget_ns: 0,
    };
    let submission = original.submit_window(request).unwrap();
    assert!(matches!(
        foreign.reconcile_window(&submission.token),
        Err(KvmComponentError::ForeignToken)
    ));
    assert!(matches!(
        foreign.observations(&submission.token),
        Err(KvmComponentError::ForeignToken)
    ));
    assert_eq!(original.observations(&submission.token).unwrap().len(), 1);
    drop(original);
    drop(foreign);
    reclaim(&queue);
}
