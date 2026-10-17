//! Actual Unix-stream prefix custody and original RUN-lifecycle tests.

// crucible-lint: allow panic-shortcut -- Test-only assertions panic on an unmet custody or codec invariant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use std::io::Write;

use crucible_protocol::{HostMsg, control_encode_host_msg};

fn running_pair() -> (UnixStream, Arc<NativeRunControlCustody>) {
    let (host, lifecycle) = crate::runtime::tests::running_plugin_control_pair();
    let preparation = NativeRunControlCustody::prepare(lifecycle);
    preparation.status.expect("actual RUN endpoint prepares");
    (host, preparation.owner)
}

#[test]
fn fragmented_terminal_stays_in_installed_storage_until_original_quit() {
    let (mut host, custody) = running_pair();
    let quit = control_encode_host_msg(&HostMsg::Quit);

    for (index, byte) in quit.iter().enumerate() {
        host.write_all(&[*byte]).unwrap();
        let result = custody.receive_step().unwrap();
        let snapshot = custody.snapshot().unwrap();

        assert_eq!(snapshot.received, index + 1);
        assert_eq!(&snapshot.backing[..snapshot.received], &quit[..index + 1]);
        assert_eq!(snapshot.terminal, index + 1 == quit.len());
        if index + 1 < quit.len() {
            assert!(result.is_none());
            assert_eq!(
                snapshot.lifecycle,
                ControlLifecycleState::RunningViaSharedMemory
            );
        } else {
            assert!(matches!(
                result,
                Some(LiveRuntimeTeardownTrigger::HostQuit(_))
            ));
            assert_eq!(snapshot.lifecycle, ControlLifecycleState::QuitSent);
        }
    }
}

#[test]
fn no_data_retry_preserves_partial_prefix_and_real_endpoint_identity() {
    let (mut host, custody) = running_pair();
    let quit = control_encode_host_msg(&HostMsg::Quit);
    host.write_all(&quit[..2]).unwrap();
    assert!(custody.receive_step().unwrap().is_none());
    let original = custody.snapshot().unwrap();

    assert!(custody.receive_step().unwrap().is_none());
    assert_eq!(custody.snapshot().unwrap(), original);
    assert_ne!(original.socket_identity, (0, 0));

    host.write_all(&quit[2..]).unwrap();
    assert!(custody.receive_step().unwrap().is_none());
    assert!(matches!(
        custody.receive_step().unwrap(),
        Some(LiveRuntimeTeardownTrigger::HostQuit(_))
    ));
}

#[test]
fn original_terminal_retry_never_dequeues_a_successor_frame() {
    let (mut host, custody) = running_pair();
    let quit = control_encode_host_msg(&HostMsg::Quit);
    host.write_all(&quit).unwrap();
    assert!(custody.receive_step().unwrap().is_none());
    assert!(matches!(
        custody.receive_step().unwrap(),
        Some(LiveRuntimeTeardownTrigger::HostQuit(_))
    ));
    let original = custody.snapshot().unwrap();

    host.write_all(&[91, 92, 93, 94]).unwrap();
    assert!(matches!(
        custody.receive_step().unwrap(),
        Some(LiveRuntimeTeardownTrigger::HostQuit(_))
    ));
    assert_eq!(custody.snapshot().unwrap(), original);

    let mut stored = custody.original.lock().unwrap();
    let mut unread = [0; 4];
    assert_eq!(stored.socket.read(&mut unread).unwrap(), 4);
    assert_eq!(unread, [91, 92, 93, 94]);
}

#[test]
fn malformed_extent_keeps_exact_original_bytes_and_cached_fault() {
    for length in [0_u32, MAX_FRAME_SIZE + 1, u32::MAX] {
        let (mut host, custody) = running_pair();
        let prefix = length.to_be_bytes();
        host.write_all(&prefix).unwrap();

        assert!(matches!(
            custody.receive_step().unwrap(),
            Some(LiveRuntimeTeardownTrigger::RunControlFault { .. })
        ));
        let original = custody.snapshot().unwrap();
        assert_eq!(original.received, 4);
        assert_eq!(&original.backing[..4], &prefix);
        assert!(original.terminal);
        assert!(matches!(
            custody.receive_step().unwrap(),
            Some(LiveRuntimeTeardownTrigger::RunControlFault { .. })
        ));
        assert_eq!(custody.snapshot().unwrap(), original);
    }
}

#[test]
fn eof_after_partial_body_retains_the_original_declared_extent() {
    let (mut host, custody) = running_pair();
    let quit = control_encode_host_msg(&HostMsg::Quit);
    host.write_all(&quit[..quit.len() - 1]).unwrap();
    assert!(custody.receive_step().unwrap().is_none());
    assert!(custody.receive_step().unwrap().is_none());
    drop(host);

    assert!(matches!(
        custody.receive_step().unwrap(),
        Some(LiveRuntimeTeardownTrigger::RunControlFault { .. })
    ));
    let snapshot = custody.snapshot().unwrap();
    assert_eq!(snapshot.expected, Some(quit.len()));
    assert_eq!(snapshot.received, quit.len() - 1);
    assert_eq!(
        &snapshot.backing[..snapshot.received],
        &quit[..quit.len() - 1]
    );
}

#[test]
fn rejected_setup_owner_keeps_socket_and_never_creates_run() {
    let (mut host, socket) = UnixStream::pair().unwrap();
    let lifecycle = ControlLifecycleStream::connected_unix_stream(socket).unwrap();
    let original_state = lifecycle.state();
    let preparation = NativeRunControlCustody::prepare(lifecycle);
    assert!(matches!(
        preparation.status,
        Err(NativeRunControlError::NotRunning)
    ));
    host.write_all(&control_encode_host_msg(&HostMsg::Quit))
        .unwrap();

    assert!(matches!(
        preparation.owner.receive_step(),
        Err(NativeRunControlError::NotRunning)
    ));
    let snapshot = preparation.owner.snapshot().unwrap();
    assert_eq!(snapshot.received, 0);
    assert_eq!(snapshot.lifecycle, original_state);
    assert!(!snapshot.terminal);
}

#[test]
fn held_actual_worker_never_reads_even_a_partial_ready_prefix() {
    use crate::runtime::worker_quiescence::{
        LiveWorkerQuiescence, WORKER_REQUIRED, WORKER_RUN_CONTROL,
    };
    let (mut host, custody) = running_pair();
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    workers.hold();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader_custody = Arc::clone(&custody);
    let reader_workers = Arc::clone(&workers);
    let reader = std::thread::spawn(move || run_reader(reader_custody, sender, reader_workers));
    let quit = control_encode_host_msg(&HostMsg::Quit);
    host.write_all(&quit).unwrap();

    for _ in 0..100_000 {
        if workers.snapshot().parked_mask & WORKER_RUN_CONTROL != 0 {
            break;
        }
        std::thread::yield_now();
    }
    assert_ne!(workers.snapshot().parked_mask & WORKER_RUN_CONTROL, 0);
    assert_eq!(custody.snapshot().unwrap().received, 0);
    assert!(receiver.try_recv().is_err());

    // Only this test releases the real gate; production closure does not gain
    // authority from these storage or accounting facts.
    workers.release();
    assert!(matches!(
        receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap(),
        LiveRuntimeTeardownTrigger::HostQuit(_)
    ));
    assert!(reader.join().unwrap());
    assert_eq!(custody.snapshot().unwrap().received, quit.len());
}
