//! Actual socket and mapped queue custody with model-only initializer evidence.

// crucible-lint: allow panic-shortcut -- Test-only assertions panic on an unmet custody or codec invariant.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::os::unix::net::UnixStream;

use crucible_protocol::node_control::{NativeChannel, NativeControlEdition, NativeFrame};
use crucible_protocol::{HostMsg, control_encode_host_msg};

use super::super::preparation_fifo::tests::{initializer, mapped};
use super::*;
use crate::runtime::worker_quiescence::{WORKER_REQUIRED, WORKER_RUN_CONTROL, WORKER_TEARDOWN};

fn inbox(scope: [u8; 32]) -> (NativeChannel, Arc<NativeAdministrativeInbox>) {
    let (host, native) =
        NativeChannel::supervised_pair_for_edition(NativeControlEdition::Administration).unwrap();
    let mut endpoint = Some(native);
    let inbox =
        NativeAdministrativeInbox::from_pinned_endpoint(&mut endpoint, scope, false, 8, 65536)
            .unwrap();
    (host, Arc::new(inbox))
}

fn run() -> (UnixStream, Arc<NativeRunControlCustody>) {
    let (host, original) = crate::runtime::native_run_control::test_running_pair();
    let prepared = NativeRunControlCustody::prepare(original);
    prepared.status.unwrap();
    (host, prepared.owner)
}

fn credit() -> NativePreparationTransportCredit {
    NativePreparationTransportCredit {
        fifo_bytes: 64 * 1024 * 1024,
        inbox_bytes: 65536,
    }
}

fn query(scope: [u8; 32]) -> NativeFrame {
    NativeFrame::QueryAdministration {
        prepared_scope_hash: scope,
        administration_commitment: [7; 32],
    }
}

#[test]
fn busy_inbox_preserves_original_partial_run_and_all_native_holds() {
    let region = mapped(1);
    let initialization = initializer(true);
    let (_admin_host, inbox) = inbox(initialization.scope);
    let (mut host, run) = run();
    let quit = control_encode_host_msg(&HostMsg::Quit);
    host.write_all(&quit[..2]).unwrap();
    assert!(run.receive_step().unwrap().is_none());
    let original_run = run.snapshot().unwrap();
    let workers = Arc::clone(inbox.modeled_workers());
    let _reader = workers.idle(WORKER_RUN_CONTROL);
    let _teardown = workers.idle(WORKER_TEARDOWN);
    let callbacks = Arc::new(LiveCallbackQuiescence::new());
    let mut custody = NativePreparationTransportCustody::new(
        initialization,
        Arc::clone(&callbacks),
        Arc::clone(&workers),
        &region,
        Arc::clone(&inbox),
        Arc::clone(&run),
        credit(),
    )
    .unwrap();
    let busy = inbox.test_hold_mailbox();

    assert!(custody.try_retain().unwrap().is_none());
    assert_eq!(custody.original_run.as_ref(), Some(&original_run));
    assert!(custody.original_inbox.is_none());
    assert!(callbacks.enter().is_none());
    assert!(workers.snapshot().held);
    drop(busy);

    let retained = custody.try_retain().unwrap().unwrap();
    assert_eq!(retained.run, &original_run);
    assert_eq!(&retained.run.backing[..2], &quit[..2]);
    assert!(retained.fifo.canonical_len().unwrap() > 0);
    assert!(retained.inbox.starts_with(b"CNAINB01"));
    assert_eq!(run.snapshot().unwrap(), original_run);
}

#[test]
fn historical_inbox_cut_never_consumes_unread_kernel_packet_or_relabels_later_journal() {
    let region = mapped(1);
    let initialization = initializer(true);
    let (host, inbox) = inbox(initialization.scope);
    let original_query = query(initialization.scope);
    assert!(host.send(&original_query).unwrap());
    let (_run_host, run) = run();
    let workers = Arc::clone(inbox.modeled_workers());
    let _reader = workers.idle(WORKER_RUN_CONTROL);
    let _teardown = workers.idle(WORKER_TEARDOWN);
    let mut custody = NativePreparationTransportCustody::new(
        initialization,
        Arc::new(LiveCallbackQuiescence::new()),
        Arc::clone(&workers),
        &region,
        Arc::clone(&inbox),
        run,
        credit(),
    )
    .unwrap();

    let original = custody.try_retain().unwrap().unwrap().inbox.to_vec();
    assert!(inbox.original_frame(1).is_err());
    assert!(matches!(
        inbox.receive_one().unwrap(),
        super::super::administrative_mailbox::NativeAdministrativeReceive::Retained(1, _)
    ));
    assert_eq!(inbox.original_frame(1).unwrap(), original_query);

    // The actual bounded administration journal survives beside this historical
    // cut. Capturing neither dequeues nor fences the unread peer's future data.
    assert_eq!(custody.try_retain().unwrap().unwrap().inbox, original);
    assert_ne!(inbox.try_snapshot(65536).unwrap().unwrap(), original);
}

#[test]
fn equal_worker_mask_cannot_adopt_an_independently_created_native_owner() {
    let region = mapped(1);
    let initialization = initializer(true);
    let (_host, inbox) = inbox(initialization.scope);
    let (_run_host, run) = run();
    let foreign = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    assert_eq!(foreign.worker_mask(), inbox.modeled_workers().worker_mask());
    let callbacks = Arc::new(LiveCallbackQuiescence::new());

    assert!(matches!(
        NativePreparationTransportCustody::new(
            initialization,
            Arc::clone(&callbacks),
            Arc::clone(&foreign),
            &region,
            inbox,
            run,
            credit(),
        ),
        Err(NativePreparationTransportError::Ownership)
    ));
    assert!(!foreign.snapshot().held);
    assert!(!callbacks.snapshot().hot_fork_held);
}

#[test]
fn actual_terminal_prefix_remains_retained_when_new_epoch_preparation_is_refused() {
    let region = mapped(1);
    let initialization = initializer(true);
    let (_host, inbox) = inbox(initialization.scope);
    let (mut host, run) = run();
    host.write_all(&control_encode_host_msg(&HostMsg::Quit))
        .unwrap();
    assert!(run.receive_step().unwrap().is_none());
    assert!(run.receive_step().unwrap().is_some());
    let original = run.snapshot().unwrap();
    let workers = Arc::clone(inbox.modeled_workers());
    let _reader = workers.idle(WORKER_RUN_CONTROL);
    let _teardown = workers.idle(WORKER_TEARDOWN);
    let callbacks = Arc::new(LiveCallbackQuiescence::new());
    let mut custody = NativePreparationTransportCustody::new(
        initialization,
        Arc::clone(&callbacks),
        Arc::clone(&workers),
        &region,
        inbox,
        Arc::clone(&run),
        credit(),
    )
    .unwrap();

    assert!(custody.try_retain().is_err());
    assert_eq!(custody.original_run.as_ref(), Some(&original));
    assert!(custody.failed);
    assert!(custody.try_retain().is_err());
    assert_eq!(run.snapshot().unwrap(), original);
    assert!(callbacks.enter().is_none());
    assert!(workers.snapshot().held);
}
