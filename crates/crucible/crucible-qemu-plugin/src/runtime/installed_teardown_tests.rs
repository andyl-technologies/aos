//! Real channel ownership and modeled-gate tests for the original teardown worker.

use super::*;
use crate::runtime::worker_quiescence::{LiveWorkerQuiescence, WORKER_REQUIRED, WORKER_TEARDOWN};

#[test]
fn original_trigger_remains_retained_while_actual_worker_entry_is_held() {
    let (sender, receiver) = mpsc::channel();
    let mailbox = InstalledTeardownMailbox::new(receiver);
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    workers.hold();
    let (retained_sender, retained_receiver) = mpsc::sync_channel(1);
    let (consumed_sender, consumed_receiver) = mpsc::sync_channel(1);
    let original = Arc::clone(&mailbox);
    let worker_gates = Arc::clone(&workers);
    let worker = std::thread::spawn(move || {
        let idle = worker_gates.idle(WORKER_TEARDOWN);
        original.receive_original().unwrap();
        let pending = idle.received();
        retained_sender.send(()).unwrap();
        let _entered = pending.enter();
        let trigger = original.take_after_modeled_entry().unwrap();
        consumed_sender.send(trigger).unwrap();
    });

    sender
        .send(LiveRuntimeTeardownTrigger::RunControlFault {
            diagnostic: "original opaque diagnostic".into(),
        })
        .unwrap();
    retained_receiver.recv().unwrap();
    let snapshot = workers.snapshot();
    assert!(snapshot.held);
    assert_eq!(snapshot.pending_mask, WORKER_TEARDOWN);
    assert_eq!(snapshot.operations_in_flight, 0);
    assert!(
        matches!(&*mailbox.original.lock().unwrap(), Some(LiveRuntimeTeardownTrigger::RunControlFault { diagnostic }) if diagnostic == "original opaque diagnostic")
    );
    assert!(consumed_receiver.try_recv().is_err());
    assert!(mailbox.lifetime_valid());

    workers.release();
    let trigger = consumed_receiver.recv().unwrap();
    assert!(
        matches!(trigger, LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } if diagnostic == "original opaque diagnostic")
    );
    worker.join().unwrap();
    assert!(mailbox.original.lock().unwrap().is_none());
}

#[test]
fn duplicate_reader_refusal_retains_the_same_original_trigger() {
    let (sender, receiver) = mpsc::channel();
    let mailbox = InstalledTeardownMailbox::new(receiver);
    sender
        .send(LiveRuntimeTeardownTrigger::RunControlFault {
            diagnostic: "kept".into(),
        })
        .unwrap();
    mailbox.receive_original().unwrap();

    assert!(matches!(
        mailbox.receive_original(),
        Err(InstalledTeardownMailboxError::Lifetime)
    ));
    assert!(!mailbox.lifetime_valid());
    assert!(
        matches!(&*mailbox.original.lock().unwrap(), Some(LiveRuntimeTeardownTrigger::RunControlFault { diagnostic }) if diagnostic == "kept")
    );
    assert!(mailbox.take_after_modeled_entry().is_err());
}

#[test]
fn disconnected_producer_is_a_failure_without_an_invented_teardown_trigger() {
    let (sender, receiver) = mpsc::channel();
    let mailbox = InstalledTeardownMailbox::new(receiver);
    drop(sender);

    assert!(matches!(
        mailbox.receive_original(),
        Err(InstalledTeardownMailboxError::Disconnected)
    ));
    assert!(!mailbox.lifetime_valid());
    assert!(mailbox.original.lock().unwrap().is_none());
}
