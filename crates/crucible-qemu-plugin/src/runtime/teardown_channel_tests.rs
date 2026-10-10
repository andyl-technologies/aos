//! Actual trigger ownership and finite credit under the installed worker's held gate.

use super::*;
use crate::runtime::installed_teardown::InstalledTeardownMailbox;
use crate::runtime::worker_quiescence::{LiveWorkerQuiescence, WORKER_REQUIRED, WORKER_TEARDOWN};

fn finite_channel() -> (TeardownSender, TeardownReceiver) {
    let original = Arc::new(BoundedOriginalMailbox::new(3).unwrap());
    (
        TeardownSender::Bounded(Arc::clone(&original)),
        TeardownReceiver::Bounded(original),
    )
}

fn fault(message: &str) -> LiveRuntimeTeardownTrigger {
    LiveRuntimeTeardownTrigger::RunControlFault {
        diagnostic: String::from(message),
    }
}

fn submit(sender: &TeardownSender, mut trigger: LiveRuntimeTeardownTrigger) -> u64 {
    for _ in 0..100_000 {
        match sender.try_submit_original(trigger) {
            Ok(sequence) => return sequence,
            Err(SubmissionRefusal {
                reason: MailboxRefusal::Busy,
                original,
            }) => {
                trigger = original;
                std::thread::yield_now();
            }
            Err(error) => panic!("unexpected original refusal: {:?}", error.reason),
        }
    }
    panic!("actual original queue remained busy");
}

#[test]
fn held_original_worker_preserves_all_three_real_triggers_and_overflow() {
    let (sender, receiver) = finite_channel();
    let mailbox = InstalledTeardownMailbox::new(receiver);
    let workers = LiveWorkerQuiescence::new(WORKER_REQUIRED);
    workers.hold();
    let (retained_sender, retained_receiver) = mpsc::sync_channel(1);
    let (completed_sender, completed_receiver) = mpsc::sync_channel(1);
    let worker_mailbox = Arc::clone(&mailbox);
    let worker_gate = Arc::clone(&workers);
    let worker = std::thread::spawn(move || {
        let idle = worker_gate.idle(WORKER_TEARDOWN);
        worker_mailbox.receive_original().unwrap();
        let pending = idle.received();
        retained_sender.send(()).unwrap();
        let _operation = pending.enter();
        completed_sender
            .send(worker_mailbox.take_after_modeled_entry().unwrap())
            .unwrap();
    });

    let first = submit(&sender, fault("first-original"));
    retained_receiver.recv().unwrap();
    let second = submit(&sender, fault("second-original"));
    let third = submit(&sender, fault("third-original"));
    let oversized = String::from("fourth-still-owned");
    let address = oversized.as_ptr();
    let refused = sender
        .try_submit_original(LiveRuntimeTeardownTrigger::RunControlFault {
            diagnostic: oversized,
        })
        .err()
        .unwrap();

    assert_eq!(refused.reason, MailboxRefusal::CreditExhausted);
    assert!(
        matches!(&refused.original, LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } if diagnostic.as_ptr() == address && diagnostic == "fourth-still-owned")
    );
    assert!(completed_receiver.try_recv().is_err());
    assert_eq!(workers.snapshot().operations_in_flight, 0);
    assert_eq!(workers.snapshot().pending_mask, WORKER_TEARDOWN);
    assert!(mailbox.lifetime_valid());

    workers.release();
    assert!(
        matches!(completed_receiver.recv().unwrap(), LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } if diagnostic == "first-original")
    );
    worker.join().unwrap();
    assert_eq!(first, 1);
    let TeardownSender::Bounded(queue) = &sender else {
        panic!("missing actual finite allocation");
    };
    assert_eq!(queue.receive_original().unwrap(), second);
    assert!(
        matches!(queue.take_received(second).unwrap(), LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } if diagnostic == "second-original")
    );
    assert_eq!(queue.receive_original().unwrap(), third);
    assert!(
        matches!(queue.take_received(third).unwrap(), LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } if diagnostic == "third-original")
    );
    assert!(sender.try_submit_original(refused.original).is_ok());
}

#[test]
fn oversized_diagnostic_is_returned_unchanged_before_publication() {
    let (sender, receiver) = finite_channel();
    let original = "d".repeat(MAXIMUM_DIAGNOSTIC_BYTES + 1);
    let address = original.as_ptr();

    let refused = sender
        .try_submit_original(LiveRuntimeTeardownTrigger::RunControlFault {
            diagnostic: original,
        })
        .err()
        .unwrap();
    assert_eq!(refused.reason, MailboxRefusal::CreditExhausted);
    assert!(
        matches!(refused.original, LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } if diagnostic.len() == 513 && diagnostic.as_ptr() == address)
    );
    assert!(receiver.recv().is_err());
    assert_eq!(submit(&sender, fault("admitted-after-refusal")), 1);
}

#[test]
fn busy_callback_route_returns_the_same_original_without_waiting_or_submission() {
    let (sender, receiver) = finite_channel();
    let router = LiveRuntimeTeardownRouter::new(sender);
    let held = router.sender.lock().unwrap();
    let message = String::from("route-original");
    let address = message.as_ptr();

    let refused = router
        .try_send_bounded(LiveRuntimeTeardownTrigger::RunControlFault {
            diagnostic: message,
        })
        .err()
        .unwrap();
    assert_eq!(refused.reason, MailboxRefusal::Busy);
    assert!(
        matches!(&refused.original, LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } if diagnostic.as_ptr() == address)
    );
    drop(held);
    assert_eq!(
        router
            .try_send_bounded(refused.original)
            .unwrap_or_else(|_| panic!("retained original retry failed")),
        1
    );
    let RetainedTrigger::Bounded(sequence) = receiver.receive_retained().unwrap() else {
        panic!("lost original finite queue");
    };
    assert!(
        matches!(receiver.take_bounded(sequence).unwrap(), LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } if diagnostic == "route-original")
    );
}

#[test]
fn short_diagnostic_with_excessive_retained_capacity_is_not_accepted_as_bounded() {
    let (sender, _) = finite_channel();
    let mut diagnostic = String::with_capacity(1024);
    diagnostic.push_str("short");
    let address = diagnostic.as_ptr();

    let refused = sender
        .try_submit_original(LiveRuntimeTeardownTrigger::RunControlFault { diagnostic })
        .err()
        .unwrap();
    assert_eq!(refused.reason, MailboxRefusal::CreditExhausted);
    assert!(
        matches!(refused.original, LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } if diagnostic.as_ptr() == address && diagnostic.capacity() == 1024 && diagnostic == "short")
    );
}

#[test]
fn inherited_finite_route_is_refused_before_the_original_mutex() {
    let (sender, _) = finite_channel();
    let router = LiveRuntimeTeardownRouter::new(sender);
    // Explicitly modeled PID mismatch leaves the actual mutex held, proving the
    // foreign-process branch precedes even a nonblocking ownership attempt.
    router.process_id.store(0, Ordering::Release);
    let held = router.sender.lock().unwrap();

    let refused = router
        .try_send_bounded(fault("foreign-original"))
        .err()
        .unwrap();
    assert_eq!(refused.reason, MailboxRefusal::ForeignProcess);
    assert!(
        matches!(refused.original, LiveRuntimeTeardownTrigger::RunControlFault { diagnostic } if diagnostic == "foreign-original")
    );
    drop(held);
}

#[test]
// crucible-lint: allow clippy-disallowed-method -- The absolute watchdog supervises a real local child, never guest time.
#[allow(clippy::disallowed_methods)]
fn finite_overflow_aborts_actual_producer_child_without_running_teardown() {
    const CHILD_SELECTOR: &str = "CRUCIBLE_TEST_FINITE_TEARDOWN_CHILD";
    if std::env::var_os(CHILD_SELECTOR).is_some() {
        overflow_original_child();
    }

    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["runtime::teardown_channel::tests::finite_overflow_aborts_actual_producer_child_without_running_teardown", "--exact", "--nocapture"])
        .env(CHILD_SELECTOR, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("actual finite-producer child containment watchdog");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.signal(), Some(libc::SIGABRT));
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(!diagnostic.contains("finite original overflow returned"));
}

#[test]
// crucible-lint: allow clippy-disallowed-method -- The absolute watchdog supervises a real child with an actual held stderr lock.
#[allow(clippy::disallowed_methods)]
fn finite_overflow_ignores_held_stderr_before_actual_child_abort() {
    const CHILD_SELECTOR: &str = "CRUCIBLE_TEST_FINITE_TEARDOWN_STDERR_CHILD";
    if std::env::var_os(CHILD_SELECTOR).is_some() {
        let (held_sender, held_receiver) = mpsc::sync_channel(1);
        let _lock_owner = std::thread::spawn(move || {
            let _held_stderr = std::io::stderr().lock();
            held_sender.send(()).unwrap();
            loop {
                std::thread::park();
            }
        });
        held_receiver.recv().unwrap();
        overflow_original_child();
    }

    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["runtime::teardown_channel::tests::finite_overflow_ignores_held_stderr_before_actual_child_abort", "--exact", "--nocapture"])
        .env(CHILD_SELECTOR, "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.signal(), Some(libc::SIGABRT));
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("actual finite-producer child waited for held stderr");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn overflow_original_child() -> ! {
    let (sender, _retained_receiver) = finite_channel();
    for index in 0..3 {
        assert_eq!(
            submit(&sender, fault(&format!("original-{index}"))),
            index + 1
        );
    }
    let _must_abort = sender.send(fault("fourth-original-fatal"));
    panic!("finite original overflow returned to producer");
}

#[test]
fn finite_identity_requires_the_actual_original_bounded_route() {
    let (finite_sender, _) = finite_channel();
    let finite = LiveRuntimeTeardownRouter::new(finite_sender);
    let (legacy_sender, _) = mpsc::channel();
    let legacy = LiveRuntimeTeardownRouter::new(legacy_sender);

    assert!(finite.is_original_finite());
    assert!(!legacy.is_original_finite());
    finite
        .process_id
        .store(std::process::id().wrapping_add(1), Ordering::Release);
    assert!(!finite.is_original_finite());
}
