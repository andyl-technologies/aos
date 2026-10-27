//! Reviews typed pre-action placement deferral with its real retained journals.
//!
//! These exact consumers retain the same Original and distinguish native return
//! from semantic failure. Component observations issue no Source authority.

use super::{Companion, Contract};

#[path = "pager_placement/queue.rs"]
mod queue;
#[path = "pager_placement/body.rs"]
mod body;
#[path = "pager_placement/effects.rs"]
mod effects;
#[path = "pager_placement/end.rs"]
mod end;

pub(super) use queue::{QUEUE, QUEUE_CAPTURE};
pub(super) use body::{JOURNAL, WORK_OWNER};
pub(super) use effects::{DISPATCH, EVICTION};
pub(super) use end::{END_RETURN, LIFECYCLE, END_CLEANUP, CLEANUP_CALLER};

const COMPANIONS: &[Companion] = &[
    QUEUE,
    QUEUE_CAPTURE,
    JOURNAL,
    WORK_OWNER,
    DISPATCH,
    EVICTION,
    END_RETURN,
    LIFECYCLE,
    END_CLEANUP,
    CLEANUP_CALLER,
];

const QUEUE_TESTS: &[(&str, usize)] = &[
    (
        r#"fn late_busy_or_again_preserves_the_first_error_without_rescheduling() {
    // This exercises the actual outer routing/queue-return helpers. It issues
    // no Source operation, native callback, physical-end receipt or authority.
    for status in [-libc::EBUSY, -libc::EAGAIN] {
        let queue = Mutex::new(PlacementQueue {
            dispatching: true,
            ..PlacementQueue::default()
        });
        for first in [
            RamError::PlacementNotRetryable {
                operation: "physical placement dispatch",
                status,
            },
            RamError::Native {
                operation: "paging worker registration",
                status,
            },
        ] {
            queue.lock().unwrap().dispatching = true;
            let calls = AtomicUsize::new(0);

            let work = route_placement_refusal(first.clone(), || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
            let result = finish_placement_dispatch(&queue, work);

            assert_eq!(result, Err(first));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(!queue.lock().unwrap().dispatching);
        }
    }
}"#,
        1,
    ),
    (
        r#"fn pre_entry_busy_or_again_still_routes_to_the_same_retry_owner() {
    for status in [-libc::EBUSY, -libc::EAGAIN] {
        let calls = AtomicUsize::new(0);
        let first = RamError::PlacementDeferred {
            operation: "physical placement exclusion",
            status,
        };

        let result = route_placement_refusal(first, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        assert_eq!(result, Ok(()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}"#,
        1,
    ),
    (
        r#"fn original_completion_refusal_retains_the_same_queued_receipt() {
    let (mut queued, counts) = receipt(true);
    let operation = Arc::downgrade(&queued.as_ref().unwrap().operation);

    assert!(
        finish_queued_receipt(&mut queued, None, || {
            panic!("failed original must not publish settlement")
        })
        .is_err()
    );
    assert!(Arc::ptr_eq(
        &operation.upgrade().unwrap(),
        &queued.as_ref().unwrap().operation
    ));
    assert_eq!(counts.completed.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
}"#,
        1,
    ),
    (
        r#"fn publication_refusal_retains_a_completed_operation_for_containment() {
    let (mut queued, counts) = receipt(false);

    assert!(
        finish_queued_receipt(&mut queued, Some(7), || {
            Err(RamError::Invariant("placement receipt unavailable"))
        })
        .is_err()
    );
    assert_eq!(queued.as_ref().unwrap().generation, 7);
    assert_eq!(counts.completed.load(Ordering::SeqCst), 1);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
}"#,
        1,
    ),
    (
        r#"fn superseded_generation_cannot_finish_or_drop_current_receipt() {
    let (mut queued, counts) = receipt(false);

    assert!(
        finish_queued_receipt(&mut queued, Some(6), || {
            panic!("stale generation must not publish")
        })
        .is_ok()
    );
    assert_eq!(queued.as_ref().unwrap().generation, 7);
    assert_eq!(counts.completed.load(Ordering::SeqCst), 0);
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
}"#,
        1,
    ),
    (
        r#"fn completion_and_publication_precede_actual_receipt_release() {
    let (mut queued, counts) = receipt(false);

    finish_queued_receipt(&mut queued, Some(7), || {
        assert_eq!(counts.completed.load(Ordering::SeqCst), 1);
        assert_eq!(counts.dropped.load(Ordering::SeqCst), 0);
        Ok(())
    })
    .unwrap();
    assert!(queued.is_none());
    assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
}"#,
        1,
    ),
];

const EVICTION_TESTS: &[(&str, usize)] = &[
    (
        r#"fn completed_or_uncertain_end_cannot_retry_a_late_busy_or_again() {
    // This checks the real dispatch decision over saved call history. It does
    // not issue a native certificate or claim a real physical end occurred.
    for status in [-libc::EBUSY, -libc::EAGAIN] {
        let journal = PlacementDispatchJournal::default();
        assert!(journal.retry_before_action(status, 0));
        assert!(!journal.retry_before_action(status, 7));

        journal.end_entered.store(true, Ordering::Release);
        assert!(!journal.retry_before_action(status, 0));

        journal.end_status.store(0, Ordering::Release);
        journal.end_returned.store(true, Ordering::Release);
        journal.action_completed.store(true, Ordering::Release);
        journal.callback_status.store(0, Ordering::Release);
        journal.callback_returned.store(true, Ordering::Release);
        journal.runner_entered.store(true, Ordering::Release);
        journal.runner_status.store(status, Ordering::Release);
        journal.runner_returned.store(true, Ordering::Release);
        journal.record_first_negative(status);
        assert!(!journal.retry_before_action(status, 0));
        assert!(journal.reset().is_err());
        assert_eq!(journal.end_status.load(Ordering::Acquire), 0);
        assert_eq!(journal.callback_status.load(Ordering::Acquire), 0);
        assert_eq!(journal.runner_status.load(Ordering::Acquire), status);
    }
}"#,
        1,
    ),
    (
        r#"let result = journal.finish_preservation(Err(first.clone()), &counters);
assert_eq!(result, Err(first.clone()));
assert!(matches!(&journal.preservation, Effect::Failed(error) if *error == first));
assert!(matches!(&journal.writeback_post, Effect::Failed(RamError::Io(error))
    if error.raw_os_error() == Some(libc::ETIMEDOUT)));
assert_eq!(posts.load(Ordering::SeqCst), 1);
assert_eq!(completions.load(Ordering::SeqCst), 0);
assert!(matches!(journal.writeback_completion, Effect::NotStarted));
assert!(journal.writeback.is_some());
assert_eq!(counters.preserved_writes.load(Ordering::Acquire), 0);"#,
        1,
    ),
];

// The route's complete body remains the exact shared same-file proof. Owning
// that same body as an expression preserves its real lexical witness when a
// different local requirement is omitted by the generic adversarial control.
const _: () = assert!(QUEUE.required.len() == 14);
const SCHEDULING_REQUIRED: &[(&str, usize)] = &[
    QUEUE.required[0],
    QUEUE.required[1],
    QUEUE.required[2],
    QUEUE.required[3],
    QUEUE.required[4],
    QUEUE.required[5],
    QUEUE.required[6],
    QUEUE.required[8],
    QUEUE.required[9],
    QUEUE.required[10],
    QUEUE.required[11],
    QUEUE.required[12],
    QUEUE.required[13],
];

pub(super) const CONTRACTS: &[Contract] = &[
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/paged_ram/engine/scheduling",
        required: SCHEDULING_REQUIRED,
        expressions: &[QUEUE.required[7]],
        identifiers: &[("retry", 2)],
        companions: COMPANIONS,
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/paged_ram/engine/scheduling/tests",
        required: QUEUE_TESTS,
        expressions: &[],
        identifiers: &[(
            "pre_entry_busy_or_again_still_routes_to_the_same_retry_owner",
            1,
        )],
        companions: COMPANIONS,
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/paged_ram/engine/service/capture_work",
        required: JOURNAL.required,
        expressions: &[],
        identifiers: &[("retry_before_action", 1)],
        companions: COMPANIONS,
    },
    Contract {
        package: "crucible-qemu-plugin",
        target: "src/paged_ram/engine/service/capture_work/eviction/tests",
        required: EVICTION_TESTS,
        expressions: &[
            (r#"assert!(journal.retry_before_action(status, 0));"#, 1),
            (r#"assert!(!journal.retry_before_action(status, 0));"#, 2),
            (r#"assert!(!journal.retry_before_action(status, 7));"#, 1),
        ],
        identifiers: &[
            (
                "completed_or_uncertain_end_cannot_retry_a_late_busy_or_again",
                1,
            ),
            ("retry_before_action", 4),
        ],
        companions: COMPANIONS,
    },
];

// Concrete argument mutations extend the existing generic negative controls.
#[cfg(test)]
pub(super) fn altered_expression(expression: &str) -> String {
    expression
        .replace("retry()", "retry(foreign_owner)")
        .replace("status, 0", "status, 1")
        .replace("status, 7", "status, 8")
}

#[cfg(test)]
#[path = "pager_placement/tests.rs"]
mod tests;
