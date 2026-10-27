//! Checks coalescing, independent deadlines and noncancelling original handoffs.

#![allow(clippy::unwrap_used)]

use super::*;

#[allow(
    clippy::disallowed_methods,
    reason = "A single test clock origin anchors manually advanced FUSE deadlines; it never enters repository or Crucible state."
)]
fn clock_origin() -> Instant {
    Instant::now()
}

fn id(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap()
}

fn queue(nodes: u32, waiters: u32) -> Queue {
    Queue::new(Limits {
        nodes,
        waiters,
        bytes: 65536,
    })
    .unwrap()
}

fn start(result: Enqueued) -> Ticket {
    match result {
        Enqueued::Start(ticket) => ticket,
        other => panic!("expected original handoff, got {other:?}"),
    }
}

#[test]
fn concurrent_same_inode_waiters_share_one_original_handoff() {
    let now = clock_origin();
    let timeout = Duration::from_secs(60);
    let mut queue = queue(2, 4);

    let original = start(queue.enqueue(id(19), id(1), now, timeout).unwrap());
    assert_eq!(
        queue.enqueue(id(19), id(2), now, timeout),
        Ok(Enqueued::Joined(original))
    );
    assert_eq!(
        queue.enqueue(id(19), id(3), now, timeout),
        Ok(Enqueued::Joined(original))
    );
    let unrelated = start(queue.enqueue(id(20), id(4), now, timeout).unwrap());
    assert_ne!(original, unrelated);
    assert_eq!(original.node(), id(19));
    assert_eq!((queue.pending(), queue.waiting()), (2, 4));
    assert_eq!(queue.next_reply(now), None);

    queue.complete(original, Outcome::Ready).unwrap();
    let mut responses = Vec::new();
    while let Some(reply) = queue.next_reply(now) {
        assert_eq!(reply.ticket, original);
        assert_eq!(reply.outcome, Outcome::Ready);
        responses.push(reply.unique.get());
    }
    responses.sort_unstable();
    assert_eq!(responses, [1, 2, 3]);
    assert_eq!((queue.pending(), queue.waiting()), (1, 1));
}

#[test]
fn individual_deadlines_and_late_joiners_never_cancel_the_shared_fetch() {
    let now = clock_origin();
    let mut queue = queue(1, 3);
    let original = start(
        queue
            .enqueue(id(19), id(1), now, Duration::from_secs(1))
            .unwrap(),
    );
    queue
        .enqueue(id(19), id(2), now, Duration::from_secs(3))
        .unwrap();
    assert_eq!(queue.next_deadline(), Some(now + Duration::from_secs(1)));

    let expired = queue.next_reply(now + Duration::from_secs(1)).unwrap();
    assert!(expired.expired);
    assert_eq!(
        (expired.unique, expired.ticket, expired.outcome),
        (id(1), original, Outcome::IoError)
    );
    assert_eq!((queue.pending(), queue.waiting()), (1, 1));
    assert_eq!(
        queue.enqueue(
            id(19),
            id(3),
            now + Duration::from_secs(2),
            Duration::from_secs(5)
        ),
        Ok(Enqueued::Joined(original))
    );
    assert_eq!(
        queue
            .next_reply(now + Duration::from_secs(3))
            .unwrap()
            .unique,
        id(2)
    );

    queue.complete(original, Outcome::Ready).unwrap();
    let late = queue.next_reply(now + Duration::from_secs(4)).unwrap();
    assert!(!late.expired);
    assert_eq!(
        (late.unique, late.ticket, late.outcome),
        (id(3), original, Outcome::Ready)
    );
    assert_eq!((queue.pending(), queue.waiting()), (0, 0));
    assert_eq!(queue.next_deadline(), None);
}

#[test]
fn stale_completions_cannot_resolve_a_new_fetch_for_the_same_node() {
    let now = clock_origin();
    let timeout = Duration::from_secs(60);
    let mut queue = queue(1, 3);
    let original = start(queue.enqueue(id(19), id(1), now, timeout).unwrap());
    queue.complete(original, Outcome::IoError).unwrap();
    let retry = start(queue.enqueue(id(19), id(2), now, timeout).unwrap());
    assert_ne!(retry, original);

    assert_eq!(queue.complete(original, Outcome::Ready), Err(Error::Stale));
    let failed = queue.next_reply(now).unwrap();
    assert!(!failed.expired);
    assert_eq!(
        (failed.unique, failed.ticket, failed.outcome),
        (id(1), original, Outcome::IoError)
    );
    assert_eq!(queue.next_reply(now), None);
    assert_eq!((queue.pending(), queue.waiting()), (1, 1));

    queue.complete(retry, Outcome::Ready).unwrap();
    let ready = queue.next_reply(now).unwrap();
    assert_eq!(
        (ready.unique, ready.ticket, ready.outcome),
        (id(2), retry, Outcome::Ready)
    );
}

#[test]
fn refusals_leave_original_waiters_and_ticket_sequence_unchanged() {
    let now = clock_origin();
    let timeout = Duration::from_secs(60);
    let mut queue = queue(1, 2);
    let original = start(queue.enqueue(id(19), id(1), now, timeout).unwrap());

    assert_eq!(
        queue.enqueue(id(20), id(1), now, timeout),
        Err(Error::Duplicate)
    );
    assert_eq!(
        queue.enqueue(id(20), id(2), now, Duration::ZERO),
        Err(Error::Deadline)
    );
    assert_eq!(
        queue.enqueue(id(20), id(2), now, Duration::MAX),
        Err(Error::Deadline)
    );
    assert_eq!(
        queue.enqueue(id(20), id(2), now, timeout),
        Err(Error::Capacity)
    );
    assert_eq!(
        (queue.pending(), queue.waiting(), queue.next_sequence),
        (1, 1, 2)
    );
    // A full node table still admits a waiter on an original pending node.
    assert_eq!(
        queue.enqueue(id(19), id(2), now, timeout),
        Ok(Enqueued::Joined(original))
    );
    assert_eq!(
        queue.enqueue(id(19), id(3), now, timeout),
        Err(Error::Capacity)
    );
    assert_eq!(
        (queue.pending(), queue.waiting(), queue.next_sequence),
        (1, 2, 2)
    );

    queue.complete(original, Outcome::Ready).unwrap();
    while queue.next_reply(now).is_some() {}
    queue.next_sequence = u64::MAX;
    assert_eq!(
        queue.enqueue(id(20), id(3), now, timeout),
        Err(Error::Sequence)
    );
    assert_eq!((queue.pending(), queue.waiting()), (0, 0));
}

#[test]
fn abandoned_and_expired_waiters_preserve_handoffs_through_draining() {
    let now = clock_origin();
    let timeout = Duration::from_secs(1);
    let mut queue = queue(2, 2);
    let abandoned = start(queue.enqueue(id(19), id(1), now, timeout).unwrap());
    let expired = start(queue.enqueue(id(20), id(2), now, timeout).unwrap());

    assert!(queue.abandon(id(1)));
    assert!(!queue.abandon(id(1)));
    assert_eq!(queue.next_reply(now + timeout).unwrap().ticket, expired);
    assert_eq!((queue.pending(), queue.waiting()), (2, 0));
    queue.drain();
    assert_eq!(
        queue.enqueue(id(19), id(3), now, timeout),
        Err(Error::Draining)
    );
    assert_eq!(queue.pending(), 2);

    queue.complete(abandoned, Outcome::Ready).unwrap();
    queue.complete(expired, Outcome::Ready).unwrap();
    assert_eq!(queue.next_reply(now + timeout), None);
    assert_eq!((queue.pending(), queue.waiting()), (0, 0));
}

#[test]
fn startup_budgets_and_completed_deadlines_remain_fail_closed() {
    for limits in [
        Limits {
            nodes: 0,
            waiters: 1,
            bytes: 65536,
        },
        Limits {
            nodes: 1,
            waiters: 0,
            bytes: 65536,
        },
        Limits {
            nodes: 1,
            waiters: 1,
            bytes: 1,
        },
        Limits {
            nodes: u32::MAX,
            waiters: u32::MAX,
            bytes: 65536,
        },
    ] {
        assert!(matches!(Queue::new(limits), Err(Error::Budget)));
    }
    let budget = storage_bytes(1, 1).unwrap();
    let mut queue = Queue::new(Limits {
        nodes: 1,
        waiters: 1,
        bytes: budget,
    })
    .unwrap();
    let now = clock_origin();
    let timeout = Duration::from_secs(1);
    let original = start(queue.enqueue(id(19), id(1), now, timeout).unwrap());

    queue.complete(original, Outcome::Ready).unwrap();
    let reply = queue.next_reply(now + timeout).unwrap();
    assert_eq!(reply.outcome, Outcome::IoError);
    assert_eq!(queue.next_reply(now + timeout), None);
}
