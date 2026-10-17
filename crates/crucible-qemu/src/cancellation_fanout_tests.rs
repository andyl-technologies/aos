//! Per-node cancellation eventfd minting and sticky fan-out regressions.

// crucible-lint: allow panic-shortcut -- focused descriptor fixtures use exact panic messages.
#![allow(clippy::expect_used)]

use std::os::fd::BorrowedFd;

use super::*;

fn readable(event: BorrowedFd<'_>) -> bool {
    let mut poll = libc::pollfd {
        fd: event.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe {
        // SAFETY: `poll` is one initialized pollfd value.
        libc::poll(&mut poll, 1, 0)
    };
    ready == 1 && poll.revents & libc::POLLIN != 0
}

fn nonblocking(event: BorrowedFd<'_>) -> bool {
    let flags = unsafe {
        // SAFETY: F_GETFL reads flags of a live borrowed descriptor.
        libc::fcntl(event.as_raw_fd(), libc::F_GETFL)
    };
    flags >= 0 && flags & libc::O_NONBLOCK != 0
}

fn eventfd_id(event: BorrowedFd<'_>) -> String {
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", event.as_raw_fd()))
        .expect("eventfd fdinfo");
    fdinfo
        .lines()
        .find(|line| line.starts_with("eventfd-id:"))
        .expect("eventfd-id row")
        .to_owned()
}

#[test]
fn members_are_distinct_nonblocking_eventfds_signaled_together() {
    use std::os::fd::AsFd as _;

    let fanout = Arc::new(QemuCancellationFanout::default());
    let first = fanout.mint().expect("first member").0;
    let second = fanout.mint().expect("second member").0;

    assert!(nonblocking(first.as_fd()) && nonblocking(second.as_fd()));
    assert_ne!(eventfd_id(first.as_fd()), eventfd_id(second.as_fd()));
    assert!(!readable(first.as_fd()) && !readable(second.as_fd()));

    fanout.signal().expect("signal members");

    assert!(readable(first.as_fd()) && readable(second.as_fd()));
}

#[test]
fn members_minted_after_cancellation_start_readable() {
    use std::os::fd::AsFd as _;

    let fanout = Arc::new(QemuCancellationFanout::default());
    fanout.signal().expect("signal empty fan-out");

    let late = fanout.mint().expect("late member").0;

    assert!(readable(late.as_fd()));
}

#[test]
fn one_member_flag_change_does_not_reach_another_member() {
    use std::os::fd::AsFd as _;

    let fanout = Arc::new(QemuCancellationFanout::default());
    let first = fanout.mint().expect("first member").0;
    let second = fanout.mint().expect("second member").0;

    // Model QEMU's SCM_RIGHTS receive, which clears O_NONBLOCK on the open
    // file description of the descriptor it received.
    let cleared = unsafe {
        // SAFETY: F_SETFL updates flags of a live owned descriptor.
        libc::fcntl(first.as_raw_fd(), libc::F_SETFL, 0)
    };
    assert_eq!(cleared, 0);

    assert!(!nonblocking(first.as_fd()));
    assert!(nonblocking(second.as_fd()));
}

#[test]
fn retired_members_stop_receiving_cancellation_while_live_members_still_do() {
    use std::os::fd::AsFd as _;

    let fanout = Arc::new(QemuCancellationFanout::default());
    let (retired, retired_membership) = fanout.mint().expect("retired member");
    let (live, _live_membership) = fanout.mint().expect("live member");

    retired_membership.retire_after_reap();
    fanout.signal().expect("signal members");

    assert!(!readable(retired.as_fd()));
    assert!(readable(live.as_fd()));
}

#[test]
fn dropped_unretired_members_stay_signaled() {
    use std::os::fd::AsFd as _;

    let fanout = Arc::new(QemuCancellationFanout::default());
    let (event, membership) = fanout.mint().expect("member");

    drop(membership);
    fanout.signal().expect("signal members");

    assert!(readable(event.as_fd()));
}

#[test]
fn minting_fails_closed_at_the_live_member_limit() {
    let fanout = Arc::new(QemuCancellationFanout::default());
    let mut memberships = Vec::new();
    for _ in 0..MAX_LIVE_CANCELLATION_FANOUT_MEMBERS {
        // Only the fan-out's retained duplicate stays open.
        let (event, membership) = fanout.mint().expect("member within the limit");
        drop(event);
        memberships.push(membership);
    }

    let exhausted = fanout.mint().expect_err("live member limit");
    assert_eq!(exhausted.kind(), std::io::ErrorKind::OutOfMemory);

    memberships
        .pop()
        .expect("one live membership")
        .retire_after_reap();
    drop(fanout.mint().expect("member after one retirement"));
}

#[test]
fn retired_slots_let_an_attempt_mint_beyond_the_live_member_limit() {
    let fanout = Arc::new(QemuCancellationFanout::default());

    for _ in 0..MAX_LIVE_CANCELLATION_FANOUT_MEMBERS * 4 {
        let (event, membership) = fanout.mint().expect("member of a reaped node");
        drop(event);
        membership.retire_after_reap();
    }

    let state = fanout.state.lock().expect("fan-out state");
    assert_eq!(state.live_members(), 0);
    assert_eq!(state.slots.len(), 1);
}
