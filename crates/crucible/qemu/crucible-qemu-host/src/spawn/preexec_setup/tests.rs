//! Exercises physical standing-alias retention across partial preparation.
// SPDX-License-Identifier: Apache-2.0

// Test failures deliberately panic to report violated ownership invariants.
#![allow(clippy::unwrap_used)]

use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use super::*;

fn duplicate(role: BorrowedFd<'_>) -> Result<OwnedFd, PreexecSetupCause> {
    rustix::io::fcntl_dupfd_cloexec(role, super::super::CHILD_SOURCE_FD_MIN)
        .map_err(PreexecSetupCause::Kernel)
}

fn assert_live_alias(alias: &OwnedFd, original: &UnixStream, peer: &mut UnixStream) {
    let original_stat = rustix::fs::fstat(original).unwrap();
    let alias_stat = rustix::fs::fstat(alias).unwrap();
    assert_eq!(alias_stat.st_dev, original_stat.st_dev);
    assert_eq!(alias_stat.st_ino, original_stat.st_ino);

    assert_eq!(rustix::io::write(alias, b"x").unwrap(), 1);
    let mut byte = [0];
    peer.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"x");
}

#[test]
fn standing_alias_second_duplication_failure_retains_first_physical_alias() {
    let (publication, mut peer) = UnixStream::pair().unwrap();
    let (cancellation, _) = UnixStream::pair().unwrap();
    let mut aliases = std::array::from_fn(|_| None);
    let mut calls = 0;

    let result = retain_standing_aliases(
        &mut aliases,
        [publication.as_fd(), cancellation.as_fd()],
        |role| {
            calls += 1;
            if calls == 2 {
                return Err(PreexecSetupCause::Kernel(rustix::io::Errno::IO));
            }
            duplicate(role)
        },
    );

    assert!(matches!(
        result,
        Err(PreexecSetupCause::Kernel(rustix::io::Errno::IO))
    ));
    assert_eq!(calls, 2);
    assert!(aliases[4].is_none());
    assert_live_alias(aliases[3].as_ref().unwrap(), &publication, &mut peer);
}

#[test]
fn standing_alias_second_original_refusal_preserves_first_without_second_effect() {
    let (publication, mut peer) = UnixStream::pair().unwrap();
    let (cancellation, _) = UnixStream::pair().unwrap();
    let mut aliases = std::array::from_fn(|_| None);
    let mut checks = 0;
    let mut effects = 0;

    let result = retain_standing_aliases(
        &mut aliases,
        [publication.as_fd(), cancellation.as_fd()],
        |role| {
            checks += 1;
            if checks == 2 {
                return Err(PreexecSetupCause::Original(
                    HostSupervisionError::Unavailable,
                ));
            }
            effects += 1;
            duplicate(role)
        },
    );

    assert!(matches!(
        result,
        Err(PreexecSetupCause::Original(
            HostSupervisionError::Unavailable
        ))
    ));
    assert_eq!((checks, effects), (2, 1));
    assert!(aliases[4].is_none());
    assert_live_alias(aliases[3].as_ref().unwrap(), &publication, &mut peer);
}

#[test]
fn standing_alias_first_refusal_creates_neither_alias() {
    let (publication, _) = UnixStream::pair().unwrap();
    let (cancellation, _) = UnixStream::pair().unwrap();
    let mut aliases = std::array::from_fn(|_| None);
    let mut calls = 0;

    let result = retain_standing_aliases(
        &mut aliases,
        [publication.as_fd(), cancellation.as_fd()],
        |_| {
            calls += 1;
            Err(PreexecSetupCause::Kernel(rustix::io::Errno::MFILE))
        },
    );

    assert!(matches!(
        result,
        Err(PreexecSetupCause::Kernel(rustix::io::Errno::MFILE))
    ));
    assert_eq!(calls, 1);
    assert!(aliases.iter().all(Option::is_none));
}

#[test]
fn standing_alias_occupied_journal_refuses_before_replacement() {
    let (publication, _) = UnixStream::pair().unwrap();
    let (cancellation, mut peer) = UnixStream::pair().unwrap();
    let mut aliases = std::array::from_fn(|_| None);
    aliases[4] = Some(duplicate(cancellation.as_fd()).unwrap());
    let retained_fd = aliases[4].as_ref().unwrap().as_raw_fd();
    let mut calls = 0;

    let result = retain_standing_aliases(
        &mut aliases,
        [publication.as_fd(), cancellation.as_fd()],
        |role| {
            calls += 1;
            duplicate(role)
        },
    );

    assert!(matches!(result, Err(PreexecSetupCause::Geometry)));
    assert_eq!(calls, 0);
    assert!(aliases[3].is_none());
    assert_eq!(aliases[4].as_ref().unwrap().as_raw_fd(), retained_fd);
    assert_live_alias(aliases[4].as_ref().unwrap(), &cancellation, &mut peer);
}

#[test]
fn standing_alias_success_preserves_both_ordered_physical_roles() {
    let (publication, mut publication_peer) = UnixStream::pair().unwrap();
    let (cancellation, mut cancellation_peer) = UnixStream::pair().unwrap();
    let mut aliases = std::array::from_fn(|_| None);

    retain_standing_aliases(
        &mut aliases,
        [publication.as_fd(), cancellation.as_fd()],
        duplicate,
    )
    .unwrap();

    assert_live_alias(
        aliases[3].as_ref().unwrap(),
        &publication,
        &mut publication_peer,
    );
    assert_live_alias(
        aliases[4].as_ref().unwrap(),
        &cancellation,
        &mut cancellation_peer,
    );
    assert!(
        aliases[..3]
            .iter()
            .chain(&aliases[5..])
            .all(Option::is_none)
    );
}

// These component fixtures pay the actual containing cleanup allocation. They
// exercise real queue writes and alias closes without issuing Main or Source.
fn component_owner(
    cleanup: &crate::launch_cleanup::LaunchCleanup,
    role: BorrowedFd<'_>,
) -> PreparedPreexecSetup {
    PreparedPreexecSetup {
        aliases: std::array::from_fn(|index| (index < 8).then(|| duplicate(role).unwrap())),
        frame: crucible_qemu_protocol::publisher_subscription::PublisherSetup {
            region_len: 4096,
            process_generation: 1,
            device_digest_workspace: None,
            lender_generation: 1,
            device: 0,
            inode: 0,
            producer_event: 1,
            receiver_event: 2,
        }
        .encode()
        .unwrap(),
        queued: false,
        receipt: None,
        failure: None,
        retention: Some(cleanup.claim_preexec().unwrap()),
        cleanup: Some(cleanup.clone()),
        control: None,
    }
}

#[test]
fn preexec_abandonment_preserves_actual_queue_closes_and_independent_failure() {
    use crucible_host_resources::host_supervision::HostOperationBudgets;
    use crucible_host_resources::test_support::TestAllocationObserver;

    let fixture = crate::launch_cleanup::tests::allocation::fixture();
    let (socket, peer) = UnixStream::pair().unwrap();
    let (role, role_peer) = UnixStream::pair().unwrap();
    let mut owner = component_owner(&fixture.cleanup, role.as_fd());
    let frame = owner.frame;
    let descriptors: Vec<_> = owner
        .aliases
        .iter()
        .flatten()
        .map(AsRawFd::as_raw_fd)
        .collect();
    owner.queued = true;
    owner.receipt = Some(
        crucible_qemu_protocol::publisher_subscription::send_publisher_setup_frame_with_descriptors(
            socket.as_raw_fd(),
            &owner.frame,
            &descriptors,
        )
        .unwrap(),
    );
    let receipt = format!("{:?}", owner.receipt);

    // Observe two independent real refusals after the completed queue write.
    let cause = rustix::io::fcntl_dupfd_cloexec(role.as_fd(), i32::MAX).unwrap_err();
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    supervisor.cancel().unwrap();
    let original_after = supervisor.wait_for_active_work_change().unwrap_err();
    let original_description = format!("{original_after:?}");
    let error = PreexecSetupError {
        cause: PreexecSetupCause::Kernel(cause),
        original_after: Some(original_after),
        _owner: owner,
    };
    let mut child = crate::QemuNodeChild::new(
        std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap(),
    );
    child.retain_launch_cleanup(fixture.cleanup.clone());

    let (_, counts) = TestAllocationObserver::count(|| drop(error));

    // Reap the real child before assertions, retaining the queue peer until now.
    child.force_kill_and_reap_failed_realization().unwrap();
    drop(child);
    drop((socket, peer, role, role_peer));

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    let history = fixture.cleanup.abandoned_preexec().unwrap_or_else(|| {
        panic!("abandoned preexec history must remain in its containing allocation")
    });
    assert_eq!(history._frame, frame);
    assert!(history._queued);
    assert_eq!(format!("{:?}", history._receipt), receipt);
    for (index, descriptor) in descriptors.iter().enumerate() {
        let closed = history._aliases[index].as_ref().unwrap();
        assert_eq!(closed._descriptor, *descriptor);
        assert!(closed._result.is_ok());
    }
    assert!(history._aliases[8].is_none());
    let failure = history._failure.as_ref().unwrap();
    assert!(matches!(failure._cause, PreexecSetupCause::Kernel(errno) if errno == cause));
    assert_eq!(
        format!("{:?}", failure._original_after.as_ref().unwrap()),
        original_description
    );
    assert!(fixture.cleanup.claim_preexec().is_none());
    drop(fixture.cleanup);

    for account in fixture.accounts {
        assert!(account.reserve_resources(0, 0, 1).is_err());
    }
}

#[test]
fn unqueued_preexec_closes_aliases_without_retaining_the_containing_loan() {
    use crucible_host_resources::test_support::TestAllocationObserver;

    let fixture = crate::launch_cleanup::tests::allocation::fixture();
    let (role, peer) = UnixStream::pair().unwrap();
    let owner = component_owner(&fixture.cleanup, role.as_fd());
    let (_, counts) = TestAllocationObserver::count(|| drop(owner));

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(fixture.cleanup.abandoned_preexec().is_none());
    assert!(fixture.cleanup.claim_preexec().is_none());
    drop((role, peer, fixture.cleanup));

    for account in fixture.accounts {
        let complete = account.reserve_resources(0, 0, fixture.bytes).unwrap();
        drop(complete);
    }
}

#[test]
fn preexec_recipient_is_claimed_once_without_allocating() {
    use crucible_host_resources::test_support::TestAllocationObserver;

    let fixture = crate::launch_cleanup::tests::allocation::fixture();
    let (token, counts) = TestAllocationObserver::count(|| fixture.cleanup.claim_preexec());

    assert!(token.is_some());
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(fixture.cleanup.claim_preexec().is_none());
    drop(token);
    assert!(fixture.cleanup.claim_preexec().is_none());
    drop(fixture.cleanup);

    for account in fixture.accounts {
        let complete = account.reserve_resources(0, 0, fixture.bytes).unwrap();
        drop(complete);
    }
}

#[test]
fn queued_preexec_refunds_after_actual_receiver_close_and_child_reap() {
    use crucible_host_resources::test_support::TestAllocationObserver;

    let fixture = crate::launch_cleanup::tests::allocation::fixture();
    let (socket, peer) = UnixStream::pair().unwrap();
    let (role, role_peer) = UnixStream::pair().unwrap();
    let mut owner = component_owner(&fixture.cleanup, role.as_fd());
    let descriptors: Vec<_> = owner
        .aliases
        .iter()
        .flatten()
        .map(AsRawFd::as_raw_fd)
        .collect();
    owner.queued = true;
    owner.receipt = Some(
        crucible_qemu_protocol::publisher_subscription::send_publisher_setup_frame_with_descriptors(
            socket.as_raw_fd(),
            &owner.frame,
            &descriptors,
        )
        .unwrap(),
    );
    let mut child = crate::QemuNodeChild::new(
        std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap(),
    );
    child.retain_launch_cleanup(fixture.cleanup.clone());
    drop(peer);
    child.force_kill_and_reap_failed_realization().unwrap();
    drop(child);

    let (_, counts) = TestAllocationObserver::count(|| drop(owner));

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(fixture.cleanup.abandoned_preexec().is_none());
    drop((socket, role, role_peer, fixture.cleanup));

    for account in fixture.accounts {
        let complete = account.reserve_resources(0, 0, fixture.bytes).unwrap();
        drop(complete);
    }
}
