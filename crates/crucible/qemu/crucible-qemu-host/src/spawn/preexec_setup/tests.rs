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
