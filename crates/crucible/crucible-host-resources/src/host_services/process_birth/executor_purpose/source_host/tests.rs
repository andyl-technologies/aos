//! Checks actual socket identity and the private once-birth journal.
//!
//! Journal cases construct no authenticated Main, Source purpose, native
//! execution profile or physical return receipt.

use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use super::{SourceBirthEndpoint, SourceChildState, record_collected_child};

#[test]
fn birth_endpoint_tracks_the_actual_socket_across_descriptor_duplication() {
    let (endpoint, peer) = UnixStream::pair().unwrap();
    let (other, _) = UnixStream::pair().unwrap();
    let duplicate = endpoint.try_clone().unwrap();
    let identity = SourceBirthEndpoint::read(endpoint.as_fd()).unwrap();

    assert_eq!(
        identity,
        SourceBirthEndpoint::read(duplicate.as_fd()).unwrap()
    );
    assert_ne!(identity, SourceBirthEndpoint::read(peer.as_fd()).unwrap());
    assert_ne!(identity, SourceBirthEndpoint::read(other.as_fd()).unwrap());

    drop(endpoint);
    assert_eq!(
        identity,
        SourceBirthEndpoint::read(duplicate.as_fd()).unwrap()
    );
}

#[test]
fn birth_endpoint_refuses_a_regular_file() {
    let file = tempfile::tempfile().unwrap();

    assert!(SourceBirthEndpoint::read(file.as_fd()).is_err());
}

#[test]
fn birth_journal_refuses_foreign_endpoints_and_a_second_attempt() {
    let (endpoint, other) = UnixStream::pair().unwrap();
    let identity = SourceBirthEndpoint::read(endpoint.as_fd()).unwrap();
    let foreign = SourceBirthEndpoint::read(other.as_fd()).unwrap();
    let mut journal = SourceChildState::default();
    journal.assign_endpoint(identity).unwrap();

    assert!(journal.begin_birth(foreign).is_err());
    assert!(!journal.birth_attempted);
    assert_eq!(journal.endpoint, Some(identity));

    journal.begin_birth(identity).unwrap();

    assert!(journal.begin_birth(identity).is_err());
    assert!(journal.assign_endpoint(foreign).is_err());
    assert_eq!(journal.endpoint, Some(identity));
    assert!(!journal.returned_or_unstarted());
}

#[test]
fn unattempted_birth_assignment_cannot_be_reissued() {
    let (endpoint, other) = UnixStream::pair().unwrap();
    let identity = SourceBirthEndpoint::read(endpoint.as_fd()).unwrap();
    let foreign = SourceBirthEndpoint::read(other.as_fd()).unwrap();
    let mut journal = SourceChildState::default();
    journal.assign_endpoint(identity).unwrap();

    assert!(journal.returned_or_unstarted());
    assert!(journal.assign_endpoint(identity).is_err());
    assert!(journal.assign_endpoint(foreign).is_err());
    assert!(!journal.birth_attempted);
    assert_eq!(journal.endpoint, Some(identity));
}

#[test]
fn birth_journal_requires_endpoint_custody_before_accepting_a_reap_record() {
    let (endpoint, _) = UnixStream::pair().unwrap();
    let identity = SourceBirthEndpoint::read(endpoint.as_fd()).unwrap();

    // Exhausts bookkeeping combinations; the PID is no process authority.
    for assigned in [false, true] {
        for attempted in [false, true] {
            for retained in [false, true] {
                for reaped in [false, true] {
                    let journal = SourceChildState {
                        endpoint: assigned.then_some(identity),
                        birth_attempted: attempted,
                        process: retained.then_some(1),
                        reaped,
                    };
                    let unstarted = !attempted && !retained && !reaped;
                    let collected = assigned && attempted && retained && reaped;

                    assert_eq!(journal.returned_or_unstarted(), unstarted || collected);
                }
            }
        }
    }
}

// A real Rust test executable lists its cases and exits without executing them.
// This is an ordinary kernel child, not an authenticated Source or native Main.
fn spawn_test_child() -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--list")
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap()
}

fn modeled_collection_journal(child: &std::process::Child) -> std::sync::Mutex<SourceChildState> {
    let (endpoint, _) = UnixStream::pair().unwrap();
    std::sync::Mutex::new(SourceChildState {
        endpoint: Some(SourceBirthEndpoint::read(endpoint.as_fd()).unwrap()),
        birth_attempted: true,
        process: Some(child.id()),
        reaped: false,
    })
}

#[test]
fn contended_collection_journal_refuses_after_actual_child_wait_without_erasing_custody() {
    let mut child = spawn_test_child();
    assert!(child.wait().unwrap().success());
    let journal = modeled_collection_journal(&child);
    let held = journal.lock().unwrap();

    let error = record_collected_child(&journal, &child).unwrap_err();

    assert_eq!(error.raw_os_error(), Some(libc::EBUSY));
    assert!(!held.reaped);
    assert!(!held.returned_or_unstarted());
    drop(held);

    record_collected_child(&journal, &child).unwrap();
    assert!(journal.lock().unwrap().returned_or_unstarted());
}

#[test]
fn poisoned_collection_journal_refuses_after_actual_child_wait() {
    let mut child = spawn_test_child();
    assert!(child.wait().unwrap().success());
    let journal = modeled_collection_journal(&child);
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = journal.lock().unwrap();
        panic!("interrupt the actual collection journal");
    }));
    assert!(interrupted.is_err());

    let error = record_collected_child(&journal, &child).unwrap_err();

    assert_eq!(error.raw_os_error(), Some(libc::EOWNERDEAD));
    let held = journal.lock().err().unwrap().into_inner();
    assert!(!held.reaped);
    assert!(!held.returned_or_unstarted());
}

#[test]
fn foreign_actual_child_cannot_complete_the_original_collection_journal() {
    let mut child = spawn_test_child();
    let mut foreign = spawn_test_child();
    assert_ne!(child.id(), foreign.id());
    assert!(child.wait().unwrap().success());
    assert!(foreign.wait().unwrap().success());
    let journal = modeled_collection_journal(&child);

    let error = record_collected_child(&journal, &foreign).unwrap_err();

    assert_eq!(error.raw_os_error(), Some(libc::EPROTO));
    assert!(!journal.lock().unwrap().reaped);
    record_collected_child(&journal, &child).unwrap();
    assert!(journal.lock().unwrap().returned_or_unstarted());
}
