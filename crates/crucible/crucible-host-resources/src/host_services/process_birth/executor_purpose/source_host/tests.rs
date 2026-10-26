//! Checks actual socket identity and the private once-birth journal.
//!
//! Journal cases construct no authenticated Main, Source purpose, native
//! execution profile or physical return receipt.

use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use super::{SourceBirthEndpoint, SourceChildState};

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
