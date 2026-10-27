//! Checks both actual output allocations against the original paired counters.
//!
//! Mechanism loans exercise the same generic body without issuing a Source.

use super::*;
use crucible_host_resources::host_services::{HostServiceAllocator, HostServiceLeasePair};
use crucible_host_resources::test_support::{AllocationIdentity, TestAllocationObserver};
use std::alloc::Layout;
use std::os::unix::process::ExitStatusExt;

struct Fixture {
    accounts: [HostServiceAllocator; 2],
    allocations: [AllocationIdentity; 2],
    received: FundedProbeOutput<HostServiceLeasePair>,
}

fn fixture() -> Fixture {
    let accounts = [
        HostServiceAllocator::new(1, 1, 4096).unwrap(),
        HostServiceAllocator::new(1, 1, 4096).unwrap(),
    ];
    let funding = HostServiceLeasePair::new(
        accounts[0].reserve_resources(0, 0, 4096).unwrap(),
        accounts[1].reserve_resources(0, 0, 4096).unwrap(),
    );
    let (stdout, stdout_allocation) = capture_buffer(b"actual monitor output");
    let (stderr, stderr_allocation) = capture_buffer(b"actual diagnostic");
    let (received, counts) = TestAllocationObserver::count(|| {
        FundedProbeOutput::new(
            Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout,
                stderr,
            },
            funding,
        )
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);

    Fixture {
        accounts,
        allocations: [stdout_allocation, stderr_allocation],
        received,
    }
}

fn capture_buffer(bytes: &[u8]) -> (Vec<u8>, AllocationIdentity) {
    let (buffer, allocation, counts) = TestAllocationObserver::capture_layout_and_count(
        Layout::array::<u8>(bytes.len()).unwrap(),
        || bytes.to_vec(),
    );

    assert_eq!(counts.allocations, 1);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    (buffer, allocation.unwrap())
}

#[test]
fn received_probe_buffers_close_before_their_original_paired_refund() {
    let Fixture {
        accounts,
        allocations,
        received,
    } = fixture();
    assert!(received.output().status.success());
    assert_eq!(received.output().stdout, b"actual monitor output");
    assert_eq!(received.output().stderr, b"actual diagnostic");

    let ((), observations) = TestAllocationObserver::observe_controls(
        [&accounts[0], &accounts[1]],
        None,
        [Some(allocations[0]), Some(allocations[1]), None],
        || drop(received),
    );

    for observation in observations.into_iter().take(2) {
        let observation = observation.unwrap();
        assert_eq!(observation.before.original_bytes, [Some(4096); 2]);
        assert_eq!(observation.after.original_bytes, [Some(4096); 2]);
    }
    assert_returned(&accounts);
}

#[test]
fn received_probe_move_keeps_both_buffers_funded_on_the_receiving_thread() {
    let Fixture {
        accounts,
        allocations,
        received,
    } = fixture();

    std::thread::scope(|scope| {
        let accounts = &accounts;
        scope
            .spawn(move || {
                assert_eq!(received.output().stdout, b"actual monitor output");
                let ((), observations) = TestAllocationObserver::observe_controls(
                    [&accounts[0], &accounts[1]],
                    None,
                    [Some(allocations[0]), Some(allocations[1]), None],
                    || drop(received),
                );
                for observation in observations.into_iter().take(2) {
                    let observation = observation.unwrap();
                    assert_eq!(observation.before.original_bytes, [Some(4096); 2]);
                    assert_eq!(observation.after.original_bytes, [Some(4096); 2]);
                }
            })
            .join()
            .unwrap();
    });

    assert_returned(&accounts);
}

fn assert_returned(accounts: &[HostServiceAllocator; 2]) {
    for account in accounts {
        drop(account.reserve_resources(0, 0, 4096).unwrap());
    }
}
