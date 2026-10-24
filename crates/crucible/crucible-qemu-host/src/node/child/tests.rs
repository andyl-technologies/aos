//! Actual child wait and pending-input retention with paired component funding.
//!
//! These controls use real kernel children and sockets. They issue no Main,
//! Source role, installed startup operation or native-profile authority.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;
use crucible_qemu_protocol::ram_page::RamPageBinding;
use rustix::process::{Pid, Signal, WaitOptions, kill_process, waitpid};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::sync::Arc;

/// Reaps only this fixture's actual child if an assertion interrupts transfer.
struct FixtureReap {
    child: Option<Pid>,
}

impl Drop for FixtureReap {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            let _killed = kill_process(child, Signal::KILL);
            let _waited = waitpid(Some(child), WaitOptions::empty());
        }
    }
}

#[test]
fn child_recipient_claim_is_linear_and_unborn_release_refunds_paired_credit() {
    let fixture = crate::launch_cleanup::tests::allocation::fixture();

    let (recipient, counts) =
        TestAllocationObserver::count(|| fixture.cleanup.claim_child_return());
    let recipient = recipient.unwrap_or_else(|| panic!("first child return claim must succeed"));

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(fixture.cleanup.claim_child_return().is_none());
    assert!(fixture.cleanup.retained_unreaped_child().is_none());
    drop(recipient);
    assert!(fixture.cleanup.claim_child_return().is_none());
    drop(fixture.cleanup);

    for account in fixture.accounts {
        let complete = account.reserve_resources(0, 0, fixture.bytes).unwrap();
        drop(complete);
    }
}

#[test]
fn unreaped_child_retains_actual_wait_owner_and_pending_source_without_allocation() {
    let fixture = crate::launch_cleanup::tests::allocation::fixture();
    // Reserve the same funded return slot before the actual process is born.
    let recipient = fixture.cleanup.claim_child_return().unwrap();
    let process = Command::new("sleep").arg("60").spawn().unwrap();
    let process_id = process.id();
    let mut reap = FixtureReap {
        child: Some(Pid::from_child(&process)),
    };
    let mut child = QemuNodeChild::new(process);
    child.retain_launch_cleanup(fixture.cleanup.clone());
    child.retain_child_return(recipient);

    let backing: Arc<dyn crate::ram_source::QemuRamBacking> =
        Arc::new(crate::qmp::checkpoint_paged_source_support::ImmutableBacking::new(2).unwrap());
    let backing_observer = Arc::downgrade(&backing);
    let binding = RamPageBinding {
        session: [1; 16],
        owner_incarnation: [2; 16],
        source_generation: 1,
        root_digest: *backing.root_record().digest().as_bytes(),
    };
    let (socket, peer) = UnixStream::pair().unwrap();
    child.ram_source_start = Some(crate::ram_source::SourceInput::new(
        socket, backing, binding,
    ));

    // Exercise the fallback transfer itself while actual reap is unknown;
    // the fixture does not fake a failed wait or invent a terminal receipt.
    let (retained, counts) = TestAllocationObserver::count(|| child.retain_unreaped_fields(None));
    let published = fixture.cleanup.retained_unreaped_child();
    let (retained_id, pending_input, running, waited_id, status) = {
        let mut actual = published
            .unwrap_or_else(|| panic!("actual unreaped child must remain in its paid recipient"))
            .lock()
            .unwrap();
        let retained_id = actual._child.id();
        let pending_input = actual._pending_source.is_some();
        let running = actual._child.try_wait().unwrap().is_none();
        actual._child.kill().unwrap();
        let status = actual._child.wait().unwrap();
        reap.child = None;
        (
            retained_id,
            pending_input,
            running,
            actual._child.id(),
            status,
        )
    };
    fixture.cleanup.child_reaped();

    assert!(retained);
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert!(!child.reaped());
    assert!(child.child.transferred());
    assert!(child.ram_source_start.is_none());
    assert!(child.child_return.is_none());
    assert_eq!(retained_id, process_id);
    assert_eq!(waited_id, process_id);
    assert!(running);
    assert!(!status.success());
    assert!(pending_input);
    assert!(backing_observer.upgrade().is_some());
    drop((child, peer, fixture.cleanup));

    // The test's actual reap does not erase the unknown disposition that was
    // handed over. Closing all ordinary observers still retains the same loan
    // and pending input until the containing process exits.
    assert!(backing_observer.upgrade().is_some());
    for account in fixture.accounts {
        assert!(matches!(
            account.reserve_resources(0, 0, 1),
            Err(crucible_host_resources::host_services::HostServiceError::CapacityExhausted)
        ));
    }
}

#[test]
fn actual_child_reap_closes_unused_recipient_before_paired_refund() {
    let fixture = crate::launch_cleanup::tests::allocation::fixture();
    let recipient = fixture.cleanup.claim_child_return().unwrap();
    let process = Command::new("true").spawn().unwrap();
    let mut child = QemuNodeChild::new(process);
    child.retain_launch_cleanup(fixture.cleanup.clone());
    child.retain_child_return(recipient);

    child
        .force_kill_and_reap_failed_helper(Duration::from_secs(5))
        .unwrap();
    assert!(child.reaped());
    assert!(fixture.cleanup.retained_unreaped_child().is_none());
    let ((), counts) = TestAllocationObserver::count(|| drop(child));
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    drop(fixture.cleanup);

    for account in fixture.accounts {
        let complete = account.reserve_resources(0, 0, fixture.bytes).unwrap();
        drop(complete);
    }
}
