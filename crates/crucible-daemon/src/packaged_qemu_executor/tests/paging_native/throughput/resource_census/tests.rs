//! Kernel census parser, inode identity and finite scratch ownership regressions.

use super::*;
use crucible_linux_resource::host_services::HostServiceAllocator;
use crucible_linux_resource::host_supervision::{HostOperationBudgets, HostOperationSupervisor};
use std::time::Duration;

#[test]
fn controller_failure_releases_worker_without_waiting_for_its_original_cap() {
    use super::super::{Rendezvous, RendezvousAbortGuard};
    use std::sync::mpsc;

    for sampler_panics in [false, true] {
        let allocator = HostServiceAllocator::new(1, 1, 1 << 20).unwrap();
        let permit = allocator.reserve_resources(1, 0, 1 << 20).unwrap();
        let worker_supervisor = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(30)),
        )
        .unwrap();
        let controller_supervisor = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(30)),
        )
        .unwrap();
        let original_cap = worker_supervisor.cap_id();
        let rendezvous = Rendezvous::default();
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (completed_tx, completed_rx) = mpsc::sync_channel(0);
        std::thread::scope(|scope| {
            let original = worker_supervisor
                .begin(HostOperationClass::Quiescence)
                .unwrap();
            let worker_rendezvous = &rendezvous;
            let worker = std::thread::Builder::new()
                .stack_size(super::super::workers::WORKER_STACK)
                .spawn_scoped(scope, move || {
                    let _permit = permit;
                    entered_tx.send(()).unwrap();
                    let result = worker_rendezvous.wait_for_release(&original);
                    completed_tx.send(result).unwrap();
                })
                .unwrap();
            entered_rx.recv().unwrap();

            if sampler_panics {
                let failure = std::panic::catch_unwind(|| {
                    let _abort = RendezvousAbortGuard::new(&rendezvous);
                    panic!("injected census sampler panic");
                });
                assert!(failure.is_err());
            } else {
                let abort = RendezvousAbortGuard::new(&rendezvous);
                let original = controller_supervisor
                    .begin(HostOperationClass::Preparation)
                    .unwrap();
                controller_supervisor.cancel().unwrap();
                assert!(original.wait_for_change().is_err());
                drop(abort);
            }
            // The worker's separate original 30-second cap remains live. The
            // guard's abort/release, rather than expiry or a new supervisor,
            // must cause this completion within two seconds.
            assert!(matches!(
                completed_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                Err(super::super::HostOperationalError::Unavailable)
            ));
            worker.join().unwrap();
        });
        assert_eq!(worker_supervisor.cap_id(), original_cap);
        assert!(rendezvous.aborted.load(super::super::Ordering::Acquire));
        assert!(rendezvous.released.load(super::super::Ordering::Acquire));
        assert!(allocator.reserve_resources(1, 0, 1 << 20).is_ok());
    }
}

#[test]
fn borrowed_link_target_has_an_explicit_buffer_bound() {
    let allocator = HostServiceAllocator::new(1, DESCRIPTORS, SCRATCH_BYTES).unwrap();
    let _loan = allocator
        .reserve_resources(0, DESCRIPTORS, SCRATCH_BYTES)
        .unwrap();
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(30)),
    )
    .unwrap();
    let guard = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("target");
    std::os::unix::fs::symlink("accepted", &path).unwrap();
    let mut buffer = [0; MAX_PATH + 1];
    assert_eq!(
        link_target(&path, &mut buffer, &guard).unwrap(),
        Path::new("accepted")
    );
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("x".repeat(MAX_PATH + 1), &path).unwrap();
    assert_eq!(
        link_target(&path, &mut buffer, &guard).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn process_birth_parser_handles_command_parentheses_and_rejects_wrong_identity() {
    let stat = "17 (command with ) in name) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1234 9";
    assert_eq!(birth_tick(stat, 17).unwrap(), 1234);
    assert!(birth_tick(stat, 18).is_err());
    assert!(birth_tick("17 (short) S 1", 17).is_err());
}

#[test]
fn process_revalidation_rejects_membership_and_birth_identity_changes() {
    let allocator = HostServiceAllocator::new(1, DESCRIPTORS, SCRATCH_BYTES).unwrap();
    let _loan = allocator
        .reserve_resources(0, DESCRIPTORS, SCRATCH_BYTES)
        .unwrap();
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(30)),
    )
    .unwrap();
    let guard = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let cgroup = tempfile::tempdir().unwrap();
    let membership = cgroup.path().join("cgroup.procs");
    let pid = std::process::id();
    std::fs::write(&membership, format!("{pid}\n")).unwrap();
    let pids = processes(cgroup.path(), &guard).unwrap();
    let mut before = process_identities(&pids, &guard).unwrap();
    assert!(stable_processes(cgroup.path(), &pids, &before, &guard).unwrap());

    before[0].birth_tick = before[0].birth_tick.checked_add(1).unwrap();
    assert!(!stable_processes(cgroup.path(), &pids, &before, &guard).unwrap());
    before[0].birth_tick -= 1;
    std::fs::write(&membership, "").unwrap();
    assert!(!stable_processes(cgroup.path(), &pids, &before, &guard).unwrap());
    guard.complete().unwrap();
}

#[test]
fn kernel_fields_require_units_uniqueness_and_checked_bytes() {
    assert_eq!(
        field("Private_Clean: 17 kB\n", "Private_Clean:", true).unwrap(),
        Some(17 * 1024)
    );
    assert_eq!(field("file 4096\n", "file", false).unwrap(), Some(4096));
    assert_eq!(field("anon 7\n", "file", false).unwrap(), None);
    for malformed in [
        "Pss: 7 MB",
        "Pss: 7 kB extra",
        "Pss: 7 kB\nPss: 8 kB",
        "Pss: 18446744073709551615 kB",
    ] {
        assert!(field(malformed, "Pss:", true).is_err());
    }
    assert_eq!(
        serde_json::to_value(Census::default()).unwrap()["process_memory"],
        serde_json::Value::Null
    );
}

#[test]
fn inode_aliases_deduplicate_and_changing_extents_refuse() {
    let mut aliases = [(2, 3, 8192, true), (1, 3, 4096, false), (2, 3, 8192, true)];
    let storage = summarize_inodes(&mut aliases).unwrap();
    assert_eq!(storage.allocated_bytes, 12_288);
    assert_eq!(storage.unique_inodes, 2);
    assert_eq!(storage.unlinked_inodes, 1);
    assert!(summarize_inodes(&mut [(1, 2, 4096, true), (1, 2, 8192, true)]).is_err());
    assert!(summarize_inodes(&mut [(1, 2, u64::MAX, false), (2, 2, 1, false)]).is_err());
}

#[test]
fn real_inode_census_counts_hardlinks_once_and_excludes_symlink_targets() {
    let allocator = HostServiceAllocator::new(1, DESCRIPTORS + 2, SCRATCH_BYTES + 4096).unwrap();
    let file_loan = allocator.reserve_resources(0, 2, 4096).unwrap();
    let loan = allocator
        .reserve_resources(0, DESCRIPTORS, SCRATCH_BYTES)
        .unwrap();
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(30)),
    )
    .unwrap();
    let guard = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("file"), [7; 4096]).unwrap();
    std::fs::hard_link(root.path().join("file"), root.path().join("alias")).unwrap();
    std::fs::write(outside.path().join("excluded"), [9; 8192]).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("outside")).unwrap();
    let unlinked_path = root.path().join("unlinked");
    let mut unlinked = std::fs::File::create(&unlinked_path).unwrap();
    std::io::Write::write_all(&mut unlinked, &[3; 4096]).unwrap();
    let alias = unlinked.try_clone().unwrap();
    std::fs::remove_file(unlinked_path).unwrap();
    let measured = storage_usage(&[root.path()], &[], &guard).unwrap();
    let expected = std::fs::symlink_metadata(root.path()).unwrap().blocks() * 512
        + std::fs::symlink_metadata(root.path().join("file"))
            .unwrap()
            .blocks()
            * 512
        + unlinked.metadata().unwrap().blocks() * 512
        + std::fs::symlink_metadata(root.path().join("outside"))
            .unwrap()
            .blocks()
            * 512;
    assert_eq!(measured.allocated_bytes, expected);
    assert_eq!(measured.unique_inodes, 4);
    assert_eq!(measured.unlinked_inodes, 1);
    let overlapping = storage_usage(&[root.path(), root.path()], &[], &guard).unwrap();
    assert_eq!(overlapping.allocated_bytes, expected);
    assert_eq!(overlapping.unique_inodes, measured.unique_inodes);
    guard.complete().unwrap();
    drop(alias);
    drop(unlinked);
    drop(file_loan);
    assert!(
        allocator
            .reserve_resources(0, DESCRIPTORS, SCRATCH_BYTES)
            .is_err()
    );
    let borrower = loan.clone();
    drop(loan);
    assert!(
        allocator
            .reserve_resources(0, DESCRIPTORS, SCRATCH_BYTES)
            .is_err()
    );
    drop(borrower);
    assert!(
        allocator
            .reserve_resources(0, DESCRIPTORS, SCRATCH_BYTES)
            .is_ok()
    );
}

#[test]
fn parser_refuses_oversized_input_and_original_cancellation() {
    let allocator = HostServiceAllocator::new(1, DESCRIPTORS, SCRATCH_BYTES).unwrap();
    let _loan = allocator
        .reserve_resources(0, DESCRIPTORS, SCRATCH_BYTES)
        .unwrap();
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(30)),
    )
    .unwrap();
    let guard = supervisor.begin(HostOperationClass::Preparation).unwrap();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("oversized");
    std::fs::write(&path, vec![b'0'; MAX_TEXT + 1]).unwrap();
    assert_eq!(
        text(&path, &guard).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    supervisor.cancel().unwrap();
    assert_eq!(
        text(&path, &guard).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
}
