//! Actual mapping-allocation custody across in-place selection.

// crucible-lint: allow panic-shortcut -- Lifecycle test assertions deliberately panic on failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::tests::original_aliases;
use super::*;
use crate::SelectedRingAdmissionBudget;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn ordinary_owner_preserves_views_and_reversible_ring_release() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    let address = first.mapping_start();
    let mut owner = OwnedSetupMapping::new(first);

    assert_eq!(owner.mapping().mapping_start(), address);
    assert_eq!(owner.ordinary_mapping_mut()?.mapping_start(), address);
    owner.mapping().hold_hot_fork_ring_io()?;
    assert_eq!(alias.release_hot_fork_ring_io()?.held_rings(), 0);
    assert!(owner.selected_mut().is_err());
    Ok(())
}

#[test]
fn whole_selection_preserves_the_same_owner_allocation_and_views() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let address = first.mapping_start();
    let mut owner = OwnedSetupMapping::new(first);
    let allocation = match &owner.owner {
        MappingOwner::Ordinary(mapping) => Arc::as_ptr(mapping),
        MappingOwner::Selected(_) => return Err("unexpected initial selection".into()),
    };

    owner.select_whole(7)?;

    let selected = owner.selected_mut()?;
    assert_eq!(Arc::as_ptr(&selected.mapping), allocation);
    assert_eq!(Arc::strong_count(&selected.mapping), 1);
    selected.selection_status()?;
    assert_eq!(owner.mapping().mapping_start(), address);
    assert!(owner.ordinary_mapping_mut().is_err());
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
fn failed_selection_retains_the_same_owner_before_any_retry_or_drop() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut owner = OwnedSetupMapping::new(first);
    let allocation = match &owner.owner {
        MappingOwner::Ordinary(mapping) => Arc::as_ptr(mapping),
        MappingOwner::Selected(_) => return Err("unexpected initial selection".into()),
    };

    assert_eq!(
        owner.select_whole(0),
        Err(WholeMappingCustodyError::ZeroEpoch)
    );

    assert_eq!(Arc::as_ptr(&owner.selected_mut()?.mapping), allocation);
    assert_eq!(owner.selected_mut()?.epoch(), 0);
    assert_eq!(
        owner.select_whole(7),
        Err(WholeMappingCustodyError::Selected)
    );
    assert!(owner.ordinary_mapping_mut().is_err());
    drop(owner);
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
fn an_additional_real_owner_refuses_unique_ordinary_mutation() -> TestResult {
    let (_file, first, _alias) = original_aliases()?;
    let mut owner = OwnedSetupMapping::new(first);
    let extra_owner = match &owner.owner {
        MappingOwner::Ordinary(mapping) => Arc::clone(mapping),
        MappingOwner::Selected(_) => return Err("unexpected initial selection".into()),
    };

    assert!(matches!(
        owner.ordinary_mapping_mut(),
        Err(WholeMappingCustodyError::Busy)
    ));

    drop(extra_owner);
    assert!(owner.ordinary_mapping_mut().is_ok());
    Ok(())
}

#[test]
fn two_balanced_local_loans_keep_the_same_selected_world_mapping() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let address = first.mapping_start();
    let mut owner = OwnedSetupMapping::new(first);
    owner.select_whole(7)?;
    let selected = owner.selected_mut()?;

    for sequence in 1..=2 {
        // This models the caller's native proof; it asserts only real local
        // paired balance and does not qualify a native stopped/result/ACK cut.
        let (_, completion) = selected.with_paired_selected_scope(
            7,
            sequence,
            0x1000 + sequence as usize,
            SelectedRingAdmissionBudget {
                producer_attempts: 0,
                consumer_attempts: 0,
            },
            |mapping| Ok::<_, std::io::Error>(mapping.mapping_start()),
        )??;
        selected.retire_paired_scope(7, sequence, 0x1000 + sequence as usize, completion)?;
    }

    assert_eq!(owner.mapping().mapping_start(), address);
    assert!(owner.ordinary_mapping_mut().is_err());
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
fn early_intent_fences_aliases_and_retains_the_same_owner_before_epoch_adoption() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut owner = OwnedSetupMapping::new(first);
    let original = match &owner.owner {
        MappingOwner::Ordinary(mapping) => Arc::downgrade(mapping),
        MappingOwner::Selected(_) => return Err("unexpected original selection".into()),
    };
    let address = owner.mapping().mapping_start();

    owner.prepare_whole_intent_retention()?;
    owner.begin_whole_intent()?;
    assert!(owner.selected_mut().is_err());
    assert!(owner.ordinary_mapping_mut().is_err());
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    drop(owner);

    let retained = original
        .upgrade()
        .ok_or("intent abandoned the actual mapped Arc")?;
    assert_eq!(retained.mapping_start(), address);
    assert!(retained.hot_fork_ring_io_snapshot()?.quiescent());
    assert!(retained.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn exclusive_owner_failure_cancels_its_actual_loan_without_local_retirement() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut owner = OwnedSetupMapping::new(first);
    owner.prepare_whole_intent_retention()?;
    owner.begin_whole_intent()?;
    owner.select_whole_bounded(7, 2)?;
    owner.selected_mut()?.begin_paired_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 0,
            consumer_attempts: 0,
        },
    )?;
    let header = crate::RingHeader::new();
    let mut entries: [crate::FrameEntry; 2] = std::array::from_fn(|_| crate::FrameEntry::default());
    let frame = crate::FrameEntry::new(11, 0, 52, b"ordinary-after-cancellation")?;

    owner.refuse_whole_control();
    assert!(owner.selected_mut()?.selection_status().is_err());
    assert!(owner.select_whole_bounded(7, 2).is_err());
    header.enqueue(&mut entries, &frame)?;
    assert_eq!(
        header
            .dequeue(&entries)?
            .ok_or("ordinary frame absent")?
            .seq,
        52
    );
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
fn prepared_parent_ticket_after_actual_child_replacement_runs_in_isolation() -> TestResult {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact",
            "mapped_setup_region::selected_lifecycle::owned_setup::tests::prepared_parent_ticket_child_replacement_fixture",
            "--test-threads=1"])
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
#[ignore = "owns child mapping replacement with an inherited locked parent quarantine"]
fn prepared_parent_ticket_child_replacement_fixture() -> TestResult {
    use crate::mapped_setup_region::selected_lifecycle::{quarantine, registry};
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::Duration;

    let (_source_file, first, alias) = original_aliases()?;
    let (file, destination, destination_alias) = original_aliases()?;
    let expected = destination.backing_identity();
    drop(destination);
    drop(destination_alias);
    first.exclude_from_hot_fork_child()?;
    let address = first.mapping_start();
    let parent_pid = std::process::id();
    let mut owner = OwnedSetupMapping::new(first);
    owner.prepare_whole_intent_retention()?;
    assert!(owner.retention_slot.armed());
    assert!(!owner.intent);
    assert_eq!(quarantine().lock().unwrap().reserved, 1);
    let before = owner.mapping().hot_fork_ring_io_snapshot()?;
    let (locked_tx, locked_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _quarantine = quarantine()
            .lock()
            .expect("parent original retention store");
        locked_tx.send(()).expect("report actual store lock");
        release_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("release parent store lock");
    });
    locked_rx.recv_timeout(Duration::from_secs(2))?;
    let (mut parent_socket, mut child_socket) = UnixStream::pair()?;
    parent_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    child_socket.set_write_timeout(Some(Duration::from_secs(2)))?;

    // SAFETY: this isolated fixture owns its stack mapping and child lifetime.
    // The other thread holds only quarantine, never a mapping reference.
    let child = unsafe { libc::fork() };
    if child < 0 {
        release_tx.send(())?;
        worker
            .join()
            .map_err(|_| "parent retention worker panicked")?;
        return Err(std::io::Error::last_os_error().into());
    }
    if child == 0 {
        drop(parent_socket);
        let result = (|| -> TestResult {
            owner
                .ordinary_mapping_mut()?
                .install_hot_fork_child_mapping(file.as_fd(), expected)?;
            assert_eq!(
                owner.mapping().mapping_owner_key().process,
                std::process::id()
            );
            assert_ne!(std::process::id(), parent_pid);
            assert!(!owner.retention_slot.armed());
            assert_eq!(owner.mapping().hot_fork_ring_io_snapshot()?, before);
            assert_eq!(
                owner.prepare_whole_intent_retention(),
                Err(WholeMappingCustodyError::Unregistered)
            );
            assert_eq!(
                owner.begin_whole_intent(),
                Err(WholeMappingCustodyError::Selected)
            );
            assert_eq!(
                owner.select_whole_bounded(7, 1),
                Err(WholeMappingCustodyError::Selected)
            );
            assert_eq!(quarantine().lock().unwrap().reserved, 0);
            assert!(quarantine().lock().unwrap().owners.is_empty());
            assert!(!owner.intent);
            let weak = match &owner.owner {
                MappingOwner::Ordinary(mapping) => Arc::downgrade(mapping),
                MappingOwner::Selected(_) => {
                    return Err("foreign ticket adopted epoch custody".into());
                }
            };

            drop(owner);
            assert!(weak.upgrade().is_none());
            assert!(!registry().lock().unwrap().mappings.contains_key(&address));
            child_socket.write_all(&[1])?;
            Ok(())
        })();
        // SAFETY: copied parent actors and the vanished thread's guard must
        // never run destructors in this child process.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
    }

    drop(child_socket);
    release_tx.send(())?;
    worker
        .join()
        .map_err(|_| "parent retention worker panicked")?;
    let mut response = [0];
    let completion = parent_socket.read_exact(&mut response);
    if completion.is_err() {
        // SAFETY: this fixture owns and reaps the exact child on timeout.
        unsafe { libc::kill(child, libc::SIGKILL) };
    }
    let mut status = 0;
    // SAFETY: status is writable and child is the exact owned process.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    completion?;
    assert_eq!(response, [1]);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert!(owner.retention_slot.armed());
    assert_eq!(quarantine().lock().unwrap().reserved, 1);
    assert_eq!(owner.mapping().mapping_owner_key().process, parent_pid);
    assert_eq!(alias.hot_fork_ring_io_snapshot()?, before);

    drop(owner);
    assert_eq!(quarantine().lock().unwrap().reserved, 0);
    assert!(quarantine().lock().unwrap().owners.is_empty());
    Ok(())
}
