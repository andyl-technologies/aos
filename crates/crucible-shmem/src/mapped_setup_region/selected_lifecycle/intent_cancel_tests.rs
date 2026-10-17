//! Actual source-intent fencing and failure cancellation on original mapping owners.

// crucible-lint: allow panic-shortcut -- Lifecycle test assertions deliberately panic on failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

#[test]
fn source_intent_fences_ordinary_aliases_before_assigning_an_epoch_or_scope() -> TestResult {
    let (file, mut first, mut alias) = original_aliases()?;
    let size = first.region_len();
    let offsets = directed_header_offsets(&mut first, 0)?;
    let original = alias.node_directed_ring_pair_mut(
        0,
        0,
        crate::SLOT_NET_ROUTER as u32,
        crate::SLOT_NET_ROUTER as u32,
        0,
    )?;
    let frame = FrameEntry::new(11, 0, 52, b"original-before-source-observation")?;
    original
        .first
        .header
        .enqueue(original.first.entries, &frame)?;
    let before = original.first.header.snapshot(original.first.entries)?;
    first.hold_hot_fork_ring_io()?;
    let owner = SharedOwnedSetupMapping::new(first);

    owner.prepare_whole_intent_retention()?;
    owner.begin_whole_intent()?;
    let generation = owner.generation()?;
    let cell = generation.cell.as_ref().map_err(|error| *error)?;
    assert!(!generation.selected.load(Ordering::Acquire));
    assert!(!cell.selected.load(Ordering::Acquire));
    assert_eq!(cell.epoch.load(Ordering::Acquire), 0);
    assert_eq!(cell.next_sequence.load(Ordering::Acquire), 1);
    assert!(
        owner
            .with_selected(|selected| selected.selection_status())
            .is_err()
    );
    assert!(crate::mmap_setup_region(file.as_fd(), size).is_err());
    assert!(original.first.header.release_hot_fork_producers().held());
    assert!(original.first.header.release_hot_fork_consumers().held());
    assert_eq!(
        original.first.header.snapshot(original.first.entries)?,
        before
    );

    owner.select_whole_roster_bounded(7, 1, &offsets)?;
    owner.with_selected(|selected| {
        selected.begin_paired_scope(
            7,
            1,
            123,
            SelectedRingAdmissionBudget {
                producer_attempts: 0,
                consumer_attempts: 1,
            },
        )
    })??;
    let received = owner.with_selected(|selected| {
        selected.with_paired_mapping(|mapping| {
            let pair = mapping.node_directed_ring_pair_mut(
                0,
                0,
                crate::SLOT_NET_ROUTER as u32,
                crate::SLOT_NET_ROUTER as u32,
                0,
            )?;
            pair.first
                .header
                .dequeue(pair.first.entries)?
                .ok_or::<Box<dyn std::error::Error>>("original staged frame absent".into())
        })
    })???;
    assert_eq!(
        &received.data[..usize::from(received.len)],
        b"original-before-source-observation"
    );
    owner.with_selected(|selected| selected.end_paired_scope(7, 1, 123))??;
    Ok(())
}

#[test]
fn intent_refusal_while_an_actual_ordinary_loan_is_live_stays_failed_after_release() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let owner = SharedOwnedSetupMapping::new(first);
    let domain = Arc::clone(
        owner
            .generation()?
            .domain
            .as_ref()
            .map_err(|error| *error)?,
    );
    owner.prepare_whole_intent_retention()?;
    let ordinary_loan = crate::mapped_setup_region::selected_lifecycle::ordinary(&domain)?;

    assert_eq!(
        owner.begin_whole_intent(),
        Err(WholeMappingCustodyError::Busy)
    );
    assert!(alias.release_hot_fork_ring_io().is_err());
    drop(ordinary_loan);
    assert_eq!(
        owner.begin_whole_intent(),
        Err(WholeMappingCustodyError::Selected)
    );
    assert!(owner.select_whole_roster_bounded(7, 1, &[1]).is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
fn getter_failure_before_end_cancels_tls_and_preserves_actual_ring_effect_history() -> TestResult {
    let (_file, first, mut alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let original = alias.node_directed_ring_pair_mut(
        0,
        0,
        crate::SLOT_NET_ROUTER as u32,
        crate::SLOT_NET_ROUTER as u32,
        0,
    )?;
    let owner = SharedOwnedSetupMapping::new(first);
    owner.prepare_whole_intent_retention()?;
    owner.begin_whole_intent()?;
    owner.select_whole_bounded(7, 2)?;
    owner.with_selected(|selected| {
        selected.begin_paired_scope(
            7,
            1,
            123,
            SelectedRingAdmissionBudget {
                producer_attempts: 1,
                consumer_attempts: 1,
            },
        )
    })??;
    let frame = FrameEntry::new(11, 0, 52, b"published-before-native-getter-failure")?;
    owner.with_selected(|selected| {
        selected.with_paired_mapping(|mapping| {
            let pair = mapping.node_directed_ring_pair_mut(
                0,
                0,
                crate::SLOT_NET_ROUTER as u32,
                crate::SLOT_NET_ROUTER as u32,
                0,
            )?;
            pair.first.header.enqueue(pair.first.entries, &frame)?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    })???;
    let before = original.first.header.snapshot(original.first.entries)?;
    let outside = crate::RingHeader::new();
    let mut outside_entries: [FrameEntry; 2] = std::array::from_fn(|_| FrameEntry::default());

    // Simulate the actual provider error branch before it can call End.
    // The mandatory C refusal callback invokes this same local cancellation.
    owner.refuse_whole_control();
    outside.enqueue(&mut outside_entries, &frame)?;
    assert_eq!(
        outside
            .dequeue(&outside_entries)?
            .ok_or("outside frame absent")?
            .seq,
        52
    );
    assert!(
        owner
            .with_selected(|selected| selected.end_paired_scope(7, 1, 123))
            .is_err()
    );
    let cell = owner.generation()?.cell.as_ref().map_err(|error| *error)?;
    assert!(!cell.lease_alive.load(Ordering::Acquire));
    assert_eq!(cell.next_sequence.load(Ordering::Acquire), 1);
    assert!(
        cell.active_scope
            .lock()
            .expect("original active scope journal")
            .is_some()
    );
    assert!(
        cell.pending_completion
            .lock()
            .expect("original completion journal")
            .is_none()
    );
    assert_eq!(
        original.first.header.snapshot(original.first.entries)?,
        before
    );
    assert!(original.first.header.producer_barrier_snapshot().held());
    assert!(original.first.header.consumer_barrier_snapshot().held());
    Ok(())
}

#[test]
fn foreign_pid_cancellation_avoids_absent_headers_and_inherited_control_mutexes() -> TestResult {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored", "--exact",
            "mapped_setup_region::selected_lifecycle::shared_owned_setup::tests::intent_cancel::foreign_pid_cancellation_fixture",
            "--test-threads=1",
        ])
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
#[ignore = "runs alone with absent child mapping and inherited live scope/control locks"]
fn foreign_pid_cancellation_fixture() -> TestResult {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::Duration;

    let (_file, first, alias) = original_aliases()?;
    first.exclude_from_hot_fork_child()?;
    first.hold_hot_fork_ring_io()?;
    let owner = Arc::new(SharedOwnedSetupMapping::new(first));
    owner.prepare_whole_intent_retention()?;
    owner.begin_whole_intent()?;
    owner.select_whole_bounded(7, 1)?;
    let outside = crate::RingHeader::new();
    let mut outside_entries: [FrameEntry; 2] = std::array::from_fn(|_| FrameEntry::default());
    let frame = FrameEntry::new(11, 0, 52, b"ordinary-child-after-exact-cancellation")?;
    outside.enqueue(&mut outside_entries, &frame)?;
    owner.with_selected(|selected| {
        selected.begin_paired_scope(
            7,
            1,
            123,
            SelectedRingAdmissionBudget {
                producer_attempts: 0,
                consumer_attempts: 0,
            },
        )
    })??;
    let worker_owner = Arc::clone(&owner);
    let (locked_tx, locked_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let generation = worker_owner.generation().expect("actual parent generation");
        let _owner = generation.owner.lock().expect("actual shared owner mutex");
        let _domain = generation
            .domain
            .as_ref()
            .expect("original domain")
            .selection
            .lock()
            .expect("actual backing mutex");
        let _cell = generation
            .cell
            .as_ref()
            .expect("original cell")
            .selection
            .lock()
            .expect("actual cell mutex");
        let _registry = crate::mapped_setup_region::selected_lifecycle::registry()
            .lock()
            .expect("actual registry mutex");
        locked_tx.send(()).expect("report inherited control locks");
        release_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("release parent control locks");
    });
    locked_rx.recv_timeout(Duration::from_secs(2))?;
    let (mut parent_socket, mut child_socket) = UnixStream::pair()?;
    parent_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    child_socket.set_write_timeout(Some(Duration::from_secs(2)))?;

    // SAFETY: this isolated fixture owns the child lifetime. The source VMA
    // is absent and parent locks belong to a different vanished child thread.
    let child = unsafe { libc::fork() };
    if child < 0 {
        release_tx.send(())?;
        worker
            .join()
            .map_err(|_| "parent control worker panicked")?;
        return Err(std::io::Error::last_os_error().into());
    }
    if child == 0 {
        drop(parent_socket);
        let result = (|| -> TestResult {
            owner.refuse_whole_control();
            assert!(matches!(
                owner.with_selected(|selected| selected.end_paired_scope(7, 1, 123)),
                Err(WholeMappingCustodyError::Unregistered)
            ));
            assert_eq!(
                outside
                    .dequeue(&outside_entries)?
                    .ok_or("copied outside frame absent")?
                    .seq,
                52
            );
            child_socket.write_all(&[1])?;
            Ok(())
        })();
        // SAFETY: copied parent actors and guards must not run destructors.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
    }

    drop(child_socket);
    release_tx.send(())?;
    worker
        .join()
        .map_err(|_| "parent control worker panicked")?;
    let mut response = [0];
    let completion = parent_socket.read_exact(&mut response);
    if completion.is_err() {
        // SAFETY: the fixture owns this exact child PID and reaps on timeout.
        unsafe { libc::kill(child, libc::SIGKILL) };
    }
    let mut status = 0;
    // SAFETY: status is writable and child is this fixture's exact owned PID.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    completion?;
    assert_eq!(response, [1]);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    owner.with_selected(|selected| selected.end_paired_scope(7, 1, 123))??;
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
fn original_retention_budget_and_intent_handoff_run_in_isolation() -> TestResult {
    for fixture in [
        "retention_budget_before_native_hold_fixture",
        "pre_epoch_retention_handoff_fixture",
    ] {
        let name = format!(
            "mapped_setup_region::selected_lifecycle::shared_owned_setup::tests::intent_cancel::{fixture}"
        );
        assert!(
            std::process::Command::new(std::env::current_exe()?)
                .args(["--ignored", "--exact", &name, "--test-threads=1"])
                .status()?
                .success()
        );
    }
    Ok(())
}

#[test]
#[ignore = "owns the complete process retention budget before any source HOLD"]
fn retention_budget_before_native_hold_fixture() -> TestResult {
    use crate::mapped_setup_region::selected_lifecycle::{
        MAX_RETAINED_MAPPINGS, RetentionSlot, quarantine, registry,
    };
    let (_file, first, alias) = original_aliases()?;
    let address = first.mapping_start();
    let owner = SharedOwnedSetupMapping::new(first);
    let before = owner.mapping()?.hot_fork_ring_io_snapshot()?;
    let mut tickets = Vec::new();
    for _ in 0..MAX_RETAINED_MAPPINGS {
        let ticket = Arc::new(RetentionSlot::default());
        ticket.reserve()?;
        tickets.push(ticket);
    }

    assert_eq!(
        owner.prepare_whole_intent_retention(),
        Err(WholeMappingCustodyError::ResourceLimit)
    );
    let generation = owner.generation()?;
    assert!(!generation.intent.load(Ordering::Acquire));
    assert!(
        !generation
            .domain
            .as_ref()
            .map_err(|e| *e)?
            .selected
            .load(Ordering::Acquire)
    );
    assert_eq!(owner.mapping()?.hot_fork_ring_io_snapshot()?, before);
    owner.refuse_whole_control();
    assert!(!generation.intent.load(Ordering::Acquire));
    assert!(owner.begin_whole_intent().is_err());
    assert_eq!(quarantine().lock().unwrap().reserved, MAX_RETAINED_MAPPINGS);

    drop(owner);
    assert!(!registry().lock().unwrap().mappings.contains_key(&address));
    let present = std::fs::read_to_string("/proc/self/maps")?
        .lines()
        .any(|line| {
            let Some(span) = line.split_whitespace().next() else {
                return false;
            };
            let Some((start, end)) = span.split_once('-') else {
                return false;
            };
            let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            ) else {
                return false;
            };
            start <= address && address < end
        });
    assert!(!present);
    drop(tickets);
    assert_eq!(quarantine().lock().unwrap().reserved, 0);
    assert!(!alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
#[ignore = "proves exact Arc transfer and reservation reuse in a private process"]
fn pre_epoch_retention_handoff_fixture() -> TestResult {
    use crate::mapped_setup_region::selected_lifecycle::quarantine;
    let (_file, first, alias) = original_aliases()?;
    let address = first.mapping_start();
    let owner = SharedOwnedSetupMapping::new(first);
    owner.prepare_whole_intent_retention()?;
    assert_eq!(quarantine().lock().unwrap().reserved, 1);
    owner.mapping()?.hold_hot_fork_ring_io()?;
    owner.begin_whole_intent()?;
    owner.refuse_whole_control();

    drop(owner);
    {
        let store = quarantine().lock().unwrap();
        assert_eq!(store.reserved, 0);
        assert_eq!(store.owners.len(), 1);
        assert_eq!(store.owners[0].mapping_start(), address);
        assert_eq!(Arc::strong_count(&store.owners[0]), 1);
        assert!(store.owners[0].hot_fork_ring_io_snapshot()?.quiescent());
    }
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    let (_other_file, second, _second_alias) = original_aliases()?;
    let selected = SharedOwnedSetupMapping::new(second);
    selected.prepare_whole_intent_retention()?;
    selected.mapping()?.hold_hot_fork_ring_io()?;
    selected.begin_whole_intent()?;
    selected.select_whole_bounded(7, 1)?;
    assert_eq!(quarantine().lock().unwrap().reserved, 1);

    drop(selected);
    let store = quarantine().lock().unwrap();
    assert_eq!(store.reserved, 0);
    assert_eq!(store.owners.len(), 2);
    Ok(())
}
