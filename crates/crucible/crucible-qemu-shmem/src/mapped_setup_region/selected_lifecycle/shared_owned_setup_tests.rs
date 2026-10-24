//! Same-field ownership through shared userdata and short guarded callbacks.

// crucible-lint: allow panic-shortcut -- Lifecycle test assertions deliberately panic on failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::tests::original_aliases;

type TestResult = Result<(), Box<dyn std::error::Error>>;
use super::*;
use crate::{FrameEntry, SelectedRingAdmissionBudget};
use std::os::fd::AsFd;

#[test]
fn shared_userdata_controls_preserve_one_original_mapping_allocation() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let owner = Arc::new(SharedOwnedSetupMapping::new(first));
    let address = owner.mapping()?.mapping_start();
    let allocation = std::ptr::from_ref::<MappedSetupRegion>(&*owner.mapping()?) as usize;
    let callback_owner = Arc::clone(&owner);

    owner.select_whole_bounded(7, 2)?;
    callback_owner.with_selected(|selected| {
        assert_eq!(Arc::strong_count(&selected.mapping), 1);
        assert_eq!(Arc::as_ptr(&selected.mapping) as usize, allocation);
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
    let frame = FrameEntry::new(11, 0, 42, b"shared-original-field")?;
    callback_owner.with_selected(|selected| {
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
    let received = callback_owner.with_selected(|selected| {
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
                .ok_or::<Box<dyn std::error::Error>>("original frame absent".into())
        })
    })???;
    let completion =
        callback_owner.with_selected(|selected| selected.end_paired_scope(7, 1, 123))??;

    assert_eq!(received.seq, 42);
    assert_eq!(
        &received.data[..usize::from(received.len)],
        b"shared-original-field"
    );
    assert_eq!(completion.producer_attempts(), 1);
    assert_eq!(completion.consumer_attempts(), 1);
    assert_eq!(owner.mapping()?.mapping_start(), address);
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    drop(completion);
    Ok(())
}

#[test]
fn read_guard_racing_adoption_publishes_sticky_selection_before_busy() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut owner = SharedOwnedSetupMapping::new(first);
    let address = owner.mapping()?.mapping_start();
    {
        let read = owner.mapping()?;
        assert_eq!(
            owner.select_whole_bounded(7, 2),
            Err(WholeMappingCustodyError::Busy)
        );
        assert_eq!(read.mapping_start(), address);
        assert!(alias.release_hot_fork_ring_io().is_err());
    }

    assert!(owner.ordinary_mapping_mut().is_err());
    assert!(owner.select_whole_bounded(7, 2).is_err());
    assert!(owner.with_selected(|_| Ok::<_, ()>(())).is_err());
    drop(owner);
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn retained_read_guard_refuses_mutable_callback_before_service() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let owner = SharedOwnedSetupMapping::new(first);
    owner.select_whole_bounded(7, 2)?;
    let read = owner.mapping()?;
    let mut called = false;

    assert_eq!(
        owner.with_selected(|_| {
            called = true;
            Ok::<_, ()>(())
        }),
        Err(WholeMappingCustodyError::Busy)
    );
    assert!(!called);
    assert!(read.hot_fork_ring_io_snapshot()?.quiescent());
    drop(read);
    assert!(owner.with_selected(|_| Ok::<_, ()>(())).is_err());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn shared_callback_error_revokes_the_original_native_permit() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let owner = SharedOwnedSetupMapping::new(first);
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

    assert_eq!(
        owner.with_selected(|_| Err::<(), _>("native callback failure"))?,
        Err("native callback failure")
    );
    assert!(
        owner
            .with_selected(|selected| selected.end_paired_scope(7, 1, 123))
            .is_err()
    );
    let ordinary = crate::RingHeader::new();
    let mut entries: [FrameEntry; 2] = std::array::from_fn(|_| FrameEntry::default());
    ordinary.enqueue(
        &mut entries,
        &FrameEntry::new(11, 0, 1, b"after-revoked-original-permit")?,
    )?;
    assert_eq!(ordinary.live_len(&entries)?, 1);
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn two_node_aliases_keep_independent_epochs_and_operation_cells() -> TestResult {
    let (file, first, second) = original_aliases()?;
    let size = first.region_len();
    first.hold_hot_fork_ring_io()?;
    let first_owner = SharedOwnedSetupMapping::new(first);
    let second_owner = SharedOwnedSetupMapping::new(second);
    first_owner.select_whole_bounded(7, 2)?;
    second_owner.select_whole_bounded(9, 2)?;

    let mut completions = Vec::new();
    for (owner, epoch, node, allocation) in [(&first_owner, 7, 0, 123), (&second_owner, 9, 1, 456)]
    {
        let frame = FrameEntry::new(11, node, allocation as u32, b"per-node-original-ring")?;
        owner.with_selected(|selected| {
            selected.begin_paired_scope(
                epoch,
                1,
                allocation,
                SelectedRingAdmissionBudget {
                    producer_attempts: 1,
                    consumer_attempts: 1,
                },
            )
        })??;
        owner.with_selected(|selected| {
            selected.with_paired_mapping(|mapping| {
                let pair = mapping.node_directed_ring_pair_mut(
                    node,
                    node,
                    crate::SLOT_NET_ROUTER as u32,
                    crate::SLOT_NET_ROUTER as u32,
                    0,
                )?;
                pair.first.header.enqueue(pair.first.entries, &frame)?;
                let actual = pair
                    .first
                    .header
                    .dequeue(pair.first.entries)?
                    .ok_or("original node frame absent")?;
                assert_eq!(actual.seq, allocation as u32);
                assert_eq!(
                    &actual.data[..usize::from(actual.len)],
                    b"per-node-original-ring"
                );
                Ok::<_, Box<dyn std::error::Error>>(())
            })
        })???;
        let completion =
            owner.with_selected(|selected| selected.end_paired_scope(epoch, 1, allocation))??;
        assert_eq!(completion.producer_attempts(), 1);
        assert_eq!(completion.consumer_attempts(), 1);
        completions.push((owner, epoch, allocation, completion));
    }

    assert!(
        first_owner
            .mapping()?
            .hot_fork_ring_io_snapshot()?
            .quiescent()
    );
    assert!(second_owner.mapping()?.release_hot_fork_ring_io().is_err());
    assert!(crate::mmap_setup_region(file.as_fd(), size).is_err());
    assert!(!Arc::ptr_eq(
        first_owner
            .generation()?
            .cell
            .as_ref()
            .map_err(|error| *error)?,
        second_owner
            .generation()?
            .cell
            .as_ref()
            .map_err(|error| *error)?
    ));
    assert!(Arc::ptr_eq(
        first_owner
            .generation()?
            .domain
            .as_ref()
            .map_err(|error| *error)?,
        second_owner
            .generation()?
            .domain
            .as_ref()
            .map_err(|error| *error)?
    ));

    // This checks only local token correlation. No native retirement is
    // inferred; production must join original native journals first.
    for (owner, epoch, allocation, completion) in completions {
        owner.with_selected(|selected| {
            selected.retire_paired_scope(epoch, 1, allocation, completion)
        })??;
        owner.with_selected(|selected| {
            selected.begin_paired_scope(
                epoch,
                2,
                allocation,
                SelectedRingAdmissionBudget {
                    producer_attempts: 0,
                    consumer_attempts: 0,
                },
            )
        })??;
        owner.with_selected(|selected| selected.end_paired_scope(epoch, 2, allocation))??;
    }
    Ok(())
}

#[test]
fn same_backing_foreign_completion_cannot_advance_another_node_cell() -> TestResult {
    let (_file, first, second) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut first = first.retain_whole_mapping(7);
    let mut second = second.retain_whole_mapping(7);
    first.selection_status()?;
    second.selection_status()?;
    let budget = SelectedRingAdmissionBudget {
        producer_attempts: 0,
        consumer_attempts: 0,
    };
    first.begin_paired_scope(7, 1, 123, budget)?;
    let foreign = first.end_paired_scope(7, 1, 123)?;
    second.begin_paired_scope(7, 1, 123, budget)?;
    let original = second.end_paired_scope(7, 1, 123)?;

    assert_eq!(
        second.retire_paired_scope(7, 1, 123, foreign),
        Err(WholeMappingCustodyError::Selected)
    );
    assert_eq!(
        second
            .cell
            .as_ref()
            .ok_or("second cell absent")?
            .next_sequence
            .load(Ordering::Acquire),
        1
    );
    assert_eq!(
        first
            .cell
            .as_ref()
            .ok_or("first cell absent")?
            .next_sequence
            .load(Ordering::Acquire),
        1
    );
    drop(original);
    assert!(
        first
            .mapping()
            .ok_or("first owner absent")?
            .hot_fork_ring_io_snapshot()?
            .quiescent()
    );
    Ok(())
}

#[test]
fn same_backing_mutable_alias_is_not_implicitly_enrolled_in_current_node_loan() -> TestResult {
    let (_file, first, mut second) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut retained = first.retain_whole_mapping(7);
    retained.begin_paired_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 1,
            consumer_attempts: 1,
        },
    )?;

    assert!(
        second
            .node_directed_ring_pair_mut(
                0,
                0,
                crate::SLOT_NET_ROUTER as u32,
                crate::SLOT_NET_ROUTER as u32,
                0,
            )
            .is_err()
    );
    assert!(retained.end_paired_scope(7, 1, 123).is_err());
    assert!(second.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
fn shared_child_userdata_rebinds_with_real_inherited_owner_and_registry_locks() -> TestResult {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored", "--exact",
            "mapped_setup_region::selected_lifecycle::shared_owned_setup::tests::shared_child_userdata_fixture",
            "--test-threads=1",
        ])
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
#[ignore = "runs alone with actual multithreaded fork and shared registered userdata"]
fn shared_child_userdata_fixture() -> TestResult {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::Duration;

    let (_source_file, original, source_alias) = original_aliases()?;
    let (destination_file, destination, destination_alias) = original_aliases()?;
    let expected = destination.backing_identity();
    original.exclude_from_hot_fork_child()?;
    destination.hold_hot_fork_ring_io()?;
    drop(source_alias);
    drop(destination);
    drop(destination_alias);
    let owner = Arc::new(SharedOwnedSetupMapping::new(original));
    let worker_owner = Arc::clone(&owner);
    let (locked_tx, locked_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _read_guard = worker_owner.mapping().expect("actual shared owner guard");
        let domain = worker_owner
            .generation()
            .expect("current parent generation")
            .domain
            .as_ref()
            .expect("original backing domain");
        let _domain_loan = domain
            .selection
            .lock()
            .expect("actual original domain loan");
        let _registry_loan = super::super::registry()
            .lock()
            .expect("actual parent registry loan");
        locked_tx.send(()).expect("report inherited locks");
        release_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("release parent loans");
    });
    locked_rx.recv_timeout(Duration::from_secs(2))?;
    let (mut parent_socket, mut child_socket) = UnixStream::pair()?;
    parent_socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    child_socket.set_write_timeout(Some(Duration::from_secs(2)))?;

    // SAFETY: this isolated control owns the fork lifetime. The child keeps
    // shared Arc userdata exactly as the GPL hook does; it never obtains &mut
    // from vanished threads or from an inherited Arc reference count.
    let child = unsafe { libc::fork() };
    if child < 0 {
        release_tx.send(())?;
        worker.join().map_err(|_| "parent guard worker panicked")?;
        return Err(std::io::Error::last_os_error().into());
    }
    if child == 0 {
        drop(parent_socket);
        let result = (|| -> TestResult {
            assert!(matches!(
                owner.mapping(),
                Err(WholeMappingCustodyError::Unregistered)
            ));
            let shared_userdata: &SharedOwnedSetupMapping = owner.as_ref();
            shared_userdata.install_hot_fork_child_mapping(destination_file.as_fd(), expected)?;
            let mapping = shared_userdata.mapping()?;
            assert_eq!(mapping.backing_identity(), expected);
            assert_eq!(mapping.mapping_process_id as u32, std::process::id());
            assert!(mapping.hot_fork_ring_io_snapshot()?.quiescent());
            drop(mapping);
            shared_userdata.select_whole_bounded(9, 1)?;
            shared_userdata.with_selected(|selected| {
                selected.begin_paired_scope(
                    9,
                    1,
                    456,
                    SelectedRingAdmissionBudget {
                        producer_attempts: 0,
                        consumer_attempts: 0,
                    },
                )
            })??;
            shared_userdata.with_selected(|selected| selected.end_paired_scope(9, 1, 456))??;
            child_socket.write_all(&[1])?;
            Ok(())
        })();
        // SAFETY: avoid copied parent actor destructors in this owned child.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
    }

    drop(child_socket);
    release_tx.send(())?;
    worker.join().map_err(|_| "parent guard worker panicked")?;
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
    assert_eq!(
        owner.mapping()?.backing_identity(),
        owner.generation()?.registration.owner.identity
    );
    Ok(())
}

#[test]
fn child_replacement_refuses_a_read_guard_in_the_actual_forking_thread() -> TestResult {
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored", "--exact",
            "mapped_setup_region::selected_lifecycle::shared_owned_setup::tests::calling_thread_guard_fixture",
            "--test-threads=1",
        ])
        .status()?;
    assert!(status.success());
    Ok(())
}

#[test]
#[ignore = "runs alone with actual fork and an original calling-thread read guard"]
fn calling_thread_guard_fixture() -> TestResult {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let (_source_file, original, source_alias) = original_aliases()?;
    let (destination_file, destination, destination_alias) = original_aliases()?;
    let expected = destination.backing_identity();
    original.exclude_from_hot_fork_child()?;
    drop(source_alias);
    drop(destination);
    drop(destination_alias);
    let owner = SharedOwnedSetupMapping::new(original);
    let guard = owner.mapping()?;
    let (mut parent_socket, mut child_socket) = UnixStream::pair()?;
    parent_socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    // SAFETY: this isolated fixture owns the child lifetime and deliberately
    // keeps the actual fork-calling thread's guard live across the fork.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if child == 0 {
        drop(parent_socket);
        let refusal = owner.install_hot_fork_child_mapping(destination_file.as_fd(), expected);
        let valid = matches!(
            refusal,
            Err(HotForkChildMappingInstallError::WholeCustody {
                source: WholeMappingCustodyError::Busy,
            })
        );
        let result = child_socket.write_all(&[u8::from(valid)]);
        // SAFETY: copied guard and parent owners must not run destructors.
        unsafe { libc::_exit(if valid && result.is_ok() { 0 } else { 1 }) };
    }

    drop(child_socket);
    drop(guard);
    let mut response = [0];
    let completion = parent_socket.read_exact(&mut response);
    if completion.is_err() {
        // SAFETY: the fixture owns the exact child PID and reaps on timeout.
        unsafe { libc::kill(child, libc::SIGKILL) };
    }
    let mut status = 0;
    // SAFETY: status is writable and child is this fixture's exact PID.
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    completion?;
    assert_eq!(response, [1]);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    Ok(())
}

fn directed_header_offsets(
    mapping: &mut MappedSetupRegion,
    node: u32,
) -> Result<[u64; 2], Box<dyn std::error::Error>> {
    let base = mapping.mapping_start();
    let pair = mapping.node_directed_ring_pair_mut(
        node,
        node,
        crate::SLOT_NET_ROUTER as u32,
        crate::SLOT_NET_ROUTER as u32,
        0,
    )?;
    Ok([
        (std::ptr::from_ref(pair.first.header) as usize - base) as u64,
        (std::ptr::from_ref(pair.second.header) as usize - base) as u64,
    ])
}

#[test]
fn exact_original_roster_allows_enrolled_ring_service_and_stays_held() -> TestResult {
    let (_file, mut first, alias) = original_aliases()?;
    let offsets = directed_header_offsets(&mut first, 0)?;
    first.hold_hot_fork_ring_io()?;
    let owner = SharedOwnedSetupMapping::new(first);
    owner.select_whole_roster_bounded(7, 1, &offsets)?;
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
    owner.with_selected(|selected| {
        selected.with_paired_mapping(|mapping| {
            let pair = mapping.node_directed_ring_pair_mut(
                0,
                0,
                crate::SLOT_NET_ROUTER as u32,
                crate::SLOT_NET_ROUTER as u32,
                0,
            )?;
            let frame = FrameEntry::new(11, 0, 42, b"exact-original-roster")?;
            pair.first.header.enqueue(pair.first.entries, &frame)?;
            let actual = pair
                .first
                .header
                .dequeue(pair.first.entries)?
                .ok_or("enrolled frame absent")?;
            assert_eq!(
                &actual.data[..usize::from(actual.len)],
                b"exact-original-roster"
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    })???;
    let completion = owner.with_selected(|selected| selected.end_paired_scope(7, 1, 123))??;
    assert_eq!(completion.producer_attempts(), 1);
    assert_eq!(completion.consumer_attempts(), 1);
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn unenrolled_direct_mutable_view_refuses_before_slice_or_ring_effects() -> TestResult {
    let (_file, mut first, mut alias) = original_aliases()?;
    let offsets = directed_header_offsets(&mut first, 0)?;
    let unchanged = alias.node_directed_ring_pair_mut(
        1,
        1,
        crate::SLOT_NET_ROUTER as u32,
        crate::SLOT_NET_ROUTER as u32,
        0,
    )?;
    let original = FrameEntry::new(11, 1, 52, b"unenrolled-original-data")?;
    unchanged
        .first
        .header
        .enqueue(unchanged.first.entries, &original)?;
    let before = unchanged.first.header.snapshot(unchanged.first.entries)?;
    first.hold_hot_fork_ring_io()?;
    let mut retained = first.retain_whole_mapping(7);
    retained.restrict_paired_header_offsets(&offsets)?;
    retained.begin_paired_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 1,
            consumer_attempts: 1,
        },
    )?;

    let refused = retained.with_paired_mapping(|mapping| {
        assert!(
            mapping
                .node_directed_ring_pair_mut(
                    1,
                    1,
                    crate::SLOT_NET_ROUTER as u32,
                    crate::SLOT_NET_ROUTER as u32,
                    0,
                )
                .is_err()
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    refused?;
    assert!(retained.end_paired_scope(7, 1, 123).is_err());
    assert_eq!(
        unchanged.first.header.snapshot(unchanged.first.entries)?,
        before
    );
    assert!(unchanged.first.header.producer_barrier_snapshot().held());
    assert!(unchanged.first.header.consumer_barrier_snapshot().held());
    Ok(())
}

#[test]
fn invalid_or_renewed_roster_retains_sticky_mapping_custody() -> TestResult {
    for invalid in [vec![1], vec![0], vec![]] {
        let (_file, first, alias) = original_aliases()?;
        first.hold_hot_fork_ring_io()?;
        let mut retained = first.retain_whole_mapping(7);
        assert!(retained.restrict_paired_header_offsets(&invalid).is_err());
        assert!(retained.selection_status().is_err());
        assert!(alias.release_hot_fork_ring_io().is_err());
    }
    let (_file, mut first, alias) = original_aliases()?;
    let offsets = directed_header_offsets(&mut first, 0)?;
    first.hold_hot_fork_ring_io()?;
    let mut retained = first.retain_whole_mapping(7);
    retained.restrict_paired_header_offsets(&offsets)?;
    assert!(retained.restrict_paired_header_offsets(&offsets).is_err());
    assert!(retained.selection_status().is_err());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn atomic_roster_adoption_refuses_invalid_input_without_ordinary_fallback() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let owner = SharedOwnedSetupMapping::new(first);

    assert!(owner.select_whole_roster_bounded(7, 1, &[1]).is_err());
    assert!(owner.select_whole_roster_bounded(7, 1, &[1]).is_err());
    assert!(
        owner
            .with_selected(|selected| selected.selection_status())
            .is_err()
    );
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
// crucible-lint: allow nondeterminism -- Bounded host-only watchdog; never simulation time.
#[allow(clippy::disallowed_methods)]
fn concurrent_refusal_during_adoption_cannot_return_successful_custody() -> TestResult {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let (_file, mut first, alias) = original_aliases()?;
    let offsets = directed_header_offsets(&mut first, 0)?;
    first.hold_hot_fork_ring_io()?;
    let owner = Arc::new(SharedOwnedSetupMapping::new(first));
    let selecting_owner = Arc::clone(&owner);
    let (outcome_tx, outcome_rx) = mpsc::sync_channel(1);
    let records = super::super::registry()
        .lock()
        .expect("actual registry publication loan");
    let worker = std::thread::spawn(move || {
        let result = selecting_owner.select_whole_roster_bounded(7, 1, &offsets);
        outcome_tx
            .send(result)
            .expect("report actual adoption result");
    });

    // The selector owns the actual mapping mutex while waiting for this real
    // registry loan. A competing callback must refuse the same original cell.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match owner.generation()?.owner.try_lock() {
            Err(std::sync::TryLockError::WouldBlock) => break,
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err("owner unexpectedly poisoned".into());
            }
            Ok(guard) => drop(guard),
        }
        if Instant::now() >= deadline {
            drop(records);
            worker.join().map_err(|_| "selector worker panicked")?;
            return Err("selector did not acquire actual original owner".into());
        }
        std::thread::yield_now();
    }
    assert_eq!(
        owner.with_selected(|selected| selected.selection_status()),
        Err(WholeMappingCustodyError::Busy)
    );
    drop(records);
    assert_eq!(
        outcome_rx.recv_timeout(Duration::from_secs(2))?,
        Err(WholeMappingCustodyError::Selected)
    );
    worker.join().map_err(|_| "selector worker panicked")?;
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[path = "intent_cancel_tests.rs"]
mod intent_cancel;
