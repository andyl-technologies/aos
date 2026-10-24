//! Actual memfd aliases and process-local selected lifecycle controls.

// crucible-lint: allow panic-shortcut -- Lifecycle test assertions deliberately panic on failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs::File;
use std::io::Write;
use std::os::fd::AsFd;
use std::sync::mpsc;
use std::time::Duration;

use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};

use super::*;
use crate::{RegionAllocation, RegionConfig, mmap_setup_region};

type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) fn original_aliases()
-> Result<(File, MappedSetupRegion, MappedSetupRegion), Box<dyn std::error::Error>> {
    let allocation = RegionAllocation::new(RegionConfig::new(2, 2))?;
    let bytes = allocation.setup_region_bytes()?;
    let mut file = File::from(memfd_create(
        "whole-mapping-lifecycle-test",
        MemfdFlags::ALLOW_SEALING,
    )?);
    file.set_len(allocation.layout().region_size)?;
    file.write_all(&bytes)?;
    fcntl_add_seals(&file, SealFlags::SHRINK | SealFlags::SEAL)?;

    let first = mmap_setup_region(file.as_fd(), allocation.layout().region_size)?;
    let second = mmap_setup_region(file.as_fd(), allocation.layout().region_size)?;
    Ok((file, first, second))
}

#[test]
fn ordinary_alias_keeps_original_reversible_release() -> TestResult {
    let (_file, first, second) = original_aliases()?;
    assert!(first.hold_hot_fork_ring_io()?.quiescent());

    let released = second.release_hot_fork_ring_io()?;

    assert_eq!(released.held_rings(), 0);
    assert_eq!(first.hot_fork_ring_io_snapshot()?, released);
    Ok(())
}

#[test]
fn selection_fences_existing_raw_headers_and_future_mappings() -> TestResult {
    let (file, first, mut second) = original_aliases()?;
    assert!(first.hold_hot_fork_ring_io()?.quiescent());
    let before = first.hot_fork_ring_io_snapshot()?;
    let region_len = first.region_len();
    {
        let pair = second.node_directed_ring_pair_mut(
            0,
            0,
            crate::SLOT_NET_ROUTER as u32,
            crate::SLOT_NET_ROUTER as u32,
            0,
        )?;
        let snapshot = pair.first.header.snapshot(pair.first.entries)?;

        let retained = first.retain_whole_mapping(7);
        retained.selection_status()?;
        assert!(pair.first.header.release_hot_fork_producers().held());
        assert!(pair.first.header.release_hot_fork_consumers().held());
        assert!(
            pair.first
                .header
                .restore(pair.first.entries, &snapshot)
                .is_err()
        );
    }

    assert!(second.release_hot_fork_ring_io().is_err());
    assert!(second.restore_hot_fork_parent_inheritance().is_err());
    assert!(matches!(
        mmap_setup_region(file.as_fd(), region_len),
        Err(SetupRegionMapError::WholeCustody { .. })
    ));
    assert_eq!(second.hot_fork_ring_io_snapshot()?, before);
    Ok(())
}

#[test]
fn foreign_epoch_keeps_original_epoch_and_sticky_uncertainty() -> TestResult {
    let (_file, first, second) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut retained = first.retain_whole_mapping(7);
    retained.selection_status()?;
    let mut called = false;

    assert!(
        retained
            .with_selected_scope(8, |_| {
                called = true;
                Ok::<_, ()>(())
            })
            .is_err()
    );

    assert!(!called);
    assert_eq!(retained.epoch(), 7);
    assert!(retained.selection_status().is_err());
    assert!(
        retained
            .with_selected_scope(7, |_| Ok::<_, ()>(()))
            .is_err()
    );
    assert!(second.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
fn service_error_retains_same_original_without_ordinary_release() -> TestResult {
    let (_file, first, second) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut retained = first.retain_whole_mapping(7);

    assert_eq!(
        retained.with_selected_scope(7, |_| Err::<(), _>("partial-service"))?,
        Err("partial-service")
    );

    assert!(retained.selection_status().is_err());
    assert!(second.release_hot_fork_ring_io().is_err());
    assert!(second.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
fn concurrent_release_cannot_cross_the_same_selected_service_loan() -> TestResult {
    let (_file, first, second) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let before = first.hot_fork_ring_io_snapshot()?;
    let mut retained = first.retain_whole_mapping(7);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (finish_tx, finish_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let result = retained.with_selected_scope(7, |_| {
            entered_tx.send(())?;
            finish_rx.recv_timeout(Duration::from_secs(2))?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        assert!(matches!(result, Ok(Ok(()))));
        retained
    });
    entered_rx.recv_timeout(Duration::from_secs(2))?;

    assert!(second.release_hot_fork_ring_io().is_err());
    assert!(second.restore_hot_fork_parent_inheritance().is_err());
    assert_eq!(second.hot_fork_ring_io_snapshot()?, before);

    finish_tx.send(())?;
    let retained = worker
        .join()
        .map_err(|_| std::io::Error::other("selected service worker panicked"))?;
    assert!(retained.selection_status().is_err());
    assert_eq!(second.hot_fork_ring_io_snapshot()?, before);
    Ok(())
}

#[test]
fn growing_same_backing_cannot_evade_selected_mapping_domain() -> TestResult {
    let (file, first, second) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let length = first.region_len();
    let retained = first.retain_whole_mapping(7);
    retained.selection_status()?;

    file.set_len(length + 4096)?;

    assert!(matches!(
        mmap_setup_region(file.as_fd(), length),
        Err(SetupRegionMapError::WholeCustody { .. })
    ));
    assert!(second.release_hot_fork_ring_io().is_err());
    assert!(second.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
fn invalid_epoch_selection_still_fences_ordinary_release() -> TestResult {
    let (_file, first, second) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;

    let retained = first.retain_whole_mapping(0);

    assert_eq!(
        retained.selection_status(),
        Err(WholeMappingCustodyError::ZeroEpoch)
    );
    assert!(second.release_hot_fork_ring_io().is_err());
    assert!(second.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

thread_local! {
    static AFTER_ADMISSION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

pub(super) fn after_map_admission() {
    let hook = AFTER_ADMISSION.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[test]
fn pending_mapper_keeps_domain_across_last_alias_drop() -> TestResult {
    let (file, first, second) = original_aliases()?;
    let length = first.region_len();
    drop(second);
    let worker_file = file.try_clone()?;
    let (admitted_tx, admitted_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        AFTER_ADMISSION.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                admitted_tx.send(()).expect("report pending admission");
                resume_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("resume original pending mapper");
            }));
        });
        mmap_setup_region(worker_file.as_fd(), length)
    });
    admitted_rx.recv_timeout(Duration::from_secs(2))?;

    drop(first);
    let replacement = mmap_setup_region(file.as_fd(), length)?;
    replacement.hold_hot_fork_ring_io()?;
    let retained = replacement.retain_whole_mapping(7);
    retained.selection_status()?;
    resume_tx.send(())?;

    let result = worker
        .join()
        .map_err(|_| std::io::Error::other("pending mapper panicked"))?;
    assert!(matches!(
        result,
        Err(SetupRegionMapError::WholeCustody {
            source: WholeMappingCustodyError::Selected,
        })
    ));
    assert!(
        retained
            .mapping()
            .ok_or("missing selected owner")?
            .hot_fork_ring_io_snapshot()?
            .quiescent()
    );
    Ok(())
}

#[test]
fn address_publication_waits_for_authenticated_unmap_record() -> TestResult {
    let (_original_file, first, unused_alias) = original_aliases()?;
    drop(unused_alias);
    let (_replacement_file, second, unused_replacement) = original_aliases()?;
    drop(unused_replacement);
    let address = first.mapping_start();
    let replacement_identity = second.backing_identity;
    let replacement_domain =
        domain_at(second.mapping_start())?.ok_or("replacement domain absent")?;
    let (begin_tx, begin_rx) = mpsc::sync_channel(1);
    let (blocked_tx, blocked_rx) = mpsc::sync_channel(1);
    let (published_tx, published_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        begin_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("start after authentic unmap fence acquired");
        assert!(matches!(
            registry().try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        blocked_tx
            .send(())
            .expect("report observed registry exclusion");

        let mut records = locked_registry().expect("publication registry");
        // This synthetic publication targets the exact reused address. It
        // models the post-mmap registration boundary, not a new kernel VMA.
        let replacement = records
            .mappings
            .remove(&second.mapping_start())
            .expect("actual replacement mapping record");
        records.mappings.insert(address, replacement);
        published_tx.send(()).expect("report completed publication");
        std::mem::forget(second);
    });

    unmap_ordinary(&first, || {
        begin_tx.send(()).expect("start blocked publisher");
        blocked_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("publisher observed actual registry exclusion");
        // No syscall is made in this registry-order control. The callback
        // acknowledges removal under the original registry fence; real
        // munmap remains exclusively in the authentic mapped owner Drop.
        true
    })?;
    published_rx.recv_timeout(Duration::from_secs(2))?;
    worker
        .join()
        .map_err(|_| std::io::Error::other("publication worker panicked"))?;

    {
        let records = locked_registry()?;
        let replacement = records
            .mappings
            .get(&address)
            .ok_or("replacement registration was deleted")?;
        assert_eq!(replacement.identity, replacement_identity);
        assert!(Arc::ptr_eq(&replacement.domain, &replacement_domain));
    }
    // The test transferred registry records, not kernel ownership. Preserve
    // both original VMAs instead of claiming a synthetic physical teardown.
    std::mem::forget(first);
    Ok(())
}

#[test]
fn actual_selected_ring_service_keeps_held_and_requires_paired_retirement() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut retained = first.retain_whole_mapping(7);
    let budget = SelectedRingAdmissionBudget {
        producer_attempts: 1,
        consumer_attempts: 1,
    };
    let frame = crate::FrameEntry::new(11, 0, 1, b"original-payload")?;

    let (delivered, completion) =
        retained.with_paired_selected_scope(7, 1, 123, budget, |mapping| {
            let pair = mapping.node_directed_ring_pair_mut(
                0,
                0,
                crate::SLOT_NET_ROUTER as u32,
                crate::SLOT_NET_ROUTER as u32,
                0,
            )?;
            assert!(pair.first.header.producer_barrier_snapshot().held());
            assert!(pair.first.header.consumer_barrier_snapshot().held());
            pair.first.header.enqueue(pair.first.entries, &frame)?;
            let delivered = pair.first.header.dequeue(pair.first.entries)?;
            assert!(pair.first.header.producer_barrier_snapshot().quiescent());
            assert!(pair.first.header.consumer_barrier_snapshot().quiescent());
            Ok::<_, Box<dyn std::error::Error>>(delivered)
        })??;

    let delivered = delivered.ok_or_else(|| std::io::Error::other("original frame missing"))?;
    assert_eq!(delivered.seq, frame.seq);
    assert_eq!(
        &delivered.data[..usize::from(delivered.len)],
        b"original-payload"
    );
    assert_eq!(completion.producer_attempts(), 1);
    assert_eq!(completion.consumer_attempts(), 1);
    assert!(retained.selection_status().is_err());
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());

    // This call exercises local balance only. No native stopped cut, complete
    // request/result/ACK or eligibility is modeled as source-issued evidence.
    retained.retire_paired_scope(7, 1, 123, completion)?;
    retained.selection_status()?;
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn selected_attempt_exhaustion_retains_original_publication_and_unknown() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut retained = first.retain_whole_mapping(7);
    let frame = crate::FrameEntry::new(11, 0, 1, b"retained-on-refusal")?;

    let result = retained.with_paired_selected_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 1,
            consumer_attempts: 0,
        },
        |mapping| {
            let pair = mapping.node_directed_ring_pair_mut(
                0,
                0,
                crate::SLOT_NET_ROUTER as u32,
                crate::SLOT_NET_ROUTER as u32,
                0,
            )?;
            pair.first.header.enqueue(pair.first.entries, &frame)?;
            assert!(
                pair.first
                    .header
                    .enqueue(pair.first.entries, &frame)
                    .is_err()
            );
            assert_eq!(pair.first.header.live_len(pair.first.entries)?, 1);
            Ok::<_, Box<dyn std::error::Error>>(())
        },
    );

    assert!(result.is_err());
    assert!(retained.selection_status().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn foreign_mapping_cannot_retire_original_paired_completion() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    let (_foreign_file, foreign, foreign_alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    foreign.hold_hot_fork_ring_io()?;
    let mut original = first.retain_whole_mapping(7);
    let mut foreign = foreign.retain_whole_mapping(7);
    let (_, completion) = original.with_paired_selected_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 0,
            consumer_attempts: 0,
        },
        |_| Ok::<_, std::io::Error>(()),
    )??;

    assert!(foreign.retire_paired_scope(7, 1, 123, completion).is_err());
    assert!(original.selection_status().is_err());
    assert!(foreign.selection_status().is_err());
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(foreign_alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn sixteen_actual_paired_loans_keep_world_held_without_history_reset() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut retained = first.retain_whole_mapping(7);
    let budget = SelectedRingAdmissionBudget {
        producer_attempts: 1,
        consumer_attempts: 1,
    };

    for sequence in 1..=16_u64 {
        let frame = crate::FrameEntry::new(11, 0, sequence as u32, b"same-world")?;
        let (_, completion) = retained.with_paired_selected_scope(
            7,
            sequence,
            sequence as usize,
            budget,
            |mapping| {
                let pair = mapping.node_directed_ring_pair_mut(
                    0,
                    0,
                    crate::SLOT_NET_ROUTER as u32,
                    crate::SLOT_NET_ROUTER as u32,
                    0,
                )?;
                pair.first.header.enqueue(pair.first.entries, &frame)?;
                let received = pair
                    .first
                    .header
                    .dequeue(pair.first.entries)?
                    .ok_or_else(|| std::io::Error::other("same-world frame missing"))?;
                assert_eq!(u64::from(received.seq), sequence);
                Ok::<_, Box<dyn std::error::Error>>(())
            },
        )??;
        retained.retire_paired_scope(7, sequence, sequence as usize, completion)?;
        assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
        assert!(alias.release_hot_fork_ring_io().is_err());
    }

    assert!(
        retained
            .with_paired_selected_scope(7, 17, 17, budget, |_| Ok::<_, std::io::Error>(()),)
            .is_err()
    );
    assert!(retained.selection_status().is_err());
    Ok(())
}

#[test]
fn selected_scope_refuses_foreign_open_memfd_ring_before_publication() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    let (_foreign_file, mut foreign, _foreign_alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut retained = first.retain_whole_mapping(7);
    let frame = crate::FrameEntry::new(11, 0, 1, b"foreign-original")?;
    let pair = foreign.node_directed_ring_pair_mut(
        0,
        0,
        crate::SLOT_NET_ROUTER as u32,
        crate::SLOT_NET_ROUTER as u32,
        0,
    )?;
    pair.first.header.enqueue(pair.first.entries, &frame)?;
    let before = pair.first.header.snapshot(pair.first.entries)?;

    let result = retained.with_paired_selected_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 0,
            consumer_attempts: 0,
        },
        |_| {
            assert!(
                pair.first
                    .header
                    .enqueue(pair.first.entries, &frame)
                    .is_err()
            );
            assert!(pair.first.header.dequeue(pair.first.entries).is_err());
            assert_eq!(pair.first.header.snapshot(pair.first.entries)?, before);
            Ok::<_, Box<dyn std::error::Error>>(())
        },
    );

    assert!(result.is_err());
    assert_eq!(pair.first.header.snapshot(pair.first.entries)?, before);
    assert_eq!(pair.first.header.live_len(pair.first.entries)?, 1);
    assert!(retained.selection_status().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn selected_scope_refuses_standalone_header_before_publication() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut retained = first.retain_whole_mapping(7);
    let header = crate::RingHeader::new();
    let mut entries: [crate::FrameEntry; 2] = std::array::from_fn(|_| crate::FrameEntry::default());
    let frame = crate::FrameEntry::new(11, 0, 1, b"standalone-original")?;
    header.enqueue(&mut entries, &frame)?;
    let before = header.snapshot(&entries)?;

    let result = retained.with_paired_selected_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 0,
            consumer_attempts: 0,
        },
        |_| {
            assert!(header.enqueue(&mut entries, &frame).is_err());
            assert!(header.dequeue(&entries).is_err());
            assert_eq!(header.snapshot(&entries)?, before);
            Ok::<_, Box<dyn std::error::Error>>(())
        },
    );

    assert!(result.is_err());
    assert_eq!(header.snapshot(&entries)?, before);
    assert_eq!(header.live_len(&entries)?, 1);
    assert!(retained.selection_status().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn selected_header_missing_held_refuses_before_publication() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut retained = first.retain_whole_mapping(7);
    let frame = crate::FrameEntry::new(11, 0, 1, b"must-not-publish")?;

    let result = retained.with_paired_selected_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 1,
            consumer_attempts: 1,
        },
        |mapping| {
            let pair = mapping.node_directed_ring_pair_mut(
                0,
                0,
                crate::SLOT_NET_ROUTER as u32,
                crate::SLOT_NET_ROUTER as u32,
                0,
            )?;
            let before = pair.first.header.snapshot(pair.first.entries)?;
            // This deliberately uses the private mutation primitive to model
            // a corrupted HELD state; ordinary aliases cannot release it.
            assert!(
                !pair
                    .first
                    .header
                    .release_hot_fork_producers_with_mapping_loan()
                    .held()
            );
            assert!(
                !pair
                    .first
                    .header
                    .release_hot_fork_consumers_with_mapping_loan()
                    .held()
            );
            assert!(
                pair.first
                    .header
                    .enqueue(pair.first.entries, &frame)
                    .is_err()
            );
            assert!(pair.first.header.dequeue(pair.first.entries).is_err());
            assert_eq!(pair.first.header.snapshot(pair.first.entries)?, before);
            Ok::<_, Box<dyn std::error::Error>>(())
        },
    );

    assert!(result.is_err());
    assert!(retained.selection_status().is_err());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn constructor_capacity_advances_exactly_its_finite_selected_slots() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut owner = OwnedSetupMapping::new(first);
    owner.select_whole_bounded(7, 2)?;
    let selected = owner.selected_mut()?;

    for sequence in 1..=2 {
        let (_, completion) = selected.with_paired_selected_scope(
            7,
            sequence,
            sequence as usize,
            SelectedRingAdmissionBudget {
                producer_attempts: 0,
                consumer_attempts: 0,
            },
            |_| Ok::<_, std::io::Error>(()),
        )??;
        selected.retire_paired_scope(7, sequence, sequence as usize, completion)?;
    }

    let mut called = false;
    assert!(
        selected
            .with_paired_selected_scope(
                7,
                3,
                3,
                SelectedRingAdmissionBudget {
                    producer_attempts: 0,
                    consumer_attempts: 0
                },
                |_| {
                    called = true;
                    Ok::<_, std::io::Error>(())
                },
            )
            .is_err()
    );
    assert!(!called);
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn invalid_constructor_capacity_retains_selected_original() -> TestResult {
    for capacity in [0, 65_537] {
        let (_file, first, alias) = original_aliases()?;
        first.hold_hot_fork_ring_io()?;
        let mut owner = OwnedSetupMapping::new(first);

        assert_eq!(
            owner.select_whole_bounded(7, capacity),
            Err(WholeMappingCustodyError::ResourceLimit)
        );
        assert!(owner.ordinary_mapping_mut().is_err());
        assert!(alias.release_hot_fork_ring_io().is_err());
        assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    }
    Ok(())
}

#[test]
fn selected_admission_losing_held_during_cas_retry_preserves_original_ring() -> TestResult {
    for producer in [true, false] {
        let (_file, first, alias) = original_aliases()?;
        first.hold_hot_fork_ring_io()?;
        let mut retained = first.retain_whole_mapping(7);
        let result = retained.with_paired_selected_scope(
            7,
            1,
            123,
            SelectedRingAdmissionBudget {
                producer_attempts: 1,
                consumer_attempts: 1,
            },
            |mapping| {
                let pair = mapping.node_directed_ring_pair_mut(
                    0,
                    0,
                    crate::SLOT_NET_ROUTER as u32,
                    crate::SLOT_NET_ROUTER as u32,
                    0,
                )?;
                let before = pair.first.header.snapshot(pair.first.entries)?;
                let admitted = if producer {
                    pair.first
                        .header
                        .enter_producer_with_test_hook(|| {
                            pair.first
                                .header
                                .release_hot_fork_producers_with_mapping_loan();
                        })
                        .is_some()
                } else {
                    pair.first
                        .header
                        .enter_consumer_with_test_hook(|| {
                            pair.first
                                .header
                                .release_hot_fork_consumers_with_mapping_loan();
                        })
                        .is_some()
                };
                assert!(!admitted);
                assert_eq!(pair.first.header.snapshot(pair.first.entries)?, before);
                Ok::<_, Box<dyn std::error::Error>>(())
            },
        );

        assert!(result.is_err());
        assert!(retained.selection_status().is_err());
        assert!(alias.release_hot_fork_ring_io().is_err());
    }
    Ok(())
}

#[test]
fn selected_view_construction_requires_current_exact_mapping_permit() -> TestResult {
    let (_file, first, mut alias) = original_aliases()?;
    let (_foreign_file, mut foreign, _foreign_alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut selected = first.retain_whole_mapping(7);

    assert!(matches!(
        alias.node_directed_ring_pair_mut(
            0,
            0,
            crate::SLOT_NET_ROUTER as u32,
            crate::SLOT_NET_ROUTER as u32,
            0
        ),
        Err(super::super::MappedSetupRegionAccessError::WholeCustody { .. })
    ));
    let result = selected.with_paired_selected_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 0,
            consumer_attempts: 0,
        },
        |mapping| {
            assert!(
                mapping
                    .node_directed_ring_pair_mut(
                        0,
                        0,
                        crate::SLOT_NET_ROUTER as u32,
                        crate::SLOT_NET_ROUTER as u32,
                        0
                    )
                    .is_ok()
            );
            assert!(matches!(
                foreign.node_directed_ring_pair_mut(
                    0,
                    0,
                    crate::SLOT_NET_ROUTER as u32,
                    crate::SLOT_NET_ROUTER as u32,
                    0
                ),
                Err(super::super::MappedSetupRegionAccessError::WholeCustody { .. })
            ));
            Ok::<_, std::io::Error>(())
        },
    );
    assert!(result.is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[test]
fn changed_current_epoch_refuses_before_selected_ring_publication() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut retained = first.retain_whole_mapping(7);
    let cell = Arc::clone(retained.cell.as_ref().ok_or("selected cell absent")?);
    let frame = crate::FrameEntry::new(11, 0, 1, b"unchanged-epoch-data")?;
    let result = retained.with_paired_selected_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 1,
            consumer_attempts: 1,
        },
        |mapping| {
            let pair = mapping.node_directed_ring_pair_mut(
                0,
                0,
                crate::SLOT_NET_ROUTER as u32,
                crate::SLOT_NET_ROUTER as u32,
                0,
            )?;
            let before = pair.first.header.snapshot(pair.first.entries)?;
            cell.epoch.store(8, Ordering::Release);
            assert!(
                pair.first
                    .header
                    .enqueue(pair.first.entries, &frame)
                    .is_err()
            );
            assert!(pair.first.header.dequeue(pair.first.entries).is_err());
            assert_eq!(pair.first.header.snapshot(pair.first.entries)?, before);
            Ok::<_, Box<dyn std::error::Error>>(())
        },
    );

    assert!(result.is_err());
    assert!(retained.selection_status().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    Ok(())
}

#[path = "selected_lifecycle_process_tests.rs"]
mod process;

#[path = "selected_lifecycle_native_callback_tests.rs"]
mod native_callbacks;

#[path = "selected_lifecycle_fork_race_tests.rs"]
mod fork_races;

pub(super) fn before_unmap_domain_lock(address: usize) {
    fork_races::before_unmap_domain_lock(address);
}
