//! Separate synchronous callbacks sharing one finite original ring loan.

use super::*;

#[test]
fn separate_native_callbacks_share_one_nonrenewing_ring_loan() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut original = first.retain_whole_mapping(7);
    let frame = crate::FrameEntry::new(11, 0, 42, b"actual-original-callback-frame")?;

    original.begin_paired_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 1,
            consumer_attempts: 1,
        },
    )?;
    original.with_paired_mapping(|mapping| {
        let pair = mapping.node_directed_ring_pair_mut(
            0,
            0,
            crate::SLOT_NET_ROUTER as u32,
            crate::SLOT_NET_ROUTER as u32,
            0,
        )?;
        pair.first.header.enqueue(pair.first.entries, &frame)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })??;

    let received = original.with_paired_mapping(|mapping| {
        let pair = mapping.node_directed_ring_pair_mut(
            0,
            0,
            crate::SLOT_NET_ROUTER as u32,
            crate::SLOT_NET_ROUTER as u32,
            0,
        )?;
        let frame = pair
            .first
            .header
            .dequeue(pair.first.entries)?
            .ok_or("original frame absent")?;
        assert_eq!(pair.first.header.live_len(pair.first.entries)?, 0);
        Ok::<_, Box<dyn std::error::Error>>(frame)
    })??;
    let completion = original.end_paired_scope(7, 1, 123)?;

    assert_eq!(received.seq, 42);
    assert_eq!(
        &received.data[..usize::from(received.len)],
        b"actual-original-callback-frame"
    );
    assert_eq!(completion.producer_attempts(), 1);
    assert_eq!(completion.consumer_attempts(), 1);
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    assert!(alias.release_hot_fork_ring_io().is_err());
    assert!(original.selection_status().is_err());
    // These are actual local callbacks, not native stopped or journal proof.
    drop(completion);
    Ok(())
}

#[test]
fn callback_credit_does_not_renew_at_the_next_native_callback() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut original = first.retain_whole_mapping(7);
    let frame = crate::FrameEntry::new(11, 0, 42, b"finite-original-credit")?;
    original.begin_paired_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 1,
            consumer_attempts: 0,
        },
    )?;
    original.with_paired_mapping(|mapping| {
        let pair = mapping.node_directed_ring_pair_mut(
            0,
            0,
            crate::SLOT_NET_ROUTER as u32,
            crate::SLOT_NET_ROUTER as u32,
            0,
        )?;
        pair.first.header.enqueue(pair.first.entries, &frame)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })??;
    original.with_paired_mapping(|mapping| {
        let pair = mapping.node_directed_ring_pair_mut(
            0,
            0,
            crate::SLOT_NET_ROUTER as u32,
            crate::SLOT_NET_ROUTER as u32,
            0,
        )?;
        let before = pair.first.header.snapshot(pair.first.entries)?;
        assert!(
            pair.first
                .header
                .enqueue(pair.first.entries, &frame)
                .is_err()
        );
        assert_eq!(pair.first.header.snapshot(pair.first.entries)?, before);
        assert_eq!(pair.first.header.live_len(pair.first.entries)?, 1);
        Ok::<_, Box<dyn std::error::Error>>(())
    })??;

    assert!(original.end_paired_scope(7, 1, 123).is_err());
    assert!(original.selection_status().is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn callback_error_and_unwind_refuse_further_native_callback_borrows() -> TestResult {
    for panic in [false, true] {
        let (_file, first, alias) = original_aliases()?;
        first.hold_hot_fork_ring_io()?;
        let mut original = first.retain_whole_mapping(7);
        original.begin_paired_scope(
            7,
            1,
            123,
            SelectedRingAdmissionBudget {
                producer_attempts: 1,
                consumer_attempts: 1,
            },
        )?;
        if panic {
            let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = original
                    .with_paired_mapping::<(), ()>(|_| panic!("native callback unwind control"));
            }));
            assert!(unwind.is_err());
        } else {
            assert_eq!(
                original.with_paired_mapping(|_| Err::<(), _>("partial-native-callback"))?,
                Err("partial-native-callback")
            );
        }

        let mut called = false;
        assert!(
            original
                .with_paired_mapping(|_| {
                    called = true;
                    Ok::<_, ()>(())
                })
                .is_err()
        );
        assert!(!called);
        assert!(original.end_paired_scope(7, 1, 123).is_err());
        assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
        assert!(alias.release_hot_fork_ring_io().is_err());
    }
    Ok(())
}

#[test]
fn foreign_thread_callback_refusal_invalidates_original_thread_loan() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut original = first.retain_whole_mapping(7);
    original.begin_paired_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 1,
            consumer_attempts: 1,
        },
    )?;
    let worker = std::thread::spawn(move || {
        let mut called = false;
        assert!(
            original
                .with_paired_mapping(|_| {
                    called = true;
                    Ok::<_, ()>(())
                })
                .is_err()
        );
        assert!(!called);
        original
    });
    let mut original = worker
        .join()
        .map_err(|_| "foreign callback worker panicked")?;

    let mut called = false;
    assert!(
        original
            .with_paired_mapping(|_| {
                called = true;
                Ok::<_, ()>(())
            })
            .is_err()
    );
    assert!(!called);
    assert!(original.end_paired_scope(7, 1, 123).is_err());
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn wrong_end_identity_revokes_tls_before_any_fallback_admission() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut original = first.retain_whole_mapping(7);
    original.begin_paired_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 1,
            consumer_attempts: 1,
        },
    )?;

    assert!(original.end_paired_scope(7, 1, 124).is_err());
    let ordinary = crate::RingHeader::new();
    let mut entries: [crate::FrameEntry; 2] = std::array::from_fn(|_| crate::FrameEntry::default());
    ordinary.enqueue(
        &mut entries,
        &crate::FrameEntry::new(11, 0, 1, b"ordinary-after-ended-loan")?,
    )?;
    assert_eq!(ordinary.live_len(&entries)?, 1);
    assert!(original.selection_status().is_err());
    assert!(
        original
            .begin_paired_scope(
                7,
                1,
                123,
                SelectedRingAdmissionBudget {
                    producer_attempts: 1,
                    consumer_attempts: 1
                }
            )
            .is_err()
    );
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}

#[test]
fn owner_drop_revokes_native_callback_loan_and_keeps_actual_mapping_held() -> TestResult {
    let (_file, first, alias) = original_aliases()?;
    first.hold_hot_fork_ring_io()?;
    let mut original = first.retain_whole_mapping(7);
    original.begin_paired_scope(
        7,
        1,
        123,
        SelectedRingAdmissionBudget {
            producer_attempts: 1,
            consumer_attempts: 1,
        },
    )?;

    drop(original);

    let ordinary = crate::RingHeader::new();
    let mut entries: [crate::FrameEntry; 2] = std::array::from_fn(|_| crate::FrameEntry::default());
    ordinary.enqueue(
        &mut entries,
        &crate::FrameEntry::new(11, 0, 1, b"ordinary-after-owner-drop")?,
    )?;
    assert_eq!(ordinary.live_len(&entries)?, 1);
    assert!(alias.hot_fork_ring_io_snapshot()?.quiescent());
    assert!(alias.release_hot_fork_ring_io().is_err());
    Ok(())
}
