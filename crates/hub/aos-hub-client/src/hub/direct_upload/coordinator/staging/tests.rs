//! Exercises actual overlap, draining, and the unchanged serial content bound.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Barrier;

use super::*;

#[tokio::test]
async fn metadata_batches_overlap_within_the_bound() {
    let barrier = Barrier::new(MAX_PARALLEL_BATCHES);
    let active = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let finished = AtomicUsize::new(0);

    tokio::time::timeout(
        Duration::from_secs(5),
        run((0..32).collect(), MAX_PARALLEL_BATCHES, |_| async {
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            barrier.wait().await;
            active.fetch_sub(1, Ordering::SeqCst);
            finished.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }),
    )
    .await
    .expect("all batches must actually overlap")
    .expect("metadata staged");

    assert_eq!(peak.load(Ordering::SeqCst), MAX_PARALLEL_BATCHES);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(finished.load(Ordering::SeqCst), 32);
}

#[tokio::test]
async fn observed_failure_drains_neighbors_without_dispatching_more_batches() {
    let started = AtomicUsize::new(0);
    let finished = AtomicUsize::new(0);
    let barrier = Barrier::new(MAX_PARALLEL_BATCHES);
    let refused = AtomicBool::new(false);

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        run((0..16).collect(), MAX_PARALLEL_BATCHES, |index| {
            let started = &started;
            let finished = &finished;
            let barrier = &barrier;
            let refused = &refused;
            async move {
                started.fetch_add(1, Ordering::SeqCst);
                barrier.wait().await;
                if index == 0 {
                    refused.store(true, Ordering::SeqCst);
                }
                while !refused.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
                finished.fetch_add(1, Ordering::SeqCst);
                if index == 0 {
                    Err(DirectClientError::ControlUnavailable)
                } else {
                    Ok(())
                }
            }
        }),
    )
    .await
    .expect("neighbors must drain");

    assert_eq!(result, Err(DirectClientError::ControlUnavailable));
    assert_eq!(started.load(Ordering::SeqCst), MAX_PARALLEL_BATCHES);
    assert_eq!(finished.load(Ordering::SeqCst), MAX_PARALLEL_BATCHES);
}

#[tokio::test]
async fn content_bound_remains_serial_and_invalid_bounds_refuse_dispatch() {
    let active = AtomicUsize::new(0);
    run((0..8).collect(), 1, |_| async {
        assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
        tokio::task::yield_now().await;
        assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
        Ok(())
    })
    .await
    .expect("serial content batches");

    for maximum in [0, MAX_PARALLEL_BATCHES + 1] {
        assert_eq!(
            run(vec![0], maximum, |_| async { panic!("invalid dispatch") }).await,
            Err(DirectClientError::Invalid)
        );
    }
}

#[tokio::test]
async fn slow_batch_does_not_hold_completed_scheduling_positions() {
    let release = tokio::sync::Notify::new();
    let finished = AtomicUsize::new(0);
    let active = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);

    let uploads = run((0..24).collect(), MAX_PARALLEL_BATCHES, |index| {
        let release = &release;
        let finished = &finished;
        let active = &active;
        let peak = &peak;
        async move {
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            if index == 0 {
                release.notified().await;
            } else {
                tokio::task::yield_now().await;
            }
            active.fetch_sub(1, Ordering::SeqCst);
            finished.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    });
    let release_after_progress = async {
        while finished.load(Ordering::SeqCst) < 16 {
            tokio::task::yield_now().await;
        }
        release.notify_one();
    };

    let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(uploads, release_after_progress)
    })
    .await
    .expect("later batches must progress while the original batch remains pending");

    result.expect("all metadata batches staged");
    assert_eq!(finished.load(Ordering::SeqCst), 24);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert!(peak.load(Ordering::SeqCst) <= MAX_PARALLEL_BATCHES);
}

#[tokio::test]
async fn drained_failures_preserve_input_order_after_admission_stops() {
    let started = AtomicUsize::new(0);

    let result = run((0..8).collect(), 3, |index| {
        let started = &started;
        async move {
            started.fetch_add(1, Ordering::SeqCst);
            match index {
                0 => {
                    tokio::task::yield_now().await;
                    Ok(())
                }
                1 => {
                    tokio::task::yield_now().await;
                    tokio::task::yield_now().await;
                    Err(DirectClientError::Blocked)
                }
                _ => Err(DirectClientError::ControlUnavailable),
            }
        }
    })
    .await;

    assert_eq!(result, Err(DirectClientError::Blocked));
    assert_eq!(started.load(Ordering::SeqCst), 3);
}
