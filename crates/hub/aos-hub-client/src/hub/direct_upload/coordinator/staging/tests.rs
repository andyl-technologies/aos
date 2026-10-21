//! Exercises actual overlap, draining, and the unchanged serial content bound.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Barrier;

use super::*;

#[tokio::test]
async fn metadata_batches_overlap_in_bounded_groups() {
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
async fn failed_batch_drains_neighbors_without_dispatching_later_groups() {
    let started = AtomicUsize::new(0);
    let finished = AtomicUsize::new(0);
    let barrier = Barrier::new(MAX_PARALLEL_BATCHES);

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        run((0..16).collect(), MAX_PARALLEL_BATCHES, |index| {
            let started = &started;
            let finished = &finished;
            let barrier = &barrier;
            async move {
                started.fetch_add(1, Ordering::SeqCst);
                barrier.wait().await;
                tokio::task::yield_now().await;
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
