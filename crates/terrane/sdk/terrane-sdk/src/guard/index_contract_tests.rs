//! Exercises exact native index key limits and batched canonical resynchronization.
//!
//! Fixtures retain genuine native factories, signed producers and Original controls.
//! Independent canonical construction stays outside the measured writer invocation.

use super::index_backfill::native_fixture;

mod key_limit;
mod multi_edit;

use native_fixture::TestResult;

/// Rejects a valid one-byte-over indexed value before any durable publication effect.
///
/// # Errors
/// Preserves genuine factory, producer, Original, publication and strict-load failures.
/// # Panics
/// Panics if independent canonical bytes, exact limits or publication snapshots disagree.
#[tokio::test]
async fn native_index_key_limit_refuses_before_publication_effects() -> TestResult {
    key_limit::exercise().await
}

/// Maintains multi-edit graft occurrences with independent canonical batch accounting.
///
/// # Errors
/// Preserves genuine publication, Original, canonical model and strict-load failures.
/// # Panics
/// Panics if canonical outputs, logical deltas or independent physical streams differ.
#[tokio::test]
async fn native_index_multi_edit_batches_and_resynchronizes_canonically() -> TestResult {
    multi_edit::exercise(1024, false).await
}

/// Checks the 1024-occurrence adversarial native canonical edit composition.
///
/// # Errors
/// Preserves genuine publication, Original, canonical model and strict-load failures.
/// # Panics
/// Panics if canonical outputs, logical deltas or independent physical streams differ.
#[tokio::test]
async fn native_index_multi_edit_batches_and_resynchronizes_canonically_1024_adversarial()
-> TestResult {
    multi_edit::exercise(1024, true).await
}

/// Checks the 2048-occurrence ordinary native canonical edit composition.
///
/// # Errors
/// Preserves genuine publication, Original, canonical model and strict-load failures.
/// # Panics
/// Panics if canonical outputs, logical deltas or independent physical streams differ.
#[tokio::test]
async fn native_index_multi_edit_batches_and_resynchronizes_canonically_2048_ordinary() -> TestResult
{
    multi_edit::exercise(2048, false).await
}

/// Checks the 2048-occurrence adversarial native canonical edit composition.
///
/// # Errors
/// Preserves genuine publication, Original, canonical model and strict-load failures.
/// # Panics
/// Panics if canonical outputs, logical deltas or independent physical streams differ.
#[tokio::test]
async fn native_index_multi_edit_batches_and_resynchronizes_canonically_2048_adversarial()
-> TestResult {
    multi_edit::exercise(2048, true).await
}

/// Checks the 4096-occurrence ordinary native canonical edit composition.
///
/// # Errors
/// Preserves genuine publication, Original, canonical model and strict-load failures.
/// # Panics
/// Panics if canonical outputs, logical deltas or independent physical streams differ.
#[tokio::test]
async fn native_index_multi_edit_batches_and_resynchronizes_canonically_4096_ordinary() -> TestResult
{
    multi_edit::exercise(4096, false).await
}

/// Checks the 4096-occurrence adversarial native canonical edit composition.
///
/// # Errors
/// Preserves genuine publication, Original, canonical model and strict-load failures.
/// # Panics
/// Panics if canonical outputs, logical deltas or independent physical streams differ.
#[tokio::test]
async fn native_index_multi_edit_batches_and_resynchronizes_canonically_4096_adversarial()
-> TestResult {
    multi_edit::exercise(4096, true).await
}
