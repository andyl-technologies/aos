//! Exercises real native side-record backfill through the normal publication path.

pub(super) mod native;

/// Copies authenticated side bytes without any attempted plaintext content read.
///
/// # Errors
/// Preserves genuine factory, producer, current and durable publication failures.
/// # Panics
/// Panics when independent byte, count or agreement assertions fail.
#[tokio::test]
async fn native_index_backfill_reuses_checked_side_value_without_plaintext_reads()
-> native::fixture::TestResult {
    native::reuse().await
}

/// Leaves invalid, unavailable and unsupported inputs explicitly unresolved.
///
/// # Errors
/// Preserves real native setup, catalog and mandatory storage failures.
/// # Panics
/// Panics when incomplete coverage or atomic-file assertions fail.
#[tokio::test]
async fn native_index_backfill_reports_unavailable_or_invalid_evidence_as_gaps()
-> native::fixture::TestResult {
    native::gaps().await
}

/// Refuses real current, Original and missing final acknowledgment changes.
///
/// # Errors
/// Preserves genuine setup and publication failures from the owning caller.
/// # Panics
/// Panics when no-copy, first-refusal or missing-ack assertions fail.
#[tokio::test]
async fn native_index_backfill_rechecks_producer_current_and_final_publication()
-> native::fixture::TestResult {
    native::current().await
}

/// Completes actual winning inline and owner bindings across repeated grafts.
///
/// # Errors
/// Preserves genuine signed-history, carrier loading and warm current lookup failures.
/// # Panics
/// Panics when carrier, coverage or independent warm lookup assertions fail.
#[tokio::test]
async fn native_index_backfill_closes_required_inline_and_index_gaps_in_real_commit()
-> native::fixture::TestResult {
    native::complete().await
}

/// Preserves complete winning carriers through a genuine protected factory reopen.
///
/// # Errors
/// Preserves real materialization, protected reopen, snapshot and current lookup failures.
/// # Panics
/// Panics when winning identity, complete coverage or the deduplicated object set differs.
#[tokio::test]
async fn native_index_backfill_preserves_complete_carriers_after_protected_reopen()
-> native::fixture::TestResult {
    native::protected_reopen().await
}

/// Updates an already required binding in the actual same signed checkpoint.
///
/// # Errors
/// Preserves real producer, bound requirement, current and durable publication failures.
/// # Panics
/// Panics when initialization, copied paths or incremental Existing mode differs.
#[tokio::test]
async fn native_index_backfill_updates_existing_required_binding_in_real_commit()
-> native::fixture::TestResult {
    native::existing_binding().await
}
