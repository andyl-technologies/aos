//! Actual cursor/blob snapshot, admission and first-refusal controls.

use super::*;
use std::cell::Cell;

fn body() -> (ContentId, Vec<u8>) {
    let envelope = crate::content_envelope::ContentEnvelope::new(
        "crucible.ram.page",
        1,
        [].into(),
        vec![17; 128],
    )
    .unwrap();
    let bytes = envelope.canonical_bytes();
    (
        ContentId::for_bytes(ObjectKind::RamExtent, 1, &bytes),
        bytes,
    )
}

fn admitted_buffer(original: &DecodeBudget, length: u64) -> Result<Vec<u8>, StoreError> {
    let length = usize::try_from(length).map_err(|_| StoreError::Quota)?;
    original
        .charge_array::<u8>(length)
        .map_err(|error| admission_under(original, error))?;
    original
        .verify_live()
        .map_err(|error| admission_under(original, error))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|source| StoreError::Allocation {
            source,
            custody: Some(original.custody()),
        })?;
    Ok(bytes)
}

#[test]
fn live_metadata_cursor_pins_blob_across_foreign_wal_growth() {
    if isolated("single_record::live_metadata_cursor_pins_blob_across_foreign_wal_growth") {
        return;
    }
    let (root, _guard, backend, original) = backend();
    let connection = backend.lock_connection().unwrap();
    connection
        .execute_batch("PRAGMA journal_mode=WAL;")
        .unwrap();
    connection
        .busy_timeout(Duration::from_millis(1234))
        .unwrap();
    let (id, bytes) = body();
    let encoded = id.to_string();
    connection
        .execute(
            "INSERT INTO objects(id,body) VALUES (?1,?2)",
            rusqlite::params![encoded, &bytes],
        )
        .unwrap();
    let foreign = fixture_sqlite_connection(root.path().join(DATABASE_FILE)).unwrap();
    let replacement = vec![99_u8; bytes.len() + 1024];
    let response = original.child().unwrap();
    let admissions = Cell::new(0);

    let accepted = super::super::single_record::consume(
        &original,
        &connection,
        &backend.quarantined,
        &mut || Ok(()),
        super::super::single_record::Record {
            id,
            maximum: bytes.len() as u64,
        },
        |length| {
            admissions.set(admissions.get() + 1);
            assert_eq!(length, bytes.len() as u64);
            // This explicit test-only foreign connection mutates the row after
            // metadata; production admission performs only closed accounting.
            foreign
                .execute(
                    "UPDATE objects SET body=?1 WHERE id=?2",
                    rusqlite::params![&replacement, encoded],
                )
                .unwrap();
            admitted_buffer(&response, length)
        },
        |actual| {
            assert_eq!(actual, bytes);
            Ok(true)
        },
    )
    .unwrap();
    let read = accepted.finish(Ok).unwrap().unwrap();
    assert_eq!(read, bytes);
    assert_eq!(admissions.get(), 1);
    assert!(connection.is_autocommit());
    assert_eq!(timeout(&connection), 1234);

    // A subsequent purpose sees the new length and refuses before any body
    // allocation or consumer, rather than trusting the prior admitted length.
    let allocations = Cell::new(0);
    let failure = super::super::single_record::consume(
        &original,
        &connection,
        &backend.quarantined,
        &mut || Ok(()),
        super::super::single_record::Record {
            id,
            maximum: bytes.len() as u64,
        },
        |length| {
            assert_eq!(length, replacement.len() as u64);
            if length > bytes.len() as u64 {
                return Err(StoreError::Quota);
            }
            allocations.set(allocations.get() + 1);
            admitted_buffer(&response, length)
        },
        |_| panic!("oversized body cannot reach the consumer"),
    )
    .err()
    .unwrap();
    assert!(matches!(failure.original_failure(), StoreError::Quota));
    assert_eq!(allocations.get(), 0);
    assert!(scope(&failure).blob_close_failure().is_none());
    assert!(scope(&failure).metadata_completion_failure().is_none());
    assert!(scope(&failure).metadata_finalization_failure().is_none());
    assert!(connection.is_autocommit());
    assert_eq!(timeout(&connection), 1234);
}

#[test]
fn actual_eof_refusal_precedes_pending_validation_and_closes_native_state() {
    if isolated(
        "single_record::actual_eof_refusal_precedes_pending_validation_and_closes_native_state",
    ) {
        return;
    }
    let (_root, _guard, backend, original) = backend();
    let connection = backend.lock_connection().unwrap();
    connection.busy_timeout(Duration::from_millis(876)).unwrap();
    let (id, bytes) = body();
    connection
        .execute(
            "INSERT INTO objects(id,body) VALUES (?1,?2)",
            rusqlite::params![id.to_string(), &bytes],
        )
        .unwrap();
    let response = original.child().unwrap();
    let validated = Cell::new(false);
    let refused = Cell::new(false);

    let failure = super::super::single_record::consume(
        &original,
        &connection,
        &backend.quarantined,
        &mut || {
            assert!(!refused.get(), "no callback after the first refusal");
            if validated.get() {
                refused.set(true);
                Err(StoreError::Unavailable)
            } else {
                Ok(())
            }
        },
        super::super::single_record::Record {
            id,
            maximum: bytes.len() as u64,
        },
        |length| admitted_buffer(&response, length),
        |_| {
            validated.set(true);
            Ok(false)
        },
    )
    .err()
    .unwrap();
    assert!(refused.get());
    assert!(matches!(
        failure.original_failure(),
        StoreError::Unavailable
    ));
    assert_eq!(scope(&failure).outcome(), SqliteCommitOutcome::NotCommitted);
    assert!(scope(&failure).blob_close_failure().is_none());
    assert!(scope(&failure).metadata_completion_failure().is_none());
    assert!(scope(&failure).metadata_finalization_failure().is_none());
    assert!(scope(&failure).restoration_failure().is_none());
    assert!(connection.is_autocommit());
    assert_eq!(timeout(&connection), 876);
}

#[test]
fn known_body_corruption_precedes_later_eof_and_keeps_clean_absence_distinct() {
    if isolated(
        "single_record::known_body_corruption_precedes_later_eof_and_keeps_clean_absence_distinct",
    ) {
        return;
    }
    let (_root, _guard, backend, original) = backend();
    let connection = backend.lock_connection().unwrap();
    let (id, bytes) = body();
    let mut corrupted = bytes.clone();
    corrupted[0] ^= 1;
    connection
        .execute(
            "INSERT INTO objects(id,body) VALUES (?1,?2)",
            rusqlite::params![id.to_string(), &corrupted],
        )
        .unwrap();
    let response = original.child().unwrap();
    let failure = super::super::single_record::consume(
        &original,
        &connection,
        &backend.quarantined,
        &mut || Ok(()),
        super::super::single_record::Record {
            id,
            maximum: bytes.len() as u64,
        },
        |length| admitted_buffer(&response, length),
        |_| panic!("known full-ID corruption precedes validation and EOF"),
    )
    .err()
    .unwrap();
    assert!(
        matches!(failure.original_failure(), StoreError::Corrupt { id: actual } if *actual == id)
    );
    assert!(!failure.confirmed_absence(id));
    assert!(connection.is_autocommit());

    connection
        .execute("DELETE FROM objects WHERE id=?1", [id.to_string()])
        .unwrap();
    let absence = super::super::single_record::consume(
        &original,
        &connection,
        &backend.quarantined,
        &mut || Ok(()),
        super::super::single_record::Record {
            id,
            maximum: bytes.len() as u64,
        },
        |_| panic!("clean absence cannot admit body storage"),
        |_| panic!("clean absence cannot consume a body"),
    )
    .unwrap()
    .finish(Ok)
    .unwrap();
    assert!(absence.is_none());
    assert!(connection.is_autocommit());
}

#[test]
fn native_diagnostic_admission_refuses_before_connection_or_metadata_effects() {
    if isolated(
        "single_record::native_diagnostic_admission_refuses_before_connection_or_metadata_effects",
    ) {
        return;
    }
    let (_root, _guard, backend, original) = backend();
    let (id, bytes) = body();
    // This fixture's unchanged 64 MiB account cannot admit the closed 18m
    // message envelope for its independently authored 8 MiB native heap.
    // Holding the actual read connection makes any misplaced acquisition
    // visible through the next callback instead of silently reading metadata.
    let connection = backend
        .read_connection
        .try_lock_for("hold-single-record-admission-control")
        .unwrap()
        .unwrap();
    let prior_timeout = timeout(&connection);
    let mut callbacks = 0;

    let error = backend
        .consume_canonical_record(
            &original,
            id,
            bytes.len() as u64,
            &mut || {
                callbacks += 1;
                assert_eq!(
                    callbacks, 1,
                    "refused admission cannot acquire native state"
                );
                Ok(())
            },
            |_| panic!("refused diagnostic purpose cannot admit a body"),
            |_| panic!("refused diagnostic purpose cannot consume bytes"),
        )
        .unwrap_err();

    assert!(matches!(
        error.original_failure(),
        StoreError::DecodeAdmission { .. }
    ));
    assert_eq!(callbacks, 1);
    assert!(original.verify_live().is_err());
    assert!(connection.is_autocommit());
    assert_eq!(timeout(&connection), prior_timeout);
}
