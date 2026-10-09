//! Closes one metadata cursor and incremental blob before exposing owned bytes.
//!
//! The live metadata SELECT pins the read snapshot until the blob closes. No
//! full-body SQL value is requested before the RAM operation admits its length.

use super::*;
use rusqlite::DatabaseName;

pub(in crate::content_store::sqlite) const METADATA: &str =
    "SELECT typeof(body) = 'blob', length(body), rowid, typeof(body) FROM objects WHERE id = ?1";

/// Identifies the canonical object and the already-declared body limit.
#[derive(Clone, Copy)]
pub(in crate::content_store::sqlite) struct Record {
    pub(in crate::content_store::sqlite) id: ContentId,
    pub(in crate::content_store::sqlite) maximum: u64,
}

struct Attempt<T> {
    result: Result<T, StoreError>,
    cleanup: [Option<rusqlite::Error>; 3],
    admitted: bool,
}

fn is_busy(error: &StoreError) -> bool {
    match error {
        StoreError::StreamIo { source, .. } => source
            .get_ref()
            .and_then(|source| source.downcast_ref::<rusqlite::Error>())
            .is_some_and(|error| {
                matches!(error, rusqlite::Error::SqliteFailure(code, _) if code.extended_code == 5)
            }),
        _ => false,
    }
}

pub(in crate::content_store::sqlite) fn consume(
    original: &crate::owned_decode::DecodeBudget,
    connection: &Connection,
    quarantined: &AtomicBool,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    record: Record,
    admit: impl FnOnce(u64) -> Result<Vec<u8>, StoreError>,
    validate: impl FnOnce(&[u8]) -> Result<bool, StoreError>,
) -> Result<Accepted<Option<Vec<u8>>>, StoreError> {
    consume_inner::<true>(
        original,
        connection,
        quarantined,
        boundary,
        record,
        admit,
        validate,
    )
}

// Only the fixed Merkle entry may defer digest authentication until a fresh
// post-native-close row query. The intermediate bytes remain crate-private.
pub(in crate::content_store::sqlite) fn consume_merkle(
    original: &crate::owned_decode::DecodeBudget,
    connection: &Connection,
    quarantined: &AtomicBool,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    id: ContentId,
    admit: impl FnOnce(u64) -> Result<Vec<u8>, StoreError>,
) -> Result<Accepted<Option<Vec<u8>>>, StoreError> {
    if id.kind() != crate::content_store::ObjectKind::MerkleNode {
        return Err(StoreError::Corrupt { id });
    }
    consume_inner::<false>(
        original,
        connection,
        quarantined,
        boundary,
        Record {
            id,
            maximum: crate::content_store::MAX_MERKLE_NODE_ENVELOPE_BYTES as u64,
        },
        admit,
        |_| Ok(true),
    )
}

fn consume_inner<const AUTHENTICATE: bool>(
    original: &crate::owned_decode::DecodeBudget,
    connection: &Connection,
    quarantined: &AtomicBool,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    record: Record,
    admit: impl FnOnce(u64) -> Result<Vec<u8>, StoreError>,
    validate: impl FnOnce(&[u8]) -> Result<bool, StoreError>,
) -> Result<Accepted<Option<Vec<u8>>>, StoreError> {
    let mut check = || {
        crate::content_store::checked_reader::check(original, boundary)?;
        healthy(quarantined)
    };
    check()?;
    if !connection.is_autocommit() {
        quarantined.store(true, Ordering::Release);
        return Err(StoreError::Unavailable);
    }
    let credit = snapshot::SnapshotScope::prepare(original)?;
    let saved: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(|source| database_error("read-sqlite-busy-timeout", source))?;
    let saved = u64::try_from(saved)
        .ok()
        .filter(|value| *value <= i32::MAX as u64)
        .ok_or(StoreError::Quota)?;
    check()?;

    // Arm before changing connection state. An unwind quarantines all aliases;
    // it never runs hidden SQL cleanup or renews the incoming operation.
    let mut sentinel = CleanupSentinel {
        quarantined,
        armed: true,
    };
    let mut admit = Some(admit);
    let mut validate = Some(validate);
    let attempt = match connection.busy_timeout(Duration::ZERO) {
        Ok(()) => crate::content_store::batch::with_id_text(record.id, |encoded| {
            loop {
                let attempt = read_attempt::<AUTHENTICATE>(
                    original,
                    connection,
                    record,
                    encoded,
                    &mut check,
                    &mut admit,
                    &mut validate,
                );
                // Retry only the untouched metadata operation after all its native
                // state closed cleanly. Admission, a consumer or cleanup is never
                // replayed, even if its returned error happens to be BUSY.
                let repeat = !attempt.admitted
                    && attempt.cleanup.iter().all(Option::is_none)
                    && attempt.result.as_ref().err().is_some_and(is_busy)
                    && connection.is_autocommit();
                if !repeat {
                    break Ok(attempt);
                }
                if let Err(error) = check() {
                    break Ok(Attempt {
                        result: Err(error),
                        cleanup: [None, None, None],
                        admitted: false,
                    });
                }
                std::thread::yield_now();
            }
        }),
        Err(source) => Ok(Attempt {
            result: Err(database_error("disable-sqlite-busy-wait", source)),
            cleanup: [None, None, None],
            admitted: false,
        }),
    };
    let attempt = attempt.unwrap_or_else(|error| Attempt {
        result: Err(error),
        cleanup: [None, None, None],
        admitted: false,
    });
    let Attempt {
        mut result,
        cleanup,
        ..
    } = attempt;
    let restoration = connection.busy_timeout(Duration::from_millis(saved)).err();
    let closed =
        cleanup.iter().all(Option::is_none) && restoration.is_none() && connection.is_autocommit();
    if !closed {
        quarantined.store(true, Ordering::Release);
        if result.is_ok() && !connection.is_autocommit() {
            result = Err(StoreError::Unavailable);
        }
    } else {
        sentinel.armed = false;
        result = result.and_then(|value| {
            check()?;
            Ok(value)
        });
    }
    match result {
        Ok(value) if closed => Ok(Accepted {
            value,
            outcome: SqliteCommitOutcome::NotCommitted,
            diagnostic: None,
            credit,
        }),
        result => Err(read_scope_error(
            result.err(),
            None,
            restoration,
            cleanup,
            // This read cannot publish a commit. Native closure is described
            // by the actual cleanup fields, not invented rollback evidence.
            SqliteCommitOutcome::NotCommitted,
            credit,
            None,
        )),
    }
}

fn read_attempt<const AUTHENTICATE: bool>(
    original: &crate::owned_decode::DecodeBudget,
    connection: &Connection,
    record: Record,
    encoded: &str,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
    admit: &mut Option<impl FnOnce(u64) -> Result<Vec<u8>, StoreError>>,
    validate: &mut Option<impl FnOnce(&[u8]) -> Result<bool, StoreError>>,
) -> Attempt<Option<Vec<u8>>> {
    let Record { id, maximum } = record;
    let mut admitted = false;
    let mut cleanup = [None, None, None];
    let mut statement = match check().and_then(|()| {
        connection
            .prepare(METADATA)
            .map_err(|source| database_error("prepare-canonical-sqlite-metadata", source))
    }) {
        Ok(statement) => statement,
        Err(error) => {
            return Attempt {
                result: Err(error),
                cleanup,
                admitted,
            };
        }
    };
    let result = (|| {
        let mut rows = statement
            .query([encoded])
            .map_err(|source| database_error("query-canonical-sqlite-metadata", source))?;
        let result = (|| {
            let Some(row) = rows
                .next()
                .map_err(|source| database_error("read-canonical-sqlite-metadata", source))?
            else {
                return Ok(None);
            };
            let blob = row
                .get::<_, bool>(0)
                .map_err(|source| database_error("read-canonical-sqlite-metadata", source))?;
            let length = row
                .get::<_, i64>(1)
                .map_err(|source| database_error("read-canonical-sqlite-metadata", source))?;
            let rowid = row
                .get::<_, i64>(2)
                .map_err(|source| database_error("read-canonical-sqlite-metadata", source))?;
            let length = u64::try_from(length).map_err(|_| StoreError::Corrupt { id })?;
            check()?;
            // The scalar admission consumes the same original response bank
            // before opening a body or reserving any Rust buffer capacity.
            let admit = admit.take().ok_or(StoreError::Unsupported {
                capability: "canonical-sqlite-admission-already-used",
            })?;
            admitted = true;
            let mut bytes = admit(length)?;
            if length > maximum {
                return Err(StoreError::Corrupt { id });
            }
            if !blob {
                let kind = row
                    .get_ref(3)
                    .map_err(|source| database_error("borrow-bounded-sqlite-body", source))?;
                let data_type = match kind.as_str() {
                    Ok("integer") => rusqlite::types::Type::Integer,
                    Ok("real") => rusqlite::types::Type::Real,
                    Ok("text") => rusqlite::types::Type::Text,
                    Ok("null") => rusqlite::types::Type::Null,
                    _ => return Err(StoreError::Corrupt { id }),
                };
                return Err(database_error(
                    "borrow-bounded-sqlite-body",
                    rusqlite::Error::InvalidColumnType(0, "body".to_owned(), data_type),
                ));
            }
            original
                .verify_live()
                .map_err(|error| admission_under(original, error))?;
            let mut blob = connection
                .blob_open(DatabaseName::Main, "objects", "body", rowid, true)
                .map_err(|source| database_error("open-canonical-sqlite-blob", source))?;
            let result = (|| {
                if blob.len() as u64 != length {
                    return Err(StoreError::Corrupt { id });
                }
                let length = usize::try_from(length).map_err(|_| StoreError::Quota)?;
                if bytes.capacity() < length || !bytes.is_empty() {
                    return Err(StoreError::Unsupported {
                        capability: "canonical-sqlite-buffer-not-prepared",
                    });
                }
                bytes.resize(length, 0);
                for chunk in bytes.chunks_mut(64 * 1024) {
                    check()?;
                    blob.read_exact(chunk)
                        .map_err(|source| StoreError::StreamIo {
                            operation: "read-canonical-sqlite-blob",
                            source,
                        })?;
                }
                // Known digest corruption precedes a later EOF poll. Pure
                // framing/role errors remain private until that real poll.
                if AUTHENTICATE && !id.authenticates(&bytes) {
                    return Err(StoreError::Corrupt { id });
                }
                let valid = validate.take().ok_or(StoreError::Unsupported {
                    capability: "canonical-sqlite-consumer-already-used",
                })?(&bytes)?;
                check()?;
                if !valid {
                    return Err(StoreError::Unsupported {
                        capability: "bounded-canonical-validation-refused",
                    });
                }
                Ok(Some(bytes))
            })();
            // Blob::close reports its result and closes unconditionally in the
            // pinned binding. No later callback runs after a failed body/EOF.
            cleanup[0] = blob.close().err();
            result
        })();
        // DONE exposes its combined step/reset result. A step error and Drop
        // suppress their reset errors in rusqlite 0.32.1; no extra observation
        // is fabricated. Native cursor completion is unconditional cleanup.
        cleanup[1] = match rows.next() {
            Ok(None) => None,
            Ok(Some(_)) => Some(rusqlite::Error::InvalidQuery),
            Err(error) => Some(error),
        };
        drop(rows);
        result
    })();
    cleanup[2] = statement.finalize().err();
    Attempt {
        result,
        cleanup,
        admitted,
    }
}
