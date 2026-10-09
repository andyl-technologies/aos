//! Stable scalar admission and borrowed canonical consumption in one snapshot.
//!
//! The private consumer owns canonical validation. This module admits metadata
//! before requesting a BLOB and retains the actual snapshot cleanup outcome.

use super::*;
use crate::owned_decode::DecodeBudget;
use batch::{busy, diagnostic};

mod session;
pub(crate) use session::SqliteRamReadSession;

const METADATA: &str = "SELECT typeof(body) = 'blob', length(body) FROM objects WHERE id = ?1";
const BODY: &str = "SELECT CASE WHEN typeof(body) = 'blob' AND length(body) = ?2 AND length(body) <= ?3 THEN body ELSE NULL END FROM objects WHERE id = ?1";

impl SqliteBlobBackend {
    pub(crate) fn consume_canonical_record(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
        admit: impl FnOnce(u64) -> Result<Vec<u8>, StoreError>,
        validate: impl FnOnce(&[u8]) -> Result<bool, StoreError>,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        super::super::checked_reader::check(original, boundary)?;
        let credit = diagnostic::admit_for_single_record_query(
            original,
            self.maximum_sqlite_heap_bytes,
            busy::single_record::METADATA.len(),
        )?;
        diagnostic::retain_failure(credit, || {
            let mut check = || {
                super::super::checked_reader::check(original, boundary)?;
                busy::healthy(&self.quarantined)
            };
            let _staging = catalog::read_gate_with_boundary(&mut check)?;
            let connection = loop {
                check()?;
                match self
                    .read_connection
                    .try_lock_for("lock-canonical-sqlite-record")?
                {
                    Some(connection) => break connection,
                    None => std::thread::yield_now(),
                }
            };
            busy::single_record::consume(
                original,
                &connection,
                &self.quarantined,
                &mut check,
                busy::single_record::Record { id, maximum },
                admit,
                validate,
            )?
            .finish(Ok)
        })
    }

    /// Consumes an admitted canonical body in a stable read snapshot.
    ///
    /// The private RAM consumer authenticates and validates the borrowed bytes.
    /// Metadata admission precedes the body query; actual EOF supervision,
    /// rollback and exact timeout restoration precede acceptance.
    ///
    /// # Errors
    ///
    /// Returns original supervision, admission, SQL, absence, length, consumer
    /// refusal or cleanup errors. Failures after entering the snapshot retain
    /// its complete observed scope outcome.
    pub(crate) fn consume_canonical_snapshot(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
        admit: impl FnOnce(u64) -> Result<(), StoreError>,
        consume: impl FnOnce(&[u8]) -> bool,
    ) -> Result<(), StoreError> {
        super::super::checked_reader::check(original, boundary)?;
        let credit = diagnostic::admit_for_query(
            original,
            self.maximum_sqlite_heap_bytes,
            None,
            METADATA.len().max(BODY.len()),
        )?;
        diagnostic::retain_failure(credit, || {
            let mut check = || {
                super::super::checked_reader::check(original, boundary)?;
                busy::healthy(&self.quarantined)
            };
            let _staging = catalog::read_gate_with_boundary(&mut check)?;
            let mut connection = loop {
                check()?;
                match self
                    .read_connection
                    .try_lock_for("lock-bounded-sqlite-snapshot")?
                {
                    Some(connection) => break connection,
                    None => std::thread::yield_now(),
                }
            };
            let accepted = busy::snapshot::with_snapshot(
                original,
                &mut connection,
                &self.quarantined,
                &mut check,
                |connection, check| {
                    consume_record(
                        RecordQuery {
                            original,
                            connection,
                            quarantined: &self.quarantined,
                            id,
                            maximum,
                        },
                        check,
                        AdmissionEdge::Poll,
                        admit,
                        |bytes| Ok(consume(bytes)),
                    )
                },
            )?;
            // The owning scope has performed actual EOF supervision and exact
            // cleanup before a pending validation error can be sealed. This
            // private marker has meaning only beside that consumer's evidence.
            accepted.finish(|valid| {
                if valid {
                    Ok(())
                } else {
                    Err(StoreError::Unsupported {
                        capability: "bounded-canonical-validation-refused",
                    })
                }
            })
        })
    }
}

#[derive(Clone, Copy)]
enum AdmissionEdge {
    Poll,
    OriginalOnly,
}

struct RecordQuery<'query> {
    original: &'query DecodeBudget,
    connection: &'query Connection,
    quarantined: &'query std::sync::atomic::AtomicBool,
    id: ContentId,
    maximum: u64,
}

// The comparison supplies only closed pure accounting and canonical parsing.
// Its metadata check can also discharge a previous pending EOF immediately
// before the fixed query; the single-record producer retains its old polls.
fn consume_record(
    query: RecordQuery<'_>,
    check: &mut dyn FnMut() -> Result<(), StoreError>,
    edge: AdmissionEdge,
    admit: impl FnOnce(u64) -> Result<(), StoreError>,
    consume: impl FnOnce(&[u8]) -> Result<bool, StoreError>,
) -> Result<bool, StoreError> {
    let RecordQuery {
        original,
        connection,
        quarantined,
        id,
        maximum,
    } = query;
    super::super::batch::with_id_text(id, |encoded| {
        let (_, length) = busy::retry(connection, true, quarantined, check, |_| {
            connection
                .query_row(METADATA, [encoded], |row| {
                    Ok((row.get::<_, bool>(0)?, row.get::<_, i64>(1)?))
                })
                .optional()
                .map_err(|source| database_error("read-bounded-sqlite-metadata", source))?
                .ok_or(StoreError::NotFound { id })
        })?;
        let length = u64::try_from(length).map_err(|_| StoreError::Corrupt { id })?;
        match edge {
            AdmissionEdge::Poll => check()?,
            AdmissionEdge::OriginalOnly => original
                .verify_live()
                .map_err(|error| crate::content_store::batch::admission_under(original, error))?,
        }
        admit(length)?;
        if length > maximum {
            return Err(StoreError::Corrupt { id });
        }

        // BEGIN precedes metadata; the second projection also
        // checks its exact admitted length and cap. No changed
        // or oversized native BLOB is materialized on mismatch.
        let mut consume = Some(consume);
        busy::retry(connection, true, quarantined, check, |_| {
            let mut statement = connection
                .prepare(BODY)
                .map_err(|source| database_error("prepare-bounded-sqlite-body", source))?;
            let mut rows = statement
                .query(rusqlite::params![encoded, length, maximum])
                .map_err(|source| database_error("query-bounded-sqlite-body", source))?;
            let row = rows
                .next()
                .map_err(|source| database_error("read-bounded-sqlite-body", source))?
                .ok_or(StoreError::NotFound { id })?;
            let value = row
                .get_ref(0)
                .map_err(|source| database_error("borrow-bounded-sqlite-body", source))?;
            let bytes = value.as_blob().map_err(|_| {
                database_error(
                    "borrow-bounded-sqlite-body",
                    rusqlite::Error::InvalidColumnType(0, BODY.to_owned(), value.data_type()),
                )
            })?;
            if bytes.len() as u64 != length {
                return Err(StoreError::Corrupt { id });
            }
            let consume = consume.take().ok_or(StoreError::Unsupported {
                capability: "bounded-sqlite-consumer-already-used",
            })?;
            consume(bytes)
        })
    })
}
