//! Original-operation source reading through SQLite's bounded read gate.

use crate::content_store::batch::admission_under;
use std::sync::atomic::AtomicBool;

use super::*;

struct ReadChunk {
    bytes: Vec<u8>,
    _credit: crate::owned_decode::DecodeScratch,
}

impl AuthenticatingSqliteReader {
    pub(in super::super) fn read_with_boundary(
        &mut self,
        original: &crate::owned_decode::DecodeBudget,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        busy::healthy(&self.quarantined)?;
        let _staging = catalog::read_gate_with_boundary(boundary)?;
        busy::healthy(&self.quarantined)?;
        if output.is_empty() || self.finalized {
            boundary()?;
            return Ok(0);
        }
        self.scan_with_boundary(original, self.range.offset, boundary)?;
        if self.output_offset < self.range.length {
            let length = usize::try_from(
                (self.range.length - self.output_offset)
                    .min(output.len() as u64)
                    .min(MAX_CHUNK_BYTES as u64),
            )
            .map_err(|_| StoreError::Quota)?;
            let chunk = self.chunk_with_boundary(original, self.scan_offset, length, boundary)?;
            output[..length].copy_from_slice(&chunk.bytes);
            self.hasher.update(&chunk.bytes);
            self.scan_offset += length as u64;
            self.output_offset += length as u64;
            boundary()?;
            return Ok(length);
        }
        self.scan_with_boundary(original, self.logical_length, boundary)?;
        // Even an empty original must prove that its row still exists at EOF.
        // This zero-byte projection validates current total length under the
        // same checked SQL scope; it never treats an old digest as possession.
        drop(self.chunk_with_boundary(original, 0, 0, boundary)?);
        if *self.hasher.finalize().as_bytes() != self.id.digest() {
            return Err(StoreError::Corrupt { id: self.id });
        }
        self.finalized = true;
        boundary()?;
        Ok(0)
    }

    fn scan_with_boundary(
        &mut self,
        original: &crate::owned_decode::DecodeBudget,
        target: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        while self.scan_offset < target {
            let length = usize::try_from((target - self.scan_offset).min(MAX_CHUNK_BYTES as u64))
                .map_err(|_| StoreError::Quota)?;
            let chunk = self.chunk_with_boundary(original, self.scan_offset, length, boundary)?;
            self.hasher.update(&chunk.bytes);
            self.scan_offset += length as u64;
        }
        Ok(())
    }

    fn chunk_with_boundary(
        &self,
        original: &crate::owned_decode::DecodeBudget,
        offset: u64,
        length: usize,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<ReadChunk, StoreError> {
        boundary()?;
        original
            .verify_live()
            .map_err(|error| admission_under(original, error))?;
        let credit = original
            .reserve_scratch_array::<u8>(length)
            .map_err(|error| admission_under(original, error))?;
        let mut connection = loop {
            busy::healthy(&self.quarantined)?;
            boundary()?;
            match self.connection.try_lock_for("lock-sqlite-blob-reader")? {
                Some(connection) => {
                    busy::healthy(&self.quarantined)?;
                    break connection;
                }
                None => std::thread::yield_now(),
            }
        };
        boundary()?;
        let sqlite_offset = i64::try_from(offset)
            .ok()
            .and_then(|offset| offset.checked_add(1))
            .ok_or(StoreError::Quota)?;
        let accepted = busy::with_zero(
            original,
            &mut connection,
            &self.quarantined,
            boundary,
            |connection, _, boundary| {
                current_chunk(
                    connection,
                    &self.quarantined,
                    boundary,
                    self.id,
                    sqlite_offset,
                    length,
                    self.logical_length,
                )
            },
        )?;
        accepted.finish(|bytes| {
            boundary()?;
            let bytes = bytes.ok_or(StoreError::Corrupt { id: self.id })?;
            if bytes.len() != length {
                return Err(StoreError::Corrupt { id: self.id });
            }
            Ok(ReadChunk {
                bytes,
                _credit: credit,
            })
        })
    }
}

// Both the ordinary checked stream and the fixed native Merkle entry use this
// exact current-row predicate and zero-only decoder; neither snapshot metadata
// nor an empty digest can stand in for possession at nonempty EOF.
pub(in crate::content_store::sqlite) fn current_chunk(
    connection: &Connection,
    quarantined: &AtomicBool,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    id: ContentId,
    sqlite_offset: i64,
    length: usize,
    logical_length: u64,
) -> Result<Option<Vec<u8>>, StoreError> {
    busy::retry(connection, false, quarantined, boundary, |_| {
        let mut statement = connection
            .prepare_cached(diagnostic::SOURCE_SQL)
            .map_err(|source| database_error("prepare-sqlite-batch-source", source))?;
        with_id_text(id, |encoded| {
            statement
                .query_row(
                    params![encoded, sqlite_offset, length as i64, logical_length],
                    |row| {
                        if length == 0 {
                            // SQLite projects an empty BLOB's zero-byte substring as
                            // NULL. The predicate already proves a present row with
                            // its saved length; a NULL body cannot match it.
                            row.get::<_, Option<Vec<u8>>>(0)
                                .map(Option::unwrap_or_default)
                        } else {
                            row.get::<_, Vec<u8>>(0)
                        }
                    },
                )
                .optional()
                .map_err(|source| database_error("read-sqlite-batch-source", source))
        })
    })
}
