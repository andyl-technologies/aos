//! Deferred checked SQL lookup and one linear diagnostic bank per reader.

use super::*;
use crate::owned_decode::{DecodeBudget, DecodeScratch};
use batch::{busy, diagnostic};

pub(super) fn lookup(
    backend: &SqliteBlobBackend,
    caller: &DecodeBudget,
    id: ContentId,
    range: Option<ByteRange>,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<BlobHandle, StoreError> {
    let original = caller.clone();
    super::super::checked_reader::check(&original, boundary)?;
    let diagnostic = diagnostic::admit(&original, &backend.connection, None)?;
    diagnostic::retain_failure(diagnostic, || {
        busy::healthy(&backend.quarantined)?;
        let mut check = || {
            super::super::checked_reader::check(&original, boundary)?;
            busy::healthy(&backend.quarantined)
        };
        let credit = original
            .reserve_scratch_bytes(
                (std::mem::size_of::<SqliteBlobSource>() + 2 * std::mem::size_of::<usize>()) as u64,
            )
            .map_err(|error| super::super::batch::admission_under(&original, error))?;
        let _staging = catalog::read_gate_with_boundary(&mut check)?;
        let mut connection = loop {
            check()?;
            match backend
                .read_connection
                .try_lock_for("lock-checked-sqlite-length")?
            {
                Some(connection) => break connection,
                None => std::thread::yield_now(),
            }
        };
        let accepted = busy::with_zero(
            &original,
            &mut connection,
            &backend.quarantined,
            &mut check,
            |connection, _, check| {
                busy::retry(connection, false, &backend.quarantined, check, |_| {
                    let mut statement = connection
                        .prepare_cached("SELECT length(body) FROM objects WHERE id = ?1")
                        .map_err(|source| {
                            database_error("prepare-checked-sqlite-length", source)
                        })?;
                    super::super::batch::with_id_text(id, |encoded| {
                        statement
                            .query_row([encoded], |row| row.get::<_, i64>(0))
                            .optional()
                            .map_err(|source| database_error("read-checked-sqlite-length", source))
                    })
                })
            },
        )?;
        let handle = accepted.finish(|length| {
            check()?;
            let length = length.ok_or(StoreError::NotFound { id })?;
            let length = u64::try_from(length).map_err(|_| StoreError::Corrupt { id })?;
            let range = range.unwrap_or(ByteRange { offset: 0, length });
            validate_range(length, range)?;
            let source_lease = backend
                .catalog_supervisor
                .as_ref()
                .map(|supervisor| {
                    supervisor.reserve_resident_bytes(
                        (std::mem::size_of::<SqliteBlobSource>()
                            + 2 * std::mem::size_of::<usize>()
                            + super::super::physical_quota::deferred_source_metadata_bytes())
                            as u64,
                    )
                })
                .transpose()?;
            check()?;
            let source = SqliteBlobSource {
                connection: backend.read_connection.clone(),
                id,
                logical_length: length,
                range,
                catalog_supervisor: backend.catalog_supervisor.clone(),
                quarantined: backend.quarantined.clone(),
                resident_lease: backend.resident_lease.clone(),
                original: original.clone().into(),
                _source_lease: source_lease.into(),
                _source_credit: Some(credit),
            };
            Ok(if range.offset == 0 && range.length == length {
                BlobHandle::authenticated(id, source)
            } else {
                BlobHandle::integrity_checked(id, source)
            })
        })?;
        drop(connection);
        drop(_staging);
        super::super::checked_reader::check(&original, boundary)?;
        Ok(handle)
    })
}

pub(super) fn open(
    source: &SqliteBlobSource,
    caller: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<super::super::CheckedReader, StoreError> {
    let original = match source.original.as_ref() {
        Some(original) => original.clone(),
        None => caller.clone(),
    };
    super::super::checked_reader::check_pair(caller, &original, boundary)?;
    let diagnostic = diagnostic::admit(&original, &source.connection, None)?;
    let credit = original
        .reserve_scratch_array::<Reader>(1)
        .map_err(|error| super::super::batch::admission_under(&original, error))?;
    // A failed open consumes the same bank; a successful reader owns it until
    // EOF or transfers it once into its terminal error.
    let mut diagnostic = Some(diagnostic);
    let result = (|| {
        busy::healthy(&source.quarantined)?;
        let reader = source.reader()?;
        super::super::checked_reader::check_pair(caller, &original, boundary)?;
        Ok(super::super::CheckedReader::admitted(
            Box::new(Reader {
                reader,
                original: original.clone(),
                caller: caller.clone(),
                failed: false,
                diagnostic: diagnostic.take(),
            }),
            credit,
            crate::owned_decode::ResourceLoanSlot::default(),
        ))
    })();
    result.map_err(|error| match diagnostic {
        Some(credit) => diagnostic::retain_error(credit, error),
        None => error,
    })
}

// The concrete source lends its authenticating reader for this synchronous
// whole read. Streaming opens retain their ordinary owning wrapper; arbitrary
// readers still use the unchanged generic output/length/EOF boundary checks.
pub(super) fn read_all(
    source: &SqliteBlobSource,
    caller: &DecodeBudget,
    maximum: u64,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<super::super::OwnedBlobBytes, StoreError> {
    let original = source.original.as_ref().unwrap_or(caller);
    super::super::checked_reader::check_pair(caller, original, boundary)?;
    let diagnostic = diagnostic::admit(original, &source.connection, None)?;
    diagnostic::retain_failure(diagnostic, || {
        busy::healthy(&source.quarantined)?;
        let bytes = {
            let mut reader = source.reader()?;
            super::super::batch::read_reader_under(
                original,
                caller,
                source.range.length,
                maximum,
                boundary,
                &mut |output, boundary| {
                    let mut check = || {
                        super::super::checked_reader::check_pair(caller, original, boundary)?;
                        busy::healthy(&source.quarantined)
                    };
                    reader.read_with_boundary(original, output, &mut check)
                },
            )?
        };
        // The reader and its resident loan close before accepting the output.
        // The source, diagnostic bank and owned byte credit still retain the
        // same accounts while this final physical/original cut runs.
        super::super::checked_reader::check_pair(caller, original, boundary)?;
        Ok(bytes)
    })
}

struct Reader {
    reader: AuthenticatingSqliteReader,
    original: DecodeBudget,
    caller: DecodeBudget,
    failed: bool,
    diagnostic: Option<DecodeScratch>,
}

impl super::super::checked_reader::AuditedCheckedBlobReader for Reader {}

impl super::super::CheckedBlobReader for Reader {
    fn full_eof_identity(&self) -> Option<ContentId> {
        Some(self.reader.id)
    }

    fn original_account(&self) -> &crate::owned_decode::DecodeBudget {
        &self.original
    }

    fn read_with_boundary(
        &mut self,
        output: &mut [u8],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<usize, StoreError> {
        if self.failed {
            return Err(super::super::checked_reader::failed());
        }
        let original = &self.original;
        let quarantined = self.reader.quarantined.clone();
        let result = (|| {
            if self.diagnostic.is_none() {
                super::super::checked_reader::check_pair(&self.caller, original, boundary)?;
                busy::healthy(&quarantined)?;
                return Ok(0);
            }
            let mut check = || {
                super::super::checked_reader::check_pair(&self.caller, original, boundary)?;
                busy::healthy(&quarantined)
            };
            check()?;
            let count = self
                .reader
                .read_with_boundary(original, output, &mut check)?;
            check()?;
            if !output.is_empty() && count == 0 {
                super::super::checked_reader::check_pair(&self.caller, original, boundary)?;
                self.diagnostic.take();
            }
            Ok(count)
        })();
        match result {
            Ok(count) => Ok(count),
            Err(error) => {
                self.failed = true;
                Err(match self.diagnostic.take() {
                    Some(credit) => diagnostic::retain_error(credit, error),
                    None => error,
                })
            }
        }
    }
}
