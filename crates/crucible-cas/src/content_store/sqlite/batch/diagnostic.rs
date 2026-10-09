//! Prepaid checked SQLite error copies and their last-owner allocation custody.
//!
//! The binding copies SQLite's message before returning an error. Its private
//! connection must therefore have an actual native heap ceiling before this
//! checked route reserves the possible Rust copy. Generic routes are unchanged.

use crate::content_store::batch::{admission_under, allocation_under};

use std::fmt;
use std::mem::{align_of, size_of};

use crate::owned_decode::DecodeScratch;

use super::*;

const AUDITED_SQLITE_VERSION: i32 = 3_053_004;
const STATIC_SQLITE_ERROR_BYTES: u64 = 36;
const MINIMUM_STRING_CAPACITY: u64 = 8;
const ROLLBACK_DIAGNOSTIC_BYTES: usize = 42;

// These fixed statements also bound a copied expression/column name or SQL
// input in rusqlite's typed errors. No caller-provided SQL reaches this route.
pub(in crate::content_store::sqlite) const PRESENCE_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM objects WHERE id = ?1)";
pub(super) const INSERT_SQL: &str = "INSERT INTO objects (id, body) VALUES (?1, ?2)";
pub(super) const SOURCE_SQL: &str =
    "SELECT substr(body, ?2, ?3) FROM objects WHERE id = ?1 AND length(body) = ?4";
pub(super) const METADATA_SQL: &str =
    "SELECT instance, generation, checksum FROM metadata WHERE singleton = 1";
pub(in crate::content_store::sqlite) const INVENTORY_SQL: &str =
    "SELECT id, length(body) FROM objects ORDER BY id";
pub(in crate::content_store::sqlite) const DELETE_SQL: &str = "DELETE FROM objects WHERE id = ?1";
pub(super) const UPDATE_SQL: &str =
    "UPDATE metadata SET generation = ?1, checksum = ?2 WHERE singleton = 1";

/// Retains a checked SQLite failure with its original diagnostic allocation loan.
///
/// The original store error closes before the linear loan. Borrowing the error
/// preserves its typed source chain without detaching the owned diagnostic.
pub struct SqliteDiagnosticError {
    error: Box<StoreError>,
    _credit: DecodeScratch,
}

impl SqliteDiagnosticError {
    /// Returns the original store error while its allocation loan remains live.
    #[must_use]
    pub fn failure(&self) -> &StoreError {
        &self.error
    }
}

impl fmt::Debug for SqliteDiagnosticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl fmt::Display for SqliteDiagnosticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for SqliteDiagnosticError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.failure())
    }
}

pub(in super::super) fn admit(
    original: &crate::owned_decode::DecodeBudget,
    native_heap: &SqliteConnection,
    root: Option<&Path>,
) -> Result<DecodeScratch, StoreError> {
    admit_for_query(original, native_heap, root, 0)
}

pub(in crate::content_store::sqlite) fn admit_for_query(
    original: &crate::owned_decode::DecodeBudget,
    native_heap: &SqliteConnection,
    root: Option<&Path>,
    query_width: usize,
) -> Result<DecodeScratch, StoreError> {
    let heap = reviewed_heap(native_heap.maximum_heap_bytes(), rusqlite::version_number())?;
    original
        .reserve_scratch_bytes(peak_bytes_for_query(heap, root, query_width)?)
        .map_err(|error| admission_under(original, error))
}

// This closed reader retains work, blob-close and metadata completion errors.
// Rows' failing step can additionally allocate a discarded reset diagnostic.
// Three retained 4m capacities plus that transient 6m conversion need 18m;
// finalization after the pinned reset/rewind can add only a static OOM message.
// Arbitrary callback errors retain their separate original allocation custody.
pub(in crate::content_store::sqlite) fn admit_for_single_record_query(
    original: &crate::owned_decode::DecodeBudget,
    native_heap: &SqliteConnection,
    query_width: usize,
) -> Result<DecodeScratch, StoreError> {
    let heap = reviewed_heap(native_heap.maximum_heap_bytes(), rusqlite::version_number())?;
    original
        .reserve_scratch_bytes(single_record_peak_bytes(heap, query_width)?)
        .map_err(|error| admission_under(original, error))
}

fn reviewed_heap(heap: u64, version: i32) -> Result<u64, StoreError> {
    if version != AUDITED_SQLITE_VERSION {
        return Err(StoreError::Unsupported {
            capability: "sqlite-diagnostic-reviewed-version",
        });
    }
    Ok(heap)
}

fn message_peak(native_heap: u64) -> Result<u64, StoreError> {
    native_heap
        .max(STATIC_SQLITE_ERROR_BYTES)
        .max(MINIMUM_STRING_CAPACITY)
        .checked_mul(6)
        .ok_or(StoreError::Quota)
}

fn single_record_peak_bytes(native_heap: u64, query_width: usize) -> Result<u64, StoreError> {
    let message = message_peak(native_heap)?;
    let fixed = peak_bytes_for_query(native_heap, None, query_width)?
        .checked_sub(message)
        .ok_or(StoreError::Quota)?;
    message
        .checked_mul(3)
        .and_then(|bytes| {
            fixed
                .checked_mul(4)
                .and_then(|fixed| bytes.checked_add(fixed))
        })
        .and_then(|bytes| bytes.checked_add(6 * STATIC_SQLITE_ERROR_BYTES))
        .ok_or(StoreError::Quota)
}

fn peak_bytes_for_query(
    native_heap: u64,
    root: Option<&Path>,
    query_width: usize,
) -> Result<u64, StoreError> {
    // Rust 1.98.1's from_utf8_lossy starts at m bytes, produces at most 3m,
    // and doubles to at most 4m. Its largest reallocation keeps 2m + 4m
    // live. The minimum byte-vector growth is covered when m is below 8.
    // SQLite 3.53.4's dynamic errmsg is native-allocator-backed; its static
    // fallback census is at most 36 bytes. This is a copy geometry bound,
    // rather than an assumption that corrupt-schema messages are short.
    let message = message_peak(native_heap)?;

    // io::Error::other owns both the rusqlite error Box and Rust's private
    // Custom Box. Custom has ErrorKind, one fat error pointer, two function
    // pointers and alignment >= 4. Rounding each field to the maximum field
    // alignment bounds any Rust field ordering, including trailing padding.
    let alignment = align_of::<io::ErrorKind>()
        .max(align_of::<usize>())
        .max(align_of::<fn()>())
        .max(4);
    let callbacks = rounded(size_of::<fn()>(), alignment)?
        .checked_mul(2)
        .ok_or(StoreError::Quota)?;
    let custom = rounded(size_of::<io::ErrorKind>(), alignment)?
        .checked_add(rounded(2 * size_of::<usize>(), alignment)?)
        .and_then(|bytes| bytes.checked_add(callbacks))
        .ok_or(StoreError::Quota)?;
    let wrappers = size_of::<StoreError>()
        .checked_add(size_of::<rusqlite::Error>())
        .and_then(|bytes| bytes.checked_add(custom))
        .ok_or(StoreError::Quota)?;

    let sql_bytes = [
        PRESENCE_SQL,
        INSERT_SQL,
        SOURCE_SQL,
        METADATA_SQL,
        UPDATE_SQL,
        INVENTORY_SQL,
        DELETE_SQL,
    ]
    .into_iter()
    .map(str::len)
    .max()
    .ok_or(StoreError::Quota)?
    .max(query_width);
    // A typed column error and modern SQLite's SQL-input error each have one
    // additional fixed-text allocation; banking both also covers coexistence.
    let names = sql_bytes.checked_mul(2).ok_or(StoreError::Quota)?;
    let paths = root
        .map(lock_path_capacity)
        .transpose()?
        .unwrap_or(0)
        .checked_mul(2)
        .ok_or(StoreError::Quota)?;
    // A batch's ordinary Transaction drop can copy one additional fixed
    // ROLLBACK diagnostic while the work error remains live. The private
    // main/temp connection has no hooks or attached schemas; the reviewed
    // fixed-literal paths emit at most 42 ASCII bytes, copied exactly once.
    // Source reads do not hold a transaction and need no cleanup message.
    let cleanup = if root.is_some() {
        ROLLBACK_DIAGNOSTIC_BYTES
    } else {
        0
    };
    let fixed = wrappers
        .checked_add(names)
        .and_then(|bytes| bytes.checked_add(paths))
        .and_then(|bytes| bytes.checked_add(cleanup))
        .ok_or(StoreError::Quota)?;
    message
        .checked_add(u64::try_from(fixed).map_err(|_| StoreError::Quota)?)
        .ok_or(StoreError::Quota)
}

fn rounded(bytes: usize, alignment: usize) -> Result<usize, StoreError> {
    bytes
        .checked_add(alignment - 1)
        .map(|bytes| bytes & !(alignment - 1))
        .ok_or(StoreError::Quota)
}

fn lock_path_capacity(root: &Path) -> Result<usize, StoreError> {
    root.as_os_str()
        .len()
        .checked_add(1)
        .and_then(|bytes| bytes.checked_add(LOCK_FILE.len()))
        .ok_or(StoreError::Quota)
}

pub(super) fn lock_path(
    original: &crate::owned_decode::DecodeBudget,
    root: &Path,
) -> Result<PathBuf, StoreError> {
    let mut path = PathBuf::new();
    path.try_reserve_exact(lock_path_capacity(root)?)
        .map_err(|error| allocation_under(original, error))?;
    path.push(root);
    path.push(LOCK_FILE);
    Ok(path)
}

pub(in super::super) fn retain_failure<T>(
    credit: DecodeScratch,
    work: impl FnOnce() -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    match work() {
        Ok(value) => Ok(value),
        Err(error) => Err(retain_error(credit, error)),
    }
}

pub(in super::super) fn retain_error(credit: DecodeScratch, error: StoreError) -> StoreError {
    // The sealed direct marker owns no diagnostic allocation. Nested scopes
    // and all native or arbitrary errors keep their complete prepaid custody.
    if matches!(&error, StoreError::RamBoundary { .. }) {
        drop(credit);
        return error;
    }

    StoreError::SqliteDiagnostic {
        source: SqliteDiagnosticError {
            error: Box::new(error),
            _credit: credit,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_record_peak_covers_retained_and_transient_conversion_capacity() {
        for heap in [0, 1, 36, 8 * 1024 * 1024] {
            let width = super::super::busy::single_record::METADATA.len();
            let message = message_peak(heap).unwrap();
            let fixed = peak_bytes_for_query(heap, None, width).unwrap() - message;
            assert_eq!(
                single_record_peak_bytes(heap, width).unwrap(),
                3 * message + 4 * fixed + 6 * STATIC_SQLITE_ERROR_BYTES,
            );
        }
        assert!(matches!(
            single_record_peak_bytes(u64::MAX, 0),
            Err(StoreError::Quota)
        ));
        assert!(matches!(
            single_record_peak_bytes(u64::MAX / 18, usize::MAX),
            Err(StoreError::Quota)
        ));
    }

    #[test]
    fn single_record_route_requires_the_actual_reviewed_native_heap() {
        assert!(matches!(
            reviewed_heap(8 << 20, AUDITED_SQLITE_VERSION - 1),
            Err(StoreError::Unsupported {
                capability: "sqlite-diagnostic-reviewed-version"
            })
        ));
        assert_eq!(
            reviewed_heap(8 << 20, AUDITED_SQLITE_VERSION).unwrap(),
            8 << 20
        );
    }
}
