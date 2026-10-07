//! Prepaid checked SQLite error copies and their last-owner allocation custody.
//!
//! The binding copies SQLite's message before returning an error. Its private
//! connection must therefore have an actual native heap ceiling before this
//! checked route reserves the possible Rust copy. Generic routes are unchanged.

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
pub(super) const PRESENCE_SQL: &str = "SELECT EXISTS(SELECT 1 FROM objects WHERE id = ?1)";
pub(super) const INSERT_SQL: &str = "INSERT INTO objects (id, body) VALUES (?1, ?2)";
pub(super) const SOURCE_SQL: &str = "SELECT substr(body, ?2, ?3) FROM objects WHERE id = ?1";
pub(super) const METADATA_SQL: &str =
    "SELECT instance, generation, checksum FROM metadata WHERE singleton = 1";
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
    native_heap: Option<u64>,
    root: Option<&Path>,
) -> Result<DecodeScratch, StoreError> {
    let heap = native_heap.ok_or(StoreError::Unsupported {
        capability: "sqlite-diagnostic-native-heap-bound",
    })?;
    if rusqlite::version_number() != AUDITED_SQLITE_VERSION {
        return Err(StoreError::Unsupported {
            capability: "sqlite-diagnostic-reviewed-version",
        });
    }
    account()?
        .reserve_scratch_bytes(peak_bytes(heap, root)?)
        .map_err(admission)
}

fn peak_bytes(native_heap: u64, root: Option<&Path>) -> Result<u64, StoreError> {
    // Rust 1.98.1's from_utf8_lossy starts at m bytes, produces at most 3m,
    // and doubles to at most 4m. Its largest reallocation keeps 2m + 4m
    // live. The minimum byte-vector growth is covered when m is below 8.
    // SQLite 3.53.4's dynamic errmsg is native-allocator-backed; its static
    // fallback census is at most 36 bytes. This is a copy geometry bound,
    // rather than an assumption that corrupt-schema messages are short.
    let message = native_heap
        .max(STATIC_SQLITE_ERROR_BYTES)
        .max(MINIMUM_STRING_CAPACITY)
        .checked_mul(6)
        .ok_or(StoreError::Quota)?;

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
    ]
    .into_iter()
    .map(str::len)
    .max()
    .ok_or(StoreError::Quota)?;
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

pub(super) fn lock_path(root: &Path) -> Result<PathBuf, StoreError> {
    let mut path = PathBuf::new();
    path.try_reserve_exact(lock_path_capacity(root)?)
        .map_err(allocation)?;
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
        Err(error) => Err(StoreError::SqliteDiagnostic {
            source: SqliteDiagnosticError {
                error: Box::new(error),
                _credit: credit,
            },
        }),
    }
}
