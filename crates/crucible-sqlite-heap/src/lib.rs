//! Integer-only controls for the process-wide native SQLite allocator.
//!
//! Implementation contract: Integer-only native SQLite allocator limits and usage controls.
//!
//! Module map: `lib.rs` defines [`NativeHeapError`] and the safe limit,
//! usage, high-water and memory-release operations.
//!
//! This boundary initializes the existing linked SQLite library, installs a
//! positive hard limit and reads allocator usage. It owns no connection,
//! resource authority, callback or shutdown operation. Its caller retains the
//! original process budget and closes all managed borrowers before refunding it.
//! Native initialization happens before a new hard limit takes effect; callers
//! must fund that first-entry peak independently.
//!
//! Unsafe boundary discipline: public callers use safe integer-only controls
//! that validate positive representable limits and retain actual native status.
//! The boundary exposes no pointers, callbacks, configuration or shutdown.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::num::NonZeroU64;

use libsqlite3_sys as ffi;

/// Distinguishes invalid limits from actual native initialization failures.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum NativeHeapError {
    /// The positive ceiling cannot be represented by the native interface.
    #[error("SQLite heap ceiling is not representable")]
    InvalidLimit,
    /// The same linked SQLite library failed actual initialization.
    #[error("SQLite allocator initialization failed with native code {code}")]
    Initialization {
        /// The actual native SQLite result code.
        code: i32,
    },
    /// The initialized native allocator refused the requested limit.
    #[error("SQLite allocator refused its positive heap ceiling")]
    LimitRefused,
}

/// Installs an exact positive process-wide hard heap ceiling.
///
/// The operation initializes SQLite before applying the ceiling. A successful
/// return reports current allocator usage, not the initialization high-water.
/// The caller must retain its original credit before entry and coordinate
/// process ownership; this primitive supplies no allocation authority.
///
/// This uses the mutex-enabled linked SQLite allocator's thread-safe controls.
/// It does not reconfigure the library or require other connections to close.
/// Memory safety does not establish that foreign connections are funded by the
/// caller's original authority.
///
/// # Errors
/// Returns the actual SQLite initialization failure or a refused native limit.
pub fn install_limit(maximum: NonZeroU64) -> Result<i64, NativeHeapError> {
    let maximum = i64::try_from(maximum.get()).map_err(|_| NativeHeapError::InvalidLimit)?;

    // SAFETY: SQLite initialization is thread safe. It accepts no pointer or
    // callback and returns the actual initialization status. No global config
    // or shutdown operation is exposed by this boundary.
    let initialized = unsafe { ffi::sqlite3_initialize() };
    if initialized != ffi::SQLITE_OK {
        return Err(NativeHeapError::Initialization { code: initialized });
    }

    // SAFETY: This pinned SQLite API protects its allocator limit with its
    // native mutex. The value is positive and representable; neither a query
    // sentinel nor the unlimited zero value is passed.
    let previous = unsafe { ffi::sqlite3_hard_heap_limit64(maximum) };
    if previous < 0 {
        return Err(NativeHeapError::LimitRefused);
    }
    Ok(memory_used())
}

/// Reads the linked SQLite allocator's current outstanding bytes.
///
/// This thread-safe status query neither initializes nor shuts down SQLite.
/// Zero supplements managed connection closure; it cannot prove that no native
/// handle, VFS resource, foreign actor or operation survives. Meaningful usage
/// accounting requires the pinned memory-status-enabled library configuration.
#[must_use]
pub fn memory_used() -> i64 {
    // SAFETY: The native status API reads protected allocator counters without
    // caller pointers, callbacks or a lifecycle transition.
    unsafe { ffi::sqlite3_memory_used() }
}

/// Reads the linked allocator's recorded high-water without resetting it.
///
/// The process-wide observation includes prior users of this linked library.
/// It supplies measured evidence, never a universal initialization peak bound.
#[must_use]
pub fn memory_highwater() -> i64 {
    // SAFETY: The native status API reads protected scalar counters. Passing
    // zero preserves the high-water and performs no lifecycle transition.
    unsafe { ffi::sqlite3_memory_highwater(0) }
}

/// Requests release of available native cache memory.
///
/// The linked library may implement this as a no-op. The return value reports
/// actual released bytes and is never a connection-close or terminal receipt.
#[must_use]
pub fn release_memory() -> i32 {
    // SAFETY: Cache release is a thread-safe allocator operation with an
    // integer bound. It does not invalidate live connections or shut down the
    // library, and it takes no user pointer or callback.
    unsafe { ffi::sqlite3_release_memory(i32::MAX) }
}
