//! One-shot ownership and complete observation of process-start descriptors.
//!
//! This module is the sole raw-descriptor boundary for Mount-manager startup
//! capture. The one unsafe constructor expresses the unavoidable Rust I/O
//! ownership transfer. It accepts no environment-derived role, name, expected
//! object, or durable-state claim. Successful capture returns only safe,
//! opaque, move-only owners and read-only kernel projections.

mod execution;
mod model;
mod scan;

pub use model::*;

use std::sync::atomic::{AtomicU8, Ordering};

use crate::{Error, Result};

const CAPTURE_FRESH: u8 = 0;
const CAPTURE_RUNNING: u8 = 1;
const CAPTURE_SUCCEEDED: u8 = 2;
const CAPTURE_POISONED: u8 = 3;

static CAPTURE_STATE: AtomicU8 = AtomicU8::new(CAPTURE_FRESH);

/// Claims and double-observes the complete initial process descriptor table.
///
/// The capture scans every numeric `/proc/self/fd` entry rather than trusting
/// `LISTEN_FDS`. Activation environment values are copied only as bounded,
/// nonauthoritative hints. Every original is correlated with a retained
/// duplicate through `kcmp(KCMP_FILE)` before ownership transfer.
/// Blockable signals are fenced around scanning, duplication, observation, and
/// closure, then the exact calling-thread mask is restored on every return.
///
/// # Safety
///
/// The caller must be the single-threaded process startup owner, must
/// exclusively own every descriptor present before this call, and must ensure
/// no `File`, `OwnedFd`, or other I/O-safe owner has been constructed for those
/// numeric descriptors. No other code may open, close, duplicate, or replace a
/// descriptor or mutate the activation environment until this call returns.
/// Signal dispositions must already be fixed for process startup; this call
/// temporarily changes only the calling thread's signal mask.
///
/// This ownership assertion cannot be inferred from an FD scan. A completely
/// safe alternative requires a separate launcher to transfer owned descriptors
/// with `SCM_RIGHTS`.
///
/// # Errors
///
/// Returns an error for repeated capture, multiple threads, malformed procfs,
/// an exceeded bound, an unstable table or object, missing fs-verity/build
/// identity, changed execution or launcher provenance, or any kernel failure.
/// Every failed attempt permanently poisons capture in this process.
pub unsafe fn claim_initial_process_fd_table_once(
    limits: StartupFdCaptureHardLimitsV1,
) -> Result<ClaimedInitialProcessFdTableV1> {
    CAPTURE_STATE
        .compare_exchange(
            CAPTURE_FRESH,
            CAPTURE_RUNNING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| Error::invalid("startup FD capture", "capture was already attempted"))?;

    let result = limits.validate().and_then(|()| {
        // SAFETY: this function forwards its documented exclusive-ownership
        // and single-threaded preconditions to the only raw implementation.
        unsafe { scan::claim_initial_process_fd_table(limits) }
    });
    CAPTURE_STATE.store(
        if result.is_ok() {
            CAPTURE_SUCCEEDED
        } else {
            CAPTURE_POISONED
        },
        Ordering::Release,
    );
    result
}
