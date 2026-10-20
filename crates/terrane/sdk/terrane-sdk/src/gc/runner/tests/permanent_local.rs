//! Qualifies recurring local passes and collector-only fresh-placement recovery.
//!
//! All owners, leases and acknowledgments come from actual production factories
//! over private temporary storage. Candidate completion never ends ownership.

#![allow(
    clippy::unwrap_used,
    reason = "Genuine temporary-storage witnesses intentionally panic on refusal."
)]

#[path = "permanent_local/faults.rs"]
mod faults;
#[path = "permanent_local/recovery.rs"]
mod recovery;
#[path = "permanent_local/restore.rs"]
mod restore;
#[path = "permanent_local/support.rs"]
mod support;
