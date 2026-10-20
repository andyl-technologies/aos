//! Owns pure collector records and reachability policy from specification 17.
//!
//! The lease module preserves the registered singleton collector record and
//! pure proposal/ownership checks. Native conditional writes, authoritative
//! time, and physical collection qualification remain backend obligations.
//!
//! ```text
//! GcLease = {1: holder, 2: epoch, 3: expiry}
//! ```
//!
//! Publication codecs carry untrusted record data; native current-root and
//! destructive-effect authorization remain independent backend obligations.

mod journal;
mod lease;
mod mark;
mod proof;
mod records;
mod retention;
mod windows;

pub mod publication;
pub mod retirement;

pub use journal::{
    ArtifactBinding, ArtifactVersion, CreationJournal, DeleteAuthorization, DeleteOperation,
    DeletePhase, JournalState,
};
pub use lease::{GcError, GcLease};
pub use mark::{CommitVisits, MARK_FILTER_BYTES, MarkSet};
pub use proof::ProofContext;
pub use records::{
    CheckpointPointer, ExpandedContext, ExpandedObject, GcMark, GcRoot, GcRoots, GcState, Pending,
    Phase, RootReason,
};
pub use retention::{ParentCutoff, ReflogRetention, RetentionPolicy};
pub use windows::{RetentionTimes, Tombstone, Windows, checkpoint_digest, retains};

use lease::key;
