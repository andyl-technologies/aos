//! Defines actual native publication synchronization boundaries.
//!
//! The outputs child synchronizes exact producer writes and consumed Original
//! controls while preserving complete Frame checks at each effect boundary.

#[path = "publication_sync/outputs.rs"]
pub(super) mod outputs;

use super::PathBuf;

/// Describes one actual Frame boundary without constructing a native result.
pub(super) struct SyncScope {
    /// Actual selected namespace or configured control directory.
    pub(super) path: PathBuf,
    /// Actual configured owner checked by the corresponding selected producer.
    pub(super) owner: u32,
    /// Distinguishes protected controls from namespace payloads.
    pub(super) protected: bool,
}
