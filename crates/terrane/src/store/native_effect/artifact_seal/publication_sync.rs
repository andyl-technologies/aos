//! Synchronizes retained publication metadata on its original nofollow descriptor.
//!
//! Callers are closed native workers. This helper neither creates an acknowledgment
//! nor accepts a permission callback. Each boundary comes from the actual selected
//! namespace or its independently configured controls. System ancestors are checked
//! by the Frame but are never synchronized as publication directories.

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
