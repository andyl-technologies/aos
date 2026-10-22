//! Supplies complete candidate names from an actual reference authority.
//!
//! Enumeration is separate from ordinary point reads: individually readable
//! refs and filesystem directory entries cannot establish a complete inventory.
//! Names may remain registered after deletion or a losing initial publication.

use super::{RefStore, StoreFailure};

/// Enumerates authoritative candidate names without granting read authority.
///
/// Each name still requires a fresh guarded point read. Implementations must
/// refuse when completeness is unavailable, including unmigrated legacy state.
/// An inventory is not a snapshot of the live records or a proof of existence.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait RefInventory: RefStore {
    /// Reads the complete registered ref-name inventory.
    ///
    /// # Errors
    /// Rejects unavailable completeness, malformed administrative state, and
    /// backend failures. It never substitutes a directory or point-read scan.
    async fn ref_names(&self) -> Result<Vec<String>, StoreFailure>;
}
