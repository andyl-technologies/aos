//! Observes committed index membership without reading each requested body.
//!
//! These answers support bounded Distribution negotiation. A positive index
//! entry is not plaintext verification, current authorization, Original custody
//! or an admission receipt. Ordinary content reads still verify their bytes.

use terrane_format::identity::Digest;

use super::{CapabilityReport, StoreFailure};

/// Bounds one committed-index presence request to the protocol hash limit.
pub const MAX_INDEXED_HASHES: usize = 4096;

/// Queries committed, unexcluded index entries independently of body verification.
///
/// Implementations preserve input order and duplicates, using a selected index
/// observation rather than one backing-object probe per hash. An answer of true
/// requires a Live committed index entry whose pack is not tombstoned or otherwise
/// physically excluded. Virtual objects without such an entry are not present.
/// No result grants permission to disclose the existence or contents of an object.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub trait IndexedContent: CapabilityReport {
    /// Returns one committed-index membership bit for each requested digest.
    ///
    /// Empty input returns an empty result without storage I/O. At most
    /// [`MAX_INDEXED_HASHES`] digests are accepted in one call. Content kinds are
    /// already separated by registered digest calculation; this operation does
    /// not infer a kind or read a body from an untrusted digest.
    ///
    /// # Errors
    /// Rejects excessive requests and unavailable, malformed or inconsistent
    /// selected index state. A failure returns no partial membership result.
    async fn indexed_presence(&self, hashes: &[Digest]) -> Result<Vec<bool>, StoreFailure>;
}
