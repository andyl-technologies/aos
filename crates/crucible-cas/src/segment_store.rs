//! Content-addressed storage shared by every segmented log.
//!
//! RFC-0020 section 15 retains run-length logs as sealed, content-addressed
//! segments plus a small open tail. Two logs use that shape: the executor's
//! attempt event log and the fault runtime's resolved-effect trace. Both seal
//! by the same rule ([`SEGMENT_TARGET_BYTES`], [`MAX_SEGMENT_BYTES`]), both
//! bound one manifest to [`MAX_MANIFEST_SEGMENTS`] segments, and both read and
//! write segments through the traits in this module, so one attempt directory,
//! one prepared-result journal, and one set of read handles serve either log.
//!
//! - [`SegmentSource`] reads one segment by its content identity. Readers
//!   authenticate every segment they receive against the reference that named
//!   it, so a source only returns the bytes it holds under an identity.
//! - [`SegmentSink`] additionally stores sealed segments. It is shared by
//!   reference (`&self`), because a fault runtime and its checkpoints keep
//!   writing into the store their owner supplied.
//! - [`SharedSegmentStore`] keeps segments in memory for in-process callers,
//!   transport bundles, and tests.
//! - [`SegmentSources`] chains read handles to several stores, for results
//!   whose segments were sealed into more than one place.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};

pub use crate::content_store::ContentId;

/// Encoded tail size before which a segmented log seals its open tail.
///
/// A log seals before an append would make the tail's encoding exceed this
/// target, so seal points depend only on the appended sequence (CCOMP-26).
pub const SEGMENT_TARGET_BYTES: usize = 8 * 1024 * 1024;

/// Largest encoded segment any writer produces or reader accepts.
pub const MAX_SEGMENT_BYTES: usize = 16 * 1024 * 1024;

/// Largest number of segments one manifest may reference.
///
/// A manifest and its segments are published as the evidence children of one
/// campaign record, whose evidence set holds at most 4,096 objects.
pub const MAX_MANIFEST_SEGMENTS: usize = 4_095;

/// Read access to sealed segments, addressed by content identity.
pub trait SegmentSource {
    /// Reads one encoded segment.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the segment is absent, unreadable, or larger
    /// than [`MAX_SEGMENT_BYTES`].
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>>;
}

/// Shared, writable storage for the segments a running log seals.
pub trait SegmentSink: SegmentSource + Send + Sync {
    /// Stores one encoded segment under its identity.
    ///
    /// Segments are immutable and content-addressed, so storing an identity
    /// that is already present succeeds without rewriting it.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the segment cannot be durably written, or
    /// when `bytes` do not derive `id`.
    fn put_segment(&self, id: ContentId, bytes: &[u8]) -> io::Result<()>;
}

/// In-memory segment store shared by every clone.
///
/// Segments are keyed by the identity their bytes derive, so the store never
/// holds bytes under a foreign identity. Sealed bytes are immutable and
/// reference-counted, so reading a segment copies it once.
#[derive(Clone, Default)]
pub struct SharedSegmentStore {
    segments: Arc<Mutex<BTreeMap<ContentId, Arc<[u8]>>>>,
}

impl SharedSegmentStore {
    /// Builds an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of stored segments.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when a prior panic poisoned the store.
    pub fn len(&self) -> io::Result<usize> {
        Ok(self.lock()?.len())
    }

    /// Returns whether no segment is stored.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when a prior panic poisoned the store.
    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.lock()?.is_empty())
    }

    /// Returns whether a segment with `id` is stored.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when a prior panic poisoned the store.
    pub fn contains(&self, id: ContentId) -> io::Result<bool> {
        Ok(self.lock()?.contains_key(&id))
    }

    /// Returns the total encoded bytes of every stored segment.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when a prior panic poisoned the store.
    pub fn total_bytes(&self) -> io::Result<u64> {
        Ok(self
            .lock()?
            .values()
            .map(|bytes| bytes.len() as u64)
            .fold(0, u64::saturating_add))
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, BTreeMap<ContentId, Arc<[u8]>>>> {
        self.segments
            .lock()
            .map_err(|_| io::Error::other("shared segment store lock is poisoned"))
    }
}

impl SegmentSource for SharedSegmentStore {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        self.lock()?
            .get(&id)
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "segment absent"))
    }
}

impl SegmentSink for SharedSegmentStore {
    fn put_segment(&self, id: ContentId, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > MAX_SEGMENT_BYTES || !id.authenticates(bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "segment bytes do not derive their identity",
            ));
        }
        self.lock()?.entry(id).or_insert_with(|| Arc::from(bytes));
        Ok(())
    }
}

impl fmt::Debug for SharedSegmentStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let segments = self.segments.lock().map_or(0, |segments| segments.len());
        formatter
            .debug_struct("SharedSegmentStore")
            .field("segments", &segments)
            .finish()
    }
}

/// Shared read handles to every store that may hold a log's segments.
///
/// A result references its segments by identity and keeps these handles
/// instead of the bytes, so its size does not grow with the log. Lookups try
/// each store in order. Every reader authenticates the bytes it receives
/// against the referencing segment reference, so a store that lacks a
/// segment, or holds foreign bytes under its name, can only make a read fail.
#[derive(Clone, Default)]
pub struct SegmentSources {
    sources: Vec<Arc<dyn SegmentSource + Send + Sync>>,
}

impl SegmentSources {
    /// Reads through exactly one store.
    #[must_use]
    pub fn single(source: Arc<dyn SegmentSource + Send + Sync>) -> Self {
        Self {
            sources: vec![source],
        }
    }

    /// Adds `source` after every store already held.
    pub fn push(&mut self, source: Arc<dyn SegmentSource + Send + Sync>) {
        self.sources.push(source);
    }

    /// Adds every store of `other` after the stores already held.
    pub fn extend(&mut self, other: Self) {
        self.sources.extend(other.sources);
    }

    /// Returns whether no store is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

impl fmt::Debug for SegmentSources {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SegmentSources")
            .field("stores", &self.sources.len())
            .finish()
    }
}

impl From<SharedSegmentStore> for SegmentSources {
    fn from(store: SharedSegmentStore) -> Self {
        Self::single(Arc::new(store))
    }
}

impl SegmentSource for SegmentSources {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        let mut last_error = None;
        for source in &self.sources {
            match source.segment(id) {
                Ok(bytes) => return Ok(bytes),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "segment absent")))
    }
}

#[cfg(test)]
mod tests {
    use crate::content_store::ObjectKind;

    use super::*;

    #[test]
    fn shared_store_rejects_bytes_under_a_foreign_identity() {
        let store = SharedSegmentStore::new();
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"segment");

        let refused = store.put_segment(id, b"other");

        assert!(refused.is_err());
        assert!(!store.contains(id).unwrap_or(true));
    }

    #[test]
    fn sources_fall_through_to_the_store_holding_a_segment() {
        let first = SharedSegmentStore::new();
        let second = SharedSegmentStore::new();
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"segment");
        second
            .put_segment(id, b"segment")
            .unwrap_or_else(|error| panic!("put: {error}"));
        let mut sources = SegmentSources::from(first);
        sources.push(Arc::new(second));

        let bytes = sources.segment(id);

        assert_eq!(bytes.ok().as_deref(), Some(&b"segment"[..]));
    }
}
