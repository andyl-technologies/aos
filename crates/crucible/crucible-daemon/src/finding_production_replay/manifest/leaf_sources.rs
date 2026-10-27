//! Blob sources that serve capture leaves without copying them first.
//!
//! A backend reads a leaf only when it copies it, so these adapters hold a
//! shared reference, a segment identity, or a closure frame index and
//! produce the bytes on open. Side-log and side-trace segments share one
//! segment store interface, so one adapter serves each direction for both.

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read};
use std::sync::Arc;

use crucible_engine::ContentHash;
use crucible_store::content_store::{BlobHandle, BlobSource, ContentId, StoreError};

use super::super::FindingProductionReplaySharedContext;
use crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure;
use crucible_engine::segment_store::{MAX_SEGMENT_BYTES, SegmentSource, SegmentSources};

/// Shared immutable bytes a leaf source reads without copying them first.
#[derive(Clone)]
pub(super) enum SharedBytes {
    /// Bytes owned through their own reference count.
    Owned(Arc<[u8]>),
    /// One lifecycle object inside a shared replay context.
    LifecycleObject {
        context: Arc<FindingProductionReplaySharedContext>,
        identity: ContentHash,
    },
}

impl SharedBytes {
    pub(super) fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            // A context never loses an object, so absence cannot occur; an
            // empty read would fail the backend's length and identity checks.
            Self::LifecycleObject { context, identity } => context
                .lifecycle_objects
                .get(identity)
                .map_or(&[][..], Vec::as_slice),
        }
    }
}

pub(super) struct SharedBytesSource(pub(super) SharedBytes);

impl BlobSource for SharedBytesSource {
    fn logical_length(&self) -> u64 {
        self.0.as_slice().len() as u64
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Ok(Box::new(SharedBytesReader {
            bytes: self.0.clone(),
            position: 0,
        }))
    }
}

struct SharedBytesReader {
    bytes: SharedBytes,
    position: usize,
}

impl Read for SharedBytesReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .bytes
            .as_slice()
            .get(self.position..)
            .unwrap_or_default();
        let count = remaining.len().min(buffer.len());
        buffer[..count].copy_from_slice(&remaining[..count]);
        self.position += count;
        Ok(count)
    }
}

/// One side-log or side-trace segment read from its stores when it is copied.
///
/// The backend authenticates the copied bytes against `id`, so a store that
/// holds other bytes under that identity fails the copy.
pub(super) struct SegmentLeafSource {
    pub(super) id: ContentId,
    pub(super) encoded_bytes: u64,
    pub(super) segments: SegmentSources,
}

impl BlobSource for SegmentLeafSource {
    fn logical_length(&self) -> u64 {
        self.encoded_bytes
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        let bytes = self
            .segments
            .segment(self.id)
            .map_err(|source| StoreError::StreamIo {
                operation: "read-finding-replay-segment",
                source,
            })?;
        Ok(Box::new(Cursor::new(bytes)))
    }
}

/// One replay-closure frame read from its closure when it is copied.
pub(super) struct ClosureFrameLeafSource {
    pub(super) closure: GuardedCampaignReplayClosure,
    pub(super) index: usize,
    pub(super) length: u64,
}

impl BlobSource for ClosureFrameLeafSource {
    fn logical_length(&self) -> u64 {
        self.length
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        let bytes = self
            .closure
            .frame_bytes(self.index)
            .map_err(|error| StoreError::StreamIo {
                operation: "read-finding-replay-closure-frame",
                source: io::Error::other(error.to_string()),
            })?;
        Ok(Box::new(Cursor::new(bytes)))
    }
}

/// Serves a loaded side log's or side trace's segments from their published
/// leaf handles.
///
/// Each read is bounded by the per-segment format bound, and the reader
/// authenticates the bytes against the segment reference that named them.
pub(super) struct LeafSegmentSource {
    pub(super) handles: BTreeMap<ContentId, BlobHandle>,
}

impl SegmentSource for LeafSegmentSource {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        let handle = self.handles.get(&id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "finding replay segment leaf absent",
            )
        })?;
        handle
            .read_all(MAX_SEGMENT_BYTES as u64)
            .map_err(io::Error::other)
    }
}
