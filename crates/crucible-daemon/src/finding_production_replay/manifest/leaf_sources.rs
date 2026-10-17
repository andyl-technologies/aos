//! Blob sources that serve capture leaves without copying them first.
//!
//! A backend reads a leaf only when it copies it, so these adapters hold a
//! shared reference, a segment reference, or a closure frame index and
//! produce the bytes on open.

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read};
use std::sync::Arc;

use crucible::ContentHash;
use crucible_cas::content_store::{BlobHandle, BlobSource, ContentId, StoreError};

use super::super::FindingProductionReplaySharedContext;
use crate::qemu_campaign_lifecycle::GuardedCampaignReplayClosure;
use crate::{
    AttemptLogSegmentRef, AttemptLogSegmentSource, AttemptLogSegmentSources,
    MAX_ATTEMPT_LOG_SEGMENT_BYTES,
};

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

/// One side-log segment read from the side's stores when it is copied.
pub(super) struct SegmentLeafSource {
    pub(super) segment: AttemptLogSegmentRef,
    pub(super) segments: AttemptLogSegmentSources,
}

impl BlobSource for SegmentLeafSource {
    fn logical_length(&self) -> u64 {
        self.segment.encoded_bytes
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        let bytes =
            self.segments
                .segment(self.segment.id)
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

/// Serves a loaded side log's segments from their published leaf handles.
pub(super) struct LeafSegmentSource {
    pub(super) handles: BTreeMap<ContentId, BlobHandle>,
}

impl AttemptLogSegmentSource for LeafSegmentSource {
    fn segment(&self, id: ContentId) -> io::Result<Vec<u8>> {
        let handle = self.handles.get(&id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "finding replay segment leaf absent",
            )
        })?;
        handle
            .read_all(MAX_ATTEMPT_LOG_SEGMENT_BYTES as u64)
            .map_err(io::Error::other)
    }
}
