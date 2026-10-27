//! Sealed event-log segments named by exact checkpoints and hot-fork continuations.
//!
//! A scheduler continuation references its log's sealed segments by identity
//! and carries only the open tail. Capture, publication, restore, and
//! hot-fork admission therefore never collect the segments: they check
//! presence, or copy and authenticate one segment at a time, from wherever
//! the referencing closure keeps them (RFC-0020 CMEAS-28).
//!
//! ```text
//! live capture / local closure / hot fork   ->  content-addressed store
//! repository-authenticated closure          ->  repository object opener
//! ```

use std::fmt;
use std::io::{self, Read};
use std::sync::Arc;

use crucible_engine::attempt_log::MAX_ATTEMPT_LOG_SEGMENT_BYTES;
use crucible_engine::{ContentHash, DagStore, EventLogSegmentReader, EventLogSegmentRef};

use super::SingleSchedulerCheckpoint;

/// Opener for one immutable object of a repository-authenticated closure.
pub(super) type ClosureObjectOpener =
    Arc<dyn Fn(ContentHash) -> io::Result<Box<dyn Read + Send>> + Send + Sync>;

/// Read access to the sealed event-log segments one checkpoint references.
///
/// The value holds no segment bytes. Readers obtain each segment through
/// [`EventLogSegmentReader`], typically by passing this value to
/// [`SingleSchedulerCheckpoint::event_log_entries`], and authenticate it
/// against its reference before decoding.
#[derive(Clone)]
pub struct ProductionEventLogSegments {
    source: SegmentSource,
}

#[derive(Clone)]
enum SegmentSource {
    /// A content-addressed store, such as a run's checkpoint object directory.
    Store(Arc<dyn DagStore>),
    /// The object opener of a repository-authenticated closure.
    Repository(ClosureObjectOpener),
}

impl ProductionEventLogSegments {
    /// Reads segments from a content-addressed store.
    pub(super) fn store(store: Arc<dyn DagStore>) -> Self {
        Self {
            source: SegmentSource::Store(store),
        }
    }

    /// Reads segments through a repository-authenticated closure's opener.
    pub(super) fn repository(open: ClosureObjectOpener) -> Self {
        Self {
            source: SegmentSource::Repository(open),
        }
    }

    /// Checks that every segment `scheduler` references can be read.
    ///
    /// A store is asked for presence only. A repository closure's inventory
    /// was authenticated when the closure was decoded, so it is not reopened.
    pub(super) fn verify_present(&self, scheduler: &SingleSchedulerCheckpoint) -> io::Result<()> {
        let SegmentSource::Store(store) = &self.source else {
            return Ok(());
        };
        for segment in scheduler.event_log_segments() {
            if !store.exists(&segment.object).map_err(io::Error::other)? {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "sealed event-log segment {} is absent",
                        segment.object.to_hex()
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Copies each segment `scheduler` references into `destination`.
    ///
    /// Segments already present stay in place; the restore that reads them
    /// authenticates their contents. Each copied segment is read, checked
    /// against its reference's length and content hash, written, and dropped
    /// before the next one is read.
    pub(super) fn hydrate(
        &self,
        scheduler: &SingleSchedulerCheckpoint,
        destination: &dyn DagStore,
    ) -> io::Result<()> {
        for segment in scheduler.event_log_segments() {
            if destination
                .exists(&segment.object)
                .map_err(io::Error::other)?
            {
                continue;
            }
            let bytes = self.read_authenticated(segment)?;
            let stored = destination.put(&bytes).map_err(io::Error::other)?;
            if stored != segment.object {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "destination store returned another sealed-segment identity",
                ));
            }
        }
        Ok(())
    }

    /// Reads one segment and checks its length and content hash.
    pub(super) fn read_authenticated(&self, segment: &EventLogSegmentRef) -> io::Result<Vec<u8>> {
        let bytes = self.read_event_log_segment(segment)?;
        if u64::try_from(bytes.len()).ok() != Some(segment.encoded_bytes)
            || ContentHash::from_bytes(&bytes) != segment.object
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "sealed event-log segment {} failed content authentication",
                    segment.object.to_hex()
                ),
            ));
        }
        Ok(bytes)
    }
}

impl EventLogSegmentReader for ProductionEventLogSegments {
    fn read_event_log_segment(&self, segment: &EventLogSegmentRef) -> io::Result<Vec<u8>> {
        let limit = segment.encoded_bytes;
        if limit > MAX_ATTEMPT_LOG_SEGMENT_BYTES as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sealed event-log segment exceeds its byte bound",
            ));
        }
        match &self.source {
            SegmentSource::Store(store) => store.get(&segment.object).map_err(io::Error::other),
            SegmentSource::Repository(open) => {
                let mut bytes = Vec::new();
                open(segment.object)?
                    .take(limit.saturating_add(1))
                    .read_to_end(&mut bytes)?;
                Ok(bytes)
            }
        }
    }
}

impl fmt::Debug for ProductionEventLogSegments {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match self.source {
            SegmentSource::Store(_) => "store",
            SegmentSource::Repository(_) => "repository",
        };
        formatter
            .debug_struct("ProductionEventLogSegments")
            .field("source", &source)
            .finish()
    }
}
