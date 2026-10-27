//! Replay-side event logs held as segment references.
//!
//! A replay side's scheduler log grows with the replayed run, so a capture
//! never holds it whole (RFC-0020 CMEAS-22). It keeps the side's
//! [`AttemptLogManifest`] and read handles to the stores holding the
//! referenced segments, and every reader streams the log one segment at a
//! time.

use super::*;
use crate::{
    AttemptEventLogError, AttemptLogEntries, AttemptLogManifest, AttemptLogSegmentSources,
};

/// The complete scheduler event log of one replay side, by reference.
///
/// The manifest names the log's segments in order; the sources read them.
/// Equality compares the manifests, which identify the entries exactly,
/// never the stores that happen to hold the segment bytes.
#[derive(Clone, Debug)]
pub struct FindingProductionReplayEventLog {
    manifest: AttemptLogManifest,
    segments: AttemptLogSegmentSources,
}

impl PartialEq for FindingProductionReplayEventLog {
    fn eq(&self, other: &Self) -> bool {
        self.manifest == other.manifest
    }
}

impl Eq for FindingProductionReplayEventLog {}

impl FindingProductionReplayEventLog {
    /// Pairs a manifest with the stores that hold its segments.
    ///
    /// Nothing is read here; [`FindingProductionReplayExecutionSide`]
    /// authenticates every segment when it validates the side.
    pub(super) const fn new(
        manifest: AttemptLogManifest,
        segments: AttemptLogSegmentSources,
    ) -> Self {
        Self { manifest, segments }
    }

    /// Returns the ordered segment references identifying the log.
    #[must_use]
    pub const fn manifest(&self) -> &AttemptLogManifest {
        &self.manifest
    }

    /// Returns the number of scheduler entries in the log.
    #[must_use]
    pub const fn entry_count(&self) -> u64 {
        self.manifest.entry_count()
    }

    /// Returns read handles to the stores holding the referenced segments.
    #[must_use]
    pub const fn segments(&self) -> &AttemptLogSegmentSources {
        &self.segments
    }

    /// Returns a pull reader over the entries, one segment at a time.
    ///
    /// Each segment is authenticated against its reference before any of its
    /// entries is yielded.
    #[must_use]
    pub fn entries(&self) -> AttemptLogEntries<'_> {
        self.manifest.entries(&self.segments)
    }

    /// Visits every entry in order.
    ///
    /// # Errors
    ///
    /// Returns an error converted from [`AttemptEventLogError`] when a segment
    /// is missing or fails authentication, or the first error `visit` returns.
    pub fn try_for_each_entry<E: From<AttemptEventLogError>>(
        &self,
        visit: impl FnMut(&SchedulerEventLogEntry) -> Result<(), E>,
    ) -> Result<(), E> {
        self.manifest.try_for_each_entry(&self.segments, visit)
    }

    /// Authenticates every segment and checks each entry against `frontier`.
    ///
    /// The manifest already proves the references are dense from sequence
    /// zero, and decoding a segment proves its entries are dense and carry
    /// valid content hashes. What remains is that no entry lies beyond the
    /// side's terminal frontier.
    pub(super) fn validate(
        &self,
        frontier: VirtualTime,
    ) -> Result<(), FindingProductionReplayCaptureError> {
        self.try_for_each_entry(|entry| {
            if entry.at() > frontier {
                return Err(SideLogError::Invalid);
            }
            Ok(())
        })
        .map_err(|_| FindingProductionReplayCaptureError::InvalidEventLog)
    }
}

/// Failure while validating a side log; every cause is an invalid log.
enum SideLogError {
    Invalid,
}

impl From<AttemptEventLogError> for SideLogError {
    fn from(_: AttemptEventLogError) -> Self {
        Self::Invalid
    }
}
