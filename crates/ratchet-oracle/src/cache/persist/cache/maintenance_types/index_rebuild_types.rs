//! Blob-index rebuild diagnostics.

use super::*;

/// A sidecar entry that would be replaced by a blob-index rebuild.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistBlobIndexStaleEntry {
    current: PersistBlobIndexEntry,
    planned: PersistBlobIndexEntry,
}

impl PersistBlobIndexStaleEntry {
    /// Creates a stale-entry diagnostic from current and planned index entries.
    pub const fn new(current: PersistBlobIndexEntry, planned: PersistBlobIndexEntry) -> Self {
        Self { current, planned }
    }

    /// Returns the newest sidecar entry currently present for this blob key.
    pub const fn current(self) -> PersistBlobIndexEntry {
        self.current
    }

    /// Returns the verified physical pack entry a rebuild would install.
    pub const fn planned(self) -> PersistBlobIndexEntry {
        self.planned
    }
}

/// Read-only diagnostics for rebuilding one blob-index sidecar from its pack.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistBlobIndexRebuildPlan {
    planned_entries: Vec<PersistBlobIndexEntry>,
    missing_entries: Vec<PersistBlobIndexEntry>,
    stale_entries: Vec<PersistBlobIndexStaleEntry>,
    dangling_entries: Vec<PersistBlobIndexEntry>,
}

impl PersistBlobIndexRebuildPlan {
    pub(in crate::cache::persist::cache) fn new(
        planned_entries: Vec<PersistBlobIndexEntry>,
        missing_entries: Vec<PersistBlobIndexEntry>,
        stale_entries: Vec<PersistBlobIndexStaleEntry>,
        dangling_entries: Vec<PersistBlobIndexEntry>,
    ) -> Self {
        Self {
            planned_entries,
            missing_entries,
            stale_entries,
            dangling_entries,
        }
    }

    /// Returns the complete newest physical pack entries a rebuild would write.
    pub fn planned_entries(&self) -> &[PersistBlobIndexEntry] {
        &self.planned_entries
    }

    /// Returns verified physical pack entries absent from the sidecar.
    pub fn missing_entries(&self) -> &[PersistBlobIndexEntry] {
        &self.missing_entries
    }

    /// Returns sidecar entries whose blob key points at an older or invalid location.
    pub fn stale_entries(&self) -> &[PersistBlobIndexStaleEntry] {
        &self.stale_entries
    }

    /// Returns sidecar entries with no verified physical record in the selected pack.
    pub fn dangling_entries(&self) -> &[PersistBlobIndexEntry] {
        &self.dangling_entries
    }

    /// Returns whether newest sidecar lookups differ from the verified pack scan.
    ///
    /// This reports semantic lookup repair only. It does not report older
    /// append-only sidecar records that a future rewrite would canonicalize
    /// away when the newest entry for each key already matches the pack.
    pub fn lookup_repair_needed(&self) -> bool {
        !self.missing_entries.is_empty()
            || !self.stale_entries.is_empty()
            || !self.dangling_entries.is_empty()
    }
}

/// Plans returned by rebuilding both blob-index sidecars.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistBlobIndexRebuild {
    value_blob_index: PersistBlobIndexRebuildPlan,
    file_blob_index: PersistBlobIndexRebuildPlan,
}

impl PersistBlobIndexRebuild {
    pub(in crate::cache::persist::cache) const fn new(
        value_blob_index: PersistBlobIndexRebuildPlan,
        file_blob_index: PersistBlobIndexRebuildPlan,
    ) -> Self {
        Self {
            value_blob_index,
            file_blob_index,
        }
    }

    /// Returns the rebuild plan applied to the `values/` blob index.
    pub fn value_blob_index(&self) -> &PersistBlobIndexRebuildPlan {
        &self.value_blob_index
    }

    /// Returns the rebuild plan applied to the `files/` blob index.
    pub fn file_blob_index(&self) -> &PersistBlobIndexRebuildPlan {
        &self.file_blob_index
    }

    /// Returns whether either applied plan observed pre-rebuild lookup differences.
    pub fn lookup_repair_needed(&self) -> bool {
        self.value_blob_index.lookup_repair_needed() || self.file_blob_index.lookup_repair_needed()
    }
}
