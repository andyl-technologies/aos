//! Shared import-result reuse for parallel evaluation (L2-P4).
//!
//! Under the P3b demand pool every worker owned a fully private import cache:
//! a helper forcing work that imported a file another worker had already
//! imported re-read, re-parsed, re-remapped, and re-evaluated that file, and
//! published a duplicate module copy into the shared module registry. This
//! module deduplicates that work with the same append-only prefix-replica
//! pattern as the other shared logs:
//!
//! - a worker that completes `import` of a path publishes the finished
//!   [`ImportCacheEntry::Ready`] surface (root value plus impure-trace
//!   bookkeeping) to one [`SharedImportLog`];
//! - every worker merges the log's unseen suffix into its local import cache
//!   before treating an import as a miss, so cross-worker duplication is
//!   bounded to genuinely concurrent first imports of the same file
//!   (first-write-wins on merge, which is confluent: both entries denote the
//!   same evaluation result).
//!
//! Publication order makes the shared values safe to adopt: the importing
//! worker publishes its module, symbols, and any nested import surfaces
//! before the import completes, and consuming the log entry passes through
//! the log mutex (a release/acquire edge) followed by a
//! [`TreeWalk::sync_shared_context`] ingestion sync, so every id reachable
//! from the adopted value resolves locally. In-flight recursion markers
//! ([`ImportCacheEntry::Evaluating`]) are deliberately never published or
//! overwritten: recursion detection stays a per-worker stack property.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use super::*;

/// One published import result, mirroring [`ImportCacheEntry::Ready`].
#[derive(Clone, Debug)]
pub(super) struct SharedImportResult {
    /// The imported file's root value in the shared heap.
    value: Value,
    /// The import's complete impure-input trace, or `None` when incomplete.
    trace: Option<Vec<ImpureInputFingerprint>>,
    /// Whether the force-cache impure trace stayed complete during the import.
    force_cache_trace_complete: bool,
}

/// The append-only shared log of completed import results.
#[derive(Debug, Default)]
pub(crate) struct SharedImportLog {
    /// Published length of `log`; release-stored after each append.
    version: AtomicUsize,
    log: Mutex<Vec<(PathBuf, SharedImportResult)>>,
}

impl SharedImportLog {
    /// Publishes one completed import result for other workers to adopt.
    fn publish(&self, path: &Path, result: SharedImportResult) {
        let mut log = parallel_demand::recover(self.log.lock());
        log.push((path.to_path_buf(), result));
        self.version.store(log.len(), Ordering::Release);
    }

    /// Merges log entries past `cursor` into a worker's local import cache.
    ///
    /// Existing local entries win: a `Ready` entry is already equivalent, and
    /// an `Evaluating` marker must survive for recursion detection (the local
    /// evaluation replaces it with its own equivalent result on completion).
    pub(super) fn sync_into(
        &self,
        cursor: &mut usize,
        local: &mut BTreeMap<PathBuf, ImportCacheEntry>,
    ) {
        if self.version.load(Ordering::Acquire) <= *cursor {
            return;
        }
        let log = parallel_demand::recover(self.log.lock());
        for (path, result) in &log[*cursor..] {
            local
                .entry(path.clone())
                .or_insert_with(|| ImportCacheEntry::Ready {
                    value: result.value,
                    trace: result.trace.clone(),
                    force_cache_trace_complete: result.force_cache_trace_complete,
                });
        }
        *cursor = log.len();
    }
}

impl TreeWalk {
    /// Merges unseen shared import results into the local import cache.
    ///
    /// Called before an import-cache miss is acted on, so a file another
    /// worker finished importing is adopted instead of re-evaluated. Cheap
    /// when already current: one acquire load.
    pub(super) fn sync_shared_import_log(&mut self) {
        let Some(shared) = self.shared.clone() else {
            return;
        };
        shared
            .imports
            .sync_into(&mut self.shared_import_log_cursor, &mut self.import_cache);
    }

    /// Publishes a completed import result to the shared log under parallel mode.
    pub(super) fn publish_shared_import_result(
        &self,
        path: &Path,
        value: Value,
        trace: Option<&[ImpureInputFingerprint]>,
        force_cache_trace_complete: bool,
    ) {
        if let Some(shared) = self.shared.as_ref() {
            shared.imports.publish(
                path,
                SharedImportResult {
                    value,
                    trace: trace.map(<[ImpureInputFingerprint]>::to_vec),
                    force_cache_trace_complete,
                },
            );
            shared.bump_version();
        }
    }
}
