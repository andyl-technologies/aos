//! Enrolls exact signed historical capture dependencies before new owner effects.
//!
//! Administrative history retains old Runtime7, snapshot and settlement roots.
//! Their dependency rows come from the original authenticated archive, rather
//! than a current native callback interpreting historical bytes as live state.

use std::collections::BTreeSet;

use crucible_node_format::{ContentRef, HashRef};

use super::super::{StateLimits, closure::core_references};
use super::capture::Objects;
use super::storage::Object;
use super::{NativeArchiveRecord, StateError, refused};
use crate::node_contract::NodeRuntime;

struct HistoricalRow<'a> {
    archive: &'a NativeArchiveRecord,
    object: &'a Object,
}

pub(super) struct HistoricalCaptureClosure<'a> {
    rows: Vec<HistoricalRow<'a>>,
    bytes: usize,
}

impl<'a> HistoricalCaptureClosure<'a> {
    pub(super) fn prepare(
        runtime: &'a NodeRuntime,
        limits: StateLimits,
    ) -> Result<Self, StateError> {
        let sources = runtime
            .original_capture_archives()
            .map_err(super::super::schema)?;
        let sources: Vec<_> = sources.collect();
        if sources.len() > 65 {
            return Err(refused("historical archive lifetime credit exceeded"));
        }
        let journal = runtime
            .original_capture_journal_with_limit(limits.maximum_record_bytes)
            .map_err(super::super::schema)?;
        if journal.attempts.is_empty() {
            return Ok(Self {
                rows: Vec::new(),
                bytes: 0,
            });
        }
        let roots = core_references(&journal, limits.maximum_record_bytes)?;
        Self::from_roots(&sources, &roots, limits)
    }

    fn from_roots(
        sources: &[&'a NativeArchiveRecord],
        roots: &[ContentRef],
        limits: StateLimits,
    ) -> Result<Self, StateError> {
        if roots.len() > limits.maximum_content_objects {
            return Err(refused("historical root credit exhausted"));
        }
        // All history rows are already authenticated index backing. Their
        // actual complete inventory is a conservative traversal demand even
        // when only a smaller subset is reachable from the current journal.
        let row_credit = sources
            .iter()
            .try_fold(0usize, |total, source| {
                total.checked_add(source.index.objects.len())
            })
            .ok_or_else(|| refused("historical source inventory count overflow"))?;
        let edge_credit = sources
            .iter()
            .flat_map(|source| &source.index.objects)
            .try_fold(0usize, |total, row| {
                total.checked_add(row.dependencies.len())
            })
            .ok_or_else(|| refused("historical source adjacency count overflow"))?;
        if row_credit > limits.maximum_content_objects
            || edge_credit > limits.maximum_dependency_edges
        {
            return Err(refused(
                "historical complete source geometry exceeds credit",
            ));
        }
        let pending_credit = edge_credit
            .checked_add(roots.len())
            .ok_or_else(|| refused("historical pending metadata overflow"))?;
        let row_bytes = row_credit
            .checked_mul(std::mem::size_of::<HistoricalRow<'_>>())
            .ok_or_else(|| refused("historical row bank overflow"))?;
        let pending_bytes = pending_credit
            .checked_mul(std::mem::size_of::<HistoricalRow<'_>>())
            .ok_or_else(|| refused("historical pending bank overflow"))?;
        let map_bytes = row_credit
            .max(1)
            .checked_mul(
                NodeRuntime::capture_map_node_storage::<&ContentRef, ()>()
                    + NodeRuntime::capture_map_node_storage::<&HashRef, ()>(),
            )
            .ok_or_else(|| refused("historical visited banks overflow"))?;
        let requested = row_bytes
            .checked_add(pending_bytes)
            .and_then(|bytes| bytes.checked_add(map_bytes))
            .ok_or_else(|| refused("historical metadata peak overflow"))?;
        if requested > limits.maximum_total_content_bytes {
            return Err(refused("historical metadata exceeds admitted byte credit"));
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(row_credit)
            .map_err(|_| refused("historical row metadata allocation refused"))?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(pending_credit)
            .map_err(|_| refused("historical dependency metadata allocation refused"))?;
        let mut visited: BTreeSet<&ContentRef> = BTreeSet::new();
        let mut hashes: BTreeSet<&HashRef> = BTreeSet::new();
        let mut bytes = 0usize;
        let mut edges = 0usize;

        for root in roots {
            pending.push(find_row(sources, root)?);
        }
        while let Some(row) = pending.pop() {
            if !visited.insert(&row.object.reference) {
                continue;
            }
            if visited.len() > limits.maximum_content_objects {
                return Err(refused("historical typed role credit exhausted"));
            }
            edges = edges
                .checked_add(row.object.dependencies.len())
                .filter(|edges| *edges <= limits.maximum_dependency_edges)
                .ok_or_else(|| refused("historical dependency credit exhausted"))?;
            if hashes.insert(&row.object.reference.hash) {
                bytes = bytes
                    .checked_add(
                        usize::try_from(row.object.reference.length.get())
                            .map_err(super::super::schema)?,
                    )
                    .filter(|bytes| *bytes <= limits.maximum_total_content_bytes)
                    .ok_or_else(|| refused("historical content credit exhausted"))?;
            }
            for dependency in &row.object.dependencies {
                pending.push(find_row(sources, dependency)?);
            }
            rows.push(row);
        }
        rows.sort_by(|left, right| left.object.reference.cmp(&right.object.reference));
        Ok(Self { rows, bytes })
    }

    pub(super) fn geometry(&self) -> (usize, usize) {
        (self.rows.len(), self.bytes)
    }

    pub(super) fn enroll(
        &self,
        objects: &mut Objects<'_>,
        limits: StateLimits,
    ) -> Result<(), StateError> {
        for row in &self.rows {
            let bytes = row
                .archive
                .object_bytes(&row.object.reference, limits.maximum_content_bytes)?;
            objects.insert(
                row.object.reference.clone(),
                &bytes,
                row.object.dependencies.clone(),
            )?;
        }
        objects.check_dependency_credit()
    }
}

fn find_row<'a>(
    sources: &[&'a NativeArchiveRecord],
    reference: &ContentRef,
) -> Result<HistoricalRow<'a>, StateError> {
    let mut original = None;
    for source in sources {
        if let Some(row) = source
            .index
            .objects
            .iter()
            .find(|row| &row.reference == reference)
        {
            if original
                .as_ref()
                .is_some_and(|previous: &HistoricalRow<'_>| {
                    previous.object.dependencies != row.dependencies
                })
            {
                return Err(refused(
                    "historical typed role has conflicting signed dependencies",
                ));
            }
            original = Some(HistoricalRow {
                archive: source,
                object: row,
            });
        }
    }
    original.ok_or_else(|| refused("historical signed capture dependency is absent"))
}

#[cfg(test)]
#[path = "historical_capture_tests.rs"]
mod tests;
