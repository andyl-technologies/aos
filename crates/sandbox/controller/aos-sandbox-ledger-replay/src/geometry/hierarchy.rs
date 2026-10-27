//! Bounds the actual matching hierarchy carriers reached by Source readback.
//!
//! The ordinary codecs and their semantic/error order remain unchanged. This
//! is conservative representation DATA before those codecs, not authority or
//! a replacement decoder. Native and typed complete validators still run.

use std::mem::size_of;

use aos_sandbox_model::SandboxId;
use aos_sandbox_model::source_tree_model::SandboxTreeRecordV1;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;

use crate::hierarchy::graph::SandboxTreeV1;
use crate::hierarchy::history::{HierarchyHistoryRecordV1, HierarchyHistoryV1};
use crate::replay::hierarchy_records::evidence_codec::HierarchyProtectedEvidenceV1;
use crate::replay::hierarchy_records::{HierarchyProtectedJournalEnvelopeV1, HierarchyProtectedJournalProjectionV1};
use crate::replay::hierarchy_records::realization::ViewRealizationPlanV1;
use crate::replay::hierarchy_records::recovery::{
    DurableDetachProgressV1, DurableRealizationProgressV1, DurableRealizationTransactionV1,
};

/// Matches the actual hierarchy kind to its closed Native namespace.
pub fn matches_namespace(key: &[u8], namespace: aos_sandbox_model::RecordNamespace) -> bool {
    match key.get(b"\0aos-hierarchy-v1\0".len() + 1).copied() {
        Some(1 | 2 | 6 | 7) => namespace == aos_sandbox_model::RecordNamespace::DesiredState,
        Some(3 | 4) => namespace == aos_sandbox_model::RecordNamespace::Effect,
        Some(5) => namespace == aos_sandbox_model::RecordNamespace::RuntimeGeneration,
        _ => false,
    }
}

/// Prices the actual matching hierarchy row before its typed decoder.
///
/// # Errors
/// Returns a checked representation-overflow error; canonical acceptance stays
/// with the unchanged ordinary decoder.
pub fn row_geometry(
    key: &[u8],
    bytes: &[u8],
) -> Result<(usize, usize, usize), JournalError> {
    let invalid = || JournalError::LimitExceeded("Source hierarchy receiving geometry");
    let common = size_of::<HierarchyProtectedJournalEnvelopeV1>()
        + size_of::<HierarchyProtectedJournalProjectionV1>();
    let kind = key.get(b"\0aos-hierarchy-v1\0".len() + 1).copied();
    let (row, dynamic, cells) = match kind {
        Some(1) => {
            // decode_tree_v1 checks the COMPLETE fixed-count encoded width
            // before reserving records or tombstones. Header/envelope bytes
            // conservatively add capacity here; absent advertised rows do not.
            let records = bytes.len() / 58;
            let tombstones = bytes.len() / 16;
            let record = size_of::<SandboxTreeRecordV1>() + 10 * size_of::<(SandboxId, usize)>()
                + 4 * size_of::<SandboxId>() + 14 * size_of::<[usize; 3]>();
            let memory = records.checked_mul(record)
                .and_then(|memory| memory.checked_add(tombstones.checked_mul(size_of::<SandboxId>() + size_of::<[usize; 3]>())?))
                .and_then(|memory| memory.checked_mul(32)).ok_or_else(invalid)?;
            let cells = records.checked_mul(14).and_then(|cells| cells.checked_add(tombstones))
                .and_then(|cells| cells.checked_mul(32)).ok_or_else(invalid)?;
            (size_of::<SandboxTreeV1>() + size_of::<crate::replay::tree_lineage::ClosedTreeLineageHeadV1>(), memory, cells)
        }
        Some(2) => {
            // Complete history and fixed single-record forms validate widths
            // before allocation. Using the minimum 16-byte identity element
            // also covers compacted-history floor maps and retained suffixes.
            let count = bytes.len() / 16;
            let width = size_of::<HierarchyHistoryRecordV1>() + size_of::<[usize; 3]>();
            (size_of::<HierarchyHistoryV1>(), count.checked_mul(width)
                .and_then(|memory| memory.checked_mul(32)).ok_or_else(invalid)?,
                count.checked_mul(32).ok_or_else(invalid)?)
        }
        Some(3 | 4) => {
            // The same artifact cursor measures actual declared reserves,
            // including a count reached immediately before EOF. Current and
            // prospective matching effects remain distinct resident owners.
            let (memory, cells) = match reducer_body(bytes) {
                Some(body) => crate::replay::hierarchy_records::artifact_codec::allocation_frontier(body)?,
                None => (0, 0),
            };
            let memory = memory.checked_mul(32).ok_or_else(invalid)?;
            let cells = cells.checked_mul(32).ok_or_else(invalid)?;
            (size_of::<ViewRealizationPlanV1>() + size_of::<DurableRealizationTransactionV1>()
                + size_of::<DurableRealizationProgressV1>() + size_of::<DurableDetachProgressV1>(), memory, cells)
        }

        Some(6) => (size_of::<HierarchyProtectedEvidenceV1>(), 0, 0),
        Some(7) => (size_of::<crate::replay::hierarchy_records::lineage::ClosedTreeLineageRecordV1>(), 0, 0),
        // Checkpoints and malformed/unrecognized kinds still reach fixed key,
        // envelope and candidate representation before their typed refusal.
        _ => (0, 0, 0),
    };
    Ok((common.checked_add(row).ok_or_else(invalid)?, dynamic, cells))
}

// Borrows structural DATA without authenticating a member, envelope or reducer.
// Invalid digests may overprice a later refusal; no typed decoder can reach an
// artifact hidden beyond these same complete enclosing lengths. The ordinary
// protocol decoder remains the sole source of canonical/semantic acceptance.
/// Borrows the same complete nested reducer bytes without authenticating them.
///
/// Malformed lengths remain subject to the original canonical decoder.
#[doc(hidden)]
pub fn reducer_body(bytes: &[u8]) -> Option<&[u8]> {
    fn u32_at(bytes: &[u8], offset: usize) -> Option<usize> {
        let end = offset.checked_add(4)?;
        usize::try_from(u32::from_be_bytes(bytes.get(offset..end)?.try_into().ok()?)).ok()
    }

    let envelope = if bytes.starts_with(b"AOSDTX01") {
        let end = 68_usize.checked_add(u32_at(bytes, 64)?)?;
        if bytes.len() != end.checked_add(32)? { return None; }
        bytes.get(68..end)?
    } else {
        bytes
    };
    if !envelope.starts_with(b"AOSHTJ01") { return None; }
    let end = 56_usize.checked_add(u32_at(envelope, 52)?)?;
    if envelope.len() != end.checked_add(32)? { return None; }
    let payload = envelope.get(56..end)?;
    if !payload.starts_with(b"AOSRDP01") { return None; }
    let companions = usize::from(u16::from_be_bytes(payload.get(14..16)?.try_into().ok()?));
    let start = 20_usize.checked_add(companions.checked_mul(32)?)?;
    let end = start.checked_add(u32_at(payload, 16)?)?;
    if payload.len() != end.checked_add(32)? { return None; }
    payload.get(start..end)
}
