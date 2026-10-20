//! Bounds the actual matching hierarchy carriers reached by Source readback.
//!
//! The ordinary codecs and their semantic/error order remain unchanged. This
//! is conservative representation DATA before those codecs, not authority or
//! a replacement decoder. Native and typed complete validators still run.

use std::mem::size_of;

use aos_sandbox_core::SandboxId;
use aos_sandbox_core::source_tree_model::SandboxTreeRecordV1;

use crate::journal::JournalError;

use aos_sandbox_ledger_replay::hierarchy::graph::SandboxTreeV1;
use aos_sandbox_ledger_replay::hierarchy::history::{HierarchyHistoryRecordV1, HierarchyHistoryV1};
use aos_sandbox_ledger_replay::replay::hierarchy_records::evidence_codec::HierarchyProtectedEvidenceV1;
use aos_sandbox_ledger_replay::replay::hierarchy_records::{HierarchyProtectedJournalEnvelopeV1, HierarchyProtectedJournalProjectionV1};
use aos_sandbox_ledger_replay::replay::hierarchy_records::realization::ViewRealizationPlanV1;
use aos_sandbox_ledger_replay::replay::hierarchy_records::recovery::{
    DurableDetachProgressV1, DurableRealizationProgressV1, DurableRealizationTransactionV1,
};

/// Matches the actual hierarchy kind to its closed Native namespace.
pub(crate) fn matches_namespace(key: &[u8], namespace: crate::RecordNamespace) -> bool {
    aos_sandbox_ledger_replay::geometry::hierarchy::matches_namespace(key, namespace)
}

/// Prices the actual matching hierarchy row before its typed decoder.
///
/// # Errors
/// Returns a checked representation-overflow error; canonical acceptance stays
/// with the unchanged ordinary decoder.
pub(crate) fn row_geometry(
    key: &[u8],
    bytes: &[u8],
) -> Result<(usize, usize, usize), JournalError> {
    aos_sandbox_ledger_replay::geometry::hierarchy::row_geometry(key, bytes).map_err(JournalError::from)
}

// Borrows structural DATA without authenticating a member, envelope or reducer.
// Invalid digests may overprice a later refusal; no typed decoder can reach an
// artifact hidden beyond these same complete enclosing lengths. The ordinary
// protocol decoder remains the sole source of canonical/semantic acceptance.
fn reducer_body(bytes: &[u8]) -> Option<&[u8]> {
    aos_sandbox_ledger_replay::geometry::hierarchy::reducer_body(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrapped(body: &[u8]) -> Vec<u8> {
        let mut payload = b"AOSRDP01".to_vec();
        payload.resize(20, 0);
        payload[16..20].copy_from_slice(&(body.len() as u32).to_be_bytes());
        payload.extend_from_slice(body);
        payload.extend_from_slice(&[0; 32]);
        let mut envelope = b"AOSHTJ01".to_vec();
        envelope.resize(56, 0);
        envelope[52..56].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        envelope.extend_from_slice(&payload);
        envelope.extend_from_slice(&[0; 32]);
        let mut member = b"AOSDTX01".to_vec();
        member.resize(68, 0);
        member[64..68].copy_from_slice(&(envelope.len() as u32).to_be_bytes());
        member.extend_from_slice(&envelope);
        member.extend_from_slice(&[0; 32]);
        member
    }

    #[test]
    fn structural_body_loan_preserves_the_actual_nested_slice_without_validation() {
        let body = b"AOSHRP01\0\x01\0\0actual held body";
        let member = wrapped(body);

        let borrowed = reducer_body(&member).unwrap();

        assert_eq!(borrowed, body);
        assert_eq!(borrowed.as_ptr(), member[144..].as_ptr());
        // The fixture has zero commitments and is deliberately not authority.
    }

    #[test]
    fn incomplete_enclosing_length_cannot_hide_a_reached_artifact_body() {
        let mut member = wrapped(b"AOSHRP01\0\x01\0\0");
        member.pop();

        assert!(reducer_body(&member).is_none());
    }
}
