//! Retains Source Tree, Lineage and History work at the real schema invocation.
//!
//! Full Native replay precedes the Source17 projection. The new purpose borrows
//! only its actual project's Tree/Lineage rows; other ordinary schema families
//! retain the same validator and acceptance semantics.

use aos_sandbox_protocol::domain_ledger::records::ProtectedDomainSchemaReplayCaptureV1;
use super::*;
use crate::hierarchy::codec::{
    HierarchyCodecError, TreeDecodeOriginalsV1, decode_tree_retaining_v1,
    HistoryDecodeOriginalsV1, CanonicalEncodingOriginalsV1, encode_tree_retaining_v1,
    decode_history_retaining_v1, encode_history_retaining_v1,
};
use super::lineage::{LineageDecodeOriginalsV1, decode_lineage_retaining_v1};

/// Contains only pure typed parser work, never a receiving or journal grant.
pub struct SourceTreeSchemaOriginalsV1 {
    tree: Option<TreeDecodeOriginalsV1>,
    encoded: Option<CanonicalEncodingOriginalsV1>,
    lineage: Option<LineageDecodeOriginalsV1>,
    history: Option<HistoryDecodeOriginalsV1>,
    history_encoding: Option<CanonicalEncodingOriginalsV1>,
    history_record: Option<Result<crate::hierarchy::history::HierarchyHistoryRecordV1, HierarchyCodecError>>,
    history_record_encoding: Option<Result<[u8; 262], HierarchyCodecError>>,
    accepted: Option<bool>,
    closed: bool,
}

impl SourceTreeSchemaOriginalsV1 {
    pub const fn new() -> Self {
        Self {
            tree: None, encoded: None, lineage: None,
            history: None, history_encoding: None,
            history_record: None, history_record_encoding: None,
            accepted: None, closed: false,
        }
    }

    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.tree.as_ref().and_then(|tree| tree.failure())
            .or_else(|| self.encoded.as_ref().and_then(|encoding| encoding.failure()))
            .or_else(|| self.lineage.as_ref().and_then(|lineage| lineage.failure()))
            .or_else(|| self.history.as_ref().and_then(|history| history.failure()))
            .or_else(|| self.history_encoding.as_ref().and_then(|encoded| encoded.failure()))
            .or_else(|| self.history_record.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.history_record_encoding.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
    }

    /// Moves the original lineage DATA error for a typed upper error boundary.
    ///
    /// This transfers only a refusal, leaves partial DATA resident, and cannot
    /// rearm decoding or turn the failed schema attempt into a success.
    pub fn take_lineage_failure_once(&mut self) -> Option<aos_sandbox_protocol::domain_ledger::DomainLedgerDataError> {
        self.lineage.as_mut().and_then(|lineage| lineage.take_failure_once())
    }

    fn enter(&mut self) -> bool {
        if self.closed || self.accepted == Some(false) || self.tree.is_some() || self.lineage.is_some()
            || self.history.is_some() || self.history_encoding.is_some()
            || self.history_record.is_some() || self.history_record_encoding.is_some()
        {
            self.closed = true;
            return false;
        }
        self.accepted = None;
        true
    }

    fn complete(&mut self, accepted: bool) -> bool {
        self.accepted = Some(accepted);
        if accepted {
            // Complete canonical body+identity equality is this pure leaf's
            // last borrower. The persistent projection owns the raw envelope.
            drop(self.encoded.take());
            drop(self.tree.take());
            drop(self.lineage.take());
            drop(self.history_encoding.take());
            drop(self.history.take());
            drop(self.history_record_encoding.take());
            drop(self.history_record.take());
        }
        accepted
    }

    pub fn receiving_fixed_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(TreeDecodeOriginalsV1::receiving_construction_bytes_v1()?)?
            .checked_add(std::mem::size_of::<LineageDecodeOriginalsV1>().checked_mul(2)?)?
            .checked_add(HistoryDecodeOriginalsV1::fixed_footprint_v1()?.0)?
            .checked_add(CanonicalEncodingOriginalsV1::fixed_footprint_v1()?.0.checked_mul(2)?)
    }

    /// Returns zero namespace entries for this fixed decoder workspace.
    pub fn receiving_fixed_cells_v1() -> Option<usize> { Some(0) }
}

pub(super) fn canonical_tree(body: &[u8], originals: Option<&mut SourceTreeSchemaOriginalsV1>) -> bool {
    let Some(originals) = originals else {
        return decode_tree_v1(body).and_then(|decoded| encode_tree_v1(&decoded))
            .is_ok_and(|encoded| encoded == body);
    };
    if !originals.enter() { return false; }
    originals.tree = Some(TreeDecodeOriginalsV1::new());
    let Some(tree) = originals.tree.as_mut() else { return originals.complete(false); };
    if decode_tree_retaining_v1(body, tree).is_err() { return originals.complete(false); }
    originals.encoded = Some(CanonicalEncodingOriginalsV1::new());
    let Some(encoding) = originals.encoded.as_mut() else { return false; };
    let Some(tree) = tree.tree() else { return false; };
    if encode_tree_retaining_v1(tree, encoding).is_err() { return false; }
    let accepted = encoding.bytes() == Some(body);
    // The caller's identity comparison follows before positive disposal.
    accepted
}

pub(super) fn canonical_lineage(body: &[u8], identity: &[u8], originals: Option<&mut SourceTreeSchemaOriginalsV1>)
    -> Option<ProtectedReducerPhaseV1>
{
    let Some(originals) = originals else {
        return decode_closed_tree_lineage_v1(body).filter(|lineage| lineage.identity().as_slice() == identity)
            .map(|_| ProtectedReducerPhaseV1::Observed);
    };
    if !originals.enter() { return None; }
    originals.lineage = Some(LineageDecodeOriginalsV1::new());
    let accepted = originals.lineage.as_mut().is_some_and(|lineage| {
        decode_lineage_retaining_v1(body, lineage).is_some_and(|record| record.identity().as_slice() == identity)
    });
    originals.complete(accepted).then_some(ProtectedReducerPhaseV1::Observed)
}

// The parent owns the one identity/last-record comparison after this same
// decoding and encoding recipe. Positive cleanup waits until that comparison.
pub(super) fn canonical_history_encoding(
    body: &[u8],
    originals: &mut SourceTreeSchemaOriginalsV1,
) -> bool {
    if !originals.enter() { return false; }
    if body.starts_with(b"AOSHHI01") {
        originals.history_record = Some(decode_history_record_v1(body));
        originals.history_record_encoding = originals.history_record.as_ref()
            .and_then(|record| record.as_ref().ok()).map(|record| encode_history_record_v1(*record));
        return originals.history_record_encoding.as_ref()
            .is_some_and(|result| result.as_ref().is_ok_and(|encoded| encoded.as_slice() == body));
    }
    originals.history = Some(HistoryDecodeOriginalsV1::new());
    let Some(history) = originals.history.as_mut() else { return false; };
    if decode_history_retaining_v1(body, history).is_err() { return false; }
    originals.history_encoding = Some(CanonicalEncodingOriginalsV1::new());
    let Some(encoding) = originals.history_encoding.as_mut() else { return false; };
    let Some(history) = history.history() else { return false; };
    if encode_history_retaining_v1(history, encoding).is_err() { return false; }
    encoding.bytes() == Some(body)
}

impl ProtectedDomainSchemaReplayCaptureV1 for HierarchyProtectedJournalSchemaV1 {
    type ReplayCapture = SourceTreeSchemaOriginalsV1;

    fn decode_reducer_phase_retaining_v1(validator: &Self::ReplayValidator, kind: Self::Kind,
        identity: &[u8], body: &[u8], capture: &mut Self::ReplayCapture,
    ) -> Option<ProtectedReducerPhaseV1> {
        if identity.len() != 48 || body.len() < 12
            || kind != Self::Kind::Evidence && body[8..12] != [0, 1, 0, 0] { return None; }
        match kind {
            Self::Kind::Tree => {
                let accepted = canonical_tree(body, Some(capture))
                    && body.get(12..28) == identity.get(..16)
                    && identity.get(16..32) == identity.get(..16)
                    && identity.get(32..48) == identity.get(..16);
                capture.complete(accepted).then_some(ProtectedReducerPhaseV1::Observed)
            }
            Self::Kind::TreeLineage => canonical_lineage(body, identity, Some(capture)),
            Self::Kind::History => {
                let accepted = canonical_history_body_with_originals(body, identity, Some(capture));
                capture.complete(accepted).then_some(ProtectedReducerPhaseV1::Observed)
            }
            // The existing Source17 iterator still selects Tree/Lineage only.
            // Remaining artifact/Evidence typed prefixes need their own actual
            // optional shared-engine destinations before a full-family claim.
            _ => Self::decode_reducer_phase(validator, kind, identity, body),
        }
    }
}

#[cfg(test)]
mod history_capture_tests {
    use super::*;

    #[test]
    fn schema_identity_refusal_keeps_the_successful_history_and_encoding() {
        let project = aos_sandbox_core::ProjectId::from_bytes([1; 16]);
        let history = crate::hierarchy::history::HierarchyHistoryV1::empty(project).unwrap();
        let body = encode_history_v1(&history).unwrap();
        let mut identity = [2; 48];
        let validator = HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[]).unwrap();
        let mut originals = SourceTreeSchemaOriginalsV1::new();

        assert!(HierarchyProtectedJournalSchemaV1::decode_reducer_phase_retaining_v1(
            &validator, HierarchyProtectedRecordKindV1::History, &identity, &body, &mut originals,
        ).is_none());
        assert_eq!(originals.accepted, Some(false));
        assert_eq!(originals.history.as_ref().unwrap().history(), Some(&history));
        let bytes = originals.history_encoding.as_ref().unwrap().bytes().unwrap().as_ptr();

        identity[..16].copy_from_slice(project.as_bytes());
        identity[16..32].copy_from_slice(project.as_bytes());
        identity[32..].copy_from_slice(project.as_bytes());
        assert!(HierarchyProtectedJournalSchemaV1::decode_reducer_phase_retaining_v1(
            &validator, HierarchyProtectedRecordKindV1::History, &identity, &body, &mut originals,
        ).is_none());
        assert_eq!(originals.history_encoding.as_ref().unwrap().bytes().unwrap().as_ptr(), bytes);
    }

    #[test]
    fn complete_history_identity_disposes_only_the_positive_leaf_work() {
        let project = aos_sandbox_core::ProjectId::from_bytes([1; 16]);
        let history = crate::hierarchy::history::HierarchyHistoryV1::empty(project).unwrap();
        let body = encode_history_v1(&history).unwrap();
        let mut identity = [0; 48];
        for component in identity.chunks_exact_mut(16) { component.copy_from_slice(project.as_bytes()); }
        let validator = HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[]).unwrap();
        let mut originals = SourceTreeSchemaOriginalsV1::new();

        let ordinary = HierarchyProtectedJournalSchemaV1::decode_reducer_phase(
            &validator, HierarchyProtectedRecordKindV1::History, &identity, &body,
        );
        let retained = HierarchyProtectedJournalSchemaV1::decode_reducer_phase_retaining_v1(
            &validator, HierarchyProtectedRecordKindV1::History, &identity, &body, &mut originals,
        );
        assert_eq!(ordinary, retained);
        assert!(retained.is_some());
        assert_eq!(originals.accepted, Some(true));
        assert!(originals.history.is_none());
        assert!(originals.history_encoding.is_none());
    }
}

#[cfg(test)]
mod tree_encoding_capture_tests {
    use super::*;

    fn tree() -> crate::hierarchy::graph::SandboxTreeV1 {
        crate::hierarchy::graph::SandboxTreeV1::from_records(
            aos_sandbox_core::ProjectId::from_bytes([1; 16]),
            aos_sandbox_core::Revision::new(1),
            aos_sandbox_core::source_tree_model::TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).unwrap(),
            Vec::new(),
        ).unwrap()
    }

    #[test]
    fn tree_identity_refusal_keeps_the_actual_encoder_through_schema_failure() {
        let body = encode_tree_v1(&tree()).unwrap();
        let validator = HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[]).unwrap();
        let mut originals = SourceTreeSchemaOriginalsV1::new();
        let identity = [2; 48];

        assert!(HierarchyProtectedJournalSchemaV1::decode_reducer_phase_retaining_v1(
            &validator, HierarchyProtectedRecordKindV1::Tree, &identity, &body, &mut originals,
        ).is_none());
        assert_eq!(originals.accepted, Some(false));
        assert!(originals.tree.as_ref().unwrap().tree().is_some());
        let encoded = originals.encoded.as_ref().unwrap().bytes().unwrap();
        assert_eq!(encoded, body);
        let allocation = encoded.as_ptr();

        assert!(HierarchyProtectedJournalSchemaV1::decode_reducer_phase_retaining_v1(
            &validator, HierarchyProtectedRecordKindV1::Tree, &identity, &body, &mut originals,
        ).is_none());
        assert_eq!(originals.encoded.as_ref().unwrap().bytes().unwrap().as_ptr(), allocation);
    }

    #[test]
    fn complete_tree_identity_disposes_only_after_the_original_comparison() {
        let tree = tree();
        let body = encode_tree_v1(&tree).unwrap();
        let mut identity = [0; 48];
        for component in identity.chunks_exact_mut(16) { component.copy_from_slice(tree.project().as_bytes()); }
        let validator = HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[]).unwrap();
        let mut originals = SourceTreeSchemaOriginalsV1::new();

        let ordinary = HierarchyProtectedJournalSchemaV1::decode_reducer_phase(
            &validator, HierarchyProtectedRecordKindV1::Tree, &identity, &body,
        );
        assert!(ordinary.is_some());
        assert_eq!(HierarchyProtectedJournalSchemaV1::decode_reducer_phase_retaining_v1(
            &validator, HierarchyProtectedRecordKindV1::Tree, &identity, &body, &mut originals,
        ), ordinary);
        assert_eq!(originals.accepted, Some(true));
        assert!(originals.tree.is_none());
        assert!(originals.encoded.is_none());
    }
}
