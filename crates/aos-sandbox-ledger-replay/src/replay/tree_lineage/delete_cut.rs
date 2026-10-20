//! Commits the canonical complete Source predecessor used by Delete V2.
//!
//! The preimage is domain, project16, native NEXT/end8 each, length8 plus the
//! complete canonical Tree, Tree/Lineage heads32 each, canonical genesis seed,
//! policy-row count8, then sorted namespace1/key-length8/key/value-length8/value.
//! Both callers reconstruct the same actual pre-Planned prefix under their own
//! native payer and currentness. This function validates saved DATA only; a
//! view or supplied coordinate cannot create a Source owner or a pending fence.

use aos_sandbox_core::{ProjectId, RecordNamespace};
use std::collections::BTreeMap;
use sha2::{Digest as _, Sha256};

/// Preserves the sole canonical Tree/Lineage or policy-custody refusal.
#[derive(Debug, thiserror::Error)]
pub enum DeleteSourceCutDataErrorV2 {
    /// The complete saved Tree/Lineage fold refused its original DATA.
    #[error(transparent)]
    Lineage(#[from] aos_sandbox_protocol::domain_ledger::DomainLedgerDataError),
    /// The existing canonical Tree encoder rejected the validated model.
    #[error(transparent)]
    Tree(#[from] crate::hierarchy::codec::HierarchyCodecError),
    /// The sole policy-custody decoder rejected its original rows.
    #[error(transparent)]
    Policy(#[from] aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1),
    /// The actual supplied predecessor is absent, pending or malformed.
    #[error("Delete Source predecessor has no complete unfenced canonical project cut")]
    Predecessor,
}

/// Commits one completely reconstructed canonical Source predecessor as DATA.
///
/// The caller prepays the full-prefix semantic peak and canonical Tree encoding
/// before this pure reconstruction. Native sequence/end must be joined to that
/// same prefix outside this function. No pending row is removed or ignored.
///
/// # Errors
/// Rejects absent/exhausted coordinates, missing project Tree, malformed full
/// Tree/Lineage, invalid policy rows, or any held/pending custody transition.
pub fn source_predecessor_cut_data_v2(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    project: ProjectId,
    next: u64,
    end: u64,
) -> Result<[u8; 32], DeleteSourceCutDataErrorV2> {
    if next == 0 || next == u64::MAX || end == 0 {
        return Err(DeleteSourceCutDataErrorV2::Predecessor);
    }
    let policy = crate::source_policy_hold::current_state(state)?;
    if policy.delete_pending.is_some() || policy.v8_pending.is_some()
        || policy.hold.is_some_and(|hold| hold.is_held())
    {
        return Err(DeleteSourceCutDataErrorV2::Predecessor);
    }
    #[cfg(target_os = "linux")]
    if policy.q04_pending.is_some() {
        return Err(DeleteSourceCutDataErrorV2::Predecessor);
    }
    let records = state.iter().map(|((namespace, key), value)|
        (*namespace, key.as_slice(), value.as_slice()))
        .filter(|(namespace, key, _)| super::retained::matching_project_tree_row(*namespace, key, project));
    let mut heads = super::replay_closed_tree_lineage_records_v2(records)?;
    let head = heads.remove(&project).ok_or(DeleteSourceCutDataErrorV2::Predecessor)?;
    let tree = crate::hierarchy::codec::encode_tree_v1(&head.tree)?;
    let mut digest = Sha256::new()
        .chain_update(b"aos.sandbox.delete.source-cut.v2\0")
        .chain_update(project.as_bytes())
        .chain_update(next.to_be_bytes())
        .chain_update(end.to_be_bytes())
        .chain_update((tree.len() as u64).to_be_bytes())
        .chain_update(&tree)
        .chain_update(head.tree_head.as_bytes())
        .chain_update(head.lineage_head.as_bytes())
        .chain_update(head.initial_seed_packet);
    let rows = state.keys().filter(|(namespace, _)|
        *namespace == RecordNamespace::SourceDomainPolicyHold).count();
    digest.update((rows as u64).to_be_bytes());
    for ((namespace, key), value) in state.iter().filter(|((namespace, _), _)|
        *namespace == RecordNamespace::SourceDomainPolicyHold)
    {
        digest.update([*namespace as u8]);
        digest.update((key.len() as u64).to_be_bytes());
        digest.update(key);
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    Ok(digest.finalize().into())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_coordinates_do_not_create_a_missing_project_predecessor() {
        let state = BTreeMap::new();
        let result = source_predecessor_cut_data_v2(&state, ProjectId::from_bytes([1; 16]), 3, 4096);

        assert!(matches!(result, Err(DeleteSourceCutDataErrorV2::Predecessor)));
    }

    #[test]
    fn malformed_policy_rows_keep_the_sole_policy_decoder_cause() {
        let mut state = BTreeMap::new();
        state.insert((RecordNamespace::SourceDomainPolicyHold, b"unknown".to_vec()), vec![1]);
        let result = source_predecessor_cut_data_v2(&state, ProjectId::from_bytes([1; 16]), 3, 4096);

        assert!(matches!(result, Err(DeleteSourceCutDataErrorV2::Policy(_))));
    }
}
