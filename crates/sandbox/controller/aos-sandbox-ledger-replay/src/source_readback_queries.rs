//! Shares existing saved ancestry and genesis member comparisons once.
//!
//! These helpers decode historical projection/state DATA only. They acquire no
//! native owner and return no currentness, ancestry capability, receiving loan
//! or mutation grant. Actual native callers retain their original guards and
//! protected evidence wrappers; independent signers use comparison DATA only.

use std::collections::BTreeMap;
use aos_sandbox_model::{ObjectDigest, ProjectId, RecordNamespace, Revision};
use aos_sandbox_protocol::controller_source_seed::CONTROLLER_SOURCE_TREE_SEED_BYTES_V1;
use aos_sandbox_protocol::domain_ledger::{DomainLedgerDataError,
    records::decode_reducer_payload_with_validator};
use crate::replay::{source_tree_genesis::SourceGenesisRowsV1, tree_lineage::{self, ClosedTreeLineageHeadV1}};
use crate::replay::hierarchy_records::{HierarchyProtectedJournalProjectionV1,
    HierarchyProtectedReplayValidatorV1, HierarchyProtectedJournalKeyV1,
    HierarchyProtectedRecordKindV1, HierarchyProtectedJournalSchemaV1};
use crate::hierarchy::codec::{decode_tree_v1, tree_commitment_v1};

/// Preserves saved-family conflict separately from the actual hierarchy error.
#[derive(Debug, thiserror::Error)]
pub enum SourceGenesisRowsReadbackErrorV1 {
    /// The exact genesis receipt/member/lineage join differs.
    #[error("Source genesis project or flight conflicts with retained state")]
    Conflict,
    /// The original complete hierarchy decoder or saved member check refused.
    #[error(transparent)]
    Hierarchy(#[from] DomainLedgerDataError),
}

/// Decodes the original ancestry fields from an already-replayed projection.
///
/// Returned revision/generation/commitment/head are nonauthorizing DATA. The
/// native caller constructs its private evidence only under its original guard.
///
/// # Errors
/// Preserves original payload, Tree/project and canonical commitment failures.
pub fn ancestry_fields_from_projection_v1(
    projection: &HierarchyProtectedJournalProjectionV1,
    key: &HierarchyProtectedJournalKeyV1,
    validator: &HierarchyProtectedReplayValidatorV1,
    project: ProjectId,
) -> Result<Option<(u64, Revision, ObjectDigest, ObjectDigest)>, DomainLedgerDataError> {
    let Some(record) = projection.records().iter().find(|record| record.key() == key) else {
        return Ok(None);
    };
    let payload = decode_reducer_payload_with_validator::<HierarchyProtectedJournalSchemaV1>(
        key, record.payload(), validator,
    )?;
    let tree = decode_tree_v1(payload.body()).map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    if tree.project() != project { return Err(DomainLedgerDataError::NonCanonicalRecord); }
    let tree_commitment = tree_commitment_v1(&tree).map_err(|_| DomainLedgerDataError::NonCanonicalRecord)?;
    Ok(Some((record.revision(), tree.tree_generation(), tree_commitment, record.digest())))
}

/// Rejoins the exact saved generation-one Tree and lineage members.
///
/// # Errors
/// Preserves original generation/seed/member and absent-row classifications.
pub fn source_tree_genesis_members_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    head: &ClosedTreeLineageHeadV1,
    project: ProjectId,
    seed_packet: &[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1],
) -> Result<(ObjectDigest, ObjectDigest, Vec<u8>, Vec<u8>), DomainLedgerDataError> {
    if head.tree.project() != project
        || head.tree.tree_generation().get() != 1
        || &head.initial_seed_packet != seed_packet
        || head.tree.records().next().is_some()
        || head.tree.tombstones().next().is_some()
    {
        return Err(DomainLedgerDataError::NonCanonicalRecord);
    }
    let tree_key = tree_lineage::tree_key(project)?;
    let mut identity = [0; 48];
    identity[..16].copy_from_slice(project.as_bytes());
    identity[24..32].copy_from_slice(&1_u64.to_be_bytes());
    identity[32..].copy_from_slice(project.as_bytes());
    let lineage_key = HierarchyProtectedJournalKeyV1::new(
        HierarchyProtectedRecordKindV1::TreeLineage,
        identity.to_vec(),
    )?;
    let get = |key: &[u8]| {
        state.get(&(RecordNamespace::DesiredState, key.to_vec()))
            .map(|bytes| bytes.clone())
            .ok_or(DomainLedgerDataError::NonCanonicalRecord)
    };
    Ok((
        head.tree_head,
        head.lineage_head,
        get(tree_key.as_bytes())?,
        get(lineage_key.as_bytes())?,
    ))
}

/// Checks the same exact saved receipt set against complete lineage heads.
///
/// # Errors
/// Preserves the original conflict-before-member order and hierarchy leaf.
pub fn validate_rows_with_lineage_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    rows: SourceGenesisRowsV1,
    heads: &std::collections::BTreeMap<ProjectId, ClosedTreeLineageHeadV1>,
) -> Result<SourceGenesisRowsV1, SourceGenesisRowsReadbackErrorV1> {
    if heads.len() != rows.receipts.len()
        || heads
            .keys()
            .any(|project| !rows.receipts.contains_key(project))
    {
        return Err(SourceGenesisRowsReadbackErrorV1::Conflict);
    }
    for receipt in rows.receipts.values() {
        let head = heads
            .get(&receipt.project())
            .ok_or(SourceGenesisRowsReadbackErrorV1::Conflict)?;
        let (tree_head, lineage_head, tree, lineage) = source_tree_genesis_members_v1(
            state,
            head,
            receipt.project(),
            &receipt.seed_packet(),
        )?;
        if tree_head != receipt.tree_head()
            || lineage_head != receipt.lineage_head()
            || !receipt.matches_members(&tree, &lineage)
        {
            return Err(SourceGenesisRowsReadbackErrorV1::Conflict);
        }
    }
    Ok(rows)
}
