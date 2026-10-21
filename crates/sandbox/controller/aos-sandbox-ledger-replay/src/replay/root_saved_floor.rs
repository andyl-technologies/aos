//! Compares canonical saved Root floors with current Source observation DATA.
//!
//! This fold does not open or validate native custody. Its native caller must
//! first validate its actual fixed Root, independently pinned roles and complete
//! saved history, and retain the same current pair through later native posts.

use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;
use super::root_genesis_records::{FLOOR_PREFIX, INTENT_PREFIX, SourceHierarchyFloorRecordV1, project_key};

/// Keeps the actual selected saved floor/archive beside its comparison identity.
///
/// This private historical DATA cannot construct a Root authority or accept D.
pub struct RootSavedSourceFloorDataV1 {
    pub genesis: SourceHierarchyFloorRecordV1,
    pub successor: Option<
        crate::replay::root_successor::RootFirstSourceSuccessorArchiveV2,
    >,
    pub tree_generation: u64,
    pub tree_commitment: aos_sandbox_model::ObjectDigest,
    pub tree_head: aos_sandbox_model::ObjectDigest,
    pub lineage_head: aos_sandbox_model::ObjectDigest,
}

#[derive(Debug, thiserror::Error)]
pub enum RootSavedFloorComparisonDataErrorV1 {
    #[error(transparent)]
    History(#[from] crate::data::SourceSuccessorDataErrorV2),
    #[error(transparent)]
    Journal(#[from] aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1),
    #[error(transparent)]
    Hierarchy(#[from] aos_sandbox_protocol::domain_ledger::DomainLedgerDataError),
    #[error(transparent)]
    Codec(#[from] crate::hierarchy::codec::HierarchyCodecError),
    #[error("current Source Tree differs from the same settled Root semantic floor")]
    Changed,
}

/// Compares an exact saved floor with independently authenticated Source DATA.
///
/// The actual caller must separately retain the same native Root/pins/full
/// history and fresh Source original. This function performs no native checks.
///
/// # Errors
/// Refuses an unfinished selected family, malformed complete archive, absent
/// floor or a different canonical Tree/lineage tuple.
pub fn compare_saved_source_floor_v1(
    rows: HistoricalLedgerReadViewV1<'_>,
    source: &aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentReplyFieldsV1,
) -> Result<RootSavedSourceFloorDataV1, RootSavedFloorComparisonDataErrorV1> {
    use aos_sandbox_model::ProjectId;
    use crate::hierarchy::codec::tree_commitment_v1;
    use crate::replay::tree_lineage::reconstructed_genesis_tree_data_v1;

    let project = ProjectId::from_bytes(source.project);
    let namespace = RecordNamespace::DesiredState;
    if rows
        .get(namespace, &project_key(INTENT_PREFIX, project))
        .is_some()
    {
        return Err(RootSavedFloorComparisonDataErrorV1::Changed);
    }
    let genesis = rows
        .get(namespace, &project_key(FLOOR_PREFIX, project))
        .ok_or(crate::data::SourceSuccessorDataErrorV2::Conflict)
        .and_then(SourceHierarchyFloorRecordV1::from_record_bytes)?;
    let mut family = crate::replay::root_successor::project_rows_v3(rows.materialized_state_v1(), Some(project))?;
    if family.intent.is_some() {
        return Err(RootSavedFloorComparisonDataErrorV1::Changed);
    }
    let successor = family.archives.remove(&project);
    let (tree_generation, tree_commitment, tree_head, lineage_head) = match &successor {
        Some(archive) => {
            // The sole complete saved project fold already validates original
            // approval, pinned roles, predecessor floor, receipt and phase.
            let receipt = archive.floor.receipt();
            (
                receipt.after_generation(),
                receipt.next_tree_commit(),
                receipt.next_tree_head(),
                receipt.next_lineage_head(),
            )
        }
        None => {
            // Genesis materialization has a different domain from canonical
            // Tree commitment. Use the SAME actual empty Tree recipe rather
            // than treating those two commitments as interchangeable.
            let tree =
                reconstructed_genesis_tree_data_v1(project, &genesis.receipt().seed_packet())?;
            (
                tree.tree_generation().get(),
                tree_commitment_v1(&tree)?,
                genesis.tree_head(),
                genesis.lineage_head(),
            )
        }
    };
    require_tree_identity_v1(
        source,
        tree_generation,
        tree_commitment,
        tree_head,
        lineage_head,
    )?;
    Ok(RootSavedSourceFloorDataV1 {
        genesis,
        successor,
        tree_generation,
        tree_commitment,
        tree_head,
        lineage_head,
    })
}

fn require_tree_identity_v1(
    source: &aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentReplyFieldsV1,
    tree_generation: u64,
    tree_commitment: aos_sandbox_model::ObjectDigest,
    tree_head: aos_sandbox_model::ObjectDigest,
    lineage_head: aos_sandbox_model::ObjectDigest,
) -> Result<(), RootSavedFloorComparisonDataErrorV1> {
    if source.tree_generation != tree_generation
        || source.tree_commitment != *tree_commitment.as_bytes()
        || source.tree_head != *tree_head.as_bytes()
        || source.lineage_head != *lineage_head.as_bytes()
    {
        return Err(RootSavedFloorComparisonDataErrorV1::Changed);
    }
    Ok(())
}

