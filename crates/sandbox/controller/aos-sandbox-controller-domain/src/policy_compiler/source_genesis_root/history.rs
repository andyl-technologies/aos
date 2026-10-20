//! Shares complete saved Root Source history validation under actual writers.
//!
//! The saved tuple argument is comparison DATA. Each caller retains its own
//! independently installed pins, actual Root journal and current native posts.
//! This helper neither constructs a Root authority nor permits a floor append.

use super::store::MAXIMUM_PROJECTS;
use super::{
    capacity,
    records::{
        FLOOR_PREFIX, INSTANCE_KEY, INTENT_PREFIX, PINS_KEY, RootSourceGenesisIntentRecordV1,
        SourceHierarchyFloorRecordV1, decode_instance,
    },
};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{Journal, RecordNamespace};
use aos_sandbox_ledger_replay::replay::root_genesis_records::project_key;

pub(super) fn validate_history_with_pins_v1(
    journal: &Journal,
    pins: &[u8; 488],
) -> Result<(), SourceGenesisErrorV1> {
    let namespace = RecordNamespace::DesiredState;
    let instance = journal
        .get(namespace, INSTANCE_KEY)
        .map(decode_instance)
        .transpose()?;
    let retained_pins = journal.get(namespace, PINS_KEY);
    if instance.is_some() != retained_pins.is_some()
        || retained_pins.is_some_and(|bytes| bytes != pins)
    {
        return Err(SourceGenesisErrorV1::Stale);
    }
    let mut intents = 0_usize;
    let mut floors = 0_usize;
    let mut capacities = journal.root_source_genesis_capacity_ids_v1()?;
    for (key, value) in journal.records(namespace) {
        if key.starts_with(INTENT_PREFIX) {
            let intent = RootSourceGenesisIntentRecordV1::from_record_bytes(value)?;
            if instance != Some(intent.instance())
                || key != capacity::intent_key(&intent)
                || intent.roles() != super::pins::saved_role_digest_v1(pins)
                || journal
                    .get(namespace, &project_key(FLOOR_PREFIX, intent.project()))
                    .is_some()
            {
                return Err(SourceGenesisErrorV1::Stale);
            }
            super::pins::verify_administrative_input_data_v1(pins, intent.accepted_input())?;
            let capacity_id = journal.root_source_genesis_capacity_identity_v1(
                &capacity::request(&intent),
                capacity::admission_id(&intent),
            )?;
            let position = capacities
                .iter()
                .position(|candidate| *candidate == capacity_id)
                .ok_or(SourceGenesisErrorV1::Stale)?;
            capacities.remove(position);
            intents += 1;
        } else if key.starts_with(FLOOR_PREFIX) {
            let floor = SourceHierarchyFloorRecordV1::from_record_bytes(value)?;
            if instance != Some(floor.instance())
                || key != capacity::floor_key(&floor)
                || floor.roles() != super::pins::saved_role_digest_v1(pins)
            {
                return Err(SourceGenesisErrorV1::Stale);
            }
            floors += 1;
        }
        if intents > 1 || floors > MAXIMUM_PROJECTS {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
    }
    if !capacities.is_empty() {
        return Err(SourceGenesisErrorV1::Stale);
    }
    super::successor_owner::validate_root_first_successor_journal_v2(journal)?;
    Ok(())
}

/// Keeps the actual selected saved floor/archive beside its comparison identity.
///
/// This private historical DATA cannot construct a Root authority or accept D.
pub(in crate::policy_compiler) struct RootSavedSourceFloorDataV1 {
    pub(in crate::policy_compiler) genesis: SourceHierarchyFloorRecordV1,
    pub(in crate::policy_compiler) successor: Option<
        aos_sandbox_ledger_replay::replay::root_successor::RootFirstSourceSuccessorArchiveV2,
    >,
    pub(in crate::policy_compiler) tree_generation: u64,
    pub(in crate::policy_compiler) tree_commitment: aos_sandbox_model::ObjectDigest,
    pub(in crate::policy_compiler) tree_head: aos_sandbox_model::ObjectDigest,
    pub(in crate::policy_compiler) lineage_head: aos_sandbox_model::ObjectDigest,
}

#[derive(Debug, thiserror::Error)]
pub(in crate::policy_compiler) enum RootSavedFloorComparisonErrorV1 {
    #[error(transparent)]
    History(#[from] SourceGenesisErrorV1),
    #[error(transparent)]
    Journal(#[from] crate::journal::JournalError),
    #[error(transparent)]
    Hierarchy(#[from] aos_sandbox_protocol::domain_ledger::DomainLedgerDataError),
    #[error(transparent)]
    Codec(#[from] aos_sandbox_ledger_replay::hierarchy::codec::HierarchyCodecError),
    #[error("current Source Tree differs from the same settled Root semantic floor")]
    Changed,
}

// The actual caller verifies the signed current Source packet and owns its
// fresh clock/native interval. This helper only compares the complete SAME
// saved Root history; it neither takes native custody nor appends a new floor.
pub(in crate::policy_compiler) fn compare_saved_source_floor_v1(
    journal: &Journal,
    pins: &[u8; 488],
    source: &aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentReplyFieldsV1,
) -> Result<RootSavedSourceFloorDataV1, RootSavedFloorComparisonErrorV1> {
    use aos_sandbox_model::ProjectId;
    use aos_sandbox_ledger_replay::hierarchy::codec::tree_commitment_v1;
    use aos_sandbox_ledger_replay::replay::tree_lineage::reconstructed_genesis_tree_data_v1;

    validate_history_with_pins_v1(journal, pins)?;
    let project = ProjectId::from_bytes(source.project);
    let namespace = RecordNamespace::DesiredState;
    if journal
        .get(namespace, &project_key(INTENT_PREFIX, project))
        .is_some()
    {
        return Err(RootSavedFloorComparisonErrorV1::Changed);
    }
    let genesis = journal
        .get(namespace, &project_key(FLOOR_PREFIX, project))
        .ok_or(SourceGenesisErrorV1::Conflict)
        .and_then(SourceHierarchyFloorRecordV1::from_record_bytes)?;
    let mut family = super::successor_owner::project_saved_rows_v3(journal, project)?;
    if family.intent.is_some() {
        return Err(RootSavedFloorComparisonErrorV1::Changed);
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
) -> Result<(), RootSavedFloorComparisonErrorV1> {
    if source.tree_generation != tree_generation
        || source.tree_commitment != *tree_commitment.as_bytes()
        || source.tree_head != *tree_head.as_bytes()
        || source.lineage_head != *lineage_head.as_bytes()
    {
        return Err(RootSavedFloorComparisonErrorV1::Changed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::ObjectDigest;
    use aos_sandbox_protocol::domain_ledger::{
        delete_root::source_current::SourceDeleteCurrentReplyFieldsV1,
        protected_names::ProtectedJournalNamesV1,
    };

    #[test]
    fn source_tuple_requires_same_semantic_generation_and_all_three_commitments() {
        // Only a comparison boundary is exercised. These values create no
        // native Root/Source owner, verified packet, current floor or grant.
        let source = SourceDeleteCurrentReplyFieldsV1 {
            generation: 1,
            query: [1; 32],
            boot: [2; 16],
            wall_seconds: 100,
            boottime_nanoseconds: 10,
            names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            next: 2,
            end: 512,
            pending_native: [3; 64],
            batch: [4; 32],
            project: [5; 16],
            operation: [6; 16],
            tree_generation: 2,
            tree_commitment: [7; 32],
            tree_head: [8; 32],
            lineage_head: [9; 32],
        };
        let compare = |value: &SourceDeleteCurrentReplyFieldsV1| {
            require_tree_identity_v1(
                value,
                2,
                ObjectDigest::from_bytes([7; 32]),
                ObjectDigest::from_bytes([8; 32]),
                ObjectDigest::from_bytes([9; 32]),
            )
        };
        assert!(compare(&source).is_ok());
        for generation in [1, 3, u64::MAX] {
            let mut changed = source;
            changed.tree_generation = generation;
            assert!(matches!(
                compare(&changed),
                Err(RootSavedFloorComparisonErrorV1::Changed)
            ));
        }
        let mut changed = source;
        changed.tree_commitment[0] ^= 1;
        assert!(compare(&changed).is_err());
        changed = source;
        changed.tree_head[31] ^= 1;
        assert!(compare(&changed).is_err());
        changed = source;
        changed.lineage_head[16] ^= 1;
        assert!(compare(&changed).is_err());
    }
}
