//! Closed, structural Source Tree lineage retained in the protected journal.
//!
//! ```text
//! AOSHTL01 | version:u16be | reserved:u16be | project:16 |
//! generation:u64be | prior-tree-head:32 | tree-head:32 |
//! prior-lineage-head:32 | tree-commitment:32 | seed-length:u16be |
//! reserved:u16be | initial AOSCSE01 packet:0-or-224
//! ```
//!
//! This is not a Controller receipt or a rollback-resistant floor. Old Tree
//! bodies are overwritten by the materialized journal: replay checks their
//! exact committed heads and contiguous links, but cannot revalidate old body
//! contents after overwrite. The current Tree body is always revalidated.

pub(super) mod retained;
mod source_family;
pub(crate) use source_family::SourceSuccessorMembersOriginalsV1;
pub(crate) use retained::{SourceCurrentTreeOriginalsV1, SourceCurrentTreeDataV1};

use std::collections::BTreeMap;
use std::path::Path;

use aos_sandbox_model::{ObjectDigest, ProjectId, Revision};

#[cfg(test)]
use crate::journal::JournalLimits;
use crate::journal::{Journal, JournalError, JournalRecord, RecordNamespace};
use aos_sandbox_protocol::domain_ledger::records::decode_reducer_payload_with_validator;
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::source_domain::{
    PROTECTED_SOURCE_DOMAIN_JOURNAL, PROTECTED_SOURCE_DOMAIN_ROOT, source_domain_journal_limits,
};

use aos_sandbox_ledger_replay::hierarchy::codec::{decode_tree_v1, tree_commitment_v1};
use aos_sandbox_ledger_replay::hierarchy::graph::SandboxTreeV1;
use aos_sandbox_model::source_tree_model::TreeLimitsV1;
use super::protected_journal::{HierarchyJournalCommitOutcomeV1, HierarchyProtectedJournalErrorV1, HierarchyProtectedJournalV1, claim_hierarchy_protected_journal_v1, hierarchy_reducer_envelope_v1, recover_hierarchy_replay_validator_for_closed_lineage_v1};
use aos_sandbox_ledger_replay::replay::hierarchy_records::{HierarchyJournalReplayPhaseV1, HierarchyProtectedJournalKeyV1, HierarchyProtectedJournalProjectionV1, HierarchyProtectedJournalSchemaV1, HierarchyProtectedRecordKindV1, HierarchyProtectedReplayValidatorV1, HierarchyReducerRecordV1};
use aos_sandbox_protocol::controller_source_seed::{
    CONTROLLER_SOURCE_TREE_SEED_BYTES_V1,
    ControllerSourceTreeSeedV1, decode_retained_source_tree_seed_v1,
};

use aos_sandbox_ledger_replay::replay::hierarchy_records::lineage::{ClosedTreeLineageRecordV1, decode_closed_tree_lineage_v1, seed_claims};

pub(super) use aos_sandbox_ledger_replay::replay::tree_lineage::ClosedTreeLineageHeadV1;

/// Replays local structure only; it never certifies Source currentness.
pub(super) fn replay_closed_tree_lineage_v1(
    journal: &mut Journal,
) -> Result<BTreeMap<ProjectId, ClosedTreeLineageHeadV1>, HierarchyProtectedJournalErrorV1> {
    let validator = recover_hierarchy_replay_validator_for_closed_lineage_v1(journal)?;
    let claimed = claim_hierarchy_protected_journal_v1(journal, validator.clone())?;
    let projection = claimed.replay()?;
    verify_closed_tree_lineage_projection_v1(&projection, &validator)
}

/// Projects one actual replayed Tree cut for the fixed Source-purpose reader.
pub(crate) fn source_first_successor_tree_readback_v2(
    journal: &mut Journal, project: ProjectId,
) -> Result<(ObjectDigest, ObjectDigest, ObjectDigest, u64), HierarchyProtectedJournalErrorV1> {
    let heads = replay_closed_tree_lineage_v1(journal)?;
    let head = heads.get(&project).ok_or(HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
    Ok((head.tree_head, head.lineage_head,
        tree_commitment_v1(&head.tree).map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?,
        head.tree.tree_generation().get()))
}

fn verify_closed_tree_lineage_projection_v1(
    projection: &HierarchyProtectedJournalProjectionV1,
    validator: &aos_sandbox_ledger_replay::replay::hierarchy_records::HierarchyProtectedReplayValidatorV1,
) -> Result<BTreeMap<ProjectId, ClosedTreeLineageHeadV1>, HierarchyProtectedJournalErrorV1> {
    aos_sandbox_ledger_replay::replay::tree_lineage::verify_closed_tree_lineage_projection_v1(projection, validator)
        .map_err(HierarchyProtectedJournalErrorV1::from)
}

/// Reuses complete pair grouping and lineage validation on actual native rows.
pub(super) fn replay_closed_tree_lineage_state_v2(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<BTreeMap<ProjectId, ClosedTreeLineageHeadV1>, HierarchyProtectedJournalErrorV1> {
    aos_sandbox_ledger_replay::replay::tree_lineage::replay_closed_tree_lineage_state_v2(state)
        .map_err(HierarchyProtectedJournalErrorV1::from)
}

pub(super) fn replay_closed_tree_lineage_records_v2<'records>(
    records: impl Iterator<Item = (RecordNamespace, &'records [u8], &'records [u8])>,
) -> Result<BTreeMap<ProjectId, ClosedTreeLineageHeadV1>, HierarchyProtectedJournalErrorV1> {
    replay_closed_tree_lineage_records_with_originals(records, None)
}

fn replay_closed_tree_lineage_records_with_originals<'records>(
    records: impl Iterator<Item = (RecordNamespace, &'records [u8], &'records [u8])>,
    originals: Option<&mut source_family::CompleteLineageOriginalsV1>,
) -> Result<BTreeMap<ProjectId, ClosedTreeLineageHeadV1>, HierarchyProtectedJournalErrorV1> {
    if let Some(originals) = originals {
        originals.observe_once(records)?;
        return originals.take_heads_once();
    }
    aos_sandbox_ledger_replay::replay::tree_lineage::replay_closed_tree_lineage_records_v2(records)
        .map_err(HierarchyProtectedJournalErrorV1::from)
}

/// Rejoins the retained genesis pair after its Tree body was overwritten.
///
/// The old lineage member supplies the original transaction and set digest.
/// The same canonical pair encoder reconstructs only the empty initial Tree;
/// the same group replay then verifies that member against the retained link.
pub(super) fn reconstructed_genesis_members_v2(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    project: ProjectId,
    seed_packet: &[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1],
) -> Result<(ObjectDigest, ObjectDigest, Vec<u8>, Vec<u8>), HierarchyProtectedJournalErrorV1> {
    aos_sandbox_ledger_replay::replay::tree_lineage::reconstructed_genesis_members_v2(state, project, seed_packet)
        .map_err(HierarchyProtectedJournalErrorV1::from)
}

/// Validates an actual native state through the sole complete lineage engine.
pub(crate) fn validate_source_first_successor_members_v2(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    receipt: &aos_sandbox_ledger_replay::replay::phase_records::SourceFirstSuccessorReceiptV2,
    appended_pair: Option<&[JournalRecord]>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::tree_lineage::validate_source_first_successor_members_v2(state, receipt, appended_pair)
        .map_err(JournalError::from)
}

/// Validates every initial and successor member without granting mutation.
pub(crate) fn validate_source_project_continuation_members_v3(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    receipts: &BTreeMap<ProjectId, aos_sandbox_ledger_replay::replay::phase_records::SourceFirstSuccessorReceiptV2>,
    proposed: Option<(&aos_sandbox_ledger_replay::replay::phase_records::SourceFirstSuccessorReceiptV2, &[JournalRecord])>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::tree_lineage::validate_source_project_continuation_members_v3(state, receipts, proposed)
        .map_err(JournalError::from)
}

/// Compares the whole family while only the selected initial project may await ACK.
pub(crate) fn validate_source_project_genesis_members_v3(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    receipts: &BTreeMap<ProjectId, aos_sandbox_ledger_replay::replay::phase_records::SourceFirstSuccessorReceiptV2>,
    selected: ProjectId,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::tree_lineage::validate_source_project_genesis_members_v3(state, receipts, selected)
        .map_err(JournalError::from)
}

/// Compares current members using genesis DATA from the same immutable family fold.
///
/// The caller borrows the actual rows decoded from `state` in its enclosing
/// complete comparison. This DATA carries no writer or currentness authority.
///
/// # Errors
///
/// Rejects malformed lineage or any initial/successor member mismatch.
pub(crate) fn validate_source_project_continuation_members_from_genesis_data_v3(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    genesis: &aos_sandbox_ledger_replay::replay::source_tree_genesis::SourceGenesisRowsV1,
    receipts: &BTreeMap<ProjectId, aos_sandbox_ledger_replay::replay::phase_records::SourceFirstSuccessorReceiptV2>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::tree_lineage::validate_source_project_continuation_members_from_genesis_data_v3(state, genesis, receipts)
        .map_err(JournalError::from)
}

/// Compares selected initial members using the same fold's already-decoded DATA.
///
/// Only the selected initial project may await ACK. The borrowed genesis rows
/// remain owned by the enclosing immutable family comparison.
///
/// # Errors
///
/// Rejects malformed lineage, foreign pending rows or member mismatches.
pub(crate) fn validate_source_project_genesis_members_from_genesis_data_v3(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    genesis: &aos_sandbox_ledger_replay::replay::source_tree_genesis::SourceGenesisRowsV1,
    receipts: &BTreeMap<ProjectId, aos_sandbox_ledger_replay::replay::phase_records::SourceFirstSuccessorReceiptV2>,
    selected: ProjectId,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::tree_lineage::validate_source_project_genesis_members_from_genesis_data_v3(state, genesis, receipts, selected)
        .map_err(JournalError::from)
}

pub(crate) use aos_sandbox_ledger_replay::replay::tree_lineage::SourceSuccessorMemberRecipe;

pub(crate) fn validate_source_successor_members_with_originals(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    recipe: SourceSuccessorMemberRecipe<'_>,
    appended_pair: Option<&[JournalRecord]>,
    parsed_genesis: Option<&aos_sandbox_ledger_replay::replay::source_tree_genesis::SourceGenesisRowsV1>,
    originals: Option<&mut SourceSuccessorMembersOriginalsV1>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::replay::tree_lineage::validate_source_successor_members_with_originals(
        state, recipe, appended_pair, parsed_genesis, originals,
    )
}

fn source_tree_pair_envelopes(
    tree: &SandboxTreeV1,
    prior_tree_head: Option<ObjectDigest>,
    prior_lineage_head: Option<ObjectDigest>,
    initial_seed_packet: Option<[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1]>,
    validator: &HierarchyProtectedReplayValidatorV1,
) -> Result<
    Vec<aos_sandbox_ledger_replay::replay::hierarchy_records::HierarchyProtectedJournalEnvelopeV1>,
    HierarchyProtectedJournalErrorV1,
> {
    aos_sandbox_ledger_replay::replay::tree_lineage::source_tree_pair_envelopes(tree, prior_tree_head, prior_lineage_head, initial_seed_packet, validator)
        .map_err(HierarchyProtectedJournalErrorV1::from)
}

/// Holds canonical planned member data, never Source append authority.
pub(super) struct PreparedSourceTreeGenesisPairV1 {
    pub(super) tree_head: ObjectDigest,
    pub(super) lineage_head: ObjectDigest,
    pub(super) records: Vec<JournalRecord>,
}

/// Carries planned successor members; it cannot authorize their native append.
pub(super) struct PreparedSourceFirstSuccessorPairV2 {
    pub(super) tree_head: ObjectDigest,
    pub(super) lineage_head: ObjectDigest,
    pub(super) records: Vec<JournalRecord>,
}

/// Plans the exact next pair with the original canonical envelope/CAS engine.
pub(super) fn prepare_source_first_successor_pair_v2(
    journal: &mut Journal,
    tree: &SandboxTreeV1,
    previous_tree_head: ObjectDigest,
    previous_lineage_head: ObjectDigest,
    transaction_id: [u8; 16],
) -> Result<PreparedSourceFirstSuccessorPairV2, HierarchyProtectedJournalErrorV1> {
    let validator = recover_hierarchy_replay_validator_for_closed_lineage_v1(journal)?;
    let claimed = claim_hierarchy_protected_journal_v1(journal, validator.clone())?;
    let heads = verify_closed_tree_lineage_projection_v1(&claimed.replay()?, &validator)?;
    let old = heads.get(&tree.project()).ok_or(HierarchyProtectedJournalErrorV1::CompareAndSwapFailed)?;
    if old.tree_head != previous_tree_head || old.lineage_head != previous_lineage_head
        || old.tree.tree_generation().get() != 1 || tree.tree_generation().get() != 2
        || old.tree.limits() != tree.limits() || old.tree.records().next().is_some()
        || old.tree.tombstones().next().is_some()
    {
        return Err(HierarchyProtectedJournalErrorV1::CompareAndSwapFailed);
    }
    let envelopes = source_tree_pair_envelopes(
        tree, Some(previous_tree_head), Some(previous_lineage_head), None, &validator,
    )?;
    let tree_head = envelopes[0].digest();
    let lineage_head = envelopes[1].digest();
    let prepared = claimed.plan(transaction_id, envelopes)?;
    Ok(PreparedSourceFirstSuccessorPairV2 {
        tree_head,
        lineage_head,
        records: prepared.journal_records().to_vec(),
    })
}

/// Reuses the existing structural Tree/lineage plan under the retained writer.
///
/// The genuine genesis owner must independently retain Controller acceptance
/// and the original Root intent, and join receipt/pending rows before commit.
pub(super) fn prepare_source_tree_genesis_pair_v1(
    journal: &mut Journal,
    packet: [u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1],
    transaction_id: [u8; 16],
) -> Result<PreparedSourceTreeGenesisPairV1, HierarchyProtectedJournalErrorV1> {
    let seed = seed_claims(&packet).ok_or(HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
    let validator = recover_hierarchy_replay_validator_for_closed_lineage_v1(journal)?;
    let claimed = claim_hierarchy_protected_journal_v1(journal, validator.clone())?;
    if verify_closed_tree_lineage_projection_v1(&claimed.replay()?, &validator)?
        .contains_key(&seed.project())
    {
        return Err(HierarchyProtectedJournalErrorV1::CompareAndSwapFailed);
    }
    let tree =
        SandboxTreeV1::from_records(seed.project(), Revision::new(1), seed.limits(), Vec::new())
            .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
    let envelopes = source_tree_pair_envelopes(&tree, None, None, Some(packet), &validator)?;
    let tree_head = envelopes[0].digest();
    let lineage_head = envelopes[1].digest();
    let prepared = claimed.plan(transaction_id, envelopes)?;
    Ok(PreparedSourceTreeGenesisPairV1 {
        tree_head,
        lineage_head,
        records: prepared.journal_records().to_vec(),
    })
}

/// Rejoins exact generation-one member data; it never certifies Root currentness.
pub(super) fn source_tree_genesis_members_v1(
    journal: &Journal, head: &ClosedTreeLineageHeadV1, project: ProjectId,
    seed_packet: &[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1],
) -> Result<(ObjectDigest, ObjectDigest, Vec<u8>, Vec<u8>), HierarchyProtectedJournalErrorV1> {
    aos_sandbox_ledger_replay::source_readback_queries::source_tree_genesis_members_v1(
        journal.historical_read_view_v1().materialized_state_v1(), head, project, seed_packet,
    ).map_err(HierarchyProtectedJournalErrorV1::from)
}

fn tree_key(
    project: ProjectId,
) -> Result<HierarchyProtectedJournalKeyV1, HierarchyProtectedJournalErrorV1> {
    aos_sandbox_ledger_replay::replay::tree_lineage::tree_key(project)
        .map_err(HierarchyProtectedJournalErrorV1::from)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_model::ObjectDigest;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::JournalLimits;
    use aos_sandbox_protocol::controller_source_seed::sign_controller_source_tree_seed_v1;
    use crate::journal::{Journal, JournalError};
    use crate::protected_domain_journal::DomainCommitOutcomeV1;

    fn open_source(directory: &Path) -> ProtectedSourceDomainJournalOwnerV1 {
        let uid = fs::metadata(directory).expect("metadata").uid();
        let journal = Journal::open_protected_at_uid(
            directory,
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            JournalLimits::default(),
            uid,
        )
        .expect("protected journal")
        .0;
        ProtectedSourceDomainJournalOwnerV1::from_test_journal(journal)
    }

    fn fixture() -> (tempfile::TempDir, ProtectedSourceDomainJournalOwnerV1) {
        let directory = tempfile::tempdir().expect("private directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private mode");
        let source = open_source(directory.path());
        (directory, source)
    }

    fn packet(project: ProjectId) -> [u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1] {
        let seed = ControllerSourceTreeSeedV1::new(
            project,
            limits(),
            5,
            ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]),
            [4; 16],
            9,
        )
        .expect("seed proposal");
        sign_controller_source_tree_seed_v1(seed, 7, &SigningKey::from_bytes(&[41; 32]))
            .expect("packet")
    }



    fn limits() -> TreeLimitsV1 {
        TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).expect("limits")
    }

    fn empty_tree(project: ProjectId, generation: u64) -> SandboxTreeV1 {
        SandboxTreeV1::from_records(project, Revision::new(generation), limits(), Vec::new())
            .expect("tree")
    }

    // Builds canonical historical test DATA and commits through the existing
    // Native adapter. It constructs no private Source/Controller authority.
    fn commit_genesis_data(
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        packet: [u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1],
    ) {
        let seed = decode_retained_source_tree_seed_v1(&packet).unwrap();
        let tree = SandboxTreeV1::from_records(seed.project(), Revision::new(1), seed.limits(), Vec::new()).unwrap();
        let validator = recover_hierarchy_replay_validator_for_closed_lineage_v1(source.journal()).unwrap();
        let envelopes = source_tree_pair_envelopes(&tree, None, None, Some(packet), &validator).unwrap();
        let mut journal = claim_hierarchy_protected_journal_v1(source.journal(), validator).unwrap();
        let prepared = journal.plan(seed.request_id(), envelopes).unwrap();
        assert!(matches!(journal.commit(prepared).unwrap(), DomainCommitOutcomeV1::Applied(_)));
    }

    fn commit_tree_only(
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        tree: &SandboxTreeV1,
        predecessor: Option<ObjectDigest>,
        transaction_id: [u8; 16],
    ) {
        let validator = recover_hierarchy_replay_validator_for_closed_lineage_v1(source.journal())
            .expect("validator");
        let mut journal = claim_hierarchy_protected_journal_v1(source.journal(), validator.clone())
            .expect("claim");
        let envelope = hierarchy_reducer_envelope_v1(
            tree_key(tree.project()).expect("tree key"),
            tree.tree_generation().get(),
            predecessor,
            HierarchyReducerRecordV1::Tree(tree),
            &validator,
        )
        .expect("tree envelope");
        let plan = journal.plan(transaction_id, vec![envelope]).expect("plan");
        assert!(matches!(
            journal.commit(plan).expect("commit"),
            DomainCommitOutcomeV1::Applied(_)
        ));
    }

    #[test]
    fn no_tree_projects_remain_absent() {
        let (_directory, mut source) = fixture();
        assert!(
            replay_closed_tree_lineage_v1(source.journal())
                .expect("replay")
                .is_empty()
        );
    }

    #[test]
    fn genesis_link_roundtrips_only_with_its_exact_seed_packet() {
        let project = ProjectId::from_bytes([1; 16]);
        let link = ClosedTreeLineageRecordV1::new(
            project,
            1,
            None,
            ObjectDigest::from_bytes([2; 32]),
            None,
            ObjectDigest::from_bytes([3; 32]),
            Some(packet(project)),
        )
        .expect("seed-bearing genesis link");

        assert_eq!(decode_closed_tree_lineage_v1(&link.encode()), Some(link));
        assert!(
            ClosedTreeLineageRecordV1::new(
                project,
                1,
                None,
                ObjectDigest::from_bytes([2; 32]),
                None,
                ObjectDigest::from_bytes([3; 32]),
                None,
            )
            .is_none()
        );
    }







    #[test]
    fn tree_without_matching_lineage_fails_cold_replay() {
        let (directory, mut source) = fixture();
        let project = ProjectId::from_bytes([1; 16]);
        commit_tree_only(&mut source, &empty_tree(project, 1), None, [6; 16]);

        drop(source);
        let mut recovered = open_source(directory.path());
        assert!(replay_closed_tree_lineage_v1(recovered.journal()).is_err());
    }

    #[test]
    fn lineage_without_tree_fails_cold_replay() {
        let (directory, mut source) = fixture();
        let project = ProjectId::from_bytes([1; 16]);
        let tree = empty_tree(project, 1);
        let validator = recover_hierarchy_replay_validator_for_closed_lineage_v1(source.journal())
            .expect("validator");
        let tree_envelope = hierarchy_reducer_envelope_v1(
            tree_key(project).expect("tree key"),
            1,
            None,
            HierarchyReducerRecordV1::Tree(&tree),
            &validator,
        )
        .expect("tree envelope");
        let link = ClosedTreeLineageRecordV1::new(
            project,
            1,
            None,
            tree_envelope.digest(),
            None,
            tree_commitment_v1(&tree).expect("commitment"),
            Some(packet(project)),
        )
        .expect("lineage");
        let lineage_envelope = hierarchy_reducer_envelope_v1(
            HierarchyProtectedJournalKeyV1::new(
                HierarchyProtectedRecordKindV1::TreeLineage,
                link.identity().to_vec(),
            )
            .expect("lineage key"),
            1,
            None,
            HierarchyReducerRecordV1::TreeLineage(&link),
            &validator,
        )
        .expect("lineage envelope");
        let mut journal =
            claim_hierarchy_protected_journal_v1(source.journal(), validator).expect("claim");
        let plan = journal.plan([8; 16], vec![lineage_envelope]).expect("plan");
        assert!(matches!(
            journal.commit(plan).expect("commit"),
            DomainCommitOutcomeV1::Applied(_)
        ));
        drop(journal);

        drop(source);
        let mut recovered = open_source(directory.path());
        assert!(replay_closed_tree_lineage_v1(recovered.journal()).is_err());
    }

    #[test]
    fn superseded_tree_without_new_link_fails_cold_replay() {
        let (directory, mut source) = fixture();
        let project = ProjectId::from_bytes([1; 16]);
        commit_genesis_data(&mut source, packet(project));
        let previous = replay_closed_tree_lineage_v1(source.journal())
            .expect("genesis replay")
            .get(&project)
            .expect("project")
            .tree_head;
        commit_tree_only(
            &mut source,
            &empty_tree(project, 2),
            Some(previous),
            [7; 16],
        );

        drop(source);
        let mut recovered = open_source(directory.path());
        assert!(replay_closed_tree_lineage_v1(recovered.journal()).is_err());
    }

    #[test]
    fn source_current_projection_uses_the_actual_matching_project_pair() {
        let (directory, mut source) = fixture();
        let project = ProjectId::from_bytes([101; 16]);
        let other = ProjectId::from_bytes([102; 16]);
        for (selected, request) in [(project, 104), (other, 105)] {
            let seed = ControllerSourceTreeSeedV1::new(selected, limits(), 5,
                ObjectDigest::from_bytes([2; 32]), ObjectDigest::from_bytes([3; 32]),
                [request; 16], 9).unwrap();
            let selected_packet = sign_controller_source_tree_seed_v1(seed, 7,
                &SigningKey::from_bytes(&[41; 32])).unwrap();
            commit_genesis_data(&mut source, selected_packet);
        }
        let expected = replay_closed_tree_lineage_v1(source.journal()).unwrap();
        let expected = expected.get(&project).unwrap();
        let mut original = SourceCurrentTreeOriginalsV1::new();

        original.observe_once(source.journal().all_records(), project).unwrap();
        let observed = original.value().unwrap();

        assert_eq!(observed.revision, 1);
        assert_eq!(observed.generation, 1);
        assert_eq!(observed.tree_head, expected.tree_head);
        assert_eq!(observed.lineage_head, expected.lineage_head);
        assert_eq!(observed.commitment, tree_commitment_v1(&expected.tree).unwrap());
        assert!(original.failure().is_none());
        assert!(original.observe_once(source.journal().all_records(), other).is_err());
        assert!(original.value().is_none());
    }

    #[test]
    fn source_current_keeps_the_actual_malformed_member_cause_after_reentry() {
        let (directory, mut source) = fixture();
        let project = ProjectId::from_bytes([103; 16]);
        commit_genesis_data(&mut source, packet(project));
        let mut rows = source.journal().all_records().map(|(namespace, key, value)| {
            ((namespace, key.to_vec()), value.to_vec())
        }).collect::<BTreeMap<_, _>>();
        let key = tree_key(project).unwrap();
        let value = rows.get_mut(&(RecordNamespace::DesiredState, key.as_bytes().to_vec())).unwrap();
        let last = value.len() - 1;
        value[last] ^= 1;
        let mut original = SourceCurrentTreeOriginalsV1::new();
        assert!(original.observe_once(rows.iter().map(|((namespace, key), value)|
            (*namespace, key.as_slice(), value.as_slice())), project).is_err());
        let cause = original.failure().unwrap().downcast_ref::<aos_sandbox_protocol::domain_ledger::DomainLedgerDataError>().unwrap()
            as *const aos_sandbox_protocol::domain_ledger::DomainLedgerDataError;
        assert!(original.value().is_none());
        assert!(original.observe_once(rows.iter().map(|((namespace, key), value)|
            (*namespace, key.as_slice(), value.as_slice())), project).is_err());
        assert_eq!(original.failure().unwrap().downcast_ref::<aos_sandbox_protocol::domain_ledger::DomainLedgerDataError>().unwrap()
            as *const aos_sandbox_protocol::domain_ledger::DomainLedgerDataError, cause);
    }

}
