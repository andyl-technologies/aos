//! Owns canonical saved Tree/Lineage grouping and reconstruction DATA.
//!
//! Full seven-family schema validation, pair grouping, current Tree commitment
//! and contiguous historical links use the same engines as native replay. A
//! structural result does not authenticate Source currentness or grant writes.

pub mod retained;
pub mod delete_cut;

use std::collections::BTreeMap;
use aos_sandbox_core::{ObjectDigest, ProjectId, Revision, RecordNamespace};
use aos_sandbox_protocol::controller_source_seed::CONTROLLER_SOURCE_TREE_SEED_BYTES_V1;
use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError as HierarchyProtectedJournalErrorV1;
use aos_sandbox_protocol::domain_ledger::records::decode_reducer_payload_with_validator;
use crate::hierarchy::codec::{decode_tree_v1, tree_commitment_v1};
use crate::hierarchy::graph::SandboxTreeV1;
use super::hierarchy_records::{HierarchyJournalReplayPhaseV1, HierarchyProtectedJournalKeyV1,
    HierarchyProtectedJournalProjectionV1, HierarchyProtectedJournalSchemaV1,
    HierarchyProtectedRecordKindV1, HierarchyProtectedReplayValidatorV1,
    HierarchyReducerRecordV1, hierarchy_reducer_envelope_v1};
use super::hierarchy_records::lineage::{ClosedTreeLineageRecordV1,
    decode_closed_tree_lineage_v1, seed_claims};

/// A structurally replayed current Tree and its immutable link head.
pub struct ClosedTreeLineageHeadV1 {
    /// Holds the structurally validated current Tree.
    pub tree: SandboxTreeV1,
    /// Holds its canonical envelope commitment.
    pub tree_head: ObjectDigest,
    /// Holds the final immutable lineage envelope commitment.
    pub lineage_head: ObjectDigest,
    /// Holds the original canonical genesis packet for structural comparison.
    pub initial_seed_packet: [u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1],
}


/// Verifies the saved pair joins and contiguous lineage of a projection.
///
/// # Errors
/// Rejects malformed, incomplete or inconsistent saved structural DATA.
pub fn verify_closed_tree_lineage_projection_v1(
    projection: &HierarchyProtectedJournalProjectionV1,
    validator: &crate::replay::hierarchy_records::HierarchyProtectedReplayValidatorV1,
) -> Result<BTreeMap<ProjectId, ClosedTreeLineageHeadV1>, HierarchyProtectedJournalErrorV1> {
    let mut work = retained::LineageWork::new();
    let result = retained::verify_projection(projection, validator, &mut work, false);
    work.into_ordinary(result)
}

/// Replays the complete saved structural Tree/Lineage state.
///
/// # Errors
/// Rejects malformed, incomplete or inconsistent saved structural DATA.
pub fn replay_closed_tree_lineage_state_v2(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<BTreeMap<ProjectId, ClosedTreeLineageHeadV1>, HierarchyProtectedJournalErrorV1> {
    replay_closed_tree_lineage_records_v2(state.iter().map(|((namespace, key), value)| {
        (*namespace, key.as_slice(), value.as_slice())
    }))
}

/// Reconstructs the canonical empty genesis Tree DATA from its saved seed.
///
/// This uses the same recipe as complete saved Tree/Lineage reconstruction;
/// it does not validate a live Source, Root floor, signature or current cut.
///
/// # Errors
/// Rejects malformed seed DATA, another project or an invalid Tree shape.
pub fn reconstructed_genesis_tree_data_v1(project: ProjectId,
    seed_packet: &[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1],
) -> Result<SandboxTreeV1, HierarchyProtectedJournalErrorV1> {
    let invalid = || HierarchyProtectedJournalErrorV1::NonCanonicalRecord;
    let seed = seed_claims(seed_packet).ok_or_else(invalid)?;
    if seed.project() != project {
        return Err(invalid());
    }
     SandboxTreeV1::from_records(project, Revision::new(1), seed.limits(), Vec::new())
        .map_err(|_| invalid())
}

/// Reconstructs only the canonical empty genesis pair against its saved link.
///
/// # Errors
/// Rejects malformed, incomplete or inconsistent saved structural DATA.
pub fn reconstructed_genesis_members_v2(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    project: ProjectId,
    seed_packet: &[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1],
) -> Result<(ObjectDigest, ObjectDigest, Vec<u8>, Vec<u8>), HierarchyProtectedJournalErrorV1> {
    use aos_sandbox_protocol::domain_ledger::records::{
        decode_durable_member, encode_durable_member, replay_projection_records,
    };

    let invalid = || HierarchyProtectedJournalErrorV1::NonCanonicalRecord;
    let tree = reconstructed_genesis_tree_data_v1(project, seed_packet)?;
    let validator = HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[])?;
    let mut envelopes = source_tree_pair_envelopes(&tree, None, None, Some(*seed_packet), &validator)?;
    let lineage_envelope = envelopes.pop().ok_or_else(invalid)?;
    let tree_envelope = envelopes.pop().ok_or_else(invalid)?;
    let lineage_bytes = state
        .get(&(RecordNamespace::DesiredState, lineage_envelope.key().as_bytes().to_vec()))
        .ok_or_else(invalid)?;
    let lineage = decode_durable_member::<HierarchyProtectedJournalSchemaV1>(
        lineage_envelope.key().clone(), lineage_bytes, &validator,
    )?;
    if lineage.member_index() != 1 || lineage.member_count() != 2
        || lineage.envelope() != &lineage_envelope
    {
        return Err(invalid());
    }
    let tree_head = tree_envelope.digest();
    let lineage_head = lineage_envelope.digest();
    let tree_member = encode_durable_member::<HierarchyProtectedJournalSchemaV1>(
        lineage.transaction_id(), 0, 2, lineage.set_digest(), tree_envelope,
    )?;
    let pair = [
        (RecordNamespace::DesiredState, tree_member.envelope().key().as_bytes(), tree_member.encoded()),
        (RecordNamespace::DesiredState, lineage.envelope().key().as_bytes(), lineage_bytes.as_slice()),
    ];
    let projection = replay_projection_records::<HierarchyProtectedJournalSchemaV1>(
        pair.into_iter(), &validator,
    )?;
    let heads = verify_closed_tree_lineage_projection_v1(&projection, &validator)?;
    if heads.len() != 1 || !heads.contains_key(&project) {
        return Err(invalid());
    }
    let (_, _, _, _, _envelope, encoded) = tree_member.into_parts();
    Ok((tree_head, lineage_head, encoded, lineage_bytes.clone()))
}

/// Encodes the canonical Tree and its immutable lineage member.
///
/// # Errors
/// Rejects malformed, incomplete or inconsistent saved structural DATA.
pub fn source_tree_pair_envelopes(
    tree: &SandboxTreeV1,
    prior_tree_head: Option<ObjectDigest>,
    prior_lineage_head: Option<ObjectDigest>,
    initial_seed_packet: Option<[u8; CONTROLLER_SOURCE_TREE_SEED_BYTES_V1]>,
    validator: &HierarchyProtectedReplayValidatorV1,
) -> Result<
    Vec<crate::replay::hierarchy_records::HierarchyProtectedJournalEnvelopeV1>,
    HierarchyProtectedJournalErrorV1,
> {
    let tree_key = tree_key(tree.project())?;
    let tree_envelope = hierarchy_reducer_envelope_v1(
        tree_key,
        tree.tree_generation().get(),
        prior_tree_head,
        HierarchyReducerRecordV1::Tree(tree),
        validator,
    )?;
    let commitment = tree_commitment_v1(tree)
        .map_err(|_| HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
    let link = ClosedTreeLineageRecordV1::new(
        tree.project(),
        tree.tree_generation().get(),
        prior_tree_head,
        tree_envelope.digest(),
        prior_lineage_head,
        commitment,
        initial_seed_packet,
    )
    .ok_or(HierarchyProtectedJournalErrorV1::NonCanonicalRecord)?;
    let lineage_envelope = hierarchy_reducer_envelope_v1(
        HierarchyProtectedJournalKeyV1::new(
            HierarchyProtectedRecordKindV1::TreeLineage,
            link.identity().to_vec(),
        )?,
        1,
        None,
        HierarchyReducerRecordV1::TreeLineage(&link),
        validator,
    )?;
    Ok(vec![tree_envelope, lineage_envelope])
}

/// Builds the existing canonical Tree identity key.
///
/// # Errors
/// Rejects malformed, incomplete or inconsistent saved structural DATA.
pub fn tree_key(
    project: ProjectId,
) -> Result<HierarchyProtectedJournalKeyV1, HierarchyProtectedJournalErrorV1> {
    let mut identity = Vec::with_capacity(48);
    for _ in 0..3 {
        identity.extend_from_slice(project.as_bytes());
    }
    HierarchyProtectedJournalKeyV1::new(HierarchyProtectedRecordKindV1::Tree, identity)
        .map_err(HierarchyProtectedJournalErrorV1::from)
}

/// Replays the complete canonical structural lineage from saved rows.
///
/// # Errors
/// Rejects malformed members, incomplete groups or noncontiguous lineage.
pub fn replay_closed_tree_lineage_records_v2<'records>(
    records: impl Iterator<Item = (RecordNamespace, &'records [u8], &'records [u8])>,
) -> Result<BTreeMap<ProjectId, ClosedTreeLineageHeadV1>, HierarchyProtectedJournalErrorV1> {
    let validator = HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[])?;
    let projection = aos_sandbox_protocol::domain_ledger::records::replay_projection_records::<
        HierarchyProtectedJournalSchemaV1,
    >(
        records,
        &validator,
    )?;
    verify_closed_tree_lineage_projection_v1(&projection, &validator)
}

pub mod source_family;
pub use source_family::SourceSuccessorMembersOriginalsV1;
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError;
use aos_sandbox_protocol::domain_ledger::transaction::JournalRecord;
use aos_sandbox_protocol::controller_source_seed::decode_retained_source_tree_seed_v1;

pub fn validate_source_first_successor_members_v2(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    receipt: &crate::replay::phase_records::SourceFirstSuccessorReceiptV2,
    appended_pair: Option<&[JournalRecord]>,
) -> Result<(), JournalError> {
    validate_source_successor_members(
        state, SourceSuccessorMemberRecipe::SingleProjectV2(receipt), appended_pair, None,
    )
}

pub fn validate_source_project_continuation_members_v3(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    receipts: &BTreeMap<ProjectId, crate::replay::phase_records::SourceFirstSuccessorReceiptV2>,
    proposed: Option<(&crate::replay::phase_records::SourceFirstSuccessorReceiptV2, &[JournalRecord])>,
) -> Result<(), JournalError> {
    validate_source_successor_members(
        state,
        SourceSuccessorMemberRecipe::MixedProjectsV3 {
            receipts,
            proposed: proposed.map(|(receipt, _)| receipt),
        },
        proposed.map(|(_, pair)| pair),
        None,
    )
}

pub fn validate_source_project_genesis_members_v3(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    receipts: &BTreeMap<ProjectId, crate::replay::phase_records::SourceFirstSuccessorReceiptV2>,
    selected: ProjectId,
) -> Result<(), JournalError> {
    validate_source_successor_members(
        state,
        SourceSuccessorMemberRecipe::MixedGenesisV3 { receipts, selected },
        None,
        None,
    )
}

pub fn validate_source_project_continuation_members_from_genesis_data_v3(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    genesis: &crate::replay::source_tree_genesis::SourceGenesisRowsV1,
    receipts: &BTreeMap<ProjectId, crate::replay::phase_records::SourceFirstSuccessorReceiptV2>,
) -> Result<(), JournalError> {
    validate_source_successor_members(
        state,
        SourceSuccessorMemberRecipe::MixedProjectsV3 { receipts, proposed: None },
        None,
        Some(genesis),
    )
}

pub fn validate_source_project_genesis_members_from_genesis_data_v3(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    genesis: &crate::replay::source_tree_genesis::SourceGenesisRowsV1,
    receipts: &BTreeMap<ProjectId, crate::replay::phase_records::SourceFirstSuccessorReceiptV2>,
    selected: ProjectId,
) -> Result<(), JournalError> {
    validate_source_successor_members(
        state,
        SourceSuccessorMemberRecipe::MixedGenesisV3 { receipts, selected },
        None,
        Some(genesis),
    )
}
// Recipes select a complete DATA comparison, never a writer or currentness
// permit. Prospective members borrow the real before-map and actual pair.
pub enum SourceSuccessorMemberRecipe<'receipt> {
    SingleProjectV2(&'receipt crate::replay::phase_records::SourceFirstSuccessorReceiptV2),
    MixedProjectsV3 {
        receipts: &'receipt BTreeMap<ProjectId, crate::replay::phase_records::SourceFirstSuccessorReceiptV2>,
        proposed: Option<&'receipt crate::replay::phase_records::SourceFirstSuccessorReceiptV2>,
    },
    MixedGenesisV3 {
        receipts: &'receipt BTreeMap<ProjectId, crate::replay::phase_records::SourceFirstSuccessorReceiptV2>,
        selected: ProjectId,
    },
}

impl SourceSuccessorMemberRecipe<'_> {
    fn proposed_receipt(&self) -> Option<&crate::replay::phase_records::SourceFirstSuccessorReceiptV2> {
        match self {
            Self::SingleProjectV2(receipt) => Some(receipt),
            Self::MixedProjectsV3 { proposed, .. } => *proposed,
            Self::MixedGenesisV3 { .. } => None,
        }
    }

    fn project_receipt(&self, project: ProjectId) -> Option<&crate::replay::phase_records::SourceFirstSuccessorReceiptV2> {
        match self {
            Self::SingleProjectV2(receipt) => (receipt.project() == project).then_some(*receipt),
            Self::MixedProjectsV3 { receipts, proposed } => proposed
                .filter(|receipt| receipt.project() == project)
                .or_else(|| receipts.get(&project)),
            Self::MixedGenesisV3 { receipts, .. } => receipts.get(&project),
        }
    }
}

pub fn validate_source_successor_members(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    recipe: SourceSuccessorMemberRecipe<'_>,
    appended_pair: Option<&[JournalRecord]>,
    parsed_genesis: Option<&crate::replay::source_tree_genesis::SourceGenesisRowsV1>,
) -> Result<(), JournalError> {
    validate_source_successor_members_with_originals::<JournalError, HierarchyProtectedJournalErrorV1, crate::genesis::SourceGenesisReceiptDataErrorV1>(state, recipe, appended_pair, parsed_genesis, None)
}

pub fn validate_source_successor_members_with_originals<E: From<JournalError> + std::error::Error + 'static, H: From<DomainLedgerDataError> + std::error::Error + 'static, R: From<crate::genesis::SourceGenesisReceiptDataErrorV1> + std::error::Error + 'static>(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    recipe: SourceSuccessorMemberRecipe<'_>,
    appended_pair: Option<&[JournalRecord]>,
    parsed_genesis: Option<&crate::replay::source_tree_genesis::SourceGenesisRowsV1>,
    originals: Option<&mut SourceSuccessorMembersOriginalsV1<E, H, R>>,
) -> Result<(), E> {
    use aos_sandbox_core::bounded_codec::CaptureOnDropV1;

    let (before, after, before_heads_sink, heads_sink, genesis_parser, genesis_sink,
        reconstructed_sink, reconstruction_error, mut appended_originals) = match originals {
        Some(originals) => (
            Some(&mut originals.before), Some(&mut originals.after),
            Some(&mut originals.before_heads), Some(&mut originals.heads),
            Some(&mut originals.genesis_parser), Some(&mut originals.genesis),
            Some(&mut originals.reconstructed), Some(&mut originals.reconstruction_error),
            Some(&mut originals.appended),
        ),
        None => (None, None, None, None, None, None, None, None, None),
    };
    let mut reconstructed_sink = reconstructed_sink;
    let invalid = || E::from(JournalError::ProtectedBoundary);
    let heads = if let Some(pair) = appended_pair {
        let receipt = recipe.proposed_receipt().ok_or_else(invalid)?;
        let heads = replay_closed_tree_lineage_records_with_originals(
            state.iter().map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice())), before,
        ).map_err(|_| invalid())?;
        let heads = CaptureOnDropV1::new(heads, before_heads_sink);
        let old = heads.get(&receipt.project()).ok_or_else(invalid)?;
        if old.tree.tree_generation().get() != 1
            || old.tree_head != receipt.old_tree_head()
            || old.lineage_head != receipt.old_lineage_head()
            || tree_commitment_v1(&old.tree).map_err(|_| invalid())? != receipt.old_tree_commit()
            || old.tree.records().next().is_some() || old.tree.tombstones().next().is_some()
            || pair.len() != 2
        {
            return Err(invalid());
        }
        let validator = HierarchyProtectedReplayValidatorV1::from_protected_current_heads(&[], &[], &[])
            .map_err(|_| invalid())?;
        for (index, record) in pair.iter().enumerate() {
            let ordinary_member;
            let member = match appended_originals.as_deref_mut() {
                Some(originals) => originals.observe_member_once(index, record, &validator).map_err(E::from)?,
                None => {
                    let key = HierarchyProtectedJournalKeyV1::decode(record.key()).map_err(|_| invalid())?;
                    ordinary_member = aos_sandbox_protocol::domain_ledger::records::decode_durable_member::<
                        HierarchyProtectedJournalSchemaV1,
                    >(key, record.value().ok_or_else(invalid)?, &validator).map_err(|_| invalid())?;
                    &ordinary_member
                }
            };
            let expected_kind = if index == 0 {
                HierarchyProtectedRecordKindV1::Tree
            } else {
                HierarchyProtectedRecordKindV1::TreeLineage
            };
            if record.namespace() != RecordNamespace::DesiredState
                || member.envelope().key().kind() != expected_kind
                || member.envelope().digest() != [receipt.next_tree_head(), receipt.next_lineage_head()][index]
            {
                return Err(invalid());
            }
        }
        // Borrow the real before-map and exact proposed members. Do not copy
        // the entire native state merely to replace these two hierarchy rows.
        let retained = state.iter().filter(|((namespace, key), _)| {
            !pair.iter().any(|record| record.namespace() == *namespace && record.key() == key.as_slice())
        }).map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice()));
        let proposed = pair.iter().filter_map(|record| {
            record.value().map(|value| (record.namespace(), record.key(), value))
        });
        let after_heads = replay_closed_tree_lineage_records_with_originals(retained.chain(proposed), after)
            .map_err(|_| invalid())?;
        heads.discard_positive();
        after_heads
    } else {
        replay_closed_tree_lineage_records_with_originals(
            state.iter().map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice())), after,
        ).map_err(|_| invalid())?
    };
    let heads = CaptureOnDropV1::new(heads, heads_sink);
    // Ordinary and prospective comparisons still decode after lineage replay.
    // Current mixed comparisons borrow the enclosing fold's exact genesis rows.
    let owned_genesis;
    let genesis = match parsed_genesis {
        Some(genesis) => genesis,
        None => {
            let value = match genesis_parser {
                Some(originals) => { originals.observe_once(state)?; originals.take_rows_once()? }
                None => crate::replay::source_tree_genesis::current_rows::<E>(state)?,
            };
            owned_genesis = CaptureOnDropV1::new(value, genesis_sink);
            &*owned_genesis
        }
    };
    let selected_genesis = match &recipe {
        SourceSuccessorMemberRecipe::MixedGenesisV3 { selected, .. } => Some(*selected),
        _ => None,
    };
    if genesis.pending.as_ref().is_some_and(|pending| selected_genesis != Some(pending.project))
        || genesis.receipts.len() != heads.len()
    {
        return Err(invalid());
    }

    for (project, head) in heads.iter() {
        let original = genesis.receipts.get(project).ok_or_else(invalid)?;
        let original_ack = if selected_genesis == Some(*project)
            && genesis.pending.as_ref().is_some_and(|pending| pending.project == *project)
        {
            None
        } else {
            Some(genesis.acks.get(project).ok_or_else(invalid)?)
        };
        let reconstructed = match reconstructed_genesis_members_v2(state, *project, &original.seed_packet()) {
            Ok(reconstructed) => reconstructed,
            Err(cause) => {
                if let Some(destination) = reconstruction_error { *destination = Some(H::from(cause)); }
                return Err(invalid());
            }
        };
        // The ordinary destructured Vec locals drop in reverse binding order.
        // Retaining the whole tuple must not change that ordinary schedule.
        let (ordinary_tree_head, ordinary_lineage_head, ordinary_tree_member, ordinary_lineage_member);
        let mut captured_reconstruction = None;
        let (tree_head, lineage_head, tree_member, lineage_member) = match reconstructed_sink.as_deref_mut() {
            Some(sink) => {
                captured_reconstruction = Some(CaptureOnDropV1::new(reconstructed, Some(sink)));
                let value = captured_reconstruction.as_ref().ok_or_else(invalid)?;
                (&value.0, &value.1, &value.2, &value.3)
            }
            None => {
                (ordinary_tree_head, ordinary_lineage_head, ordinary_tree_member, ordinary_lineage_member) = reconstructed;
                (&ordinary_tree_head, &ordinary_lineage_head, &ordinary_tree_member, &ordinary_lineage_member)
            }
        };
        if *tree_head != original.tree_head() || *lineage_head != original.lineage_head()
            || !original.matches_members(&tree_member, &lineage_member)
        {
            return Err(invalid());
        }
        let Some(receipt) = recipe.project_receipt(*project) else {
            if head.tree.tree_generation().get() != 1
                || head.tree_head != *tree_head || head.lineage_head != *lineage_head
                || head.tree.records().next().is_some() || head.tree.tombstones().next().is_some()
            {
                return Err(invalid());
            }
            if let Some(captured) = captured_reconstruction.take() { captured.discard_positive(); }
            continue;
        };

        let original_ack = original_ack.ok_or_else(invalid)?;

        let mut records = head.tree.records();
        let record = records.next().ok_or_else(invalid)?;
        let seed = decode_retained_source_tree_seed_v1(&original.seed_packet()).map_err(|_| invalid())?;
        if receipt.instance() != original.instance()
            || seed.epoch().checked_add(1) != Some(receipt.epoch())
            || receipt.predecessor_floor() != original_ack.root_floor
            || receipt.old_tree_head() != *tree_head || receipt.old_lineage_head() != *lineage_head
            || receipt.old_tree_commit() != tree_commitment_v1(&SandboxTreeV1::from_records(
                *project, Revision::new(1), head.tree.limits(), Vec::new(),
            ).map_err(|_| invalid())?).map_err(|_| invalid())?
            || head.tree.tree_generation().get() != 2
            || head.tree_head != receipt.next_tree_head()
            || head.lineage_head != receipt.next_lineage_head()
            || tree_commitment_v1(&head.tree).map_err(|_| invalid())? != receipt.next_tree_commit()
            || records.next().is_some() || record.parent().is_some() || record.is_live()
            || record.desired_generation().get() != 1 || head.tree.tombstones().next().is_some()
        {
            return Err(invalid());
        }
        if let Some(captured) = captured_reconstruction.take() { captured.discard_positive(); }
    }
    match recipe {
        SourceSuccessorMemberRecipe::SingleProjectV2(receipt) => {
            if !heads.contains_key(&receipt.project()) {
                return Err(invalid());
            }
        }
        SourceSuccessorMemberRecipe::MixedProjectsV3 { receipts, proposed } => {
            if receipts.keys().any(|project| !heads.contains_key(project))
                || proposed.is_some_and(|receipt| !heads.contains_key(&receipt.project()))
            {
                return Err(invalid());
            }
        }
        SourceSuccessorMemberRecipe::MixedGenesisV3 { receipts, selected } => {
            if receipts.contains_key(&selected)
                || receipts.keys().any(|project| !heads.contains_key(project))
            {
                return Err(invalid());
            }
        }
    }

    Ok(())
}


fn replay_closed_tree_lineage_records_with_originals<'records, H: From<DomainLedgerDataError> + std::error::Error + 'static> (
    records: impl Iterator<Item = (RecordNamespace, &'records [u8], &'records [u8])>,
    originals: Option<&mut source_family::CompleteLineageOriginalsV1<H>>,
) -> Result<BTreeMap<ProjectId, ClosedTreeLineageHeadV1>, H> {
    if let Some(originals) = originals {
        originals.observe_once(records)?;
        return originals.take_heads_once();
    }
    replay_closed_tree_lineage_records_v2(records).map_err(H::from)
}
