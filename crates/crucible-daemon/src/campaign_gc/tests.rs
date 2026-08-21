//! Canonical identity and bound tests for campaign GC plan headers.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::io::Cursor;
use std::sync::Arc;

use crucible_campaign::CampaignRepository;
use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, MemoryBlobBackend, MemoryRefBackend,
    MutableRefBackend, ObjectKind, RefCasOutcome, RefName,
};

use super::*;
use crate::MemoryAssignmentLedger;

fn hash(domain: &str, byte: u8) -> CampaignHash {
    CampaignHash::derive(domain, &[byte])
}

fn basis(
    backend: &str,
    generation: u8,
    objects: u64,
    logical_bytes: u64,
) -> CampaignGcBlobInventoryBasis {
    CampaignGcBlobInventoryBasis::new(
        backend,
        InventoryGeneration::from_bytes([generation; 32]),
        objects,
        logical_bytes,
    )
    .expect("valid physical basis")
}

fn plan_with(
    ref_generation: u8,
    ledger_generation: u8,
    physical: Vec<CampaignGcBlobInventoryBasis>,
) -> CampaignGcPlan {
    CampaignGcPlan::new(
        hash("crucible.test.gc.store-graph.v1", 1),
        CampaignGcRootSetId::from_hash(hash("crucible.test.gc.root-set.v1", 2)),
        RefInventorySummary::from_parts(
            RefInventoryGeneration::from_bytes([ref_generation; 32]),
            3,
        ),
        AssignmentRetentionSummary::new(
            AssignmentRetentionGeneration::from_bytes([ledger_generation; 32]),
            4,
            2,
            1,
        ),
        CampaignGcCandidateSetSummary::new(
            CampaignGcCandidateSetId::from_hash(hash("crucible.test.gc.candidates.v1", 3)),
            3,
            30,
        ),
        physical,
    )
    .expect("valid GC plan")
}

#[test]
fn plan_header_round_trips_and_has_one_frozen_identity() {
    let plan = plan_with(
        0x21,
        0x31,
        vec![basis("cache", 0x41, 10, 100), basis("durable", 0x42, 5, 50)],
    );
    let bytes = plan.canonical_bytes().expect("canonical plan");
    let decoded = CampaignGcPlan::from_canonical_bytes(&bytes).expect("decode canonical plan");

    assert_eq!(decoded, plan);
    assert_eq!(decoded.id(), plan.id());
    assert_eq!(plan.candidates().candidates(), 3);
    assert_eq!(plan.physical().len(), 2);
    assert_eq!(
        plan.id().expect("plan identity").to_hex(),
        "35f3e4ba9ccd69cf3ec05b8406f8b9473827118aaee9541f87834e6570a97da5"
    );
}

#[test]
fn every_administrative_generation_changes_plan_identity() {
    let original = plan_with(0x21, 0x31, vec![basis("durable", 0x41, 10, 100)]);
    let changed_ref = plan_with(0x22, 0x31, vec![basis("durable", 0x41, 10, 100)]);
    let changed_ledger = plan_with(0x21, 0x32, vec![basis("durable", 0x41, 10, 100)]);
    let changed_blob = plan_with(0x21, 0x31, vec![basis("durable", 0x42, 10, 100)]);

    let original = original.id().expect("original plan identity");
    assert_ne!(changed_ref.id().expect("changed ref identity"), original);
    assert_ne!(
        changed_ledger.id().expect("changed ledger identity"),
        original
    );
    assert_ne!(changed_blob.id().expect("changed blob identity"), original);
}

#[test]
fn plan_rejects_unordered_excessive_and_inconsistent_summaries() {
    let common = || {
        (
            hash("crucible.test.gc.store-graph.v1", 1),
            CampaignGcRootSetId::from_hash(hash("crucible.test.gc.root-set.v1", 2)),
            RefInventorySummary::from_parts(RefInventoryGeneration::from_bytes([0x21; 32]), 3),
            CampaignGcCandidateSetSummary::new(
                CampaignGcCandidateSetId::from_hash(hash("crucible.test.gc.candidates.v1", 3)),
                3,
                30,
            ),
        )
    };
    let (graph, roots, refs, candidates) = common();
    assert_eq!(
        CampaignGcPlan::new(
            graph,
            roots,
            refs,
            AssignmentRetentionSummary::new(
                AssignmentRetentionGeneration::from_bytes([0x31; 32]),
                4,
                2,
                1,
            ),
            candidates,
            vec![basis("z", 1, 10, 100), basis("a", 2, 10, 100)],
        ),
        Err(CampaignGcPlanError::InvalidPhysicalInventoryCount)
    );

    let excessive = (0..=MAX_CAMPAIGN_GC_PHYSICAL_INVENTORIES)
        .map(|index| basis(&format!("node{index:03}"), 1, 1, 1))
        .collect();
    let (graph, roots, refs, candidates) = common();
    assert_eq!(
        CampaignGcPlan::new(
            graph,
            roots,
            refs,
            AssignmentRetentionSummary::new(
                AssignmentRetentionGeneration::from_bytes([0x31; 32]),
                4,
                2,
                1,
            ),
            candidates,
            excessive,
        ),
        Err(CampaignGcPlanError::InvalidPhysicalInventoryCount)
    );

    let (graph, roots, refs, candidates) = common();
    assert_eq!(
        CampaignGcPlan::new(
            graph,
            roots,
            refs,
            AssignmentRetentionSummary::new(
                AssignmentRetentionGeneration::from_bytes([0x31; 32]),
                2,
                2,
                1,
            ),
            candidates,
            vec![basis("durable", 1, 10, 100)],
        ),
        Err(CampaignGcPlanError::InvalidLedgerSummary)
    );

    let (graph, roots, refs, _) = common();
    assert_eq!(
        CampaignGcPlan::new(
            graph,
            roots,
            refs,
            AssignmentRetentionSummary::new(
                AssignmentRetentionGeneration::from_bytes([0x31; 32]),
                4,
                2,
                1,
            ),
            CampaignGcCandidateSetSummary::new(
                CampaignGcCandidateSetId::from_hash(hash("crucible.test.gc.candidates.v1", 3,)),
                11,
                30,
            ),
            vec![basis("durable", 1, 10, 100)],
        ),
        Err(CampaignGcPlanError::InvalidCandidateSummary)
    );
}

#[test]
fn decoder_rejects_truncation_trailing_bytes_and_wrong_schema() {
    let plan = plan_with(0x21, 0x31, vec![basis("durable", 0x41, 10, 100)]);
    let bytes = plan.canonical_bytes().expect("canonical plan");
    assert_eq!(
        CampaignGcPlan::from_canonical_bytes(&bytes[..bytes.len() - 1]),
        Err(CampaignGcPlanError::InvalidLength)
    );

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        CampaignGcPlan::from_canonical_bytes(&trailing),
        Err(CampaignGcPlanError::InvalidLength)
    );

    let mut wrong_schema = bytes;
    wrong_schema[0] ^= 1;
    assert_eq!(
        CampaignGcPlan::from_canonical_bytes(&wrong_schema),
        Err(CampaignGcPlanError::UnsupportedSchema)
    );
}

#[test]
fn root_and_candidate_manifests_round_trip_with_stable_identity() {
    let first = ContentId::for_bytes(ObjectKind::Trace, 1, b"first");
    let second = ContentId::for_bytes(ObjectKind::Finding, 2, b"second");
    let roots = CampaignGcRootManifest::new([second, first, first]).expect("root manifest");
    let root_id = roots.id();
    let mut root_bytes = Vec::new();
    roots
        .write_canonical(&mut root_bytes)
        .expect("encode roots");
    let decoded_roots = CampaignGcRootManifest::from_canonical_reader(&mut Cursor::new(root_bytes))
        .expect("decode roots");
    assert_eq!(decoded_roots, roots);
    assert_eq!(decoded_roots.id(), root_id);
    let mut expected_roots = vec![first, second];
    expected_roots.sort_unstable_by(content_id_manifest_order);
    assert_eq!(decoded_roots.iter().collect::<Vec<_>>(), expected_roots);

    let candidates = CampaignGcCandidateManifest::new(vec![
        CampaignGcCandidate::new("z-tier", second, 20).expect("candidate"),
        CampaignGcCandidate::new("a-tier", first, 10).expect("candidate"),
    ])
    .expect("candidate manifest");
    let summary = candidates.summary();
    let mut candidate_bytes = Vec::new();
    candidates
        .write_canonical(&mut candidate_bytes)
        .expect("encode candidates");
    let decoded_candidates =
        CampaignGcCandidateManifest::from_canonical_reader(&mut Cursor::new(candidate_bytes))
            .expect("decode candidates");
    assert_eq!(decoded_candidates, candidates);
    assert_eq!(decoded_candidates.summary(), summary);
    assert_eq!(summary.candidates(), 2);
    assert_eq!(summary.logical_bytes(), 30);
    assert_eq!(
        decoded_candidates.iter().next().expect("first").backend(),
        "a-tier"
    );
}

#[test]
fn manifests_reject_duplicates_trailing_bytes_and_noncanonical_order() {
    let first = ContentId::for_bytes(ObjectKind::Trace, 1, b"first");
    assert!(matches!(
        CampaignGcCandidateManifest::new(vec![
            CampaignGcCandidate::new("tier", first, 1).expect("candidate"),
            CampaignGcCandidate::new("tier", first, 2).expect("candidate"),
        ]),
        Err(CampaignGcManifestError::DuplicateCandidate)
    ));

    let roots = CampaignGcRootManifest::new([first]).expect("root manifest");
    let mut bytes = Vec::new();
    roots.write_canonical(&mut bytes).expect("encode roots");
    bytes.push(0);
    assert!(matches!(
        CampaignGcRootManifest::from_canonical_reader(&mut Cursor::new(bytes)),
        Err(CampaignGcManifestError::Noncanonical)
    ));

    let second = ContentId::for_bytes(ObjectKind::Trace, 1, b"second");
    let mut descending = [second, first];
    descending.sort_unstable_by(|left, right| content_id_manifest_order(right, left));
    let mut unordered = Vec::new();
    unordered.extend_from_slice(b"crucible.campaign.gc-root-manifest.v1\0");
    unordered.extend_from_slice(&2_u64.to_be_bytes());
    for id in descending {
        let encoded = id.encode();
        unordered.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
        unordered.extend_from_slice(encoded.as_bytes());
    }
    assert!(matches!(
        CampaignGcRootManifest::from_canonical_reader(&mut Cursor::new(unordered)),
        Err(CampaignGcManifestError::Noncanonical)
    ));
}

#[test]
fn planner_authenticates_roots_and_selects_only_unreachable_placements() {
    let blobs = Arc::new(MemoryBlobBackend::new("gc-primary", 8 * 1024 * 1024));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());

    let live = ContentEnvelope::new(
        "crucible.test.gc-live",
        1,
        BTreeSet::new(),
        b"live".to_vec(),
    )
    .expect("live envelope");
    let live_bytes = live.canonical_bytes();
    let live_id = live.content_id(ObjectKind::Finding);
    blobs
        .put_if_absent(live_id, &BlobHandle::from_bytes(live_bytes))
        .expect("store live object");
    assert_eq!(
        refs.compare_exchange(
            &RefName::new("campaigns/gc-live").expect("ref name"),
            None,
            live_id,
        )
        .expect("publish ref"),
        RefCasOutcome::Advanced { next: live_id }
    );

    let orphan_bytes = b"unreachable".to_vec();
    let orphan_id = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    blobs
        .put_if_absent(orphan_id, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store orphan");

    let mut ledger = MemoryAssignmentLedger::default();
    let physical =
        CampaignGcPhysicalStore::new("gc-primary", blobs.as_ref()).expect("physical store");
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        hash("crucible.test.gc.store-graph.v1", 9),
        &[physical],
    )
    .expect("plan GC");

    assert_eq!(prepared.roots().iter().collect::<Vec<_>>(), vec![live_id]);
    assert_eq!(prepared.reachable_objects(), 1);
    assert_eq!(prepared.candidates().len(), 1);
    let candidate = prepared
        .candidates()
        .iter()
        .next()
        .expect("orphan candidate");
    assert_eq!(candidate.backend(), "gc-primary");
    assert_eq!(candidate.id(), orphan_id);
    assert_eq!(prepared.plan().root_set(), prepared.roots().id());
    assert_eq!(
        prepared.plan().candidates(),
        prepared.candidates().summary()
    );
}

#[test]
fn external_journal_reopens_exact_plan_and_durable_phase() {
    let prepared = journal_plan_fixture(0x41);
    let different = journal_plan_fixture(0x42);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let root = temp.path().join("gc-journal");

    let (mut journal, disposition) =
        DirectoryCampaignGcJournal::create(&root, &prepared).expect("create journal");
    assert_eq!(disposition, CampaignGcJournalCreateDisposition::Created);
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Planned);
    assert_eq!(journal.plan(), prepared.plan());
    assert_eq!(journal.roots(), prepared.roots());
    assert_eq!(journal.candidates(), prepared.candidates());
    assert_eq!(
        journal.begin_apply().expect("begin apply"),
        CampaignGcJournalTransition::Advanced
    );
    assert_eq!(
        journal.begin_apply().expect("repeat begin apply"),
        CampaignGcJournalTransition::Existing
    );
    drop(journal);

    let mut reopened = DirectoryCampaignGcJournal::open(&root).expect("reopen applying journal");
    assert_eq!(reopened.phase(), CampaignGcJournalPhase::Applying);
    assert_eq!(
        reopened.mark_complete().expect("complete apply"),
        CampaignGcJournalTransition::Advanced
    );
    assert_eq!(
        reopened.mark_complete().expect("repeat completion"),
        CampaignGcJournalTransition::Existing
    );
    drop(reopened);

    let (complete, disposition) =
        DirectoryCampaignGcJournal::create(&root, &prepared).expect("reopen exact journal");
    assert_eq!(disposition, CampaignGcJournalCreateDisposition::Existing);
    assert_eq!(complete.phase(), CampaignGcJournalPhase::Complete);
    drop(complete);
    assert!(matches!(
        DirectoryCampaignGcJournal::create(&root, &different),
        Err(CampaignGcJournalError::PlanMismatch)
    ));
}

#[test]
fn external_journal_rejects_incomplete_and_corrupt_state() {
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let incomplete = temp.path().join("incomplete");
    fs::create_dir(&incomplete).expect("create incomplete journal");
    assert!(matches!(
        DirectoryCampaignGcJournal::open(&incomplete),
        Err(CampaignGcJournalError::Incomplete)
    ));

    let prepared = journal_plan_fixture(0x51);
    let complete = temp.path().join("complete");
    let (journal, _) =
        DirectoryCampaignGcJournal::create(&complete, &prepared).expect("create complete journal");
    drop(journal);
    fs::write(complete.join("state-v1"), b"corrupt").expect("corrupt journal state");
    assert!(matches!(
        DirectoryCampaignGcJournal::open(&complete),
        Err(CampaignGcJournalError::InvalidState)
    ));
}

fn journal_plan_fixture(graph_byte: u8) -> CampaignGcPreparedPlan {
    let blobs = Arc::new(MemoryBlobBackend::new("journal-primary", 1024 * 1024));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let orphan_bytes = b"journal orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store journal orphan");
    let mut ledger = MemoryAssignmentLedger::default();
    let physical = CampaignGcPhysicalStore::new("journal-primary", blobs.as_ref())
        .expect("journal physical store");
    plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        hash("crucible.test.gc.journal-store-graph.v1", graph_byte),
        &[physical],
    )
    .expect("prepare journal plan")
}

fn content_id_manifest_order(left: &ContentId, right: &ContentId) -> std::cmp::Ordering {
    left.kind()
        .as_str()
        .cmp(right.kind().as_str())
        .then_with(|| left.schema_version().cmp(&right.schema_version()))
        .then_with(|| left.digest().cmp(&right.digest()))
}
