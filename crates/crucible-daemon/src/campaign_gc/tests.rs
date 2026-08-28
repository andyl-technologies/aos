//! Canonical identity and bound tests for campaign GC plan headers.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Cursor;
use std::sync::Arc;

use crucible_campaign::CampaignRepository;
use crucible_cas::content_envelope::ContentEnvelope;
use crucible_cas::content_store::{
    BlobHandle, BlobInventoryFence, BlobInventoryRecord, BlobInventorySummary, BlobStoreAdmin,
    ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MemoryBlobBackend,
    MemoryRefBackend, MutableRefBackend, ObjectKind, PackedBlobBackend, PlannedDeleteDisposition,
    RefCasOutcome, RefName, StoreEncryptionKey, StoreEncryptionKeyId, StoreError, StoreGraph,
    StoreGraphConfig, StoreGraphKeyring, StoreNodeId, StoreNodeSpec,
};

use super::apply::CampaignGcApplySources;
use super::*;
use super::{
    apply_single_host_campaign_gc_with_physical as apply_single_host_campaign_gc,
    plan_single_host_campaign_gc_with_physical as plan_single_host_campaign_gc,
};
use crate::{
    AssignmentRetentionAdmin, AssignmentRetentionFence, AssignmentRetentionGeneration,
    AssignmentRetentionInventoryError, AssignmentRetentionRoot, AssignmentRetentionSummary,
    AssignmentRetentionVisitorError, DirectoryAssignmentLedger, MemoryAssignmentLedger,
};

mod s3;

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
    let live_id = live.content_id(ObjectKind::Trace);
    blobs
        .put_if_absent(live_id, &BlobHandle::from_bytes(live_bytes))
        .expect("store live object");
    assert_eq!(
        refs.compare_exchange(
            &RefName::new("retained/gc-live").expect("ref name"),
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
        None,
        None,
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
fn write_back_journal_roots_are_planned_and_revalidated_before_gc_deletion() {
    let temp = tempfile::TempDir::new().expect("temporary write-back GC root");
    let staging_root = temp.path().join("staging");
    let archive_root = temp.path().join("archive");
    let journal_root = temp.path().join("write-back-journal");
    let write_back = StoreNodeId::new("write-back").expect("write-back node");
    let staging = StoreNodeId::new("staging").expect("staging node");
    let archive = StoreNodeId::new("archive").expect("archive node");
    let graph = Arc::new(
        StoreGraph::build(StoreGraphConfig {
            root: write_back.clone(),
            admitted_kinds: BTreeSet::from([ObjectKind::Trace]),
            nodes: BTreeMap::from([
                (
                    write_back,
                    StoreNodeSpec::WriteBack {
                        staging: staging.clone(),
                        destination: archive.clone(),
                        journal_root,
                        maximum_pending_objects: 16,
                        maximum_pending_bytes: 1024 * 1024,
                    },
                ),
                (
                    staging,
                    StoreNodeSpec::Directory {
                        root: staging_root.clone(),
                    },
                ),
                (
                    archive,
                    StoreNodeSpec::Directory {
                        root: archive_root.clone(),
                    },
                ),
            ]),
        })
        .expect("write-back store graph"),
    );
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(graph.clone(), refs.clone());

    let pending = ContentEnvelope::new(
        "crucible.test.gc-write-back-pending",
        1,
        BTreeSet::new(),
        b"pending".to_vec(),
    )
    .expect("pending envelope");
    let pending_id = pending.content_id(ObjectKind::Trace);
    graph
        .put_if_absent(
            pending_id,
            &BlobHandle::from_bytes(pending.canonical_bytes()),
        )
        .expect("stage pending root");
    let orphan = ContentEnvelope::new(
        "crucible.test.gc-write-back-orphan",
        1,
        BTreeSet::new(),
        b"orphan".to_vec(),
    )
    .expect("orphan envelope");
    let orphan_id = orphan.content_id(ObjectKind::Trace);
    let staging_leaf = DirectoryBlobBackend::new("staging", &staging_root);
    staging_leaf
        .put_if_absent(orphan_id, &BlobHandle::from_bytes(orphan.canonical_bytes()))
        .expect("store unjournaled orphan");
    let archive_leaf = DirectoryBlobBackend::new("archive", &archive_root);

    let mut ledger = MemoryAssignmentLedger::default();
    let archive_physical =
        CampaignGcPhysicalStore::new("archive", &archive_leaf).expect("archive physical");
    let staging_physical =
        CampaignGcPhysicalStore::new("staging", &staging_leaf).expect("staging physical");
    let graph_id = hash("crucible.test.gc.write-back-store-graph.v1", 0x44);
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        Some(graph.as_ref()),
        None,
        graph_id,
        &[archive_physical, staging_physical],
    )
    .expect("plan write-back-aware GC");
    assert_eq!(
        prepared.roots().iter().collect::<Vec<_>>(),
        vec![pending_id]
    );
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan_id
    );

    let (mut gc_journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("gc-journal"), &prepared)
            .expect("create GC journal");
    assert_eq!(
        graph
            .flush_write_back(1)
            .expect("complete pending transfer")
            .completed(),
        1
    );
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut gc_journal,
            CampaignGcApplySources::new(
                &repository,
                refs.as_ref(),
                &mut ledger,
                Some(graph.as_ref()),
                None,
            ),
            graph_id,
            &[archive_physical, staging_physical],
        ),
        Err(CampaignGcApplyError::RootSetChanged)
    ));
    assert!(staging_leaf.contains(orphan_id).expect("orphan retained"));
    assert_eq!(gc_journal.phase(), CampaignGcJournalPhase::Planned);
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

#[test]
fn apply_revalidates_every_basis_then_deletes_and_completes() {
    let mut fixture = apply_fixture(2);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("journal"), &fixture.prepared)
            .expect("create apply journal");
    let physical = CampaignGcPhysicalStore::new("apply-primary", fixture.blobs.as_ref())
        .expect("apply physical store");

    let report = apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(
            &fixture.repository,
            fixture.refs.as_ref(),
            &mut fixture.ledger,
            None,
            None,
        ),
        fixture.graph,
        &[physical],
    )
    .expect("apply exact plan");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert_eq!(report.candidates(), 2);
    assert_eq!(
        report.logical_bytes(),
        fixture.prepared.candidates().logical_bytes()
    );
    assert_eq!(fixture.blobs.object_count().expect("object count"), 0);
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);

    let replay = apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(
            &fixture.repository,
            fixture.refs.as_ref(),
            &mut fixture.ledger,
            None,
            None,
        ),
        fixture.graph,
        &[physical],
    )
    .expect("replay completed apply");
    assert_eq!(replay.status(), CampaignGcApplyStatus::AlreadyComplete);
    assert_eq!(replay.candidates(), report.candidates());
}

#[test]
fn stale_ref_and_blob_generations_fail_before_deletion() {
    let mut ref_fixture = apply_fixture(1);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let (mut ref_journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("ref-journal"), &ref_fixture.prepared)
            .expect("create ref-stale journal");
    let orphan = ref_fixture
        .prepared
        .candidates()
        .iter()
        .next()
        .expect("orphan candidate")
        .id();
    ref_fixture
        .refs
        .compare_exchange(
            &RefName::new("retained/new-root").expect("new ref"),
            None,
            orphan,
        )
        .expect("advance ref generation");
    let physical = CampaignGcPhysicalStore::new("apply-primary", ref_fixture.blobs.as_ref())
        .expect("ref-stale physical store");
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut ref_journal,
            CampaignGcApplySources::new(
                &ref_fixture.repository,
                ref_fixture.refs.as_ref(),
                &mut ref_fixture.ledger,
                None,
                None,
            ),
            ref_fixture.graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::RefBasisChanged)
    ));
    assert_eq!(ref_journal.phase(), CampaignGcJournalPhase::Planned);
    assert_eq!(ref_fixture.blobs.object_count().expect("object count"), 1);

    let mut blob_fixture = apply_fixture(1);
    let (mut blob_journal, _) = DirectoryCampaignGcJournal::create(
        temp.path().join("blob-journal"),
        &blob_fixture.prepared,
    )
    .expect("create blob-stale journal");
    let additional_bytes = b"post-plan object";
    let additional = ContentId::for_bytes(ObjectKind::Trace, 1, additional_bytes);
    blob_fixture
        .blobs
        .put_if_absent(additional, &BlobHandle::from_bytes(additional_bytes))
        .expect("advance blob generation");
    let physical = CampaignGcPhysicalStore::new("apply-primary", blob_fixture.blobs.as_ref())
        .expect("blob-stale physical store");
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut blob_journal,
            CampaignGcApplySources::new(
                &blob_fixture.repository,
                blob_fixture.refs.as_ref(),
                &mut blob_fixture.ledger,
                None,
                None,
            ),
            blob_fixture.graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::PhysicalBasisChanged { .. })
    ));
    assert_eq!(blob_journal.phase(), CampaignGcJournalPhase::Planned);
    assert_eq!(blob_fixture.blobs.object_count().expect("object count"), 2);
}

#[test]
fn stale_ledger_generation_fails_before_deletion() {
    let blobs = Arc::new(MemoryBlobBackend::new("ledger-primary", 1024 * 1024));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let orphan_bytes = b"ledger stale orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store ledger stale orphan");
    let mut ledger = SyntheticRetentionLedger { generation: 1 };
    let graph = hash("crucible.test.gc.ledger-store-graph.v1", 0x65);
    let physical = CampaignGcPhysicalStore::new("ledger-primary", blobs.as_ref())
        .expect("ledger physical store");
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        &[physical],
    )
    .expect("plan ledger stale GC");
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("journal"), &prepared)
            .expect("create ledger stale journal");
    ledger.generation = 2;

    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut journal,
            CampaignGcApplySources::new(&repository, refs.as_ref(), &mut ledger, None, None,),
            graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::LedgerBasisChanged)
    ));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Planned);
    assert!(blobs.contains(orphan).expect("orphan retained"));
}

#[test]
fn interrupted_apply_retains_journal_and_requires_a_fresh_plan() {
    let mut fixture = apply_fixture(2);
    let temp = tempfile::TempDir::new().expect("temporary journal parent");
    let (mut journal, _) =
        DirectoryCampaignGcJournal::create(temp.path().join("journal"), &fixture.prepared)
            .expect("create interrupted journal");
    let failing = FailAfterFirstDeleteAdmin {
        inner: fixture.blobs.as_ref(),
    };
    let physical =
        CampaignGcPhysicalStore::new("apply-primary", &failing).expect("failing physical store");
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut journal,
            CampaignGcApplySources::new(
                &fixture.repository,
                fixture.refs.as_ref(),
                &mut fixture.ledger,
                None,
                None,
            ),
            fixture.graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::Blob { .. })
    ));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Applying);
    assert_eq!(fixture.blobs.object_count().expect("object count"), 1);
    assert!(matches!(
        apply_single_host_campaign_gc(
            &mut journal,
            CampaignGcApplySources::new(
                &fixture.repository,
                fixture.refs.as_ref(),
                &mut fixture.ledger,
                None,
                None,
            ),
            fixture.graph,
            &[physical],
        ),
        Err(CampaignGcApplyError::InterruptedJournal)
    ));
    assert_eq!(fixture.blobs.object_count().expect("object count"), 1);
}

#[test]
fn directory_plan_journal_and_apply_survive_full_backend_restart() {
    let temp = tempfile::TempDir::new().expect("temporary GC root");
    let blob_root = temp.path().join("blobs");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let graph = hash("crucible.test.gc.directory-store-graph.v1", 0x71);

    let blobs = Arc::new(DirectoryBlobBackend::new("directory-primary", &blob_root));
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-directory-live",
        1,
        BTreeSet::new(),
        b"live".to_vec(),
    )
    .expect("live envelope");
    let live_id = live.content_id(ObjectKind::Trace);
    blobs
        .put_if_absent(live_id, &BlobHandle::from_bytes(live.canonical_bytes()))
        .expect("store live directory object");
    refs.compare_exchange(
        &RefName::new("retained/directory-gc").expect("directory ref"),
        None,
        live_id,
    )
    .expect("publish directory root");
    let orphan_bytes = b"directory orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store directory orphan");
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open directory ledger");
    let physical = CampaignGcPhysicalStore::new("directory-primary", blobs.as_ref())
        .expect("directory physical store");
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        &[physical],
    )
    .expect("plan directory GC");
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create directory journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(blobs);

    let blobs = Arc::new(DirectoryBlobBackend::new("directory-primary", &blob_root));
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    let mut ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen directory ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen directory journal");
    let physical = CampaignGcPhysicalStore::new("directory-primary", blobs.as_ref())
        .expect("reopened physical store");
    let report = apply_single_host_campaign_gc(
        &mut journal,
        CampaignGcApplySources::new(&repository, refs.as_ref(), &mut ledger, None, None),
        graph,
        &[physical],
    )
    .expect("apply after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(blobs.contains(live_id).expect("live placement"));
    assert!(!blobs.contains(orphan).expect("orphan placement"));
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn compressed_graph_admin_drives_plaintext_accounted_gc_across_restart() {
    let temp = tempfile::TempDir::new().expect("temporary compressed GC root");
    let blob_root = temp.path().join("compressed");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let compressed_node = StoreNodeId::new("compressed-primary").expect("compressed node");
    let graph_config = || StoreGraphConfig {
        root: compressed_node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            compressed_node.clone(),
            StoreNodeSpec::CompressedDirectory {
                root: blob_root.clone(),
                maximum_logical_object_bytes: 1024 * 1024,
            },
        )]),
    };

    let (graph, admin) = StoreGraph::build_with_admin(graph_config()).expect("compressed graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-compressed-live",
        1,
        BTreeSet::new(),
        vec![b'L'; 64 * 1024],
    )
    .expect("live envelope");
    let live_bytes = live.canonical_bytes();
    let live_id = live.content_id(ObjectKind::RamExtent);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live_bytes.clone()))
        .expect("store live compressed object");
    refs.compare_exchange(
        &RefName::new("retained/compressed-gc").expect("compressed ref"),
        None,
        live_id,
    )
    .expect("publish compressed root");
    let orphan_bytes = vec![b'O'; 128 * 1024];
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes.clone()))
        .expect("store compressed orphan");

    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open compressed ledger");
    let prepared = super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan compressed GC");
    assert_eq!(prepared.plan().physical().len(), 1);
    assert_eq!(prepared.plan().physical()[0].objects(), 2);
    assert_eq!(
        prepared.plan().physical()[0].logical_bytes(),
        u64::try_from(live_bytes.len() + orphan_bytes.len()).expect("logical byte total")
    );
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().logical_bytes(),
        u64::try_from(orphan_bytes.len()).expect("orphan logical bytes")
    );
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create compressed GC journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);

    let (graph, admin) =
        StoreGraph::build_with_admin(graph_config()).expect("restart compressed graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen compressed ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen compressed GC journal");
    let report = super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply compressed GC after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert_eq!(report.candidates(), 1);
    assert_eq!(
        report.logical_bytes(),
        u64::try_from(orphan_bytes.len()).expect("reported orphan bytes")
    );
    assert!(graph.contains(live_id).expect("live compressed placement"));
    assert!(!graph.contains(orphan).expect("orphan compressed placement"));
    assert_eq!(
        graph
            .read(live_id, None)
            .expect("read retained compressed object")
            .read_all(1024 * 1024)
            .expect("authenticate retained compressed object"),
        live_bytes
    );
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn encrypted_graph_admin_drives_plaintext_accounted_gc_across_restart() {
    run_encrypted_graph_gc_restart(false);
}

#[test]
fn compressed_encrypted_graph_admin_drives_plaintext_accounted_gc_across_restart() {
    run_encrypted_graph_gc_restart(true);
}

fn run_encrypted_graph_gc_restart(compressed: bool) {
    let temp = tempfile::TempDir::new().expect("temporary encrypted GC root");
    let blob_root = temp.path().join("encrypted");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let encrypted_node = StoreNodeId::new("encrypted-primary").expect("encrypted node");
    let key_id = StoreEncryptionKeyId::new("gc-key-1").expect("GC key ID");
    let graph_config = || StoreGraphConfig {
        root: encrypted_node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            encrypted_node.clone(),
            if compressed {
                StoreNodeSpec::CompressedEncryptedDirectory {
                    root: blob_root.clone(),
                    maximum_logical_object_bytes: 1024 * 1024,
                    key_id: key_id.clone(),
                }
            } else {
                StoreNodeSpec::EncryptedDirectory {
                    root: blob_root.clone(),
                    maximum_logical_object_bytes: 1024 * 1024,
                    key_id: key_id.clone(),
                }
            },
        )]),
    };
    let graph_keys = || {
        let mut keys = StoreGraphKeyring::new();
        keys.insert(
            key_id.clone(),
            StoreEncryptionKey::new([0x6d; 32]).expect("GC key"),
        )
        .expect("insert GC key");
        keys
    };

    let keys = graph_keys();
    let (graph, admin) =
        StoreGraph::build_with_admin_and_keys(graph_config(), &keys).expect("encrypted graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-encrypted-live",
        1,
        BTreeSet::new(),
        vec![b'L'; 64 * 1024],
    )
    .expect("live envelope");
    let live_bytes = live.canonical_bytes();
    let live_id = live.content_id(ObjectKind::RamExtent);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live_bytes.clone()))
        .expect("store live encrypted object");
    refs.compare_exchange(
        &RefName::new("retained/encrypted-gc").expect("encrypted ref"),
        None,
        live_id,
    )
    .expect("publish encrypted root");
    let orphan_bytes = vec![b'O'; 128 * 1024];
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, &orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes.clone()))
        .expect("store encrypted orphan");

    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open encrypted ledger");
    let prepared = super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan encrypted GC");
    assert_eq!(prepared.plan().physical()[0].objects(), 2);
    assert_eq!(
        prepared.plan().physical()[0].logical_bytes(),
        u64::try_from(live_bytes.len() + orphan_bytes.len()).expect("logical byte total")
    );
    assert_eq!(prepared.candidates().len(), 1);
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create encrypted GC journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);
    drop(keys);

    let keys = graph_keys();
    let (graph, admin) = StoreGraph::build_with_admin_and_keys(graph_config(), &keys)
        .expect("restart encrypted graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger =
        DirectoryAssignmentLedger::open(&ledger_root).expect("reopen encrypted ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen encrypted GC journal");
    let report = super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply encrypted GC after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert_eq!(report.candidates(), 1);
    assert_eq!(
        report.logical_bytes(),
        u64::try_from(orphan_bytes.len()).expect("reported orphan bytes")
    );
    assert!(graph.contains(live_id).expect("live encrypted placement"));
    assert!(!graph.contains(orphan).expect("orphan encrypted placement"));
    assert_eq!(
        graph
            .read(live_id, None)
            .expect("read retained encrypted object")
            .read_all(1024 * 1024)
            .expect("authenticate retained encrypted object"),
        live_bytes
    );
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn logical_quota_graph_gc_reclaims_admission_capacity_across_restart() {
    let temp = tempfile::TempDir::new().expect("temporary quota GC root");
    let blob_root = temp.path().join("objects");
    let quota_root = temp.path().join("quota");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let quota_node = StoreNodeId::new("quota-primary").expect("quota node");
    let directory_node = StoreNodeId::new("directory-child").expect("directory child");
    let graph_config = || StoreGraphConfig {
        root: quota_node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                quota_node.clone(),
                StoreNodeSpec::LogicalQuota {
                    child: directory_node.clone(),
                    state_root: quota_root.clone(),
                    maximum_objects: 2,
                    maximum_logical_bytes: 1024 * 1024,
                },
            ),
            (
                directory_node.clone(),
                StoreNodeSpec::Directory {
                    root: blob_root.clone(),
                },
            ),
        ]),
    };

    let (graph, admin) = StoreGraph::build_with_admin(graph_config()).expect("quota GC graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-quota-live",
        1,
        BTreeSet::new(),
        b"quota live".to_vec(),
    )
    .expect("quota live envelope");
    let live_id = live.content_id(ObjectKind::RamExtent);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live.canonical_bytes()))
        .expect("store quota live object");
    refs.compare_exchange(
        &RefName::new("retained/quota-gc").expect("quota ref"),
        None,
        live_id,
    )
    .expect("publish quota root");
    let orphan_bytes = b"quota orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store quota orphan");
    let rejected_bytes = b"quota initially full";
    let rejected = ContentId::for_bytes(ObjectKind::Trace, 1, rejected_bytes);
    assert!(matches!(
        graph.put_if_absent(rejected, &BlobHandle::from_bytes(rejected_bytes)),
        Err(StoreError::Quota)
    ));

    assert_eq!(admin.physical().len(), 1);
    assert_eq!(admin.physical()[0].node(), &quota_node);
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open quota GC ledger");
    let prepared = super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan quota GC");
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create quota GC journal");
    drop(journal);
    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);

    let (graph, admin) =
        StoreGraph::build_with_admin(graph_config()).expect("restart quota GC graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("reopen quota GC ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen quota GC journal");
    let report = super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply quota GC after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(graph.contains(live_id).expect("quota live placement"));
    assert!(!graph.contains(orphan).expect("quota orphan placement"));
    graph
        .put_if_absent(rejected, &BlobHandle::from_bytes(rejected_bytes))
        .expect("GC reclaimed quota admission capacity");
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

#[test]
fn packed_graph_admin_drives_restart_safe_logical_gc_without_deleting_live_pack_bytes() {
    let temp = tempfile::TempDir::new().expect("temporary packed GC root");
    let pack_root = temp.path().join("packs");
    let ref_root = temp.path().join("refs");
    let ledger_root = temp.path().join("ledger");
    let journal_root = temp.path().join("journal");
    let packed_node = StoreNodeId::new("packed-primary").expect("packed node");
    let graph_config = || StoreGraphConfig {
        root: packed_node.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([(
            packed_node.clone(),
            StoreNodeSpec::Packed {
                root: pack_root.clone(),
                target_pack_bytes: 64 * 1024,
            },
        )]),
    };

    let (graph, admin) = StoreGraph::build_with_admin(graph_config()).expect("packed graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let live = ContentEnvelope::new(
        "crucible.test.gc-packed-live",
        1,
        BTreeSet::new(),
        b"live".to_vec(),
    )
    .expect("live envelope");
    let live_id = live.content_id(ObjectKind::RamExtent);
    graph
        .put_if_absent(live_id, &BlobHandle::from_bytes(live.canonical_bytes()))
        .expect("store live packed object");
    refs.compare_exchange(
        &RefName::new("retained/packed-gc").expect("packed ref"),
        None,
        live_id,
    )
    .expect("publish packed root");
    let orphan_bytes = b"packed orphan";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    graph
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store packed orphan");

    let packed = PackedBlobBackend::open("packed-primary", &pack_root, 64 * 1024)
        .expect("packed maintenance leaf");
    let repack = packed.plan_repack().expect("packed coalescing plan");
    let repacked = packed
        .apply_repack(&repack)
        .expect("coalesce packed objects");
    assert_eq!(repacked.after().packs(), 1);
    assert_eq!(repacked.after().logical_objects(), 2);

    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("open packed ledger");
    assert_eq!(admin.physical().len(), 1);
    let prepared = super::plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("plan packed GC");
    assert_eq!(
        prepared.plan().store_graph(),
        CampaignHash::from_bytes(admin.configuration_id().as_bytes())
    );
    assert_eq!(prepared.candidates().len(), 1);
    assert_eq!(
        prepared.candidates().iter().next().expect("orphan").id(),
        orphan
    );
    let (journal, _) = DirectoryCampaignGcJournal::create(&journal_root, &prepared)
        .expect("create packed GC journal");
    drop(journal);

    let verified = StoreNodeId::new("verified-root").expect("verified root");
    let (different_graph, different_admin) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: verified.clone(),
        admitted_kinds: BTreeSet::from([ObjectKind::RamExtent, ObjectKind::Trace]),
        nodes: BTreeMap::from([
            (
                verified,
                StoreNodeSpec::Verified {
                    child: packed_node.clone(),
                },
            ),
            (
                packed_node.clone(),
                StoreNodeSpec::Packed {
                    root: pack_root.clone(),
                    target_pack_bytes: 64 * 1024,
                },
            ),
        ]),
    })
    .expect("different composition over same packed leaf");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen planned journal");
    assert!(matches!(
        super::apply_single_host_campaign_gc(
            &mut journal,
            &repository,
            refs.as_ref(),
            &mut ledger,
            None,
            None,
            &different_admin,
        ),
        Err(CampaignGcApplyError::StoreGraphChanged)
    ));
    assert!(graph.contains(orphan).expect("orphan retained on mismatch"));
    drop(journal);
    drop(different_admin);
    drop(different_graph);

    drop(ledger);
    drop(repository);
    drop(refs);
    drop(graph);
    drop(admin);
    drop(packed);

    let (graph, admin) =
        StoreGraph::build_with_admin(graph_config()).expect("restart packed graph");
    let graph = Arc::new(graph);
    let refs = Arc::new(DirectoryRefBackend::new(&ref_root));
    let repository = CampaignRepository::new(graph.clone(), refs.clone());
    let mut ledger = DirectoryAssignmentLedger::open(&ledger_root).expect("reopen packed ledger");
    let mut journal =
        DirectoryCampaignGcJournal::open(&journal_root).expect("reopen packed GC journal");
    let report = super::apply_single_host_campaign_gc(
        &mut journal,
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        &admin,
    )
    .expect("apply packed GC after restart");
    assert_eq!(report.status(), CampaignGcApplyStatus::Applied);
    assert!(graph.contains(live_id).expect("live packed placement"));
    assert!(!graph.contains(orphan).expect("orphan packed placement"));
    let packed = PackedBlobBackend::open("packed-primary", &pack_root, 64 * 1024)
        .expect("reopen packed accounting");
    let accounting = packed.accounting().expect("packed post-GC accounting");
    assert_eq!(accounting.logical_objects(), 1);
    assert_eq!(accounting.packs(), 1);
    assert_eq!(journal.phase(), CampaignGcJournalPhase::Complete);
}

struct ApplyFixture {
    blobs: Arc<MemoryBlobBackend>,
    refs: Arc<MemoryRefBackend>,
    repository: CampaignRepository,
    ledger: MemoryAssignmentLedger,
    prepared: CampaignGcPreparedPlan,
    graph: CampaignHash,
}

fn apply_fixture(orphan_count: u8) -> ApplyFixture {
    let blobs = Arc::new(MemoryBlobBackend::new("apply-primary", 1024 * 1024));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());
    for index in 0..orphan_count {
        let bytes = [index; 8];
        let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
        blobs
            .put_if_absent(id, &BlobHandle::from_bytes(bytes))
            .expect("store apply orphan");
    }
    let mut ledger = MemoryAssignmentLedger::default();
    let graph = hash("crucible.test.gc.apply-store-graph.v1", 0x61);
    let physical = CampaignGcPhysicalStore::new("apply-primary", blobs.as_ref())
        .expect("apply fixture physical store");
    let prepared = plan_single_host_campaign_gc(
        &repository,
        refs.as_ref(),
        &mut ledger,
        None,
        None,
        graph,
        &[physical],
    )
    .expect("prepare apply fixture");
    ApplyFixture {
        blobs,
        refs,
        repository,
        ledger,
        prepared,
        graph,
    }
}

struct FailAfterFirstDeleteAdmin<'a> {
    inner: &'a MemoryBlobBackend,
}

impl BlobStoreAdmin for FailAfterFirstDeleteAdmin<'_> {
    fn acquire_inventory_fence(&self) -> Result<Box<dyn BlobInventoryFence + '_>, StoreError> {
        Ok(Box::new(FailAfterFirstDeleteFence {
            inner: self.inner.acquire_inventory_fence()?,
            deletes: 0,
        }))
    }
}

struct FailAfterFirstDeleteFence<'a> {
    inner: Box<dyn BlobInventoryFence + 'a>,
    deletes: usize,
}

struct SyntheticRetentionLedger {
    generation: u8,
}

impl AssignmentRetentionAdmin for SyntheticRetentionLedger {
    type Error = std::convert::Infallible;

    fn acquire_retention_fence(
        &mut self,
    ) -> Result<Box<dyn AssignmentRetentionFence<BackendError = Self::Error> + '_>, Self::Error>
    {
        Ok(Box::new(SyntheticRetentionFence {
            generation: self.generation,
        }))
    }
}

struct SyntheticRetentionFence {
    generation: u8,
}

impl AssignmentRetentionFence for SyntheticRetentionFence {
    type BackendError = std::convert::Infallible;

    fn visit_roots(
        &mut self,
        _visitor: &mut dyn FnMut(
            AssignmentRetentionRoot,
        ) -> Result<(), AssignmentRetentionVisitorError>,
    ) -> Result<AssignmentRetentionSummary, AssignmentRetentionInventoryError<Self::BackendError>>
    {
        Ok(AssignmentRetentionSummary::new(
            AssignmentRetentionGeneration::from_bytes([self.generation; 32]),
            0,
            0,
            0,
        ))
    }
}

impl BlobInventoryFence for FailAfterFirstDeleteFence<'_> {
    fn visit_inventory(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        self.inner.visit_inventory(visitor)
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        if self.deletes == 1 {
            return Err(StoreError::Quota);
        }
        let disposition = self.inner.delete_candidate(id)?;
        self.deletes += 1;
        Ok(disposition)
    }
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
        None,
        None,
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
