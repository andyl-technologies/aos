//! Canonical identity and bound tests for campaign GC plan headers.

#![allow(clippy::expect_used)]

use super::*;

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
