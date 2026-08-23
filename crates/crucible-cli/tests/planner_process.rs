//! Packaged canonical planner process supervision flight.

// crucible-lint: allow panic-shortcut -- integration fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crucible_campaign::{
    AuthorizedPlannerService, AuthorizedPlannerServiceError, CampaignHash, CampaignMode,
    CampaignPlanningBundle, CampaignPlanningView, CampaignPolicy, CampaignSeed, CampaignSnapshotId,
    CanonicalFrontierPlanner, ExplorerPolicy, FairnessPolicy, PlannerAuthorityKey,
    PlannerInvocation, PlannerProposalDisposition, PlannerRequest, PlannerService, PlanningBudget,
    PlanningScanPage, PolicyArtifact, ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy,
    ScenarioDefId,
};
use crucible_cas::content_store::{ContentId, ObjectKind};
use crucible_daemon::{
    CanonicalPlannerProcessConfig, CanonicalPlannerProcessError, CanonicalPlannerProcessSupervisor,
};

#[test]
fn packaged_worker_is_killable_supervised_and_parent_authenticated() {
    let request = canonical_request(0x61);
    let authority = PlannerAuthorityKey::from_bytes([0x71; 32]).expect("planner authority");
    let config =
        CanonicalPlannerProcessConfig::new(env!("CARGO_BIN_EXE_crucible"), Duration::from_secs(5))
            .expect("process config");
    let (supervisor, _cancellation) = CanonicalPlannerProcessSupervisor::new(config);
    let mut service =
        AuthorizedPlannerService::new(CanonicalFrontierPlanner, supervisor, authority.clone());

    let response = service.plan(&request).expect("supervised response");
    response.validate_for(&request).expect("request binding");
    assert!(response.verify(&authority));
    assert_eq!(response.submission().measured_usage().fuel, 1);
    assert!(matches!(
        response.submission().proposal().disposition(),
        PlannerProposalDisposition::NoWork
    ));
}

#[test]
fn sticky_cancellation_rejects_evaluation_before_launch() {
    let request = canonical_request(0x62);
    let authority = PlannerAuthorityKey::from_bytes([0x72; 32]).expect("planner authority");
    let config =
        CanonicalPlannerProcessConfig::new(env!("CARGO_BIN_EXE_crucible"), Duration::from_secs(5))
            .expect("process config");
    let (supervisor, cancellation) = CanonicalPlannerProcessSupervisor::new(config);
    cancellation.cancel();
    let mut service =
        AuthorizedPlannerService::new(CanonicalFrontierPlanner, supervisor, authority);

    assert!(matches!(
        service.plan(&request),
        Err(AuthorizedPlannerServiceError::Supervisor(
            CanonicalPlannerProcessError::Canceled
        ))
    ));
}

#[test]
fn minimum_deadline_kills_and_reaps_the_packaged_worker() {
    let request = canonical_request(0x63);
    let authority = PlannerAuthorityKey::from_bytes([0x73; 32]).expect("planner authority");
    let config = CanonicalPlannerProcessConfig::new(
        env!("CARGO_BIN_EXE_crucible"),
        Duration::from_millis(1),
    )
    .expect("process config");
    let (supervisor, _cancellation) = CanonicalPlannerProcessSupervisor::new(config);
    let mut service =
        AuthorizedPlannerService::new(CanonicalFrontierPlanner, supervisor, authority);

    assert!(matches!(
        service.plan(&request),
        Err(AuthorizedPlannerServiceError::Supervisor(
            CanonicalPlannerProcessError::TimedOut
        ))
    ));
}

fn canonical_request(byte: u8) -> PlannerRequest {
    let engine = CanonicalFrontierPlanner::descriptor().expect("canonical engine");
    let engine_id = engine.id().expect("engine id");
    let policy_artifact = PolicyArtifact::new(
        engine_id,
        1,
        content(ObjectKind::Trace, byte.wrapping_add(1)),
        BTreeSet::new(),
        BTreeMap::new(),
    )
    .expect("policy artifact");
    let policy = CampaignPolicy::new(
        ScenarioDefId::from_hash(CampaignHash::derive(
            "crucible.test.packaged-planner-process-scenario.v1",
            &[byte],
        )),
        CampaignSeed::from_bytes([byte; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            puct: PuctPolicy::new(1_000_000, 0, 0),
            widening: Some(
                ProgressiveWideningPolicy::new(
                    crucible_campaign::ExactRational::new(1, 1).expect("k"),
                    crucible_campaign::ExactRational::new(1, 2).expect("alpha"),
                    1,
                    4,
                    1,
                )
                .expect("widening"),
            ),
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(1, 1).expect("fairness"),
        RetentionPolicy::new(false, 1, false, false),
        false,
    )
    .expect("policy");
    let state = CanonicalFrontierPlanner::initial_state().expect("initial state");
    let view = CampaignPlanningView::new(
        content(ObjectKind::MerkleNode, byte.wrapping_add(2)),
        content(ObjectKind::MerkleNode, byte.wrapping_add(3)),
        content(ObjectKind::MerkleNode, byte.wrapping_add(4)),
        content(ObjectKind::MerkleNode, byte.wrapping_add(5)),
        content(ObjectKind::MerkleNode, byte.wrapping_add(6)),
        content(ObjectKind::MerkleNode, byte.wrapping_add(7)),
        content(ObjectKind::MerkleNode, byte.wrapping_add(8)),
    )
    .expect("planning view");
    let invocation = PlannerInvocation::new(
        engine_id,
        policy_artifact.id().expect("artifact id"),
        policy.id().expect("policy id"),
        state.id().expect("state id"),
        view.id().expect("view id"),
        PlanningScanPage::new(None, 1, Vec::new(), true, 0).expect("empty EOF page"),
        PlanningBudget::new(4, 4, 4, 4096, 1024).expect("budget"),
    )
    .expect("invocation");
    PlannerRequest::new(
        CampaignSnapshotId::parse(&format!(
            "crucible.campaign.snapshot@{}",
            content(ObjectKind::CampaignSnapshot, byte.wrapping_add(9)).encode()
        ))
        .expect("snapshot id"),
        invocation,
        engine,
        policy_artifact,
        policy,
        state,
        view,
        CampaignPlanningBundle::new(Vec::new()).expect("empty bundle"),
    )
    .expect("planner request")
}

fn content(kind: ObjectKind, byte: u8) -> ContentId {
    let schema_version = if kind == ObjectKind::CampaignSnapshot {
        2
    } else {
        1
    };
    ContentId::for_bytes(kind, schema_version, &[byte; 32])
}
