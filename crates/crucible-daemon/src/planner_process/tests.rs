//! Canonical planner process protocol and configuration regressions.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use crucible_campaign::{
    CampaignHash, CampaignMode, CampaignPlanningBundle, CampaignPlanningView, CampaignPolicy,
    CampaignSeed, CampaignSnapshotId, ExplorerPolicy, FairnessPolicy, PlannerInvocation,
    PlannerProposalDisposition, PlanningBudget, PlanningScanPage, PolicyArtifact,
    ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy, ScenarioDefId,
};
use crucible_cas::content_store::{ContentId, ObjectKind};

use super::*;

#[test]
fn process_frame_header_is_exact_and_round_trips() {
    let mut frame = Vec::new();
    write_frame(&mut frame, REQUEST_KIND, b"request").expect("write frame");
    assert_eq!(
        &frame[..FRAME_HEADER_BYTES],
        &[
            b'C', b'R', b'U', b'C', b'P', b'P', b'0', b'1', 1, 0, 0, 0, 0, 0, 0, 7,
        ]
    );
    let (kind, body) = read_frame(Cursor::new(frame)).expect("read frame");
    assert_eq!(kind, REQUEST_KIND);
    assert_eq!(body, b"request");
}

#[test]
fn process_frame_rejects_reserved_version_and_size_drift() {
    let mut frame = Vec::new();
    write_frame(&mut frame, REQUEST_KIND, b"request").expect("write frame");
    frame[9] = 1;
    assert!(read_frame(Cursor::new(&frame)).is_err());

    frame[9] = 0;
    frame[..8].copy_from_slice(b"CRUCPP02");
    assert!(read_frame(Cursor::new(&frame)).is_err());

    frame[..8].copy_from_slice(FRAME_MAGIC);
    frame[12..16]
        .copy_from_slice(&((MAX_PLANNER_COMPONENT_MESSAGE_BYTES as u32) + 1).to_be_bytes());
    assert!(read_frame(Cursor::new(&frame)).is_err());
}

#[test]
fn process_configuration_bounds_path_and_timeout() {
    assert!(matches!(
        CanonicalPlannerProcessConfig::new("relative-worker", Duration::from_secs(1)),
        Err(CanonicalPlannerProcessError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        CanonicalPlannerProcessConfig::new("/worker", Duration::ZERO),
        Err(CanonicalPlannerProcessError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        CanonicalPlannerProcessConfig::new("/worker", Duration::from_secs(61)),
        Err(CanonicalPlannerProcessError::InvalidConfiguration(_))
    ));
    let config = CanonicalPlannerProcessConfig::new("/worker", Duration::from_secs(1))
        .expect("bounded config");
    assert_eq!(config.executable(), Path::new("/worker"));
    assert_eq!(config.execution_timeout(), Duration::from_secs(1));
}

#[test]
fn cancellation_is_sticky_before_process_launch() {
    let config = CanonicalPlannerProcessConfig::new("/does-not-exist", Duration::from_secs(1))
        .expect("bounded config");
    let (_supervisor, cancellation) = CanonicalPlannerProcessSupervisor::new(config);
    cancellation.cancel();
    assert!(cancellation.is_canceled());
}

#[test]
fn canonical_worker_returns_only_one_untrusted_proposal_frame() {
    let request = canonical_request(0x51);
    let mut input = Vec::new();
    write_frame(&mut input, REQUEST_KIND, &request.canonical_bytes()).expect("request frame");
    let mut output = Vec::new();
    serve_canonical_planner_process_once(Cursor::new(input), &mut output)
        .expect("serve canonical planner");

    let (kind, body) = parse_frame(&output).expect("proposal frame");
    assert_eq!(kind, PROPOSAL_KIND);
    let proposal = PlannerStepProposal::from_canonical_bytes(body).expect("proposal");
    assert_eq!(
        proposal.invocation(),
        request.invocation_id().expect("invocation")
    );
    assert!(matches!(
        proposal.disposition(),
        PlannerProposalDisposition::NoWork
    ));
    assert_eq!(proposal.usage_claim().fuel, 1);
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
            "crucible.test.planner-process-scenario.v1",
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
