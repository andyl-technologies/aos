#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::thread;

use crucible_campaign::{
    AuthorizedPlannerService, CampaignHash, CampaignMode, CampaignPlanningBundle,
    CampaignPlanningView, CampaignPolicy, CampaignSeed, CampaignSnapshotId, ExplorerPolicy,
    FairnessPolicy, GuidanceEvidence, PlannerAuthorityKey, PlannerClient, PlannerEngine,
    PlannerEngineOutput, PlannerExecutionSupervisor, PlannerInvocation, PlannerProposalDisposition,
    PlannerRequest, PlannerState, PlannerStepProposal, PlanningBudget, PlanningScanPage,
    PlanningUsage, PolicyArtifact, ProgressiveWideningPolicy, PuctPolicy, PurePlannerEngine,
    RetentionPolicy, ScenarioDefId, SupervisedPlannerExecution,
};
use crucible_cas::content_store::{ContentId, ObjectKind};

use super::*;

#[derive(Clone)]
struct FixedEngine {
    output: PlannerEngineOutput,
}

impl PurePlannerEngine for FixedEngine {
    type Error = Infallible;

    fn plan(&mut self, _request: &PlannerRequest) -> Result<PlannerEngineOutput, Self::Error> {
        Ok(self.output.clone())
    }
}

#[derive(Clone, Copy)]
struct FixedExecutionSupervisor(u64);

impl<E: PurePlannerEngine> PlannerExecutionSupervisor<E> for FixedExecutionSupervisor {
    type Error = Infallible;

    fn execute(
        &mut self,
        engine: &mut E,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<E::Error>, Self::Error> {
        Ok(SupervisedPlannerExecution::new(
            engine.plan(request),
            self.0,
        ))
    }
}

#[test]
fn direct_and_loopback_planner_components_are_identical() {
    let request = request(0x61);
    let authority = PlannerAuthorityKey::from_bytes([0x71; 32]).expect("authority");
    let output = no_work_output(&request);
    let direct = AuthorizedPlannerService::new(
        FixedEngine {
            output: output.clone(),
        },
        FixedExecutionSupervisor(1),
        authority.clone(),
    );
    let mut direct_client = PlannerClient::new(direct, authority.clone());
    let expected = direct_client.plan(&request).expect("direct response");

    let (client_stream, mut server_stream) = UnixStream::pair().expect("stream pair");
    let server_authority = authority.clone();
    let server_output = output;
    let server = thread::spawn(move || {
        let mut service = AuthorizedPlannerService::new(
            FixedEngine {
                output: server_output,
            },
            FixedExecutionSupervisor(1),
            server_authority,
        );
        serve_loopback_planner_once(&mut server_stream, &mut service).expect("serve planner");
    });
    let loopback = LoopbackPlannerService::new(client_stream).expect("loopback service");
    let mut loopback_client = PlannerClient::new(loopback, authority);
    let actual = loopback_client.plan(&request).expect("loopback response");
    server.join().expect("server thread");

    assert_eq!(actual, expected);
}

#[test]
fn planner_loopback_rejects_partial_frames_with_a_finite_deadline() {
    let (mut client, mut server) = UnixStream::pair().expect("stream pair");
    let timeouts = LoopbackPlannerTimeouts::new(
        std::time::Duration::from_millis(20),
        std::time::Duration::from_millis(20),
    )
    .expect("timeouts");
    let server_thread = thread::spawn(move || {
        let request = request(0x62);
        let authority = PlannerAuthorityKey::from_bytes([0x72; 32]).expect("authority");
        let mut service = AuthorizedPlannerService::new(
            FixedEngine {
                output: no_work_output(&request),
            },
            FixedExecutionSupervisor(1),
            authority,
        );
        assert!(matches!(
            serve_loopback_planner_once_with_timeouts(&mut server, &mut service, timeouts),
            Err(LoopbackPlannerServerError::Protocol(
                LoopbackPlannerProtocolError::Io(_)
            ))
        ));
    });
    client.write_all(b"CRUC").expect("partial frame");
    server_thread.join().expect("server thread");
}

fn request(byte: u8) -> PlannerRequest {
    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("engine");
    let engine_id = engine.id().expect("engine id");
    let policy_artifact = PolicyArtifact::new(
        engine_id,
        1,
        content(ObjectKind::Trace, byte.wrapping_add(1)),
        BTreeSet::new(),
        BTreeMap::new(),
    )
    .expect("policy artifact");
    let policy = policy(byte);
    let state =
        PlannerState::new(engine_id, "closed-state", 1, vec![byte; 8]).expect("planner state");
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

fn no_work_output(request: &PlannerRequest) -> PlannerEngineOutput {
    let usage = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: 0,
        input_bytes: 0,
        fuel: 1,
    };
    PlannerEngineOutput::new(
        PlannerStepProposal::new(
            request.invocation_id().expect("invocation id"),
            PlannerState::new(
                request.invocation().engine(),
                "closed-state",
                1,
                vec![0x77; 8],
            )
            .expect("next state"),
            usage,
            GuidanceEvidence::new(BTreeMap::new()).expect("evidence"),
            PlannerProposalDisposition::NoWork,
        )
        .expect("proposal"),
    )
}

fn policy(byte: u8) -> CampaignPolicy {
    CampaignPolicy::new(
        ScenarioDefId::from_hash(CampaignHash::derive(
            "crucible.test.planner-loopback-scenario.v1",
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
    .expect("policy")
}

fn content(kind: ObjectKind, byte: u8) -> ContentId {
    let schema_version = if kind == ObjectKind::CampaignSnapshot {
        2
    } else {
        1
    };
    ContentId::for_bytes(kind, schema_version, &[byte; 32])
}
