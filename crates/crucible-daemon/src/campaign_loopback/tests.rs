//! Campaign loopback framing, poisoning, authorization, and deadline tests.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;

use crucible_campaign::{
    ApplyCampaignCommandRequest, ApplyCampaignCommandResponse, BooleanDomain,
    BranchAcceptanceCount, BranchAcceptanceSummary, BranchBudget, BranchPointId, BranchRequest,
    BranchRequestCause, BranchRequestResult, CampaignBudgetLedger, CampaignChoiceEntry,
    CampaignChoiceObject, CampaignChoiceObjectKind, CampaignClient, CampaignCommandId,
    CampaignCommandResult, CampaignContinuationStatus, CampaignControlAction,
    CampaignDerivationResult, CampaignDiscoveryResult, CampaignFact,
    CampaignFindingOccurrenceObject, CampaignFindingOccurrenceObjectKind,
    CampaignFindingOccurrenceService, CampaignFindingTriageReplayRole, CampaignHash,
    CampaignLineage, CampaignMode, CampaignName, CampaignOperationalStatus, CampaignPolicy,
    CampaignPrincipal, CampaignPrincipalAuthorizer, CampaignRepository, CampaignRoots,
    CampaignSeed, CampaignSemanticStatus, CampaignService, CampaignServiceOperation,
    CampaignSnapshot, CampaignSnapshotId, CampaignState, CampaignStatusSummary, CandidateSource,
    ChoiceClassContext, ChoiceCoordinate, ChoiceDomain, ChoiceDomainId, ChoiceOpportunity,
    ChoiceOpportunityId, ChoiceSource, ChoiceValue, ConfigurationArtifact, ConfigurationArtifactId,
    ConfigurationId, ContinuationProjection, ContinuationState, ControlRequest,
    CreateCampaignRequest, CreateCampaignResponse, DeriveCampaignRequest, DeriveCampaignResponse,
    DiscoveryRequest, ExactRational, ExplainCampaignAttemptRequest, ExplainCampaignAttemptResponse,
    ExplorerPolicy, FairnessPolicy, FindingCandidateBundle, FindingCandidateBundleId, FindingId,
    FindingTriageEvidenceSet, FindingTriageReplayEvidence, GetCampaignChoiceObjectRequest,
    GetCampaignChoiceObjectResponse, GetCampaignFindingObjectRequest,
    GetCampaignFindingObjectResponse, GetCampaignFindingOccurrenceObjectRequest,
    GetCampaignFindingOccurrenceObjectResponse, GetCampaignFindingTriageReplaySegmentRequest,
    GetCampaignFindingTriageReplaySegmentResponse, GetCampaignFrontierObjectRequest,
    GetCampaignFrontierObjectResponse, GetCampaignGraphObjectRequest,
    GetCampaignGraphObjectResponse, GetCampaignPlannerRankingsRequest,
    GetCampaignPlannerRankingsResponse, GetCampaignRequest, GetCampaignResponse,
    GetCampaignSnapshotRequest, GetCampaignSnapshotResponse, MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES,
    MerkleMap, ObjectEnvelope, PinCampaignRequest, PinCampaignResponse, PinChange, PinRequest,
    PinRetention, ProgressiveWideningPolicy, PuctPolicy, QueryCampaignChoicesRequest,
    QueryCampaignChoicesResponse, QueryCampaignFindingOccurrencesRequest,
    QueryCampaignFindingOccurrencesResponse, QueryCampaignFindingsRequest,
    QueryCampaignFindingsResponse, QueryCampaignFrontierRequest, QueryCampaignFrontierResponse,
    QueryCampaignGraphRequest, QueryCampaignGraphResponse, RepositoryCampaignService,
    RetentionPolicy, ScenarioArtifactId, ScenarioDefId, SelectableDeclaration, StopCondition,
    SubmitCampaignBranchRequest, SubmitCampaignBranchResponse, SubmitCampaignDiscoveryRequest,
    SubmitCampaignDiscoveryResponse, WatchCampaignRequest, WatchCampaignResponse,
};
use crucible_cas::content_store::{ContentId, MemoryBlobBackend, MemoryRefBackend, ObjectKind};

use super::*;
use crate::{CampaignRuntimeAttachmentDisposition, CrucibleCampaignArtifactStore};

mod authentication;
mod fixed_service;
mod import;
mod protocol;
mod support;

use fixed_service::FixedCampaignService;
use support::{AllowAll, DenyAll, RecordingPeerResolver, RecordingRuntimeControl};

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("campaign-loopback-test", label.as_bytes())
}

fn snapshot(label: &str) -> CampaignSnapshotId {
    CampaignSnapshotId::parse(&format!(
        "crucible.campaign.snapshot@{}",
        ContentId::for_bytes(ObjectKind::CampaignSnapshot, 3, label.as_bytes()).encode()
    ))
    .expect("snapshot id")
}

fn lineage(label: &str) -> crucible_campaign::CampaignLineageId {
    crucible_campaign::CampaignLineageId::parse(&format!(
        "crucible.campaign.lineage@{}",
        ContentId::for_bytes(ObjectKind::CampaignFact, 1, label.as_bytes()).encode()
    ))
    .expect("lineage id")
}

fn policy(label: &str) -> crucible_campaign::CampaignPolicyId {
    policy_body(label).id().expect("policy id")
}

fn policy_body(label: &str) -> CampaignPolicy {
    creation_policy(ScenarioDefId::from_hash(hash(label)))
}

fn fixed_query_snapshot() -> (CampaignSnapshot, MerkleMap, ContentId) {
    let backend = Arc::new(MemoryBlobBackend::new("fixed-query", u64::MAX));
    let map = MerkleMap::new(backend);
    let empty = map.empty().expect("empty fixed query root").content_id();
    let (key, object) = fixed_graph_object();
    let choice = fixed_choice_entry();
    let choice_index = map
        .insert(empty, choice.index_key(), choice.opportunity().content_id())
        .expect("fixed choice index")
        .content_id();
    let root = map
        .insert(empty, key, object.content_id())
        .expect("fixed graph object")
        .content_id();
    let root = map
        .insert(root, CampaignChoiceEntry::index_anchor_key(), choice_index)
        .expect("fixed choice-index anchor")
        .content_id();
    let root = map
        .insert(root, choice.graph_key(), choice.opportunity().content_id())
        .expect("fixed choice opportunity")
        .content_id();
    let projection = fixed_frontier_projection();
    let frontier_index = map
        .insert(
            empty,
            CampaignHash::from_bytes(projection.request().content_id().digest()),
            projection.id().expect("projection id").content_id(),
        )
        .expect("fixed frontier index")
        .content_id();
    let exploration = map
        .insert(
            empty,
            CampaignHash::derive("crucible.campaign-exploration-frontier-index.v1", b""),
            frontier_index,
        )
        .expect("fixed frontier-index anchor")
        .content_id();
    let roots = CampaignRoots {
        graph: root,
        exploration,
        observations: empty,
        corpus: empty,
        coverage: empty,
        findings: empty,
        pins: empty,
        accounting: empty,
        coordination: empty,
    };
    let snapshot = CampaignSnapshot::genesis(
        lineage("lineage"),
        policy("policy"),
        roots,
        CampaignBudgetLedger::empty(empty)
            .expect("fixed query ledger")
            .id()
            .expect("fixed query ledger ID"),
    )
    .expect("fixed query snapshot");
    (snapshot, map, root)
}

fn fixed_frontier_projection() -> ContinuationProjection {
    ContinuationProjection::new(
        branch_submission("network-recovery")
            .request()
            .id()
            .expect("fixed frontier request"),
        BranchPointId::from_hash(hash("branch-point")),
        ContinuationState::Ready,
    )
}

fn fixed_choice_entry() -> CampaignChoiceEntry {
    CampaignChoiceEntry::new(
        fixed_choice_objects()
            .2
            .id()
            .expect("fixed choice opportunity"),
    )
}

fn fixed_choice_objects() -> (SelectableDeclaration, ChoiceDomain, ChoiceOpportunity) {
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.network.retry",
        ChoiceSource::Workload {
            producer: "network-product".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::from(["network-recovery".to_owned()]))
            .expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("selectable declaration");
    let opportunity = ChoiceOpportunity::new(
        ScenarioDefId::from_hash(hash("fixed-choice-scenario")),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: hash("fixed-choice-scheduler"),
            producer: hash("fixed-choice-producer"),
        },
        "fixed-choice",
        None,
    )
    .expect("choice opportunity");
    (declaration, domain, opportunity)
}

fn fixed_graph_object() -> (CampaignHash, ObjectEnvelope) {
    let scenario = ScenarioDefId::from_hash(hash("fixed-query-scenario"));
    let scenario_artifact = ScenarioArtifactId::parse(&format!(
        "crucible.campaign.scenario-artifact@{}",
        ContentId::for_bytes(ObjectKind::Scenario, 1, b"fixed-query-scenario").encode()
    ))
    .expect("fixed scenario artifact id");
    let artifact = ConfigurationArtifact::new(
        scenario,
        scenario_artifact,
        ConfigurationId::from_hash(hash("fixed-query-configuration")),
        1,
        b"fixed-query-configuration".to_vec(),
    )
    .expect("fixed configuration artifact");
    (
        hash("fixed-query-graph-key"),
        ObjectEnvelope::for_configuration_artifact(&artifact)
            .expect("fixed configuration envelope"),
    )
}

fn principal() -> CampaignPrincipal {
    CampaignPrincipal::new("operator:alice").expect("principal")
}

fn get_request(name: &str) -> GetCampaignRequest {
    GetCampaignRequest::new(principal(), CampaignName::new(name).expect("campaign name"))
        .expect("get request")
}

fn snapshot_request(name: &str, snapshot: CampaignSnapshotId) -> GetCampaignSnapshotRequest {
    GetCampaignSnapshotRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
    )
    .expect("snapshot request")
}

fn derive_request(source: &str, target: &str) -> DeriveCampaignRequest {
    DeriveCampaignRequest::new(
        principal(),
        CampaignName::new(source).expect("source campaign name"),
        snapshot("derive-source"),
        CampaignName::new(target).expect("target campaign name"),
        None,
    )
    .expect("derive request")
}

fn create_request(name: &str) -> CreateCampaignRequest {
    let scenario = ScenarioDefId::from_hash(hash("create-scenario"));
    let scenario_artifact = ScenarioArtifactId::parse(&format!(
        "crucible.campaign.scenario-artifact@{}",
        ContentId::for_bytes(ObjectKind::Scenario, 1, b"create-scenario-artifact").encode()
    ))
    .expect("scenario artifact id");
    let genesis = ConfigurationId::from_hash(hash("create-genesis"));
    let genesis_artifact = ConfigurationArtifactId::parse(&format!(
        "crucible.campaign.configuration-artifact@{}",
        ContentId::for_bytes(ObjectKind::Configuration, 1, b"create-genesis-artifact").encode()
    ))
    .expect("genesis artifact id");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_artifact,
        genesis,
        genesis_artifact,
        "crucible-test",
        "qemu-test",
        std::collections::BTreeMap::from([("control".to_owned(), 1)]),
        1,
        1,
    )
    .expect("lineage");
    CreateCampaignRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        lineage,
        creation_policy(scenario),
    )
    .expect("create request")
}

fn creation_policy(scenario: ScenarioDefId) -> CampaignPolicy {
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("widening constant"),
        ExactRational::new(1, 2).expect("widening exponent"),
        1,
        100,
        1,
    )
    .expect("widening");
    CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([7; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(widening),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
        ),
        CampaignPolicy::rules(
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )
    .expect("policy")
}

fn apply_request(name: &str) -> ApplyCampaignCommandRequest {
    ApplyCampaignCommandRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        ControlRequest {
            command: CampaignCommandId::from_hash(hash("resume")),
            expected_snapshot: snapshot("command-prior"),
            action: CampaignControlAction::Resume,
        },
    )
    .expect("apply request")
}

fn pin_request(name: &str) -> PinCampaignRequest {
    PinCampaignRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        PinRequest {
            command: CampaignCommandId::from_hash(hash("pin")),
            expected_snapshot: snapshot("pin-prior"),
            change: PinChange::new(
                ConfigurationId::from_hash(hash("pinned-configuration")),
                Some(PinRetention::Exact),
                "retain reproducer",
            )
            .expect("pin change"),
        },
    )
    .expect("pin request")
}

fn discovery_submission(name: &str) -> SubmitCampaignDiscoveryRequest {
    let configuration = ConfigurationArtifactId::parse(&format!(
        "crucible.campaign.configuration-artifact@{}",
        ContentId::for_bytes(ObjectKind::Configuration, 1, b"discovery-genesis").encode()
    ))
    .expect("discovery configuration");
    SubmitCampaignDiscoveryRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        DiscoveryRequest::new(
            CampaignCommandId::from_hash(hash("discovery")),
            snapshot("discovery-prior"),
            configuration,
            StopCondition::Terminal,
        )
        .expect("discovery command"),
    )
    .expect("discovery request")
}

fn watch_request(name: &str, after: Option<CampaignSnapshotId>) -> WatchCampaignRequest {
    WatchCampaignRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        after,
    )
    .expect("watch request")
}

fn graph_query_request(
    name: &str,
    snapshot: CampaignSnapshotId,
    after: Option<CampaignHash>,
    limit: u32,
) -> QueryCampaignGraphRequest {
    QueryCampaignGraphRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        after,
        limit,
    )
    .expect("graph query request")
}

fn finding_query_request(
    name: &str,
    snapshot: CampaignSnapshotId,
    after: Option<CampaignHash>,
    limit: u32,
) -> QueryCampaignFindingsRequest {
    QueryCampaignFindingsRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        after,
        limit,
    )
    .expect("finding query request")
}

fn graph_object_request(
    name: &str,
    snapshot: CampaignSnapshotId,
    key: CampaignHash,
) -> GetCampaignGraphObjectRequest {
    GetCampaignGraphObjectRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        key,
    )
    .expect("graph object request")
}

fn choice_query_request(
    name: &str,
    snapshot: CampaignSnapshotId,
    after: Option<ChoiceOpportunityId>,
    limit: u32,
) -> QueryCampaignChoicesRequest {
    QueryCampaignChoicesRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        after,
        limit,
    )
    .expect("choice query request")
}

fn frontier_query_request(
    name: &str,
    snapshot: CampaignSnapshotId,
    after: Option<crucible_campaign::BranchRequestId>,
    limit: u32,
) -> QueryCampaignFrontierRequest {
    QueryCampaignFrontierRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        after,
        limit,
    )
    .expect("frontier query request")
}

fn frontier_object_request(
    name: &str,
    snapshot: CampaignSnapshotId,
) -> GetCampaignFrontierObjectRequest {
    GetCampaignFrontierObjectRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        fixed_frontier_projection().request(),
    )
    .expect("frontier object request")
}

fn choice_object_request(
    name: &str,
    snapshot: CampaignSnapshotId,
    kind: CampaignChoiceObjectKind,
) -> GetCampaignChoiceObjectRequest {
    GetCampaignChoiceObjectRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot,
        fixed_choice_entry().opportunity(),
        kind,
    )
    .expect("choice object request")
}

fn branch_submission(name: &str) -> SubmitCampaignBranchRequest {
    SubmitCampaignBranchRequest::new(
        principal(),
        CampaignName::new(name).expect("campaign name"),
        snapshot("branch-prior"),
        BranchRequest::new(
            BranchRequest::identity(
                BranchPointId::from_hash(hash("branch-point")),
                ConfigurationArtifactId::parse(&format!(
                    "crucible.campaign.configuration-artifact@{}",
                    ContentId::for_bytes(ObjectKind::Configuration, 1, b"parent").encode()
                ))
                .expect("parent id"),
                ChoiceOpportunityId::parse(&format!(
                    "crucible.campaign.choice-opportunity@{}",
                    ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"opportunity").encode()
                ))
                .expect("opportunity id"),
                ChoiceDomainId::parse(&format!(
                    "crucible.campaign.choice-domain@{}",
                    ContentId::for_bytes(ObjectKind::CampaignFact, 2, b"domain").encode()
                ))
                .expect("domain id"),
            ),
            CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
                .expect("finite source"),
            BranchRequestCause::Operator(CampaignCommandId::from_hash(hash("branch-command"))),
            BranchBudget::new(1, 1).expect("branch budget"),
            StopCondition::NextChoice,
        )
        .expect("branch request"),
    )
    .expect("branch submission")
}
