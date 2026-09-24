//! Unit tests for the authenticated campaign service contracts.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use crucible_cas::content_store::{ContentId, MemoryBlobBackend, MemoryRefBackend, ObjectKind};

use super::*;
use crate::{
    AttemptAdmissionId, AttemptId, BranchAcceptanceCount, BranchAcceptanceSummary, BranchBudget,
    BranchPointId, BranchRequestCause, CampaignCommandId, CampaignControlAction,
    CampaignDiscoveryResult, CampaignMode, CampaignRoots, CampaignSeed, CandidateSource,
    ChoiceDomainId, ChoiceOpportunityId, ChoiceValue, ConfigurationArtifactId, ConfigurationId,
    DaemonEpoch, DiscoveryRequest, ExplorerPolicy, FairnessPolicy, PinChange, PinRequest,
    PinRetention, RetentionPolicy, ScenarioDefId, StopCondition,
};

mod checked_client;

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("campaign-service-test", label.as_bytes())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn snapshot(label: &str) -> CampaignSnapshotId {
    CampaignSnapshotId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignSnapshot,
        3,
        label.as_bytes(),
    ))
    .expect("snapshot id")
}

fn lineage(label: &str) -> CampaignLineageId {
    CampaignLineageId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignFact,
        1,
        label.as_bytes(),
    ))
    .expect("lineage id")
}

fn policy(label: &str) -> CampaignPolicyId {
    CampaignPolicyId::from_content_id(ContentId::for_bytes(
        ObjectKind::Policy,
        5,
        label.as_bytes(),
    ))
    .expect("policy id")
}

fn response_policy() -> CampaignPolicy {
    CampaignPolicy::new(
        CampaignPolicy::identity(
            ScenarioDefId::from_hash(hash("response-scenario")),
            CampaignSeed::from_bytes([0x42; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 4,
            },
        ),
        CampaignPolicy::rules(
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 4, true, true),
            false,
        ),
    )
    .expect("response policy")
}

fn branch_request(label: &str) -> BranchRequest {
    BranchRequest::new(
        BranchRequest::identity(
            BranchPointId::from_hash(hash(&format!("{label}-branch-point"))),
            ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
                ObjectKind::Configuration,
                1,
                format!("{label}-parent").as_bytes(),
            ))
            .expect("parent id"),
            ChoiceOpportunityId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                1,
                format!("{label}-opportunity").as_bytes(),
            ))
            .expect("opportunity id"),
            ChoiceDomainId::from_content_id(ContentId::for_bytes(
                ObjectKind::CampaignFact,
                2,
                format!("{label}-domain").as_bytes(),
            ))
            .expect("domain id"),
        ),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
            .expect("finite source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(hash(&format!(
            "{label}-command"
        )))),
        BranchBudget::new(1, 1).expect("branch budget"),
        StopCondition::NextChoice,
    )
    .expect("branch request")
}

fn get_request(name: &str) -> GetCampaignRequest {
    GetCampaignRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new(name).expect("campaign name"),
    )
    .expect("get request")
}

#[test]
fn campaign_names_match_the_repository_ref_grammar() {
    for invalid in ["bad:name", "a//b", "a/../b", "."] {
        assert!(CampaignName::new(invalid).is_err(), "accepted {invalid}");
    }
    assert!(CampaignName::new(format!("{}x", "a".repeat(255))).is_err());
    assert_eq!(
        CampaignName::new("team/network-recovery")
            .expect("nested campaign name")
            .as_str(),
        "team/network-recovery"
    );
}

#[test]
fn list_campaign_messages_are_canonical_ordered_and_request_bound() {
    let principal = CampaignPrincipal::new("operator:alice").expect("principal");
    let request = ListCampaignsRequest::new(principal.clone(), None, 2).expect("list request");
    assert_eq!(
        ListCampaignsRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode list request"),
        request
    );
    let entries = vec![
        CampaignListEntry::new(
            CampaignName::new("alpha").expect("alpha"),
            snapshot("alpha"),
            lineage("lineage"),
            policy("policy"),
            CampaignState::Running,
        ),
        CampaignListEntry::new(
            CampaignName::new("middle").expect("middle"),
            snapshot("middle"),
            lineage("lineage"),
            policy("policy"),
            CampaignState::Paused,
        ),
    ];
    let response = ListCampaignsResponse::new(
        &request,
        entries.clone(),
        Some(CampaignName::new("middle").expect("cursor")),
        2,
    )
    .expect("list response");
    assert_eq!(
        ListCampaignsResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode list response"),
        response
    );
    response.validate_for(&request).expect("request binding");

    let resumed = ListCampaignsRequest::new(
        principal,
        Some(CampaignName::new("alpha").expect("after")),
        2,
    )
    .expect("resumed request");
    assert!(response.validate_for(&resumed).is_err());
    assert!(
        ListCampaignsResponse::new(&request, entries.into_iter().rev().collect(), None, 2).is_err()
    );
    assert!(
        ListCampaignsRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            None,
            MAX_CAMPAIGN_LIST_PAGE_ITEMS + 1,
        )
        .is_err()
    );
}

#[test]
fn get_campaign_messages_are_canonical_and_request_bound() {
    let request = get_request("network-recovery");
    let policy_body = response_policy();
    assert_eq!(
        GetCampaignRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode request"),
        request
    );
    let response = GetCampaignResponse::new(
        &request,
        snapshot("snapshot"),
        lineage("lineage"),
        policy_body.id().expect("policy ID"),
        policy_body,
        CampaignState::Running,
    )
    .expect("response");
    assert_eq!(
        GetCampaignResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode response"),
        response
    );
    response.validate_for(&request).expect("request binding");
    assert!(response.validate_for(&get_request("other")).is_err());

    let timed_policy = response_policy()
        .with_attempt_timeout_policy(
            crate::CampaignAttemptTimeoutPolicy::new(Some(10), Some(4), Some(240_000))
                .expect("attempt timeout policy"),
        )
        .expect("timed campaign policy");
    assert_ne!(timed_policy.id().expect("timed ID"), response.policy());
    assert!(
        GetCampaignResponse::new(
            &request,
            response.snapshot(),
            response.lineage(),
            response.policy(),
            timed_policy.clone(),
            CampaignState::Running,
        )
        .is_err()
    );
    let timed_response = GetCampaignResponse::new(
        &request,
        response.snapshot(),
        response.lineage(),
        timed_policy.id().expect("timed ID"),
        timed_policy.clone(),
        CampaignState::Running,
    )
    .expect("timed response");
    assert_eq!(timed_response.policy_body(), &timed_policy);
    assert_eq!(
        GetCampaignResponse::from_canonical_bytes(&timed_response.canonical_bytes())
            .expect("timed policy response round trip"),
        timed_response
    );
    assert_eq!(
        timed_response
            .policy_body()
            .bound_stop(StopCondition::NextChoice)
            .expect("bound stop")
            .bounded_deadlines(),
        Some((Some(10), Some(4)))
    );

    assert_eq!(
        [
            blake3::hash(&request.canonical_bytes())
                .to_hex()
                .to_string(),
            blake3::hash(&response.canonical_bytes())
                .to_hex()
                .to_string(),
        ],
        [
            String::from("e25fd54be8cb0ea10f0dc695d3f7b029883e0f87269c692abe85f5ba9701a61d"),
            String::from("ff252716410aec699e6468c8cdf91eed05d652a7f2ddb0f4917fd269f8ad9210"),
        ]
    );
}

#[test]
fn campaign_status_messages_are_snapshot_bound_and_have_raw_vectors() {
    let head_request = get_request("network-recovery");
    let request = GetCampaignStatusRequest::new(
        head_request.principal().clone(),
        head_request.campaign().clone(),
        snapshot("snapshot"),
    )
    .expect("status request");
    let semantic = CampaignSemanticStatus::new(
        CampaignContinuationStatus::new(1, 2, 3, 4, 5),
        6,
        7,
        15,
        8_192,
    )
    .expect("semantic status");
    let operational = CampaignOperationalStatus::Observed(CampaignOperationalEvidence::new(
        DaemonEpoch::from_bytes([0x42; 16]).expect("daemon epoch"),
        hash("inventory"),
        CampaignWorldStatus::new(8, 9, 10, 11, 12, 13),
        14,
        15,
    ));
    let response =
        GetCampaignStatusResponse::new(&request, CampaignStatusSummary::new(semantic, operational))
            .expect("status response");

    assert_eq!(
        GetCampaignStatusRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode status request"),
        request
    );
    assert_eq!(
        GetCampaignStatusResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode status response"),
        response
    );
    response.validate_for(&request).expect("request binding");

    let other_snapshot = GetCampaignStatusRequest::new(
        request.principal().clone(),
        request.campaign().clone(),
        snapshot("other"),
    )
    .expect("other status request");
    assert!(response.validate_for(&other_snapshot).is_err());

    assert_eq!(
        encode_hex(&request.canonical_bytes()),
        "00000001000000000000000e6f70657261746f723a616c69636500000000000000106e6574776f726b2d7265636f76657279000000000000001a6372756369626c652e63616d706169676e2e736e617073686f74000000000000005463616d706169676e2d736e617073686f742e332e30366236343936623634333334396237373162303937613135616166353265373038383362666139646132303666646138393732313936333161303962363633"
    );
    assert_eq!(
        encode_hex(&response.canonical_bytes()),
        "000000015fb7219275515e0774826d5cc04bf9c41e7974c4c2aa996fda58247823f7a16b000000000000001a6372756369626c652e63616d706169676e2e736e617073686f74000000000000005463616d706169676e2d736e617073686f742e332e303662363439366236343333343962373731623039376131356161663532653730383833626661396461323036666461383937323139363331613039623636330000000000000001000000000000000200000000000000030000000000000004000000000000000500000000000000060000000000000007000000000000000f000000000000200001424242424242424242424242424242428a56cb32569d9a14271f8d8ce49d59c77d6a288e42372209b4234532c01c3f2900000000000000080000000000000009000000000000000a000000000000000b000000000000000c000000000000000d000000000000000e000000000000000f"
    );
}

#[test]
fn apply_command_messages_bind_principal_name_and_payload() {
    let request = ApplyCampaignCommandRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign name"),
        ControlRequest {
            command: CampaignCommandId::from_hash(hash("resume")),
            expected_snapshot: snapshot("prior"),
            action: CampaignControlAction::Resume,
        },
    )
    .expect("apply request");
    assert_eq!(
        ApplyCampaignCommandRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode request"),
        request
    );
    let response = ApplyCampaignCommandResponse::new(
        &request,
        CampaignCommandResult {
            prior_snapshot: snapshot("prior"),
            new_snapshot: snapshot("next"),
            replayed: false,
        },
    )
    .expect("apply response");
    response.validate_for(&request).expect("request binding");

    let other_principal = ApplyCampaignCommandRequest::new(
        CampaignPrincipal::new("operator:bob").expect("principal"),
        request.campaign().clone(),
        request.command().clone(),
    )
    .expect("other request");
    assert!(response.validate_for(&other_principal).is_err());

    assert_eq!(
        [
            blake3::hash(&request.canonical_bytes())
                .to_hex()
                .to_string(),
            blake3::hash(&response.canonical_bytes())
                .to_hex()
                .to_string(),
        ],
        [
            String::from("600d71c591f0a3b03ccf47413529466e32008663fad4e6f9fbcaaf375314a36d"),
            String::from("1ccec27169aa62ce8c9f530542930b5560e33d6220136442d69c97ce5fba1bb4"),
        ]
    );
}

#[test]
fn branch_messages_are_canonical_and_bind_the_exact_request() {
    let request = SubmitCampaignBranchRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign name"),
        snapshot("prior"),
        branch_request("first"),
    )
    .expect("branch submission");
    assert_eq!(
        SubmitCampaignBranchRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode request"),
        request
    );
    let summary = BranchAcceptanceSummary::new(
        BranchAcceptanceCount::Exact(1),
        BranchAcceptanceCount::Exact(0),
        BranchAcceptanceCount::Exact(1),
        1,
        1,
    )
    .expect("acceptance summary");
    let acceptance_fact = CampaignFact::BranchRequestAccepted {
        request: request.request().id().expect("request id"),
        summary,
    };
    let root = ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"branch-response-root");
    let accepted_snapshot = CampaignSnapshot::successor(
        snapshot("prior"),
        lineage("branch-response"),
        policy("branch-response"),
        CampaignRoots {
            graph: root,
            exploration: root,
            observations: root,
            corpus: root,
            coverage: root,
            findings: root,
            pins: root,
            accounting: root,
            coordination: root,
        },
        acceptance_fact.id().expect("acceptance fact id"),
        crate::test_budget_ledger_id(),
    )
    .expect("accepted snapshot");
    let response = SubmitCampaignBranchResponse::new(
        &request,
        BranchRequestResult {
            prior_snapshot: snapshot("prior"),
            new_snapshot: accepted_snapshot.id().expect("accepted snapshot id"),
            request: request.request().id().expect("request id"),
            summary,
            snapshot: accepted_snapshot,
            acceptance_fact,
            replayed: false,
        },
    )
    .expect("branch response");
    assert_eq!(
        SubmitCampaignBranchResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode response"),
        response
    );
    response.validate_for(&request).expect("request binding");
    let mut malformed_schema = response.canonical_bytes();
    malformed_schema[..std::mem::size_of::<u32>()].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(SubmitCampaignBranchResponse::from_canonical_bytes(&malformed_schema).is_err());
    let mut truncated = response.canonical_bytes();
    truncated.pop();
    assert!(SubmitCampaignBranchResponse::from_canonical_bytes(&truncated).is_err());
    let mut trailing = response.canonical_bytes();
    trailing.push(0);
    assert!(SubmitCampaignBranchResponse::from_canonical_bytes(&trailing).is_err());

    let different_summary = BranchAcceptanceSummary::new(
        BranchAcceptanceCount::Exact(1),
        BranchAcceptanceCount::Exact(1),
        BranchAcceptanceCount::Exact(0),
        1,
        1,
    )
    .expect("different acceptance summary");
    let mut mismatched_fact = response.clone();
    mismatched_fact.summary = different_summary;
    assert!(mismatched_fact.validate_for(&request).is_err());

    let different_budget = BranchAcceptanceSummary::new(
        BranchAcceptanceCount::Exact(2),
        BranchAcceptanceCount::Exact(0),
        BranchAcceptanceCount::Exact(2),
        2,
        1,
    )
    .expect("different acceptance budget");
    let mut mismatched_budget = response.clone();
    mismatched_budget.summary = different_budget;
    mismatched_budget.acceptance_fact = CampaignFact::BranchRequestAccepted {
        request: mismatched_budget.request,
        summary: different_budget,
    };
    assert!(mismatched_budget.validate_for(&request).is_err());

    let changed = SubmitCampaignBranchRequest::new(
        request.principal().clone(),
        request.campaign().clone(),
        snapshot("other-prior"),
        request.request().clone(),
    )
    .expect("changed submission");
    assert!(response.validate_for(&changed).is_err());

    assert_eq!(
        [
            blake3::hash(&request.canonical_bytes())
                .to_hex()
                .to_string(),
            blake3::hash(&response.canonical_bytes())
                .to_hex()
                .to_string(),
        ],
        [
            String::from("4c7e311ee4b4c4fec7e6577cffe3bf297d4a9d54ac50db3fa3c9dff03396653b"),
            String::from("cf4716f983aac27057f216f5c7457325df6e8fd27256f3e76fae293a114422d6"),
        ]
    );
}

#[test]
fn pin_messages_are_canonical_and_bind_the_exact_request() {
    let request = PinCampaignRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign name"),
        PinRequest {
            command: CampaignCommandId::from_hash(hash("pin")),
            expected_snapshot: snapshot("prior"),
            change: PinChange::new(
                ConfigurationId::from_hash(hash("configuration")),
                Some(PinRetention::Thin),
                "retain semantic replay",
            )
            .expect("pin change"),
        },
    )
    .expect("pin request");
    assert_eq!(
        PinCampaignRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode pin request"),
        request
    );

    let response = PinCampaignResponse::new(
        &request,
        CampaignCommandResult {
            prior_snapshot: snapshot("prior"),
            new_snapshot: snapshot("next"),
            replayed: false,
        },
    )
    .expect("pin response");
    assert_eq!(
        PinCampaignResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode pin response"),
        response
    );
    response.validate_for(&request).expect("request binding");

    let changed = PinCampaignRequest::new(
        request.principal().clone(),
        request.campaign().clone(),
        PinRequest {
            command: request.command().command,
            expected_snapshot: snapshot("other-prior"),
            change: request.command().change.clone(),
        },
    )
    .expect("changed pin request");
    assert!(response.validate_for(&changed).is_err());

    assert_eq!(
        [
            blake3::hash(&request.canonical_bytes())
                .to_hex()
                .to_string(),
            blake3::hash(&response.canonical_bytes())
                .to_hex()
                .to_string(),
        ],
        [
            String::from("314e5be32404396ac183a793a87ce47594056012d2f93b793f4c39000a196905"),
            String::from("326d43f81a14e0d706638b7d3afdc69d06557cea7b24eb6687728bc1758dea84"),
        ]
    );
}

#[test]
fn discovery_messages_are_canonical_and_bind_the_exact_request() {
    let configuration = ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
        ObjectKind::Configuration,
        1,
        b"discovery-configuration",
    ))
    .expect("configuration artifact ID");
    let request = SubmitCampaignDiscoveryRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign name"),
        DiscoveryRequest::new(
            CampaignCommandId::from_hash(hash("discovery")),
            snapshot("prior"),
            configuration,
            StopCondition::Terminal,
        )
        .expect("discovery command"),
    )
    .expect("discovery request");
    assert_eq!(
        SubmitCampaignDiscoveryRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode discovery request"),
        request
    );

    let attempt = AttemptId::parse(&format!(
        "crucible.campaign.attempt@{}",
        ContentId::for_bytes(ObjectKind::CampaignFact, 9, b"discovery-attempt").encode()
    ))
    .expect("attempt ID");
    let admission = AttemptAdmissionId::parse(&format!(
        "crucible.campaign.attempt-admission@{}",
        ContentId::for_bytes(ObjectKind::CampaignFact, 3, b"discovery-admission").encode()
    ))
    .expect("admission ID");
    let response = SubmitCampaignDiscoveryResponse::new(
        &request,
        CampaignDiscoveryResult {
            prior_snapshot: snapshot("prior"),
            new_snapshot: snapshot("next"),
            attempt,
            admission,
            replayed: false,
        },
    )
    .expect("discovery response");
    assert_eq!(
        SubmitCampaignDiscoveryResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode discovery response"),
        response
    );
    response.validate_for(&request).expect("request binding");

    let changed = SubmitCampaignDiscoveryRequest::new(
        request.principal().clone(),
        request.campaign().clone(),
        DiscoveryRequest::new(
            request.command().command,
            request.command().expected_snapshot,
            request.command().configuration,
            StopCondition::NextChoice,
        )
        .expect("changed discovery command"),
    )
    .expect("changed discovery request");
    assert!(response.validate_for(&changed).is_err());

    let mut malformed_schema = response.canonical_bytes();
    malformed_schema[..std::mem::size_of::<u32>()].copy_from_slice(&2_u32.to_be_bytes());
    assert!(SubmitCampaignDiscoveryResponse::from_canonical_bytes(&malformed_schema).is_err());

    assert_eq!(
        [
            blake3::hash(&request.canonical_bytes())
                .to_hex()
                .to_string(),
            blake3::hash(&response.canonical_bytes())
                .to_hex()
                .to_string(),
        ],
        [
            String::from("3c5f6e8cb138c61f0d5166718e04a3f4531f8d44d17a5ad525c8593f80361842"),
            String::from("4ec88d3103957d2cc90c76d5aff9c75d64601802940583d23d5d76876142fffc"),
        ]
    );
}

#[test]
fn service_error_responses_are_canonical_and_request_bound() {
    let request_digest = hash("error-request");
    let failures = [
        (
            CampaignServiceFailure::Unauthorized,
            CampaignServiceRetryDisposition::Reauthenticate,
        ),
        (
            CampaignServiceFailure::AuthorizationUnavailable,
            CampaignServiceRetryDisposition::RetryAfterBackoff,
        ),
        (
            CampaignServiceFailure::NotFound,
            CampaignServiceRetryDisposition::OperatorAction,
        ),
        (
            CampaignServiceFailure::AlreadyExists,
            CampaignServiceRetryDisposition::OperatorAction,
        ),
        (
            CampaignServiceFailure::Stale {
                expected: snapshot("expected"),
                current: snapshot("current"),
            },
            CampaignServiceRetryDisposition::RefreshCampaign,
        ),
        (
            CampaignServiceFailure::CommandReuse,
            CampaignServiceRetryDisposition::DoNotRetry,
        ),
        (
            CampaignServiceFailure::ConcurrentUpdate,
            CampaignServiceRetryDisposition::RefreshCampaign,
        ),
        (
            CampaignServiceFailure::InvalidTransition {
                state: CampaignState::Sealed,
            },
            CampaignServiceRetryDisposition::OperatorAction,
        ),
        (
            CampaignServiceFailure::InvalidRequest,
            CampaignServiceRetryDisposition::DoNotRetry,
        ),
        (
            CampaignServiceFailure::BackendUnauthorized,
            CampaignServiceRetryDisposition::Reauthenticate,
        ),
        (
            CampaignServiceFailure::ResourceExhausted,
            CampaignServiceRetryDisposition::RetryAfterBackoff,
        ),
        (
            CampaignServiceFailure::Unavailable,
            CampaignServiceRetryDisposition::RetryAfterBackoff,
        ),
        (
            CampaignServiceFailure::IntegrityFailure,
            CampaignServiceRetryDisposition::DoNotRetry,
        ),
        (
            CampaignServiceFailure::ProtocolViolation,
            CampaignServiceRetryDisposition::DoNotRetry,
        ),
    ];
    for (failure, retry_disposition) in failures {
        let response =
            CampaignServiceErrorResponse::new(request_digest, failure).expect("error response");
        assert_eq!(
            CampaignServiceErrorResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode error response"),
            response
        );
        response
            .validate_for_digest(request_digest)
            .expect("request binding");
        assert_eq!(response.failure(), failure);
        assert!(
            response
                .validate_for_digest(hash("other-error-request"))
                .is_err()
        );
        assert_eq!(failure.retry_disposition(), retry_disposition);
    }
    let golden =
        CampaignServiceErrorResponse::new(request_digest, CampaignServiceFailure::Unauthorized)
            .expect("golden error response");
    assert_eq!(
        blake3::hash(&golden.canonical_bytes()).to_hex().to_string(),
        "26766ef9f5cf89d87b0e660c0a498a7dcad09764bd5952d89c82728bd7c34d67"
    );
    assert_eq!(
        repository_service_failure(&CampaignRepositoryError::Poisoned),
        CampaignServiceFailure::IntegrityFailure
    );
    assert_eq!(
        store_service_failure(&StoreError::Poisoned {
            operation: "campaign-service-test",
        }),
        CampaignServiceFailure::IntegrityFailure
    );
}

struct DenyAll;

impl CampaignPrincipalAuthorizer for DenyAll {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Err(CampaignAuthorizationError::Unauthorized)
    }
}

#[test]
fn repository_adapter_authorizes_before_repository_access() {
    let repository = CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("campaign-service-test", u64::MAX)),
        Arc::new(MemoryRefBackend::new()),
    );
    let service = RepositoryCampaignService::new(&repository, DenyAll);
    let list = ListCampaignsRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        None,
        1,
    )
    .expect("list request");
    assert!(matches!(
        service.list_campaigns(&list),
        Err(RepositoryCampaignServiceError::Authorization(
            CampaignAuthorizationError::Unauthorized
        ))
    ));
    assert!(matches!(
        service.get_campaign(&get_request("absent")),
        Err(RepositoryCampaignServiceError::Authorization(
            CampaignAuthorizationError::Unauthorized
        ))
    ));
    let client = CampaignClient::new(RepositoryCampaignService::new(&repository, DenyAll));
    assert!(matches!(
        client.get_campaign(&get_request("absent")),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::Unauthorized
        ))
    ));

    let pin = PinCampaignRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("absent").expect("campaign name"),
        PinRequest {
            command: CampaignCommandId::from_hash(hash("pin")),
            expected_snapshot: snapshot("absent"),
            change: PinChange::new(
                ConfigurationId::from_hash(hash("configuration")),
                None,
                "remove stale pin",
            )
            .expect("pin change"),
        },
    )
    .expect("pin request");
    assert!(matches!(
        client.pin_campaign(&pin),
        Err(CampaignClientError::Service(
            CampaignServiceFailure::Unauthorized
        ))
    ));
}
