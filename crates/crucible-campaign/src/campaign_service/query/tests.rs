//! Unit tests for proof-bearing campaign query messages.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crucible_cas::content_store::{MemoryBlobBackend, ObjectKind};

use super::*;
use crate::{
    AdmissionOrdinal, AttemptId, BooleanDomain, BranchBudget, BranchPathId, BranchPathSegment,
    BranchPointId, BranchRequestCause, CampaignCommandId, CampaignPolicyId, CampaignRoots,
    CampaignViewId, CandidateSource, ChoiceClassContext, ChoiceCoordinate, ChoiceDomainId,
    ChoiceOpportunityId, ChoiceSource, ChoiceValue, ConfigurationArtifact, ConfigurationArtifactId,
    ConfigurationId, ContinuationState, CoverageProjectionId, FindingKind, FindingOccurrenceSet,
    FindingSignature, GuidanceEvidence, MeasurementSetId, ObservationId, PlannerDisposition,
    PlannerEngineId, PlannerInvocationId, PlannerStateId, PlanningAccounting, PlanningScanPosition,
    PlanningUsage, PolicyArtifactId, PropertyVerdictSetId, ReproductionArtifactId,
    RetainedPlannerRequestId, ScenarioArtifactId, ScenarioDefId, StopCondition, StopOutcome,
};

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("campaign-query-test-hash", label.as_bytes())
}

fn snapshot(label: &str) -> CampaignSnapshotId {
    CampaignSnapshotId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignSnapshot,
        2,
        label.as_bytes(),
    ))
    .expect("snapshot")
}

fn graph_entry(label: &str) -> CampaignGraphEntry {
    CampaignGraphEntry::new(
        CampaignHash::derive("campaign-query-test-key", label.as_bytes()),
        ContentId::for_bytes(ObjectKind::CampaignFact, 1, label.as_bytes()),
    )
}

fn branch_request(label: &str) -> BranchRequest {
    let hash = |suffix: &str| {
        CampaignHash::derive(
            "campaign-frontier-object-test",
            format!("{label}-{suffix}").as_bytes(),
        )
    };
    BranchRequest::new(
        BranchPointId::from_hash(hash("branch-point")),
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
            1,
            format!("{label}-domain").as_bytes(),
        ))
        .expect("domain id"),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
            .expect("finite source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(hash("command"))),
        BranchBudget::new(1, 1).expect("branch budget"),
        StopCondition::NextChoice,
    )
    .expect("branch request")
}

fn configuration_envelope(label: &str) -> ObjectEnvelope {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
        "campaign-query-test-scenario",
        label.as_bytes(),
    ));
    let scenario_artifact = ScenarioArtifactId::from_content_id(ContentId::for_bytes(
        ObjectKind::Scenario,
        1,
        format!("{label}-scenario").as_bytes(),
    ))
    .expect("scenario artifact id");
    let configuration = ConfigurationArtifact::new(
        scenario,
        scenario_artifact,
        ConfigurationId::from_hash(CampaignHash::derive(
            "campaign-query-test-configuration",
            label.as_bytes(),
        )),
        1,
        label.as_bytes().to_vec(),
    )
    .expect("configuration artifact");
    ObjectEnvelope::for_configuration_artifact(&configuration).expect("configuration envelope")
}

fn choice_objects() -> (SelectableDeclaration, ChoiceDomain, ChoiceOpportunity) {
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
    .expect("declaration");
    let opportunity = ChoiceOpportunity::new(
        ScenarioDefId::from_hash(CampaignHash::derive(
            "campaign-choice-object-test-scenario",
            b"scenario",
        )),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("campaign-choice-object-test-coordinate", b"scheduler"),
            producer: CampaignHash::derive("campaign-choice-object-test-coordinate", b"producer"),
        },
        "retry-choice",
        None,
    )
    .expect("opportunity");
    (declaration, domain, opportunity)
}

fn finding(label: &str, occurrence_root: ContentId) -> Finding {
    let observation = ObservationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Observation,
        1,
        format!("{label}-observation").as_bytes(),
    ))
    .expect("observation id");
    Finding::new(
        FindingSignature::new(
            FindingKind::Timeout,
            CampaignHash::derive("campaign-query-finding-fingerprint", label.as_bytes()),
            None,
            format!("timeout.{label}"),
            None,
            BTreeSet::new(),
        )
        .expect("finding signature"),
        observation,
        ReproductionArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Finding,
            1,
            format!("{label}-reproduction").as_bytes(),
        ))
        .expect("reproduction id"),
        snapshot(&format!("{label}-first-seen")),
        FindingOccurrenceSet::new(occurrence_root, 1, observation).expect("finding occurrences"),
        None,
        BTreeSet::new(),
    )
    .expect("finding")
}

#[test]
fn graph_pages_are_canonical_bounded_snapshot_and_cursor_bound() {
    assert!(
        QueryCampaignGraphRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot("current"),
            None,
            0,
        )
        .is_err()
    );
    assert!(
        QueryCampaignGraphRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot("current"),
            None,
            MAX_CAMPAIGN_QUERY_PAGE_ITEMS + 1,
        )
        .is_err()
    );

    let backend = Arc::new(MemoryBlobBackend::new("query-proof-test", u64::MAX));
    let map = MerkleMap::new(backend);
    let mut root = map.empty().expect("empty graph root");
    for entry in [
        graph_entry("first"),
        graph_entry("second"),
        graph_entry("third"),
    ] {
        root = map
            .insert(root.content_id(), entry.key(), entry.object())
            .expect("graph insert");
    }
    let roots = crate::CampaignRoots {
        graph: root.content_id(),
        exploration: root.content_id(),
        observations: root.content_id(),
        corpus: root.content_id(),
        coverage: root.content_id(),
        findings: root.content_id(),
        pins: root.content_id(),
        accounting: root.content_id(),
        coordination: root.content_id(),
    };
    let snapshot_body = CampaignSnapshot::genesis(
        CampaignLineageId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"query-lineage",
        ))
        .expect("lineage"),
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"query-policy",
        ))
        .expect("policy"),
        roots,
    )
    .expect("query snapshot");
    let request = QueryCampaignGraphRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign"),
        snapshot_body.id().expect("snapshot id"),
        None,
        2,
    )
    .expect("query request");
    assert_eq!(
        QueryCampaignGraphRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode request"),
        request
    );

    let (page, proof) = map
        .scan_with_proof(root.content_id(), None, 2)
        .expect("proven page");
    let entries = page
        .entries()
        .iter()
        .map(|(key, object)| CampaignGraphEntry::new(*key, *object))
        .collect::<Vec<_>>();
    let response = QueryCampaignGraphResponse::new(
        &request,
        snapshot_body.clone(),
        entries.clone(),
        page.next_after(),
        proof.clone(),
    )
    .expect("query response");
    response.validate_for(&request).expect("response binding");
    assert_eq!(
        QueryCampaignGraphResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode response"),
        response
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
            String::from("1bf139d3ed67872df2ec5241f5b1f3ffa578372fb8899deda231919342a834c0"),
            String::from("3d774c8603010f829bc81f672cabc7c683c98f9adeb8e10c7d8753f39b51f323"),
        ]
    );

    let mut reversed = entries.clone();
    reversed.reverse();
    assert!(
        QueryCampaignGraphResponse::new(
            &request,
            snapshot_body.clone(),
            reversed,
            page.next_after(),
            proof.clone(),
        )
        .is_err()
    );
    let mut forged_eof = response.clone();
    forged_eof.next_after = None;
    let forged_eof =
        QueryCampaignGraphResponse::from_canonical_bytes(&forged_eof.canonical_bytes())
            .expect("structurally canonical forged EOF");
    assert!(forged_eof.validate_for(&request).is_err());

    let mut substituted = entries.clone();
    substituted[0] = CampaignGraphEntry::new(
        substituted[0].key(),
        ContentId::for_bytes(ObjectKind::CampaignFact, 1, b"substituted-object"),
    );
    assert!(
        QueryCampaignGraphResponse::new(
            &request,
            snapshot_body.clone(),
            substituted.clone(),
            page.next_after(),
            proof.clone(),
        )
        .is_err()
    );
    let mut forged_entry = response.clone();
    forged_entry.entries = substituted;
    let forged_entry =
        QueryCampaignGraphResponse::from_canonical_bytes(&forged_entry.canonical_bytes())
            .expect("structurally canonical substituted entry");
    assert!(forged_entry.validate_for(&request).is_err());

    assert!(
        QueryCampaignGraphResponse::new(
            &request,
            snapshot_body.clone(),
            entries.clone(),
            None,
            proof.clone(),
        )
        .is_err()
    );
    assert!(
        QueryCampaignGraphResponse::new(
            &request,
            snapshot_body,
            entries[..1].to_vec(),
            page.next_after(),
            proof,
        )
        .is_err()
    );

    let next_request = QueryCampaignGraphRequest::new(
        request.principal().clone(),
        request.campaign().clone(),
        request.snapshot(),
        response.next_after(),
        2,
    )
    .expect("next request");
    assert!(response.validate_for(&next_request).is_err());

    assert!(
        CampaignServiceFailure::Stale {
            expected: request.snapshot(),
            current: snapshot("new-current"),
        }
        .validate_for_query_campaign_graph(request.snapshot())
        .is_ok()
    );
    assert!(
        CampaignServiceFailure::Stale {
            expected: snapshot("wrong-expected"),
            current: snapshot("new-current"),
        }
        .validate_for_query_campaign_graph(request.snapshot())
        .is_err()
    );
    assert!(
        CampaignServiceFailure::Stale {
            expected: request.snapshot(),
            current: request.snapshot(),
        }
        .validate_for_query_campaign_graph(request.snapshot())
        .is_err()
    );
}

#[test]
fn finding_pages_authenticate_complete_bodies_order_and_exact_eof() {
    assert!(
        QueryCampaignFindingsRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot("current"),
            None,
            MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS + 1,
        )
        .is_err()
    );

    let backend = Arc::new(MemoryBlobBackend::new("finding-query-proof", u64::MAX));
    let map = MerkleMap::new(backend);
    let empty = map.empty().expect("empty finding index");
    let findings = [
        finding("first", empty.content_id()),
        finding("second", empty.content_id()),
        finding("third", empty.content_id()),
    ];
    let mut root = empty;
    for finding in &findings {
        root = map
            .insert(
                root.content_id(),
                crate::repository::finding_signature_key(finding.signature().cluster_key()),
                finding.id().expect("finding id").content_id(),
            )
            .expect("finding index insert");
    }
    let roots = CampaignRoots {
        graph: empty.content_id(),
        exploration: empty.content_id(),
        observations: empty.content_id(),
        corpus: empty.content_id(),
        coverage: empty.content_id(),
        findings: root.content_id(),
        pins: empty.content_id(),
        accounting: empty.content_id(),
        coordination: empty.content_id(),
    };
    let snapshot_body = CampaignSnapshot::genesis(
        CampaignLineageId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"finding-query-lineage",
        ))
        .expect("lineage"),
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"finding-query-policy",
        ))
        .expect("policy"),
        roots,
    )
    .expect("finding query snapshot");
    let request = QueryCampaignFindingsRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign"),
        snapshot_body.id().expect("snapshot id"),
        None,
        2,
    )
    .expect("finding query");
    let (page, proof) = map
        .scan_with_proof(root.content_id(), request.after(), 2)
        .expect("finding page proof");
    let entries = page
        .entries()
        .iter()
        .map(|(_, id)| {
            findings
                .iter()
                .find(|finding| finding.id().expect("finding identity").content_id() == *id)
                .expect("indexed finding")
                .clone()
        })
        .collect::<Vec<_>>();
    let response = QueryCampaignFindingsResponse::new(
        &request,
        snapshot_body,
        entries,
        page.next_after(),
        proof,
    )
    .expect("finding response");
    response.validate_for(&request).expect("response binding");
    assert_eq!(
        QueryCampaignFindingsRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("decode request"),
        request
    );
    assert_eq!(
        QueryCampaignFindingsResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode response"),
        response
    );

    let mut forged_eof = response.clone();
    forged_eof.next_after = None;
    let forged_eof =
        QueryCampaignFindingsResponse::from_canonical_bytes(&forged_eof.canonical_bytes())
            .expect("structurally canonical false EOF");
    assert!(forged_eof.validate_for(&request).is_err());

    let mut substituted = response.clone();
    substituted.entries[0] = finding("substituted", empty.content_id());
    let substituted =
        QueryCampaignFindingsResponse::from_canonical_bytes(&substituted.canonical_bytes())
            .expect("structurally canonical substitution");
    assert!(substituted.validate_for(&request).is_err());

    let next = QueryCampaignFindingsRequest::new(
        request.principal().clone(),
        request.campaign().clone(),
        request.snapshot(),
        response.next_after(),
        2,
    )
    .expect("next finding query");
    assert!(response.validate_for(&next).is_err());
}

#[test]
fn finding_object_reads_authenticate_exact_child_kind_and_identity() {
    let backend = Arc::new(MemoryBlobBackend::new("finding-object-proof", u64::MAX));
    let map = MerkleMap::new(backend);
    let empty = map.empty().expect("empty finding index");
    let scenario = ScenarioDefId::from_hash(hash("finding-object-scenario"));
    let scenario_artifact = ScenarioArtifactId::from_content_id(ContentId::for_bytes(
        ObjectKind::Scenario,
        1,
        b"finding-object-scenario-artifact",
    ))
    .expect("scenario artifact ID");
    let configuration = ConfigurationId::from_hash(hash("finding-object-configuration"));
    let configuration_artifact = ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
        ObjectKind::Configuration,
        1,
        b"finding-object-configuration-artifact",
    ))
    .expect("configuration artifact ID");
    let observation = Observation::new(
        AttemptId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"finding-object-attempt",
        ))
        .expect("attempt ID"),
        configuration,
        configuration_artifact,
        BranchPathId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            2,
            b"finding-object-path",
        ))
        .expect("path ID"),
        StopOutcome::ModeledTimeout("execution".to_owned()),
        MeasurementSetId::from_content_id(ContentId::for_bytes(
            ObjectKind::Observation,
            1,
            b"finding-object-measurements",
        ))
        .expect("measurement ID"),
        PropertyVerdictSetId::from_content_id(ContentId::for_bytes(
            ObjectKind::Observation,
            1,
            b"finding-object-properties",
        ))
        .expect("property ID"),
        CoverageProjectionId::from_content_id(ContentId::for_bytes(
            ObjectKind::Projection,
            1,
            b"finding-object-coverage",
        ))
        .expect("coverage ID"),
        BTreeSet::new(),
    )
    .expect("observation");
    let observation_id = observation.id().expect("observation ID");
    let reproduction = ReproductionArtifact::new(
        scenario,
        scenario_artifact,
        configuration,
        configuration_artifact,
        hash("finding-object-fingerprint"),
        1,
        b"reproduce".to_vec(),
    )
    .expect("reproduction");
    let finding = Finding::new(
        FindingSignature::new(
            FindingKind::Timeout,
            hash("finding-object-fingerprint"),
            None,
            "timeout.execution".to_owned(),
            None,
            BTreeSet::new(),
        )
        .expect("finding signature"),
        observation_id,
        reproduction.id().expect("reproduction ID"),
        snapshot("finding-object-first-seen"),
        FindingOccurrenceSet::new(empty.content_id(), 1, observation_id)
            .expect("finding occurrences"),
        None,
        BTreeSet::new(),
    )
    .expect("finding");
    let finding_id = finding.id().expect("finding ID");
    let root = map
        .insert(
            empty.content_id(),
            crate::repository::finding_signature_key(finding.signature().cluster_key()),
            finding_id.content_id(),
        )
        .expect("finding index");
    let roots = CampaignRoots {
        graph: empty.content_id(),
        exploration: empty.content_id(),
        observations: empty.content_id(),
        corpus: empty.content_id(),
        coverage: empty.content_id(),
        findings: root.content_id(),
        pins: empty.content_id(),
        accounting: empty.content_id(),
        coordination: empty.content_id(),
    };
    let snapshot_body = CampaignSnapshot::genesis(
        CampaignLineageId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"finding-object-lineage",
        ))
        .expect("lineage"),
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"finding-object-policy",
        ))
        .expect("policy"),
        roots,
    )
    .expect("finding object snapshot");
    let request = GetCampaignFindingObjectRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign"),
        snapshot_body.id().expect("snapshot ID"),
        finding_id,
        CampaignFindingObjectKind::Observation,
    )
    .expect("finding object request");
    let (_, proof) = map
        .get_with_proof(
            root.content_id(),
            crate::repository::finding_signature_key(finding.signature().cluster_key()),
        )
        .expect("finding lookup proof");
    let response = GetCampaignFindingObjectResponse::new(
        &request,
        snapshot_body,
        finding,
        CampaignFindingObject::Observation(observation),
        proof,
    )
    .expect("finding object response");
    response.validate_for(&request).expect("response binding");
    assert_eq!(
        GetCampaignFindingObjectRequest::from_canonical_bytes(&request.canonical_bytes())
            .expect("request decode"),
        request
    );
    assert_eq!(
        GetCampaignFindingObjectResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("response decode"),
        response
    );

    let mut wrong_kind = response.clone();
    let CampaignFindingObject::Observation(value) = wrong_kind.object else {
        unreachable!("fixture object kind")
    };
    wrong_kind.object = CampaignFindingObject::LatestOccurrence(value);
    assert!(wrong_kind.validate_for(&request).is_err());

    let reproduction_request = GetCampaignFindingObjectRequest::new(
        request.principal().clone(),
        request.campaign().clone(),
        request.snapshot(),
        request.finding(),
        CampaignFindingObjectKind::Reproduction,
    )
    .expect("reproduction request");
    assert!(response.validate_for(&reproduction_request).is_err());
}

#[test]
fn attempt_explanations_authenticate_execution_proposal_selection_and_completion() {
    let backend = Arc::new(MemoryBlobBackend::new(
        "attempt-explanation-proof",
        u64::MAX,
    ));
    let map = MerkleMap::new(backend);
    let empty = map.empty().expect("empty attempt indexes");
    let (_declaration, domain, opportunity) = choice_objects();
    let parent_configuration = ConfigurationId::from_hash(hash("attempt-parent"));
    let parent = ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
        ObjectKind::Configuration,
        1,
        b"attempt-parent-artifact",
    ))
    .expect("attempt parent artifact ID");
    let branch_point = opportunity.branch_point_id(parent_configuration);
    let value = ChoiceValue::Boolean(true);
    let selection =
        Selection::new_campaign_branch(&opportunity, &domain, value.clone(), branch_point)
            .expect("attempt selection");
    let selection_id = selection.id().expect("attempt selection ID");
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        unreachable!("campaign branch selection origin")
    };
    let path = BranchPath::new(vec![BranchPathSegment::new(branch_point, edge)])
        .expect("attempt branch path");
    let path_id = path.id().expect("attempt branch path ID");
    let request = BranchRequest::new(
        branch_point,
        parent,
        opportunity.id().expect("attempt opportunity ID"),
        domain.id().expect("attempt domain ID"),
        CandidateSource::finite(BTreeSet::from([value.clone()])).expect("attempt source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(hash("attempt-command"))),
        BranchBudget::new(1, 1).expect("attempt budget"),
        StopCondition::NextChoice,
    )
    .expect("attempt request");
    let planner_invocation = PlannerInvocationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Policy,
        2,
        b"attempt-planner-invocation",
    ))
    .expect("attempt planner invocation ID");
    let proposal = Proposal::new(
        branch_point,
        request.id().expect("attempt request ID"),
        domain.id().expect("attempt proposal domain"),
        value,
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"attempt-policy",
        ))
        .expect("attempt policy ID"),
        Some(planner_invocation),
        1,
        CampaignViewId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"attempt-guidance-view",
        ))
        .expect("attempt guidance view ID"),
    )
    .expect("attempt proposal");
    let proposal_id = proposal.id().expect("attempt proposal ID");
    let planner_step = PlannerStep::new(
        None,
        planner_invocation,
        RetainedPlannerRequestId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"attempt-retained-planner-request",
        ))
        .expect("attempt retained planner request ID"),
        hash("attempt-planner-request-digest"),
        proposal.policy(),
        PlannerEngineId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"attempt-planner-engine",
        ))
        .expect("attempt planner engine ID"),
        PolicyArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"attempt-planner-artifact",
        ))
        .expect("attempt planner artifact ID"),
        proposal.guidance_basis(),
        PlannerDisposition::Issue {
            selected: PlanningScanPosition::new(branch_point, proposal.request()),
            issued_branch_requests: Vec::new(),
            issued_proposals: vec![proposal_id],
        },
        PlannerStateId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"attempt-planner-state",
        ))
        .expect("attempt planner state ID"),
        PlanningUsage {
            branch_requests: 0,
            proposals: 1,
            input_objects: 3,
            input_bytes: 1_024,
            fuel: 7,
        },
        PlanningAccounting {
            branch_requests: 0,
            proposals: 1,
            attempts: 1,
            deduplicated: 0,
            input_objects: 3,
            input_bytes: 1_024,
            fuel: 7,
        },
        GuidanceEvidence::new(BTreeMap::from([
            ("selected-exploitation-micros".to_owned(), 125_000),
            ("selected-total-micros".to_owned(), 375_000),
        ]))
        .expect("attempt planner guidance evidence"),
    )
    .expect("attempt planner step");
    let planner_step_id = planner_step.id().expect("attempt planner step ID");
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent,
            selection: selection_id,
        },
        path_id,
        StopCondition::NextChoice,
    )
    .expect("attempt");
    let attempt_id = attempt.id().expect("attempt ID");
    let admission = AttemptAdmission::new(
        attempt_id,
        AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(proposal_id),
            cause: request.cause(),
            admission_ordinal: AdmissionOrdinal::new(1),
        },
    );
    let admission_id = admission.id().expect("attempt admission ID");
    let observation = Observation::new(
        attempt_id,
        parent_configuration,
        parent,
        path_id,
        StopOutcome::TerminalSuccess,
        MeasurementSetId::from_content_id(ContentId::for_bytes(
            ObjectKind::Observation,
            1,
            b"attempt-explanation-measurements",
        ))
        .expect("attempt measurement ID"),
        PropertyVerdictSetId::from_content_id(ContentId::for_bytes(
            ObjectKind::Observation,
            1,
            b"attempt-explanation-properties",
        ))
        .expect("attempt property ID"),
        CoverageProjectionId::from_content_id(ContentId::for_bytes(
            ObjectKind::Projection,
            1,
            b"attempt-explanation-coverage",
        ))
        .expect("attempt coverage ID"),
        BTreeSet::new(),
    )
    .expect("attempt observation");
    let observation_id = observation.id().expect("attempt observation ID");

    let accounting_attempt = map
        .insert(
            empty.content_id(),
            crate::repository::attempt_index_key(attempt_id),
            attempt_id.content_id(),
        )
        .expect("attempt accounting membership");
    let accounting = map
        .insert(
            accounting_attempt.content_id(),
            crate::repository::attempt_execution_basis_key(attempt_id),
            admission_id.content_id(),
        )
        .expect("attempt accounting root");
    let exploration = map
        .insert(
            empty.content_id(),
            crate::repository::proposal_index_key(proposal_id),
            proposal_id.content_id(),
        )
        .expect("attempt proposal root");
    let observations = map
        .insert(
            empty.content_id(),
            crate::repository::attempt_observation_key(attempt_id),
            observation_id.content_id(),
        )
        .expect("attempt observation root");
    let coordination = map
        .insert(
            empty.content_id(),
            crate::repository::planner_invocation_result_key(planner_invocation),
            planner_step_id.content_id(),
        )
        .expect("attempt planner result root");
    let roots = CampaignRoots {
        graph: empty.content_id(),
        exploration: exploration.content_id(),
        observations: observations.content_id(),
        corpus: empty.content_id(),
        coverage: empty.content_id(),
        findings: empty.content_id(),
        pins: empty.content_id(),
        accounting: accounting.content_id(),
        coordination: coordination.content_id(),
    };
    let snapshot_body = CampaignSnapshot::genesis(
        CampaignLineageId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"attempt-explanation-lineage",
        ))
        .expect("attempt lineage ID"),
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"attempt-explanation-snapshot-policy",
        ))
        .expect("attempt snapshot policy ID"),
        roots,
    )
    .expect("attempt explanation snapshot");
    let explanation_request = ExplainCampaignAttemptRequest::new(
        CampaignPrincipal::new("operator:alice").expect("attempt principal"),
        CampaignName::new("network-recovery").expect("attempt campaign"),
        snapshot_body.id().expect("attempt snapshot ID"),
        attempt_id,
    )
    .expect("attempt explanation request");
    let (_, attempt_proof) = map
        .get_with_proof(
            accounting.content_id(),
            crate::repository::attempt_index_key(attempt_id),
        )
        .expect("attempt membership proof");
    let (_, admission_proof) = map
        .get_with_proof(
            accounting.content_id(),
            crate::repository::attempt_execution_basis_key(attempt_id),
        )
        .expect("attempt admission proof");
    let (_, proposal_proof) = map
        .get_with_proof(
            exploration.content_id(),
            crate::repository::proposal_index_key(proposal_id),
        )
        .expect("attempt proposal proof");
    let (_, observation_proof) = map
        .get_with_proof(
            observations.content_id(),
            crate::repository::attempt_observation_key(attempt_id),
        )
        .expect("attempt observation proof");
    let (_, planner_step_proof) = map
        .get_with_proof(
            coordination.content_id(),
            crate::repository::planner_invocation_result_key(planner_invocation),
        )
        .expect("attempt planner-step proof");
    let response = ExplainCampaignAttemptResponse::new(
        &explanation_request,
        snapshot_body,
        attempt,
        admission,
        path,
        Some(selection),
        Some(proposal),
        Some(planner_step),
        Some(observation),
        attempt_proof,
        admission_proof,
        Some(proposal_proof),
        Some(planner_step_proof),
        observation_proof,
    )
    .expect("attempt explanation response");
    response
        .validate_for(&explanation_request)
        .expect("attempt explanation binding");
    assert_eq!(
        ExplainCampaignAttemptRequest::from_canonical_bytes(&explanation_request.canonical_bytes())
            .expect("attempt request decode"),
        explanation_request
    );
    assert_eq!(
        ExplainCampaignAttemptResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("attempt response decode"),
        response
    );
    assert_eq!(
        response
            .planner_step()
            .expect("planner evidence")
            .evidence()
            .terms_micros()["selected-total-micros"],
        375_000
    );
    let mut legacy = response.clone();
    legacy.schema_version = 1;
    legacy.planner_step = None;
    legacy.planner_step_proof = None;
    let legacy_bytes = legacy.canonical_bytes();
    let legacy_decoded = ExplainCampaignAttemptResponse::from_canonical_bytes(&legacy_bytes)
        .expect("legacy attempt explanation response");
    assert_eq!(legacy_decoded.canonical_bytes(), legacy_bytes);
    legacy_decoded
        .validate_for(&explanation_request)
        .expect("legacy explanation binding");

    let mut wrong = response.clone();
    let Some(proposal) = wrong.proposal.as_mut() else {
        unreachable!("branch proposal")
    };
    *proposal = Proposal::new(
        proposal.branch_point(),
        proposal.request(),
        proposal.domain(),
        ChoiceValue::Boolean(false),
        proposal.policy(),
        proposal.planner_invocation(),
        proposal.ordinal(),
        proposal.guidance_basis(),
    )
    .expect("wrong attempt proposal");
    assert!(wrong.validate_for(&explanation_request).is_err());

    let mut wrong_step = response.clone();
    let Some(step) = wrong_step.planner_step.as_mut() else {
        unreachable!("planner evidence")
    };
    *step = PlannerStep::new(
        step.parent(),
        step.invocation(),
        step.request(),
        step.request_digest(),
        step.policy(),
        step.engine(),
        step.policy_artifact(),
        CampaignViewId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"wrong-attempt-guidance-view",
        ))
        .expect("wrong guidance view"),
        step.disposition().clone(),
        step.next_state(),
        step.usage_claim(),
        step.accounting(),
        step.evidence().clone(),
    )
    .expect("wrong planner step");
    assert!(wrong_step.validate_for(&explanation_request).is_err());
}

#[test]
fn discovery_attempt_explanations_authenticate_absent_branch_and_completion_state() {
    let backend = Arc::new(MemoryBlobBackend::new(
        "discovery-attempt-explanation",
        u64::MAX,
    ));
    let map = MerkleMap::new(backend);
    let empty = map.empty().expect("empty discovery explanation root");
    let configuration = ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
        ObjectKind::Configuration,
        1,
        b"discovery-explanation-configuration",
    ))
    .expect("discovery configuration ID");
    let path = BranchPath::new(Vec::new()).expect("discovery path");
    let attempt = Attempt::new(
        AttemptStart::Discover { configuration },
        path.id().expect("discovery path ID"),
        StopCondition::NextChoice,
    )
    .expect("discovery attempt");
    let attempt_id = attempt.id().expect("discovery attempt ID");
    let admission = AttemptAdmission::new(
        attempt_id,
        AttemptAdmissionRole::ExecutionBasis {
            proposal: None,
            cause: BranchRequestCause::ExhaustivePolicy(
                CampaignPolicyId::from_content_id(ContentId::for_bytes(
                    ObjectKind::Policy,
                    1,
                    b"discovery-explanation-policy",
                ))
                .expect("discovery policy ID"),
            ),
            admission_ordinal: AdmissionOrdinal::new(1),
        },
    );
    let accounting = map
        .insert(
            empty.content_id(),
            crate::repository::attempt_index_key(attempt_id),
            attempt_id.content_id(),
        )
        .expect("discovery attempt membership");
    let accounting = map
        .insert(
            accounting.content_id(),
            crate::repository::attempt_execution_basis_key(attempt_id),
            admission.id().expect("discovery admission ID").content_id(),
        )
        .expect("discovery admission membership");
    let roots = CampaignRoots {
        graph: empty.content_id(),
        exploration: empty.content_id(),
        observations: empty.content_id(),
        corpus: empty.content_id(),
        coverage: empty.content_id(),
        findings: empty.content_id(),
        pins: empty.content_id(),
        accounting: accounting.content_id(),
        coordination: empty.content_id(),
    };
    let snapshot_body = CampaignSnapshot::genesis(
        CampaignLineageId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"discovery-explanation-lineage",
        ))
        .expect("discovery lineage ID"),
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"discovery-explanation-active-policy",
        ))
        .expect("discovery active policy ID"),
        roots,
    )
    .expect("discovery explanation snapshot");
    let request = ExplainCampaignAttemptRequest::new(
        CampaignPrincipal::new("operator:alice").expect("discovery principal"),
        CampaignName::new("discovery-campaign").expect("discovery campaign"),
        snapshot_body.id().expect("discovery snapshot ID"),
        attempt_id,
    )
    .expect("discovery explanation request");
    let (_, attempt_proof) = map
        .get_with_proof(
            accounting.content_id(),
            crate::repository::attempt_index_key(attempt_id),
        )
        .expect("discovery attempt proof");
    let (_, admission_proof) = map
        .get_with_proof(
            accounting.content_id(),
            crate::repository::attempt_execution_basis_key(attempt_id),
        )
        .expect("discovery admission proof");
    let (_, observation_proof) = map
        .get_with_proof(
            empty.content_id(),
            crate::repository::attempt_observation_key(attempt_id),
        )
        .expect("discovery absence proof");
    let response = ExplainCampaignAttemptResponse::new(
        &request,
        snapshot_body,
        attempt,
        admission,
        path,
        None,
        None,
        None,
        None,
        attempt_proof,
        admission_proof,
        None,
        None,
        observation_proof,
    )
    .expect("discovery explanation response");

    response
        .validate_for(&request)
        .expect("discovery explanation binding");
    assert!(response.selection().is_none());
    assert!(response.proposal().is_none());
    assert!(response.observation().is_none());
}

#[test]
fn graph_object_response_authenticates_snapshot_key_and_exact_envelope() {
    let backend = Arc::new(MemoryBlobBackend::new("graph-object-query", u64::MAX));
    let map = MerkleMap::new(backend);
    let empty = map.empty().expect("empty graph");
    let key = CampaignHash::derive("campaign-query-test-key", b"configuration");
    let object = configuration_envelope("configuration");
    let graph = map
        .insert(empty.content_id(), key, object.content_id())
        .expect("graph insert");
    let roots = CampaignRoots {
        graph: graph.content_id(),
        exploration: empty.content_id(),
        observations: empty.content_id(),
        corpus: empty.content_id(),
        coverage: empty.content_id(),
        findings: empty.content_id(),
        pins: empty.content_id(),
        accounting: empty.content_id(),
        coordination: empty.content_id(),
    };
    let snapshot_body = CampaignSnapshot::genesis(
        CampaignLineageId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"graph-object-lineage",
        ))
        .expect("lineage"),
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"graph-object-policy",
        ))
        .expect("policy"),
        roots,
    )
    .expect("snapshot");
    let request = GetCampaignGraphObjectRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign"),
        snapshot_body.id().expect("snapshot id"),
        key,
    )
    .expect("request");
    let (_, proof) = map
        .get_with_proof(graph.content_id(), key)
        .expect("lookup proof");
    let response = GetCampaignGraphObjectResponse::new(&request, snapshot_body, object, proof)
        .expect("response");
    let decoded = GetCampaignGraphObjectResponse::from_canonical_bytes(&response.canonical_bytes())
        .expect("decode response");
    decoded.validate_for(&request).expect("verify response");

    let mut substituted = decoded;
    substituted.object = configuration_envelope("substituted");
    assert!(substituted.validate_for(&request).is_err());
    let wrong_key = GetCampaignGraphObjectRequest::new(
        request.principal().clone(),
        request.campaign().clone(),
        request.snapshot(),
        CampaignHash::derive("campaign-query-test-key", b"other"),
    )
    .expect("wrong-key request");
    assert!(response.validate_for(&wrong_key).is_err());
}

#[test]
fn choice_pages_authenticate_the_nested_index_and_exact_eof() {
    assert!(
        QueryCampaignChoicesRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot("choice-limit"),
            None,
            MAX_CAMPAIGN_CHOICE_QUERY_PAGE_ITEMS + 1,
        )
        .is_err()
    );
    let backend = Arc::new(MemoryBlobBackend::new("choice-query", u64::MAX));
    let map = MerkleMap::new(backend);
    let empty = map.empty().expect("empty root");
    let choices = ["first", "second"].map(|label| {
        ChoiceOpportunityId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            label.as_bytes(),
        ))
        .expect("choice id")
    });
    let mut choice_index = empty;
    for choice in choices {
        choice_index = map
            .insert(
                choice_index.content_id(),
                crate::repository::choice_index_order_key(choice),
                choice.content_id(),
            )
            .expect("choice insert");
    }
    let graph = map
        .insert(
            empty.content_id(),
            crate::repository::choice_index_anchor_key(),
            choice_index.content_id(),
        )
        .expect("choice-index anchor");
    let roots = CampaignRoots {
        graph: graph.content_id(),
        exploration: empty.content_id(),
        observations: empty.content_id(),
        corpus: empty.content_id(),
        coverage: empty.content_id(),
        findings: empty.content_id(),
        pins: empty.content_id(),
        accounting: empty.content_id(),
        coordination: empty.content_id(),
    };
    let snapshot_body = CampaignSnapshot::genesis(
        CampaignLineageId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"choice-query-lineage",
        ))
        .expect("lineage"),
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"choice-query-policy",
        ))
        .expect("policy"),
        roots,
    )
    .expect("snapshot");
    let request = QueryCampaignChoicesRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign"),
        snapshot_body.id().expect("snapshot id"),
        None,
        1,
    )
    .expect("request");
    let (_, index_proof) = map
        .get_with_proof(
            graph.content_id(),
            crate::repository::choice_index_anchor_key(),
        )
        .expect("index proof");
    let (page, page_proof) = map
        .scan_with_proof(choice_index.content_id(), None, 1)
        .expect("page proof");
    let entries = page
        .entries()
        .iter()
        .map(|(_, value)| {
            ChoiceOpportunityId::from_content_id(*value)
                .map(CampaignChoiceEntry::new)
                .expect("choice entry")
        })
        .collect::<Vec<_>>();
    let next_after = page
        .next_after()
        .and_then(|_| entries.last().map(|entry| entry.opportunity()));
    let response = QueryCampaignChoicesResponse::new(
        &request,
        snapshot_body,
        entries,
        next_after,
        index_proof,
        page_proof,
    )
    .expect("response");
    let decoded = QueryCampaignChoicesResponse::from_canonical_bytes(&response.canonical_bytes())
        .expect("decode response");
    decoded.validate_for(&request).expect("verify response");
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
            String::from("3d04a1a5b7687ffd4398b162b8b14566e1c56a16b47446db3dc734ac1b318eee"),
            String::from("9b5d7589cad830b6f816c31d5a4c8e9edae7deea41703d4993ec337833e0172f"),
        ]
    );

    let mut forged_eof = decoded.clone();
    forged_eof.next_after = None;
    assert!(forged_eof.validate_for(&request).is_err());
    let mut substituted = decoded;
    substituted.entries[0] = CampaignChoiceEntry::new(
        ChoiceOpportunityId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"unrelated-choice",
        ))
        .expect("unrelated choice"),
    );
    assert!(substituted.validate_for(&request).is_err());
}

#[test]
fn frontier_pages_authenticate_projection_bodies_and_exact_eof() {
    assert!(
        QueryCampaignFrontierRequest::new(
            CampaignPrincipal::new("operator:alice").expect("principal"),
            CampaignName::new("network-recovery").expect("campaign"),
            snapshot("frontier-limit"),
            None,
            MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS + 1,
        )
        .is_err()
    );
    let backend = Arc::new(MemoryBlobBackend::new("frontier-query", u64::MAX));
    let map = MerkleMap::new(backend);
    let empty = map.empty().expect("empty root");
    let projections = [
        ("first", ContinuationState::Ready),
        ("second", ContinuationState::Open),
    ]
    .map(|(label, state)| {
        let request = BranchRequestId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            label.as_bytes(),
        ))
        .expect("request id");
        ContinuationProjection::new(
            request,
            BranchPointId::from_hash(CampaignHash::derive(
                "campaign-frontier-query-branch-point",
                label.as_bytes(),
            )),
            state,
        )
    });
    let mut frontier_index = empty;
    for projection in projections {
        frontier_index = map
            .insert(
                frontier_index.content_id(),
                crate::repository::frontier_index_order_key(projection.request()),
                projection.id().expect("projection id").content_id(),
            )
            .expect("frontier insert");
    }
    let exploration = map
        .insert(
            empty.content_id(),
            crate::repository::frontier_index_anchor_key(),
            frontier_index.content_id(),
        )
        .expect("frontier-index anchor");
    let roots = CampaignRoots {
        graph: empty.content_id(),
        exploration: exploration.content_id(),
        observations: empty.content_id(),
        corpus: empty.content_id(),
        coverage: empty.content_id(),
        findings: empty.content_id(),
        pins: empty.content_id(),
        accounting: empty.content_id(),
        coordination: empty.content_id(),
    };
    let snapshot_body = CampaignSnapshot::genesis(
        CampaignLineageId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"frontier-query-lineage",
        ))
        .expect("lineage"),
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"frontier-query-policy",
        ))
        .expect("policy"),
        roots,
    )
    .expect("snapshot");
    let request = QueryCampaignFrontierRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign"),
        snapshot_body.id().expect("snapshot id"),
        None,
        1,
    )
    .expect("request");
    let (_, index_proof) = map
        .get_with_proof(
            exploration.content_id(),
            crate::repository::frontier_index_anchor_key(),
        )
        .expect("index proof");
    let (page, page_proof) = map
        .scan_with_proof(frontier_index.content_id(), None, 1)
        .expect("page proof");
    let entries = page
        .entries()
        .iter()
        .map(|(_, value)| {
            projections
                .iter()
                .copied()
                .find(|projection| projection.id().expect("projection id").content_id() == *value)
                .expect("projection body")
        })
        .collect::<Vec<_>>();
    let next_after = page
        .next_after()
        .and_then(|_| entries.last().map(|entry| entry.request()));
    let response = QueryCampaignFrontierResponse::new(
        &request,
        snapshot_body,
        entries,
        next_after,
        index_proof,
        page_proof,
    )
    .expect("response");
    let decoded = QueryCampaignFrontierResponse::from_canonical_bytes(&response.canonical_bytes())
        .expect("decode response");
    decoded.validate_for(&request).expect("verify response");
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
            String::from("483028d0eea2e19495841dd35e1d12e209c7f6ab06e37f659e5e1dcd98edbca4"),
            String::from("ff72a3caeb93adf388ca3bdd3a7a7fed45479a7b033ed3dfac0fdd4ed2485c26"),
        ]
    );

    let mut forged_eof = decoded.clone();
    forged_eof.next_after = None;
    assert!(forged_eof.validate_for(&request).is_err());
    let mut substituted = decoded;
    substituted.entries[0] = ContinuationProjection::new(
        substituted.entries[0].request(),
        substituted.entries[0].branch_point(),
        ContinuationState::Closed,
    );
    assert!(substituted.validate_for(&request).is_err());
}

#[test]
fn frontier_object_reads_authenticate_exact_request_membership() {
    let backend = Arc::new(MemoryBlobBackend::new("frontier-object-query", u64::MAX));
    let map = MerkleMap::new(backend);
    let empty = map.empty().expect("empty root");
    let object = branch_request("frontier-object");
    let object_id = object.id().expect("request id");
    let projection =
        ContinuationProjection::new(object_id, object.branch_point(), ContinuationState::Ready);
    let frontier_index = map
        .insert(
            empty.content_id(),
            crate::repository::frontier_index_order_key(object_id),
            projection.id().expect("projection id").content_id(),
        )
        .expect("frontier insert");
    let exploration = map
        .insert(
            empty.content_id(),
            crate::repository::frontier_index_anchor_key(),
            frontier_index.content_id(),
        )
        .expect("frontier anchor");
    let snapshot_body = CampaignSnapshot::genesis(
        CampaignLineageId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"frontier-object-lineage",
        ))
        .expect("lineage"),
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"frontier-object-policy",
        ))
        .expect("policy"),
        CampaignRoots {
            graph: empty.content_id(),
            exploration: exploration.content_id(),
            observations: empty.content_id(),
            corpus: empty.content_id(),
            coverage: empty.content_id(),
            findings: empty.content_id(),
            pins: empty.content_id(),
            accounting: empty.content_id(),
            coordination: empty.content_id(),
        },
    )
    .expect("snapshot");
    let request = GetCampaignFrontierObjectRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign"),
        snapshot_body.id().expect("snapshot id"),
        object_id,
    )
    .expect("request");
    let (_, index_proof) = map
        .get_with_proof(
            exploration.content_id(),
            crate::repository::frontier_index_anchor_key(),
        )
        .expect("index proof");
    let (_, object_proof) = map
        .get_with_proof(
            frontier_index.content_id(),
            crate::repository::frontier_index_order_key(object_id),
        )
        .expect("object proof");
    let response = GetCampaignFrontierObjectResponse::new(
        &request,
        snapshot_body,
        projection,
        object,
        index_proof,
        object_proof,
    )
    .expect("response");
    let decoded =
        GetCampaignFrontierObjectResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode response");
    decoded.validate_for(&request).expect("verify response");
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
            String::from("ded2cdc531496795ce795c8f01a5fd093fba3917917ba03221248533a7d4e90f"),
            String::from("3a48809b35eeb65b37ec29ae4dc51b1d877ebbed1f182cab8c61e2a52b35efd4"),
        ]
    );

    let mut forged_projection = decoded.clone();
    forged_projection.projection = ContinuationProjection::new(
        object_id,
        forged_projection.projection.branch_point(),
        ContinuationState::Closed,
    );
    assert!(forged_projection.validate_for(&request).is_err());
    let mut substituted = decoded;
    substituted.object = branch_request("substituted-frontier-object");
    assert!(substituted.validate_for(&request).is_err());
}

#[test]
fn choice_object_reads_authenticate_exact_opportunity_dependencies() {
    let backend = Arc::new(MemoryBlobBackend::new("choice-object-query", u64::MAX));
    let map = MerkleMap::new(backend);
    let empty = map.empty().expect("empty root");
    let (declaration, domain, opportunity) = choice_objects();
    let opportunity_id = opportunity.id().expect("opportunity id");
    let graph = map
        .insert(
            empty.content_id(),
            crate::repository::authoritative_choice_key(opportunity_id),
            opportunity_id.content_id(),
        )
        .expect("opportunity membership");
    let roots = CampaignRoots {
        graph: graph.content_id(),
        exploration: empty.content_id(),
        observations: empty.content_id(),
        corpus: empty.content_id(),
        coverage: empty.content_id(),
        findings: empty.content_id(),
        pins: empty.content_id(),
        accounting: empty.content_id(),
        coordination: empty.content_id(),
    };
    let snapshot_body = CampaignSnapshot::genesis(
        CampaignLineageId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"choice-object-lineage",
        ))
        .expect("lineage"),
        CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"choice-object-policy",
        ))
        .expect("policy"),
        roots,
    )
    .expect("snapshot");
    let request = GetCampaignChoiceObjectRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("network-recovery").expect("campaign"),
        snapshot_body.id().expect("snapshot id"),
        opportunity_id,
        CampaignChoiceObjectKind::Declaration,
    )
    .expect("request");
    let mut unknown_kind = request.canonical_bytes();
    let kind = unknown_kind.last_mut().expect("choice object kind byte");
    *kind = 2;
    assert!(matches!(
        GetCampaignChoiceObjectRequest::from_canonical_bytes(&unknown_kind),
        Err(CampaignCodecError::UnknownTag {
            kind: "campaign-choice-object-kind",
            tag: 2,
        })
    ));
    let (_, proof) = map
        .get_with_proof(
            graph.content_id(),
            crate::repository::authoritative_choice_key(opportunity_id),
        )
        .expect("opportunity proof");
    let response = GetCampaignChoiceObjectResponse::new(
        &request,
        snapshot_body.clone(),
        opportunity.clone(),
        CampaignChoiceObject::Declaration(declaration),
        proof.clone(),
    )
    .expect("declaration response");
    let decoded =
        GetCampaignChoiceObjectResponse::from_canonical_bytes(&response.canonical_bytes())
            .expect("decode response");
    decoded.validate_for(&request).expect("verify response");

    let domain_request = GetCampaignChoiceObjectRequest::new(
        request.principal().clone(),
        request.campaign().clone(),
        request.snapshot(),
        opportunity_id,
        CampaignChoiceObjectKind::Domain,
    )
    .expect("domain request");
    let domain_response = GetCampaignChoiceObjectResponse::new(
        &domain_request,
        snapshot_body,
        opportunity,
        CampaignChoiceObject::Domain(domain),
        proof,
    )
    .expect("domain response");
    domain_response
        .validate_for(&domain_request)
        .expect("verify domain response");
    assert!(domain_response.validate_for(&request).is_err());
    let mut substituted = domain_response;
    substituted.object = CampaignChoiceObject::Domain(ChoiceDomain::Boolean(
        BooleanDomain::new(2).expect("unrelated domain"),
    ));
    assert!(substituted.validate_for(&domain_request).is_err());

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
            String::from("b3a99f45d1c4d84be0175b9f4b2408877d93a6ea4796466e48350ae035d6da38"),
            String::from("74abc6ab91c7dec2cb1cde83dad1afc81e1707bf9f0717ebab4b008792a92286"),
        ]
    );
}
