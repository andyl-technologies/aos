//! Verifies cold campaign continuity through pause, archive restore, and resume.
//!
//! This is a semantic model-tier fixture: it never starts a native executor or QEMU.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- process fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use crucible_campaign::{
    ActiveAttemptPolicy, Attempt, AttemptId, AttemptStart, BooleanDomain, BranchBudget, BranchPath,
    BranchPathSegment, BranchPointId, BranchRequest, BranchRequestCause, BudgetGrant,
    CampaignArchiveCheckpointResolver, CampaignArchivePolicy, CampaignAuthorizationError,
    CampaignClient, CampaignCommandId, CampaignControlAction, CampaignFactId, CampaignHash,
    CampaignLineage, CampaignMode, CampaignName, CampaignPolicy, CampaignPrincipal,
    CampaignPrincipalAuthorizer, CampaignRepository, CampaignRepositoryError, CampaignSeed,
    CampaignServiceOperation, CampaignSnapshotId, CampaignState, CandidateSource,
    ChoiceClassContext, ChoiceCoordinate, ChoiceDomain, ChoiceOpportunity, ChoiceSource,
    ChoiceValue, ConfigurationId, ContinuationState, ControlRequest, CoverageProjection,
    ExactCheckpointId, ExactRational, ExplorerPolicy, FairnessPolicy, FindingKind,
    FindingSignature, FindingTarget, MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS,
    MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS, MAX_CAMPAIGN_QUERY_PAGE_ITEMS, MeasurementSeries,
    MeasurementSet, MetricValue, Observation, ObservationId, PinChange, PinRequest, PinRetention,
    ProgressiveWideningPolicy, PropertyEvidence, PropertyVerdict, PropertyVerdictSet, Proposal,
    PuctPolicy, QueryCampaignFindingsRequest, QueryCampaignFrontierRequest,
    QueryCampaignGraphRequest, RepositoryCampaignService, RetentionPolicy, ScenarioDefId,
    SelectableDeclaration, Selection, SelectionOrigin, StopCondition, StopOutcome,
};
use crucible_cas::content_envelope::{ContentChild, ContentEnvelope};
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend, DurabilityRequirement,
    ImmutableBlobBackend, ObjectKind,
};

const CAMPAIGN_NAME: &str = "campaign-continuity-v2";
const RESTORED_CAMPAIGN_NAME: &str = "campaign-continuity-v2-restored";
const PROCESS_HELPER: &str = "continuity_process_helper";

#[test]
fn campaign_continuity_v2_survives_pause_restart_archive_restore_and_resume()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let source_root = temporary.path().join("source");
    let destination_root = temporary.path().join("destination");
    let frozen_projection = temporary.path().join("projection-before-pause.txt");
    let resumed_state = temporary.path().join("state-after-resume.txt");
    let source_blobs = Arc::new(DirectoryBlobBackend::new(
        "campaign-continuity-v2-source",
        source_root.join("objects"),
    ));
    let source = CampaignRepository::new(
        source_blobs.clone(),
        Arc::new(DirectoryRefBackend::new(source_root.join("refs"))),
    );
    let (lineage, policy) = campaign_fixture(&source)?;

    let created = source.create(CAMPAIGN_NAME, &lineage, &policy, &BTreeMap::new())?;
    let budgeted = source.apply_control(
        CAMPAIGN_NAME,
        &control(
            "budget",
            created.snapshot_id(),
            CampaignControlAction::GrantBudget(BudgetGrant::new(4, 4)?),
        ),
    )?;
    let running = source.apply_control(
        CAMPAIGN_NAME,
        &control(
            "initial-resume",
            budgeted.new_snapshot,
            CampaignControlAction::Resume,
        ),
    )?;
    let initial_attempt = source
        .admit_initial_discovery_if_ready(CAMPAIGN_NAME)?
        .ok_or("initial discovery was not admitted")?;
    assert_ne!(
        source.head(CAMPAIGN_NAME)?.snapshot_id(),
        running.new_snapshot
    );

    let observed = publish_observed_branch(&source, &lineage, &policy)?;
    let pinned = source.apply_pin(
        CAMPAIGN_NAME,
        &PinRequest {
            command: command_id("exact-pin"),
            expected_snapshot: observed.snapshot,
            change: PinChange::new(
                observed.child,
                Some(PinRetention::Exact),
                "retain the selected continuation materialization",
            )?,
        },
    )?;

    let before_pause = source.head(CAMPAIGN_NAME)?;
    assert_eq!(before_pause.snapshot_id(), pinned.new_snapshot);
    let expected_projection = stable_projection(
        &source,
        CAMPAIGN_NAME,
        observed.observation,
        observed.branch_point,
        initial_attempt,
    )?;
    fs::write(&frozen_projection, &expected_projection)?;

    let paused = source.apply_control(
        CAMPAIGN_NAME,
        &control(
            "pause",
            before_pause.snapshot_id(),
            CampaignControlAction::Pause(ActiveAttemptPolicy::ExactCheckpoint),
        ),
    )?;
    assert_eq!(source.state(CAMPAIGN_NAME)?, CampaignState::Paused);
    assert_eq!(
        stable_projection(
            &source,
            CAMPAIGN_NAME,
            observed.observation,
            observed.branch_point,
            initial_attempt,
        )?,
        expected_projection,
    );
    assert_stable_roots(
        before_pause.snapshot().roots(),
        source.head(CAMPAIGN_NAME)?.snapshot().roots(),
    );

    let (checkpoint, checkpoint_leaf) = exact_checkpoint_closure(source_blobs.as_ref())?;
    run_helper(
        &source_root,
        CAMPAIGN_NAME,
        "verify",
        paused.new_snapshot,
        observed.observation,
        observed.branch_point,
        initial_attempt,
        &frozen_projection,
        &resumed_state,
        checkpoint,
        checkpoint_leaf,
    );

    let pin = exact_pin(&source, CAMPAIGN_NAME)?;
    let mut resolver = FixtureCheckpointResolver {
        configuration: pin.request().change.configuration(),
        fact: pin.fact(),
        checkpoint,
    };
    let plan = source.plan_campaign_archive(
        paused.new_snapshot,
        CampaignArchivePolicy::Executable,
        [],
        Some(&mut resolver),
    )?;
    assert!(plan.omitted().is_empty());
    assert_eq!(plan.manifest().checkpoint_selections().len(), 1);
    assert_eq!(
        plan.manifest().checkpoint_selections()[0].checkpoint(),
        checkpoint
    );
    assert!(
        plan.selected()
            .iter()
            .any(|entry| entry.id() == checkpoint.content_id())
    );
    assert!(
        plan.selected()
            .iter()
            .any(|entry| entry.id() == checkpoint_leaf)
    );
    source.stage_campaign_archive_metadata(&plan)?;

    let destination = CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "campaign-continuity-v2-destination",
            destination_root.join("objects"),
        )),
        Arc::new(DirectoryRefBackend::new(destination_root.join("refs"))),
    );
    source.transfer_campaign_archive_objects(
        &destination,
        &plan,
        DurabilityRequirement::new(1, false)?,
    )?;
    destination.publish_campaign_archive("campaign-continuity-v2", None, &plan)?;
    assert_eq!(
        destination.publish_transferred_campaign(
            RESTORED_CAMPAIGN_NAME,
            None,
            plan.manifest_id(),
        )?,
        paused.new_snapshot,
    );
    assert_eq!(
        source.head(CAMPAIGN_NAME)?.snapshot_id(),
        paused.new_snapshot,
        "archive publication must not mutate the source campaign",
    );

    run_helper(
        &destination_root,
        RESTORED_CAMPAIGN_NAME,
        "verify",
        paused.new_snapshot,
        observed.observation,
        observed.branch_point,
        initial_attempt,
        &frozen_projection,
        &resumed_state,
        checkpoint,
        checkpoint_leaf,
    );
    run_helper(
        &destination_root,
        RESTORED_CAMPAIGN_NAME,
        "resume",
        paused.new_snapshot,
        observed.observation,
        observed.branch_point,
        initial_attempt,
        &frozen_projection,
        &resumed_state,
        checkpoint,
        checkpoint_leaf,
    );
    run_helper(
        &destination_root,
        RESTORED_CAMPAIGN_NAME,
        "replay-resume",
        paused.new_snapshot,
        observed.observation,
        observed.branch_point,
        initial_attempt,
        &frozen_projection,
        &resumed_state,
        checkpoint,
        checkpoint_leaf,
    );

    Ok(())
}

#[test]
#[ignore = "spawned by the campaign-continuity-v2 process fixture"]
fn continuity_process_helper() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(required_environment("CRUCIBLE_CONTINUITY_ROOT"));
    let campaign = required_environment("CRUCIBLE_CONTINUITY_CAMPAIGN");
    let action = required_environment("CRUCIBLE_CONTINUITY_ACTION");
    let paused_snapshot =
        CampaignSnapshotId::parse(&required_environment("CRUCIBLE_CONTINUITY_PAUSED_SNAPSHOT"))?;
    let observation =
        ObservationId::parse(&required_environment("CRUCIBLE_CONTINUITY_OBSERVATION"))?;
    let branch_point =
        BranchPointId::parse(&required_environment("CRUCIBLE_CONTINUITY_BRANCH_POINT"))?;
    let initial_attempt =
        AttemptId::parse(&required_environment("CRUCIBLE_CONTINUITY_INITIAL_ATTEMPT"))?;
    let frozen_path = PathBuf::from(required_environment("CRUCIBLE_CONTINUITY_FROZEN"));
    let resumed_path = PathBuf::from(required_environment("CRUCIBLE_CONTINUITY_RESUMED"));
    let checkpoint =
        ExactCheckpointId::parse(&required_environment("CRUCIBLE_CONTINUITY_CHECKPOINT"))?;
    let checkpoint_leaf =
        ContentId::parse(&required_environment("CRUCIBLE_CONTINUITY_CHECKPOINT_LEAF"))?;
    let repository = directory_repository(&root);
    authenticate_checkpoint_closure(&root, checkpoint, checkpoint_leaf)?;

    if action == "replay-resume" {
        let before = exact_head_state(&repository, &campaign)?;
        assert_eq!(before, fs::read_to_string(&resumed_path)?);
        let replayed = repository.apply_control(
            &campaign,
            &control(
                "archive-resume",
                paused_snapshot,
                CampaignControlAction::Resume,
            ),
        )?;
        assert!(replayed.replayed);
        assert_eq!(replayed.prior_snapshot, paused_snapshot);
        assert_eq!(
            replayed.new_snapshot,
            repository.head(&campaign)?.snapshot_id()
        );
        assert_eq!(exact_head_state(&repository, &campaign)?, before);
        assert_eq!(repository.state(&campaign)?, CampaignState::Running);
    } else {
        assert_eq!(repository.head(&campaign)?.snapshot_id(), paused_snapshot);
        assert_eq!(repository.state(&campaign)?, CampaignState::Paused);
        if action == "resume" {
            let resumed = repository.apply_control(
                &campaign,
                &control(
                    "archive-resume",
                    paused_snapshot,
                    CampaignControlAction::Resume,
                ),
            )?;
            assert!(!resumed.replayed);
            assert_eq!(resumed.prior_snapshot, paused_snapshot);
            assert_eq!(repository.state(&campaign)?, CampaignState::Running);
            fs::write(&resumed_path, exact_head_state(&repository, &campaign)?)?;
        } else {
            assert_eq!(action, "verify");
        }
    }

    let expected = fs::read_to_string(frozen_path)?;
    assert_eq!(
        stable_projection(
            &repository,
            &campaign,
            observation,
            branch_point,
            initial_attempt,
        )?,
        expected,
    );
    Ok(())
}

struct ObservedBranch {
    snapshot: CampaignSnapshotId,
    observation: ObservationId,
    child: ConfigurationId,
    branch_point: BranchPointId,
}

fn campaign_fixture(
    repository: &CampaignRepository,
) -> Result<(CampaignLineage, CampaignPolicy), Box<dyn Error>> {
    let scenario = ScenarioDefId::from_hash(hash("scenario"));
    let genesis = ConfigurationId::from_hash(hash("genesis"));
    let scenario_content =
        repository.publish_scenario_artifact(scenario, 1, b"continuity scenario".to_vec())?;
    let genesis_content = repository.publish_configuration_artifact(
        scenario,
        scenario_content,
        genesis,
        1,
        b"continuity genesis".to_vec(),
    )?;
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-continuity-v2",
        "qemu-continuity-v2",
        BTreeMap::from([
            (String::from("control"), 1),
            (String::from("shared-memory"), 2),
        ]),
        1,
        1,
    )?;
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1)?,
        ExactRational::new(1, 2)?,
        1,
        64,
        1,
    )?;
    let policy = CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([0x20; 32]),
        CampaignMode::Streaming,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0)?,
        RetentionPolicy::new(true, 1, true, true),
        true,
    )?;
    Ok((lineage, policy))
}

fn publish_observed_branch(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    policy: &CampaignPolicy,
) -> Result<ObservedBranch, Box<dyn Error>> {
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1)?);
    let declaration = SelectableDeclaration::new(
        "product.continuity.retry",
        ChoiceSource::Workload {
            producer: String::from("continuity-fixture"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::from([String::from("continuity")]))?,
        BTreeSet::new(),
        true,
    )?;
    repository.publish_choice_domain(&domain)?;
    repository.publish_selectable(&declaration)?;
    let opportunity = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: hash("scheduler"),
            producer: hash("producer"),
        },
        "campaign-continuity-branch",
        None,
    )?;
    repository.publish_choice_opportunity(&opportunity)?;
    let opportunity_id = opportunity.id()?;
    let discovered = repository.discover_operator_choice_opportunity(
        CAMPAIGN_NAME,
        repository.head(CAMPAIGN_NAME)?.snapshot_id(),
        lineage.genesis_content(),
        opportunity_id,
    )?;
    let request = BranchRequest::new(
        opportunity.branch_point_id(lineage.genesis()),
        lineage.genesis_content(),
        opportunity_id,
        domain.id()?,
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))?,
        BranchRequestCause::Operator(command_id("branch-request")),
        BranchBudget::new(2, 2)?,
        StopCondition::NextChoice,
    )?;
    let requested = repository.submit_operator_branch_request(
        CAMPAIGN_NAME,
        discovered.new_snapshot,
        &request,
    )?;
    let proposal = Proposal::new(
        request.branch_point(),
        request.id()?,
        request.domain(),
        ChoiceValue::Boolean(false),
        policy.id()?,
        None,
        1,
        repository
            .head(CAMPAIGN_NAME)?
            .snapshot()
            .planning_view()
            .id()?,
    )?;
    let proposed = repository.issue_proposal(CAMPAIGN_NAME, requested.new_snapshot, &proposal)?;
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        request.branch_point(),
    )?;
    let SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        return Err("branch selection did not retain a campaign edge".into());
    };
    let path = BranchPath::new(vec![BranchPathSegment::new(request.branch_point(), edge)])?;
    let attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: request.parent(),
            selection: selection.id()?,
        },
        path.id()?,
        request.stop().clone(),
    )?;
    let admitted = repository.admit_proposal(
        CAMPAIGN_NAME,
        proposed.new_snapshot,
        proposed.proposal,
        &selection,
        &path,
        &attempt,
    )?;

    let child = ConfigurationId::from_hash(hash("observed-child"));
    let child_content = repository.publish_configuration_artifact(
        lineage.scenario(),
        lineage.scenario_content(),
        child,
        1,
        b"selected continuity configuration".to_vec(),
    )?;
    let measurements = MeasurementSet::new(BTreeMap::from([(
        String::from("latency"),
        MeasurementSeries::new(
            vec![MetricValue::Unsigned(7)],
            MetricValue::Unsigned(7),
            BTreeSet::new(),
        )?,
    )]))?;
    let measurement_id = repository.publish_measurement_set(&measurements)?;
    let properties = PropertyVerdictSet::new(BTreeMap::from([(
        String::from("network-recovers"),
        PropertyEvidence::new(PropertyVerdict::Passed, BTreeSet::new())?,
    )]))?;
    let property_id = repository.publish_property_verdict_set(&properties)?;
    let coverage = CoverageProjection::new(BTreeSet::from([hash("coverage")]), BTreeSet::new())?;
    let coverage_id = repository.publish_coverage_projection(&coverage)?;
    let observation = Observation::new(
        admitted.attempt,
        child,
        child_content,
        path.id()?,
        StopOutcome::Reached(StopCondition::NextChoice),
        measurement_id,
        property_id,
        coverage_id,
        BTreeSet::from([opportunity_id]),
    )?;
    let observed =
        repository.publish_observation(CAMPAIGN_NAME, admitted.new_snapshot, &observation)?;
    let fingerprint = hash("retained-finding");
    let reproduction = repository.publish_reproduction_artifact(
        lineage.scenario(),
        lineage.scenario_content(),
        child,
        child_content,
        fingerprint,
        1,
        b"portable continuity reproduction".to_vec(),
    )?;
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        String::from("campaign.continuity-v2"),
        Some(FindingTarget::Configuration(child_content)),
        BTreeSet::from([property_id.content_id()]),
    )?;
    let found = repository.publish_finding(
        CAMPAIGN_NAME,
        observed.new_snapshot,
        signature,
        observed.observation,
        reproduction,
        None,
        BTreeSet::new(),
    )?;

    Ok(ObservedBranch {
        snapshot: found.new_snapshot,
        observation: observed.observation,
        child,
        branch_point: request.branch_point(),
    })
}

fn stable_projection(
    repository: &CampaignRepository,
    campaign: &str,
    observation_id: ObservationId,
    branch_point: BranchPointId,
    initial_attempt: AttemptId,
) -> Result<String, Box<dyn Error>> {
    let head = repository.head(campaign)?;
    let roots = head.snapshot().roots();
    let principal = CampaignPrincipal::new("campaign-continuity-v2-gate")?;
    let name = CampaignName::new(campaign)?;
    let client = CampaignClient::new(RepositoryCampaignService::new(repository, AllowQueries));

    let mut graph_after = None;
    let mut graph = Vec::new();
    loop {
        let request = QueryCampaignGraphRequest::new(
            principal.clone(),
            name.clone(),
            head.snapshot_id(),
            graph_after,
            MAX_CAMPAIGN_QUERY_PAGE_ITEMS,
        )?;
        let response = client.query_campaign_graph(&request)?;
        graph.extend(
            response
                .entries()
                .iter()
                .map(|entry| format!("{}={}", entry.key(), entry.object())),
        );
        let Some(next) = response.next_after() else {
            break;
        };
        graph_after = Some(next);
    }

    let mut frontier_after = None;
    let mut frontier = Vec::new();
    loop {
        let request = QueryCampaignFrontierRequest::new(
            principal.clone(),
            name.clone(),
            head.snapshot_id(),
            frontier_after,
            MAX_CAMPAIGN_FRONTIER_QUERY_PAGE_ITEMS,
        )?;
        let response = client.query_campaign_frontier(&request)?;
        for entry in response.entries() {
            assert!(matches!(
                entry.state(),
                ContinuationState::Ready
                    | ContinuationState::WaitingForFeedback(_)
                    | ContinuationState::Open
            ));
            frontier.push(format!(
                "{}:{}:{}:{}",
                entry.request(),
                entry.branch_point(),
                hash_bytes("frontier", &entry.canonical_bytes()),
                format_args!("{:?}", entry.state()),
            ));
        }
        let Some(next) = response.next_after() else {
            break;
        };
        frontier_after = Some(next);
    }
    assert_eq!(frontier.len(), 1);

    let mut findings_after = None;
    let mut findings = Vec::new();
    loop {
        let request = QueryCampaignFindingsRequest::new(
            principal.clone(),
            name.clone(),
            head.snapshot_id(),
            findings_after,
            MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS,
        )?;
        let response = client.query_campaign_findings(&request)?;
        for finding in response.entries() {
            let reproduction = repository.load_reproduction_artifact(finding.reproduction())?;
            findings.push(format!(
                "{}:{}:{}",
                finding.id()?,
                hash_bytes("finding", &finding.canonical_bytes()),
                hash_bytes("reproduction", &reproduction.canonical_bytes()),
            ));
        }
        let Some(next) = response.next_after() else {
            break;
        };
        findings_after = Some(next);
    }
    assert_eq!(findings.len(), 1);

    let observation = repository.load_observation(observation_id)?;
    let configuration = repository.load_configuration_artifact(observation.child_content())?;
    let measurements = repository.load_measurement_set(observation.measurements())?;
    let properties = repository.load_property_verdict_set(observation.properties())?;
    let coverage = repository.load_coverage_projection(observation.coverage())?;
    let visits = repository.project_branch_edge_visits(head.snapshot_id(), branch_point)?;
    assert_eq!(visits.parent_visits(), 1);
    assert_eq!(visits.edge_visits().values().copied().sum::<u64>(), 1);

    let mut pins = Vec::new();
    let pin_summary = repository.visit_pin_retention_roots(campaign, &mut |pin| {
        pins.push(format!(
            "{}:{}:{:?}:{}:{}",
            pin.fact(),
            pin.request().change.configuration(),
            pin.retention(),
            pin.configuration_artifact(),
            pin.scenario_artifact(),
        ));
    })?;
    assert_eq!(pin_summary.entries(), 1);
    assert_eq!(pin_summary.exact_pins(), 1);
    assert_eq!(pin_summary.thin_pins(), 0);
    assert_eq!(pin_summary.tombstones(), 0);

    let budget = repository.budget_projection(campaign)?;
    assert_eq!(budget.granted_proposals, 4);
    assert_eq!(budget.granted_attempts, 4);
    assert_eq!(budget.spent_proposals, 1);
    assert_eq!(budget.spent_attempts, 2);
    let mut claimable = Vec::new();
    let mut cursor = None;
    loop {
        let page = repository.project_claimable_attempts(campaign, cursor, 10_000)?;
        claimable.extend_from_slice(page.attempts());
        let Some(next) = page.next() else {
            break;
        };
        cursor = Some(next);
    }
    assert_eq!(claimable, vec![initial_attempt]);
    assert!(!graph.is_empty());

    Ok(format!(
        concat!(
            "roots={},{},{},{},{},{},{}\n",
            "graph={}\n",
            "frontier={}\n",
            "findings={}\n",
            "observation={}:{}:{}:{}:{}:{}\n",
            "visits={:?}\n",
            "pins={}:{}:{}:{}:{}:{}\n",
            "budget={}:{}:{}:{}\n",
            "claimable={}\n"
        ),
        roots.graph,
        roots.exploration,
        roots.observations,
        roots.corpus,
        roots.coverage,
        roots.findings,
        roots.pins,
        graph.join(","),
        frontier.join(","),
        findings.join(","),
        observation_id,
        hash_bytes("observation", &observation.canonical_bytes()),
        hash_bytes("configuration", &configuration.canonical_bytes()),
        hash_bytes("measurements", &measurements.canonical_bytes()),
        hash_bytes("properties", &properties.canonical_bytes()),
        hash_bytes("coverage", &coverage.canonical_bytes()),
        visits,
        pins.join(","),
        pin_summary.pins_root(),
        pin_summary.entries(),
        pin_summary.thin_pins(),
        pin_summary.exact_pins(),
        pin_summary.tombstones(),
        budget.granted_proposals,
        budget.granted_attempts,
        budget.spent_proposals,
        budget.spent_attempts,
        claimable
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
    ))
}

fn exact_checkpoint_closure(
    blobs: &DirectoryBlobBackend,
) -> Result<(ExactCheckpointId, crucible_cas::content_store::ContentId), Box<dyn Error>> {
    let leaf = ContentEnvelope::new(
        "crucible.gate.campaign-continuity-v2.trace",
        1,
        BTreeSet::new(),
        b"portable selected execution state".to_vec(),
    )?;
    let leaf_id = leaf.content_id(ObjectKind::Trace);
    blobs.put_if_absent(leaf_id, &BlobHandle::from_bytes(leaf.canonical_bytes()))?;
    let manifest = ContentEnvelope::new(
        "crucible.gate.campaign-continuity-v2.exact-checkpoint",
        4,
        BTreeSet::from([ContentChild::new("execution-state", leaf_id)?]),
        b"selected exact continuation materialization".to_vec(),
    )?;
    let manifest_id = manifest.content_id(ObjectKind::ExactManifest);
    blobs.put_if_absent(
        manifest_id,
        &BlobHandle::from_bytes(manifest.canonical_bytes()),
    )?;
    Ok((ExactCheckpointId::try_from(manifest_id)?, leaf_id))
}

fn exact_pin(
    repository: &CampaignRepository,
    campaign: &str,
) -> Result<crucible_campaign::CampaignPinRetentionRecord, Box<dyn Error>> {
    let mut pins = Vec::new();
    repository.visit_pin_retention_roots(campaign, &mut |pin| pins.push(pin))?;
    if pins.len() != 1 || pins[0].retention() != PinRetention::Exact {
        return Err("expected one exact semantic pin".into());
    }
    Ok(pins.remove(0))
}

struct FixtureCheckpointResolver {
    configuration: ConfigurationId,
    fact: CampaignFactId,
    checkpoint: ExactCheckpointId,
}

impl CampaignArchiveCheckpointResolver for FixtureCheckpointResolver {
    fn resolve_checkpoint(
        &mut self,
        configuration: ConfigurationId,
        pin_fact: CampaignFactId,
    ) -> Result<ExactCheckpointId, CampaignRepositoryError> {
        if configuration != self.configuration || pin_fact != self.fact {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "continuity fixture exact-pin selection mismatch",
            });
        }
        Ok(self.checkpoint)
    }
}

struct AllowQueries;

impl CampaignPrincipalAuthorizer for AllowQueries {
    fn authorize(
        &self,
        _principal: &CampaignPrincipal,
        _operation: CampaignServiceOperation,
        _campaign: &CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), CampaignAuthorizationError> {
        Ok(())
    }
}

fn directory_repository(root: &Path) -> CampaignRepository {
    CampaignRepository::new(
        Arc::new(DirectoryBlobBackend::new(
            "campaign-continuity-v2-helper",
            root.join("objects"),
        )),
        Arc::new(DirectoryRefBackend::new(root.join("refs"))),
    )
}

// crucible-lint: allow rust-allow -- the cross-process fixture forwards every authenticated identity and artifact path explicitly.
#[allow(clippy::too_many_arguments)]
fn run_helper(
    root: &Path,
    campaign: &str,
    action: &str,
    paused_snapshot: CampaignSnapshotId,
    observation: ObservationId,
    branch_point: BranchPointId,
    initial_attempt: AttemptId,
    frozen: &Path,
    resumed: &Path,
    checkpoint: ExactCheckpointId,
    checkpoint_leaf: ContentId,
) {
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--ignored")
        .arg("--exact")
        .arg(PROCESS_HELPER)
        .arg("--nocapture")
        .env("CRUCIBLE_CONTINUITY_ROOT", root)
        .env("CRUCIBLE_CONTINUITY_CAMPAIGN", campaign)
        .env("CRUCIBLE_CONTINUITY_ACTION", action)
        .env(
            "CRUCIBLE_CONTINUITY_PAUSED_SNAPSHOT",
            paused_snapshot.to_string(),
        )
        .env("CRUCIBLE_CONTINUITY_OBSERVATION", observation.to_string())
        .env("CRUCIBLE_CONTINUITY_BRANCH_POINT", branch_point.to_string())
        .env(
            "CRUCIBLE_CONTINUITY_INITIAL_ATTEMPT",
            initial_attempt.to_string(),
        )
        .env("CRUCIBLE_CONTINUITY_FROZEN", frozen)
        .env("CRUCIBLE_CONTINUITY_RESUMED", resumed)
        .env("CRUCIBLE_CONTINUITY_CHECKPOINT", checkpoint.to_string())
        .env(
            "CRUCIBLE_CONTINUITY_CHECKPOINT_LEAF",
            checkpoint_leaf.to_string(),
        )
        .output()
        .expect("spawn campaign continuity helper");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "campaign continuity helper {action} failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        stdout
            .contains("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out"),
        "campaign continuity helper selector did not execute exactly one test:\n{stdout}",
    );
}

fn authenticate_checkpoint_closure(
    root: &Path,
    checkpoint: ExactCheckpointId,
    checkpoint_leaf: ContentId,
) -> Result<(), Box<dyn Error>> {
    let blobs = DirectoryBlobBackend::new(
        "campaign-continuity-v2-checkpoint-reader",
        root.join("objects"),
    );
    let manifest_bytes = blobs
        .read(checkpoint.content_id(), None)?
        .read_all(1024 * 1024)?;
    let manifest = ContentEnvelope::from_canonical_bytes(&manifest_bytes)?;
    assert_eq!(
        manifest.content_id(ObjectKind::ExactManifest),
        checkpoint.content_id(),
    );
    assert_eq!(manifest.children().len(), 1);
    assert_eq!(
        manifest.children().iter().next().map(ContentChild::id),
        Some(checkpoint_leaf),
    );
    let leaf_bytes = blobs.read(checkpoint_leaf, None)?.read_all(1024 * 1024)?;
    let leaf = ContentEnvelope::from_canonical_bytes(&leaf_bytes)?;
    assert_eq!(leaf.content_id(ObjectKind::Trace), checkpoint_leaf);
    assert!(leaf.children().is_empty());
    Ok(())
}

fn exact_head_state(
    repository: &CampaignRepository,
    campaign: &str,
) -> Result<String, CampaignRepositoryError> {
    let head = repository.head(campaign)?;
    let roots = head.snapshot().roots();
    Ok(format!(
        "snapshot={}\nroots={:?}\nstate={:?}\n",
        head.snapshot_id(),
        roots,
        repository.state(campaign)?,
    ))
}

fn assert_stable_roots(
    before: crucible_campaign::CampaignRoots,
    after: crucible_campaign::CampaignRoots,
) {
    assert_eq!(before.graph, after.graph);
    assert_eq!(before.exploration, after.exploration);
    assert_eq!(before.observations, after.observations);
    assert_eq!(before.corpus, after.corpus);
    assert_eq!(before.coverage, after.coverage);
    assert_eq!(before.findings, after.findings);
    assert_eq!(before.pins, after.pins);
}

fn control(
    label: &str,
    expected_snapshot: CampaignSnapshotId,
    action: CampaignControlAction,
) -> ControlRequest {
    ControlRequest {
        command: command_id(label),
        expected_snapshot,
        action,
    }
}

fn command_id(label: &str) -> CampaignCommandId {
    CampaignCommandId::from_hash(CampaignHash::derive(
        "gate.campaign-continuity-v2.command",
        label.as_bytes(),
    ))
}

fn hash(label: &str) -> CampaignHash {
    CampaignHash::derive("gate.campaign-continuity-v2", label.as_bytes())
}

fn hash_bytes(label: &str, bytes: &[u8]) -> CampaignHash {
    CampaignHash::derive(
        &format!("gate.campaign-continuity-v2.projection.{label}"),
        bytes,
    )
}

fn required_environment(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}
