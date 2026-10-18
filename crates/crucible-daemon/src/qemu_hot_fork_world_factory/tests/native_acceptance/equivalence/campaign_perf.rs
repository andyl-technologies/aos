//! Campaign planner and queue work at the native short-branch boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crucible_campaign::{
    AuthorizedPlannerService, BranchBudget, BranchRequest, BranchRequestCause, CampaignCommandId,
    CampaignControlAction, CampaignPlannerDriver, CampaignPlannerStepOutcome, CampaignRepository,
    CampaignSeed, CandidateSource, CanonicalFrontierPlanner, ControlRequest, PlannerClient,
    PlannerDisposition, PlanningBudget,
};
use crucible_cas::content_store::{
    DirectoryRefBackend, ObjectKind, StoreGraph, StoreGraphConfig, StoreNodeId, StoreNodeSpec,
};

use crate::guest_selectable::resolve_guest_selectable;
use crate::planner_process::{CanonicalPlannerProcessConfig, CanonicalPlannerProcessSupervisor};

use super::*;

// Share the bounded actual page walk with the durable admission diagnostic.
#[path = "../../../../../tests/support/campaign_queue_scan.rs"]
mod campaign_queue_scan;

const CAMPAIGN: &str = "native-performance-short-branch";

pub(super) struct CampaignPlannerSample {
    pub(super) nanoseconds: u64,
    pub(super) work: CampaignPlannerWork,
}

/// Owns already accepted planner results until serialization after timing.
pub(super) struct CampaignPlannerWork {
    scenario: crucible_campaign::ScenarioArtifact,
    genesis: crucible_campaign::ConfigurationArtifact,
    parent: crucible_campaign::ConfigurationId,
    request: BranchRequest,
    proposal: crucible_campaign::Proposal,
    snapshot: crucible_campaign::CampaignSnapshotId,
    queue: campaign_queue_scan::QueueScanMeasurement,
}

impl CampaignPlannerWork {
    pub(super) fn record(&self) -> serde_json::Value {
        serde_json::json!({
            "scenario_artifact": self.scenario.id().expect("scenario identity").to_text(),
            "genesis_artifact": self.genesis.id().expect("genesis identity").to_text(),
            "parent_configuration": self.parent.to_hex(),
            "request_bytes": self.request.canonical_bytes(),
            "proposal_bytes": self.proposal.canonical_bytes(),
            "snapshot": self.snapshot.to_text(),
            "queue_attempts": self.queue.attempts,
            "queue_pages": self.queue.pages,
            "queue_scanned_entries": self.queue.scanned_entries,
            "queue_empty_pages": self.queue.empty_pages,
            "ordered_attempts_digest": self.queue.ordered_attempts_digest.to_hex().as_str(),
        })
    }
}

pub(super) fn measure_campaign_planner_queue_at_boundary(
    source: &crucible::ScenarioDefForm,
    input: &CrucibleAttemptExecution,
    boundary: &BoundaryEvidence,
    index: usize,
) -> CampaignPlannerSample {
    let storage_root = PathBuf::from(
        std::env::var_os("CRUCIBLE_CAMPAIGN_PERF_STORAGE_ROOT")
            .expect("packaged campaign performance storage root"),
    )
    .join(format!("sample-{index}"));
    let planner_executable = PathBuf::from(
        std::env::var_os("CRUCIBLE_CAMPAIGN_PERF_PLANNER_EXECUTABLE")
            .expect("packaged planner worker executable"),
    );
    std::fs::create_dir_all(&storage_root).expect("create performance storage root");
    let root = StoreNodeId::new("campaign-primary").expect("campaign store node");
    // Match the deployed campaign graph's admitted kinds and durable leaf.
    let blobs = StoreGraph::build(StoreGraphConfig {
        root: root.clone(),
        admitted_kinds: BTreeSet::from([
            ObjectKind::CampaignFact,
            ObjectKind::CampaignSnapshot,
            ObjectKind::MerkleNode,
            ObjectKind::Scenario,
            ObjectKind::Configuration,
            ObjectKind::Policy,
            ObjectKind::ExactManifest,
            ObjectKind::RamExtent,
            ObjectKind::DiskExtent,
            ObjectKind::DeviceState,
            ObjectKind::Observation,
            ObjectKind::Finding,
            ObjectKind::Projection,
            ObjectKind::Trace,
        ]),
        nodes: BTreeMap::from([(
            root,
            StoreNodeSpec::Sqlite {
                root: storage_root.join("blobs"),
            },
        )]),
    })
    .expect("build production campaign SQLite store graph");
    let authority =
        crucible_campaign::PlannerAuthorityKey::from_bytes([0x92; 32]).expect("planner authority");
    let debugger_authority = crucible_campaign::DebuggerAuthorityKey::from_bytes([0x94; 32])
        .expect("debugger authority");
    let repository = Arc::new(
        CampaignRepository::with_component_authorities(
            Arc::new(blobs),
            Arc::new(DirectoryRefBackend::new(storage_root.join("refs"))),
            authority.clone(),
            debugger_authority,
        )
        .expect("configure campaign component authorities"),
    );
    let scenario_artifact =
        encode_crucible_scenario_artifact(source).expect("encode performance scenario");
    repository
        .publish_scenario_artifact(
            scenario_artifact.scenario(),
            scenario_artifact.payload_schema(),
            scenario_artifact.payload().to_vec(),
        )
        .expect("publish performance scenario");
    let genesis = Configuration::genesis(source.scenario_def());
    let genesis_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &genesis.schedule)
            .expect("encode performance genesis");
    repository
        .publish_configuration_artifact(
            genesis_artifact.scenario(),
            genesis_artifact.scenario_artifact(),
            genesis_artifact.configuration(),
            genesis_artifact.payload_schema(),
            genesis_artifact.payload().to_vec(),
        )
        .expect("publish performance genesis");
    let parent_artifact = encode_crucible_configuration_artifact(
        &scenario_artifact,
        &boundary.configuration.schedule,
    )
    .expect("encode pending performance configuration");
    let parent_content = repository
        .publish_configuration_artifact(
            parent_artifact.scenario(),
            parent_artifact.scenario_artifact(),
            parent_artifact.configuration(),
            parent_artifact.payload_schema(),
            parent_artifact.payload().to_vec(),
        )
        .expect("publish pending performance configuration");
    let lineage = input.lineage();
    assert_eq!(
        lineage.scenario_content(),
        scenario_artifact.id().expect("scenario id")
    );
    assert_eq!(
        lineage.genesis_content(),
        genesis_artifact.id().expect("genesis id")
    );
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            lineage.scenario(),
            CampaignSeed::from_bytes([0x91; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(
                    ProgressiveWideningPolicy::new(
                        ExactRational::new(1, 1).expect("widening factor"),
                        ExactRational::new(1, 2).expect("widening exponent"),
                        1,
                        100,
                        1,
                    )
                    .expect("widening policy"),
                ),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness policy"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )
    .expect("performance campaign policy");
    let created = repository
        .create(CAMPAIGN, lineage, &policy, &BTreeMap::new())
        .expect("create performance campaign");
    let funded = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: command_id(index, "fund"),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(1, 1).expect("one performance attempt"),
                ),
            },
        )
        .expect("fund performance campaign");
    let running = repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: command_id(index, "resume"),
                expected_snapshot: funded.new_snapshot,
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume performance campaign");
    let discovery = resolve_guest_selectable(
        lineage.scenario(),
        source,
        boundary.pending.node(),
        boundary.pending.pending(),
    )
    .expect("resolve exact pending campaign choice");
    repository
        .publish_choice_domain(discovery.domain())
        .expect("publish exact pending domain");
    repository
        .publish_selectable(discovery.declaration())
        .expect("publish exact pending selectable");
    repository
        .publish_choice_opportunity(discovery.opportunity())
        .expect("publish exact pending opportunity");
    let branch_point = discovery
        .opportunity()
        .branch_point_id(parent_artifact.configuration());
    let request = BranchRequest::new(
        BranchRequest::identity(
            branch_point,
            parent_content,
            discovery.opportunity().id().expect("opportunity id"),
            discovery.domain().id().expect("domain id"),
        ),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Integer(
            IntegerValue::Unsigned(7),
        )]))
        .expect("single exact guest choice"),
        BranchRequestCause::Operator(command_id(index, "request")),
        BranchBudget::new(1, 1).expect("one branch"),
        StopCondition::NextChoice,
    )
    .expect("short-branch request");
    let basis = repository
        .publish_canonical_frontier_planner_basis()
        .expect("publish canonical planner basis");
    let (engine, artifact, state) = basis.into_parts();
    let worker = CanonicalPlannerProcessConfig::new(planner_executable, Duration::from_secs(60))
        .expect("packaged planner worker contract");
    let (supervisor, _cancellation) = CanonicalPlannerProcessSupervisor::new(worker);
    let client = PlannerClient::new(
        AuthorizedPlannerService::new(CanonicalFrontierPlanner, supervisor, authority.clone()),
        authority,
    );
    let mut planner = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        client,
        engine,
        artifact,
        state,
        16,
        PlanningBudget::new(1, 1, 64, 64 * 1024, 10_000).expect("planning budget"),
    )
    .expect("campaign planner driver")
    .require_tree_search_policy();

    // Request publication is a separate setup phase. The RFC numerator starts
    // with the canonical planner step and ends after queue reservation.
    let setup_started = operational_monotonic_nanoseconds();
    let discovered = repository
        .discover_operator_choice_opportunity(
            CAMPAIGN,
            running.new_snapshot,
            parent_content,
            discovery.opportunity().id().expect("opportunity id"),
        )
        .expect("discover exact pending choice");
    repository
        .submit_operator_branch_request(CAMPAIGN, discovered.new_snapshot, &request)
        .expect("submit exact short branch");
    let setup_elapsed = operational_monotonic_nanoseconds()
        .checked_sub(setup_started)
        .expect("campaign request setup monotonic clock regressed");
    println!("corpus_{index}_campaign_request_setup_ns={setup_elapsed}");
    let started = operational_monotonic_nanoseconds();
    let CampaignPlannerStepOutcome::Advanced {
        result,
        disposition: PlannerDisposition::Issue {
            issued_proposals, ..
        },
        ..
    } = planner.step(CAMPAIGN).expect("plan exact short branch")
    else {
        panic!("canonical planner did not admit the short branch");
    };
    assert_eq!(issued_proposals.len(), 1);
    let proposal = repository
        .load_proposal(issued_proposals[0])
        .expect("load canonical short-branch proposal");
    assert_eq!(proposal.branch_point(), branch_point);
    assert_eq!(
        proposal.value(),
        &ChoiceValue::Integer(IntegerValue::Unsigned(7))
    );
    // Accounting pages may be empty before the one admitted attempt. Keep
    // the complete page walk and real one-slot reservation in the numerator.
    let queue_measurement =
        campaign_queue_scan::scan_queue(&repository, CAMPAIGN, result.new_snapshot, 1, 10_000)
            .expect("walk bounded exact short-branch queue");
    assert_eq!(queue_measurement.attempts, 1);
    let elapsed = operational_monotonic_nanoseconds()
        .checked_sub(started)
        .expect("campaign planner/queue monotonic clock regressed");
    let physical_bytes = allocated_tree_bytes(&storage_root);
    assert!(
        physical_bytes > 0,
        "durable campaign sample stored no bytes"
    );
    println!(
        "corpus_{index}_campaign_storage_root={}",
        storage_root.display()
    );
    println!("corpus_{index}_campaign_storage_physical_bytes={physical_bytes}");
    CampaignPlannerSample {
        nanoseconds: elapsed,
        work: CampaignPlannerWork {
            scenario: scenario_artifact,
            genesis: genesis_artifact,
            parent: parent_artifact.configuration(),
            request,
            proposal,
            snapshot: result.new_snapshot,
            queue: queue_measurement,
        },
    }
}

fn command_id(index: usize, operation: &str) -> CampaignCommandId {
    CampaignCommandId::from_hash(CampaignHash::derive(
        "crucible.native-campaign-performance.command.v1",
        format!("{index}:{operation}").as_bytes(),
    ))
}
