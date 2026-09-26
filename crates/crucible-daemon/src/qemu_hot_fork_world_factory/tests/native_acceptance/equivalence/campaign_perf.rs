//! Campaign planner and queue work at the native short-branch boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crucible_campaign::{
    AttemptQueue, AuthorizedPlannerService, BranchBudget, BranchRequest, BranchRequestCause,
    CampaignCommandId, CampaignControlAction, CampaignPlannerDriver, CampaignPlannerStepOutcome,
    CampaignRepository, CampaignSeed, CandidateSource, CanonicalFrontierPlanner, ControlRequest,
    DaemonEpoch, PlannerClient, PlannerDisposition, PlanningBudget, WorkerSlotId,
};
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};

use crate::guest_selectable::resolve_guest_selectable;
use crate::planner_process::{CanonicalPlannerProcessConfig, CanonicalPlannerProcessSupervisor};

use super::*;

const CAMPAIGN: &str = "native-performance-short-branch";

pub(super) fn measure_campaign_planner_queue_at_boundary(
    source: &crucible::ScenarioDefForm,
    input: &CrucibleAttemptExecution,
    boundary: &BoundaryEvidence,
    index: usize,
) -> u64 {
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
    let authority =
        crucible_campaign::PlannerAuthorityKey::from_bytes([0x92; 32]).expect("planner authority");
    let debugger_authority = crucible_campaign::DebuggerAuthorityKey::from_bytes([0x94; 32])
        .expect("debugger authority");
    let repository = Arc::new(
        CampaignRepository::with_component_authorities(
            Arc::new(DirectoryBlobBackend::new(
                format!("native-performance-{index}"),
                storage_root.join("blobs"),
            )),
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
    let page = repository
        .project_claimable_attempts(CAMPAIGN, None, 1)
        .expect("project exact short branch");
    assert_eq!(page.attempts().len(), 1);
    let mut queue = AttemptQueue::new(DaemonEpoch::from_bytes([0x93; 16]).expect("queue epoch"), 1)
        .expect("one worker slot");
    let reservation = queue
        .reserve_from_page(&page, WorkerSlotId::new(0))
        .expect("reserve short branch")
        .expect("short branch is claimable");
    queue.release(reservation).expect("release short branch");
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
    elapsed
}

fn command_id(index: usize, operation: &str) -> CampaignCommandId {
    CampaignCommandId::from_hash(CampaignHash::derive(
        "crucible.native-campaign-performance.command.v1",
        format!("{index}:{operation}").as_bytes(),
    ))
}
