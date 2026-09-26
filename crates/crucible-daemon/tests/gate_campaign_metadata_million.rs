//! Durable one-million-admission campaign metadata and paged queue gate.

// crucible-lint: allow panic-shortcut -- gate assertions fail at the violated invariant.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use crucible_campaign::{
    AlternativeId, AttemptQueue, AuthorizedPlannerService, BranchBudget, BranchRequest,
    BranchRequestCause, BudgetGrant, CampaignCommandId, CampaignControlAction, CampaignHash,
    CampaignLineage, CampaignMode, CampaignPlannerDriver, CampaignPlannerStepOutcome,
    CampaignPolicy, CampaignRepository, CampaignSeed, CandidateSource, CanonicalFrontierPlanner,
    ChoiceClassContext, ChoiceCoordinate, ChoiceDomain, ChoiceOpportunity, ChoiceSource,
    ChoiceValue, ControlRequest, DaemonEpoch, DebuggerAuthorityKey, DiscreteAlternative,
    DiscreteDomain, ExactRational, ExplorerPolicy, FairnessPolicy, MAX_CAMPAIGN_SNAPSHOT_ANCESTRY,
    PlannerAuthorityKey, PlannerClient, PlannerDisposition, PlanningBudget,
    ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy, ScenarioDefId, SelectableDeclaration,
    StopCondition, WorkerSlotId,
};
use crucible_cas::content_store::{
    DirectoryRefBackend, ObjectKind, StoreGraph, StoreGraphAdmin, StoreGraphConfig, StoreNodeId,
    StoreNodeSpec,
};
use crucible_daemon::{CanonicalPlannerProcessConfig, CanonicalPlannerProcessSupervisor};
use rustix::time::{ClockId, Timespec, clock_gettime};

const CAMPAIGN: &str = "million-real-admissions";
const REQUEST_SIZE: usize = 16;
const PAGE_SIZE: usize = 512;
const REQUIRED_ADMISSIONS: usize = 1_000_000;
const REQUIRED_ANCESTRY: usize = ancestry_for_admissions(REQUIRED_ADMISSIONS);
const CAMPAIGN_OBJECT_KINDS: [ObjectKind; 14] = [
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
];

// Host monotonic time is reported only as diagnostic evidence. It never enters
// a planner request, campaign state, or a simulation timeout.
fn measurement_elapsed_since(started: Timespec) -> Result<Duration, Box<dyn Error>> {
    let finished = clock_gettime(ClockId::Monotonic);
    let started = Duration::try_from(started)?;
    let finished = Duration::try_from(finished)?;
    Ok(finished
        .checked_sub(started)
        .ok_or("monotonic clock moved backwards")?)
}

const fn ancestry_for_admissions(admissions: usize) -> usize {
    // create + fund + resume, then discover + submit per finite request,
    // then one canonical ordered Issue successor per finite request.
    1 + 2 + 3 * (admissions / REQUEST_SIZE)
}

#[test]
fn million_admission_ancestry_capacity_probe() {
    assert_eq!(REQUIRED_ADMISSIONS % REQUEST_SIZE, 0);
    assert_eq!(ancestry_for_admissions(REQUIRED_ADMISSIONS), 187_503);
    println!(
        "campaign_million_capacity required={REQUIRED_ANCESTRY} limit={MAX_CAMPAIGN_SNAPSHOT_ANCESTRY}"
    );
}

#[test]
#[ignore = "requires a protected packaged planner worker and a durable million-admission store"]
fn million_real_admissions_fit_compact_metadata_budget() -> Result<(), Box<dyn Error>> {
    if REQUIRED_ANCESTRY > MAX_CAMPAIGN_SNAPSHOT_ANCESTRY {
        return Err(format!(
            "campaign million blocked: required ancestry {REQUIRED_ANCESTRY} exceeds authenticated limit {MAX_CAMPAIGN_SNAPSHOT_ANCESTRY}"
        )
        .into());
    }
    let root = PathBuf::from(
        std::env::var_os("CRUCIBLE_CAMPAIGN_MILLION_STORAGE_ROOT")
            .ok_or("missing durable campaign performance storage root")?,
    );
    assert!(root.is_absolute());
    let worker = PathBuf::from(
        std::env::var_os("CRUCIBLE_CAMPAIGN_MILLION_PLANNER_EXECUTABLE")
            .ok_or("missing packaged planner worker executable")?,
    );
    assert!(worker.is_absolute());

    let measured = run_corpus(&root, &worker, REQUIRED_ADMISSIONS)?;
    assert_eq!(measured.admissions, REQUIRED_ADMISSIONS);
    assert_eq!(measured.request_count, REQUIRED_ADMISSIONS / REQUEST_SIZE);
    assert_eq!(measured.hot_claimable, REQUIRED_ADMISSIONS);
    assert_eq!(measured.cold_claimable, REQUIRED_ADMISSIONS);
    assert!(measured.hot_pages > 1);
    assert_eq!(measured.hot_pages, measured.cold_pages);

    // These candidate ceilings are fixed before the million-run measurement;
    // only a terminal full-corpus run can establish the accepted budget.
    assert!(
        measured.objects <= 64_000_000,
        "object budget exceeded: {measured:?}"
    );
    assert!(
        measured.index_bytes <= 128_000_000_000,
        "index budget exceeded: {measured:?}"
    );
    assert!(
        measured.logical_bytes <= 160_000_000_000,
        "logical budget exceeded: {measured:?}"
    );
    assert!(
        measured.physical_bytes <= 256_000_000_000,
        "physical budget exceeded: {measured:?}"
    );
    assert!(
        measured.combined_peak_rss_upper_bound_kib <= 4 * 1024 * 1024,
        "RSS budget exceeded: {measured:?}"
    );
    Ok(())
}

#[test]
#[ignore = "requires a protected packaged planner worker and a durable local store"]
fn small_real_admission_corpus_exercises_the_same_path() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(
        std::env::var_os("CRUCIBLE_CAMPAIGN_MILLION_STORAGE_ROOT")
            .ok_or("missing durable campaign performance storage root")?,
    );
    let worker = PathBuf::from(
        std::env::var_os("CRUCIBLE_CAMPAIGN_MILLION_PLANNER_EXECUTABLE")
            .ok_or("missing packaged planner worker executable")?,
    );
    let measured = run_corpus(&root, &worker, 2 * REQUEST_SIZE)?;
    assert_eq!(measured.hot_claimable, 2 * REQUEST_SIZE);
    assert_eq!(measured.cold_claimable, measured.hot_claimable);
    assert!(measured.index_bytes > 0);
    assert!(measured.physical_bytes > 0);
    Ok(())
}

#[derive(Debug)]
struct CorpusMeasurement {
    admissions: usize,
    request_count: usize,
    hot_claimable: usize,
    cold_claimable: usize,
    hot_pages: usize,
    cold_pages: usize,
    objects: u64,
    index_bytes: u64,
    logical_bytes: u64,
    physical_bytes: u64,
    allocated_bytes: u64,
    coordinator_peak_rss_kib: u64,
    planner_worker_peak_rss_kib: u64,
    combined_peak_rss_upper_bound_kib: u64,
}

fn sqlite_blob_graph(root: &Path) -> Result<(Arc<StoreGraph>, StoreGraphAdmin), Box<dyn Error>> {
    let leaf = StoreNodeId::new("campaign-million-blobs")?;
    let (graph, maintenance) = StoreGraph::build_with_admin(StoreGraphConfig {
        root: leaf.clone(),
        admitted_kinds: BTreeSet::from(CAMPAIGN_OBJECT_KINDS),
        nodes: BTreeMap::from([(
            leaf,
            StoreNodeSpec::Sqlite {
                root: root.join("blobs"),
            },
        )]),
    })?;
    Ok((Arc::new(graph), maintenance))
}

fn run_corpus(
    root: &Path,
    worker: &Path,
    admissions: usize,
) -> Result<CorpusMeasurement, Box<dyn Error>> {
    assert_eq!(admissions % REQUEST_SIZE, 0);
    assert!(admissions > 0);
    std::fs::create_dir_all(root)?;
    assert!(
        root.read_dir()?.next().is_none(),
        "performance store must be empty"
    );

    let (blobs, maintenance) = sqlite_blob_graph(root)?;
    let refs = Arc::new(DirectoryRefBackend::new(root.join("refs")));
    let planner_authority = PlannerAuthorityKey::from_bytes([0x91; 32])?;
    let debugger_authority = DebuggerAuthorityKey::from_bytes([0x92; 32])?;
    let repository = Arc::new(CampaignRepository::with_component_authorities(
        blobs.clone(),
        refs.clone(),
        planner_authority.clone(),
        debugger_authority.clone(),
    )?);
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
        "gate.campaign-million.scenario",
        b"single-lightweight-branch",
    ));
    let genesis = crucible_campaign::ConfigurationId::from_hash(CampaignHash::derive(
        "gate.campaign-million.genesis",
        b"single-lightweight-branch",
    ));
    let scenario_content =
        repository.publish_scenario_artifact(scenario, 1, b"campaign million scenario".to_vec())?;
    let genesis_content = repository.publish_configuration_artifact(
        scenario,
        scenario_content,
        genesis,
        1,
        b"campaign million genesis".to_vec(),
    )?;
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "campaign-million-gate",
        "campaign-million-qemu",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )?;
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([0x93; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                widening: Some(ProgressiveWideningPolicy::new(
                    ExactRational::new(1, 1)?,
                    ExactRational::new(1, 2)?,
                    1,
                    100,
                    1,
                )?),
                puct: PuctPolicy::new(1_000_000, 1, 0),
            },
        ),
        CampaignPolicy::rules(
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0)?,
            RetentionPolicy::new(true, 1, true, true),
            true,
        ),
    )?;
    let created = repository.create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())?;
    let funded = repository.apply_control(
        CAMPAIGN,
        &ControlRequest {
            command: command_id("fund", 0),
            expected_snapshot: created.snapshot_id(),
            action: CampaignControlAction::GrantBudget(BudgetGrant::new(
                admissions as u64,
                admissions as u64,
            )?),
        },
    )?;
    let running = repository.apply_control(
        CAMPAIGN,
        &ControlRequest {
            command: command_id("resume", 0),
            expected_snapshot: funded.new_snapshot,
            action: CampaignControlAction::Resume,
        },
    )?;
    let basis = repository.publish_canonical_frontier_planner_basis()?;
    let (engine, artifact, state) = basis.into_parts();
    let config = CanonicalPlannerProcessConfig::new(worker, Duration::from_secs(60))?;
    let worker_peak_rss = Arc::new(AtomicU64::new(0));
    let (supervisor, _cancellation) = CanonicalPlannerProcessSupervisor::new(config);
    let supervisor = supervisor.with_worker_peak_rss_observer(Arc::clone(&worker_peak_rss));
    let client = PlannerClient::new(
        AuthorizedPlannerService::new(CanonicalFrontierPlanner, supervisor, planner_authority),
        PlannerAuthorityKey::from_bytes([0x91; 32])?,
    );
    let mut planner = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        client,
        engine,
        artifact,
        state,
        u32::try_from(REQUEST_SIZE)?,
        PlanningBudget::new(1, REQUEST_SIZE as u32, 64, 64 * 1024, 10_000)?,
    )?
    .require_tree_search_policy();

    let mut parent = running.new_snapshot;
    let mut ancestry_depth = 3_usize;
    let mut setup_elapsed = Duration::ZERO;
    let mut planner_elapsed = Duration::ZERO;
    for request_index in 0..admissions / REQUEST_SIZE {
        let setup_started = clock_gettime(ClockId::Monotonic);
        let request = publish_request(&repository, &lineage, request_index)?;
        let discovered = repository.discover_operator_choice_opportunity(
            CAMPAIGN,
            parent,
            genesis_content,
            request.opportunity(),
        )?;
        repository.submit_operator_branch_request(CAMPAIGN, discovered.new_snapshot, &request)?;
        ancestry_depth += 2;
        setup_elapsed += measurement_elapsed_since(setup_started)?;

        let step_started = clock_gettime(ClockId::Monotonic);
        let outcome = planner.step(CAMPAIGN)?;
        let CampaignPlannerStepOutcome::Advanced {
            result,
            disposition:
                PlannerDisposition::Issue {
                    issued_proposals, ..
                },
            ..
        } = outcome
        else {
            return Err(format!(
                "canonical planner failed to admit one finite request: {outcome:?}"
            )
            .into());
        };
        assert_eq!(issued_proposals.len(), REQUEST_SIZE);
        parent = result.new_snapshot;
        ancestry_depth += 1;
        planner_elapsed += measurement_elapsed_since(step_started)?;
        if (request_index + 1) % 1_024 == 0 {
            println!(
                "campaign_million_progress admissions={} requests={} setup_ns={} planner_ns={}",
                (request_index + 1) * REQUEST_SIZE,
                request_index + 1,
                setup_elapsed.as_nanos(),
                planner_elapsed.as_nanos(),
            );
        }
    }
    assert_eq!(ancestry_depth, ancestry_for_admissions(admissions));
    let projection = repository.budget_projection(CAMPAIGN)?;
    assert_eq!(projection.spent_proposals, admissions as u64);
    assert_eq!(projection.spent_attempts, admissions as u64);

    let hot_started = clock_gettime(ClockId::Monotonic);
    let (hot_claimable, hot_pages) = scan_queue(&repository, parent)?;
    let hot_elapsed = measurement_elapsed_since(hot_started)?;
    drop(planner);
    drop(repository);

    let mut index_bytes = 0_u64;
    let physical = maintenance.physical();
    assert_eq!(physical.len(), 1);
    let mut fence = physical[0].admin().acquire_inventory_fence()?;
    let inventory = fence.visit_inventory(&mut |record| {
        if record.id().kind() == ObjectKind::MerkleNode {
            index_bytes = index_bytes.checked_add(record.logical_length()).ok_or(
                crucible_cas::content_store::StoreError::InvalidComposition {
                    reason: "campaign index byte count overflow",
                },
            )?;
        }
        Ok(())
    })?;
    drop(fence);
    drop(physical);
    let (warm_allocated_bytes, warm_physical_bytes) = storage_tree_bytes(root)?;
    drop(maintenance);
    drop(blobs);

    let (cold_blobs, cold_maintenance) = sqlite_blob_graph(root)?;
    let cold = CampaignRepository::with_component_authorities(
        cold_blobs,
        Arc::new(DirectoryRefBackend::new(root.join("refs"))),
        PlannerAuthorityKey::from_bytes([0x91; 32])?,
        debugger_authority,
    )?;
    let cold_started = clock_gettime(ClockId::Monotonic);
    assert_eq!(cold.head(CAMPAIGN)?.snapshot_id(), parent);
    let (cold_claimable, cold_pages) = scan_queue(&cold, parent)?;
    let cold_elapsed = measurement_elapsed_since(cold_started)?;
    let (cold_allocated_bytes, cold_physical_bytes) = storage_tree_bytes(root)?;
    let allocated_bytes = warm_allocated_bytes.max(cold_allocated_bytes);
    let physical_bytes = warm_physical_bytes.max(cold_physical_bytes);
    drop(cold);
    drop(cold_maintenance);

    let coordinator_peak_rss_kib = peak_rss_kib()?;
    let planner_worker_peak_rss_kib = worker_peak_rss.load(Ordering::Acquire);
    assert!(
        planner_worker_peak_rss_kib > 0,
        "protected planner worker did not report peak RSS"
    );
    // The two process peaks need not coincide, so their sum is a safe bound.
    let combined_peak_rss_upper_bound_kib = coordinator_peak_rss_kib
        .checked_add(planner_worker_peak_rss_kib)
        .ok_or("combined peak RSS overflow")?;
    let measured = CorpusMeasurement {
        admissions,
        request_count: admissions / REQUEST_SIZE,
        hot_claimable,
        cold_claimable,
        hot_pages,
        cold_pages,
        objects: inventory.objects(),
        index_bytes,
        logical_bytes: inventory.logical_bytes(),
        physical_bytes,
        allocated_bytes,
        coordinator_peak_rss_kib,
        planner_worker_peak_rss_kib,
        combined_peak_rss_upper_bound_kib,
    };
    println!(
        "campaign_million_profile admissions={} requests={} request_size={REQUEST_SIZE} hot_claimable={} cold_claimable={} hot_pages={} cold_pages={} objects={} index_bytes={} logical_bytes={} physical_bytes={} allocated_bytes={} coordinator_peak_rss_kib={} planner_worker_peak_rss_kib={} combined_peak_rss_upper_bound_kib={} setup_ns={} planner_ns={} hot_queue_ns={} cold_reopen_queue_ns={}",
        measured.admissions,
        measured.request_count,
        measured.hot_claimable,
        measured.cold_claimable,
        measured.hot_pages,
        measured.cold_pages,
        measured.objects,
        measured.index_bytes,
        measured.logical_bytes,
        measured.physical_bytes,
        measured.allocated_bytes,
        measured.coordinator_peak_rss_kib,
        measured.planner_worker_peak_rss_kib,
        measured.combined_peak_rss_upper_bound_kib,
        setup_elapsed.as_nanos(),
        planner_elapsed.as_nanos(),
        hot_elapsed.as_nanos(),
        cold_elapsed.as_nanos(),
    );
    Ok(measured)
}

fn publish_request(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    request_index: usize,
) -> Result<BranchRequest, Box<dyn Error>> {
    let label = format!("{CAMPAIGN}-request-{request_index}");
    let alternatives = (0..REQUEST_SIZE)
        .map(|ordinal| {
            let id = AlternativeId::from_hash(CampaignHash::derive(
                "gate.campaign-million.alternative",
                format!("{label}:{ordinal}").as_bytes(),
            ));
            DiscreteAlternative::new(id, format!("alternative-{ordinal}"), None)
                .map(|alternative| (id, alternative))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let values = alternatives
        .keys()
        .copied()
        .map(ChoiceValue::Discrete)
        .collect::<BTreeSet<_>>();
    let default = values.iter().next().ok_or("empty finite domain")?.clone();
    let domain = ChoiceDomain::Discrete(DiscreteDomain::new(1, alternatives)?);
    let declaration = SelectableDeclaration::new(
        format!("gate.campaign-million.{label}"),
        ChoiceSource::Workload {
            producer: String::from("campaign-million-gate"),
        },
        domain.clone(),
        default,
        ChoiceClassContext::new(BTreeSet::new())?,
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
            scheduler: CampaignHash::derive("gate.campaign-million.scheduler", label.as_bytes()),
            producer: CampaignHash::derive("gate.campaign-million.producer", label.as_bytes()),
        },
        &label,
        None,
    )?;
    repository.publish_choice_opportunity(&opportunity)?;
    Ok(BranchRequest::new(
        BranchRequest::identity(
            opportunity.branch_point_id(lineage.genesis()),
            lineage.genesis_content(),
            opportunity.id()?,
            domain.id()?,
        ),
        CandidateSource::finite(values)?,
        BranchRequestCause::Operator(command_id("request", request_index)),
        BranchBudget::new(REQUEST_SIZE as u64, REQUEST_SIZE as u64)?,
        StopCondition::NextChoice,
    )?)
}

fn scan_queue(
    repository: &CampaignRepository,
    snapshot: crucible_campaign::CampaignSnapshotId,
) -> Result<(usize, usize), Box<dyn Error>> {
    let mut cursor = None;
    let mut attempts = 0_usize;
    let mut pages = 0_usize;
    let mut queue = AttemptQueue::new(DaemonEpoch::from_bytes([0x94; 16])?, 1)?;

    loop {
        let page = repository.project_claimable_attempts(CAMPAIGN, cursor, PAGE_SIZE)?;
        assert_eq!(page.snapshot(), snapshot);
        assert!(page.scanned_entries() <= PAGE_SIZE);
        assert!(page.attempts().len() <= PAGE_SIZE);
        attempts = attempts
            .checked_add(page.attempts().len())
            .ok_or("attempt count overflow")?;
        pages = pages.checked_add(1).ok_or("page count overflow")?;

        if !page.attempts().is_empty() {
            let reservation = queue
                .reserve_from_page(&page, WorkerSlotId::new(0))?
                .ok_or("nonempty page did not yield a reservation")?;
            assert_eq!(reservation.attempt(), page.attempts()[0]);
            queue.release(reservation)?;
        }
        let next = page.next();
        assert!(
            next.is_none() || next != cursor,
            "queue cursor did not advance"
        );
        cursor = next;
        if cursor.is_none() {
            break;
        }
        assert!(pages <= 1_000_000, "paged queue did not terminate");
    }
    assert_eq!(queue.reservation_count(), 0);
    Ok((attempts, pages))
}

fn storage_tree_bytes(root: &Path) -> Result<(u64, u64), Box<dyn Error>> {
    let mut pending = vec![root.to_path_buf()];
    let mut allocated = 0_u64;
    let mut conservative = 0_u64;
    while let Some(path) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path)?;
        assert!(
            !metadata.file_type().is_symlink(),
            "performance storage contains a symlink"
        );
        let allocated_entry = metadata
            .blocks()
            .checked_mul(512)
            .ok_or("block byte overflow")?;
        allocated = allocated
            .checked_add(allocated_entry)
            .ok_or("allocated byte count overflow")?;
        // CoW filesystems can report transiently sparse block counts for the
        // database or WAL. File length is the conservative budget witness.
        conservative = conservative
            .checked_add(allocated_entry.max(metadata.len()))
            .ok_or("physical byte count overflow")?;
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        }
    }
    Ok((allocated, conservative))
}

fn peak_rss_kib() -> Result<u64, Box<dyn Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .ok_or("missing Linux peak RSS")?;
    let mut fields = line.split_whitespace();
    let value: u64 = fields.next().ok_or("empty Linux peak RSS")?.parse()?;
    if value == 0 || fields.next() != Some("kB") || fields.next().is_some() {
        return Err("invalid Linux peak RSS".into());
    }
    Ok(value)
}

fn command_id(operation: &str, request_index: usize) -> CampaignCommandId {
    CampaignCommandId::from_hash(CampaignHash::derive(
        "gate.campaign-million.command",
        format!("{operation}:{request_index}").as_bytes(),
    ))
}
