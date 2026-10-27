//! Batched membership folding for packaged operational status.

use std::error::Error;

use crucible_campaign::{
    BudgetGrant, CampaignCommandId, CampaignControlAction, CampaignLineage, CampaignMode,
    CampaignPolicy, CampaignSeed, ConfigurationId, ControlRequest, ExactCheckpointId,
    ExplorerPolicy, FairnessPolicy, RetentionPolicy, ScenarioDefId,
};
use crucible_store::content_store::{ContentId, MemoryBlobBackend, MemoryRefBackend, ObjectKind};

use super::*;
use crate::{AttemptExecutionKey, AttemptExecutionOrigin};

type TestResult = Result<(), Box<dyn Error>>;

const CAMPAIGN: &str = "packaged-status-batches";

/// One funded campaign with one admitted discovery attempt.
struct AdmittedCampaign {
    repository: Arc<CampaignRepository>,
    snapshot: CampaignSnapshotId,
    member: AttemptExecutionKey,
    foreign_lineage: crucible_campaign::CampaignLineageId,
}

fn admitted_campaign() -> Result<AdmittedCampaign, Box<dyn Error>> {
    let repository = Arc::new(CampaignRepository::new(
        Arc::new(MemoryBlobBackend::new("packaged-status", 1024 * 1024)),
        Arc::new(MemoryRefBackend::new()),
    ));
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive(CAMPAIGN, b"scenario"));
    let genesis = ConfigurationId::from_hash(CampaignHash::derive(CAMPAIGN, b"genesis"));
    let scenario_content =
        repository.publish_scenario_artifact(scenario, 1, b"scenario".to_vec())?;
    let genesis_content = repository.publish_configuration_artifact(
        scenario,
        scenario_content,
        genesis,
        1,
        b"genesis".to_vec(),
    )?;
    let lineage_named = |qemu_build: &str| {
        CampaignLineage::new(
            scenario,
            scenario_content,
            genesis,
            genesis_content,
            "crucible-status-test",
            qemu_build,
            BTreeMap::from([(String::from("control"), 1)]),
            1,
            1,
        )
    };
    let lineage = lineage_named("qemu-status-test")?;
    let foreign_lineage = lineage_named("qemu-other-build")?.id()?;
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            scenario,
            CampaignSeed::from_bytes([0x53; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::Exhaustive {
                maximum_cardinality: 1,
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
    repository.apply_control(
        CAMPAIGN,
        &ControlRequest {
            command: CampaignCommandId::from_hash(CampaignHash::derive(CAMPAIGN, b"fund")),
            expected_snapshot: created.snapshot_id(),
            action: CampaignControlAction::GrantBudget(BudgetGrant::new(0, 1)?),
        },
    )?;
    let funded = repository.head(CAMPAIGN)?;
    repository.apply_control(
        CAMPAIGN,
        &ControlRequest {
            command: CampaignCommandId::from_hash(CampaignHash::derive(CAMPAIGN, b"resume")),
            expected_snapshot: funded.snapshot_id(),
            action: CampaignControlAction::Resume,
        },
    )?;
    let attempt = repository
        .admit_initial_discovery_if_ready(CAMPAIGN)?
        .ok_or("funded campaign did not admit discovery")?;
    let snapshot = repository.head(CAMPAIGN)?.snapshot_id();

    Ok(AdmittedCampaign {
        repository,
        snapshot,
        member: AttemptExecutionKey::new(lineage.id()?, attempt),
        foreign_lineage,
    })
}

fn checkpoint(index: u32) -> Result<ExactCheckpointId, Box<dyn Error>> {
    Ok(ExactCheckpointId::try_from(ContentId::for_bytes(
        ObjectKind::ExactManifest,
        5,
        &index.to_be_bytes(),
    ))?)
}

fn paused(index: u32) -> Result<AttemptRuntimeState, Box<dyn Error>> {
    Ok(AttemptRuntimeState::Paused {
        execution_basis: CampaignHash::derive(CAMPAIGN, &index.to_be_bytes()),
        origin: AttemptExecutionOrigin::Initial,
        daemon_epoch: DaemonEpoch::from_bytes([0x41; 16])?,
        execution: ExecutionId::from_bytes([0x42; 16])?,
        checkpoint: checkpoint(index)?,
        promotion_basis: None,
    })
}

fn projection<'a>(
    campaign: &'a AdmittedCampaign,
    snapshot: CampaignSnapshotId,
    activities: &'a BTreeMap<ExecutionId, LocalExecutionActivity>,
    lifecycles: &'a BTreeMap<ExecutionId, PackagedWorldLifecyclePhase>,
) -> Result<StatusProjection<'a>, Box<dyn Error>> {
    Ok(StatusProjection {
        repository: &campaign.repository,
        snapshot,
        daemon_epoch: DaemonEpoch::from_bytes([0x41; 16])?,
        activities,
        lifecycles,
        batch: Vec::new(),
        worlds: [0; 6],
        retained: BTreeSet::new(),
        materialized: BTreeSet::new(),
        failed: false,
    })
}

#[test]
fn projection_folds_records_beyond_one_batch_and_the_former_inventory_cap() -> TestResult {
    let campaign = admitted_campaign()?;
    let (activities, lifecycles) = (BTreeMap::new(), BTreeMap::new());
    let mut projection = projection(&campaign, campaign.snapshot, &activities, &lifecycles)?;
    const FOREIGN_RECORDS: u32 = 65_537;

    // The one member sits deep in the inventory, past many full batches.
    for index in 0..FOREIGN_RECORDS {
        let foreign = AttemptExecutionKey::new(campaign.foreign_lineage, campaign.member.attempt());
        projection.push(foreign, paused(index)?);
        assert!(projection.batch.len() < STATUS_MEMBERSHIP_BATCH_RECORDS);
        if index == 40_000 {
            projection.push(campaign.member, paused(FOREIGN_RECORDS)?);
        }
    }
    projection.flush();

    let member_root = BTreeSet::from([checkpoint(FOREIGN_RECORDS)?]);
    assert!(!projection.failed);
    assert!(projection.batch.is_empty());
    assert_eq!(projection.worlds, [0, 0, 0, 0, 0, 1]);
    assert_eq!(projection.retained, member_root);
    assert_eq!(projection.materialized, member_root);
    Ok(())
}

#[test]
fn membership_failure_poisons_the_projection() -> TestResult {
    let campaign = admitted_campaign()?;
    let missing = CampaignSnapshotId::parse(&format!(
        "crucible.campaign.snapshot@{}",
        ContentId::for_bytes(ObjectKind::CampaignSnapshot, 3, b"missing-snapshot").encode()
    ))?;
    let (activities, lifecycles) = (BTreeMap::new(), BTreeMap::new());
    let mut projection = projection(&campaign, missing, &activities, &lifecycles)?;

    projection.push(campaign.member, paused(1)?);
    projection.flush();
    projection.push(campaign.member, paused(2)?);
    projection.flush();

    assert!(projection.failed);
    assert!(projection.batch.is_empty());
    assert_eq!(projection.worlds, [0; 6]);
    assert!(projection.retained.is_empty());
    Ok(())
}
