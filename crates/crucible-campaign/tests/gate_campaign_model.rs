//! Verifies the canonical campaign model through its public repository surface.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::sync::Arc;

use crucible_campaign::{
    ActiveAttemptPolicy, CampaignCommandId, CampaignControlAction, CampaignHash, CampaignLineage,
    CampaignMode, CampaignPolicy, CampaignRepository, CampaignRepositoryError, CampaignSeed,
    CampaignState, ConfigurationId, ControlRequest, ExactRational, ExplorerPolicy, FairnessPolicy,
    ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy, ScenarioDefId,
};
use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

#[test]
fn campaign_model_public_repository_flight_is_exact() -> Result<(), Box<dyn Error>> {
    let blobs = Arc::new(MemoryBlobBackend::new(
        "campaign-model-gate",
        64 * 1024 * 1024,
    ));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs.clone(), refs.clone());

    let scenario =
        ScenarioDefId::from_hash(CampaignHash::derive("gate.campaign-model", b"scenario"));
    let genesis =
        ConfigurationId::from_hash(CampaignHash::derive("gate.campaign-model", b"genesis"));
    let scenario_content =
        repository.publish_scenario_artifact(scenario, 1, b"canonical scenario".to_vec())?;
    let genesis_content = repository.publish_configuration_artifact(
        scenario,
        scenario_content,
        genesis,
        1,
        b"canonical genesis".to_vec(),
    )?;
    let protocol_versions = BTreeMap::from([
        (String::from("control"), 1),
        (String::from("shared-memory"), 2),
    ]);
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-gate",
        "qemu-gate",
        protocol_versions.clone(),
        1,
        1,
    )?;
    let reverse_lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-gate",
        "qemu-gate",
        protocol_versions.into_iter().rev().collect(),
        1,
        1,
    )?;
    assert_eq!(lineage.id()?, reverse_lineage.id()?);

    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1)?,
        ExactRational::new(1, 2)?,
        1,
        64,
        1,
    )?;
    let policy = CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([7; 32]),
        CampaignMode::Strict,
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

    let created = repository.create("source", &lineage, &policy, &BTreeMap::new())?;
    assert_eq!(repository.state("source")?, CampaignState::Created);

    let resume = ControlRequest {
        command: command_id("resume"),
        expected_snapshot: created.snapshot_id(),
        action: CampaignControlAction::Resume,
    };
    let resumed = repository.apply_control("source", &resume)?;
    assert_eq!(repository.state("source")?, CampaignState::Running);

    let stale = ControlRequest {
        command: command_id("stale-pause"),
        expected_snapshot: created.snapshot_id(),
        action: CampaignControlAction::Pause(ActiveAttemptPolicy::Drain),
    };
    assert!(matches!(
        repository.apply_control("source", &stale),
        Err(CampaignRepositoryError::Stale { .. })
    ));
    assert_eq!(
        repository.head("source")?.snapshot_id(),
        resumed.new_snapshot
    );

    let derived = repository.derive_campaign("source", resumed.new_snapshot, "derived", None)?;
    assert!(!derived.replayed);
    assert_eq!(derived.source_snapshot, resumed.new_snapshot);

    let restarted = CampaignRepository::new(blobs, refs);
    let rebuilt = restarted.head("derived")?;
    assert_eq!(rebuilt.snapshot_id(), derived.new_snapshot);
    assert_eq!(rebuilt.snapshot().parent(), Some(resumed.new_snapshot));
    assert_eq!(restarted.state("source")?, CampaignState::Running);
    assert_eq!(restarted.state("derived")?, CampaignState::Running);

    Ok(())
}

fn command_id(label: &str) -> CampaignCommandId {
    CampaignCommandId::from_hash(CampaignHash::derive(
        "gate.campaign-model.command",
        label.as_bytes(),
    ))
}
