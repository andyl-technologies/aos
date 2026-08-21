//! Conformance tests for composed local campaign retention discovery.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::sync::Arc;

use crucible_campaign::{
    AssignmentId, CampaignCommandId, CampaignHash, CampaignLineage, CampaignMode, CampaignName,
    CampaignPolicy, CampaignRepository, CampaignSeed, ConfigurationId, ExactRational,
    ExplorerPolicy, FairnessPolicy, ObservationId, PinChange, PinRequest, PinRetention,
    ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy, ScenarioDefId,
};
use crucible_cas::content_store::{ContentId, MemoryBlobBackend, MemoryRefBackend, ObjectKind};

use super::*;
use crate::{
    AssignmentPublish, AssignmentRecord, AttemptExecutionKey, AttemptRuntimeState, AttemptStateCas,
};

struct RootLedger {
    observations: Vec<ObservationId>,
    checkpoints: Vec<ExactCheckpointId>,
}

impl AssignmentLedger for RootLedger {
    type Error = Infallible;

    fn load_assignment(
        &self,
        _assignment: AssignmentId,
    ) -> Result<Option<AssignmentRecord>, Self::Error> {
        unreachable!("retention discovery does not load assignments")
    }

    fn publish_assignment(
        &mut self,
        _record: &AssignmentRecord,
    ) -> Result<AssignmentPublish, Self::Error> {
        unreachable!("retention discovery does not publish assignments")
    }

    fn load_attempt(
        &self,
        _key: AttemptExecutionKey,
    ) -> Result<Option<AttemptRuntimeState>, Self::Error> {
        unreachable!("retention discovery does not load individual attempts")
    }

    fn compare_exchange_attempt(
        &mut self,
        _key: AttemptExecutionKey,
        _expected: Option<AttemptRuntimeState>,
        _next: Option<AttemptRuntimeState>,
    ) -> Result<AttemptStateCas, Self::Error> {
        unreachable!("retention discovery is read-only")
    }

    fn visit_observation_roots(
        &self,
        visitor: &mut dyn FnMut(ObservationId),
    ) -> Result<(), Self::Error> {
        for root in self.observations.iter().copied() {
            visitor(root);
        }
        Ok(())
    }

    fn visit_checkpoint_roots(
        &self,
        visitor: &mut dyn FnMut(ExactCheckpointId),
    ) -> Result<(), Self::Error> {
        for root in self.checkpoints.iter().copied() {
            visitor(root);
        }
        Ok(())
    }
}

#[test]
fn semantic_and_operational_roots_share_one_terminal_inventory() {
    let blobs = Arc::new(MemoryBlobBackend::new(
        "campaign-retention",
        64 * 1024 * 1024,
    ));
    let refs = Arc::new(MemoryRefBackend::new());
    let repository = CampaignRepository::new(blobs, refs);
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive(
        "crucible.test.retention.scenario.v1",
        b"scenario",
    ));
    let configuration = ConfigurationId::from_hash(CampaignHash::derive(
        "crucible.test.retention.configuration.v1",
        b"configuration",
    ));
    let scenario_artifact = repository
        .publish_scenario_artifact(scenario, 1, b"scenario".to_vec())
        .expect("scenario artifact");
    let configuration_artifact = repository
        .publish_configuration_artifact(
            scenario,
            scenario_artifact,
            configuration,
            1,
            b"configuration".to_vec(),
        )
        .expect("configuration artifact");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_artifact,
        configuration,
        configuration_artifact,
        "crucible-v1",
        "qemu-build-v1",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("lineage");
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("rational"),
        ExactRational::new(1, 2).expect("rational"),
        1,
        100,
        1,
    )
    .expect("widening");
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
        FairnessPolicy::new(0, 0).expect("fairness"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("policy");
    let campaign = CampaignName::new("retention-inventory").expect("campaign name");
    let created = repository
        .create(campaign.as_str(), &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    let pin = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.test.retention.pin.v1",
            b"pin",
        )),
        expected_snapshot: created.snapshot_id(),
        change: PinChange::new(
            configuration,
            Some(PinRetention::Thin),
            "retain semantic replay roots",
        )
        .expect("pin change"),
    };
    let pinned = repository
        .apply_pin(campaign.as_str(), &pin)
        .expect("pin campaign");

    let observation_content =
        ContentId::for_bytes(ObjectKind::Observation, 1, b"retained-observation");
    let observation = ObservationId::parse(&format!(
        "crucible.campaign.observation@{observation_content}"
    ))
    .expect("observation root");
    let checkpoint_content =
        ContentId::for_bytes(ObjectKind::ExactManifest, 2, b"retained-checkpoint");
    let checkpoint = ExactCheckpointId::parse(&format!(
        "crucible.executor.exact-checkpoint-root@{checkpoint_content}"
    ))
    .expect("checkpoint root");
    let ledger = RootLedger {
        observations: vec![observation, observation],
        checkpoints: vec![checkpoint],
    };

    let mut roots = Vec::new();
    let summary =
        visit_local_campaign_retention_roots(&repository, &campaign, &ledger, &mut |root| {
            roots.push(root)
        })
        .expect("complete retention inventory");

    assert_eq!(summary.semantic_pins().snapshot(), pinned.new_snapshot);
    assert_eq!(summary.semantic_pins().thin_pins(), 1);
    assert_eq!(summary.observation_roots(), 2);
    assert_eq!(summary.checkpoint_roots(), 1);
    assert!(matches!(
        &roots[0],
        LocalCampaignRetentionRoot::SemanticPin(record)
            if record.configuration_artifact() == configuration_artifact
                && record.scenario_artifact() == scenario_artifact
    ));
    assert_eq!(
        roots[1..],
        [
            LocalCampaignRetentionRoot::Observation(observation),
            LocalCampaignRetentionRoot::Observation(observation),
            LocalCampaignRetentionRoot::ExactCheckpoint(checkpoint),
        ]
    );
}
