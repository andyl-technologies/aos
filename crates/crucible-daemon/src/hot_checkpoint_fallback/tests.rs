// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for exact failures.
#![allow(clippy::expect_used)]

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, MaterializedState,
    SchedulerLivenessScenario, Shift, SimInstant, SingleScheduler, VirtualTime,
};
use crucible_campaign::{
    CampaignExecutorStore, CampaignLineage, CampaignMode, CampaignPolicy, CampaignSeed,
    ConfigurationArtifactId, ExactRational, ExplorerPolicy, FairnessPolicy,
    ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy, ScenarioDefId,
};
use crucible_cas::content_store::{
    BlobHandle, DirectoryBlobBackend, MemoryBlobBackend, MemoryRefBackend,
};
use crucible_qemu::{QemuReplayOracleValidation, QemuVmSnapshot};

use super::*;
use crate::{
    CapturedExactCheckpoint, CrucibleCampaignArtifactStore, HotCheckpointCandidate,
    HotCheckpointHotnessSignals, HotCheckpointLimits, HotCheckpointManager,
    HotCheckpointResourceProfile, QemuHotForkTemplatePoolSlot,
};

#[derive(Clone)]
struct ScriptedThinBases {
    expected: Option<(ContentHash, ContentHash)>,
    calls: Rc<Cell<usize>>,
}

impl sealed::QemuHotCheckpointThinFallbackCatalog for ScriptedThinBases {}

impl QemuHotCheckpointThinFallbackCatalog for ScriptedThinBases {
    fn require_thin_basis(
        &self,
        world: ContentHash,
        scenario: ContentHash,
    ) -> Result<(), QemuVmRealizationError> {
        self.calls.set(self.calls.get() + 1);
        if self.expected == Some((world, scenario)) {
            Ok(())
        } else {
            Err(QemuVmRealizationError::InvalidCheckpoint {
                role: "scripted thin fallback",
                message: String::from("missing exact World/scenario basis"),
            })
        }
    }
}

struct FallbackFixture {
    _checkpoint_directory: tempfile::TempDir,
    campaign: CampaignExecutorStore,
    checkpoints: Arc<ExactCheckpointStore>,
    lineage: crucible_campaign::CampaignLineageId,
    configuration_artifact: ConfigurationArtifactId,
    scenario: crucible::ScenarioDefForm,
    configuration: Configuration,
}

impl FallbackFixture {
    fn new(name: &str) -> Self {
        let repository = Arc::new(crucible_campaign::CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(name, 64 * 1024 * 1024)),
            Arc::new(MemoryRefBackend::new()),
        ));
        let scenario = crucible::happy_path_scenario()
            .expect("built-in scenario")
            .scenario;
        let configuration = Configuration::genesis(scenario.scenario_def());
        let artifacts = CrucibleCampaignArtifactStore::new(Arc::clone(&repository));
        let scenario_artifact = artifacts
            .import_scenario(&scenario)
            .expect("scenario artifact");
        let configuration_artifact = artifacts
            .import_configuration(&scenario, &configuration.schedule)
            .expect("configuration artifact");
        let stored_configuration = repository
            .load_configuration_artifact(configuration_artifact)
            .expect("stored configuration");
        let stored_scenario = repository
            .load_scenario_artifact(scenario_artifact)
            .expect("stored scenario");
        let lineage = CampaignLineage::new(
            ScenarioDefId::from_hash(crucible_campaign::CampaignHash::from_bytes(
                scenario.id().bytes,
            )),
            scenario_artifact,
            stored_configuration.configuration(),
            configuration_artifact,
            "crucible-hot-fallback-test",
            "qemu-hot-fallback-test",
            BTreeMap::from([(String::from("control"), 1)]),
            stored_scenario.payload_schema(),
            stored_configuration.payload_schema(),
        )
        .expect("lineage");
        let lineage_id = lineage.id().expect("lineage id");
        repository
            .create(
                name,
                &lineage,
                &policy(lineage.scenario()),
                &BTreeMap::new(),
            )
            .expect("campaign");

        let checkpoint_directory = tempfile::tempdir().expect("checkpoint directory");
        let checkpoint_backend = Arc::new(DirectoryBlobBackend::new(
            "hot-fallback-checkpoints",
            checkpoint_directory.path(),
        ));
        let checkpoints = Arc::new(
            ExactCheckpointStore::new(checkpoint_backend, 8 * 1024 * 1024)
                .expect("checkpoint store"),
        );

        Self {
            _checkpoint_directory: checkpoint_directory,
            campaign: CampaignExecutorStore::new(repository),
            checkpoints,
            lineage: lineage_id,
            configuration_artifact,
            scenario,
            configuration,
        }
    }

    fn key(&self) -> QemuHotForkTemplateKey {
        QemuHotForkTemplateKey::new(self.lineage, self.configuration.id())
    }

    fn thin_bases(&self, available: bool) -> ScriptedThinBases {
        ScriptedThinBases {
            expected: available.then_some((self.scenario.world().id, self.configuration.def.id())),
            calls: Rc::new(Cell::new(0)),
        }
    }
}

#[test]
fn thin_fallback_authenticates_exact_artifacts_and_native_base() {
    let fixture = FallbackFixture::new("hot-fallback-thin");
    let bases = fixture.thin_bases(true);
    let calls = Rc::clone(&bases.calls);
    let authenticator = QemuHotCheckpointFallbackAuthenticator::new(
        fixture.campaign.clone(),
        Arc::clone(&fixture.checkpoints),
        bases,
    );

    authenticator
        .authenticate_fallback(
            fixture.key(),
            HotCheckpointFallback::Thin(fixture.configuration_artifact),
        )
        .expect("authenticated thin fallback");

    assert_eq!(calls.get(), 1);
}

#[test]
fn thin_fallback_rejects_wrong_configuration_and_missing_native_base() {
    let fixture = FallbackFixture::new("hot-fallback-thin-reject");
    let wrong_key = QemuHotForkTemplateKey::new(
        fixture.lineage,
        ContentHash::from_bytes(b"another configuration"),
    );
    let available = QemuHotCheckpointFallbackAuthenticator::new(
        fixture.campaign.clone(),
        Arc::clone(&fixture.checkpoints),
        fixture.thin_bases(true),
    );
    assert!(matches!(
        available.authenticate_fallback(
            wrong_key,
            HotCheckpointFallback::Thin(fixture.configuration_artifact)
        ),
        Err(QemuHotCheckpointFallbackAuthenticationError::ConfigurationMismatch { .. })
    ));

    let unavailable = QemuHotCheckpointFallbackAuthenticator::new(
        fixture.campaign.clone(),
        Arc::clone(&fixture.checkpoints),
        fixture.thin_bases(false),
    );
    assert!(matches!(
        unavailable.authenticate_fallback(
            fixture.key(),
            HotCheckpointFallback::Thin(fixture.configuration_artifact)
        ),
        Err(QemuHotCheckpointFallbackAuthenticationError::ThinBase(_))
    ));
}

#[test]
fn exact_fallback_requires_matching_scenario_configuration_and_continuation() {
    let fixture = FallbackFixture::new("hot-fallback-exact");
    let (snapshot, scheduler) = resumable_snapshot(&fixture.configuration);
    let prepared = fixture
        .checkpoints
        .prepare_capture(CapturedExactCheckpoint::new_with_scheduler(
            snapshot,
            scheduler,
            BlobHandle::from_bytes(vec![0x5a; 4_096]),
        ))
        .expect("prepare exact fallback");
    fixture
        .checkpoints
        .publish(&prepared)
        .expect("publish exact fallback");
    let authenticator = QemuHotCheckpointFallbackAuthenticator::new(
        fixture.campaign.clone(),
        Arc::clone(&fixture.checkpoints),
        fixture.thin_bases(true),
    );

    authenticator
        .authenticate_fallback(fixture.key(), HotCheckpointFallback::Exact(prepared.root()))
        .expect("authenticated exact fallback");

    let legacy = fixture
        .checkpoints
        .prepare(
            &plain_snapshot(&fixture.configuration),
            BlobHandle::from_bytes(vec![0x2c; 4_096]),
        )
        .expect("prepare legacy root");
    fixture
        .checkpoints
        .publish(&legacy)
        .expect("publish legacy root");
    assert!(matches!(
        authenticator
            .authenticate_fallback(fixture.key(), HotCheckpointFallback::Exact(legacy.root())),
        Err(QemuHotCheckpointFallbackAuthenticationError::MissingCampaignContinuation)
    ));
}

#[derive(Default)]
struct ScriptedAuthenticator {
    calls: Cell<usize>,
    fail_call: Option<usize>,
}

impl HotCheckpointFallbackAuthenticator for ScriptedAuthenticator {
    type Error = ScriptedFailure;

    fn authenticate_fallback(
        &self,
        _key: QemuHotForkTemplateKey,
        _fallback: HotCheckpointFallback,
    ) -> Result<(), Self::Error> {
        self.calls.set(self.calls.get() + 1);
        if self.fail_call == Some(self.calls.get()) {
            Err(ScriptedFailure)
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct ScriptedSourceDemoter {
    calls: usize,
    fail: bool,
}

impl HotCheckpointSourceDemoter<u64> for ScriptedSourceDemoter {
    type Error = ScriptedFailure;

    fn demote_source(
        &mut self,
        factory: u64,
        _plan: HotCheckpointPlannedDemotion,
    ) -> Result<(), HotCheckpointTemplateDemotionFailure<u64, Self::Error>> {
        self.calls += 1;
        if self.fail {
            Err(HotCheckpointTemplateDemotionFailure::new(
                factory,
                ScriptedFailure,
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("scripted fallback failure")]
struct ScriptedFailure;

#[test]
fn authenticated_sink_rechecks_at_release_and_preserves_factory_on_failure() {
    let plan = demotion_plan();
    let mut sink = AuthenticatedHotCheckpointDemotionSink::new(
        ScriptedAuthenticator {
            calls: Cell::new(0),
            fail_call: Some(2),
        },
        ScriptedSourceDemoter::default(),
    );
    sink.validate_fallback(plan.slot().template_key(), plan.fallback())
        .expect("read-only preflight");

    let failure = sink
        .demote(41, plan)
        .expect_err("release-boundary reauthentication fails");
    let (factory, error) = failure.into_parts();

    assert_eq!(factory, 41);
    assert!(matches!(
        error,
        AuthenticatedHotCheckpointDemotionError::Fallback(ScriptedFailure)
    ));
    assert_eq!(sink.authenticator().calls.get(), 2);
    assert_eq!(sink.source_demoter().calls, 0);
}

fn demotion_plan() -> HotCheckpointPlannedDemotion {
    let limits = HotCheckpointLimits::new(1, resources(), 1, 1).expect("limits");
    let mut manager = HotCheckpointManager::new(limits);
    let first = candidate(1, 1);
    let slot = QemuHotForkTemplatePoolSlot::new(first.template_key(), 0);
    manager
        .commit_admission(manager.plan_admission(first).expect("first plan"), slot)
        .expect("first commit");
    manager
        .plan_admission(candidate(2, 2))
        .expect("replacement plan")
        .demotions()[0]
}

fn candidate(byte: u8, score: u64) -> HotCheckpointCandidate {
    HotCheckpointCandidate::new(
        QemuHotForkTemplateKey::new(
            crucible_campaign::CampaignLineageId::parse(&format!(
                "crucible.campaign.lineage@campaign-fact.1.{}",
                encode_hex(&[byte; 32])
            ))
            .expect("lineage"),
            ContentHash::from_bytes(&[byte]),
        ),
        resources(),
        HotCheckpointHotnessSignals::new()
            .with_pending_attempts(score)
            .expect("score"),
        HotCheckpointFallback::Exact(
            crucible_campaign::ExactCheckpointId::parse(&format!(
                "crucible.executor.exact-checkpoint-root@exact-manifest.4.{}",
                encode_hex(&[byte; 32])
            ))
            .expect("checkpoint"),
        ),
    )
}

fn resources() -> HotCheckpointResourceProfile {
    HotCheckpointResourceProfile::new(1, 1, 1, 1, 1, 1).expect("resources")
}

fn policy(scenario: ScenarioDefId) -> CampaignPolicy {
    CampaignPolicy::new(
        scenario,
        CampaignSeed::from_bytes([7; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(
                ProgressiveWideningPolicy::new(
                    ExactRational::new(1, 1).expect("rational"),
                    ExactRational::new(1, 2).expect("rational"),
                    1,
                    100,
                    1,
                )
                .expect("widening"),
            ),
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
    .expect("policy")
}

fn resumable_snapshot(
    configuration: &Configuration,
) -> (QemuVmSnapshot, crucible::SingleSchedulerCheckpoint) {
    let scheduler_scenario = SchedulerLivenessScenario::from_canonical_material(
        "hot-fallback",
        Shift::new(0).expect("zero shift"),
        1,
        SimInstant { nanos: 1 },
        Vec::new(),
        Vec::new(),
    )
    .with_scenario_def(configuration.def.clone());
    let scheduler = SingleScheduler::new(scheduler_scenario).expect("scheduler");
    let scheduler_checkpoint = scheduler.checkpoint().expect("scheduler checkpoint");
    let checkpoint = Checkpoint::from_recorded_configuration(
        configuration,
        None,
        scheduler_checkpoint.frontier(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("checkpoint");
    let materialized = MaterializedState::from_components(
        BTreeMap::new(),
        BTreeMap::new(),
        scheduler_checkpoint
            .scheduler_state()
            .expect("scheduler state"),
        scheduler_checkpoint.future_decision_rng_state().clone(),
        scheduler_checkpoint.event_log_offset(),
    );
    let checkpoint = checkpoint.with_materialized_state(Some(materialized));
    let snapshot =
        QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun).expect("snapshot");
    (snapshot, scheduler_checkpoint)
}

fn plain_snapshot(configuration: &Configuration) -> QemuVmSnapshot {
    let checkpoint = Checkpoint::from_recorded_configuration(
        configuration,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("checkpoint");
    QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun).expect("snapshot")
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
