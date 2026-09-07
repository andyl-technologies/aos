//! Canonical single-host runtime attachment regressions.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for failure localization.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::thread;
use std::time::Duration;

use crucible_campaign::{
    CampaignHash, CampaignLineage, CampaignMode, CampaignPolicy, CampaignSeed, ConfigurationId,
    DaemonEpoch, DebuggerAuthorityKey, ExecutorCapabilitySet, ExecutorCompatibilityProfile,
    ExecutorMaterializationCapability, ExplorerPolicy, FairnessPolicy, ProgressiveWideningPolicy,
    PuctPolicy, RetentionPolicy, ScenarioDefId,
};
use crucible_cas::content_store::{MemoryBlobBackend, MemoryRefBackend};

use crate::{
    AllowAllAttemptAdmission, ExecutorCapacity, LocalExecutorCapabilityService,
    LocalExecutorSupervisor, LoopbackExecutorTimeouts, MemoryAssignmentLedger,
    serve_loopback_executor_component_once,
};

use super::*;

fn fixture() -> (
    Arc<CampaignRepository>,
    Arc<MemoryBlobBackend>,
    PlannerAuthorityKey,
    CampaignLineage,
) {
    let planner = PlannerAuthorityKey::from_bytes([0x31; 32]).expect("planner authority");
    let debugger = DebuggerAuthorityKey::from_bytes([0x73; 32]).expect("debugger authority");
    let blobs = Arc::new(MemoryBlobBackend::new(
        "campaign-attachment",
        64 * 1024 * 1024,
    ));
    let repository = Arc::new(
        CampaignRepository::with_component_authorities(
            blobs.clone(),
            Arc::new(MemoryRefBackend::new()),
            planner.clone(),
            debugger,
        )
        .expect("repository authorities"),
    );
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("test", b"scenario"));
    let genesis = ConfigurationId::from_hash(CampaignHash::derive("test", b"genesis"));
    let scenario_content = repository
        .publish_scenario_artifact(scenario, 1, b"scenario".to_vec())
        .expect("scenario artifact");
    let genesis_content = repository
        .publish_configuration_artifact(scenario, scenario_content, genesis, 1, b"genesis".to_vec())
        .expect("genesis artifact");
    let lineage = CampaignLineage::new(
        scenario,
        scenario_content,
        genesis,
        genesis_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("lineage");
    let widening = ProgressiveWideningPolicy::new(
        crucible_campaign::ExactRational::new(1, 1).expect("widening coefficient"),
        crucible_campaign::ExactRational::new(1, 2).expect("widening exponent"),
        1,
        100,
        1,
    )
    .expect("widening policy");
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
    repository
        .create("attached", &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    (repository, blobs, planner, lineage)
}

fn description(
    lineage: &CampaignLineage,
    epoch: DaemonEpoch,
) -> crucible_campaign::ExecutorDescription {
    let resources =
        AttemptResourceLimits::new(4, 1024 * 1024, 1024 * 1024, 10_000).expect("resource ceiling");
    let capabilities = ExecutorCapabilitySet::new(
        ExecutorCompatibilityProfile::from_lineage(lineage),
        "x86_64",
        BTreeSet::from([String::from("deterministic-tcg")]),
        BTreeSet::from([ExecutorMaterializationCapability::ThinReplay]),
        2,
        resources,
        BTreeSet::from([CampaignHash::derive("test", b"store")]),
    )
    .expect("executor capabilities");
    crucible_campaign::ExecutorDescription::new(epoch, capabilities).expect("executor description")
}

fn executor_pair(lineage: &CampaignLineage) -> (UnixStream, thread::JoinHandle<()>) {
    let epoch = DaemonEpoch::from_bytes([0x41; 16]).expect("daemon epoch");
    let supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(2, 4, 1024 * 1024, 1024 * 1024, 10_000).expect("executor capacity"),
    );
    let mut service = LocalExecutorCapabilityService::new(supervisor, description(lineage, epoch))
        .expect("capability service");
    let (client, mut server) = UnixStream::pair().expect("executor stream pair");
    let worker = thread::spawn(move || {
        serve_loopback_executor_component_once(
            &mut server,
            &mut service,
            LoopbackExecutorTimeouts::default(),
        )
        .expect("serve executor description");
    });
    (client, worker)
}

#[test]
fn attachment_negotiates_before_publishing_and_runs_one_inactive_campaign() {
    let (repository, blobs, planner, lineage) = fixture();
    let before = blobs.object_count().expect("objects before attachment");
    let (executor, server) = executor_pair(&lineage);
    let planner_process = CanonicalPlannerProcessConfig::new(
        "/nonexistent-until-planning-is-required",
        Duration::from_secs(1),
    )
    .expect("planner process config");
    let config = CanonicalCampaignRuntimeConfig::canonical_defaults(
        CampaignName::new("attached").expect("campaign name"),
        planner_process,
    )
    .expect("runtime config");

    let prepared =
        prepare_canonical_campaign_runtime(Arc::clone(&repository), planner, executor, &config)
            .expect("prepare attached runtime");
    server.join().expect("join executor description server");
    assert_eq!(
        blobs.object_count().expect("objects after attachment"),
        before + 4
    );

    let runtime = prepared.start().expect("start attached runtime");
    let report = runtime.shutdown_and_join().expect("join attached runtime");
    assert!(report.steps() <= 1);
}

#[test]
fn incompatible_executor_rejects_before_planner_basis_publication() {
    let (repository, blobs, planner, lineage) = fixture();
    let before = blobs.object_count().expect("objects before rejection");
    let mut incompatible = lineage.clone();
    incompatible = CampaignLineage::new(
        incompatible.scenario(),
        incompatible.scenario_content(),
        incompatible.genesis(),
        incompatible.genesis_content(),
        incompatible.crucible_version(),
        "different-qemu",
        incompatible.protocol_versions().clone(),
        incompatible.scenario_schema(),
        incompatible.exact_closure_schema(),
    )
    .expect("incompatible lineage profile");
    let (executor, server) = executor_pair(&incompatible);
    let config = CanonicalCampaignRuntimeConfig::canonical_defaults(
        CampaignName::new("attached").expect("campaign name"),
        CanonicalPlannerProcessConfig::new("/planner", Duration::from_secs(1))
            .expect("planner process config"),
    )
    .expect("runtime config");

    assert!(matches!(
        prepare_canonical_campaign_runtime(repository, planner, executor, &config),
        Err(CanonicalCampaignRuntimeError::ExecutorIncompatible)
    ));
    server.join().expect("join executor description server");
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        before
    );
}

#[test]
fn dropping_an_attached_runtime_joins_before_releasing_ownership() {
    let (repository, _blobs, planner, lineage) = fixture();
    let (executor, server) = executor_pair(&lineage);
    let config = CanonicalCampaignRuntimeConfig::canonical_defaults(
        CampaignName::new("attached").expect("campaign name"),
        CanonicalPlannerProcessConfig::new("/planner", Duration::from_secs(1))
            .expect("planner process config"),
    )
    .expect("runtime config");
    let runtime = prepare_canonical_campaign_runtime(repository, planner, executor, &config)
        .expect("prepare attached runtime")
        .start()
        .expect("start attached runtime");
    server.join().expect("join executor description server");
    let completion = runtime.completion_handle();

    drop(runtime);

    assert!(completion.is_finished());
}
