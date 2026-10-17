//! Shared capture fixtures for finding-replay unit tests.
//!
//! Capture and capture-store tests build their sides through the same
//! validating constructors production uses, over in-memory segment stores.

use super::*;
use crate::MemorySegmentStore;
use crucible::{
    Configuration, EventAttributeValue, EventLevel, EventLogTime, EventPayload, EventSource,
    Icount, NodeTemplate, Plan, Properties, ReadyPoint, ScenarioDefForm, Schedule,
    SchedulerEventLogClass, Seed, WhiteBoxPolicy, World, WorldNode,
};
use crucible_campaign::CampaignHash;
use crucible_cas::content_store::BlobHandle;

pub(crate) fn vm_node() -> WorldNode {
    WorldNode {
        id: NodeId {
            name: String::from("node-0"),
        },
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("finding-production-replay"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

pub(crate) fn finding_for_world_and_plan(world: World, plan: Plan) -> FindingReproductionArtifact {
    let form =
        ScenarioDefForm::from_components(&world, &plan, &Properties::empty(), Seed::from_u64(1))
            .expect("scenario");
    let artifact = crucible::ReproductionArtifact::capture(&form, &Schedule::empty())
        .expect("model reproduction");
    let replay = artifact.replay().expect("model replay");
    FindingReproductionArtifact {
        artifact,
        replay,
        finding_fingerprint: ContentHash::from_bytes(b"finding"),
        configuration: Configuration::genesis(form.scenario_def()).id(),
        discovery_path: crucible::FindingDiscoveryPath::StateSpaceSearch,
    }
}

pub(crate) fn finding_for_world(world: World) -> FindingReproductionArtifact {
    finding_for_world_and_plan(world, Plan::empty())
}

pub(crate) fn finding() -> FindingReproductionArtifact {
    finding_for_world(World::from_nodes(vec![vm_node()]).expect("world"))
}

pub(crate) fn campaign_binding(
    finding: &FindingReproductionArtifact,
    kind: FindingKind,
) -> (ReproductionArtifactId, FindingSignature) {
    let scenario = crate::encode_crucible_scenario_artifact(finding.artifact.scenario_form())
        .expect("campaign scenario");
    let configuration =
        crate::encode_crucible_configuration_artifact(&scenario, finding.artifact.schedule())
            .expect("campaign configuration");
    let reproduction = crucible_campaign::ReproductionArtifact::new(
        crucible_campaign::ReproductionArtifactBasis::new(
            scenario.scenario(),
            scenario.id().expect("scenario id"),
            configuration.configuration(),
            configuration.id().expect("configuration id"),
            CampaignHash::from_bytes(finding.finding_fingerprint.bytes),
        ),
        crate::CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V4,
        finding.artifact.to_compact_binary(),
    )
    .expect("campaign reproduction")
    .id()
    .expect("reproduction id");
    let signature = FindingSignature::new(
        kind,
        CampaignHash::from_bytes(finding.finding_fingerprint.bytes),
        (kind == FindingKind::PropertyViolation).then(|| String::from("property")),
        match kind {
            FindingKind::PropertyViolation => String::from("property.violation"),
            FindingKind::Divergence => String::from("qemu.replay-divergence"),
            FindingKind::Timeout => String::from("execution-budget"),
        },
        None,
        BTreeSet::new(),
    )
    .expect("finding signature");
    (reproduction, signature)
}

pub(crate) fn deployment() -> FindingProductionReplayDeployment {
    let runtime = FindingProductionReplayRuntimeIdentity::new(
        "sha256:qemu-build",
        "sha256:qemu-patches",
        format!("crucible-shmem-abi-v{}", crucible::SHMEM_ABI_VERSION),
        crucible::SHMEM_ABI_VERSION.to_string(),
    )
    .expect("runtime identity");
    FindingProductionReplayDeployment::new(
        runtime,
        FindingProductionReplayRootImageFormat::Raw,
        vec![FindingProductionReplayGuestAssets::new(
            VmArchitecture::X86_64,
            FindingProductionReplayAsset::from_bytes(b"kernel".to_vec()),
            FindingProductionReplayAsset::from_bytes(b"root-image".to_vec()),
            Some(String::from("console=ttyS0")),
        )],
        None,
    )
}

pub(crate) fn side_event(sequence: u64, kind: &str) -> SchedulerEventLogEntry {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        String::from("canonical_selection"),
        EventAttributeValue::String(kind.to_owned()),
    );
    let event = SchedulerEventLogEntry::from_retained_open_event(
        sequence,
        EventLogTime::from_virtual_time(VirtualTime { ticks: 7 }),
        EventSource::Engine,
        EventLevel::Info,
        SchedulerEventLogClass::Causal,
        EventPayload::new("campaign_selection", attributes),
    )
    .expect("fixture event");
    assert!(
        event.has_valid_content_hash(),
        "fixture event must authenticate"
    );
    event
}

pub(crate) fn terminal_fingerprint(at: VirtualTime) -> FingerprintSample {
    FingerprintSample {
        node: NodeId {
            name: String::from("node-0"),
        },
        at,
        fingerprint: crucible::ExecutionFingerprint {
            hash: ContentHash::from_bytes(b"terminal"),
        },
    }
}

/// Builds a side through the validating constructor over a sealed log.
pub(crate) fn side_with(
    outcome: FindingProductionReplayTerminalOutcome,
    completed_quanta: u64,
    frontier: VirtualTime,
    entries: Vec<SchedulerEventLogEntry>,
) -> Result<FindingProductionReplayExecutionSide, FindingProductionReplayCaptureError> {
    let mut store = MemorySegmentStore::default();
    let manifest = store.sealed_log(entries).expect("seal fixture log");
    FindingProductionReplayExecutionSide::from_parts(
        outcome,
        completed_quanta,
        frontier,
        FindingProductionReplayEventLog::new(manifest, store.into()),
        vec![terminal_fingerprint(frontier)],
        None,
    )
}

pub(crate) fn side(kind: &str) -> FindingProductionReplayExecutionSide {
    side_with(
        FindingProductionReplayTerminalOutcome::Failed,
        1,
        VirtualTime { ticks: 7 },
        vec![side_event(0, kind)],
    )
    .expect("fixture side")
}

pub(crate) fn side_entries(
    side: &FindingProductionReplayExecutionSide,
) -> Vec<SchedulerEventLogEntry> {
    side.event_log()
        .entries()
        .collect::<Result<_, _>>()
        .expect("side log reads back")
}

pub(crate) fn leaf_handles(
    objects: &FindingProductionReplayCaptureObjects,
) -> BTreeMap<ContentId, BlobHandle> {
    objects
        .leaves()
        .iter()
        .map(|(id, leaf)| (*id, leaf.source().clone()))
        .collect()
}

/// Publishes a capture to an in-memory leaf map and decodes it back.
pub(crate) fn round_trip(
    capture: &FindingProductionReplayCapture,
    limits: FindingProductionReplayCaptureLimits,
) -> Result<FindingProductionReplayCapture, FindingProductionReplayCaptureError> {
    let objects = capture.prepare_objects()?;
    FindingProductionReplayCapture::from_objects(
        objects.root(),
        objects.manifest_bytes(),
        &leaf_handles(&objects),
        limits,
    )
}

pub(crate) fn timeout_side() -> FindingProductionReplayExecutionSide {
    let mut side = side("quantum-budget");
    side.outcome = FindingProductionReplayTerminalOutcome::Timeout;
    side
}

/// Builds one complete timeout capture whose side log holds `kinds`.
pub(crate) fn timeout_capture(
    kinds: &[&str],
) -> (
    FindingProductionReplayCapture,
    FindingProductionReplayCaptureLimits,
) {
    let finding = finding();
    let (reproduction, signature) = campaign_binding(&finding, FindingKind::Timeout);
    let closure = GuardedCampaignReplayClosure::empty();
    let limits = FindingProductionReplayCaptureLimits::for_finding(&finding);
    let entries = kinds
        .iter()
        .zip(0_u64..)
        .map(|(kind, sequence)| side_event(sequence, kind))
        .collect();
    let side = side_with(
        FindingProductionReplayTerminalOutcome::Timeout,
        1,
        VirtualTime { ticks: 7 },
        entries,
    )
    .expect("timeout side");
    let capture = FindingProductionReplayCapture::new(
        &finding,
        reproduction,
        signature,
        &closure,
        FindingProductionReplayCaptureInput::new(
            FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
            deployment(),
            vec![side],
            BTreeMap::new(),
            limits,
        ),
    )
    .expect("timeout capture");
    (capture, limits)
}
