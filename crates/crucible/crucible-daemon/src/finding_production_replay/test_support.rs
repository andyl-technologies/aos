//! Shared capture fixtures for finding-replay unit tests.
//!
//! Capture and capture-store tests build their sides through the same
//! validating constructors production uses, over in-memory segment stores.

use super::*;
use crate::MemorySegmentStore;
use crucible_engine::model::{
    FaultCoordinate, FaultReplayMode, FaultResourceLimits, FaultSignalPlan,
    NormalizedSpatialArtifact, ResolvedReplayWorkItem, SignalBoundaryBehavior, SignalDomain,
    SignalId, SignalInterpolation, SignalNode, SignalNodeKind, SignalProgram, SignalResourceLimits,
    SignalShape, SignalSourceSpecification, SignalUnit, SignalValue, SignalValueType,
    SpatialArtifactKind,
};
use crucible_engine::{
    Configuration, EventAttributeValue, EventLevel, EventLogTime, EventPayload, EventSource,
    Icount, NodeTemplate, Plan, Properties, ReadyPoint, ScenarioDefForm, Schedule,
    SchedulerEventLogClass, Seed, WhiteBoxPolicy, World, WorldNode,
};
use crucible_campaign::CampaignHash;
use crucible_store::content_store::BlobHandle;

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
    let artifact = crucible_engine::ReproductionArtifact::capture(&form, &Schedule::empty())
        .expect("model reproduction");
    let replay = artifact.replay().expect("model replay");
    FindingReproductionArtifact {
        artifact,
        replay,
        finding_fingerprint: ContentHash::from_bytes(b"finding"),
        configuration: Configuration::genesis(form.scenario_def()).id(),
        discovery_path: crucible_engine::FindingDiscoveryPath::StateSpaceSearch,
    }
}

pub(crate) fn finding_for_world(world: World) -> FindingReproductionArtifact {
    finding_for_world_and_plan(world, Plan::empty())
}

pub(crate) fn finding() -> FindingReproductionArtifact {
    finding_for_world(World::from_nodes(vec![vm_node()]).expect("world"))
}

/// Builds a finding whose fault plan has one signal program over one stored
/// spatial artifact, so its capture requires a resolved-effect trace.
pub(crate) fn finding_with_signal_artifact()
-> (FindingReproductionArtifact, MemoryDagStore, ContentHash) {
    let world = World::from_nodes(vec![vm_node()]).expect("world");
    let signal = SignalId::parse("portable-signal").expect("signal id");
    let frame = SignalId::parse("portable-frame").expect("frame id");
    let shape =
        SignalShape::new(SignalValueType::I64, SignalUnit::Dimensionless, 0).expect("signal shape");
    let artifact = NormalizedSpatialArtifact::new(
        frame.clone(),
        shape.clone(),
        SpatialArtifactKind::RegularGrid {
            origin_mm: [0; 3],
            cell_size_mm: [1; 3],
            dimensions: [1; 3],
            values: vec![SignalValue::I64(7)],
        },
    )
    .expect("signal artifact");
    let source = SignalNode {
        id: signal.clone(),
        domain: SignalDomain::Spatial,
        output: shape,
        inputs: Vec::new(),
        kind: SignalNodeKind::Source(SignalSourceSpecification::RegularGrid {
            artifact: artifact.content(),
            coordinate_frame: frame,
            origin_mm: [0; 3],
            cell_size_mm: [1; 3],
            dimensions: [1; 3],
            interpolation: SignalInterpolation::Nearest,
            outside: SignalBoundaryBehavior::Error,
        }),
    };
    let program = SignalProgram::new(vec![source], vec![signal], SignalResourceLimits::default())
        .expect("signal program");
    let faults = FaultSignalPlan::new(vec![program], Vec::new(), FaultResourceLimits::default())
        .expect("fault signal plan");
    let plan = Plan::empty()
        .with_fault_signals_for_world(&world, faults)
        .expect("scenario fault plan");
    let store = MemoryDagStore::new();
    let identity = store
        .put(&artifact.encode())
        .expect("store signal artifact");

    (finding_for_world_and_plan(world, plan), store, identity)
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
        crate::crucible_artifact::crucible_reproduction_payload(&finding.artifact)
            .expect("campaign reproduction payload"),
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
        format!("crucible-shmem-abi-v{}", crucible_engine::SHMEM_ABI_VERSION),
        crucible_engine::SHMEM_ABI_VERSION.to_string(),
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
        fingerprint: crucible_engine::ExecutionFingerprint {
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

/// Records `count` scheduler-boundary pass items, sealing a new segment
/// before one would exceed `segment_target_bytes`.
///
/// Production traces seal at 8 MiB; a small target gives a trace of many
/// segments from a few kilobytes of items.
pub(crate) fn segmented_trace(count: u64, segment_target_bytes: usize) -> ResolvedEffectTrace {
    // A scheduler-boundary pass item: no opportunity fields, no records.
    let items = (0..count).map(|index| ResolvedReplayWorkItem {
        coordinate: FaultCoordinate {
            virtual_ticks: index,
            retired_instructions: None,
        },
        same_coordinate_sequence: 0,
        opportunity: None,
        target: None,
        operation: None,
        direction: None,
        phase: None,
        network_frame_key: None,
        network_producer_direction_key: None,
        derivation_fingerprint: ContentHash::from_bytes(&index.to_be_bytes()),
        records: Vec::new(),
    });
    ResolvedEffectTrace::from_items_with_segment_target(
        FaultReplayMode::RecomputedCause,
        items,
        segment_target_bytes,
    )
    .expect("segmented fixture trace")
}

/// Builds a timeout side carrying `trace` through the validating constructor.
pub(crate) fn traced_side(
    trace: ResolvedEffectTrace,
) -> Result<FindingProductionReplayExecutionSide, FindingProductionReplayCaptureError> {
    let frontier = VirtualTime { ticks: 7 };
    let mut store = MemorySegmentStore::default();
    let manifest = store
        .sealed_log(vec![side_event(0, "quantum-budget")])
        .expect("seal fixture log");
    FindingProductionReplayExecutionSide::from_parts(
        FindingProductionReplayTerminalOutcome::Timeout,
        1,
        frontier,
        FindingProductionReplayEventLog::new(manifest, store.into()),
        vec![terminal_fingerprint(frontier)],
        Some(trace),
    )
}

/// Builds one complete timeout capture of a signal-plan finding whose side
/// carries `trace`.
pub(crate) fn traced_capture(
    trace: ResolvedEffectTrace,
) -> (
    FindingProductionReplayCapture,
    FindingProductionReplayCaptureLimits,
) {
    let (finding, store, _) = finding_with_signal_artifact();
    let (reproduction, signature) = campaign_binding(&finding, FindingKind::Timeout);
    let limits = FindingProductionReplayCaptureLimits::for_finding(&finding);
    let FindingProductionReplayCaptureOutcome::Complete(lifecycle_objects) =
        capture_finding_replay_lifecycle_objects(&finding, Some(&store), None)
            .expect("capture signal objects")
    else {
        panic!("complete signal store was reported incomplete");
    };
    let capture = FindingProductionReplayCapture::new(
        &finding,
        reproduction,
        signature,
        &GuardedCampaignReplayClosure::empty(),
        FindingProductionReplayCaptureInput::new(
            FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
            deployment(),
            vec![traced_side(trace).expect("traced side")],
            lifecycle_objects,
            limits,
        ),
    )
    .expect("traced capture");
    (capture, limits)
}
