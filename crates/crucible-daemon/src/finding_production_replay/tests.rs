//! Capture validation and bounded producer regression tests.

use super::*;
use crucible::model::{
    FaultResourceLimits, FaultSignalPlan, NormalizedSpatialArtifact, SignalBoundaryBehavior,
    SignalDomain, SignalId, SignalInterpolation, SignalNode, SignalNodeKind, SignalProgram,
    SignalResourceLimits, SignalShape, SignalSourceSpecification, SignalUnit, SignalValue,
    SignalValueType, SpatialArtifactKind,
};
use crucible::{
    Configuration, ContentAddressedBlobRef, EventAttributeValue, EventLevel, EventLogTime,
    EventPayload, EventSource, Icount, NodeTemplate, Plan, Properties, ReadyPoint, ScenarioDefForm,
    Schedule, SchedulerEventLogClass, Seed, WhiteBoxPolicy, World, WorldBlockLatency,
    WorldIoCoreConfig, WorldIoNode, WorldNode, WorldNodeDef,
};
use crucible_campaign::{CampaignHash, FindingKind, FindingSignature};

fn vm_node() -> WorldNode {
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
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn finding_for_world_and_plan(world: World, plan: Plan) -> FindingReproductionArtifact {
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

fn finding_for_world(world: World) -> FindingReproductionArtifact {
    finding_for_world_and_plan(world, Plan::empty())
}

fn finding() -> FindingReproductionArtifact {
    finding_for_world(World::from_nodes(vec![vm_node()]).expect("world"))
}

fn finding_with_signal_artifact() -> (FindingReproductionArtifact, MemoryDagStore, ContentHash) {
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

fn campaign_binding(
    finding: &FindingReproductionArtifact,
    kind: FindingKind,
) -> (ReproductionArtifactId, FindingSignature) {
    let scenario = crate::encode_crucible_scenario_artifact(finding.artifact.scenario_form())
        .expect("campaign scenario");
    let configuration =
        crate::encode_crucible_configuration_artifact(&scenario, finding.artifact.schedule())
            .expect("campaign configuration");
    let reproduction = crucible_campaign::ReproductionArtifact::new(
        scenario.scenario(),
        scenario.id().expect("scenario id"),
        configuration.configuration(),
        configuration.id().expect("configuration id"),
        CampaignHash::from_bytes(finding.finding_fingerprint.bytes),
        crate::CRUCIBLE_REPRODUCTION_PAYLOAD_SCHEMA_V3,
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

fn deployment() -> FindingProductionReplayDeployment {
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

fn side_event(sequence: u64, kind: &str) -> SchedulerEventLogEntry {
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

fn side(kind: &str) -> FindingProductionReplayExecutionSide {
    FindingProductionReplayExecutionSide {
        outcome: FindingProductionReplayTerminalOutcome::Failed,
        completed_quanta: 1,
        frontier: VirtualTime { ticks: 7 },
        event_log: vec![side_event(0, kind)],
        terminal_fingerprints: vec![FingerprintSample {
            node: NodeId {
                name: String::from("node-0"),
            },
            at: VirtualTime { ticks: 7 },
            fingerprint: crucible::ExecutionFingerprint {
                hash: ContentHash::from_bytes(b"terminal"),
            },
        }],
        resolved_effect_trace: None,
    }
}

#[test]
fn continuation_event_suffix_requires_its_complete_prefix() {
    let prefix = side_event(0, "prefix");
    let suffix = side_event(1, "suffix");

    assert!(event_log_prefix_is_missing(
        &[],
        std::slice::from_ref(&suffix)
    ));
    assert!(!event_log_prefix_is_missing(
        std::slice::from_ref(&prefix),
        std::slice::from_ref(&suffix)
    ));
    assert!(!event_log_prefix_is_missing(&[], &[]));
    assert!(
        validate_event_log_parts(
            std::slice::from_ref(&prefix),
            &[suffix],
            VirtualTime { ticks: 7 }
        )
        .is_ok()
    );

    let overlap = side_event(0, "prefix");
    assert!(matches!(
        validate_event_log_parts(&[prefix], &[overlap], VirtualTime { ticks: 7 }),
        Err(FindingProductionReplayCaptureError::InvalidEventLog)
    ));
}

#[test]
fn decoder_rejects_hostile_declared_container_length_before_deserialization() {
    let finding = finding();
    let mut limits = FindingProductionReplayCaptureLimits::for_finding(&finding);
    limits.max_encoded_bytes = 64;
    let hostile = [0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

    assert!(matches!(
        FindingProductionReplayCapture::from_canonical_bytes(&hostile, limits),
        Err(FindingProductionReplayCaptureError::DecodeBounds)
    ));
}

fn timeout_side() -> FindingProductionReplayExecutionSide {
    let mut side = side("quantum-budget");
    side.outcome = FindingProductionReplayTerminalOutcome::Timeout;
    side
}

#[test]
fn canonical_capture_round_trips_and_selects_expected_divergence_side() {
    let finding = finding();
    let (reproduction, signature) = campaign_binding(&finding, FindingKind::Divergence);
    let closure = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(
        finding.artifact.schedule(),
    )
    .expect("empty choice closure");
    let limits = FindingProductionReplayCaptureLimits::for_finding(&finding);
    let material = FindingProductionReplayCaptureMaterial::new(
        &finding,
        FindingKind::Divergence,
        FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
        deployment(),
        vec![side("expected"), side("reproduced")],
        &closure,
        BTreeMap::new(),
        limits,
    )
    .expect("capture material");
    let cloned_material = material.clone();
    assert!(Arc::ptr_eq(
        material.shared_context(),
        cloned_material.shared_context()
    ));
    assert!(Arc::ptr_eq(
        &material.model_reproduction,
        &cloned_material.model_reproduction
    ));
    assert!(Arc::ptr_eq(&material.sides, &cloned_material.sides));
    assert!(Arc::ptr_eq(
        &material.campaign_replay_closure,
        &cloned_material.campaign_replay_closure
    ));
    let capture = material
        .bind(reproduction, signature.clone(), limits)
        .expect("bind capture");
    let (_, wrong_kind) = campaign_binding(&finding, FindingKind::Timeout);
    assert!(matches!(
        cloned_material.bind(reproduction, wrong_kind, limits),
        Err(FindingProductionReplayCaptureError::CaptureBinding)
    ));
    assert_eq!(
        capture.selected_side(),
        FindingProductionReplaySelectedSide::Expected
    );

    let bytes = capture.to_canonical_bytes(limits).expect("encode");
    let decoded =
        FindingProductionReplayCapture::from_canonical_bytes(&bytes, limits).expect("decode");
    assert_eq!(decoded, capture);
    assert_eq!(
        decoded.content_hash(limits).expect("decoded content hash"),
        capture.content_hash(limits).expect("capture content hash")
    );
    decoded
        .validate_binding(reproduction, &signature)
        .expect("campaign binding");
}

#[test]
fn capture_rejects_missing_or_extraneous_lifecycle_objects() {
    let finding = finding();
    let (reproduction, signature) = campaign_binding(&finding, FindingKind::Timeout);
    let closure = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(
        finding.artifact.schedule(),
    )
    .expect("empty choice closure");
    let mut objects = BTreeMap::new();
    let bytes = b"unreferenced".to_vec();
    objects.insert(ContentHash::from_bytes(&bytes), bytes);
    let error = FindingProductionReplayCapture::new(
        &finding,
        reproduction,
        signature,
        FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
        deployment(),
        vec![timeout_side()],
        &closure,
        objects,
        FindingProductionReplayCaptureLimits::for_finding(&finding),
    )
    .err()
    .unwrap_or_else(|| panic!("extraneous object must fail"));
    assert!(matches!(
        error,
        FindingProductionReplayCaptureError::InvalidLifecycleObjects
    ));
}

#[test]
fn paired_capture_rejects_equal_executions() {
    let finding = finding();
    let (reproduction, signature) = campaign_binding(&finding, FindingKind::Divergence);
    let closure = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(
        finding.artifact.schedule(),
    )
    .expect("empty choice closure");
    let observed = side("same");
    let error = FindingProductionReplayCapture::new(
        &finding,
        reproduction,
        signature,
        FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
        deployment(),
        vec![observed.clone(), observed],
        &closure,
        BTreeMap::new(),
        FindingProductionReplayCaptureLimits::for_finding(&finding),
    )
    .err()
    .unwrap_or_else(|| panic!("equal paired sides must fail"));
    assert!(matches!(
        error,
        FindingProductionReplayCaptureError::PairedSidesDoNotDiverge
    ));
}

#[test]
fn referenced_world_object_must_exist_and_match_its_hash() {
    let base = b"world-block-base".to_vec();
    let identity = ContentHash::from_bytes(&base);
    let io = WorldIoNode::block(
        NodeId {
            name: String::from("disk-0"),
        },
        NodeId {
            name: String::from("node-0"),
        },
        WorldIoCoreConfig::new(0),
        ContentAddressedBlobRef::from_hash(identity),
        u64::try_from(base.len()).expect("base length"),
        WorldBlockLatency::new(1, 1, 1, 1, 0),
    );
    let world = World::from_node_defs_and_links(
        vec![WorldNodeDef::Vm(vm_node()), WorldNodeDef::Io(io)],
        Vec::new(),
    )
    .expect("world with block device");
    let finding = finding_for_world(world);
    let empty = MemoryDagStore::new();
    assert!(matches!(
        capture_finding_replay_lifecycle_objects(&finding, None, Some(&empty)),
        Err(FindingProductionReplayCaptureError::Store(_))
    ));

    let (reproduction, signature) = campaign_binding(&finding, FindingKind::Timeout);
    let closure = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(
        finding.artifact.schedule(),
    )
    .expect("empty choice closure");
    let mut tampered = BTreeMap::new();
    tampered.insert(identity, b"tampered-world-block".to_vec());
    let error = FindingProductionReplayCapture::new(
        &finding,
        reproduction,
        signature,
        FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
        deployment(),
        vec![timeout_side()],
        &closure,
        tampered,
        FindingProductionReplayCaptureLimits::for_finding(&finding),
    )
    .err()
    .unwrap_or_else(|| panic!("hash-tampered referenced object must fail"));
    assert!(matches!(
        error,
        FindingProductionReplayCaptureError::InvalidLifecycleObjects
    ));
}

#[test]
fn signal_lifecycle_capture_requires_authenticates_and_bounds_its_store() {
    let (finding, store, identity) = finding_with_signal_artifact();
    assert!(matches!(
        capture_finding_replay_lifecycle_objects(&finding, None, None),
        Ok(FindingProductionReplayCaptureOutcome::Incomplete(
            FindingProductionReplayIncomplete::MissingSignalArtifactStore
        ))
    ));

    let empty = MemoryDagStore::new();
    assert!(matches!(
        capture_finding_replay_lifecycle_objects(&finding, Some(&empty), None),
        Err(FindingProductionReplayCaptureError::SignalArtifacts(_))
    ));

    let objects = match capture_finding_replay_lifecycle_objects(&finding, Some(&store), None)
        .expect("capture signal objects")
    {
        FindingProductionReplayCaptureOutcome::Complete(objects) => objects,
        FindingProductionReplayCaptureOutcome::Incomplete(reason) => {
            panic!("complete signal store was rejected: {reason}")
        }
    };
    assert_eq!(objects.keys().copied().collect::<Vec<_>>(), vec![identity]);

    let mut tampered = objects.clone();
    tampered
        .get_mut(&identity)
        .expect("referenced signal object")
        .push(0);
    let limits = FindingProductionReplayCaptureLimits::for_finding(&finding);
    assert!(matches!(
        validate_lifecycle_objects(finding.artifact.scenario_form(), &tampered, limits),
        Err(FindingProductionReplayCaptureError::InvalidLifecycleObjects)
    ));

    let mut small_limits = limits;
    small_limits.max_lifecycle_bytes = 1;
    assert!(matches!(
        capture_finding_replay_lifecycle_objects_with_limits(
            &finding,
            Some(&store),
            None,
            small_limits,
        ),
        Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-lifecycle-bytes"
        })
    ));
    assert!(matches!(
        validate_lifecycle_objects(finding.artifact.scenario_form(), &objects, small_limits),
        Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-lifecycle-bytes"
        })
    ));
}

#[test]
fn capture_enforces_small_asset_and_encoded_byte_caps() {
    let finding = finding();
    let (reproduction, signature) = campaign_binding(&finding, FindingKind::Timeout);
    let closure = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(
        finding.artifact.schedule(),
    )
    .expect("empty choice closure");
    let mut asset_limits = FindingProductionReplayCaptureLimits::for_finding(&finding);
    asset_limits.max_guest_asset_bytes = 1;
    assert!(matches!(
        FindingProductionReplayCapture::new(
            &finding,
            reproduction,
            signature.clone(),
            FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
            deployment(),
            vec![timeout_side()],
            &closure,
            BTreeMap::new(),
            asset_limits,
        ),
        Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-guest-asset-bytes"
        })
    ));

    let limits = FindingProductionReplayCaptureLimits::for_finding(&finding);
    let capture = FindingProductionReplayCapture::new(
        &finding,
        reproduction,
        signature,
        FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
        deployment(),
        vec![timeout_side()],
        &closure,
        BTreeMap::new(),
        limits,
    )
    .expect("capture");
    let mut encoded_limits = limits;
    encoded_limits.max_encoded_bytes = 8;
    assert!(matches!(
        capture.to_canonical_bytes(encoded_limits),
        Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-encoded-bytes"
        })
    ));

    let bytes = capture.to_canonical_bytes(limits).expect("encode capture");
    assert!(matches!(
        FindingProductionReplayCapture::from_canonical_bytes(&bytes, encoded_limits),
        Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-encoded-bytes"
        })
    ));
    let mut decoded_asset_limits = limits;
    decoded_asset_limits.max_guest_asset_bytes = 1;
    assert!(matches!(
        FindingProductionReplayCapture::from_canonical_bytes(&bytes, decoded_asset_limits),
        Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-guest-asset-bytes"
        })
    ));
}

#[test]
fn deployment_capture_survives_removal_of_source_paths() {
    let directory = tempfile::tempdir().expect("asset directory");
    let kernel = directory.path().join("kernel");
    let root_image = directory.path().join("root.img");
    let initrd = directory.path().join("initrd");
    let kernel_bytes = b"captured-kernel";
    let root_image_bytes = b"captured-root";
    let initrd_bytes = b"captured-initrd";
    std::fs::write(&kernel, kernel_bytes).expect("write kernel");
    std::fs::write(&root_image, root_image_bytes).expect("write root");
    std::fs::write(&initrd, initrd_bytes).expect("write initrd");
    let mut node = vm_node();
    node.kernel = Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
        kernel_bytes,
    )));
    node.root_image = Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
        root_image_bytes,
    )));
    node.initrd = Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
        initrd_bytes,
    )));
    let finding = finding_for_world(World::from_nodes(vec![node]).expect("world"));
    let config = crucible_api::ProductionVmLifecycleConfig::new(
        "installed-qemu",
        "installed-plugin",
        &kernel,
        &root_image,
        directory.path().join("run"),
    )
    .with_initrd(&initrd)
    .with_kernel_cmdline_prefix("console=ttyS0 replay=portable")
    .with_root_image_format(crucible_api::ProductionRootImageFormat::Raw);
    let selected = config
        .portable_replay_asset_paths(finding.artifact.scenario_form())
        .expect("select exact assets");
    let runtime = deployment().runtime;
    let limits = FindingProductionReplayCaptureLimits::for_finding(&finding);
    let captured = capture_finding_replay_deployment(
        finding.artifact.scenario_form(),
        &selected,
        runtime,
        limits,
    )
    .expect("capture deployment");
    drop(directory);

    assert_eq!(
        captured.guest_assets()[0].kernel().bytes(),
        b"captured-kernel"
    );
    assert_eq!(
        captured.guest_assets()[0].root_image().bytes(),
        b"captured-root"
    );
    assert_eq!(
        captured.initrd().map(FindingProductionReplayAsset::bytes),
        Some(b"captured-initrd".as_slice())
    );
    assert_eq!(
        captured.guest_assets()[0].kernel_cmdline_prefix(),
        Some("console=ttyS0 replay=portable")
    );
    assert_eq!(
        captured.root_image_format(),
        FindingProductionReplayRootImageFormat::Raw
    );
}

#[test]
fn deployment_static_limit_counts_duplicate_content_once() {
    let directory = tempfile::tempdir().expect("asset directory");
    let kernel = directory.path().join("kernel");
    let root_image = directory.path().join("root.img");
    let shared_bytes = b"shared-boot-content";
    std::fs::write(&kernel, shared_bytes).expect("write kernel");
    std::fs::write(&root_image, shared_bytes).expect("write root");

    let identity = ContentHash::from_bytes(shared_bytes);
    let mut node = vm_node();
    node.kernel = Some(ContentAddressedBlobRef::from_hash(identity));
    node.root_image = Some(ContentAddressedBlobRef::from_hash(identity));
    let finding = finding_for_world(World::from_nodes(vec![node]).expect("world"));
    let config = crucible_api::ProductionVmLifecycleConfig::new(
        "installed-qemu",
        "installed-plugin",
        &kernel,
        &root_image,
        directory.path().join("run"),
    );
    let selected = config
        .portable_replay_asset_paths(finding.artifact.scenario_form())
        .expect("select exact assets");
    let captured = deployment::capture_finding_replay_deployment_with_static_limit(
        finding.artifact.scenario_form(),
        &selected,
        deployment().runtime,
        FindingProductionReplayCaptureLimits::for_finding(&finding),
        u64::try_from(shared_bytes.len()).expect("shared length"),
    )
    .expect("capture duplicate assets at exact unique limit");
    let assets = &captured.deployment.guest_assets[0];

    assert_eq!(
        captured.unique_bytes,
        u64::try_from(shared_bytes.len()).expect("shared length")
    );
    assert!(Arc::ptr_eq(&assets.kernel.bytes, &assets.root_image.bytes));
}

#[test]
fn deployment_rejects_streamed_asset_before_bounded_copy() {
    let directory = tempfile::tempdir().expect("asset directory");
    let kernel = directory.path().join("kernel");
    let root_image = directory.path().join("root.img");
    let kernel_bytes = vec![0x5a; 64 * 1024];
    let root_bytes = b"root";
    std::fs::write(&kernel, &kernel_bytes).expect("write oversized kernel");
    std::fs::write(&root_image, root_bytes).expect("write root");

    let mut node = vm_node();
    node.kernel = Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
        &kernel_bytes,
    )));
    node.root_image = Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
        root_bytes,
    )));
    let finding = finding_for_world(World::from_nodes(vec![node]).expect("world"));
    let config = crucible_api::ProductionVmLifecycleConfig::new(
        "installed-qemu",
        "installed-plugin",
        &kernel,
        &root_image,
        directory.path().join("run"),
    );
    let selected = config
        .portable_replay_asset_paths(finding.artifact.scenario_form())
        .expect("select exact assets");

    assert!(matches!(
        deployment::capture_finding_replay_deployment_with_static_limit(
            finding.artifact.scenario_form(),
            &selected,
            deployment().runtime,
            FindingProductionReplayCaptureLimits::for_finding(&finding),
            1,
        ),
        Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-static-bytes"
        })
    ));
}

#[test]
fn static_limit_counts_guest_and_world_roles_by_content_identity() {
    let directory = tempfile::tempdir().expect("asset directory");
    let kernel = directory.path().join("kernel");
    let root_image = directory.path().join("root.img");
    let kernel_bytes = b"kernel-only-content";
    let shared_bytes = b"guest-root-and-world-base";
    std::fs::write(&kernel, kernel_bytes).expect("write kernel");
    std::fs::write(&root_image, shared_bytes).expect("write root");

    let shared_identity = ContentHash::from_bytes(shared_bytes);
    let mut node = vm_node();
    node.kernel = Some(ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(
        kernel_bytes,
    )));
    node.root_image = Some(ContentAddressedBlobRef::from_hash(shared_identity));
    let io = WorldIoNode::block(
        NodeId {
            name: String::from("disk-0"),
        },
        node.id.clone(),
        WorldIoCoreConfig::new(0),
        ContentAddressedBlobRef::from_hash(shared_identity),
        u64::try_from(shared_bytes.len()).expect("base length"),
        WorldBlockLatency::new(1, 1, 1, 1, 0),
    );
    let world = World::from_node_defs_and_links(
        vec![WorldNodeDef::Vm(node), WorldNodeDef::Io(io)],
        Vec::new(),
    )
    .expect("world with shared root and block base");
    let finding = finding_for_world(world);
    let config = crucible_api::ProductionVmLifecycleConfig::new(
        "installed-qemu",
        "installed-plugin",
        &kernel,
        &root_image,
        directory.path().join("run"),
    );
    let selected = config
        .portable_replay_asset_paths(finding.artifact.scenario_form())
        .expect("select exact assets");
    let static_limit =
        u64::try_from(kernel_bytes.len() + shared_bytes.len()).expect("static unique length");
    let limits = FindingProductionReplayCaptureLimits::for_finding(&finding);
    let captured = deployment::capture_finding_replay_deployment_with_static_limit(
        finding.artifact.scenario_form(),
        &selected,
        deployment().runtime,
        limits,
        static_limit,
    )
    .expect("capture guest assets");
    let world_store = MemoryDagStore::new();
    world_store.put(shared_bytes).expect("store world base");
    let lifecycle = capture_finding_replay_lifecycle_objects_with_budget(
        &finding,
        None,
        Some(&world_store),
        limits,
        &captured.unique_identities,
        captured.unique_bytes,
        static_limit,
    )
    .expect("capture shared-role lifecycle object");

    let FindingProductionReplayCaptureOutcome::Complete(objects) = lifecycle else {
        panic!("complete shared-role lifecycle capture was rejected")
    };
    assert_eq!(objects.get(&shared_identity), Some(&shared_bytes.to_vec()));
}

#[test]
fn capture_rejects_progress_beyond_recipe_or_terminal_frontier() {
    let finding = finding();
    let (reproduction, signature) = campaign_binding(&finding, FindingKind::Timeout);
    let closure = GuardedCampaignReplayClosure::empty_for_selection_free_schedule(
        finding.artifact.schedule(),
    )
    .expect("empty choice closure");
    let limits = FindingProductionReplayCaptureLimits::for_finding(&finding);

    let mut over_budget = timeout_side();
    over_budget.completed_quanta = 65;
    assert!(matches!(
        FindingProductionReplayCapture::new(
            &finding,
            reproduction,
            signature.clone(),
            FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
            deployment(),
            vec![over_budget],
            &closure,
            BTreeMap::new(),
            limits,
        ),
        Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-completed-quanta"
        })
    ));

    let mut late_event = timeout_side();
    late_event.frontier = VirtualTime { ticks: 6 };
    late_event.terminal_fingerprints[0].at = VirtualTime { ticks: 6 };
    assert!(matches!(
        FindingProductionReplayCapture::new(
            &finding,
            reproduction,
            signature,
            FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
            deployment(),
            vec![late_event],
            &closure,
            BTreeMap::new(),
            limits,
        ),
        Err(FindingProductionReplayCaptureError::InvalidEventLog)
    ));
}
