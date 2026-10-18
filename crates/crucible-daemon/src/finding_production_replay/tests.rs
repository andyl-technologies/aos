//! Capture validation and bounded producer regression tests.

use super::capture::validate_execution_side;
use super::test_support::*;
use super::*;
use crucible::model::{FaultReplayMode, ResolvedEffectTrace};
use crucible::{
    ContentAddressedBlobRef, Plan, Properties, ScenarioDefForm, ScenarioSelectableLimits,
    ScenarioSelectables, Seed, World, WorldBlockLatency, WorldIoCoreConfig, WorldIoNode,
    WorldNodeDef,
};
use crucible_campaign::FindingKind;
use crucible_cas::content_store::BlobHandle;

#[test]
fn snapshot_capture_requires_a_dense_prefix_before_the_recording() {
    let frontier = VirtualTime { ticks: 7 };
    let prefix = side_event(0, "prefix");
    let suffix = side_event(1, "suffix");
    let snapshot = QemuAttemptExecutionEvidenceSnapshot::for_replay_capture_test(
        1,
        frontier,
        std::slice::from_ref(&suffix),
    )
    .expect("resumed snapshot");
    let failed = FindingProductionReplayTerminalOutcome::Failed;

    let FindingProductionReplayCaptureOutcome::Complete(captured) =
        FindingProductionReplayExecutionSide::from_snapshot(
            failed,
            std::slice::from_ref(&prefix),
            &snapshot,
        )
        .expect("dense prefix and recording")
    else {
        panic!("complete snapshot was reported incomplete");
    };
    assert_eq!(side_entries(&captured), vec![prefix.clone(), suffix]);

    assert!(matches!(
        FindingProductionReplayExecutionSide::from_snapshot(failed, &[], &snapshot),
        Ok(FindingProductionReplayCaptureOutcome::Incomplete(
            FindingProductionReplayIncomplete::MissingEventLogPrefix
        ))
    ));
    let overlap = QemuAttemptExecutionEvidenceSnapshot::for_replay_capture_test(
        1,
        frontier,
        std::slice::from_ref(&side_event(0, "overlap")),
    )
    .expect("fresh snapshot");
    assert!(matches!(
        FindingProductionReplayExecutionSide::from_snapshot(failed, &[prefix], &overlap),
        Err(FindingProductionReplayCaptureError::InvalidEventLog)
    ));
}

#[test]
fn terminal_fingerprint_may_precede_but_not_exceed_shared_frontier() {
    let finding = finding();
    let recipe = FindingProductionReplayRecipe::new(10_000, 64, true).expect("valid recipe");
    let mut paused = side("paused-selectable");
    paused.terminal_fingerprints[0].at = VirtualTime { ticks: 5 };

    validate_execution_side(&paused, finding.artifact.scenario_form(), recipe)
        .expect("a stopped node may be behind the shared frontier");

    paused.terminal_fingerprints[0].at = VirtualTime { ticks: 8 };
    assert!(matches!(
        validate_execution_side(&paused, finding.artifact.scenario_form(), recipe),
        Err(FindingProductionReplayCaptureError::InvalidTerminalFingerprints)
    ));
}

#[test]
fn network_only_finding_accepts_canonical_effect_trace() {
    let world = World::from_nodes(vec![vm_node()]).expect("network-only world");
    let base = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(1),
    )
    .expect("network-only scenario");
    let selectables = ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::default(),
        vec![crucible::NetworkFaultSelectable::declaration().expect("network declaration")],
    )
    .expect("network selectables");
    let scenario = base
        .with_selectables(selectables)
        .expect("selected scenario");
    let trace =
        ResolvedEffectTrace::empty(FaultReplayMode::RecomputedCause).expect("empty network trace");
    let mut execution = side("network-fault");
    execution.resolved_effect_trace = Some(trace);
    let recipe = FindingProductionReplayRecipe::new(10_000, 64, true).expect("valid recipe");

    validate_execution_side(&execution, &scenario, recipe)
        .expect("network-only scenario accepts its canonical trace");
}

#[test]
fn decoder_rejects_hostile_declared_container_length_before_deserialization() {
    let hostile = [0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

    assert!(matches!(
        manifest::decode_manifest_body(&hostile),
        Err(FindingProductionReplayCaptureError::DecodeBounds)
    ));
}

#[test]
fn canonical_capture_round_trips_and_selects_expected_divergence_side() {
    let finding = finding();
    let (reproduction, signature) = campaign_binding(&finding, FindingKind::Divergence);
    let closure = GuardedCampaignReplayClosure::empty();
    let limits = FindingProductionReplayCaptureLimits::for_finding(&finding);
    let material = FindingProductionReplayCaptureMaterial::new(
        &finding,
        FindingKind::Divergence,
        &closure,
        FindingProductionReplayCaptureInput::new(
            FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
            deployment(),
            vec![side("expected"), side("reproduced")],
            BTreeMap::new(),
            limits,
        ),
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
    assert!(
        material
            .campaign_replay_closure
            .shares_storage_with(&cloned_material.campaign_replay_closure)
    );
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

    let objects = capture.prepare_objects().expect("prepare capture objects");
    let leaves = leaf_handles(&objects);
    let decoded = FindingProductionReplayCapture::from_objects(
        objects.root(),
        objects.manifest_bytes(),
        &leaves,
        limits,
    )
    .expect("decode");
    assert_eq!(decoded, capture);
    assert_eq!(
        decoded.prepare_objects().expect("re-prepare").root(),
        objects.root(),
        "a decoded capture derives the same manifest identity"
    );
    let segments = objects
        .leaves()
        .values()
        .filter(|leaf| leaf.role() == FindingProductionReplayLeafRole::EventLogSegment)
        .count();
    assert_eq!(segments, 2, "each side log is referenced by its segments");

    let envelope =
        decode_finding_production_replay_manifest(objects.root(), objects.manifest_bytes())
            .expect("manifest envelope");
    let old_schema = crucible_cas::content_envelope::ContentEnvelope::new(
        FINDING_PRODUCTION_REPLAY_CAPTURE_SCHEMA,
        5,
        envelope.children().clone(),
        envelope.body().to_vec(),
    )
    .expect("version 5 envelope");
    let old_root = crucible_campaign::FindingReplayCaptureEvidenceId::from_manifest_content_id(
        old_schema.content_id(crucible_cas::content_store::ObjectKind::ExactManifest),
    );
    assert!(
        old_root.is_err(),
        "a version 5 identity is not a capture root"
    );
    assert!(matches!(
        FindingProductionReplayCapture::from_objects(
            objects.root(),
            &old_schema.canonical_bytes(),
            &leaves,
            limits,
        ),
        Err(FindingProductionReplayCaptureError::UnsupportedSchema { actual: 5 })
    ));

    let mut missing = leaves.clone();
    let segment = objects
        .leaves()
        .iter()
        .find(|(_, leaf)| leaf.role() == FindingProductionReplayLeafRole::EventLogSegment)
        .map(|(id, _)| *id)
        .expect("segment leaf");
    missing.remove(&segment);
    assert!(matches!(
        FindingProductionReplayCapture::from_objects(
            objects.root(),
            objects.manifest_bytes(),
            &missing,
            limits,
        ),
        Err(FindingProductionReplayCaptureError::MissingLeaf { id }) if id == segment
    ));

    let mut substituted = leaves;
    substituted.insert(segment, BlobHandle::from_bytes(vec![0; 1]));
    assert!(matches!(
        FindingProductionReplayCapture::from_objects(
            objects.root(),
            objects.manifest_bytes(),
            &substituted,
            limits,
        ),
        Err(FindingProductionReplayCaptureError::InvalidManifest {
            reason: "leaf length"
        })
    ));
}

#[test]
fn capture_rejects_missing_or_extraneous_lifecycle_objects() {
    let finding = finding();
    let (reproduction, signature) = campaign_binding(&finding, FindingKind::Timeout);
    let closure = GuardedCampaignReplayClosure::empty();
    let mut objects = BTreeMap::new();
    let bytes = b"unreferenced".to_vec();
    objects.insert(ContentHash::from_bytes(&bytes), bytes);
    let error = FindingProductionReplayCapture::new(
        &finding,
        reproduction,
        signature,
        &closure,
        FindingProductionReplayCaptureInput::new(
            FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
            deployment(),
            vec![timeout_side()],
            objects,
            FindingProductionReplayCaptureLimits::for_finding(&finding),
        ),
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
    let closure = GuardedCampaignReplayClosure::empty();
    let observed = side("same");
    let error = FindingProductionReplayCapture::new(
        &finding,
        reproduction,
        signature,
        &closure,
        FindingProductionReplayCaptureInput::new(
            FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
            deployment(),
            vec![observed.clone(), observed],
            BTreeMap::new(),
            FindingProductionReplayCaptureLimits::for_finding(&finding),
        ),
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
        WorldIoCoreConfig::new(),
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
    let closure = GuardedCampaignReplayClosure::empty();
    let mut tampered = BTreeMap::new();
    tampered.insert(identity, b"tampered-world-block".to_vec());
    let error = FindingProductionReplayCapture::new(
        &finding,
        reproduction,
        signature,
        &closure,
        FindingProductionReplayCaptureInput::new(
            FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
            deployment(),
            vec![timeout_side()],
            tampered,
            FindingProductionReplayCaptureLimits::for_finding(&finding),
        ),
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
fn capture_enforces_guest_asset_caps_when_captured_and_decoded() {
    let finding = finding();
    let (reproduction, signature) = campaign_binding(&finding, FindingKind::Timeout);
    let closure = GuardedCampaignReplayClosure::empty();
    let mut asset_limits = FindingProductionReplayCaptureLimits::for_finding(&finding);
    asset_limits.max_guest_asset_bytes = 1;
    assert!(matches!(
        FindingProductionReplayCapture::new(
            &finding,
            reproduction,
            signature.clone(),
            &closure,
            FindingProductionReplayCaptureInput::new(
                FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
                deployment(),
                vec![timeout_side()],
                BTreeMap::new(),
                asset_limits,
            ),
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
        &closure,
        FindingProductionReplayCaptureInput::new(
            FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
            deployment(),
            vec![timeout_side()],
            BTreeMap::new(),
            limits,
        ),
    )
    .expect("capture");
    let mut decoded_asset_limits = limits;
    decoded_asset_limits.max_guest_asset_bytes = 1;
    assert!(matches!(
        round_trip(&capture, decoded_asset_limits),
        Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-guest-asset-bytes"
        })
    ));
    round_trip(&capture, limits).expect("capture decodes under its own limits");
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
    .with_root_image_format(crucible_qemu::QemuRootImageFormat::Raw);
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
        WorldIoCoreConfig::new(),
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
        FindingProductionReplayBudget {
            precharged_identities: &captured.unique_identities,
            precharged_bytes: captured.unique_bytes,
            total_byte_limit: static_limit,
        },
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
    let closure = GuardedCampaignReplayClosure::empty();
    let limits = FindingProductionReplayCaptureLimits::for_finding(&finding);

    let mut over_budget = timeout_side();
    over_budget.completed_quanta = 65;
    assert!(matches!(
        FindingProductionReplayCapture::new(
            &finding,
            reproduction,
            signature.clone(),
            &closure,
            FindingProductionReplayCaptureInput::new(
                FindingProductionReplayRecipe::new(10_000, 64, true).expect("recipe"),
                deployment(),
                vec![over_budget],
                BTreeMap::new(),
                limits,
            ),
        ),
        Err(FindingProductionReplayCaptureError::LimitExceeded {
            limit: "finding-production-replay-completed-quanta"
        })
    ));

    assert!(matches!(
        side_with(
            FindingProductionReplayTerminalOutcome::Timeout,
            1,
            VirtualTime { ticks: 6 },
            vec![side_event(0, "quantum-budget")],
        ),
        Err(FindingProductionReplayCaptureError::InvalidEventLog)
    ));
}
