//! Tests for storage-fault opportunity resolution.

use std::sync::Arc;

use crucible::model::{
    BindingActionCause, BoundedCount, ByteRange, ContentAddressedBlobRef, ContentHash, CountLimit,
    EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest, FaultCoordinate, FaultOperation,
    FaultPhase, HexBytes, Icount, NodeId, NodeTemplate, OperationSet, PositiveU64, ReadyPoint,
    SignalId, StoragePolicyArtifactKind, StoragePolicyDuplicateCompletion,
    StoragePolicyPersistence, StoragePolicyResult, StoragePolicyService, StoragePolicyServiceClass,
    StoragePolicyTypedResult, VmArchitecture, WhiteBoxPolicy, WorldBlockLatency,
    WorldFaultTopology, WorldFlushSemantics, WorldIoCoreConfig, WorldIoNode, WorldNode,
    WorldNodeDef, WorldStorageFaultDevice, WorldStorageKind, WorldStorageMedia,
    WorldStoragePersistence, WorldStoragePolicyArtifact,
};
use crucible_device::block::{BlockErrorCode, ResolvedBlockDuplicateCompletion};

use super::*;

fn id(value: &str) -> FaultObjectId {
    FaultObjectId::parse(value)
        .unwrap_or_else(|error| panic!("test object ID should be valid: {error}"))
}

fn target() -> ResolvedFaultTarget {
    ResolvedFaultTarget::BlockDevice {
        device: ContentHash::from_bytes(b"block-device-hash"),
    }
}

fn action(
    binding: &str,
    lifetime: EffectLifetime,
    phase: FaultPhase,
    specification: StorageEffectSpecification,
    mapping_output: ResolvedMappingOutput,
) -> ResolvedBindingAction {
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        lifetime,
        EffectSpecification::Storage(specification),
    )
    .unwrap_or_else(|error| panic!("test effect should be valid: {error}"));
    ResolvedBindingAction {
        kind: match lifetime {
            EffectLifetime::Persistent | EffectLifetime::StateMachine => {
                BindingActionKind::UpsertPersistent
            }
            EffectLifetime::Opportunity | EffectLifetime::Impulse => BindingActionKind::Apply,
        },
        binding: id(binding),
        target: target(),
        phase,
        effect: Arc::new(effect),
        mapping_output: Arc::new(mapping_output),
        mapped_digest: ContentHash::from_bytes(binding.as_bytes()),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 10,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    }
}

fn opaque_world() -> World {
    World::from_content_hash(ContentHash::from_bytes(b"storage-resolver-test-world"))
}

fn world_with_block_result(id_value: &str, result: StoragePolicyResult) -> World {
    let mut topology = WorldFaultTopology::default();
    topology
        .storage_policy_artifacts
        .push(WorldStoragePolicyArtifact {
            id: id(id_value),
            semantic_version: 1,
            artifact: StoragePolicyArtifactKind::TypedResult(StoragePolicyTypedResult::Block {
                result,
            }),
        });
    opaque_world()
        .with_fault_topology(topology)
        .unwrap_or_else(|error| panic!("test storage policy should be valid: {error}"))
}

fn world_with_storage_policies(
    artifacts: impl IntoIterator<Item = WorldStoragePolicyArtifact>,
) -> World {
    let mut topology = WorldFaultTopology::default();
    topology.storage_policy_artifacts.extend(artifacts);
    topology
        .storage_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));
    opaque_world()
        .with_fault_topology(topology)
        .unwrap_or_else(|error| panic!("test storage policies should be valid: {error}"))
}

fn storage_policy_artifact(
    id_value: &str,
    artifact: StoragePolicyArtifactKind,
) -> WorldStoragePolicyArtifact {
    WorldStoragePolicyArtifact {
        id: id(id_value),
        semantic_version: 1,
        artifact,
    }
}

fn world_with_declared_block(
    artifacts: impl IntoIterator<Item = WorldStoragePolicyArtifact>,
) -> (World, ResolvedFaultTarget) {
    let vm_id = NodeId {
        name: String::from("storage-owner"),
    };
    let block_id = NodeId {
        name: String::from("block-device"),
    };
    let vm = WorldNode {
        id: vm_id.clone(),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    };
    let block = WorldIoNode::block(
        block_id,
        vm_id,
        WorldIoCoreConfig::new(0),
        ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(b"block-base-image")),
        4096,
        WorldBlockLatency::new(1, 1, 1, 1, 1),
    );
    let resolved_target = ResolvedFaultTarget::BlockDevice {
        device: block.fault_target_hash(),
    };
    let mut topology = WorldFaultTopology::default();
    topology.storage_policy_artifacts.extend(artifacts);
    topology
        .storage_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));
    topology.storage_devices.push(WorldStorageFaultDevice {
        id: SignalId::parse("block-contract")
            .unwrap_or_else(|error| panic!("test contract ID should be valid: {error}")),
        device: SignalId::parse("block-device")
            .unwrap_or_else(|error| panic!("test device ID should be valid: {error}")),
        kind: WorldStorageKind::Block,
        persistence: WorldStoragePersistence {
            logical_block_bytes: 512,
            physical_sector_bytes: 512,
            atomic_write_bytes: 512,
            length_bytes: 4096,
            discard_granularity_bytes: 512,
            maximum_request_bytes: 4096,
            volatile_cache_bytes: 4096,
            controller_buffer_bytes: 0,
            flush_semantics: WorldFlushSemantics::WritebackBarrier,
            discard_semantics: WorldDiscardSemantics::DeterministicZero,
            completion_durability: WorldCompletionDurability::VolatileCacheAccepted,
            cache_entries: 16,
            controller_entries: 0,
            persistence_dependencies: 64,
            retained_versions_per_interval: 4,
        },
        media: WorldStorageMedia::Ram { page_bytes: 4096 },
        fault_domains: Vec::new(),
    });
    let world = World::from_node_defs_and_links(
        vec![WorldNodeDef::Vm(vm), WorldNodeDef::Io(block)],
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("test block world should build: {error}"))
    .with_fault_topology(topology)
    .unwrap_or_else(|error| panic!("test block topology should be valid: {error}"));
    (world, resolved_target)
}

fn context() -> StorageFaultResolutionContext {
    StorageFaultResolutionContext::new(ContentHash::from_bytes(b"storage-resolver-seed"))
}

fn unexpected_read_source(
    _device: ContentHash,
    _offset: u64,
    _count: u32,
) -> Result<Vec<u8>, String> {
    Err(String::from("test did not admit a misdirected read source"))
}

fn opportunity(request: &BlockRequest, phase: FaultPhase) -> FaultOpportunity {
    opportunity_for_target(target(), request, phase)
}

fn opportunity_for_target(
    target: ResolvedFaultTarget,
    request: &BlockRequest,
    phase: FaultPhase,
) -> FaultOpportunity {
    let wire = request
        .encode()
        .unwrap_or_else(|error| panic!("test request should encode: {error}"));
    block_request_fault_opportunity(
        target,
        request,
        *blake3::hash(&wire).as_bytes(),
        phase,
        FaultCoordinate {
            virtual_nanos: 10,
            retired_instructions: None,
        },
        1,
    )
    .unwrap_or_else(|error| panic!("test opportunity should be valid: {error}"))
}

fn resolve_single_effect(
    world: &World,
    request: &BlockRequest,
    phase: FaultPhase,
    binding: &str,
    lifetime: EffectLifetime,
    specification: StorageEffectSpecification,
    mapping_output: ResolvedMappingOutput,
) -> ResolvedBlockFaultDirective {
    resolve_single_effect_for_target(
        world,
        target(),
        request,
        phase,
        binding,
        lifetime,
        specification,
        mapping_output,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the test helper keeps the typed production mutation inputs explicit"
)]
fn resolve_single_effect_for_target(
    world: &World,
    resolved_target: ResolvedFaultTarget,
    request: &BlockRequest,
    phase: FaultPhase,
    binding: &str,
    lifetime: EffectLifetime,
    specification: StorageEffectSpecification,
    mapping_output: ResolvedMappingOutput,
) -> ResolvedBlockFaultDirective {
    let opportunity = opportunity_for_target(resolved_target.clone(), request, phase);
    let mut resolved_action = action(binding, lifetime, phase, specification, mapping_output);
    resolved_action.target = resolved_target.clone();
    if lifetime == EffectLifetime::Opportunity {
        resolved_action = bind_to_opportunity(resolved_action, &opportunity);
    }
    resolve_block_fault_directive_with_capacity(
        world,
        &resolved_target,
        request,
        1,
        &opportunity,
        4096,
        context(),
        &mut unexpected_read_source,
        [&resolved_action],
    )
    .unwrap_or_else(|error| panic!("production storage effect should resolve: {error}"))
}

#[test]
fn stall_timeout_resolves_exact_timeout_and_optional_recovery_subscription() {
    let timeout_result = id("timeout-result");
    let recovery_event = id("recover-storage");
    let world = world_with_block_result(timeout_result.as_str(), StoragePolicyResult::Timeout);
    let request = BlockRequest::read(7, 0, 512);
    let opportunity = opportunity(&request, FaultPhase::Resolve);
    let action = bind_to_opportunity(
        action(
            "stall-read",
            EffectLifetime::Opportunity,
            FaultPhase::Resolve,
            StorageEffectSpecification::StallTimeout {
                stall_nanos: PositiveU64::new("stall_nanos", 25)
                    .unwrap_or_else(|error| panic!("test timeout should be valid: {error}")),
                recovery_event: Some(recovery_event.clone()),
                timeout_result,
            },
            ResolvedMappingOutput::Activation { active: true },
        ),
        &opportunity,
    );
    let resolved = resolve_block_fault_directive_with_capacity(
        &world,
        &target(),
        &request,
        1,
        &opportunity,
        4096,
        context(),
        &mut unexpected_read_source,
        [&action],
    )
    .unwrap_or_else(|error| panic!("stall should resolve: {error}"));

    assert!(resolved.retain_completion);
    assert_eq!(resolved.retention_timeout_nanos, Some(35));
    assert_eq!(
        resolved.retention_recovery_event,
        Some(storage_recovery_event_key(&recovery_event))
    );
    assert_eq!(resolved.retention_recovery_after_nanos, Some(10));
    assert_eq!(
        resolved
            .retention_timeout_response
            .as_ref()
            .and_then(|response| response.error_code().ok()),
        Some(BlockErrorCode::Timeout)
    );
}

#[test]
fn flush_stall_without_recovery_still_retains_until_exact_timeout() {
    let timeout_result = id("flush-timeout-result");
    let world = world_with_block_result(timeout_result.as_str(), StoragePolicyResult::Timeout);
    let request = BlockRequest::flush(8);
    let opportunity = opportunity(&request, FaultPhase::Persist);
    let action =
        bind_to_opportunity(
            action(
                "stall-flush",
                EffectLifetime::Opportunity,
                FaultPhase::Persist,
                StorageEffectSpecification::FlushDisposition {
                    kind: StorageFlushKind::Stall,
                    status: timeout_result,
                    stall_nanos: Some(PositiveU64::new("stall_nanos", 40).unwrap_or_else(
                        |error| panic!("test flush timeout should be valid: {error}"),
                    )),
                    recovery_event: None,
                },
                ResolvedMappingOutput::Activation { active: true },
            ),
            &opportunity,
        );
    let resolved = resolve_block_fault_directive_with_capacity(
        &world,
        &target(),
        &request,
        1,
        &opportunity,
        4096,
        context(),
        &mut unexpected_read_source,
        [&action],
    )
    .unwrap_or_else(|error| panic!("flush stall should resolve: {error}"));

    assert!(resolved.retain_completion);
    assert_eq!(resolved.retention_timeout_nanos, Some(50));
    assert_eq!(resolved.retention_recovery_event, None);
    assert_eq!(
        resolved.flush_disposition,
        BlockFaultFlushDisposition::Stall
    );
}

fn bind_to_opportunity(
    mut action: ResolvedBindingAction,
    opportunity: &FaultOpportunity,
) -> ResolvedBindingAction {
    action.opportunity = Some(opportunity.id());
    action.cause = BindingActionCause::Opportunity(opportunity.id());
    action
}

#[test]
fn service_classes_are_canonical_after_identity_and_operation_conversion() {
    let classes = vec![
        StoragePolicyServiceClass {
            class: id("class-a"),
            operations: OperationSet::new(vec![
                FaultOperation::StorageGetLength,
                FaultOperation::StorageDiscard,
            ])
            .unwrap_or_else(|error| panic!("service operations should be valid: {error}")),
            priority: 1,
            weight: PositiveU64::new("weight", 1)
                .unwrap_or_else(|error| panic!("service weight should be valid: {error}")),
        },
        StoragePolicyServiceClass {
            class: id("class-b"),
            operations: OperationSet::new(vec![FaultOperation::StorageRead])
                .unwrap_or_else(|error| panic!("service operations should be valid: {error}")),
            priority: 0,
            weight: PositiveU64::new("weight", 2)
                .unwrap_or_else(|error| panic!("service weight should be valid: {error}")),
        },
    ];

    let resolved = resolve_service_classes(classes)
        .unwrap_or_else(|error| panic!("service classes should resolve: {error}"));

    assert!(
        resolved
            .windows(2)
            .all(|pair| pair[0].class < pair[1].class)
    );
    assert!(resolved.iter().all(|class| {
        class
            .operations
            .windows(2)
            .all(|pair| pair[0].to_wire() < pair[1].to_wire())
    }));
    for class in &resolved {
        assert!(
            class.operations.contains(&BlockOp::Discard)
                != class.operations.contains(&BlockOp::Read)
        );
    }
}

#[test]
fn persistence_resolver_accepts_discard_and_rejects_operation_aliasing() {
    let physical = BlockPersistenceOpportunity {
        sequence: 4,
        request_id: 17,
        operation_sequence: 3,
        operation: BlockOp::Discard,
        request_digest: [3; 32],
        offset: 4096,
        count: 4096,
        intended_digest: [5; 32],
        ready_nanos: 10,
    };
    let coordinate = FaultCoordinate {
        virtual_nanos: 10,
        retired_instructions: None,
    };
    let payload = OpportunityPayload::StorageRequest {
        request_sequence: physical.sequence,
        start_byte: Some(physical.offset),
        length_bytes: Some(u64::from(physical.count)),
        request_digest: ContentHash {
            bytes: physical.intended_digest,
        },
    };
    let discard = FaultOpportunity::new(
        target(),
        FaultOperation::StorageDiscard,
        FaultPhase::Persist,
        coordinate,
        physical.sequence,
        None,
        payload.clone(),
    )
    .unwrap_or_else(|error| panic!("discard persistence opportunity should build: {error}"));
    let resolved = resolve_block_persistence_media_directive(
        &opaque_world(),
        &target(),
        &physical,
        &discard,
        context(),
        std::iter::empty::<&ResolvedBindingAction>(),
    )
    .unwrap_or_else(|error| panic!("discard persistence should resolve: {error}"));
    assert_eq!(resolved.opportunity, physical);
    assert!(resolved.flash_rules.is_empty());

    let write_alias = FaultOpportunity::new(
        target(),
        FaultOperation::StorageWrite,
        FaultPhase::Persist,
        coordinate,
        physical.sequence,
        None,
        payload,
    )
    .unwrap_or_else(|error| panic!("write alias opportunity should build: {error}"));
    assert!(matches!(
        resolve_block_persistence_media_directive(
            &opaque_world(),
            &target(),
            &physical,
            &write_alias,
            context(),
            std::iter::empty::<&ResolvedBindingAction>(),
        ),
        Err(StorageFaultResolutionError::OpportunityMismatch)
    ));
}

#[test]
fn composition_is_canonical_and_uses_most_severe_availability() {
    let degraded = action(
        "z-degraded",
        EffectLifetime::Persistent,
        FaultPhase::Admit,
        StorageEffectSpecification::Availability {
            state: StorageAvailabilityState::Degraded,
            reconnect_policy: crucible::model::StorageTransitionPolicy::Fail,
        },
        ResolvedMappingOutput::Activation { active: true },
    );
    let offline = action(
        "a-offline",
        EffectLifetime::Persistent,
        FaultPhase::Admit,
        StorageEffectSpecification::Availability {
            state: StorageAvailabilityState::Offline,
            reconnect_policy: crucible::model::StorageTransitionPolicy::Fail,
        },
        ResolvedMappingOutput::Activation { active: true },
    );
    let request = BlockRequest::read(7, 0, 512);
    let opportunity = opportunity(&request, FaultPhase::Admit);
    let world = opaque_world();

    let first = resolve_block_fault_directive_with_capacity(
        &world,
        &target(),
        &request,
        1,
        &opportunity,
        4096,
        context(),
        &mut unexpected_read_source,
        [&degraded, &offline],
    )
    .unwrap_or_else(|error| panic!("composition should resolve: {error}"));
    let second = resolve_block_fault_directive_with_capacity(
        &world,
        &target(),
        &request,
        1,
        &opportunity,
        4096,
        context(),
        &mut unexpected_read_source,
        [&offline, &degraded],
    )
    .unwrap_or_else(|error| panic!("composition should resolve: {error}"));

    assert_eq!(first, second);
    assert_eq!(first.availability, BlockFaultAvailability::Offline);
}

#[test]
fn latency_uses_typed_dynamic_value_and_checked_sum() {
    let operations = OperationSet::new(vec![FaultOperation::StorageRead])
        .unwrap_or_else(|error| panic!("operation set should be valid: {error}"));
    let dynamic = action(
        "dynamic-latency",
        EffectLifetime::Opportunity,
        FaultPhase::Resolve,
        StorageEffectSpecification::Latency {
            operations: operations.clone(),
            extra_nanos: 3,
            jitter_nanos: 0,
        },
        ResolvedMappingOutput::Parameter {
            parameter: MappedEffectParameter::DurationNanos,
            value: SignalValue::DurationNanos(11),
        },
    );
    let fixed = action(
        "fixed-latency",
        EffectLifetime::Opportunity,
        FaultPhase::Resolve,
        StorageEffectSpecification::Latency {
            operations,
            extra_nanos: 7,
            jitter_nanos: 0,
        },
        ResolvedMappingOutput::Hazard {
            probability_millionths: 1_000_000,
        },
    );

    let request = BlockRequest::read(9, 0, 512);
    let opportunity = opportunity(&request, FaultPhase::Resolve);
    let dynamic = bind_to_opportunity(dynamic, &opportunity);
    let fixed = bind_to_opportunity(fixed, &opportunity);
    let directive = resolve_block_fault_directive_with_capacity(
        &opaque_world(),
        &target(),
        &request,
        1,
        &opportunity,
        4096,
        context(),
        &mut unexpected_read_source,
        [&fixed, &dynamic],
    )
    .unwrap_or_else(|error| panic!("latency should resolve: {error}"));
    assert_eq!(directive.additional_latency_nanos, 18);
}

#[test]
fn production_resolver_mutates_capacity_service_and_delivery_directives() {
    let world = world_with_storage_policies([
        storage_policy_artifact(
            "duplicate-policy",
            StoragePolicyArtifactKind::DuplicateCompletion(
                StoragePolicyDuplicateCompletion::Ignore,
            ),
        ),
        storage_policy_artifact(
            "service-policy",
            StoragePolicyArtifactKind::Service(StoragePolicyService {
                discipline: StoragePolicyQueueDiscipline::Fifo,
                classes: Vec::new(),
                rebuild_shares_service: true,
            }),
        ),
    ]);
    let read = BlockRequest::read(41, 0, 4);

    let capacity = resolve_single_effect(
        &world,
        &read,
        FaultPhase::Admit,
        "reported-capacity",
        EffectLifetime::Persistent,
        StorageEffectSpecification::ReportedCapacity {
            length_bytes: PositiveU64::new("length_bytes", 2048)
                .unwrap_or_else(|error| panic!("test capacity should be valid: {error}")),
            shrink_policy: crucible::model::StorageTransitionPolicy::Drain,
        },
        ResolvedMappingOutput::Activation { active: true },
    );
    assert_eq!(capacity.reported_capacity_bytes, 2048);

    let service = resolve_single_effect(
        &world,
        &read,
        FaultPhase::Queue,
        "bounded-service",
        EffectLifetime::Persistent,
        StorageEffectSpecification::Service {
            bytes_per_second: PositiveU64::new("bytes_per_second", 4096)
                .unwrap_or_else(|error| panic!("test rate should be valid: {error}")),
            iops: Some(
                PositiveU64::new("iops", 32)
                    .unwrap_or_else(|error| panic!("test IOPS should be valid: {error}")),
            ),
            queue_depth: BoundedCount::new(CountLimit::QueueEntries, 8)
                .unwrap_or_else(|error| panic!("test queue depth should be valid: {error}")),
            service_policy: id("service-policy"),
        },
        ResolvedMappingOutput::Activation { active: true },
    );
    assert_eq!(service.service_rules.len(), 1);
    assert_eq!(service.service_rules[0].bytes_per_second, 4096);
    assert_eq!(service.service_rules[0].iops, Some(32));
    assert_eq!(service.service_rules[0].queue_depth, 8);
    assert!(service.service_rules[0].rebuild_shares_service);

    let reordered = resolve_single_effect(
        &world,
        &read,
        FaultPhase::Deliver,
        "completion-reorder",
        EffectLifetime::Opportunity,
        StorageEffectSpecification::CompletionReorder {
            window_nanos: PositiveU64::new("window_nanos", 75)
                .unwrap_or_else(|error| panic!("test reorder window should be valid: {error}")),
            selection: StorageSelection::CanonicalLast,
        },
        ResolvedMappingOutput::Hazard {
            probability_millionths: 1_000_000,
        },
    );
    assert_eq!(reordered.additional_latency_nanos, 75);

    let duplicated = resolve_single_effect(
        &world,
        &read,
        FaultPhase::Deliver,
        "duplicate-completion",
        EffectLifetime::Opportunity,
        StorageEffectSpecification::DuplicateCompletion {
            copies: BoundedCount::new(CountLimit::DuplicatesOrInstructionReplay, 2)
                .unwrap_or_else(|error| panic!("test duplicate count should be valid: {error}")),
            gap_nanos: 9,
            protocol_policy: id("duplicate-policy"),
        },
        ResolvedMappingOutput::Hazard {
            probability_millionths: 1_000_000,
        },
    );
    assert_eq!(duplicated.duplicate_completions.len(), 2);
    assert!(matches!(
        duplicated.duplicate_completions.as_slice(),
        [
            ResolvedBlockDuplicateCompletion::Ignore { gap_nanos: 9 },
            ResolvedBlockDuplicateCompletion::Ignore { gap_nanos: 18 }
        ]
    ));
}

#[test]
fn production_resolver_mutates_read_and_media_directives() {
    let read = BlockRequest::read(42, 512, 4);
    let transformed = resolve_single_effect(
        &opaque_world(),
        &read,
        FaultPhase::Resolve,
        "read-transform",
        EffectLifetime::Opportunity,
        StorageEffectSpecification::ReadTransform {
            mutation: StorageReadMutation::BitFlip {
                range: ByteRange::new(1, 2)
                    .unwrap_or_else(|error| panic!("test byte range should be valid: {error}")),
                mask: HexBytes::parse("a55a", 2)
                    .unwrap_or_else(|error| panic!("test XOR mask should be valid: {error}")),
            },
        },
        ResolvedMappingOutput::Activation { active: true },
    );
    assert_eq!(
        transformed.read_transforms,
        [BlockFaultReadTransform::Xor {
            offset: 1,
            mask: vec![0xa5, 0x5a],
        }]
    );

    let media = resolve_single_effect(
        &opaque_world(),
        &read,
        FaultPhase::Resolve,
        "media-range",
        EffectLifetime::Persistent,
        StorageEffectSpecification::MediaRange {
            range: ByteRange::new(512, 1024)
                .unwrap_or_else(|error| panic!("test media range should be valid: {error}")),
            state: StorageMediaState::Latent,
            operations: OperationSet::new(vec![FaultOperation::StorageRead])
                .unwrap_or_else(|error| panic!("test media operations should be valid: {error}")),
            count_threshold: Some(
                PositiveU64::new("count_threshold", 3).unwrap_or_else(|error| {
                    panic!("test count threshold should be valid: {error}")
                }),
            ),
            time_threshold_nanos: Some(
                PositiveU64::new("time_threshold_nanos", 50)
                    .unwrap_or_else(|error| panic!("test time threshold should be valid: {error}")),
            ),
        },
        ResolvedMappingOutput::Activation { active: true },
    );
    assert_eq!(media.media_rules.len(), 1);
    assert_eq!(media.media_rules[0].start, 512);
    assert_eq!(media.media_rules[0].length, 1024);
    assert_eq!(media.media_rules[0].state, BlockMediaRangeState::Latent);
    assert_eq!(media.media_rules[0].operations, [BlockOp::Read]);
    assert_eq!(media.media_rules[0].count_threshold, Some(3));
    assert_eq!(media.media_rules[0].time_threshold_nanos, Some(50));
}

#[test]
fn production_resolver_mutates_write_and_persistence_directives() {
    let (world, block_target) = world_with_declared_block([
        storage_policy_artifact(
            "ordering-policy",
            StoragePolicyArtifactKind::Persistence(StoragePolicyPersistence {
                ordering: StoragePolicyPersistenceOrdering::DescendingRange,
                delay_nanos: 125,
                preserve_barriers: true,
            }),
        ),
        storage_policy_artifact(
            "write-success",
            StoragePolicyArtifactKind::TypedResult(StoragePolicyTypedResult::Block {
                result: StoragePolicyResult::Success,
            }),
        ),
    ]);
    let write = BlockRequest::write(43, 1024, vec![0x5a; 512]);

    let disposition = resolve_single_effect_for_target(
        &world,
        block_target.clone(),
        &write,
        FaultPhase::Persist,
        "write-disposition",
        EffectLifetime::Opportunity,
        StorageEffectSpecification::WriteDisposition {
            disposition: StorageWriteDispositionKind::Lost {
                selection: StorageSelection::All,
            },
            acknowledged_status: id("write-success"),
        },
        ResolvedMappingOutput::Activation { active: true },
    );
    assert_eq!(
        disposition.write_disposition,
        BlockFaultWriteDisposition::Lost
    );

    let persistence = resolve_single_effect_for_target(
        &world,
        block_target,
        &write,
        FaultPhase::Persist,
        "persistence-order",
        EffectLifetime::Persistent,
        StorageEffectSpecification::PersistenceOrder {
            ordering_group: id("database-wal"),
            ordering_rule: id("ordering-policy"),
        },
        ResolvedMappingOutput::Activation { active: true },
    );
    assert_eq!(persistence.persistence_transforms.len(), 1);
    assert_eq!(
        persistence.persistence_transforms[0].ordering,
        BlockPersistenceOrdering::DescendingRange
    );
    assert_eq!(persistence.persistence_transforms[0].delay_nanos, 125);
    assert!(persistence.persistence_transforms[0].preserve_barriers);
    assert_eq!(persistence.persistence_admitted_nanos, 10);
}

#[test]
fn wrong_dynamic_parameter_fails_closed() {
    let latency = action(
        "bad-latency-mapping",
        EffectLifetime::Opportunity,
        FaultPhase::Resolve,
        StorageEffectSpecification::Latency {
            operations: OperationSet::new(vec![FaultOperation::StorageRead])
                .unwrap_or_else(|error| panic!("operation set should be valid: {error}")),
            extra_nanos: 3,
            jitter_nanos: 0,
        },
        ResolvedMappingOutput::Parameter {
            parameter: MappedEffectParameter::BitsPerSecond,
            value: SignalValue::RatePerSecond(11),
        },
    );

    let request = BlockRequest::read(9, 0, 512);
    let opportunity = opportunity(&request, FaultPhase::Resolve);
    let latency = bind_to_opportunity(latency, &opportunity);
    let error = match resolve_block_fault_directive_with_capacity(
        &opaque_world(),
        &target(),
        &request,
        1,
        &opportunity,
        4096,
        context(),
        &mut unexpected_read_source,
        [&latency],
    ) {
        Ok(_) => panic!("wrong dynamic field must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        StorageFaultResolutionError::MappingOutput {
            expected: MappedEffectParameter::DurationNanos,
            ..
        }
    ));
}

#[test]
fn opportunity_binds_wire_digest_range_phase_and_monotone_sequence() {
    let request = BlockRequest::read(7, 512, 1024);
    let coordinate = FaultCoordinate {
        virtual_nanos: 40,
        retired_instructions: Some(20),
    };
    let first = block_request_fault_opportunity(
        target(),
        &request,
        [3; 32],
        FaultPhase::Resolve,
        coordinate,
        11,
    )
    .unwrap_or_else(|error| panic!("opportunity should be valid: {error}"));
    let next = block_request_fault_opportunity(
        target(),
        &request,
        [3; 32],
        FaultPhase::Resolve,
        coordinate,
        12,
    )
    .unwrap_or_else(|error| panic!("opportunity should be valid: {error}"));
    let changed_wire = block_request_fault_opportunity(
        target(),
        &request,
        [4; 32],
        FaultPhase::Resolve,
        coordinate,
        11,
    )
    .unwrap_or_else(|error| panic!("opportunity should be valid: {error}"));

    assert_eq!(first.operation(), FaultOperation::StorageRead);
    assert_eq!(first.phase(), FaultPhase::Resolve);
    assert_ne!(first.id(), next.id());
    assert_ne!(first.id(), changed_wire.id());
}

#[test]
fn delivery_opportunity_binds_the_computed_response() {
    let request = BlockRequest::read(7, 512, 4);
    let directive = ResolvedBlockFaultDirective::fault_free(&request, 4096);
    let delivery = BlockDeliveryOpportunity {
        request_sequence: 11,
        request: request.clone(),
        request_icount: 20,
        ready_nanos: 40,
        wire_digest: [3; 32],
        response: BlockResponse::ok(request.request_id, b"good".to_vec()),
        resolved: directive,
        required_durable_frontier: None,
    };
    let coordinate = FaultCoordinate {
        virtual_nanos: 40,
        retired_instructions: Some(20),
    };
    let first = block_delivery_fault_opportunity(target(), &delivery, coordinate)
        .unwrap_or_else(|error| panic!("delivery opportunity should be valid: {error}"));
    let mut changed = delivery;
    changed.response = BlockResponse::ok(request.request_id, b"evil".to_vec());
    let changed = block_delivery_fault_opportunity(target(), &changed, coordinate)
        .unwrap_or_else(|error| panic!("changed delivery should be valid: {error}"));

    assert_eq!(first.phase(), FaultPhase::Deliver);
    assert_ne!(first.id(), changed.id());
    assert!(matches!(
        first.payload(),
        OpportunityPayload::StorageCompletion {
            response_status: 0,
            ..
        }
    ));
}

#[test]
fn delivery_completion_payload_authenticates_the_original_request() {
    let request = BlockRequest::read(7, 512, 4);
    let wire = request
        .encode()
        .unwrap_or_else(|error| panic!("test request should encode: {error}"));
    let delivery = BlockDeliveryOpportunity {
        request_sequence: 11,
        request: request.clone(),
        request_icount: 20,
        ready_nanos: 40,
        wire_digest: *blake3::hash(&wire).as_bytes(),
        response: BlockResponse::ok(request.request_id, b"good".to_vec()),
        resolved: ResolvedBlockFaultDirective::fault_free(&request, 4096),
        required_durable_frontier: None,
    };
    let opportunity = block_delivery_fault_opportunity(
        target(),
        &delivery,
        FaultCoordinate {
            virtual_nanos: 40,
            retired_instructions: Some(20),
        },
    )
    .unwrap_or_else(|error| panic!("delivery opportunity should be valid: {error}"));

    let resolved = resolve_block_fault_directive_with_capacity(
        &opaque_world(),
        &target(),
        &request,
        delivery.request_sequence,
        &opportunity,
        4096,
        context(),
        &mut unexpected_read_source,
        [],
    )
    .unwrap_or_else(|error| panic!("delivery request identity should validate: {error}"));
    assert_eq!(resolved.request_sequence, delivery.request_sequence);
}

#[test]
fn keyed_choices_are_reproducible_and_scenario_owned() {
    let latency = action(
        "keyed-choice",
        EffectLifetime::Opportunity,
        FaultPhase::Resolve,
        StorageEffectSpecification::Latency {
            operations: OperationSet::new(vec![FaultOperation::StorageRead])
                .unwrap_or_else(|error| panic!("operation set should be valid: {error}")),
            extra_nanos: 0,
            jitter_nanos: 99,
        },
        ResolvedMappingOutput::Hazard {
            probability_millionths: 1_000_000,
        },
    );
    let request = BlockRequest::read(5, 512, 512);
    let first = keyed_inclusive(context(), &latency, &request, b"test-choice", u64::MAX);
    let repeated = keyed_inclusive(context(), &latency, &request, b"test-choice", u64::MAX);
    let different_seed = keyed_inclusive(
        StorageFaultResolutionContext::new(ContentHash::from_bytes(b"different-seed")),
        &latency,
        &request,
        b"test-choice",
        u64::MAX,
    );

    assert_eq!(first, repeated);
    assert_ne!(first, different_seed);
}

#[test]
fn every_non_success_block_policy_result_maps_exactly() {
    use crucible::model::StoragePolicyResult;

    let cases = [
        (StoragePolicyResult::Offline, BlockFaultResult::Offline),
        (StoragePolicyResult::ReadOnly, BlockFaultResult::ReadOnly),
        (
            StoragePolicyResult::InvalidRange,
            BlockFaultResult::InvalidRange,
        ),
        (StoragePolicyResult::Busy, BlockFaultResult::Busy),
        (StoragePolicyResult::Timeout, BlockFaultResult::Timeout),
        (
            StoragePolicyResult::MediumError,
            BlockFaultResult::MediumError,
        ),
        (
            StoragePolicyResult::IntegrityError,
            BlockFaultResult::IntegrityError,
        ),
        (StoragePolicyResult::IoError, BlockFaultResult::IoError),
        (StoragePolicyResult::NoSpace, BlockFaultResult::NoSpace),
        (StoragePolicyResult::NotFound, BlockFaultResult::NotFound),
        (StoragePolicyResult::Stale, BlockFaultResult::Stale),
    ];
    assert_eq!(
        block_failure_from_result(StoragePolicyResult::Success),
        None
    );
    for (policy, expected) in cases {
        assert_eq!(block_failure_from_result(policy), Some(expected));
    }
}

#[test]
fn hazard_probability_uses_the_request_keyed_draw() {
    let latency = action(
        "small-hazard",
        EffectLifetime::Opportunity,
        FaultPhase::Resolve,
        StorageEffectSpecification::Latency {
            operations: OperationSet::new(vec![FaultOperation::StorageRead])
                .unwrap_or_else(|error| panic!("operation set should be valid: {error}")),
            extra_nanos: 1,
            jitter_nanos: 0,
        },
        ResolvedMappingOutput::Hazard {
            probability_millionths: 1,
        },
    );
    let request = BlockRequest::read(5, 512, 512);
    let expected = keyed_inclusive(
        context(),
        &latency,
        &request,
        b"storage.effect-probability.v1",
        999_999,
    ) < 1;

    assert_eq!(
        probability_applies(context(), &latency, &request, 1_000_000)
            .unwrap_or_else(|error| panic!("hazard should resolve: {error}")),
        expected
    );
}

#[test]
fn opportunity_action_requires_exact_opportunity_identity() {
    let request = BlockRequest::read(9, 0, 512);
    let opportunity = opportunity(&request, FaultPhase::Resolve);
    let latency = action(
        "unbound-latency",
        EffectLifetime::Opportunity,
        FaultPhase::Resolve,
        StorageEffectSpecification::Latency {
            operations: OperationSet::new(vec![FaultOperation::StorageRead])
                .unwrap_or_else(|error| panic!("operation set should be valid: {error}")),
            extra_nanos: 1,
            jitter_nanos: 0,
        },
        ResolvedMappingOutput::Hazard {
            probability_millionths: 1_000_000,
        },
    );

    assert!(matches!(
        resolve_block_fault_directive_with_capacity(
            &opaque_world(),
            &target(),
            &request,
            1,
            &opportunity,
            4096,
            context(),
            &mut unexpected_read_source,
            [&latency],
        ),
        Err(StorageFaultResolutionError::ActionIdentity { .. })
    ));
}

#[test]
fn opportunity_payload_cannot_alias_another_same_operation_request() {
    let first_request = BlockRequest::read(9, 0, 512);
    let second_request = BlockRequest::read(10, 512, 512);
    let first_opportunity = opportunity(&first_request, FaultPhase::Resolve);

    assert_eq!(
        resolve_block_fault_directive_with_capacity(
            &opaque_world(),
            &target(),
            &second_request,
            1,
            &first_opportunity,
            4096,
            context(),
            &mut unexpected_read_source,
            [],
        ),
        Err(StorageFaultResolutionError::OpportunityMismatch)
    );
}

#[test]
fn write_fragments_follow_physical_atomic_boundaries() {
    let request = BlockRequest::write(1, 6, vec![0; 12]);
    assert_eq!(
        atomic_fragments(&request, 8, &id("atomic-test"))
            .unwrap_or_else(|error| panic!("fragments should resolve: {error}")),
        vec![
            BlockFaultByteSpan {
                start: 0,
                length: 2,
            },
            BlockFaultByteSpan {
                start: 2,
                length: 8,
            },
            BlockFaultByteSpan {
                start: 10,
                length: 2,
            },
        ]
    );
}

#[test]
fn volatile_cache_loss_selection_is_exact_and_reproducible() {
    let all = action(
        "cache-loss-all",
        EffectLifetime::Impulse,
        FaultPhase::Boundary,
        StorageEffectSpecification::VolatileCacheLoss {
            selector: StorageVolatileCacheLossSelector::All,
            loss: StorageVolatileCacheLossKind::ProtectionFailure,
        },
        ResolvedMappingOutput::Impulse {
            event: SignalValue::Bytes(vec![1]),
        },
    );
    let state = BlockFaultState::write_through(4096);
    let eligible = [2, 5, 9];
    assert_eq!(
        select_volatile_cache_loss(
            context(),
            &all,
            &StorageVolatileCacheLossSelector::All,
            &state,
            &eligible,
        )
        .unwrap_or_else(|error| panic!("all selection should resolve: {error}")),
        vec![2, 5, 9]
    );
    assert_eq!(
        select_volatile_cache_loss(
            context(),
            &all,
            &StorageVolatileCacheLossSelector::AfterSequence { sequence: 2 },
            &state,
            &eligible,
        )
        .unwrap_or_else(|error| panic!("sequence selection should resolve: {error}")),
        vec![5, 9]
    );
    let subset = StorageVolatileCacheLossSelector::KeyedSubset {
        count: BoundedCount::new(CountLimit::LargeStateEntries, 2)
            .unwrap_or_else(|error| panic!("subset count should be valid: {error}")),
    };
    let first = select_volatile_cache_loss(context(), &all, &subset, &state, &eligible)
        .unwrap_or_else(|error| panic!("keyed selection should resolve: {error}"));
    let repeated = select_volatile_cache_loss(context(), &all, &subset, &state, &eligible)
        .unwrap_or_else(|error| panic!("keyed selection should repeat: {error}"));
    assert_eq!(first, repeated);
    assert_eq!(first.len(), 2);
    assert!(first.iter().all(|sequence| eligible.contains(sequence)));
}

#[test]
fn volatile_cache_loss_requires_a_boundary_event_payload() {
    let bytes = action(
        "cache-loss-bytes",
        EffectLifetime::Impulse,
        FaultPhase::Boundary,
        StorageEffectSpecification::VolatileCacheLoss {
            selector: StorageVolatileCacheLossSelector::All,
            loss: StorageVolatileCacheLossKind::PowerLoss,
        },
        ResolvedMappingOutput::Impulse {
            event: SignalValue::Bytes(vec![1]),
        },
    );
    assert!(matches!(
        resolve_volatile_cache_loss(
            &target(),
            &BlockFaultState::write_through(4096),
            context(),
            &bytes,
            VolatileCacheLossReplay::Record,
        ),
        Err(StorageFaultResolutionError::ActionIdentity { .. })
    ));

    let event = action(
        "cache-loss-event",
        EffectLifetime::Impulse,
        FaultPhase::Boundary,
        StorageEffectSpecification::VolatileCacheLoss {
            selector: StorageVolatileCacheLossSelector::All,
            loss: StorageVolatileCacheLossKind::PowerLoss,
        },
        ResolvedMappingOutput::Impulse {
            event: SignalValue::Event {
                schema: SignalId::parse("loss-event")
                    .unwrap_or_else(|error| panic!("test signal ID should be valid: {error}")),
                payload: vec![7],
            },
        },
    );
    let state = BlockFaultState::write_through(4096);
    let resolved = resolve_volatile_cache_loss(
        &target(),
        &state,
        context(),
        &event,
        VolatileCacheLossReplay::Record,
    )
    .unwrap_or_else(|error| panic!("event loss should resolve: {error}"));
    assert_eq!(resolved.entry_set_digest, state.volatile_entries_digest());
    assert!(resolved.eligible_sequences.is_empty());
    assert!(resolved.protected_sequences.is_empty());
    assert!(resolved.selected_sequences.is_empty());
    assert_eq!(resolved.durable_frontier_before, 0);
    assert_eq!(resolved.durable_frontier_after, 0);
    assert!(matches!(
        resolve_volatile_cache_loss(
            &target(),
            &state,
            context(),
            &event,
            VolatileCacheLossReplay::Locked {
                expected_entry_set_digest: [9; 32],
            },
        ),
        Err(StorageFaultResolutionError::ReplayEntrySetMismatch { .. })
    ));
}

#[test]
fn independently_sampled_storage_phases_merge_without_erasing_prior_fields() {
    let request = BlockRequest::write(77, 8, vec![1; 4]);
    let mut accumulated = ResolvedBlockFaultDirective::fault_free(&request, 4096);
    accumulated.request_sequence = 1_001;

    let mut admit = accumulated.clone();
    admit.availability = BlockFaultAvailability::Degraded;
    admit.reported_capacity_bytes = 2048;
    merge_block_fault_phase_directive(&mut accumulated, FaultPhase::Admit, admit)
        .unwrap_or_else(|error| panic!("admit phase should merge: {error}"));

    let mut resolve = ResolvedBlockFaultDirective::fault_free(&request, 4096);
    resolve.request_sequence = 1_001;
    resolve.execution_nanos = 31;
    resolve.additional_latency_nanos = 7;
    resolve.error_result = Some(BlockFaultResult::IoError);
    merge_block_fault_phase_directive(&mut accumulated, FaultPhase::Resolve, resolve)
        .unwrap_or_else(|error| panic!("resolve phase should merge: {error}"));

    let mut deliver = ResolvedBlockFaultDirective::fault_free(&request, 4096);
    deliver.request_sequence = 1_001;
    deliver.additional_latency_nanos = 11;
    merge_block_fault_phase_directive(&mut accumulated, FaultPhase::Deliver, deliver)
        .unwrap_or_else(|error| panic!("deliver phase should merge: {error}"));

    assert_eq!(accumulated.availability, BlockFaultAvailability::Degraded);
    assert_eq!(accumulated.reported_capacity_bytes, 2048);
    assert_eq!(accumulated.execution_nanos, 31);
    assert_eq!(accumulated.additional_latency_nanos, 18);
    assert_eq!(accumulated.error_result, Some(BlockFaultResult::IoError));
}
