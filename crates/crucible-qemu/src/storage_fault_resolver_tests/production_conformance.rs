//! Causal production-conformance cases for the closed storage vocabulary.

use super::*;

pub(super) fn record_production_effect_rows(
    effects: &[crucible::model::EffectKind],
    case_id: &str,
    evidence: &str,
) {
    use std::io::Write as _;

    let Some(path) = std::env::var_os("CRUCIBLE_STORAGE_PRODUCTION_EFFECT_ROWS") else {
        return;
    };
    let registry = crucible::model::production_storage_effect_implementation_registry()
        .unwrap_or_else(|error| panic!("production storage registry must validate: {error}"));
    let mut output = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap_or_else(|error| panic!("open production storage evidence output: {error}"));
    for effect in effects {
        registry
            .require_implemented(*effect)
            .unwrap_or_else(|error| panic!("storage effect row must be implemented: {error}"));
        writeln!(
            output,
            "production_effect_row={}|{}|gate:live-block-io|production-block-fault-resolver|{}",
            effect.as_str(),
            case_id,
            evidence,
        )
        .unwrap_or_else(|error| panic!("write production storage evidence row: {error}"));
    }
}

fn world_with_declared_storage_array() -> World {
    let vm_id = NodeId {
        name: String::from("array-owner"),
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
    let block = |name: &str, seed: &[u8]| {
        WorldIoNode::block(
            NodeId {
                name: String::from(name),
            },
            vm_id.clone(),
            WorldIoCoreConfig::new(0),
            ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(seed)),
            4096,
            WorldBlockLatency::new(1, 1, 1, 1, 1),
        )
    };
    let logical = block("logical-array", b"logical-array-image");
    let member_a = block("member-device-a", b"member-a-image");
    let member_b = block("member-device-b", b"member-b-image");

    let persistence = WorldStoragePersistence {
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
    };
    let storage_device = |id_value: &str, device: &str| WorldStorageFaultDevice {
        id: SignalId::parse(id_value)
            .unwrap_or_else(|error| panic!("test contract ID should parse: {error}")),
        device: SignalId::parse(device)
            .unwrap_or_else(|error| panic!("test device ID should parse: {error}")),
        kind: WorldStorageKind::Block,
        persistence: persistence.clone(),
        media: WorldStorageMedia::Ram { page_bytes: 4096 },
        fault_domains: Vec::new(),
    };

    let storage_devices = vec![
        storage_device("logical-contract", "logical-array"),
        storage_device("member-a-contract", "member-device-a"),
        storage_device("member-b-contract", "member-device-b"),
    ];
    let storage_policy_artifacts = vec![
        storage_policy_artifact(
            "array-error",
            StoragePolicyArtifactKind::TypedResult(StoragePolicyTypedResult::Block {
                result: StoragePolicyResult::IoError,
            }),
        ),
        storage_policy_artifact(
            "array-selection",
            StoragePolicyArtifactKind::ArraySelection(
                crucible::model::StoragePolicyArraySelection::LowestHealthy,
            ),
        ),
        storage_policy_artifact(
            "array-state",
            StoragePolicyArtifactKind::ArrayState {
                members: vec![
                    crucible::model::StoragePolicyArrayMemberState {
                        member: id("member-a"),
                        online: true,
                    },
                    crucible::model::StoragePolicyArrayMemberState {
                        member: id("member-b"),
                        online: false,
                    },
                ],
                paths: vec![crucible::model::StoragePolicyArrayPathState {
                    path: id("path-a"),
                    online: true,
                }],
            },
        ),
        storage_policy_artifact(
            "array-rebuild",
            StoragePolicyArtifactKind::Rebuild(crucible::model::StoragePolicyRebuild {
                chunk_bytes: PositiveU64::new("chunk_bytes", 512)
                    .unwrap_or_else(|error| panic!("test chunk size should validate: {error}")),
                queue_depth: BoundedCount::new(CountLimit::QueueEntries, 2)
                    .unwrap_or_else(|error| panic!("test queue depth should validate: {error}")),
                bytes_per_second: PositiveU64::new("bytes_per_second", 4096)
                    .unwrap_or_else(|error| panic!("test rebuild rate should validate: {error}")),
            }),
        ),
        storage_policy_artifact(
            "array-consistency",
            StoragePolicyArtifactKind::ArrayConsistency(
                crucible::model::StoragePolicyArrayConsistency::RequireQuorum,
            ),
        ),
        storage_policy_artifact(
            "path-policy",
            StoragePolicyArtifactKind::Path(
                crate::production_fault_runtime::test_support::storage_path_fixture(),
            ),
        ),
    ];
    let mut topology = WorldFaultTopology {
        storage_devices,
        storage_policy_artifacts,
        ..WorldFaultTopology::default()
    };
    topology
        .storage_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));
    topology
        .storage_arrays
        .push(crucible::model::WorldStorageArray {
            id: SignalId::parse("array-a")
                .unwrap_or_else(|error| panic!("test array ID should parse: {error}")),
            device: SignalId::parse("logical-array")
                .unwrap_or_else(|error| panic!("test logical device should parse: {error}")),
            semantic_version: 1,
            layout: crucible::model::WorldStorageArrayLayout::Mirror,
            chunk_bytes: 512,
            read_quorum: 1,
            write_quorum: 1,
            members: vec![
                crucible::model::WorldStorageArrayMember {
                    id: SignalId::parse("member-a")
                        .unwrap_or_else(|error| panic!("test member ID should parse: {error}")),
                    device: SignalId::parse("member-device-a")
                        .unwrap_or_else(|error| panic!("test member device should parse: {error}")),
                    ordinal: 0,
                },
                crucible::model::WorldStorageArrayMember {
                    id: SignalId::parse("member-b")
                        .unwrap_or_else(|error| panic!("test member ID should parse: {error}")),
                    device: SignalId::parse("member-device-b")
                        .unwrap_or_else(|error| panic!("test member device should parse: {error}")),
                    ordinal: 1,
                },
            ],
            paths: vec![crucible::model::WorldStoragePath {
                id: SignalId::parse("path-a")
                    .unwrap_or_else(|error| panic!("test path ID should parse: {error}")),
                queue_depth: 8,
                policy: SignalId::parse("path-policy")
                    .unwrap_or_else(|error| panic!("test path policy should parse: {error}")),
            }],
            member_path_state: id("array-state"),
            selection_policy: id("array-selection"),
            rebuild_service: id("array-rebuild"),
            consistency_policy: id("array-consistency"),
            failure_result: id("array-error"),
            fault_domains: Vec::new(),
        });

    World::from_node_defs_and_links(
        vec![
            WorldNodeDef::Vm(vm),
            WorldNodeDef::Io(logical),
            WorldNodeDef::Io(member_a),
            WorldNodeDef::Io(member_b),
        ],
        Vec::new(),
    )
    .unwrap_or_else(|error| panic!("test array world should build: {error}"))
    .with_fault_topology(topology)
    .unwrap_or_else(|error| panic!("test array topology should validate: {error}"))
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
fn production_resolver_mutates_failure_and_volatile_cache_directives() {
    let world = world_with_storage_policies([
        storage_policy_artifact(
            "io-error",
            StoragePolicyArtifactKind::TypedResult(StoragePolicyTypedResult::Block {
                result: StoragePolicyResult::IoError,
            }),
        ),
        storage_policy_artifact(
            "write-cache",
            StoragePolicyArtifactKind::Cache(crucible::model::StoragePolicyCache {
                eviction: StoragePolicyCacheEviction::Lru,
                dirty_eviction: StoragePolicyDirtyEviction::Persist,
                power_loss_protected: true,
            }),
        ),
    ]);
    let read = BlockRequest::read(141, 0, 512);
    let failed = resolve_single_effect(
        &world,
        &read,
        FaultPhase::Resolve,
        "operation-failure",
        EffectLifetime::Opportunity,
        StorageEffectSpecification::OperationFailure {
            operations: OperationSet::new(vec![FaultOperation::StorageRead])
                .unwrap_or_else(|error| panic!("test operation set should be valid: {error}")),
            probability: crucible::model::ProbabilityMillionths::new(1_000_000)
                .unwrap_or_else(|error| panic!("test probability should be valid: {error}")),
            status: id("io-error"),
        },
        ResolvedMappingOutput::Hazard {
            probability_millionths: 1_000_000,
        },
    );
    assert_eq!(failed.error_result, Some(BlockFaultResult::IoError));

    let write = BlockRequest::write(142, 0, vec![0x5a; 512]);
    let cached = resolve_single_effect(
        &world,
        &write,
        FaultPhase::Persist,
        "volatile-cache",
        EffectLifetime::Persistent,
        StorageEffectSpecification::VolatileCache {
            capacity_bytes: PositiveU64::new("capacity_bytes", 4096)
                .unwrap_or_else(|error| panic!("test cache capacity should be valid: {error}")),
            cache_policy: id("write-cache"),
        },
        ResolvedMappingOutput::Activation { active: true },
    );
    let cache = cached
        .cache_policy
        .unwrap_or_else(|| panic!("volatile cache must resolve to a live cache policy"));
    assert_eq!(cache.capacity_bytes, 4096);
    assert_eq!(cache.eviction, BlockFaultCacheEviction::Lru);
    assert_eq!(cache.dirty_eviction, BlockFaultDirtyEviction::Persist);
    assert!(cache.power_loss_protected);

    record_production_effect_rows(
        &[
            crucible::model::EffectKind::StorageOperationFailure,
            crucible::model::EffectKind::StorageVolatileCache,
        ],
        "failure-and-volatile-cache-directives",
        "typed-io-error+bounded-lru-write-cache",
    );
}

#[test]
fn production_resolver_mutates_flash_state_directive() {
    let world = world_with_storage_policies([
        storage_policy_artifact(
            "retention",
            StoragePolicyArtifactKind::Retention(crucible::model::StoragePolicyRetention {
                minimum_age_nanos: PositiveU64::new("minimum_age_nanos", 10)
                    .unwrap_or_else(|error| panic!("test retention age should be valid: {error}")),
                wear_age_nanos: 3,
                bit_probability: crucible::model::ProbabilityMillionths::new(250_000)
                    .unwrap_or_else(|error| panic!("test probability should be valid: {error}")),
                maximum_changed_bits: BoundedCount::new(CountLimit::LargeStateEntries, 4)
                    .unwrap_or_else(|error| panic!("test bit count should be valid: {error}")),
            }),
        ),
        storage_policy_artifact(
            "read-disturb",
            StoragePolicyArtifactKind::ReadDisturb(crucible::model::StoragePolicyReadDisturb {
                read_threshold: PositiveU64::new("read_threshold", 8)
                    .unwrap_or_else(|error| panic!("test read threshold should be valid: {error}")),
                neighbor_pages: BoundedCount::new(CountLimit::LargeStateEntries, 2)
                    .unwrap_or_else(|error| panic!("test neighbor count should be valid: {error}")),
                bit_probability: crucible::model::ProbabilityMillionths::new(500_000)
                    .unwrap_or_else(|error| panic!("test probability should be valid: {error}")),
                maximum_changed_bits: BoundedCount::new(CountLimit::LargeStateEntries, 3)
                    .unwrap_or_else(|error| panic!("test bit count should be valid: {error}")),
            }),
        ),
        storage_policy_artifact(
            "program-erase",
            StoragePolicyArtifactKind::ProgramErase(crucible::model::StoragePolicyProgramErase {
                program_probability: crucible::model::ProbabilityMillionths::new(100_000)
                    .unwrap_or_else(|error| panic!("test probability should be valid: {error}")),
                erase_probability: crucible::model::ProbabilityMillionths::new(200_000)
                    .unwrap_or_else(|error| panic!("test probability should be valid: {error}")),
                worn_probability: crucible::model::ProbabilityMillionths::new(900_000)
                    .unwrap_or_else(|error| panic!("test probability should be valid: {error}")),
                partial_program: true,
                partial_erase: false,
            }),
        ),
    ]);
    let write = BlockRequest::write(143, 0, vec![0x5a; 4096]);
    let directive = resolve_single_effect(
        &world,
        &write,
        FaultPhase::Persist,
        "flash-state",
        EffectLifetime::Persistent,
        StorageEffectSpecification::FlashState {
            erase_block_bytes: PositiveU64::new("erase_block_bytes", 16_384)
                .unwrap_or_else(|error| panic!("test erase block should be valid: {error}")),
            program_page_bytes: PositiveU64::new("program_page_bytes", 4096)
                .unwrap_or_else(|error| panic!("test program page should be valid: {error}")),
            endurance_cycles: PositiveU64::new("endurance_cycles", 1_000)
                .unwrap_or_else(|error| panic!("test endurance should be valid: {error}")),
            retention_rule: id("retention"),
            read_disturb_rule: id("read-disturb"),
            program_erase_rule: id("program-erase"),
        },
        ResolvedMappingOutput::Activation { active: true },
    );
    assert_eq!(directive.persistence_media_rules.len(), 1);
    let flash = &directive.persistence_media_rules[0];
    assert_eq!(flash.erase_block_bytes, 16_384);
    assert_eq!(flash.program_page_bytes, 4096);
    assert_eq!(flash.endurance_cycles, 1_000);
    assert_eq!(flash.retention.maximum_changed_bits, 4);
    assert_eq!(flash.read_disturb.neighbor_pages, 2);
    assert!(flash.program_erase.partial_program);
    assert!(!flash.program_erase.partial_erase);

    record_production_effect_rows(
        &[crucible::model::EffectKind::StorageFlashState],
        "flash-state-resolves-complete-media-policy",
        "geometry+retention+read-disturb+program-erase",
    );
}

#[test]
fn production_resolver_mutates_controller_lifecycle_directive() {
    let world = world_with_storage_policies([
        storage_policy_artifact(
            "controller-error",
            StoragePolicyArtifactKind::TypedResult(StoragePolicyTypedResult::Block {
                result: StoragePolicyResult::IoError,
            }),
        ),
        storage_policy_artifact(
            "controller-reset",
            StoragePolicyArtifactKind::ControllerTransition(
                crucible::model::StoragePolicyControllerTransition {
                    transition: crucible::model::StorageControllerTransition::Reset,
                    failure_result: id("controller-error"),
                    unadmitted: crucible::model::StoragePolicyTransitionUnadmitted::Reject,
                    queued:
                        crucible::model::StoragePolicyTransitionPendingOperation::RetryPreserveId,
                    executing: crucible::model::StoragePolicyTransitionPendingOperation::Fail,
                    resolved: crucible::model::StoragePolicyTransitionResolvedOperation::Complete,
                    completed_undelivered:
                        crucible::model::StoragePolicyTransitionUndeliveredOperation::Complete,
                    controller_buffer: crucible::model::StoragePolicyTransitionState::Lose,
                    volatile_cache: crucible::model::StoragePolicyTransitionState::Preserve,
                    request_ids:
                        crucible::model::StoragePolicyTransitionRequestIds::NewEpochFromZero,
                    duplicate_history: crucible::model::StoragePolicyTransitionState::Lose,
                    topology: crucible::model::StoragePolicyTransitionTopology::ReenumerateDeclared,
                    recovery_nanos: PositiveU64::new("recovery_nanos", 75)
                        .unwrap_or_else(|error| panic!("test recovery should be valid: {error}")),
                },
            ),
        ),
    ]);
    let action = action(
        "controller-lifecycle",
        EffectLifetime::StateMachine,
        FaultPhase::Boundary,
        StorageEffectSpecification::ControllerLifecycle {
            transition: crucible::model::StorageControllerTransition::Reset,
            transition_policy: id("controller-reset"),
            namespaces: crucible::model::ObjectIdSet::new(vec![id("namespace-a")])
                .unwrap_or_else(|error| panic!("test namespace set should be valid: {error}")),
            paths: crucible::model::ObjectIdSet::new(vec![id("path-a")])
                .unwrap_or_else(|error| panic!("test path set should be valid: {error}")),
        },
        ResolvedMappingOutput::Activation { active: true },
    );
    let transition = resolve_block_controller_transition(&world, &action)
        .unwrap_or_else(|error| panic!("controller lifecycle should resolve: {error}"));
    assert_eq!(transition.failure_result, BlockFaultResult::IoError);
    assert_eq!(transition.unadmitted, BlockTransitionUnadmitted::Reject);
    assert_eq!(transition.queued, BlockTransitionPending::RetryPreserveId);
    assert_eq!(transition.executing, BlockTransitionPending::Fail);
    assert_eq!(transition.controller_buffer, BlockTransitionState::Lose);
    assert_eq!(transition.volatile_cache, BlockTransitionState::Preserve);
    assert_eq!(
        transition.request_ids,
        BlockTransportRequestIds::NewEpochFromZero
    );
    assert_eq!(transition.recovery_nanos, 75);

    record_production_effect_rows(
        &[crucible::model::EffectKind::StorageControllerLifecycle],
        "controller-lifecycle-resolves-complete-transition",
        "request-epoch+pending-queues+volatile-state+recovery-coordinate",
    );
}

#[test]
fn production_resolver_mutates_storage_array_state_directive() {
    let world = world_with_declared_storage_array();
    let action = action(
        "array-state",
        EffectLifetime::StateMachine,
        FaultPhase::Resolve,
        StorageEffectSpecification::ArrayState {
            layout: id("array-a"),
            member_path_state: id("array-state"),
            selection_policy: id("array-selection"),
            rebuild_service: id("array-rebuild"),
            consistency_policy: id("array-consistency"),
            failure_result: id("array-error"),
        },
        ResolvedMappingOutput::Activation { active: true },
    );
    let policy = resolve_storage_array_policy(&world, &action)
        .unwrap_or_else(|error| panic!("storage array policy should resolve: {error}"));
    assert_eq!(policy.array, id("array-a"));
    assert_eq!(
        policy.layout,
        crucible::model::WorldStorageArrayLayout::Mirror
    );
    assert_eq!(policy.read_quorum, 1);
    assert_eq!(policy.write_quorum, 1);
    assert_eq!(policy.members.len(), 2);
    assert!(policy.members[0].online);
    assert!(!policy.members[1].online);
    assert_eq!(policy.online_paths, 1);
    assert_eq!(
        policy.selection,
        crucible::model::StoragePolicyArraySelection::LowestHealthy
    );
    assert_eq!(policy.rebuild.chunk_bytes.get(), 512);
    assert_eq!(policy.failure_result, BlockFaultResult::IoError);

    record_production_effect_rows(
        &[crucible::model::EffectKind::StorageArrayState],
        "storage-array-resolves-complete-member-path-policy",
        "member-state+path-state+quorum+rebuild+consistency",
    );
}

#[test]
fn every_non_success_block_policy_result_maps_exactly() {
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
