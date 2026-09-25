//! Temporal-graph admission and engine error regressions.

use super::*;

#[test]
fn instantiate_requires_baked_genesis_when_no_cached_path() {
    let scenario = generated_scenario(59);
    let config = Configuration {
        def: scenario,
        schedule: generated_schedule(59, 2),
    };

    let error = match instantiate(&TemporalGraph::empty(), &config) {
        Ok(_) => panic!("uncached path without baked genesis should fail"),
        Err(error) => error,
    };

    assert!(matches!(error, EngineError::MissingBakedGenesis { .. }));
    assert_eq!(
        error.to_string(),
        "missing baked genesis checkpoint for scenario"
    );
}

#[test]
fn temporal_graph_rejects_mismatched_or_thin_cached_snapshots() {
    let scenario = generated_scenario(61);
    let config = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(61, 2),
    };
    let other = Configuration::genesis(scenario);
    let mismatched = Checkpoint::new(config.id(), other.id(), CheckpointKind::Fat);
    let thin = Checkpoint::new(config.id(), config.id(), CheckpointKind::Thin);
    let valid = fat_checkpoint_for(&config);
    let mut wrong_scenario = valid.clone();
    wrong_scenario.scenario_ref = generated_scenario(62).id();
    let mut wrong_parent = valid.clone();
    wrong_parent.parent = None;
    let mut wrong_delta = valid.clone();
    wrong_delta.schedule_delta = Schedule::empty();

    let mismatch_error = match TemporalGraph::empty().with_cached_snapshot(&config, mismatched) {
        Ok(_) => panic!("mismatched snapshot should be rejected"),
        Err(error) => error,
    };
    let thin_error = match TemporalGraph::empty().with_cached_snapshot(&config, thin) {
        Ok(_) => panic!("thin snapshot should be rejected"),
        Err(error) => error,
    };
    let scenario_error = match TemporalGraph::empty().with_cached_snapshot(&config, wrong_scenario)
    {
        Ok(_) => panic!("scenario-ref mismatch should be rejected"),
        Err(error) => error,
    };
    let parent_error = match TemporalGraph::empty().with_cached_snapshot(&config, wrong_parent) {
        Ok(_) => panic!("parent mismatch should be rejected"),
        Err(error) => error,
    };
    let delta_error = match TemporalGraph::empty().with_cached_snapshot(&config, wrong_delta) {
        Ok(_) => panic!("schedule-delta mismatch should be rejected"),
        Err(error) => error,
    };

    assert!(matches!(
        mismatch_error,
        EngineError::CheckpointConfigurationMismatch { .. }
    ));
    assert!(matches!(
        thin_error,
        EngineError::CheckpointNotLoadable {
            kind: CheckpointKind::Thin,
            ..
        }
    ));
    assert!(matches!(
        scenario_error,
        EngineError::CheckpointTopologyMismatch {
            reason: "scenario-ref-mismatch",
            ..
        }
    ));
    assert!(matches!(
        parent_error,
        EngineError::CheckpointTopologyMismatch {
            reason: "parent-mismatch",
            ..
        }
    ));
    assert!(matches!(
        delta_error,
        EngineError::CheckpointTopologyMismatch {
            reason: "schedule-delta-mismatch",
            ..
        }
    ));
}

#[test]
fn temporal_graph_rejects_plain_cached_genesis_snapshot() {
    let scenario = generated_scenario(63);
    let genesis = Configuration::genesis(scenario);

    let error =
        match TemporalGraph::empty().with_cached_snapshot(&genesis, fat_checkpoint_for(&genesis)) {
            Ok(_) => panic!("genesis snapshot should be registered through baked genesis"),
            Err(error) => error,
        };

    assert!(matches!(
        error,
        EngineError::GenesisSnapshotMustBeBaked { .. }
    ));
    assert_eq!(
        error.to_string(),
        "genesis snapshots must be registered as baked genesis checkpoints"
    );
}

#[test]
fn temporal_graph_rejects_mismatched_or_thin_baked_genesis() {
    let scenario = generated_scenario(67);
    let genesis = Configuration::genesis(scenario.clone());
    let descendant = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(67, 1),
    };
    let mismatched = GenesisCheckpoint {
        checkpoint: fat_checkpoint_for(&descendant),
    };
    let thin = GenesisCheckpoint {
        checkpoint: Checkpoint::new(genesis.id(), genesis.id(), CheckpointKind::Thin),
    };

    let mismatch_error = match TemporalGraph::empty().with_baked_genesis(&scenario, mismatched) {
        Ok(_) => panic!("mismatched baked genesis should be rejected"),
        Err(error) => error,
    };
    let thin_error = match TemporalGraph::empty().with_baked_genesis(&scenario, thin) {
        Ok(_) => panic!("thin baked genesis should be rejected"),
        Err(error) => error,
    };

    assert!(matches!(
        mismatch_error,
        EngineError::CheckpointConfigurationMismatch { .. }
    ));
    assert!(matches!(
        thin_error,
        EngineError::CheckpointNotLoadable {
            kind: CheckpointKind::Thin,
            ..
        }
    ));
}

#[test]
fn backend_trait_is_object_safe() {
    struct StubBackend;

    impl Backend for StubBackend {
        fn advance_to_horizon(
            &mut self,
            _horizon: ExecutionHorizon,
        ) -> Result<AdvanceOutcome, BackendError> {
            Ok(AdvanceOutcome::ReachedHorizon)
        }

        fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
            Ok(ExecutionFingerprint {
                hash: ContentHash::default(),
            })
        }

        fn deliver_input(&mut self, _input: BackendInput) -> Result<(), BackendError> {
            Ok(())
        }

        fn snapshot(&mut self) -> Result<Checkpoint, BackendError> {
            Ok(Checkpoint::new(
                ContentHash::default(),
                ContentHash::default(),
                CheckpointKind::Fat,
            ))
        }

        fn restore(&mut self, _checkpoint: &Checkpoint) -> Result<(), BackendError> {
            Ok(())
        }

        fn shutdown(&mut self) -> Result<(), BackendError> {
            Ok(())
        }
    }

    let mut backend = StubBackend;
    let object: &mut dyn Backend = &mut backend;
    let advanced = object.advance_to_horizon(ExecutionHorizon {
        icount: Icount { retired: 10 },
    });

    assert_eq!(advanced, Ok(AdvanceOutcome::ReachedHorizon));
}

#[test]
fn engine_and_backend_errors_render_all_variants_deterministically() {
    let checkpoint_not_loadable = EngineError::CheckpointNotLoadable {
        checkpoint: ContentHash::default(),
        kind: CheckpointKind::Thin,
    };
    let checkpoint_mismatch = EngineError::CheckpointConfigurationMismatch {
        checkpoint: ContentHash::default(),
        expected: ContentHash::default(),
        actual: ContentHash::default(),
    };
    let missing_genesis = EngineError::MissingBakedGenesis {
        scenario: ContentHash::default(),
    };
    let genesis_must_be_baked = EngineError::GenesisSnapshotMustBeBaked {
        configuration: ContentHash::default(),
    };
    let runtime_mismatch = EngineError::RuntimeConfigurationMismatch {
        runtime: ContentHash::default(),
        expected: ContentHash::default(),
        actual: ContentHash::default(),
    };
    let replay_target_mismatch = EngineError::ReplayTargetMismatch {
        expected: ContentHash::default(),
        actual: ContentHash::default(),
    };
    let replay_oracle_mismatch = EngineError::ReplayOracleMismatch {
        checkpoint: ContentHash::default(),
        expected: ContentHash::default(),
        actual: ContentHash::default(),
    };
    let schedule_prefix = EngineError::SchedulePrefix(ScheduleError::PrefixTooLong {
        requested: 3,
        available: 2,
    });
    let backend_unsupported = BackendError::Unsupported {
        capability: "snapshot",
    };
    let backend_rejected = BackendError::Rejected {
        message: String::from("stable rejection"),
    };

    assert_eq!(
        checkpoint_not_loadable.to_string(),
        "checkpoint is not loadable because it is thin"
    );
    assert_eq!(
        checkpoint_mismatch.to_string(),
        "checkpoint configuration does not match requested configuration"
    );
    assert_eq!(
        missing_genesis.to_string(),
        "missing baked genesis checkpoint for scenario"
    );
    assert_eq!(
        genesis_must_be_baked.to_string(),
        "genesis snapshots must be registered as baked genesis checkpoints"
    );
    assert_eq!(
        runtime_mismatch.to_string(),
        "runtime configuration does not match replay start configuration"
    );
    assert_eq!(
        replay_target_mismatch.to_string(),
        "replayed suffix did not produce requested configuration"
    );
    assert_eq!(
        replay_oracle_mismatch.to_string(),
        "replay oracle mismatch between fat checkpoint and thin derivation"
    );
    assert_eq!(
        schedule_prefix.to_string(),
        "schedule prefix failed: schedule prefix length 3 exceeds available length 2"
    );
    assert_eq!(
        backend_unsupported.to_string(),
        "backend capability snapshot is unsupported"
    );
    assert_eq!(backend_rejected.to_string(), "stable rejection");
}

pub(in crate::tests) fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.configuration.generated",
        &format!("node=a\nseed={seed}\nimage=generated-{seed:04}"),
        Seed::from_u64(seed),
    )
}

pub(in crate::tests) fn generated_world(seed: u64) -> World {
    world_from_nodes(vec![ready_node(
        &format!("generated-{seed}"),
        ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
    )])
}

pub(in crate::tests) fn world_from_nodes(nodes: Vec<WorldNode>) -> World {
    match World::from_nodes(nodes) {
        Ok(world) => world,
        Err(error) => panic!("test world should be valid: {error}"),
    }
}

pub(in crate::tests) fn world_from_nodes_and_links(
    nodes: Vec<WorldNode>,
    links: Vec<LinkDef>,
) -> World {
    match World::from_nodes_and_links(nodes, links) {
        Ok(world) => world,
        Err(error) => panic!("test world topology should be valid: {error}"),
    }
}

pub(in crate::tests) fn two_ready_nodes() -> Vec<WorldNode> {
    vec![
        ready_node(
            "a",
            ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
        ),
        ready_node(
            "b",
            ReadyPoint::FixedIcount {
                icount: Icount { retired: 2 },
            },
        ),
    ]
}

#[cfg(feature = "test-double")]
pub(in crate::tests) fn shmem_layout(
    vm_node_count: u32,
    queue_capacity: u32,
    icount_shift: u32,
) -> crucible_shmem::RegionLayout {
    match crucible_shmem::RegionLayout::for_config(crucible_shmem::RegionConfig::new(
        vm_node_count,
        queue_capacity,
        icount_shift,
    )) {
        Ok(layout) => layout,
        Err(error) => panic!("shmem region layout should be valid: {error}"),
    }
}

#[cfg(feature = "test-double")]
pub(in crate::tests) fn world_with_physical_layout_id(
    world: &World,
    layout: crucible_shmem::RegionLayout,
    host_page_size: u64,
) -> World {
    match World::from_recorded_parts(
        ContentHash::from_canonical_material(
            "crucible.test.physical-transport-layout",
            &format!(
                "vm_node_count={}\nnode_count={}\nqueue_capacity={}\nring_count={}\nnode_slots_off={}\nring_hdr_off={}\nring_data_off={}\nentry_stride={}\nregion_size={}\nicount_shift={}\nhost_page_size={}",
                layout.vm_node_count,
                layout.node_count,
                layout.queue_capacity,
                layout.ring_count,
                layout.node_slots_off,
                layout.ring_hdr_off,
                layout.ring_data_off,
                layout.entry_stride,
                layout.region_size,
                layout.icount_shift,
                host_page_size
            ),
        ),
        world.vm_nodes().to_vec(),
        world.links().to_vec(),
    ) {
        Ok(world) => world,
        Err(error) => panic!("physical-layout-id world should remain valid: {error}"),
    }
}

pub(in crate::tests) fn ready_node(name: &str, ready_point: ReadyPoint) -> WorldNode {
    WorldNode {
        id: node_id(name),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point,
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

pub(in crate::tests) fn link(left: &str, right: &str) -> LinkDef {
    match LinkDef::new(node_id(left), node_id(right)) {
        Ok(link) => link,
        Err(error) => panic!("test link should be valid: {error}"),
    }
}

pub(in crate::tests) fn transport_link(
    left: &str,
    right: &str,
    latency_ns: u64,
    jitter_ns: u64,
    loss_millionths: u32,
    bandwidth_bps: Option<u64>,
) -> LinkDef {
    let loss = match LinkLossProbability::from_millionths(loss_millionths) {
        Ok(loss) => loss,
        Err(error) => panic!("test loss probability should be valid: {error}"),
    };
    match LinkDef::with_transport(
        node_id(left),
        node_id(right),
        SimDuration { ticks: latency_ns },
        SimDuration { ticks: jitter_ns },
        loss,
        bandwidth_bps,
    ) {
        Ok(link) => link,
        Err(error) => panic!("test transport link should be valid: {error}"),
    }
}

pub(in crate::tests) fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

pub(in crate::tests) fn seeded_stream_map(
    streams: Vec<SeededRngStream>,
) -> std::collections::BTreeMap<RngStreamId, u64> {
    streams
        .into_iter()
        .map(|stream| (stream.stream, stream.seed))
        .collect()
}

pub(in crate::tests) fn generated_schedule(seed: u64, len: u64) -> Schedule {
    let mut schedule = Schedule::empty();
    for index in 0..len {
        schedule = schedule.appended(generated_decision(seed, index));
    }
    schedule
}

pub(in crate::tests) fn swap_first_two_decisions(schedule: &Schedule) -> Schedule {
    let decisions = schedule.decisions();
    let mut swapped = Schedule::empty();

    if decisions.len() < 2 {
        return schedule.clone();
    }

    swapped = swapped.appended(decisions[1].clone());
    swapped = swapped.appended(decisions[0].clone());
    for decision in &decisions[2..] {
        swapped = swapped.appended(decision.clone());
    }

    swapped
}

pub(in crate::tests) fn record_representative_decision(
    recorder: &mut DecisionRecorder,
    index: u64,
) {
    match index % 3 {
        0 => {
            let _ =
                recorder.draw_u64_accepted(RngStreamId::for_node(format!("node-a/faults/{index}")));
        }
        1 => {
            let _ = recorder.draw_u64_accepted(RngStreamId::for_node(format!(
                "node-b/network/link-a-b/{index}"
            )));
        }
        _ => {
            let _value = recorder.draw_u64_accepted(RngStreamId::for_node("node-a/app-random"));
        }
    }
}

pub(in crate::tests) fn configuration_execution_fingerprint(
    configuration: &Configuration,
) -> ExecutionFingerprint {
    let state = match reduce(&configuration.def, &configuration.schedule) {
        Ok(state) => state,
        Err(error) => panic!("pure configuration fingerprint should reduce: {error}"),
    };
    ExecutionFingerprint { hash: state.id }
}

pub(in crate::tests) fn reduced_state_id(configuration: &Configuration) -> ContentHash {
    match reduce(&configuration.def, &configuration.schedule) {
        Ok(state) => state.id,
        Err(error) => panic!("pure reduced state should construct: {error}"),
    }
}

pub(in crate::tests) fn corrupt_checkpoint_node_blob(
    checkpoint: &Checkpoint,
    node: &NodeId,
    label: &str,
) -> Checkpoint {
    let mut corrupted = checkpoint.clone();
    corrupted.node_blobs.insert(
        node.clone(),
        NodeBlobRef::baked(ContentHash::from_canonical_material(
            "crucible.test.corrupt-checkpoint-node-blob",
            label,
        )),
    );
    corrupted.state = Some(MaterializedState::from_checkpoint_parts(
        &corrupted.node_icounts,
        &corrupted.node_blobs,
    ));
    corrupted
}

pub(in crate::tests) fn fat_checkpoint_for(configuration: &Configuration) -> Checkpoint {
    let parent = if configuration.is_genesis() {
        None
    } else {
        let schedule = match configuration
            .schedule
            .prefix(configuration.schedule.len().saturating_sub(1))
        {
            Ok(schedule) => schedule,
            Err(error) => panic!("test schedule prefix should build: {error}"),
        };
        Some(Configuration {
            def: configuration.def.clone(),
            schedule,
        })
    };
    match Checkpoint::from_recorded_configuration(
        configuration,
        parent.as_ref(),
        VirtualTime::default(),
        std::collections::BTreeMap::new(),
        CheckpointKind::Fat,
        std::collections::BTreeMap::new(),
    ) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("test checkpoint should be recorded-shaped: {error}"),
    }
}

pub(in crate::tests) fn genesis_checkpoint_for(configuration: &Configuration) -> GenesisCheckpoint {
    GenesisCheckpoint {
        checkpoint: fat_checkpoint_for(configuration),
    }
}

pub(in crate::tests) fn event_key(virtual_time: u64, sequence: u64) -> EventKey {
    EventKey::new(
        VirtualTime {
            ticks: virtual_time,
        },
        scheduler_node("consumer"),
        scheduler_node("producer"),
        sequence,
    )
}

pub(in crate::tests) fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

pub(in crate::tests) fn generated_decision(seed: u64, index: u64) -> Decision {
    match (seed + index) % 6 {
        0 => Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime {
                ticks: seed + index,
            },
            order: vec![
                event_key(seed + index, index),
                event_key(seed + index, index + 1),
            ],
        }),
        1 => Decision::RngDraw(RngDecision {
            stream: RngStreamId::for_node(format!("node-{seed}/network-{index}")),
            value: seed.wrapping_mul(0xd6e8_feb8_6659_fd93) ^ index,
        }),
        2 => Decision::RngDraw(RngDecision {
            stream: RngStreamId::for_node(format!("node-{seed}/stream-{index}")),
            value: seed.rotate_left((index % 31) as u32) ^ index,
        }),
        3 => Decision::Override(OverrideDecision {
            point: SchedulingPoint {
                key: format!("point-{seed}-{index}"),
            },
            choice: ChoiceTag {
                name: format!("choice-{index}"),
            },
        }),
        4 => Decision::Preemption(PreemptionDecision {
            node: NodeId {
                name: format!("node-{seed}"),
            },
            at: Icount {
                retired: seed + index + 1,
            },
            kind: PreemptionKind::VcpuSwitch {
                from_vcpu: VcpuId { index: 0 },
                to_vcpu: VcpuId { index: 1 },
            },
        }),
        _ => Decision::RngDraw(RngDecision {
            stream: RngStreamId::for_node(format!("app-random-{index}")),
            value: seed.wrapping_mul(0x9e37_79b9) ^ index,
        }),
    }
}
