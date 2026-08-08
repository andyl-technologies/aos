//! World topology, launch-input, and validation-matrix unit tests.

use super::*;

#[test]
fn seed_is_scenario_identity_and_name_hashed_stream_root() {
    let world = world_from_nodes_and_links(
        two_ready_nodes(),
        vec![transport_link("a", "b", 10, 1, 0, None)],
    );
    let expanded_world = world_from_nodes_and_links(
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
            ready_node(
                "c",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 3 },
                },
            ),
        ],
        vec![transport_link("a", "b", 10, 1, 0, None)],
    );
    let seed = Seed::from_u64(42);
    let other_seed = Seed::from_u64(43);
    let mut tail_changed_bytes = seed.bytes();
    tail_changed_bytes[31] = 1;
    let tail_changed_seed = Seed::from_bytes(tail_changed_bytes);
    let empty_plan = Plan::empty();
    let empty_properties = Properties::empty();
    let node_stream = RngStreamId::for_node("a");
    let link_stream = RngStreamId::for_link("a");
    let generic_seeded = ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.seeded-scenario",
        "world=opaque",
        seed,
    );
    let generic_other_seed = ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.seeded-scenario",
        "world=opaque",
        other_seed,
    );
    let world_streams = seeded_stream_map(world.seeded_rng_streams(seed));
    let expanded_streams = seeded_stream_map(expanded_world.seeded_rng_streams(seed));
    let mut world_node_draws = seed.fork_stream(&node_stream);
    let mut expanded_node_draws = seed.fork_stream(&node_stream);
    let mut seeded_recorder =
        DecisionRecorder::new(Configuration::genesis(world.scenario_def_with_seed(seed)));
    let mut expected_recorder_stream = seed.fork_stream(&node_stream);

    assert_eq!(
        world.scenario_def(),
        world.scenario_def_with_seed(Seed::default())
    );
    assert_eq!(
        world
            .scenario_def_with_plan_and_properties(&empty_plan, &empty_properties)
            .unwrap_or_else(|error| panic!(
                "default-seed empty components should compose: {error}"
            )),
        world
            .scenario_def_with_plan_properties_and_seed(
                &empty_plan,
                &empty_properties,
                Seed::default(),
            )
            .unwrap_or_else(|error| panic!("explicit default seed should compose: {error}"))
    );
    assert_ne!(world.scenario_def(), world.scenario_def_with_seed(seed));
    assert_ne!(
        world.scenario_def_with_seed(seed),
        world.scenario_def_with_seed(other_seed)
    );
    assert_ne!(generic_seeded.id(), generic_other_seed.id());
    assert_ne!(generic_seeded.seed(), generic_other_seed.seed());
    assert_ne!(
        Configuration::genesis(generic_seeded.clone()).id(),
        Configuration::genesis(generic_other_seed.clone()).id()
    );
    assert_ne!(
        reduce(&generic_seeded, &Schedule::empty())
            .unwrap_or_else(|error| panic!("seeded reduce should succeed: {error}"))
            .id,
        reduce(&generic_other_seed, &Schedule::empty())
            .unwrap_or_else(|error| panic!("other seeded reduce should succeed: {error}"))
            .id
    );
    assert_ne!(
        seed.stream_seed(&node_stream),
        other_seed.stream_seed(&node_stream)
    );
    assert_ne!(
        seed.stream_seed(&node_stream),
        tail_changed_seed.stream_seed(&node_stream)
    );
    for index in 0..32 {
        let mut bytes = seed.bytes();
        bytes[index] ^= 0x80;
        let changed_seed = Seed::from_bytes(bytes);
        assert_ne!(
            seed.stream_seed(&node_stream),
            changed_seed.stream_seed(&node_stream),
            "byte {index} should contribute to stream derivation"
        );
    }
    assert_ne!(
        seed.stream_seed(&node_stream),
        seed.stream_seed(&link_stream)
    );
    assert_eq!(
        seed.stream_seed(&node_stream),
        seed.fork_stream(&node_stream).seed()
    );
    assert_eq!(world_node_draws.next_u64(), expanded_node_draws.next_u64());
    assert_eq!(
        seeded_recorder.draw_u64(node_stream.clone()),
        expected_recorder_stream.next_u64()
    );

    for stream in world.static_topology().rng_streams {
        assert_eq!(
            world_streams.get(&stream),
            expanded_streams.get(&stream),
            "stream seed should be stable for existing stream {stream:?}"
        );
    }
    assert!(expanded_streams.contains_key(&RngStreamId::for_node("c")));
}

#[cfg(feature = "test-double")]
#[test]
fn world_logical_topology_ignores_physical_transport_layout() {
    let compact_layout = shmem_layout(2, 16, 3);
    let expanded_layout = shmem_layout(2, 64, 3);
    let world = world_from_nodes_and_links(
        two_ready_nodes(),
        vec![transport_link("a", "b", 5, 1, 0, None)],
    );
    let compact_world = world_with_physical_layout_id(&world, compact_layout, 4096);
    let expanded_world = world_with_physical_layout_id(&world, expanded_layout, 65_536);
    let compact_baked = match bake(&compact_world) {
        Ok(genesis) => genesis,
        Err(error) => panic!("compact-layout world should bake: {error}"),
    };
    let expanded_baked = match bake(&expanded_world) {
        Ok(genesis) => genesis,
        Err(error) => panic!("expanded-layout world should bake: {error}"),
    };

    assert_ne!(compact_layout, expanded_layout);
    assert_ne!(
        compact_layout.queue_capacity,
        expanded_layout.queue_capacity
    );
    assert_ne!(compact_layout.region_size, expanded_layout.region_size);
    assert_ne!(compact_world.id, expanded_world.id);
    assert_eq!(compact_world.vm_nodes(), expanded_world.vm_nodes());
    assert_eq!(compact_world.links(), expanded_world.links());
    assert_eq!(
        compact_world.static_topology(),
        expanded_world.static_topology()
    );
    assert_eq!(compact_world.scenario_def(), expanded_world.scenario_def());
    assert_eq!(compact_baked.checkpoint.id, expanded_baked.checkpoint.id);
}

#[test]
fn world_ready_point_rejects_agent_signal_without_white_box_opt_in() {
    let invalid = World::from_nodes(vec![WorldNode {
        id: node_id("agent"),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::AgentSignal,
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }]);
    let duplicate = World::from_nodes(vec![
        ready_node(
            "dup",
            ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
        ),
        ready_node(
            "dup",
            ReadyPoint::NetworkIdle {
                window: SimDuration { nanos: 10 },
            },
        ),
    ]);
    let valid = World::from_nodes(vec![WorldNode {
        id: node_id("agent"),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::AgentSignal,
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }]);

    assert!(matches!(
        invalid,
        Err(EngineError::WhiteBoxReadyPointWithoutOptIn { .. })
    ));
    assert!(matches!(
        duplicate,
        Err(EngineError::DuplicateWorldNodeId { .. })
    ));
    assert!(valid.is_ok());
}

#[test]
fn bake_is_content_identical_for_each_ready_point_policy() {
    let policies = vec![
        (
            ReadyPoint::FixedIcount {
                icount: Icount { retired: 10 },
            },
            WhiteBoxPolicy::Disabled,
        ),
        (
            ReadyPoint::NetworkIdle {
                window: SimDuration { nanos: 250 },
            },
            WhiteBoxPolicy::Disabled,
        ),
        (
            ReadyPoint::ConsoleMarker {
                marker: String::from("ready"),
            },
            WhiteBoxPolicy::Disabled,
        ),
        (ReadyPoint::AgentSignal, WhiteBoxPolicy::Enabled),
    ];

    for (index, (ready_point, white_box)) in policies.into_iter().enumerate() {
        let node_name = format!("node-{index}");
        let node = WorldNode {
            id: node_id(&node_name),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point,
            white_box,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        };
        let world = if matches!(&node.ready_point, ReadyPoint::NetworkIdle { .. }) {
            let peer_name = format!("peer-{index}");
            world_from_nodes_and_links(
                vec![
                    node,
                    ready_node(
                        &peer_name,
                        ReadyPoint::FixedIcount {
                            icount: Icount { retired: 1 },
                        },
                    ),
                ],
                vec![link(&node_name, &peer_name)],
            )
        } else {
            world_from_nodes(vec![node])
        };
        let first = match bake(&world) {
            Ok(genesis) => genesis,
            Err(error) => panic!("ready-point policy should bake: {error}"),
        };
        let second = match bake(&world) {
            Ok(genesis) => genesis,
            Err(error) => panic!("ready-point policy should bake again: {error}"),
        };

        assert_eq!(first, second);
        assert_eq!(first.checkpoint.kind, CheckpointKind::Fat);
        assert_eq!(
            first.checkpoint.configuration,
            Configuration::genesis(world.scenario_def()).id()
        );
    }
}

#[test]
fn ready_point_policy_material_affects_baked_genesis() {
    let cases = vec![
        (
            "fixed-icount target",
            WorldNode {
                id: node_id("node"),
                arch: NodeTemplate::DEFAULT_ARCH,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point: ReadyPoint::FixedIcount {
                    icount: Icount { retired: 10 },
                },
                white_box: WhiteBoxPolicy::Disabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                kernel: None,
                root_image: None,
                initrd: None,
            },
            WorldNode {
                id: node_id("node"),
                arch: NodeTemplate::DEFAULT_ARCH,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point: ReadyPoint::FixedIcount {
                    icount: Icount { retired: 11 },
                },
                white_box: WhiteBoxPolicy::Disabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                kernel: None,
                root_image: None,
                initrd: None,
            },
        ),
        (
            "network-idle window",
            WorldNode {
                id: node_id("node"),
                arch: NodeTemplate::DEFAULT_ARCH,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point: ReadyPoint::NetworkIdle {
                    window: SimDuration { nanos: 250 },
                },
                white_box: WhiteBoxPolicy::Disabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                kernel: None,
                root_image: None,
                initrd: None,
            },
            WorldNode {
                id: node_id("node"),
                arch: NodeTemplate::DEFAULT_ARCH,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point: ReadyPoint::NetworkIdle {
                    window: SimDuration { nanos: 251 },
                },
                white_box: WhiteBoxPolicy::Disabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                kernel: None,
                root_image: None,
                initrd: None,
            },
        ),
        (
            "console marker",
            WorldNode {
                id: node_id("node"),
                arch: NodeTemplate::DEFAULT_ARCH,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point: ReadyPoint::ConsoleMarker {
                    marker: String::from("ready"),
                },
                white_box: WhiteBoxPolicy::Disabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                kernel: None,
                root_image: None,
                initrd: None,
            },
            WorldNode {
                id: node_id("node"),
                arch: NodeTemplate::DEFAULT_ARCH,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point: ReadyPoint::ConsoleMarker {
                    marker: String::from("ready-v2"),
                },
                white_box: WhiteBoxPolicy::Disabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                kernel: None,
                root_image: None,
                initrd: None,
            },
        ),
        (
            "agent-signal variant",
            WorldNode {
                id: node_id("node"),
                arch: NodeTemplate::DEFAULT_ARCH,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point: ReadyPoint::AgentSignal,
                white_box: WhiteBoxPolicy::Enabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                kernel: None,
                root_image: None,
                initrd: None,
            },
            WorldNode {
                id: node_id("node"),
                arch: NodeTemplate::DEFAULT_ARCH,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point: ReadyPoint::ConsoleMarker {
                    marker: String::from("agent-ready"),
                },
                white_box: WhiteBoxPolicy::Enabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                kernel: None,
                root_image: None,
                initrd: None,
            },
        ),
        (
            "white-box policy",
            WorldNode {
                id: node_id("node"),
                arch: NodeTemplate::DEFAULT_ARCH,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point: ReadyPoint::FixedIcount {
                    icount: Icount { retired: 10 },
                },
                white_box: WhiteBoxPolicy::Disabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                kernel: None,
                root_image: None,
                initrd: None,
            },
            WorldNode {
                id: node_id("node"),
                arch: NodeTemplate::DEFAULT_ARCH,
                memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                cmdline: String::new(),
                ready_point: ReadyPoint::FixedIcount {
                    icount: Icount { retired: 10 },
                },
                white_box: WhiteBoxPolicy::Enabled,
                smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                kernel: None,
                root_image: None,
                initrd: None,
            },
        ),
    ];

    for (label, base_node, changed_node) in cases {
        let uses_network_idle = matches!(&base_node.ready_point, ReadyPoint::NetworkIdle { .. })
            || matches!(&changed_node.ready_point, ReadyPoint::NetworkIdle { .. });
        let base = if uses_network_idle {
            world_from_nodes_and_links(
                vec![
                    base_node,
                    ready_node(
                        "peer",
                        ReadyPoint::FixedIcount {
                            icount: Icount { retired: 1 },
                        },
                    ),
                ],
                vec![link("node", "peer")],
            )
        } else {
            world_from_nodes(vec![base_node])
        };
        let changed = if uses_network_idle {
            world_from_nodes_and_links(
                vec![
                    changed_node,
                    ready_node(
                        "peer",
                        ReadyPoint::FixedIcount {
                            icount: Icount { retired: 1 },
                        },
                    ),
                ],
                vec![link("node", "peer")],
            )
        } else {
            world_from_nodes(vec![changed_node])
        };
        let base_baked = match bake(&base) {
            Ok(genesis) => genesis,
            Err(error) => panic!("{label} base world should bake: {error}"),
        };
        let changed_baked = match bake(&changed) {
            Ok(genesis) => genesis,
            Err(error) => panic!("{label} changed world should bake: {error}"),
        };

        assert_ne!(base.id, changed.id, "{label}");
        assert_ne!(
            base_baked.checkpoint.id, changed_baked.checkpoint.id,
            "{label}"
        );
    }
}

#[test]
fn baked_genesis_records_node_blob_refs_uniformly() {
    let node = ready_node(
        "node",
        ReadyPoint::FixedIcount {
            icount: Icount { retired: 64 },
        },
    );
    let world = world_from_nodes(vec![node.clone()]);
    let baked = match bake(&world) {
        Ok(genesis) => genesis,
        Err(error) => panic!("world with ready-point node should bake: {error}"),
    };
    let Some(blob) = baked.checkpoint.node_blob(&node.id) else {
        panic!("baked genesis should carry a blob ref for the node");
    };

    assert_eq!(baked.checkpoint.node_blobs.len(), 1);
    assert!(matches!(blob, NodeBlobRef::Baked(_)));
    assert_eq!(
        Some(blob),
        baked.checkpoint.node_blobs.get(&node_id("node"))
    );
}

#[test]
fn node_blob_refs_are_uniform_for_baked_and_cow_delta_state() {
    let node = node_id("node");
    let baked_blob = ContentHash::from_canonical_material("crucible.test.node-blob", "baked");
    let delta = ContentHash::from_canonical_material("crucible.test.node-blob", "delta");
    let resolved = ContentHash::from_canonical_material("crucible.test.node-blob", "resolved");
    let cow_blob = NodeBlobRef::cow_delta(baked_blob, delta, resolved);
    let materialized_blob = NodeBlobRef::baked(resolved);
    let genesis = Configuration::genesis(generated_scenario(71));
    let descendant = Configuration {
        def: genesis.def.clone(),
        schedule: generated_schedule(71, 1),
    };
    let genesis_checkpoint = Checkpoint::with_node_blobs(
        ContentHash::from_canonical_material("crucible.test.checkpoint", "genesis"),
        genesis.id(),
        CheckpointKind::Fat,
        std::collections::BTreeMap::from([(node.clone(), NodeBlobRef::baked(baked_blob))]),
    );
    let descendant_checkpoint = Checkpoint::with_node_blobs(
        ContentHash::from_canonical_material("crucible.test.checkpoint", "descendant"),
        descendant.id(),
        CheckpointKind::Fat,
        std::collections::BTreeMap::from([(node.clone(), cow_blob.clone())]),
    );

    assert!(matches!(
        genesis_checkpoint.node_blob(&node),
        Some(NodeBlobRef::Baked(_))
    ));
    assert!(matches!(
        descendant_checkpoint.node_blob(&node),
        Some(NodeBlobRef::CowDelta { resolved: hash, .. }) if *hash == resolved
    ));
    assert_eq!(
        descendant_checkpoint
            .node_blob(&node)
            .map(NodeBlobRef::content_hash),
        Some(materialized_blob.content_hash())
    );
}

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
    let engine = EngineError::NotImplemented {
        operation: "instantiate",
    };
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
    let backend_not_implemented = BackendError::NotImplemented {
        operation: "snapshot",
    };
    let backend_rejected = BackendError::Rejected {
        message: String::from("stable rejection"),
    };

    assert_eq!(engine.to_string(), "instantiate is not implemented yet");
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
        backend_not_implemented.to_string(),
        "backend operation snapshot is not implemented yet"
    );
    assert_eq!(backend_rejected.to_string(), "stable rejection");
}

pub(super) fn generated_scenario(seed: u64) -> ScenarioDef {
    ScenarioDef::from_canonical_material_with_seed(
        "crucible.test.configuration.generated",
        &format!("node=a\nseed={seed}\nimage=generated-{seed:04}"),
        Seed::from_u64(seed),
    )
}

pub(super) fn generated_world(seed: u64) -> World {
    World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.world.generated",
        &format!("nodes=a,b\nlinks=a-b\nseed={seed}"),
    ))
}

pub(super) fn world_from_nodes(nodes: Vec<WorldNode>) -> World {
    match World::from_nodes(nodes) {
        Ok(world) => world,
        Err(error) => panic!("test world should be valid: {error}"),
    }
}

pub(super) fn world_from_nodes_and_links(nodes: Vec<WorldNode>, links: Vec<LinkDef>) -> World {
    match World::from_nodes_and_links(nodes, links) {
        Ok(world) => world,
        Err(error) => panic!("test world topology should be valid: {error}"),
    }
}

pub(super) fn two_ready_nodes() -> Vec<WorldNode> {
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
pub(super) fn shmem_layout(
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
pub(super) fn world_with_physical_layout_id(
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

pub(super) fn ready_node(name: &str, ready_point: ReadyPoint) -> WorldNode {
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

pub(super) fn link(left: &str, right: &str) -> LinkDef {
    match LinkDef::new(node_id(left), node_id(right)) {
        Ok(link) => link,
        Err(error) => panic!("test link should be valid: {error}"),
    }
}

pub(super) fn transport_link(
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
        SimDuration { nanos: latency_ns },
        SimDuration { nanos: jitter_ns },
        loss,
        bandwidth_bps,
    ) {
        Ok(link) => link,
        Err(error) => panic!("test transport link should be valid: {error}"),
    }
}

pub(super) fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

pub(super) fn seeded_stream_map(
    streams: Vec<SeededRngStream>,
) -> std::collections::BTreeMap<RngStreamId, u64> {
    streams
        .into_iter()
        .map(|stream| (stream.stream, stream.seed))
        .collect()
}

pub(super) fn generated_schedule(seed: u64, len: u64) -> Schedule {
    let mut schedule = Schedule::empty();
    for index in 0..len {
        schedule = schedule.appended(generated_decision(seed, index));
    }
    schedule
}

pub(super) fn drift_rate(numerator: u64, denominator: u64) -> ClockDriftRate {
    match ClockDriftRate::new(numerator, denominator) {
        Ok(rate) => rate,
        Err(error) => panic!("test drift rate should be valid: {error}"),
    }
}

pub(super) fn material_with_skew(base: &str, skew: NodeClockSkew) -> String {
    match skew.scenario_hash_material() {
        Ok(Some(skew_material)) => format!("{base}\n{skew_material}"),
        Ok(None) => base.to_owned(),
        Err(error) => panic!("test clock skew material should be valid: {error}"),
    }
}

pub(super) fn swap_first_two_decisions(schedule: &Schedule) -> Schedule {
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

pub(super) fn record_representative_decision(recorder: &mut DecisionRecorder, index: u64) {
    match index % 3 {
        0 => {
            let _ = recorder.draw_u64(RngStreamId::for_node(format!("node-a/faults/{index}")));
        }
        1 => {
            let _ = recorder.draw_u64(RngStreamId::for_node(format!(
                "node-b/network/link-a-b/{index}"
            )));
        }
        _ => {
            let served = recorder.serve_app_random(
                NodeId {
                    name: String::from("node-a"),
                },
                RngStreamId::for_node("node-a/app-random"),
                16,
            );
            assert!(served.is_ok());
        }
    }
}

pub(super) fn configuration_execution_fingerprint(
    configuration: &Configuration,
) -> ExecutionFingerprint {
    let state = match reduce(&configuration.def, &configuration.schedule) {
        Ok(state) => state,
        Err(error) => panic!("pure configuration fingerprint should reduce: {error}"),
    };
    ExecutionFingerprint { hash: state.id }
}

pub(super) fn reduced_state_id(configuration: &Configuration) -> ContentHash {
    match reduce(&configuration.def, &configuration.schedule) {
        Ok(state) => state.id,
        Err(error) => panic!("pure reduced state should construct: {error}"),
    }
}

pub(super) fn corrupt_checkpoint_node_blob(
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

pub(super) fn fat_checkpoint_for(configuration: &Configuration) -> Checkpoint {
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

pub(super) fn genesis_checkpoint_for(configuration: &Configuration) -> GenesisCheckpoint {
    GenesisCheckpoint {
        checkpoint: fat_checkpoint_for(configuration),
    }
}

pub(super) fn event_key(virtual_time: u64, sequence: u64) -> EventKey {
    EventKey::new(
        VirtualTime {
            ticks: virtual_time,
        },
        scheduler_node("consumer"),
        scheduler_node("producer"),
        sequence,
    )
}

pub(super) fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: name.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

pub(super) fn generated_decision(seed: u64, index: u64) -> Decision {
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
        _ => Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: format!("node-{seed}"),
            },
            stream: RngStreamId::for_node(format!("app-random-{index}")),
            request_id: index,
            width: 32,
            value: seed.wrapping_mul(0x9e37_79b9) ^ index,
        }),
    }
}
