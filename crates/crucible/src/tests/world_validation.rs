//! World topology, launch-input, and validation-matrix unit tests.

use super::*;

trait DecisionRecorderTestExt {
    fn draw_u64_accepted(&mut self, stream: RngStreamId) -> u64;
}

impl DecisionRecorderTestExt for DecisionRecorder {
    fn draw_u64_accepted(&mut self, stream: RngStreamId) -> u64 {
        self.draw_u64(stream)
            .unwrap_or_else(|error| panic!("test RNG draw should be accepted: {error}"))
    }
}

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
        seeded_recorder.draw_u64_accepted(node_stream.clone()),
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

#[path = "world_validation/temporal_graph.rs"]
mod temporal_graph;

pub(super) use temporal_graph::*;
