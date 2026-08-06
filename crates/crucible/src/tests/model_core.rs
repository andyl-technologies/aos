//! Core model, scenario identity, and step-transition unit tests.

use super::*;

#[test]
fn step_appends_decision_without_mutating_parent() {
    let config = Configuration::genesis(ScenarioDef::from_canonical_material(
        "crucible.test.step",
        "scenario=stub",
    ));
    let decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("root"),
        value: 42,
    });

    let child = step(&config, decision.clone());

    assert!(config.schedule.is_empty());
    assert_eq!(child.schedule.decisions(), &[decision]);
}

#[test]
fn step_is_pure_temporal_graph_edge_constructor() {
    for seed in 0..64 {
        let parent = Configuration {
            def: generated_scenario(seed),
            schedule: generated_schedule(seed, 4),
        };
        let original_parent = parent.clone();
        let decision = generated_decision(seed, 64);

        let child = step(&parent, decision.clone());

        assert_eq!(parent, original_parent);
        assert_eq!(child.def, parent.def);
        assert_ne!(child, parent);
        assert_eq!(child.schedule.len(), parent.schedule.len() + 1);
        assert_eq!(
            child.schedule.prefix(parent.schedule.len()),
            Ok(parent.schedule.clone())
        );
        assert_eq!(child.schedule.decisions().last(), Some(&decision));
        assert_eq!(child.id(), child.content_hash());
    }
}

#[test]
fn schedule_prefix_bounds_are_checked() {
    let schedule = Schedule::empty().appended(Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name("root"),
        value: 1,
    }));

    let prefix = schedule.prefix(1);
    assert!(prefix.is_ok());
    assert_eq!(prefix.as_ref().map(Schedule::len), Ok(1));
    let error = match schedule.prefix(2) {
        Ok(_) => panic!("prefix beyond schedule length should fail"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        ScheduleError::PrefixTooLong {
            requested: 2,
            available: 1,
        }
    ));
    assert_eq!(
        error.to_string(),
        "schedule prefix length 2 exceeds available length 1"
    );
}

#[test]
fn time_vocabulary_converts_icount_and_virtual_instants_exactly() {
    let shift = match Shift::new(4) {
        Ok(shift) => shift,
        Err(error) => panic!("valid shift should construct: {error}"),
    };
    let icount = Icount { retired: 17 };
    let instant = match icount.to_virtual(shift) {
        Ok(instant) => instant,
        Err(error) => panic!("valid icount conversion should succeed: {error}"),
    };
    let unaligned = VirtualInstant { nanos: 275 };

    assert_eq!(instant, VirtualInstant { nanos: 272 });
    assert_eq!(instant.to_icount_floor(shift), Ok(icount));
    assert_eq!(instant.to_icount_ceil(shift), Ok(icount));
    assert_eq!(unaligned.to_icount_floor(shift), Ok(Icount { retired: 17 }));
    assert_eq!(unaligned.to_icount_ceil(shift), Ok(Icount { retired: 18 }));
    let alias: SimInstant = instant;
    assert_eq!(alias, instant);
}

#[test]
fn time_vocabulary_keeps_duration_and_offset_distinct() {
    let earlier = VirtualInstant { nanos: 40 };
    let later = VirtualInstant { nanos: 100 };
    let duration = SimDuration { nanos: 25 };

    assert_eq!(later.duration_since(earlier), SimDuration { nanos: 60 });
    assert_eq!(earlier.duration_since(later), SimDuration { nanos: 0 });
    assert_eq!(earlier + duration, VirtualInstant { nanos: 65 });
    assert_eq!(
        duration + SimDuration { nanos: 5 },
        SimDuration { nanos: 30 }
    );
    assert_eq!(duration * 3, SimDuration { nanos: 75 });
    assert_eq!(
        VirtualInstant { nanos: 10 }.with_skew(SimOffset { nanos: -15 }),
        VirtualInstant::EPOCH
    );
    assert_eq!(
        VirtualInstant { nanos: 10 }.with_skew(SimOffset { nanos: 15 }),
        VirtualInstant { nanos: 25 }
    );
}

#[test]
fn time_vocabulary_rejects_invalid_shift_and_virtual_time_overflow() {
    let invalid = Shift { bits: 64 };
    let valid = Shift { bits: 63 };

    assert_eq!(
        Shift::new(64),
        Err(TimeConversionError::InvalidShift { shift: invalid })
    );
    assert_eq!(
        Icount { retired: 1 }.to_virtual(invalid),
        Err(TimeConversionError::InvalidShift { shift: invalid })
    );
    assert_eq!(
        Icount { retired: 2 }.to_virtual(valid),
        Err(TimeConversionError::VirtualTimeOverflow {
            icount: Icount { retired: 2 },
            shift: valid,
        })
    );
}

#[test]
fn clock_skew_applies_fixed_point_drift_to_guest_reads_only() {
    let scheduler_time = VirtualInstant { nanos: 100 };
    let skew = NodeClockSkew {
        offset: SimOffset { nanos: -10 },
        drift_rate: drift_rate(3, 2),
    };

    assert_eq!(
        skew.guest_visible_time(scheduler_time),
        Ok(VirtualInstant { nanos: 140 })
    );
    assert_eq!(scheduler_time, VirtualInstant { nanos: 100 });
    assert_eq!(
        NodeClockSkew::PERFECT.guest_visible_time(scheduler_time),
        Ok(scheduler_time)
    );
}

#[test]
fn clock_skew_uses_floor_rounding_without_floating_point() {
    let skew = NodeClockSkew {
        offset: SimOffset { nanos: 0 },
        drift_rate: drift_rate(3, 2),
    };

    assert_eq!(
        skew.guest_visible_time(VirtualInstant { nanos: 5 }),
        Ok(VirtualInstant { nanos: 7 })
    );
    assert_eq!(
        NodeClockSkew {
            offset: SimOffset { nanos: -20 },
            drift_rate: drift_rate(1, 3),
        }
        .guest_visible_time(VirtualInstant { nanos: 9 }),
        Ok(VirtualInstant::EPOCH)
    );
}

#[test]
fn clock_skew_rejects_invalid_drift_rate_and_overflow() {
    let invalid = ClockDriftRate {
        numerator: 1,
        denominator: 0,
    };
    let overflowing = ClockDriftRate {
        numerator: u64::MAX,
        denominator: 1,
    };

    assert_eq!(
        ClockDriftRate::new(1, 0),
        Err(TimeConversionError::InvalidDriftRate {
            drift_rate: invalid,
        })
    );
    assert_eq!(
        invalid.apply_floor(VirtualInstant { nanos: 1 }),
        Err(TimeConversionError::InvalidDriftRate {
            drift_rate: invalid,
        })
    );
    assert_eq!(
        overflowing.apply_floor(VirtualInstant { nanos: 2 }),
        Err(TimeConversionError::GuestVisibleTimeOverflow {
            virtual_time: VirtualInstant { nanos: 2 },
            drift_rate: overflowing,
        })
    );
    assert_eq!(
        NodeClockSkew {
            offset: SimOffset { nanos: 1 },
            drift_rate: ClockDriftRate::ONE,
        }
        .guest_visible_time(VirtualInstant { nanos: u64::MAX }),
        Err(TimeConversionError::GuestVisibleTimeOffsetOverflow {
            virtual_time: VirtualInstant { nanos: u64::MAX },
            offset: SimOffset { nanos: 1 },
        })
    );
    assert_eq!(
        NodeClockSkew {
            offset: SimOffset { nanos: 1 },
            drift_rate: invalid,
        }
        .scenario_hash_material(),
        Err(TimeConversionError::InvalidDriftRate {
            drift_rate: invalid,
        })
    );
}

#[test]
fn clock_skew_hash_material_omits_perfect_clock_and_records_overrides() {
    let base = "scenario=clock-skew\nnode=a";
    let perfect_material = material_with_skew(base, NodeClockSkew::default());
    let explicit_perfect_material = material_with_skew(base, NodeClockSkew::PERFECT);
    let equivalent_perfect_material = material_with_skew(
        base,
        NodeClockSkew {
            offset: SimOffset { nanos: 0 },
            drift_rate: drift_rate(2, 2),
        },
    );
    let skewed = NodeClockSkew {
        offset: SimOffset { nanos: 50 },
        drift_rate: drift_rate(1001, 1000),
    };
    let skewed_material = material_with_skew(base, skewed);

    assert_eq!(NodeClockSkew::PERFECT.scenario_hash_material(), Ok(None));
    assert_eq!(perfect_material, base);
    assert_eq!(explicit_perfect_material, base);
    assert_eq!(equivalent_perfect_material, base);
    assert!(skewed_material.contains("clock_skew_offset_ns=50"));
    assert!(skewed_material.contains("clock_drift_rate=1001/1000"));
    assert!(skewed_material.contains("clock_drift_rounding=floor"));
    assert!(skewed_material.contains("clock_skew_applies_to=guest-visible-only"));
    assert!(skewed_material.contains("clock_skew_scheduling_axis=unskewed-icount-derived"));
    assert_ne!(
        ScenarioDef::from_canonical_material("crucible.test.clock-skew", &perfect_material).id(),
        ScenarioDef::from_canonical_material("crucible.test.clock-skew", &skewed_material).id(),
    );
}

#[test]
fn canonical_material_builds_stable_scenario_identity() {
    let first = ScenarioDef::from_canonical_material("crucible.test.scenario", "field=a\nvalue=1");
    let second = ScenarioDef::from_canonical_material("crucible.test.scenario", "field=a\nvalue=1");
    let changed_material =
        ScenarioDef::from_canonical_material("crucible.test.scenario", "field=a\nvalue=2");
    let changed_domain =
        ScenarioDef::from_canonical_material("crucible.test.other", "field=a\nvalue=1");

    assert_eq!(first, second);
    assert_ne!(first.id(), changed_material.id());
    assert_ne!(first.id(), changed_domain.id());
}

#[test]
fn world_node_launch_inputs_are_portable_and_identity_bearing() {
    let blob_ref = |label: &str| {
        ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
            "crucible.test.node-launch-inputs.blob",
            label,
        ))
    };
    let kernel = blob_ref("kernel");
    let root_image = blob_ref("root-image");
    let initrd = blob_ref("initrd");
    let ready_point = ReadyPoint::FixedIcount {
        icount: Icount { retired: 77 },
    };
    let cmdline = "console=ttyS0 root=/dev/vda ro";
    let base_node = WorldNode {
        id: node_id("vm"),
        arch: VmArchitecture::Aarch64,
        memory_mib: 2048,
        cmdline: cmdline.to_owned(),
        ready_point: ready_point.clone(),
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: 2,
        icount_shift: 1,
        kernel: Some(kernel),
        root_image: Some(root_image),
        initrd: Some(initrd),
    };
    let base_world = world_from_nodes(vec![base_node.clone()]);
    let base_scenario = base_world.scenario_def();
    let template_scenario = ScenarioBuilder::new()
        .node(
            "vm",
            NodeTemplate::fixed_icount(Icount { retired: 77 })
                .arch(VmArchitecture::Aarch64)
                .memory_mib(2048)
                .cmdline(cmdline)
                .white_box(WhiteBoxPolicy::Enabled)
                .smp_vcpus(2)
                .icount_shift(1)
                .kernel(kernel)
                .root_image(root_image)
                .initrd(initrd),
        )
        .build()
        .unwrap_or_else(|error| panic!("template scenario should be valid: {error}"));
    let material = String::from_utf8(base_world.canonical_bytes())
        .unwrap_or_else(|error| panic!("world material should be utf8: {error}"));
    let toml = base_world
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("world TOML should serialize: {error}"));
    let host_path_toml = toml.replacen(&kernel.to_uri(), "/nix/store/kernel", 1);
    let round_trip_binary = World::from_compact_binary(&base_world.to_compact_binary())
        .unwrap_or_else(|error| panic!("world binary should parse: {error}"));

    assert_eq!(template_scenario, base_scenario);
    assert_eq!(
        base_world.id(),
        ContentHash::from_canonical_material("crucible.model.world.v3", &material)
    );
    assert_eq!(base_world.vm_nodes().len(), 1);
    assert_eq!(base_world.vm_nodes()[0].arch, VmArchitecture::Aarch64);
    assert_eq!(base_world.vm_nodes()[0].memory_mib, 2048);
    assert_eq!(base_world.vm_nodes()[0].cmdline, cmdline);
    assert_eq!(base_world.vm_nodes()[0].ready_point, ready_point);
    assert_eq!(base_world.vm_nodes()[0].white_box, WhiteBoxPolicy::Enabled);
    assert_eq!(base_world.vm_nodes()[0].smp_vcpus, 2);
    assert_eq!(base_world.vm_nodes()[0].icount_shift, 1);
    assert_eq!(base_world.vm_nodes()[0].kernel, Some(kernel));
    assert_eq!(base_world.vm_nodes()[0].root_image, Some(root_image));
    assert_eq!(base_world.vm_nodes()[0].initrd, Some(initrd));
    assert_eq!(
        World::from_canonical_toml(&toml)
            .unwrap_or_else(|error| panic!("world TOML should parse: {error}")),
        base_world
    );
    assert_eq!(round_trip_binary, base_world);
    assert!(toml.contains("arch = \"aarch64\""));
    assert!(toml.contains("memory_mib = 2048"));
    assert!(toml.contains("cmdline = \"console=ttyS0 root=/dev/vda ro\""));
    assert!(material.contains("arch=aarch64"));
    assert!(material.contains("memory_mib=2048"));
    assert!(material.contains(&format!("cmdline_len={}", cmdline.len())));
    assert!(material.contains("cmdline=console=ttyS0 root=/dev/vda ro"));

    let assert_identity_changes = |label: &str, node: WorldNode| {
        let changed_world = world_from_nodes(vec![node]);
        assert_ne!(base_world.id(), changed_world.id(), "{label}");
        assert_ne!(
            base_scenario.id(),
            changed_world.scenario_def().id(),
            "{label}"
        );
    };
    assert_identity_changes(
        "architecture must affect identity",
        WorldNode {
            arch: VmArchitecture::X86_64,
            ..base_node.clone()
        },
    );
    assert_identity_changes(
        "memory size must affect identity",
        WorldNode {
            memory_mib: 4096,
            ..base_node.clone()
        },
    );
    assert_identity_changes(
        "kernel command line must affect identity",
        WorldNode {
            cmdline: format!("{cmdline} quiet"),
            ..base_node.clone()
        },
    );
    assert_identity_changes(
        "kernel blob must affect identity",
        WorldNode {
            kernel: Some(blob_ref("kernel-v2")),
            ..base_node.clone()
        },
    );
    assert_identity_changes(
        "root image blob must affect identity",
        WorldNode {
            root_image: Some(blob_ref("root-image-v2")),
            ..base_node.clone()
        },
    );
    assert_identity_changes(
        "initrd blob must affect identity",
        WorldNode {
            initrd: Some(blob_ref("initrd-v2")),
            ..base_node.clone()
        },
    );
    assert_identity_changes(
        "fixed vCPU count must affect identity",
        WorldNode {
            smp_vcpus: 3,
            ..base_node.clone()
        },
    );
    assert_identity_changes(
        "fixed icount shift must affect identity",
        WorldNode {
            icount_shift: 2,
            ..base_node.clone()
        },
    );
    assert_identity_changes(
        "ready point must affect identity",
        WorldNode {
            ready_point: ReadyPoint::ConsoleMarker {
                marker: String::from("ready"),
            },
            ..base_node.clone()
        },
    );
    assert_identity_changes(
        "white-box opt-in must affect identity",
        WorldNode {
            white_box: WhiteBoxPolicy::Disabled,
            ..base_node.clone()
        },
    );

    assert!(matches!(
        World::from_nodes(vec![WorldNode {
            memory_mib: 0,
            ..base_node
        }]),
        Err(EngineError::WorldNodeMemoryMibZero { node }) if node == node_id("vm")
    ));
    assert!(matches!(
        ContentAddressedBlobRef::parse("kernel", "/nix/store/kernel"),
        Err(EngineError::ScenarioImageReferenceNotContentAddressed { field, value })
            if field == "kernel" && value == "/nix/store/kernel"
    ));
    assert!(matches!(
        World::from_canonical_toml(&host_path_toml),
        Err(EngineError::ScenarioImageReferenceNotContentAddressed { field, value })
            if field == "kernel" && value == "/nix/store/kernel"
    ));
}

#[test]
fn configuration_id_is_content_addressed_by_def_and_schedule() {
    let scenario =
        ScenarioDef::from_canonical_material("crucible.test.configuration", "node=a\nseed=1");
    let same_scenario =
        ScenarioDef::from_canonical_material("crucible.test.configuration", "node=a\nseed=1");
    let base_schedule = Schedule::empty().appended(Decision::RngDraw(RngDecision {
        stream: RngStreamId::for_node("node-a/faults"),
        value: 7,
    }));
    let same = Configuration {
        def: same_scenario,
        schedule: base_schedule.clone(),
    };
    let changed_schedule = Configuration {
        def: scenario.clone(),
        schedule: base_schedule.appended(Decision::FaultFires(FaultDecision {
            at: VirtualTime { ticks: 1 },
            fault: FaultId {
                name: String::from("link-drop"),
            },
            fired: true,
        })),
    };
    let base = Configuration {
        def: scenario,
        schedule: same.schedule.clone(),
    };

    assert_eq!(base, same);
    assert_eq!(base.id(), same.id());
    assert_eq!(base.id(), base.content_hash());
    assert_ne!(base.schedule, changed_schedule.schedule);
    assert_ne!(base.id(), changed_schedule.id());
}

#[test]
fn configuration_id_property_covers_generated_def_schedule_pairs() {
    let mut checked_cases = 0;

    for seed in 0..64 {
        let def = generated_scenario(seed);
        let schedule = generated_schedule(seed, 6);
        let base = Configuration {
            def: def.clone(),
            schedule: schedule.clone(),
        };
        let same = Configuration {
            def: generated_scenario(seed),
            schedule: schedule.clone(),
        };
        let changed_schedule = Configuration {
            def: def.clone(),
            schedule: schedule.appended(generated_decision(seed, 99)),
        };
        let same_length_changed_schedule = Configuration {
            def: def.clone(),
            schedule: generated_schedule(seed + 10_000, 6),
        };
        let reordered_schedule = Configuration {
            def: def.clone(),
            schedule: swap_first_two_decisions(&base.schedule),
        };
        let changed_def = Configuration {
            def: generated_scenario(seed + 1_000),
            schedule: base.schedule.clone(),
        };

        assert_eq!(base, same);
        assert_eq!(base.id(), same.id());
        assert_eq!(base.id(), base.content_hash());
        assert_ne!(base.schedule, changed_schedule.schedule);
        assert_ne!(base.id(), changed_schedule.id());
        assert_eq!(
            base.schedule.len(),
            same_length_changed_schedule.schedule.len()
        );
        assert_ne!(base.schedule, same_length_changed_schedule.schedule);
        assert_ne!(base.id(), same_length_changed_schedule.id());
        assert_eq!(base.schedule.len(), reordered_schedule.schedule.len());
        assert_ne!(base.schedule, reordered_schedule.schedule);
        assert_ne!(base.id(), reordered_schedule.id());
        assert_ne!(base.def, changed_def.def);
        assert_ne!(base.id(), changed_def.id());

        checked_cases += 1;
    }

    assert_eq!(checked_cases, 64);
}

#[test]
fn reduce_is_pure_over_scenario_and_schedule() {
    let scenario = ScenarioDef::from_canonical_material("crucible.test.reduce", "node=a\nseed=1");
    let other_scenario =
        ScenarioDef::from_canonical_material("crucible.test.reduce", "node=a\nseed=2");
    let first_decision = Decision::RngDraw(RngDecision {
        stream: RngStreamId::for_node("node-a/faults"),
        value: 7,
    });
    let second_decision = Decision::FaultFires(FaultDecision {
        at: VirtualTime { ticks: 10 },
        fault: FaultId {
            name: String::from("link-drop"),
        },
        fired: true,
    });
    let schedule = Schedule::empty()
        .appended(first_decision.clone())
        .appended(second_decision.clone());
    let reordered = Schedule::empty()
        .appended(second_decision)
        .appended(first_decision);

    let first = reduce(&scenario, &schedule);
    let second = reduce(&scenario, &schedule);
    let changed_scenario = reduce(&other_scenario, &schedule);
    let changed_order = reduce(&scenario, &reordered);

    assert_eq!(first, second);
    assert_ne!(first, changed_scenario);
    assert_ne!(first, changed_order);
}

#[test]
fn reduce_is_prefix_closed_by_schedule_hash() {
    let scenario =
        ScenarioDef::from_canonical_material("crucible.test.reduce", "node=a\nseed=prefix");
    let root = Configuration::genesis(scenario.clone());
    let child = step(
        &root,
        Decision::DeliveryOrder(DeliveryOrderDecision {
            at: VirtualTime { ticks: 4 },
            order: vec![event_key(4, 1), event_key(4, 2)],
        }),
    );
    let grandchild = step(
        &child,
        Decision::AppRandom(AppRandomDecision {
            node: NodeId {
                name: String::from("node-a"),
            },
            stream: RngStreamId::for_node("app/request"),
            request_id: 3,
            width: 16,
            value: 0xace,
        }),
    );
    let child_prefix = match grandchild.schedule.prefix(1) {
        Ok(prefix) => prefix,
        Err(error) => panic!("valid prefix should not fail: {error}"),
    };
    let root_reduced = reduce(&scenario, &root.schedule);
    let child_reduced = reduce(&scenario, &child.schedule);
    let child_prefix_reduced = reduce(&scenario, &child_prefix);
    let grandchild_reduced = reduce(&scenario, &grandchild.schedule);

    assert_eq!(child.schedule, child_prefix);
    assert_eq!(child_reduced, child_prefix_reduced);
    assert_ne!(root_reduced, child_reduced);
    assert_ne!(child_reduced, grandchild_reduced);
    assert_ne!(root.content_hash(), child.content_hash());
    assert_ne!(child.content_hash(), grandchild.content_hash());
    assert_ne!(
        child.schedule.content_hash(),
        grandchild.schedule.content_hash()
    );
}

#[test]
fn resume_continue_matches_uninterrupted_run_by_fingerprint() {
    let scenario = generated_scenario(0x500);
    let mut uninterrupted = DecisionRecorder::new(Configuration::genesis(scenario.clone()));
    for index in 0..8 {
        record_representative_decision(&mut uninterrupted, index);
    }
    let uninterrupted = uninterrupted.into_configuration();

    let mut prefix = DecisionRecorder::new(Configuration::genesis(scenario));
    for index in 0..4 {
        record_representative_decision(&mut prefix, index);
    }
    let prefix = prefix.into_configuration();
    let prefix_len = prefix.schedule.len();
    let mut resumed = DecisionRecorder::new(prefix.clone());
    for index in 4..8 {
        record_representative_decision(&mut resumed, index);
    }
    let resumed = resumed.into_configuration();

    assert_eq!(
        uninterrupted.schedule.prefix(prefix_len),
        Ok(prefix.schedule.clone())
    );
    assert_ne!(
        configuration_execution_fingerprint(&prefix),
        configuration_execution_fingerprint(&uninterrupted)
    );
    assert_eq!(uninterrupted, resumed);
    assert_eq!(
        configuration_execution_fingerprint(&uninterrupted),
        configuration_execution_fingerprint(&resumed)
    );
}

#[test]
fn instantiate_loads_exact_snapshot_without_genesis() {
    let scenario = generated_scenario(41);
    let config = Configuration {
        def: scenario,
        schedule: generated_schedule(41, 3),
    };
    let graph =
        match TemporalGraph::empty().with_cached_snapshot(&config, fat_checkpoint_for(&config)) {
            Ok(graph) => graph,
            Err(error) => panic!("valid exact snapshot should register: {error}"),
        };

    let runtime = match instantiate(&graph, &config) {
        Ok(runtime) => runtime,
        Err(error) => panic!("exact snapshot should instantiate without genesis: {error}"),
    };

    assert_eq!(runtime.configuration, config.id());
    assert_eq!(runtime.id, reduced_state_id(&config));
}

#[test]
fn instantiate_replays_from_nearest_cached_ancestor() {
    let scenario = generated_scenario(43);
    let config = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(43, 5),
    };
    let near_ancestor = Configuration {
        def: scenario.clone(),
        schedule: match config.schedule.prefix(3) {
            Ok(schedule) => schedule,
            Err(error) => panic!("valid ancestor prefix should construct: {error}"),
        },
    };
    let far_ancestor = Configuration {
        def: scenario,
        schedule: match config.schedule.prefix(1) {
            Ok(schedule) => schedule,
            Err(error) => panic!("valid ancestor prefix should construct: {error}"),
        },
    };
    let graph = match TemporalGraph::empty()
        .with_cached_snapshot(&far_ancestor, fat_checkpoint_for(&far_ancestor))
        .and_then(|graph| {
            graph.with_cached_snapshot(&near_ancestor, fat_checkpoint_for(&near_ancestor))
        }) {
        Ok(graph) => graph,
        Err(error) => panic!("valid ancestor snapshots should register: {error}"),
    };

    let selected_ancestor = match graph.nearest_cached_ancestor(&config) {
        Ok(Some(ancestor)) => ancestor,
        Ok(None) => panic!("nearest cached ancestor should exist"),
        Err(error) => panic!("ancestor lookup should succeed: {error}"),
    };
    let runtime = match instantiate(&graph, &config) {
        Ok(runtime) => runtime,
        Err(error) => panic!("ancestor replay should instantiate: {error}"),
    };

    assert_eq!(selected_ancestor, near_ancestor);
    assert_eq!(runtime.configuration, config.id());
    assert_eq!(runtime.id, reduced_state_id(&config));
}

#[test]
fn instantiate_loads_baked_genesis_for_genesis() {
    let scenario = generated_scenario(47);
    let genesis = Configuration::genesis(scenario.clone());
    let graph = match TemporalGraph::empty()
        .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };

    let runtime = match instantiate(&graph, &genesis) {
        Ok(runtime) => runtime,
        Err(error) => panic!("baked genesis should instantiate genesis: {error}"),
    };

    assert_eq!(runtime.configuration, genesis.id());
    assert_eq!(runtime.id, reduced_state_id(&genesis));
}

#[test]
fn instantiate_replays_from_baked_genesis_for_uncached_descendant() {
    let scenario = generated_scenario(53);
    let genesis = Configuration::genesis(scenario.clone());
    let config = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(53, 4),
    };
    let graph = match TemporalGraph::empty()
        .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };

    let runtime = match instantiate(&graph, &config) {
        Ok(runtime) => runtime,
        Err(error) => panic!("baked-genesis replay should instantiate descendant: {error}"),
    };

    assert_eq!(runtime.configuration, config.id());
    assert_eq!(runtime.id, reduced_state_id(&config));
}

#[test]
fn temporal_graph_save_materializes_fat_checkpoint_keyed_by_configuration() {
    let scenario = generated_scenario(75);
    let genesis = Configuration::genesis(scenario.clone());
    let config = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(75, 2),
    };
    let mut graph = match TemporalGraph::empty()
        .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };

    let checkpoint = match graph.save_checkpoint(&config) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("save should materialize through instantiate: {error}"),
    };
    let saved_again = match graph.save_checkpoint(&config) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("duplicate save should reuse checkpoint: {error}"),
    };

    assert_eq!(checkpoint, saved_again);
    assert_eq!(checkpoint.configuration, config.id());
    assert_eq!(checkpoint.kind, CheckpointKind::Fat);
    assert_eq!(graph.cached_snapshot(&config), Some(&checkpoint));
    assert_eq!(graph.cached_snapshot_count(), 1);
    assert!(matches!(
        graph.checkpoint_node(config.id()),
        Some(source) if source.kind == CheckpointKind::Thin && source.state.is_none()
    ));
    assert!(graph.contains_configuration(&config));
    assert_eq!(
        instantiate(&graph, &config).map(|runtime| runtime.id),
        Ok(reduced_state_id(&config))
    );
}

#[test]
fn compact_checkpoint_decode_rejects_inconsistent_outer_shape() {
    let config = Configuration::genesis(generated_scenario(87));
    let valid = fat_checkpoint_for(&config);

    let mut fat_without_state = valid.clone();
    fat_without_state.state = None;
    assert!(matches!(
        Checkpoint::from_compact_binary(&fat_without_state.to_compact_binary()),
        Err(EngineError::ScenarioSerialization { reason })
            if reason == "fat checkpoint is missing materialized state"
    ));

    let mut thin_with_state = Checkpoint::new(config.id(), config.id(), CheckpointKind::Thin);
    thin_with_state.state = valid.state.clone();
    assert!(matches!(
        Checkpoint::from_compact_binary(&thin_with_state.to_compact_binary()),
        Err(EngineError::ScenarioSerialization { reason })
            if reason == "thin checkpoint carries materialized state"
    ));

    let mut identity_mismatch = valid;
    identity_mismatch.id = ContentHash::from_canonical_material(
        "crucible.test.invalid-checkpoint",
        "identity-mismatch",
    );
    assert!(matches!(
        Checkpoint::from_compact_binary(&identity_mismatch.to_compact_binary()),
        Err(EngineError::ScenarioSerialization { reason })
            if reason == "checkpoint id does not match configuration id"
    ));
}

#[test]
fn temporal_graph_materialized_cache_keeps_thin_checkpoint_source_of_truth() {
    let scenario = generated_scenario(76);
    let genesis = Configuration::genesis(scenario.clone());
    let config = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(76, 3),
    };
    let mut graph = match TemporalGraph::empty()
        .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };

    let thin = match graph.record_thin_checkpoint(&config) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("thin checkpoint should record: {error}"),
    };
    let fat = match graph.materialize_checkpoint(&config) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("hot checkpoint should materialize: {error}"),
    };
    let source = match graph.checkpoint_node(config.id()) {
        Some(checkpoint) => checkpoint,
        None => panic!("source checkpoint should remain recorded"),
    };

    assert_eq!(thin.id, config.id());
    assert_eq!(thin.kind, CheckpointKind::Thin);
    assert!(thin.state.is_none());
    assert_eq!(fat.id, thin.id);
    assert_eq!(fat.kind, CheckpointKind::Fat);
    assert!(fat.state.is_some());
    assert_eq!(source, &thin);
    assert_eq!(graph.cached_snapshot(&config), Some(&fat));
}

#[test]
fn temporal_graph_evicts_fat_checkpoint_back_to_thin_without_state_change() {
    let scenario = generated_scenario(80);
    let genesis = Configuration::genesis(scenario.clone());
    let config = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(80, 3),
    };
    let mut graph = match TemporalGraph::empty()
        .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };
    let fat = match graph.materialize_checkpoint(&config) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("checkpoint should materialize: {error}"),
    };
    let exact_runtime = match instantiate(&graph, &config) {
        Ok(runtime) => runtime,
        Err(error) => panic!("exact cached checkpoint should instantiate: {error}"),
    };

    let thin = match graph.evict_fat_checkpoint_to_thin(&config) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("fat checkpoint should evict to thin: {error}"),
    };
    let replay_runtime = match instantiate(&graph, &config) {
        Ok(runtime) => runtime,
        Err(error) => panic!("thin checkpoint should replay from ancestor: {error}"),
    };

    assert_eq!(fat.id, thin.id);
    assert_eq!(thin.kind, CheckpointKind::Thin);
    assert!(thin.state.is_none());
    assert!(graph.cached_snapshot(&config).is_none());
    assert_eq!(graph.cached_snapshot_count(), 0);
    assert_eq!(exact_runtime, replay_runtime);
}

#[test]
fn temporal_graph_gc_cache_collection_preserves_replay_oracle_path() {
    let scenario = generated_scenario(84);
    let genesis = Configuration::genesis(scenario.clone());
    let config = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(84, 3),
    };
    let mut graph = match TemporalGraph::empty()
        .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };
    let fat = match graph.materialize_checkpoint(&config) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("checkpoint should materialize before cache GC: {error}"),
    };
    let before_check = match graph.replay_checkpoint(&config, &fat) {
        Ok(check) => check,
        Err(error) => panic!("fat snapshot should match thin derivation before GC: {error}"),
    };

    let thin = match graph.collect_cached_snapshot(&config) {
        Ok(Some(checkpoint)) => checkpoint,
        Ok(None) => panic!("fat cache entry should exist before collection"),
        Err(error) => panic!("fat cache collection should succeed: {error}"),
    };
    let replay_runtime = match instantiate(&graph, &config) {
        Ok(runtime) => runtime,
        Err(error) => {
            panic!("thin derivation should remain realizable after cache GC: {error}")
        }
    };
    let after_check = match graph.replay_checkpoint(&config, &fat) {
        Ok(check) => check,
        Err(error) => {
            panic!("fat snapshot should still match thin derivation after GC: {error}")
        }
    };

    assert_eq!(thin.kind, CheckpointKind::Thin);
    assert!(thin.state.is_none());
    assert!(graph.cached_snapshot(&config).is_none());
    assert_eq!(before_check, after_check);
    assert_eq!(replay_runtime.configuration, config.id());
    assert_eq!(replay_runtime.id, reduced_state_id(&config));
}

#[test]
fn temporal_graph_materialization_policy_keeps_cold_or_over_budget_nodes_thin() {
    let scenario = generated_scenario(81);
    let genesis = Configuration::genesis(scenario.clone());
    let first = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(81, 1),
    };
    let cold = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(82, 1),
    };
    let over_budget = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(83, 1),
    };
    let mut graph = match TemporalGraph::empty()
        .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };
    let policy = MaterializationPolicy::with_budget(1);

    let hot = match graph.materialize_hot_checkpoint(
        &first,
        policy,
        MaterializationTrigger::RepeatedForkSource,
    ) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("first hot checkpoint should materialize: {error}"),
    };
    let cold_checkpoint =
        match graph.materialize_hot_checkpoint(&cold, policy, MaterializationTrigger::Cold) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("cold checkpoint should remain thin: {error}"),
        };
    let over_budget_checkpoint = match graph.materialize_hot_checkpoint(
        &over_budget,
        policy,
        MaterializationTrigger::SharedReplayPath,
    ) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("over-budget hot checkpoint should remain thin: {error}"),
    };

    assert_eq!(hot.kind, CheckpointKind::Fat);
    assert_eq!(graph.cached_snapshot_count(), 1);
    assert_eq!(cold_checkpoint.kind, CheckpointKind::Thin);
    assert_eq!(over_budget_checkpoint.kind, CheckpointKind::Thin);
    assert!(graph.cached_snapshot(&cold).is_none());
    assert!(graph.cached_snapshot(&over_budget).is_none());

    match graph.evict_fat_checkpoint_to_thin(&first) {
        Ok(checkpoint) => assert_eq!(checkpoint.kind, CheckpointKind::Thin),
        Err(error) => panic!("eviction should free the materialization budget: {error}"),
    }
    let interactive = match graph.materialize_hot_checkpoint(
        &over_budget,
        policy,
        MaterializationTrigger::InteractiveTarget,
    ) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("interactive target should materialize after eviction: {error}"),
    };

    assert_eq!(interactive.kind, CheckpointKind::Fat);
    assert_eq!(graph.cached_snapshot(&over_budget), Some(&interactive));
    assert_eq!(graph.cached_snapshot_count(), 1);
}

#[test]
fn temporal_graph_savevm_hedge_keeps_unreliable_device_checkpoint_thin() {
    let scenario = generated_scenario(85);
    let genesis = Configuration::genesis(scenario.clone());
    let config = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(85, 2),
    };
    let device = device_id("block0");
    let checkpoint = fat_checkpoint_with_device_overlay(&config, device.clone());
    let hedge = SavevmCompletenessHedge::with_unreliable_devices([device.clone()]);
    let mut hedged_graph = match TemporalGraph::empty()
        .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };

    let allowed = match hedged_graph.cache_snapshot_with_savevm_hedge(
        &config,
        checkpoint.clone(),
        &SavevmCompletenessHedge::verified(),
    ) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("verified device snapshot should cache as fat: {error}"),
    };
    assert_eq!(hedged_graph.cached_snapshot(&config), Some(&allowed));

    let thin =
        match hedged_graph.cache_snapshot_with_savevm_hedge(&config, checkpoint.clone(), &hedge) {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("unreliable device snapshot should fall back to thin: {error}"),
        };
    let runtime = match instantiate(&hedged_graph, &config) {
        Ok(runtime) => runtime,
        Err(error) => panic!("thin fallback should replay to the target: {error}"),
    };

    assert!(SavevmCompletenessHedge::verified().allows_checkpoint(&checkpoint));
    assert!(!hedge.allows_checkpoint(&checkpoint));
    assert!(hedge.unreliable_devices().contains(&device));
    assert_eq!(allowed.kind, CheckpointKind::Fat);
    assert_eq!(thin.kind, CheckpointKind::Thin);
    assert!(thin.state.is_none());
    assert!(hedged_graph.cached_snapshot(&config).is_none());
    assert_eq!(hedged_graph.cached_snapshot_count(), 0);
    assert_eq!(runtime.configuration, config.id());
    assert_eq!(runtime.id, reduced_state_id(&config));
}

#[test]
fn temporal_graph_savevm_full_s3_fallback_evicts_hot_checkpoint_to_thin() {
    let scenario = generated_scenario(86);
    let genesis = Configuration::genesis(scenario.clone());
    let config = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(86, 2),
    };
    let mut graph = match TemporalGraph::empty()
        .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };
    let fat = match graph.materialize_checkpoint(&config) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("checkpoint should materialize before fallback: {error}"),
    };
    let exact_runtime = match instantiate(&graph, &config) {
        Ok(runtime) => runtime,
        Err(error) => panic!("exact snapshot should instantiate before fallback: {error}"),
    };
    let hedge = SavevmCompletenessHedge::thin_replay_until_full_s3();
    let policy = MaterializationPolicy::with_budget(8);

    let thin = match graph.materialize_hot_checkpoint_with_savevm_hedge(
        &config,
        policy,
        MaterializationTrigger::InteractiveTarget,
        &hedge,
    ) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("fallback should evict hot checkpoint to thin: {error}"),
    };
    let replay_runtime = match instantiate(&graph, &config) {
        Ok(runtime) => runtime,
        Err(error) => panic!("thin fallback should replay after eviction: {error}"),
    };

    assert!(!hedge.fat_snapshot_default());
    assert!(hedge.unreliable_devices().is_empty());
    assert_eq!(fat.kind, CheckpointKind::Fat);
    assert_eq!(thin.id, fat.id);
    assert_eq!(thin.kind, CheckpointKind::Thin);
    assert!(thin.state.is_none());
    assert!(graph.cached_snapshot(&config).is_none());
    assert_eq!(graph.cached_snapshot_count(), 0);
    assert_eq!(exact_runtime, replay_runtime);
}

#[test]
fn temporal_graph_replay_checkpoint_is_on_demand_replay_oracle() {
    let scenario = generated_scenario(77);
    let genesis = Configuration::genesis(scenario.clone());
    let config = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(77, 3),
    };
    let mut graph = match TemporalGraph::empty()
        .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };
    let checkpoint = match graph.save_checkpoint(&config) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("save should materialize checkpoint: {error}"),
    };

    let check = match graph.replay_checkpoint(&config, &checkpoint) {
        Ok(check) => check,
        Err(error) => panic!("fat checkpoint should match thin replay: {error}"),
    };
    let genesis_checkpoint = match graph.save_checkpoint(&genesis) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("genesis save should reuse baked checkpoint: {error}"),
    };
    let genesis_check = match graph.replay_checkpoint(&genesis, &genesis_checkpoint) {
        Ok(check) => check,
        Err(error) => panic!("baked genesis should match thin replay: {error}"),
    };
    let mut corrupted = checkpoint.clone();
    corrupted.id = ContentHash::from_canonical_material(
        "crucible.test.fat-checkpoint.corrupt",
        "wrong-runtime",
    );
    let mismatch = match graph.replay_checkpoint(&config, &corrupted) {
        Ok(_) => panic!("corrupt fat checkpoint should fail replay oracle"),
        Err(error) => error,
    };

    assert_eq!(check.configuration, config.id());
    assert_eq!(check.fat_checkpoint, checkpoint.id);
    assert_eq!(check.thin_checkpoint, checkpoint.id);
    assert_eq!(genesis_check.configuration, genesis.id());
    assert_eq!(genesis_check.fat_checkpoint, genesis_checkpoint.id);
    assert_eq!(genesis_check.thin_checkpoint, genesis_checkpoint.id);
    assert!(matches!(
        mismatch,
        EngineError::CheckpointIdentityMismatch { checkpoint, .. } if checkpoint == corrupted.id
    ));
}

#[test]
fn temporal_graph_replay_checkpoint_rejects_materialized_payload_drift() {
    let node = node_id("node");
    let world = world_from_nodes(vec![WorldNode {
        id: node.clone(),
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
    }]);
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let config = step(&genesis, generated_decision(84, 0));
    let baked = match bake(&world) {
        Ok(genesis) => genesis,
        Err(error) => panic!("world bake should produce a genesis checkpoint: {error}"),
    };
    let mut graph = match TemporalGraph::empty().with_baked_genesis(&scenario, baked) {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };
    let checkpoint = match graph.materialize_checkpoint(&config) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("checkpoint should materialize through thin replay: {error}"),
    };
    let mut corrupted = checkpoint.clone();
    corrupted.node_blobs.insert(
        node,
        NodeBlobRef::baked(ContentHash::from_canonical_material(
            "crucible.test.materialized-payload-drift",
            "wrong-vm-blob",
        )),
    );
    corrupted.state = Some(MaterializedState::from_checkpoint_parts(
        &corrupted.node_icounts,
        &corrupted.node_blobs,
    ));
    let expected_state = checkpoint
        .state
        .as_ref()
        .map(|state| state.id)
        .unwrap_or_else(|| panic!("valid materialized checkpoint should carry state"));
    let actual_state = corrupted
        .state
        .as_ref()
        .map(|state| state.id)
        .unwrap_or_else(|| panic!("corrupted checkpoint should carry recomputed state"));

    let error = match graph.replay_checkpoint(&config, &corrupted) {
        Ok(_) => panic!("payload drift should fail replay-oracle validation"),
        Err(error) => error,
    };

    assert_eq!(corrupted.id, checkpoint.id);
    assert_eq!(corrupted.configuration, checkpoint.configuration);
    assert_eq!(corrupted.parent, checkpoint.parent);
    assert_eq!(corrupted.schedule_delta, checkpoint.schedule_delta);
    assert_ne!(actual_state, expected_state);
    assert!(matches!(
        error,
        EngineError::ReplayOracleMismatch {
            checkpoint: corrupt_id,
            expected,
            actual,
        } if corrupt_id == corrupted.id
            && expected == expected_state
            && actual == actual_state
    ));
}

#[test]
fn temporal_graph_replay_oracle_rejects_cached_snapshot_to_thin() {
    let node = node_id("node");
    let world = world_from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 12 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }]);
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let config = step(&genesis, generated_decision(87, 0));
    let baked = match bake(&world) {
        Ok(genesis) => genesis,
        Err(error) => panic!("world bake should produce a genesis checkpoint: {error}"),
    };
    let mut source = match TemporalGraph::empty().with_baked_genesis(&scenario, baked.clone()) {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };
    let checkpoint = match source.materialize_checkpoint(&config) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("checkpoint should materialize through thin replay: {error}"),
    };
    let checks = match source.validate_cached_snapshots_with_replay_oracle() {
        Ok(checks) => checks,
        Err(error) => panic!("valid cache should pass replay-oracle admission: {error}"),
    };
    let mut corrupted = checkpoint.clone();
    corrupted.node_blobs.insert(
        node,
        NodeBlobRef::baked(ContentHash::from_canonical_material(
            "crucible.test.cached-replay-oracle",
            "wrong-cached-vm-blob",
        )),
    );
    corrupted.state = Some(MaterializedState::from_checkpoint_parts(
        &corrupted.node_icounts,
        &corrupted.node_blobs,
    ));
    let expected_state = checkpoint
        .state
        .as_ref()
        .map(|state| state.id)
        .unwrap_or_else(|| panic!("valid materialized checkpoint should carry state"));
    let actual_state = corrupted
        .state
        .as_ref()
        .map(|state| state.id)
        .unwrap_or_else(|| panic!("corrupted checkpoint should carry recomputed state"));
    let corrupted_for_validation = corrupted.clone();
    let mut graph = match TemporalGraph::empty().with_baked_genesis(&scenario, baked.clone()) {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };
    if let Err(error) = graph.cache_snapshot(&config, corrupted) {
        panic!("corrupt-but-loadable cache should insert before oracle admission: {error}");
    }

    let load_error = match instantiate(&graph, &config) {
        Ok(_) => panic!("public exact-cache instantiate should reject corrupt fat snapshot"),
        Err(error) => error,
    };
    let error = match graph.materialize_checkpoint(&config) {
        Ok(_) => panic!("corrupt cached snapshot should fail replay-oracle admission"),
        Err(error) => error,
    };
    let thin = match graph.checkpoint_node(config.id()) {
        Some(checkpoint) => checkpoint,
        None => panic!("replay-oracle rejection should keep the thin checkpoint node"),
    };
    let runtime = match instantiate(&graph, &config) {
        Ok(runtime) => runtime,
        Err(error) => {
            panic!("thin derivation should remain realizable after rejection: {error}")
        }
    };
    let mut validation_graph = match TemporalGraph::empty().with_baked_genesis(&scenario, baked) {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };
    if let Err(error) = validation_graph.cache_snapshot(&config, corrupted_for_validation) {
        panic!("corrupt-but-loadable cache should insert before whole-cache validation: {error}");
    }
    let validation_error = match validation_graph.validate_cached_snapshots_with_replay_oracle() {
        Ok(_) => panic!("whole-cache replay-oracle validation should reject corrupt cache"),
        Err(error) => error,
    };

    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].configuration, config.id());
    assert!(matches!(
        load_error,
        EngineError::ReplayOracleMismatch {
            checkpoint: corrupt_id,
            expected,
            actual,
        } if corrupt_id == checkpoint.id
            && expected == expected_state
            && actual == actual_state
    ));
    assert!(matches!(
        error,
        EngineError::ReplayOracleMismatch {
            checkpoint: corrupt_id,
            expected,
            actual,
        } if corrupt_id == checkpoint.id
            && expected == expected_state
            && actual == actual_state
    ));
    assert!(matches!(
        validation_error,
        EngineError::ReplayOracleMismatch {
            checkpoint: corrupt_id,
            expected,
            actual,
        } if corrupt_id == checkpoint.id
            && expected == expected_state
            && actual == actual_state
    ));
    assert!(graph.cached_snapshot(&config).is_none());
    assert!(validation_graph.cached_snapshot(&config).is_none());
    assert_eq!(thin.kind, CheckpointKind::Thin);
    assert!(thin.state.is_none());
    assert_eq!(runtime.configuration, config.id());
    assert_eq!(runtime.id, reduced_state_id(&config));
}

#[test]
fn temporal_graph_replay_oracle_admits_cached_ancestors_before_target() {
    let node = node_id("node");
    let world = world_from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 13 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }]);
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let ancestor = step(&genesis, generated_decision(88, 0));
    let target = step(&ancestor, generated_decision(88, 1));
    let baked = match bake(&world) {
        Ok(genesis) => genesis,
        Err(error) => panic!("world bake should produce a genesis checkpoint: {error}"),
    };
    let mut source = match TemporalGraph::empty().with_baked_genesis(&scenario, baked.clone()) {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };
    let ancestor_checkpoint = match source.materialize_checkpoint(&ancestor) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("ancestor checkpoint should materialize: {error}"),
    };
    let corrupt_ancestor =
        corrupt_checkpoint_node_blob(&ancestor_checkpoint, &node, "wrong-ancestor-vm-blob");
    let mut unsafe_replay_graph = TemporalGraph::empty();
    if let Err(error) = unsafe_replay_graph.cache_snapshot(&ancestor, corrupt_ancestor.clone()) {
        panic!("corrupt-but-loadable ancestor cache should insert: {error}");
    }
    let corrupt_runtime = match instantiate(&unsafe_replay_graph, &target) {
        Ok(runtime) => runtime,
        Err(error) => panic!("target setup should replay from corrupt ancestor: {error}"),
    };
    let corrupt_target = match Checkpoint::from_recorded_configuration(
        &target,
        Some(&ancestor),
        VirtualTime::default(),
        corrupt_runtime.node_icounts,
        CheckpointKind::Fat,
        corrupt_runtime.node_blobs,
    ) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("corrupt target checkpoint should remain loadable: {error}"),
    };
    let expected_state = ancestor_checkpoint
        .state
        .as_ref()
        .map(|state| state.id)
        .unwrap_or_else(|| panic!("valid ancestor checkpoint should carry state"));
    let actual_state = corrupt_ancestor
        .state
        .as_ref()
        .map(|state| state.id)
        .unwrap_or_else(|| panic!("corrupted ancestor checkpoint should carry state"));
    let mut graph = match TemporalGraph::empty().with_baked_genesis(&scenario, baked) {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };
    if let Err(error) = graph.cache_snapshot(&ancestor, corrupt_ancestor) {
        panic!("corrupt-but-loadable ancestor cache should insert before admission: {error}");
    }
    if let Err(error) = graph.cache_snapshot(&target, corrupt_target) {
        panic!("corrupt-but-loadable target cache should insert before admission: {error}");
    }

    let error = match graph.materialize_checkpoint(&target) {
        Ok(_) => {
            panic!("cached target should not validate against an unadmitted corrupt ancestor")
        }
        Err(error) => error,
    };

    assert!(matches!(
        error,
        EngineError::ReplayOracleMismatch {
            checkpoint: corrupt_id,
            expected,
            actual,
        } if corrupt_id == ancestor_checkpoint.id
            && expected == expected_state
            && actual == actual_state
    ));
    assert!(graph.cached_snapshot(&ancestor).is_none());
    assert!(graph.cached_snapshot(&target).is_none());
    assert!(matches!(
        graph.checkpoint_node(ancestor.id()),
        Some(checkpoint) if checkpoint.kind == CheckpointKind::Thin && checkpoint.state.is_none()
    ));
    assert!(matches!(
        graph.checkpoint_node(target.id()),
        Some(checkpoint) if checkpoint.kind == CheckpointKind::Thin && checkpoint.state.is_none()
    ));
}

#[test]
fn temporal_graph_replay_checkpoint_ignores_exact_target_snapshot() {
    let scenario = generated_scenario(78);
    let genesis = Configuration::genesis(scenario.clone());
    let config = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(78, 2),
    };
    let mut materializer = match TemporalGraph::empty()
        .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };
    let checkpoint = match materializer.save_checkpoint(&config) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("save should materialize checkpoint: {error}"),
    };
    let graph = match TemporalGraph::empty().with_cached_snapshot(&config, checkpoint.clone()) {
        Ok(graph) => graph,
        Err(error) => panic!("valid exact target snapshot should register: {error}"),
    };

    let error = match graph.replay_checkpoint(&config, &checkpoint) {
        Ok(_) => panic!("replay oracle should not load the exact target snapshot"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        EngineError::MissingBakedGenesis { scenario: missing } if missing == scenario.id()
    ));
}

#[test]
fn temporal_graph_checkpoint_resume_resolves_cached_snapshot_without_thin_node() {
    let scenario = generated_scenario(178);
    let genesis = Configuration::genesis(scenario.clone());
    let config = Configuration {
        def: scenario.clone(),
        schedule: generated_schedule(178, 2),
    };
    let mut materializer = match TemporalGraph::empty()
        .with_baked_genesis(&scenario, genesis_checkpoint_for(&genesis))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };
    let checkpoint = match materializer.save_checkpoint(&config) {
        Ok(checkpoint) => checkpoint,
        Err(error) => panic!("save should materialize checkpoint: {error}"),
    };
    let mut graph = match TemporalGraph::empty().with_cached_snapshot(&config, checkpoint) {
        Ok(graph) => graph,
        Err(error) => panic!("valid cached snapshot should register: {error}"),
    };

    assert!(graph.checkpoint_node(config.id()).is_none());
    assert_eq!(graph.checkpoint_configuration(config.id()), Some(&config));
    let resumed = match graph.resume_checkpoint(config.id()) {
        Ok(runtime) => runtime,
        Err(error) => panic!("cached snapshot checkpoint should resume: {error}"),
    };
    assert_eq!(resumed.configuration, config.id());
    assert_eq!(resumed.runtime.configuration, config.id());
}

#[test]
fn temporal_graph_frontier_enumeration_deduplicates_by_configuration_id() {
    let scenario = generated_scenario(79);
    let frontier = Configuration::genesis(scenario.clone());
    let duplicate = generated_decision(79, 0);
    let distinct = generated_decision(79, 1);
    let mut graph = match TemporalGraph::empty()
        .with_baked_genesis(&scenario, genesis_checkpoint_for(&frontier))
    {
        Ok(graph) => graph,
        Err(error) => panic!("valid baked genesis should register: {error}"),
    };

    let first = graph.enumerate_frontier(
        &frontier,
        vec![duplicate.clone(), duplicate, distinct.clone()],
    );
    let first = match first {
        Ok(children) => children,
        Err(error) => panic!("first frontier enumeration should record children: {error}"),
    };
    let second =
        match graph.enumerate_frontier(&frontier, vec![generated_decision(79, 0), distinct]) {
            Ok(children) => children,
            Err(error) => panic!("second frontier enumeration should reuse children: {error}"),
        };

    assert_eq!(first.len(), 2);
    assert!(first.iter().all(|child| !child.already_recorded));
    assert_eq!(second.len(), 2);
    assert!(second.iter().all(|child| child.already_recorded));
    assert_eq!(graph.recorded_configuration_count(), 3);
    assert_eq!(graph.checkpoint_node_count(), 3);
    assert!(graph.contains_configuration(&frontier));
    for child in first {
        assert!(graph.contains_configuration(&child.configuration));
        assert_eq!(child.configuration.def, frontier.def);
        assert_eq!(
            child.configuration.schedule.len(),
            frontier.schedule.len() + 1
        );
    }
}

#[test]
fn bake_content_addresses_world_as_shared_fat_genesis_checkpoint() {
    let world = generated_world(71);
    let same_world = generated_world(71);
    let other_world = generated_world(72);
    let def = world.scenario_def();
    let genesis = Configuration::genesis(def.clone());

    let baked = match bake(&world) {
        Ok(genesis) => genesis,
        Err(error) => panic!("world bake should produce a genesis checkpoint: {error}"),
    };
    let baked_again = match bake(&same_world) {
        Ok(genesis) => genesis,
        Err(error) => panic!("same world bake should be deterministic: {error}"),
    };
    let other_baked = match bake(&other_world) {
        Ok(genesis) => genesis,
        Err(error) => panic!("other world bake should produce a checkpoint: {error}"),
    };

    assert_eq!(world, same_world);
    assert_eq!(world.scenario_def(), same_world.scenario_def());
    assert_eq!(baked, baked_again);
    assert_ne!(baked.checkpoint.id, other_baked.checkpoint.id);
    assert_ne!(def, other_world.scenario_def());
    assert_eq!(baked.checkpoint.configuration, genesis.id());
    assert_eq!(baked.checkpoint.kind, CheckpointKind::Fat);
}

#[test]
fn baked_world_genesis_instantiates_as_first_resume() {
    let world = generated_world(73);
    let def = world.scenario_def();
    let genesis = Configuration::genesis(def.clone());
    let baked = match bake(&world) {
        Ok(genesis) => genesis,
        Err(error) => panic!("world bake should produce a genesis checkpoint: {error}"),
    };
    let graph = match TemporalGraph::empty().with_baked_genesis(&def, baked) {
        Ok(graph) => graph,
        Err(error) => panic!("baked world genesis should register: {error}"),
    };

    let runtime = match instantiate(&graph, &genesis) {
        Ok(runtime) => runtime,
        Err(error) => panic!("baked world genesis should instantiate by load: {error}"),
    };

    assert_eq!(runtime.configuration, genesis.id());
    assert_eq!(runtime.id, reduced_state_id(&genesis));
}

#[test]
fn world_ready_point_policies_are_hashed_canonically() {
    let fixed = ready_node(
        "a",
        ReadyPoint::FixedIcount {
            icount: Icount { retired: 42 },
        },
    );
    let idle = ready_node(
        "b",
        ReadyPoint::NetworkIdle {
            window: SimDuration { nanos: 1_000 },
        },
    );
    let console = ready_node(
        "c",
        ReadyPoint::ConsoleMarker {
            marker: String::from("crucible-ready"),
        },
    );
    let agent = WorldNode {
        id: node_id("d"),
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
    };

    let canonical = world_from_nodes_and_links(
        vec![fixed.clone(), idle.clone(), console.clone(), agent.clone()],
        vec![link("a", "b")],
    );
    let reordered =
        world_from_nodes_and_links(vec![agent, console, idle, fixed], vec![link("a", "b")]);
    let changed = world_from_nodes(vec![ready_node(
        "a",
        ReadyPoint::FixedIcount {
            icount: Icount { retired: 43 },
        },
    )]);
    let baked = match bake(&canonical) {
        Ok(genesis) => genesis,
        Err(error) => panic!("canonical ready-point world should bake: {error}"),
    };
    let baked_again = match bake(&reordered) {
        Ok(genesis) => genesis,
        Err(error) => panic!("reordered ready-point world should bake: {error}"),
    };
    let manually_reordered = match World::from_recorded_parts(
        canonical.id,
        canonical.vm_nodes().iter().rev().cloned().collect(),
        canonical.links().iter().rev().cloned().collect(),
    ) {
        Ok(world) => world,
        Err(error) => panic!("manually reordered ready-point world should be valid: {error}"),
    };
    let manually_baked = match bake(&manually_reordered) {
        Ok(genesis) => genesis,
        Err(error) => panic!("manually reordered ready-point world should bake: {error}"),
    };

    assert_eq!(canonical.vm_nodes().len(), 4);
    assert_eq!(canonical.id, reordered.id);
    assert_eq!(canonical.vm_nodes(), reordered.vm_nodes());
    assert_eq!(canonical.scenario_def(), manually_reordered.scenario_def());
    assert_eq!(baked, baked_again);
    assert_eq!(baked, manually_baked);
    assert_ne!(canonical.id, changed.id);
    assert_ne!(
        baked.checkpoint.id,
        match bake(&changed) {
            Ok(genesis) => genesis.checkpoint.id,
            Err(error) => panic!("changed ready-point world should bake: {error}"),
        }
    );
}

#[test]
fn world_topology_hashes_nodes_and_links_canonically() {
    let node_a = ready_node(
        "a",
        ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
    );
    let node_b = ready_node(
        "b",
        ReadyPoint::FixedIcount {
            icount: Icount { retired: 2 },
        },
    );

    let canonical =
        world_from_nodes_and_links(vec![node_a.clone(), node_b.clone()], vec![link("a", "b")]);
    let reordered =
        world_from_nodes_and_links(vec![node_b.clone(), node_a.clone()], vec![link("b", "a")]);
    let without_link = world_from_nodes(vec![node_b, node_a]);
    let baked = match bake(&canonical) {
        Ok(genesis) => genesis,
        Err(error) => panic!("canonical linked world should bake: {error}"),
    };
    let baked_again = match bake(&reordered) {
        Ok(genesis) => genesis,
        Err(error) => panic!("reordered linked world should bake: {error}"),
    };
    let unlinked_baked = match bake(&without_link) {
        Ok(genesis) => genesis,
        Err(error) => panic!("unlinked world should bake: {error}"),
    };

    assert_eq!(canonical.id, reordered.id);
    assert_eq!(canonical.vm_nodes(), reordered.vm_nodes());
    assert_eq!(canonical.links(), reordered.links());
    assert_eq!(canonical.links(), [link("a", "b")].as_slice());
    assert_eq!(canonical.scenario_def(), reordered.scenario_def());
    assert_eq!(baked, baked_again);
    assert_ne!(canonical.id, without_link.id);
    assert_ne!(canonical.scenario_def(), without_link.scenario_def());
    assert_ne!(baked.checkpoint.id, unlinked_baked.checkpoint.id);
}

#[test]
fn world_topology_rejects_invalid_links() {
    let nodes = vec![
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
    ];
    let duplicate_node = World::from_nodes_and_links(
        vec![
            ready_node(
                "dup",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 1 },
                },
            ),
            ready_node(
                "dup",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 2 },
                },
            ),
        ],
        Vec::new(),
    );
    let duplicate =
        World::from_nodes_and_links(nodes.clone(), vec![link("a", "b"), link("b", "a")]);
    let unknown = World::from_nodes_and_links(nodes, vec![link("a", "missing")]);
    let self_loop = LinkDef::new(node_id("a"), node_id("a"));

    assert!(matches!(
        duplicate_node,
        Err(EngineError::DuplicateWorldNodeId { .. })
    ));
    assert!(matches!(
        duplicate,
        Err(EngineError::DuplicateWorldLink { .. })
    ));
    assert!(matches!(
        unknown,
        Err(EngineError::WorldLinkUnknownNode { node, .. }) if node == node_id("missing")
    ));
    assert!(matches!(
        self_loop,
        Err(EngineError::WorldLinkSelfLoop { node }) if node == node_id("a")
    ));
}

#[test]
fn world_link_transport_material_affects_world_identity() {
    let nodes = two_ready_nodes();
    let base = world_from_nodes_and_links(
        nodes.clone(),
        vec![transport_link("a", "b", 5, 1, 250_000, Some(1_000_000))],
    );
    let reordered = world_from_nodes_and_links(
        nodes.clone().into_iter().rev().collect(),
        vec![transport_link("b", "a", 5, 1, 250_000, Some(1_000_000))],
    );
    let changed_latency = world_from_nodes_and_links(
        nodes.clone(),
        vec![transport_link("a", "b", 6, 1, 250_000, Some(1_000_000))],
    );
    let changed_jitter = world_from_nodes_and_links(
        nodes.clone(),
        vec![transport_link("a", "b", 5, 2, 250_000, Some(1_000_000))],
    );
    let changed_loss = world_from_nodes_and_links(
        nodes.clone(),
        vec![transport_link("a", "b", 5, 1, 250_001, Some(1_000_000))],
    );
    let changed_bandwidth = world_from_nodes_and_links(
        nodes,
        vec![transport_link("a", "b", 5, 1, 250_000, Some(2_000_000))],
    );
    let base_baked = match bake(&base) {
        Ok(genesis) => genesis,
        Err(error) => panic!("base transport world should bake: {error}"),
    };
    let changed_latency_baked = match bake(&changed_latency) {
        Ok(genesis) => genesis,
        Err(error) => panic!("changed-latency transport world should bake: {error}"),
    };

    assert_eq!(base.id, reordered.id);
    assert_eq!(base.links(), reordered.links());
    assert_eq!(base.links()[0].latency(), SimDuration { nanos: 5 });
    assert_eq!(base.links()[0].jitter(), SimDuration { nanos: 1 });
    assert_eq!(base.links()[0].loss().millionths(), 250_000);
    assert_eq!(base.links()[0].bandwidth_bps(), Some(1_000_000));
    assert_ne!(base.id, changed_latency.id);
    assert_ne!(base.id, changed_jitter.id);
    assert_ne!(base.id, changed_loss.id);
    assert_ne!(base.id, changed_bandwidth.id);
    assert_eq!(base.scenario_def(), reordered.scenario_def());
    assert_ne!(base.scenario_def(), changed_latency.scenario_def());
    assert_ne!(
        base_baked.checkpoint.id,
        changed_latency_baked.checkpoint.id
    );
}

#[test]
fn world_link_transport_rejects_invalid_floor_and_loss() {
    let below_floor = LinkDef::with_transport(
        node_id("a"),
        node_id("b"),
        SimDuration { nanos: 0 },
        SimDuration { nanos: 0 },
        LinkLossProbability::ZERO,
        None,
    );
    let jitter_below_floor = LinkDef::with_transport(
        node_id("a"),
        node_id("b"),
        SimDuration { nanos: 5 },
        SimDuration { nanos: 5 },
        LinkLossProbability::ZERO,
        None,
    );
    let loss_out_of_range = LinkLossProbability::from_millionths(1_000_001);
    let duplicate_endpoint_pair = World::from_nodes_and_links(
        two_ready_nodes(),
        vec![
            transport_link("a", "b", 5, 1, 0, None),
            transport_link("b", "a", 6, 1, 0, None),
        ],
    );

    assert_eq!(MIN_LINK_LATENCY, SimDuration { nanos: 1 });
    assert_eq!(
        LinkLossProbability::ONE.millionths(),
        LinkLossProbability::from_millionths(1_000_000)
            .map(|loss| loss.millionths())
            .unwrap_or_default()
    );
    assert!(matches!(
        below_floor,
        Err(EngineError::WorldLinkLatencyBelowFloor { latency, minimum, .. })
            if latency == SimDuration { nanos: 0 } && minimum == MIN_LINK_LATENCY
    ));
    assert!(matches!(
        jitter_below_floor,
        Err(EngineError::WorldLinkJitterBelowLatencyFloor {
            latency,
            jitter,
            minimum,
            ..
        }) if latency == SimDuration { nanos: 5 }
            && jitter == SimDuration { nanos: 5 }
            && minimum == MIN_LINK_LATENCY
    ));
    assert!(matches!(
        loss_out_of_range,
        Err(EngineError::LinkLossProbabilityOutOfRange {
            millionths: 1_000_001,
            maximum: 1_000_000,
        })
    ));
    assert!(matches!(
        duplicate_endpoint_pair,
        Err(EngineError::DuplicateWorldLink { .. })
    ));
}

#[test]
fn scheduler_link_latency_floor_rejects_subfloor_before_hashing_and_enters_world_material() {
    let below_floor = LinkDef::with_transport(
        node_id("a"),
        node_id("b"),
        SimDuration { nanos: 0 },
        SimDuration::default(),
        LinkLossProbability::ZERO,
        None,
    );
    let jitter_below_floor = LinkDef::with_transport(
        node_id("a"),
        node_id("b"),
        SimDuration { nanos: 5 },
        SimDuration { nanos: 5 },
        LinkLossProbability::ZERO,
        None,
    );
    let floor_world = world_from_nodes_and_links(two_ready_nodes(), vec![link("a", "b")]);
    let material = String::from_utf8(floor_world.canonical_bytes())
        .unwrap_or_else(|error| panic!("world material should be utf8: {error}"));
    let toml = floor_world
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("world TOML should serialize: {error}"));
    let subfloor_toml = toml.replace("latency_nanos = 1", "latency_nanos = 0");
    let parsed_subfloor = World::from_canonical_toml(&subfloor_toml);
    let raised_latency_world = world_from_nodes_and_links(
        two_ready_nodes(),
        vec![transport_link("a", "b", 2, 0, 0, None)],
    );

    assert_eq!(MIN_LINK_LATENCY, SimDuration { nanos: 1 });
    assert!(matches!(
        below_floor,
        Err(EngineError::WorldLinkLatencyBelowFloor { latency, minimum, .. })
            if latency == SimDuration { nanos: 0 } && minimum == MIN_LINK_LATENCY
    ));
    assert!(matches!(
        jitter_below_floor,
        Err(EngineError::WorldLinkJitterBelowLatencyFloor {
            latency,
            jitter,
            minimum,
            ..
        }) if latency == SimDuration { nanos: 5 }
            && jitter == SimDuration { nanos: 5 }
            && minimum == MIN_LINK_LATENCY
    ));
    assert!(matches!(
        parsed_subfloor,
        Err(EngineError::WorldLinkLatencyBelowFloor { latency, minimum, .. })
            if latency == SimDuration { nanos: 0 } && minimum == MIN_LINK_LATENCY
    ));
    assert!(material.contains("min_link_latency_ns=1"));
    assert_eq!(
        floor_world.id(),
        ContentHash::from_canonical_material("crucible.model.world.v3", &material)
    );
    assert_ne!(floor_world.id(), raised_latency_world.id());
    assert_ne!(
        floor_world.scenario_def().id(),
        raised_latency_world.scenario_def().id()
    );
    assert_eq!(
        floor_world.static_topology().lookahead_graph[0].minimum_latency,
        MIN_LINK_LATENCY
    );
}

#[test]
fn world_static_topology_is_derived_from_world_only() {
    let world = world_from_nodes_and_links(
        two_ready_nodes(),
        vec![transport_link("b", "a", 10, 2, 0, None)],
    );
    let reordered = world_from_nodes_and_links(
        two_ready_nodes().into_iter().rev().collect(),
        vec![transport_link("a", "b", 10, 2, 0, None)],
    );
    let changed_latency = world_from_nodes_and_links(
        two_ready_nodes(),
        vec![transport_link("a", "b", 11, 2, 0, None)],
    );
    let genesis = Configuration::genesis(world.scenario_def());
    let scheduled = Configuration {
        def: genesis.def.clone(),
        schedule: genesis.schedule.appended(generated_decision(93, 0)),
    };

    let topology = world.static_topology();

    assert_eq!(genesis.def, scheduled.def);
    assert_ne!(genesis.schedule, scheduled.schedule);
    assert_eq!(topology, reordered.static_topology());
    assert_eq!(topology.participants, vec![node_id("a"), node_id("b")]);
    assert_eq!(
        topology.rng_streams,
        vec![
            RngStreamId::for_link(
                "link_endpoint_a_len=1\nlink_endpoint_a=a\nlink_endpoint_b_len=1\nlink_endpoint_b=b",
            ),
            RngStreamId::for_node("a"),
            RngStreamId::for_node("b"),
        ]
    );
    assert_eq!(
        topology.lookahead_graph,
        vec![
            WorldLookaheadEdge {
                from: node_id("a"),
                to: node_id("b"),
                minimum_latency: SimDuration { nanos: 8 },
            },
            WorldLookaheadEdge {
                from: node_id("b"),
                to: node_id("a"),
                minimum_latency: SimDuration { nanos: 8 },
            },
        ]
    );
    assert_eq!(topology.bake_nodes, vec![node_id("a"), node_id("b")]);
    assert_ne!(
        topology.lookahead_graph,
        changed_latency.static_topology().lookahead_graph
    );
}

#[test]
fn world_static_topology_link_rng_streams_are_collision_free() {
    let world = world_from_nodes_and_links(
        vec![
            ready_node(
                "a",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 1 },
                },
            ),
            ready_node(
                "b--c",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 2 },
                },
            ),
            ready_node(
                "a--b",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 3 },
                },
            ),
            ready_node(
                "c",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 4 },
                },
            ),
        ],
        vec![link("a", "b--c"), link("a--b", "c")],
    );

    let link_streams = world
        .static_topology()
        .rng_streams
        .into_iter()
        .filter(|stream| stream.domain == crucible_sim::DECISION_RNG_LINK_STREAM_DOMAIN)
        .collect::<Vec<_>>();

    assert_eq!(
        link_streams,
        vec![
            RngStreamId::for_link(
                "link_endpoint_a_len=1\nlink_endpoint_a=a\nlink_endpoint_b_len=4\nlink_endpoint_b=b--c",
            ),
            RngStreamId::for_link(
                "link_endpoint_a_len=4\nlink_endpoint_a=a--b\nlink_endpoint_b_len=1\nlink_endpoint_b=c",
            ),
        ]
    );
}
