    #[test]
    fn scenario_def_form_rejects_well_formedness_matrix_before_hashing() {
        let world = world_from_nodes_and_links(
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
            vec![link("a", "b")],
        );
        let changed_vcpu_world = world_from_nodes_and_links(
            vec![
                WorldNode {
                    smp_vcpus: 2,
                    ..ready_node(
                        "a",
                        ReadyPoint::FixedIcount {
                            icount: Icount { retired: 1 },
                        },
                    )
                },
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
            vec![link("a", "b")],
        );
        let changed_shift_world = world_from_nodes_and_links(
            vec![
                WorldNode {
                    icount_shift: 1,
                    ..ready_node(
                        "a",
                        ReadyPoint::FixedIcount {
                            icount: Icount { retired: 1 },
                        },
                    )
                },
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
            vec![link("a", "b")],
        );
        let duplicate_node_ids = World::from_nodes(vec![
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
        ]);
        let unknown_link_endpoint = World::from_nodes_and_links(
            vec![ready_node(
                "a",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 1 },
                },
            )],
            vec![link("a", "missing")],
        );
        let latency_below_floor = LinkDef::with_transport(
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
        let loss_out_of_range = LinkLossProbability::from_millionths(1_000_001);
        let plan_unknown_node = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime::default(),
                tag: tag("missing-node"),
                fault: MembershipFault::Crash {
                    node: node_id("missing"),
                    restart: RestartPolicy::StayDown,
                },
            }],
        );
        let plan_unknown_link = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime::default(),
                tag: tag("missing-link"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("b"),
                    endpoint_b: node_id("c"),
                    direction: PartitionDirection::Bidirectional,
                },
            }],
        );
        let unsupported_fault_param_toml = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[entry]]
kind = "activate"
at_ticks = 0
tag = "unsupported-window"

[entry.fault]
kind = "crash"
node = "a"
restart = "stay_down"
window = 10
"#;
        let unsupported_fault_param =
            Plan::from_canonical_toml_for_world(&world, unsupported_fault_param_toml);
        let unknown_direction_toml = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[entry]]
kind = "activate"
at_ticks = 0
tag = "bad-direction"

[entry.fault]
kind = "partition"
endpoint_a = "a"
endpoint_b = "b"
direction = "sideways"
"#;
        let unknown_direction = Plan::from_canonical_toml_for_world(&world, unknown_direction_toml);
        let unknown_heal_tag = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Heal {
                at: VirtualTime { ticks: 10 },
                tag: tag("never-activated"),
            }],
        );
        let negative_plan_time_toml = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[entry]]
kind = "heal"
at_ticks = -5
tag = "negative-time"
"#;
        let negative_plan_time =
            Plan::from_canonical_toml_for_world(&world, negative_plan_time_toml);
        let unknown_property_ref = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "missing",
                "missing property node",
                Property::Always {
                    predicate: named_predicate("node_alive", &["missing"]),
                },
            )],
        );
        let empty_property_compound = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "empty",
                "empty all-of",
                Property::Always {
                    predicate: Predicate::AllOf {
                        predicates: Vec::new(),
                    },
                },
            )],
        );
        let white_box_ready_point_without_opt_in = World::from_nodes(vec![WorldNode {
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
        let zero_vcpu_count = World::from_nodes(vec![WorldNode {
            id: node_id("zero-vcpu"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: 0,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }]);
        let icount_shift_too_large = World::from_nodes(vec![WorldNode {
            id: node_id("bad-shift"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: 63,
            kernel: None,
            root_image: None,
            initrd: None,
        }]);
        let valid_plan = Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime::default(),
                tag: tag("valid-crash"),
                fault: MembershipFault::Crash {
                    node: node_id("a"),
                    restart: RestartPolicy::StayDown,
                },
            }],
        )
        .unwrap_or_else(|error| panic!("valid plan should build: {error}"));
        let valid_form = ScenarioDefForm::from_components(
            &world,
            &valid_plan,
            &Properties::empty(),
            Seed::from_u64(0x0010_0021),
        )
        .unwrap_or_else(|error| panic!("valid scenario form should build: {error}"));
        let scenario_negative_plan_time = ScenarioDefForm::from_canonical_toml(
            &valid_form
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("valid scenario should serialize: {error}"))
                .replace("at_ticks = 0", "at_ticks = -7"),
        );

        assert!(matches!(
            duplicate_node_ids,
            Err(EngineError::DuplicateWorldNodeId { node }) if node == node_id("dup")
        ));
        assert!(matches!(
            unknown_link_endpoint,
            Err(EngineError::WorldLinkUnknownNode { node, .. })
                if node == node_id("missing")
        ));
        assert!(matches!(
            latency_below_floor,
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
                millionths,
                maximum,
            }) if millionths == 1_000_001 && maximum == 1_000_000
        ));
        assert!(matches!(
            plan_unknown_node,
            Err(EngineError::PlanFaultUnknownNode { node })
                if node == node_id("missing")
        ));
        assert!(matches!(
            plan_unknown_link,
            Err(EngineError::PlanFaultUnknownLink {
                endpoint_a,
                endpoint_b,
            }) if endpoint_a == node_id("b") && endpoint_b == node_id("c")
        ));
        assert!(matches!(
            unsupported_fault_param,
            Err(EngineError::PlanFaultUnsupportedParam { entry, field })
                if entry == 0 && field == "window"
        ));
        assert!(matches!(
            unknown_direction,
            Err(EngineError::PlanFaultUnknownDirection { entry, direction })
                if entry == 0 && direction == "sideways"
        ));
        assert!(matches!(
            unknown_heal_tag,
            Err(EngineError::PlanHealUnknownTag { tag })
                if tag == self::tag("never-activated")
        ));
        assert!(matches!(
            negative_plan_time,
            Err(EngineError::PlanNegativeTime { entry, at_ticks })
                if entry == 0 && at_ticks == -5
        ));
        assert!(matches!(
            unknown_property_ref,
            Err(EngineError::PropertyPredicateUnknownNode { node })
                if node == node_id("missing")
        ));
        assert!(matches!(
            empty_property_compound,
            Err(EngineError::PropertyPredicateEmptyCompound { kind }) if kind == "all-of"
        ));
        assert!(matches!(
            white_box_ready_point_without_opt_in,
            Err(EngineError::WhiteBoxReadyPointWithoutOptIn { node })
                if node == node_id("agent")
        ));
        assert!(matches!(
            zero_vcpu_count,
            Err(EngineError::WorldNodeSmpVcpuCountZero { node })
                if node == node_id("zero-vcpu")
        ));
        assert!(matches!(
            icount_shift_too_large,
            Err(EngineError::WorldNodeIcountShiftTooLarge {
                node,
                shift,
                maximum,
            }) if node == node_id("bad-shift") && shift == 63 && maximum == 62
        ));
        assert!(matches!(
            scenario_negative_plan_time,
            Err(EngineError::PlanNegativeTime { entry, at_ticks })
                if entry == 0 && at_ticks == -7
        ));
        assert_eq!(valid_form.id(), valid_form.scenario_def().id());
        assert_ne!(world.id(), changed_vcpu_world.id());
        assert_ne!(world.id(), changed_shift_world.id());
        assert_ne!(world.scenario_def(), changed_vcpu_world.scenario_def());
        assert_ne!(world.scenario_def(), changed_shift_world.scenario_def());
    }

    #[test]
    fn plan_content_address_is_orthogonal_and_canonical() {
        let world = world_from_nodes_and_links(
            two_ready_nodes(),
            vec![transport_link("a", "b", 10, 1, 0, None)],
        );
        let changed_world = world_from_nodes_and_links(
            vec![
                ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 11 },
                    },
                ),
                ready_node(
                    "b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 12 },
                    },
                ),
            ],
            vec![transport_link("a", "b", 20, 1, 0, None)],
        );
        let incompatible_world = world_from_nodes_and_links(two_ready_nodes(), Vec::new());
        let authored_order = vec![
            PlanEntry::Heal {
                at: VirtualTime { ticks: 40 },
                tag: tag("split"),
            },
            PlanEntry::Activate {
                at: VirtualTime { ticks: 10 },
                tag: tag("split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("b"),
                    endpoint_b: node_id("a"),
                    direction: PartitionDirection::Bidirectional,
                },
            },
            PlanEntry::Activate {
                at: VirtualTime { ticks: 20 },
                tag: tag("crash-b"),
                fault: MembershipFault::Crash {
                    node: node_id("b"),
                    restart: RestartPolicy::FromLastCheckpoint,
                },
            },
        ];
        let canonical_order = vec![
            PlanEntry::Activate {
                at: VirtualTime { ticks: 10 },
                tag: tag("split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("a"),
                    endpoint_b: node_id("b"),
                    direction: PartitionDirection::Bidirectional,
                },
            },
            PlanEntry::Activate {
                at: VirtualTime { ticks: 20 },
                tag: tag("crash-b"),
                fault: MembershipFault::Crash {
                    node: node_id("b"),
                    restart: RestartPolicy::FromLastCheckpoint,
                },
            },
            PlanEntry::Heal {
                at: VirtualTime { ticks: 40 },
                tag: tag("split"),
            },
        ];

        let plan = match Plan::from_entries_for_world(&world, authored_order) {
            Ok(plan) => plan,
            Err(error) => panic!("authored-order plan should be valid: {error}"),
        };
        let same_plan = match Plan::from_entries_for_world(&world, canonical_order) {
            Ok(plan) => plan,
            Err(error) => panic!("canonical-order plan should be valid: {error}"),
        };
        let same_plan_changed_world =
            match Plan::from_entries_for_world(&changed_world, same_plan.entries().to_vec()) {
                Ok(plan) => plan,
                Err(error) => panic!("same plan should apply to compatible world: {error}"),
            };
        let changed_plan = match Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 11 },
                tag: tag("split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("a"),
                    endpoint_b: node_id("b"),
                    direction: PartitionDirection::Bidirectional,
                },
            }],
        ) {
            Ok(plan) => plan,
            Err(error) => panic!("changed plan should be valid: {error}"),
        };
        let empty_plan = Plan::empty();

        assert_eq!(plan.content_hash(), same_plan.content_hash());
        assert_eq!(plan.entries(), same_plan.entries());
        assert_eq!(plan.content_hash(), same_plan_changed_world.content_hash());
        assert_ne!(plan.content_hash(), changed_plan.content_hash());
        assert_eq!(
            world.scenario_def(),
            world
                .scenario_def_with_plan(&empty_plan)
                .unwrap_or_else(|error| panic!("empty plan should compose: {error}"))
        );
        assert_eq!(
            world
                .scenario_def_with_plan(&plan)
                .unwrap_or_else(|error| panic!("plan should compose: {error}")),
            world
                .scenario_def_with_plan(&same_plan)
                .unwrap_or_else(|error| panic!("same plan should compose: {error}"))
        );
        assert_ne!(
            world.scenario_def(),
            world
                .scenario_def_with_plan(&plan)
                .unwrap_or_else(|error| panic!("plan should affect scenario identity: {error}"))
        );
        assert_ne!(
            world
                .scenario_def_with_plan(&plan)
                .unwrap_or_else(|error| panic!("plan should compose: {error}")),
            changed_world
                .scenario_def_with_plan(&same_plan_changed_world)
                .unwrap_or_else(|error| panic!(
                    "same plan should compose with compatible world: {error}"
                ))
        );
        assert!(matches!(
            incompatible_world.scenario_def_with_plan(&plan),
            Err(EngineError::PlanFaultUnknownLink {
                endpoint_a,
                endpoint_b,
            }) if endpoint_a == node_id("a") && endpoint_b == node_id("b")
        ));
    }

    #[test]
    fn properties_content_address_is_orthogonal_and_validated() {
        let mut world_nodes = two_ready_nodes();
        world_nodes[0].white_box = WhiteBoxPolicy::Enabled;
        let world =
            world_from_nodes_and_links(world_nodes, vec![transport_link("a", "b", 10, 1, 0, None)]);
        let mut changed_world_nodes = vec![
            ready_node(
                "a",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 11 },
                },
            ),
            ready_node(
                "b",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 12 },
                },
            ),
        ];
        changed_world_nodes[0].white_box = WhiteBoxPolicy::Enabled;
        let changed_world = world_from_nodes_and_links(
            changed_world_nodes,
            vec![transport_link("a", "b", 20, 1, 0, None)],
        );
        let incompatible_world = world_from_nodes_and_links(
            vec![ready_node(
                "a",
                ReadyPoint::FixedIcount {
                    icount: Icount { retired: 1 },
                },
            )],
            Vec::new(),
        );
        let authored_order = vec![
            assertion(
                "settles",
                "replicas settle to the same state",
                Property::AfterQuiescence {
                    predicate: named_predicate("replicas_equal", &["b", "a"]),
                },
            ),
            assertion(
                "alive",
                "nodes remain alive",
                Property::Always {
                    predicate: Predicate::AllOf {
                        predicates: vec![
                            named_predicate("node_alive", &["b"]),
                            named_predicate("node_alive", &["a"]),
                        ],
                    },
                },
            ),
            assertion(
                "commit-reached",
                "commit marker was reached",
                Property::Reachable {
                    predicate: Predicate::GuestMarker {
                        marker: marker_id("commit"),
                    },
                    expectation: ReachabilityExpectation::Reachable {
                        on_unreached: ReachableDisposition::Warn,
                    },
                },
            ),
        ];
        let canonical_order = vec![
            assertion(
                "alive",
                "nodes remain alive",
                Property::Always {
                    predicate: Predicate::AllOf {
                        predicates: vec![
                            named_predicate("node_alive", &["a"]),
                            named_predicate("node_alive", &["b"]),
                        ],
                    },
                },
            ),
            assertion(
                "commit-reached",
                "commit marker was reached",
                Property::Reachable {
                    predicate: Predicate::GuestMarker {
                        marker: marker_id("commit"),
                    },
                    expectation: ReachabilityExpectation::Reachable {
                        on_unreached: ReachableDisposition::Warn,
                    },
                },
            ),
            assertion(
                "settles",
                "replicas settle to the same state",
                Property::AfterQuiescence {
                    predicate: named_predicate("replicas_equal", &["b", "a"]),
                },
            ),
        ];

        let properties = match Properties::from_assertions_for_world(&world, authored_order) {
            Ok(properties) => properties,
            Err(error) => panic!("authored-order properties should be valid: {error}"),
        };
        let same_properties = match Properties::from_assertions_for_world(&world, canonical_order) {
            Ok(properties) => properties,
            Err(error) => panic!("canonical-order properties should be valid: {error}"),
        };
        let same_properties_changed_world = match Properties::from_assertions_for_world(
            &changed_world,
            same_properties.assertions().to_vec(),
        ) {
            Ok(properties) => properties,
            Err(error) => panic!("same properties should apply to compatible world: {error}"),
        };
        let changed_properties = match Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "alive",
                "node b remains alive",
                Property::Always {
                    predicate: named_predicate("node_alive", &["b"]),
                },
            )],
        ) {
            Ok(properties) => properties,
            Err(error) => panic!("changed properties should be valid: {error}"),
        };
        let unknown_node = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "missing",
                "missing node is invalid",
                Property::Always {
                    predicate: named_predicate("node_alive", &["missing"]),
                },
            )],
        );
        let duplicate_id = Properties::from_assertions_for_world(
            &world,
            vec![
                assertion(
                    "dup",
                    "first",
                    Property::Always {
                        predicate: named_predicate("node_alive", &["a"]),
                    },
                ),
                assertion(
                    "dup",
                    "second",
                    Property::Sometimes {
                        predicate: named_predicate("node_alive", &["b"]),
                    },
                ),
            ],
        );
        let empty_compound = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "empty",
                "empty all-of is invalid",
                Property::Always {
                    predicate: Predicate::AllOf {
                        predicates: Vec::new(),
                    },
                },
            )],
        );
        let empty_plan = Plan::empty();
        let empty_properties = Properties::empty();
        let partition_plan = match Plan::from_entries_for_world(
            &world,
            vec![PlanEntry::Activate {
                at: VirtualTime { ticks: 10 },
                tag: tag("split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("a"),
                    endpoint_b: node_id("b"),
                    direction: PartitionDirection::Bidirectional,
                },
            }],
        ) {
            Ok(plan) => plan,
            Err(error) => panic!("partition plan should be valid: {error}"),
        };
        let mut no_link_world_nodes = two_ready_nodes();
        no_link_world_nodes[0].white_box = WhiteBoxPolicy::Enabled;
        let no_link_world = world_from_nodes_and_links(no_link_world_nodes, Vec::new());

        assert_eq!(properties.content_hash(), same_properties.content_hash());
        assert_eq!(properties.assertions(), same_properties.assertions());
        assert_eq!(
            properties.content_hash(),
            same_properties_changed_world.content_hash()
        );
        assert_ne!(properties.content_hash(), changed_properties.content_hash());
        assert_eq!(
            world.scenario_def(),
            world
                .scenario_def_with_plan_and_properties(&empty_plan, &empty_properties)
                .unwrap_or_else(|error| panic!(
                    "empty plan and properties should compose: {error}"
                ))
        );
        assert_eq!(
            world
                .scenario_def_with_plan(&empty_plan)
                .unwrap_or_else(|error| panic!("empty plan should compose: {error}")),
            world
                .scenario_def_with_plan_and_properties(&empty_plan, &empty_properties)
                .unwrap_or_else(|error| panic!(
                    "empty properties should preserve plan-only scenario: {error}"
                ))
        );
        assert_ne!(
            world
                .scenario_def_with_plan(&empty_plan)
                .unwrap_or_else(|error| panic!("empty plan should compose: {error}")),
            world
                .scenario_def_with_plan_and_properties(&empty_plan, &properties)
                .unwrap_or_else(|error| panic!(
                    "properties should affect scenario identity: {error}"
                ))
        );
        assert_ne!(
            world
                .scenario_def_with_plan_and_properties(&empty_plan, &properties)
                .unwrap_or_else(|error| panic!("properties should compose: {error}")),
            changed_world
                .scenario_def_with_plan_and_properties(&empty_plan, &same_properties_changed_world)
                .unwrap_or_else(|error| panic!(
                    "same properties should compose with compatible world: {error}"
                ))
        );
        assert!(matches!(
            incompatible_world.scenario_def_with_plan_and_properties(&empty_plan, &properties),
            Err(EngineError::PropertyPredicateUnknownNode { node }) if node == node_id("b")
        ));
        assert!(matches!(
            no_link_world.scenario_def_with_plan_and_properties(&partition_plan, &properties),
            Err(EngineError::PlanFaultUnknownLink {
                endpoint_a,
                endpoint_b,
            }) if endpoint_a == node_id("a") && endpoint_b == node_id("b")
        ));
        assert!(matches!(
            unknown_node,
            Err(EngineError::PropertyPredicateUnknownNode { node })
                if node == node_id("missing")
        ));
        assert!(matches!(
            duplicate_id,
            Err(EngineError::PropertyDuplicateAssertionId { id }) if id == assertion_id("dup")
        ));
        assert!(matches!(
            empty_compound,
            Err(EngineError::PropertyPredicateEmptyCompound { kind }) if kind == "all-of"
        ));
    }

    #[test]
    fn scenario_builder_keeps_authoring_layers_structurally_orthogonal() {
        let seed = Seed::from_u64(0x0010_0015);
        let plan_entry = PlanEntry::Activate {
            at: VirtualTime { ticks: 3 },
            tag: tag("split"),
            fault: MembershipFault::Partition {
                endpoint_a: node_id("a"),
                endpoint_b: node_id("b"),
                direction: PartitionDirection::Bidirectional,
            },
        };
        let property = assertion(
            "both-alive",
            "both nodes stay alive",
            Property::Always {
                predicate: Predicate::AllOf {
                    predicates: vec![
                        named_predicate("node_alive", &["b"]),
                        named_predicate("node_alive", &["a"]),
                    ],
                },
            },
        );

        let scenario = ScenarioBuilder::new()
            .node(
                "a",
                NodeTemplate::fixed_icount(Icount { retired: 11 })
                    .white_box(WhiteBoxPolicy::Disabled),
            )
            .node_like("b", "a")
            .link_with_transport(
                "b",
                "a",
                SimDuration { nanos: 10 },
                SimDuration { nanos: 1 },
                LinkLossProbability::ZERO,
                Some(1_000_000),
            )
            .plan_entry(plan_entry.clone())
            .property(property.clone())
            .seed(seed)
            .build()
            .unwrap_or_else(|error| panic!("builder-authored scenario should be valid: {error}"));
        let manual_world = world_from_nodes_and_links(
            vec![
                ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 11 },
                    },
                ),
                ready_node(
                    "b",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 11 },
                    },
                ),
            ],
            vec![transport_link("a", "b", 10, 1, 0, Some(1_000_000))],
        );
        let manual_plan = Plan::from_entries_for_world(&manual_world, vec![plan_entry])
            .unwrap_or_else(|error| panic!("manual plan should be valid: {error}"));
        let manual_properties =
            Properties::from_assertions_for_world(&manual_world, vec![property])
                .unwrap_or_else(|error| panic!("manual properties should be valid: {error}"));
        let manual_scenario = manual_world
            .scenario_def_with_plan_properties_and_seed(&manual_plan, &manual_properties, seed)
            .unwrap_or_else(|error| panic!("manual scenario composition should be valid: {error}"));
        let reused_world_scenario = ScenarioBuilder::new()
            .world(&manual_world)
            .seed(seed)
            .build()
            .unwrap_or_else(|error| panic!("world-template scenario should be valid: {error}"));
        let complete_layer_scenario = ScenarioBuilder::new()
            .world(&manual_world)
            .plan(manual_plan.clone())
            .properties(manual_properties.clone())
            .seed(seed)
            .build()
            .unwrap_or_else(|error| panic!("complete-layer scenario should be valid: {error}"));
        let templated_world_scenario = ScenarioBuilder::new()
            .node("fixed", NodeTemplate::fixed_icount(Icount { retired: 5 }))
            .node(
                "idle",
                NodeTemplate::network_idle(SimDuration { nanos: 1_000 }),
            )
            .node("console", NodeTemplate::console_marker("ready"))
            .node("agent", NodeTemplate::agent_signal())
            .link("fixed", "idle")
            .link_def(link("agent", "console"))
            .seed(seed)
            .build()
            .unwrap_or_else(|error| panic!("templated world scenario should be valid: {error}"));
        let templated_world = world_from_nodes_and_links(
            vec![
                ready_node(
                    "fixed",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 5 },
                    },
                ),
                ready_node(
                    "idle",
                    ReadyPoint::NetworkIdle {
                        window: SimDuration { nanos: 1_000 },
                    },
                ),
                ready_node(
                    "console",
                    ReadyPoint::ConsoleMarker {
                        marker: String::from("ready"),
                    },
                ),
                WorldNode {
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
                },
            ],
            vec![link("idle", "fixed"), link("console", "agent")],
        );

        assert_eq!(scenario, manual_scenario);
        assert_eq!(complete_layer_scenario, manual_scenario);
        assert_eq!(
            templated_world_scenario,
            templated_world.scenario_def_with_seed(seed)
        );
        assert_eq!(
            reused_world_scenario,
            manual_world.scenario_def_with_seed(seed)
        );
        assert!(matches!(
            ScenarioBuilder::new().node_like("copy", "missing").build(),
            Err(EngineError::ScenarioBuilderUnknownNodeTemplate { node, template })
                if node == node_id("copy") && template == node_id("missing")
        ));
        assert!(matches!(
            ScenarioBuilder::new()
                .node("a", NodeTemplate::fixed_icount(Icount { retired: 1 }))
                .node("b", NodeTemplate::fixed_icount(Icount { retired: 2 }))
                .plan_entry(PlanEntry::Activate {
                    at: VirtualTime { ticks: 1 },
                    tag: tag("split"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("a"),
                        endpoint_b: node_id("b"),
                        direction: PartitionDirection::Bidirectional,
                    },
                })
                .build(),
            Err(EngineError::PlanFaultUnknownLink {
                endpoint_a,
                endpoint_b,
            }) if endpoint_a == node_id("a") && endpoint_b == node_id("b")
        ));
        assert!(matches!(
            ScenarioBuilder::new()
                .node("a", NodeTemplate::fixed_icount(Icount { retired: 1 }))
                .property(assertion(
                    "missing",
                    "missing node should be rejected",
                    Property::Always {
                        predicate: named_predicate("node_alive", &["b"]),
                    },
                ))
                .build(),
            Err(EngineError::PropertyPredicateUnknownNode { node }) if node == node_id("b")
        ));
        assert!(matches!(
            ScenarioBuilder::new()
                .node("agent", NodeTemplate::new(ReadyPoint::AgentSignal))
                .build(),
            Err(EngineError::WhiteBoxReadyPointWithoutOptIn { node })
                if node == node_id("agent")
        ));
    }

    #[test]
    fn serializable_scenario_form_round_trips_and_rejects_host_paths() {
        let kernel_ref = ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
            "crucible.test.blob",
            "kernel",
        ));
        let root_image_ref = ContentAddressedBlobRef::from_hash(
            ContentHash::from_canonical_material("crucible.test.blob", "root-image"),
        );
        let initrd_ref = ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
            "crucible.test.blob",
            "initrd",
        ));
        let world = world_from_nodes_and_links(
            vec![
                WorldNode {
                    id: node_id("a"),
                    arch: NodeTemplate::DEFAULT_ARCH,
                    memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
                    cmdline: String::new(),
                    ready_point: ReadyPoint::FixedIcount {
                        icount: Icount { retired: 11 },
                    },
                    white_box: WhiteBoxPolicy::Disabled,
                    smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
                    icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
                    kernel: Some(kernel_ref),
                    root_image: Some(root_image_ref),
                    initrd: Some(initrd_ref),
                },
                ready_node(
                    "b",
                    ReadyPoint::ConsoleMarker {
                        marker: String::from("ready"),
                    },
                ),
            ],
            vec![transport_link("b", "a", 10, 1, 0, Some(1_000_000))],
        );
        let world_without_image_refs = world_from_nodes_and_links(
            vec![
                ready_node(
                    "a",
                    ReadyPoint::FixedIcount {
                        icount: Icount { retired: 11 },
                    },
                ),
                ready_node(
                    "b",
                    ReadyPoint::ConsoleMarker {
                        marker: String::from("ready"),
                    },
                ),
            ],
            vec![transport_link("b", "a", 10, 1, 0, Some(1_000_000))],
        );
        let plan = Plan::from_entries_for_world(
            &world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("split"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("b"),
                        endpoint_b: node_id("a"),
                        direction: PartitionDirection::Bidirectional,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 40 },
                    tag: tag("split"),
                },
            ],
        )
        .unwrap_or_else(|error| panic!("serialized-form plan should be valid: {error}"));
        let properties = Properties::from_assertions_for_world(
            &world,
            vec![assertion(
                "safety",
                "replicas never diverge",
                Property::Reachable {
                    predicate: Predicate::Once {
                        predicate: Box::new(Predicate::AllOf {
                            predicates: vec![
                                named_predicate("node_alive", &["a"]),
                                Predicate::Not {
                                    predicate: Box::new(named_predicate("node_alive", &["b"])),
                                },
                            ],
                        }),
                    },
                    expectation: ReachabilityExpectation::Reachable {
                        on_unreached: ReachableDisposition::Fail,
                    },
                },
            )],
        )
        .unwrap_or_else(|error| panic!("serialized-form properties should be valid: {error}"));
        let seed = Seed::from_u64(0x0010_0016);
        let form = ScenarioDefForm::from_components(&world, &plan, &properties, seed)
            .unwrap_or_else(|error| panic!("scenario form should validate: {error}"));
        let scenario = world
            .scenario_def_with_plan_properties_and_seed(&plan, &properties, seed)
            .unwrap_or_else(|error| panic!("manual scenario should validate: {error}"));
        let toml = form
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("scenario form TOML should serialize: {error}"));
        let binary = form.to_compact_binary();
        let parsed_toml = ScenarioDefForm::from_canonical_toml(&toml)
            .unwrap_or_else(|error| panic!("scenario form TOML should parse: {error}"));
        let parsed_binary = ScenarioDefForm::from_compact_binary(&binary)
            .unwrap_or_else(|error| panic!("scenario form binary should parse: {error}"));
        let world_toml = world
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("world TOML should serialize: {error}"));
        let plan_toml = plan
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("plan TOML should serialize: {error}"));
        let properties_toml = properties
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("properties TOML should serialize: {error}"));
        let seed_toml = seed
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("seed TOML should serialize: {error}"));
        let blob_hash = kernel_ref.hash();
        let blob_uri = kernel_ref.to_uri();
        let blob = ContentAddressedBlobRef::parse("kernel", &blob_uri)
            .unwrap_or_else(|error| panic!("blob ref should parse: {error}"));
        let wrong_hash =
            ContentHash::from_canonical_material("crucible.test.scenario-form", "wrong");
        let wrong_id_toml = toml.replacen(
            &format!("id = \"blake3:{}\"", form.id().to_hex()),
            &format!("id = \"blake3:{}\"", wrong_hash.to_hex()),
            1,
        );
        let empty_world = World::from_nodes_and_links(Vec::new(), Vec::new())
            .unwrap_or_else(|error| panic!("empty world should serialize: {error}"));
        let empty_world_toml = empty_world
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("empty world TOML should serialize: {error}"));
        let wrong_empty_world_toml = empty_world_toml.replacen(
            &format!("id = \"blake3:{}\"", empty_world.id().to_hex()),
            &format!("id = \"blake3:{}\"", wrong_hash.to_hex()),
            1,
        );
        let mut host_path_toml = toml.clone();
        host_path_toml.push_str("\nkernel=\"/nix/store/not-a-content-ref/bzImage\"\n");

        assert_eq!(form.scenario_def(), scenario);
        assert_eq!(parsed_toml, form);
        assert_eq!(parsed_binary, form);
        assert_eq!(parsed_toml.canonical_bytes(), form.canonical_bytes());
        assert_eq!(parsed_binary.canonical_bytes(), form.canonical_bytes());
        assert_ne!(form.canonical_bytes(), binary);
        assert_ne!(world_without_image_refs.id(), world.id());
        assert!(toml.contains(&format!("kernel = \"{}\"", kernel_ref.to_uri())));
        assert!(toml.contains(&format!("root_image = \"{}\"", root_image_ref.to_uri())));
        assert!(toml.contains(&format!("initrd = \"{}\"", initrd_ref.to_uri())));
        assert_eq!(
            World::from_canonical_toml(&world_toml)
                .unwrap_or_else(|error| panic!("world TOML should parse: {error}")),
            world
        );
        assert_eq!(
            World::from_compact_binary(&world.to_compact_binary())
                .unwrap_or_else(|error| panic!("world binary should parse: {error}")),
            world
        );
        assert_eq!(
            Plan::from_canonical_toml_for_world(&world, &plan_toml)
                .unwrap_or_else(|error| panic!("plan TOML should parse: {error}")),
            plan
        );
        assert_eq!(
            Plan::from_compact_binary_for_world(&world, &plan.to_compact_binary())
                .unwrap_or_else(|error| panic!("plan binary should parse: {error}")),
            plan
        );
        assert_eq!(
            Properties::from_canonical_toml_for_world(&world, &properties_toml)
                .unwrap_or_else(|error| panic!("properties TOML should parse: {error}")),
            properties
        );
        assert_eq!(
            Properties::from_compact_binary_for_world(&world, &properties.to_compact_binary())
                .unwrap_or_else(|error| panic!("properties binary should parse: {error}")),
            properties
        );
        assert_eq!(
            Seed::from_canonical_toml(&seed_toml)
                .unwrap_or_else(|error| panic!("seed TOML should parse: {error}")),
            seed
        );
        assert_eq!(
            Seed::from_compact_binary(&seed.to_compact_binary())
                .unwrap_or_else(|error| panic!("seed binary should parse: {error}")),
            seed
        );
        assert_eq!(blob.hash(), blob_hash);
        assert_eq!(blob.to_uri(), blob_uri);
        assert!(matches!(
            ContentAddressedBlobRef::parse("kernel", "/nix/store/kernel"),
            Err(EngineError::ScenarioImageReferenceNotContentAddressed { field, value })
                if field == "kernel" && value == "/nix/store/kernel"
        ));
        assert!(matches!(
            ScenarioDefForm::from_canonical_toml(&wrong_id_toml),
            Err(EngineError::ScenarioSerializedIdMismatch { component, .. })
                if component == "scenario"
        ));
        assert!(matches!(
            World::from_canonical_toml(&wrong_empty_world_toml),
            Err(EngineError::ScenarioSerializedIdMismatch { component, .. })
                if component == "world"
        ));
        assert!(matches!(
            ScenarioDefForm::from_canonical_toml(&host_path_toml),
            Err(EngineError::ScenarioImageReferenceNotContentAddressed { field, .. })
                if field == "kernel"
        ));
    }

    #[test]
    fn scenario_family_pins_concrete_validated_instances() {
        let seed_a = Seed::from_u64(0x0010_0017);
        let seed_b = Seed::from_u64(0x0010_0018);
        let zero_density = FaultDensity::ZERO;
        let half_density = FaultDensity::from_millionths(500_000)
            .unwrap_or_else(|error| panic!("half density should be valid: {error}"));
        let space = FamilySpace::new(
            SeedSpace::explicit(vec![seed_b, seed_a])
                .unwrap_or_else(|error| panic!("explicit seed space should be valid: {error}")),
            FaultDensityRange::new(zero_density, half_density)
                .unwrap_or_else(|error| panic!("density range should be valid: {error}")),
            TopologySizeRange::new(3, 4)
                .unwrap_or_else(|error| panic!("topology size range should be valid: {error}")),
            vec![
                TopologyShape::Star,
                TopologyShape::Ring,
                TopologyShape::Mesh,
                TopologyShape::Random,
            ],
        )
        .unwrap_or_else(|error| panic!("family space should be valid: {error}"));
        let tiny_space = FamilySpace::new(
            SeedSpace::explicit(vec![seed_a, seed_b])
                .unwrap_or_else(|error| panic!("tiny seed space should be valid: {error}")),
            FaultDensityRange::new(
                zero_density,
                FaultDensity::from_millionths(1).unwrap_or_else(|error| {
                    panic!("one-millionth density should be valid: {error}")
                }),
            )
            .unwrap_or_else(|error| panic!("tiny density range should be valid: {error}")),
            TopologySizeRange::new(1, 2).unwrap_or_else(|error| {
                panic!("tiny topology size range should be valid: {error}")
            }),
            vec![TopologyShape::Ring, TopologyShape::Star],
        )
        .unwrap_or_else(|error| panic!("tiny family space should be valid: {error}"));
        let generated_seeds = SeedSpace::generated(Seed::from_u64(0xfeed), 2)
            .unwrap_or_else(|error| panic!("generated seed space should be valid: {error}"));
        let family = ScenarioFamily::new(space, NodeTemplate::fixed_icount(Icount { retired: 17 }))
            .property(assertion(
                "node-zero-live",
                "first generated node remains addressable",
                Property::Sometimes {
                    predicate: named_predicate("node_alive", &["node-0"]),
                },
            ));
        let params = FamilyParams {
            seed: seed_a,
            fault_density: half_density,
            topology_size: 4,
            topology_shape: TopologyShape::Ring,
        };
        let pinned = family
            .instantiate(params)
            .unwrap_or_else(|error| panic!("family params should instantiate: {error}"));
        let repeated = family
            .instantiate(params)
            .unwrap_or_else(|error| panic!("same family params should instantiate: {error}"));
        let zero_faults = family
            .instantiate(FamilyParams {
                fault_density: zero_density,
                ..params
            })
            .unwrap_or_else(|error| {
                panic!("zero-density family params should instantiate: {error}")
            });
        let other_seed = family
            .instantiate(FamilyParams {
                seed: seed_b,
                ..params
            })
            .unwrap_or_else(|error| panic!("other seed family params should instantiate: {error}"));
        let smaller_topology = family
            .instantiate(FamilyParams {
                topology_size: 3,
                ..params
            })
            .unwrap_or_else(|error| panic!("smaller topology should instantiate: {error}"));
        let star_topology = family
            .instantiate(FamilyParams {
                topology_shape: TopologyShape::Star,
                ..params
            })
            .unwrap_or_else(|error| panic!("star topology should instantiate: {error}"));
        let mesh_topology = family
            .instantiate(FamilyParams {
                topology_shape: TopologyShape::Mesh,
                ..params
            })
            .unwrap_or_else(|error| panic!("mesh topology should instantiate: {error}"));
        let random_zero_faults = family
            .instantiate(FamilyParams {
                fault_density: zero_density,
                topology_shape: TopologyShape::Random,
                ..params
            })
            .unwrap_or_else(|error| {
                panic!("random zero-density topology should instantiate: {error}")
            });
        let random_half_faults = family
            .instantiate(FamilyParams {
                topology_shape: TopologyShape::Random,
                ..params
            })
            .unwrap_or_else(|error| {
                panic!("random half-density topology should instantiate: {error}")
            });
        let sampled = family
            .instantiate_sample(0)
            .unwrap_or_else(|error| panic!("sampled family params should instantiate: {error}"));
        let sampled_again = family
            .instantiate_sample(0)
            .unwrap_or_else(|error| panic!("same sample should instantiate: {error}"));
        let generated_seed_0 = generated_seeds
            .seed_at(0)
            .unwrap_or_else(|error| panic!("generated seed 0 should exist: {error}"));
        let generated_seed_1 = generated_seeds
            .seed_at(1)
            .unwrap_or_else(|error| panic!("generated seed 1 should exist: {error}"));
        let out_of_space = family.instantiate(FamilyParams {
            topology_size: 5,
            ..params
        });
        let bad_density = FaultDensity::from_millionths(1_000_001);
        let pinned_form = pinned.clone().into_form();
        let pinned_genesis = pinned.genesis_configuration();
        let round_tripped_pinned_form = ScenarioDefForm::from_canonical_toml(
            &pinned_genesis
                .scenario_form()
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("pinned form TOML should serialize: {error}")),
        )
        .unwrap_or_else(|error| panic!("pinned form TOML should parse: {error}"));
        let tiny_total = tiny_space
            .cardinality()
            .unwrap_or_else(|error| panic!("tiny space cardinality should compute: {error}"));
        let mut tiny_samples = std::collections::BTreeSet::new();
        for index in 0..tiny_total {
            tiny_samples.insert(
                tiny_space
                    .sample(index)
                    .unwrap_or_else(|error| panic!("tiny sample {index} should exist: {error}")),
            );
        }
        let exhausted_tiny_sample = tiny_space.sample(tiny_total);

        assert_eq!(pinned, repeated);
        assert_eq!(pinned.params(), params);
        assert_eq!(pinned.form().seed(), params.seed);
        assert_eq!(pinned.form().world().vm_nodes().len(), 4);
        assert_eq!(pinned.form().world().links().len(), 4);
        assert_eq!(pinned.form().properties().assertions().len(), 1);
        assert_eq!(pinned.form().plan().entries().len(), 8);
        assert_eq!(
            pinned
                .form()
                .plan()
                .entries()
                .iter()
                .filter(|entry| matches!(entry, PlanEntry::Activate { .. }))
                .count(),
            4
        );
        assert_eq!(pinned_form, pinned.form().clone());
        assert_eq!(pinned_genesis.configuration().def, pinned.scenario_def());
        assert_eq!(pinned_genesis.scenario_form(), pinned.form());
        assert_eq!(round_tripped_pinned_form, pinned.form().clone());
        assert!(zero_faults.form().plan().entries().is_empty());
        assert_ne!(zero_faults.id(), pinned.id());
        assert_ne!(other_seed.id(), pinned.id());
        assert_eq!(smaller_topology.form().world().vm_nodes().len(), 3);
        assert_eq!(smaller_topology.form().world().links().len(), 3);
        assert_ne!(smaller_topology.id(), pinned.id());
        assert_eq!(star_topology.form().world().links().len(), 3);
        assert_ne!(star_topology.id(), pinned.id());
        assert_eq!(mesh_topology.form().world().links().len(), 6);
        assert_ne!(mesh_topology.id(), pinned.id());
        assert_eq!(
            random_zero_faults.form().world(),
            random_half_faults.form().world()
        );
        assert!(random_zero_faults.form().plan().entries().is_empty());
        assert!(!random_half_faults.form().plan().entries().is_empty());
        assert_ne!(random_zero_faults.id(), random_half_faults.id());
        assert_eq!(sampled, sampled_again);
        assert!(family.space().contains(sampled.params()));
        assert_eq!(tiny_total, 16);
        assert_eq!(tiny_samples.len(), tiny_total as usize);
        assert!(matches!(
            exhausted_tiny_sample,
            Err(EngineError::ScenarioFamilyParameterOutOfSpace { parameter })
                if parameter == "sample_index"
        ));
        assert_ne!(generated_seed_0, generated_seed_1);
        assert!(matches!(
            out_of_space,
            Err(EngineError::ScenarioFamilyParameterOutOfSpace { parameter })
                if parameter == "topology_size"
        ));
        assert!(matches!(
            bad_density,
            Err(EngineError::FaultDensityOutOfRange { millionths, maximum })
                if millionths == 1_000_001 && maximum == 1_000_000
        ));
    }

    #[test]
    fn reproduction_artifact_is_self_contained_and_replay_checked() {
        let seed = Seed::from_u64(0x0010_0018);
        let density = FaultDensity::from_millionths(250_000)
            .unwrap_or_else(|error| panic!("density should be valid: {error}"));
        let space = FamilySpace::new(
            SeedSpace::explicit(vec![seed])
                .unwrap_or_else(|error| panic!("seed space should be valid: {error}")),
            FaultDensityRange::new(density, density)
                .unwrap_or_else(|error| panic!("density range should be valid: {error}")),
            TopologySizeRange::new(3, 3)
                .unwrap_or_else(|error| panic!("topology size range should be valid: {error}")),
            vec![TopologyShape::Ring],
        )
        .unwrap_or_else(|error| panic!("family space should be valid: {error}"));
        let family = ScenarioFamily::new(space, NodeTemplate::fixed_icount(Icount { retired: 24 }));
        let pinned = family
            .instantiate_sample(0)
            .unwrap_or_else(|error| panic!("sample should instantiate: {error}"));
        let pinned_genesis = pinned.genesis_configuration();
        let fault_name = pinned
            .form()
            .plan()
            .entries()
            .iter()
            .find_map(|entry| match entry {
                PlanEntry::Activate { tag, .. } => Some(tag.name.clone()),
                PlanEntry::Heal { .. } => None,
            })
            .unwrap_or_else(|| "family-fault-0".to_owned());
        let schedule = Schedule::empty()
            .appended(Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime { ticks: 1 },
                order: vec![event_key(1, 1), event_key(1, 2)],
            }))
            .appended(Decision::FaultFires(FaultDecision {
                at: VirtualTime { ticks: 2 },
                fault: FaultId { name: fault_name },
                fired: true,
            }))
            .appended(Decision::RngDraw(RngDecision {
                stream: RngStreamId::for_node("node-0"),
                value: 0x0010_0018,
            }))
            .appended(Decision::Override(OverrideDecision {
                point: SchedulingPoint {
                    key: "node-0/fault-choice".to_owned(),
                },
                choice: ChoiceTag {
                    name: "fire".to_owned(),
                },
            }))
            .appended(Decision::Preemption(PreemptionDecision {
                node: node_id("node-0"),
                at: Icount { retired: 32 },
                kind: PreemptionKind::VcpuSwitch {
                    from_vcpu: VcpuId { index: 0 },
                    to_vcpu: VcpuId { index: 1 },
                },
            }))
            .appended(Decision::Preemption(PreemptionDecision {
                node: node_id("node-1"),
                at: Icount { retired: 48 },
                kind: PreemptionKind::InterruptAt {
                    target_vcpu: VcpuId { index: 0 },
                    irq: IrqVector { vector: 32 },
                },
            }))
            .appended(Decision::AppRandom(AppRandomDecision {
                node: node_id("node-2"),
                stream: RngStreamId::for_node("node-2"),
                request_id: 7,
                width: 64,
                value: 0xfeed_beef,
            }));
        let schedule_binary = schedule.to_compact_binary();
        let parsed_schedule = Schedule::from_compact_binary(&schedule_binary)
            .unwrap_or_else(|error| panic!("schedule binary should parse: {error}"));
        let artifact = ReproductionArtifact::capture(pinned.form(), &schedule)
            .unwrap_or_else(|error| panic!("artifact capture should reduce: {error}"));
        let replay = artifact
            .replay()
            .unwrap_or_else(|error| panic!("artifact should replay: {error}"));
        let expected_state = replay.state;
        let artifact_bytes = artifact.to_compact_binary();
        let decoded_artifact = ReproductionArtifact::from_compact_binary(&artifact_bytes)
            .unwrap_or_else(|error| panic!("artifact binary should parse: {error}"));
        let reduced_state = reduce(&artifact.scenario_def(), artifact.schedule())
            .unwrap_or_else(|error| panic!("artifact schedule should reduce: {error}"))
            .id;
        let scenario_toml = artifact
            .scenario_form()
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("scenario TOML should serialize: {error}"));
        let round_tripped_scenario = ScenarioDefForm::from_canonical_toml(&scenario_toml)
            .unwrap_or_else(|error| panic!("scenario TOML should parse: {error}"));
        let offline_replay_artifact =
            ReproductionArtifact::from_recorded_parts(round_tripped_scenario, parsed_schedule);
        let pinned_genesis_artifact =
            ReproductionArtifact::from_pinned_configuration(&pinned_genesis)
                .unwrap_or_else(|error| panic!("pinned genesis should capture: {error}"));
        let checkpoint_configuration = Configuration {
            def: artifact.scenario_def(),
            schedule: artifact.schedule().clone(),
        };
        let genesis_configuration = pinned_genesis.configuration().clone();
        let checkpoint = Checkpoint::from_recorded_configuration(
            &checkpoint_configuration,
            Some(&genesis_configuration),
            VirtualTime { ticks: 7 },
            std::collections::BTreeMap::new(),
            CheckpointKind::Fat,
            std::collections::BTreeMap::new(),
        )
        .unwrap_or_else(|error| panic!("checkpoint should record: {error}"));
        let checkpoint_binary = checkpoint.to_compact_binary();
        let decoded_checkpoint = Checkpoint::from_compact_binary(&checkpoint_binary)
            .unwrap_or_else(|error| panic!("checkpoint binary should parse: {error}"));
        let drifted_schedule = artifact.schedule().appended(Decision::RngDraw(RngDecision {
            stream: RngStreamId::for_node("node-1"),
            value: 99,
        }));
        let drifted_state = reduce(&artifact.scenario_def(), &drifted_schedule)
            .unwrap_or_else(|error| panic!("drifted schedule should reduce: {error}"))
            .id;
        let schedule_drift_artifact = ReproductionArtifact::from_recorded_parts(
            artifact.scenario_form().clone(),
            drifted_schedule,
        );
        let wrong_state = ContentHash::from_canonical_material(
            "crucible.test.reproduction-artifact",
            "wrong-recorded-state",
        );

        assert_eq!(artifact.seed(), artifact.scenario_def().seed());
        assert_eq!(artifact.scenario_form(), pinned.form());
        assert_eq!(artifact.schedule(), &schedule);
        assert_eq!(reduced_state, replay.state);
        assert_eq!(
            artifact.id(),
            ContentHash::from_bytes(&artifact.canonical_bytes())
        );
        assert_eq!(artifact.to_compact_binary(), artifact.canonical_bytes());
        assert_eq!(replay.artifact, artifact.id());
        assert_eq!(replay.scenario, artifact.scenario_def().id());
        assert_eq!(replay.schedule, artifact.schedule().content_hash());
        assert_eq!(replay.state, expected_state);
        assert_eq!(decoded_artifact, artifact);
        assert_eq!(
            decoded_artifact
                .verify_replay(expected_state)
                .unwrap_or_else(|error| panic!("decoded replay should verify: {error}")),
            replay
        );
        assert_eq!(offline_replay_artifact.id(), artifact.id());
        assert_eq!(
            offline_replay_artifact.canonical_bytes(),
            artifact.canonical_bytes()
        );
        assert_eq!(
            offline_replay_artifact
                .replay()
                .unwrap_or_else(|error| panic!("offline replay should verify: {error}")),
            replay
        );
        assert_eq!(decoded_checkpoint, checkpoint);
        assert_eq!(
            decoded_checkpoint.to_compact_binary(),
            checkpoint.to_compact_binary()
        );
        assert_eq!(pinned_genesis_artifact.scenario_form(), pinned.form());
        assert!(pinned_genesis_artifact.schedule().is_empty());
        assert_ne!(schedule_drift_artifact.id(), artifact.id());
        assert!(matches!(
            schedule_drift_artifact.verify_replay(expected_state),
            Err(EngineError::ReproductionArtifactReplayMismatch {
                artifact: replayed_artifact,
                expected,
                actual,
            }) if replayed_artifact == schedule_drift_artifact.id()
                && expected == expected_state
                && actual == drifted_state
        ));
        assert!(matches!(
            artifact.verify_replay(wrong_state),
            Err(EngineError::ReproductionArtifactReplayMismatch {
                artifact: replayed_artifact,
                expected,
                actual,
            }) if replayed_artifact == artifact.id()
                && expected == wrong_state
                && actual == expected_state
        ));
    }

    #[test]
    fn canonicalization_hashes_meaning_not_authoring_spelling() {
        let kernel = ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
            "crucible.test.canonicalization.blob",
            "kernel",
        ));
        let root_image = ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
            "crucible.test.canonicalization.blob",
            "root-image",
        ));
        let initrd = ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
            "crucible.test.canonicalization.blob",
            "initrd",
        ));
        let changed_kernel =
            ContentAddressedBlobRef::from_hash(ContentHash::from_canonical_material(
                "crucible.test.canonicalization.blob",
                "changed-kernel",
            ));
        let node_a = WorldNode {
            id: node_id("a"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: Some(kernel),
            root_image: Some(root_image),
            initrd: Some(initrd),
        };
        let node_b = WorldNode {
            id: node_id("b"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::NetworkIdle {
                window: SimDuration { nanos: 12 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: Some(root_image),
            initrd: None,
        };
        let node_c = WorldNode {
            id: node_id("c"),
            arch: NodeTemplate::DEFAULT_ARCH,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::ConsoleMarker {
                marker: "ready".to_owned(),
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: Some(kernel),
            root_image: None,
            initrd: Some(initrd),
        };
        let authored_world = world_from_nodes_and_links(
            vec![node_c.clone(), node_a.clone(), node_b.clone()],
            vec![
                transport_link("c", "b", 50, 5, 125_000, Some(1_000_000)),
                transport_link("b", "a", 10, 1, 0, None),
            ],
        );
        let canonical_world = world_from_nodes_and_links(
            vec![node_a.clone(), node_b.clone(), node_c.clone()],
            vec![
                transport_link("a", "b", 10, 1, 0, None),
                transport_link("b", "c", 50, 5, 125_000, Some(1_000_000)),
            ],
        );
        let changed_loss_world = world_from_nodes_and_links(
            vec![node_a.clone(), node_b.clone(), node_c.clone()],
            vec![
                transport_link("a", "b", 10, 1, 0, None),
                transport_link("b", "c", 50, 5, 125_001, Some(1_000_000)),
            ],
        );
        let changed_ref_world = world_from_nodes_and_links(
            vec![
                WorldNode {
                    kernel: Some(changed_kernel),
                    ..node_a.clone()
                },
                node_b.clone(),
                node_c.clone(),
            ],
            canonical_world.links().to_vec(),
        );
        let changed_icount_world = world_from_nodes_and_links(
            vec![
                WorldNode {
                    ready_point: ReadyPoint::FixedIcount {
                        icount: Icount { retired: 2 },
                    },
                    ..node_a.clone()
                },
                node_b.clone(),
                node_c.clone(),
            ],
            canonical_world.links().to_vec(),
        );
        let changed_duration_world = world_from_nodes_and_links(
            vec![
                node_a.clone(),
                WorldNode {
                    ready_point: ReadyPoint::NetworkIdle {
                        window: SimDuration { nanos: 13 },
                    },
                    ..node_b.clone()
                },
                node_c.clone(),
            ],
            canonical_world.links().to_vec(),
        );
        let changed_bandwidth_world = world_from_nodes_and_links(
            vec![node_a.clone(), node_b.clone(), node_c.clone()],
            vec![
                transport_link("a", "b", 10, 1, 0, None),
                transport_link("b", "c", 50, 5, 125_000, Some(2_000_000)),
            ],
        );
        let authored_plan = Plan::from_entries_for_world(
            &authored_world,
            vec![
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 40 },
                    tag: tag("split"),
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 20 },
                    tag: tag("crash-c"),
                    fault: MembershipFault::Crash {
                        node: node_id("c"),
                        restart: RestartPolicy::FromReadyPoint,
                    },
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("split"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("c"),
                        endpoint_b: node_id("b"),
                        direction: PartitionDirection::EndpointBToEndpointA,
                    },
                },
            ],
        )
        .unwrap_or_else(|error| panic!("authored plan should be valid: {error}"));
        let canonical_plan = Plan::from_entries_for_world(
            &canonical_world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("split"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("b"),
                        endpoint_b: node_id("c"),
                        direction: PartitionDirection::EndpointAToEndpointB,
                    },
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 20 },
                    tag: tag("crash-c"),
                    fault: MembershipFault::Crash {
                        node: node_id("c"),
                        restart: RestartPolicy::FromReadyPoint,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 40 },
                    tag: tag("split"),
                },
            ],
        )
        .unwrap_or_else(|error| panic!("canonical plan should be valid: {error}"));
        let changed_time_plan = Plan::from_entries_for_world(
            &canonical_world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 11 },
                    tag: tag("split"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("b"),
                        endpoint_b: node_id("c"),
                        direction: PartitionDirection::EndpointAToEndpointB,
                    },
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 20 },
                    tag: tag("crash-c"),
                    fault: MembershipFault::Crash {
                        node: node_id("c"),
                        restart: RestartPolicy::FromReadyPoint,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 40 },
                    tag: tag("split"),
                },
            ],
        )
        .unwrap_or_else(|error| panic!("changed-time plan should be valid: {error}"));
        let changed_tag_plan = Plan::from_entries_for_world(
            &canonical_world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("split-alt"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("b"),
                        endpoint_b: node_id("c"),
                        direction: PartitionDirection::EndpointAToEndpointB,
                    },
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 20 },
                    tag: tag("crash-c"),
                    fault: MembershipFault::Crash {
                        node: node_id("c"),
                        restart: RestartPolicy::FromReadyPoint,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 40 },
                    tag: tag("split-alt"),
                },
            ],
        )
        .unwrap_or_else(|error| panic!("changed-tag plan should be valid: {error}"));
        let changed_fault_plan = Plan::from_entries_for_world(
            &canonical_world,
            vec![
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 10 },
                    tag: tag("split"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node_id("b"),
                        endpoint_b: node_id("c"),
                        direction: PartitionDirection::Bidirectional,
                    },
                },
                PlanEntry::Activate {
                    at: VirtualTime { ticks: 20 },
                    tag: tag("crash-c"),
                    fault: MembershipFault::Crash {
                        node: node_id("c"),
                        restart: RestartPolicy::FromReadyPoint,
                    },
                },
                PlanEntry::Heal {
                    at: VirtualTime { ticks: 40 },
                    tag: tag("split"),
                },
            ],
        )
        .unwrap_or_else(|error| panic!("changed-fault plan should be valid: {error}"));
        let authored_properties = Properties::from_assertions_for_world(
            &authored_world,
            vec![
                assertion(
                    "settles",
                    "replicas settle",
                    Property::AfterQuiescence {
                        predicate: named_predicate("replicas_equal", &["b", "c"]),
                    },
                ),
                assertion(
                    "alive",
                    "nodes remain alive",
                    Property::Always {
                        predicate: Predicate::AllOf {
                            predicates: vec![
                                named_predicate("node_alive", &["c"]),
                                named_predicate("node_alive", &["a"]),
                            ],
                        },
                    },
                ),
            ],
        )
        .unwrap_or_else(|error| panic!("authored properties should be valid: {error}"));
        let canonical_properties = Properties::from_assertions_for_world(
            &canonical_world,
            vec![
                assertion(
                    "alive",
                    "nodes remain alive",
                    Property::Always {
                        predicate: Predicate::AllOf {
                            predicates: vec![
                                named_predicate("node_alive", &["a"]),
                                named_predicate("node_alive", &["c"]),
                            ],
                        },
                    },
                ),
                assertion(
                    "settles",
                    "replicas settle",
                    Property::AfterQuiescence {
                        predicate: named_predicate("replicas_equal", &["b", "c"]),
                    },
                ),
            ],
        )
        .unwrap_or_else(|error| panic!("canonical properties should be valid: {error}"));
        let changed_message_properties = Properties::from_assertions_for_world(
            &canonical_world,
            vec![
                assertion(
                    "alive",
                    "nodes stay alive",
                    Property::Always {
                        predicate: Predicate::AllOf {
                            predicates: vec![
                                named_predicate("node_alive", &["a"]),
                                named_predicate("node_alive", &["c"]),
                            ],
                        },
                    },
                ),
                assertion(
                    "settles",
                    "replicas settle",
                    Property::AfterQuiescence {
                        predicate: named_predicate("replicas_equal", &["b", "c"]),
                    },
                ),
            ],
        )
        .unwrap_or_else(|error| panic!("changed-message properties should be valid: {error}"));
        let changed_predicate_properties = Properties::from_assertions_for_world(
            &canonical_world,
            vec![
                assertion(
                    "alive",
                    "nodes remain alive",
                    Property::Always {
                        predicate: named_predicate("node_alive", &["a"]),
                    },
                ),
                assertion(
                    "settles",
                    "replicas settle",
                    Property::AfterQuiescence {
                        predicate: named_predicate("replicas_equal", &["b", "c"]),
                    },
                ),
            ],
        )
        .unwrap_or_else(|error| panic!("changed-predicate properties should be valid: {error}"));
        let seed = Seed::from_u64(0x0010_0019);
        let authored_form = ScenarioDefForm::from_components(
            &authored_world,
            &authored_plan,
            &authored_properties,
            seed,
        )
        .unwrap_or_else(|error| panic!("authored form should be valid: {error}"));
        let canonical_form = ScenarioDefForm::from_components(
            &canonical_world,
            &canonical_plan,
            &canonical_properties,
            seed,
        )
        .unwrap_or_else(|error| panic!("canonical form should be valid: {error}"));
        let other_seed_form = ScenarioDefForm::from_components(
            &canonical_world,
            &canonical_plan,
            &canonical_properties,
            Seed::from_u64(0x0010_0020),
        )
        .unwrap_or_else(|error| panic!("other-seed form should be valid: {error}"));
        let loss = LinkLossProbability::from_millionths(125_000)
            .unwrap_or_else(|error| panic!("fixed loss should be valid: {error}"));
        let density = FaultDensity::from_millionths(125_000)
            .unwrap_or_else(|error| panic!("fixed density should be valid: {error}"));
        let density_family = ScenarioFamily::new(
            FamilySpace::new(
                SeedSpace::explicit(vec![seed])
                    .unwrap_or_else(|error| panic!("density seed space should be valid: {error}")),
                FaultDensityRange::new(FaultDensity::ZERO, density)
                    .unwrap_or_else(|error| panic!("density range should be valid: {error}")),
                TopologySizeRange::new(4, 4).unwrap_or_else(|error| {
                    panic!("density topology range should be valid: {error}")
                }),
                vec![TopologyShape::Ring],
            )
            .unwrap_or_else(|error| panic!("density family space should be valid: {error}")),
            NodeTemplate::fixed_icount(Icount { retired: 8 }),
        );
        let zero_density_instance = density_family
            .instantiate(FamilyParams {
                seed,
                fault_density: FaultDensity::ZERO,
                topology_size: 4,
                topology_shape: TopologyShape::Ring,
            })
            .unwrap_or_else(|error| panic!("zero-density family should instantiate: {error}"));
        let fixed_density_instance = density_family
            .instantiate(FamilyParams {
                seed,
                fault_density: density,
                topology_size: 4,
                topology_shape: TopologyShape::Ring,
            })
            .unwrap_or_else(|error| panic!("fixed-density family should instantiate: {error}"));

        assert_eq!(loss.millionths(), 125_000);
        assert_eq!(density.millionths(), 125_000);
        assert_eq!(
            authored_world.id().to_hex(),
            "2f107a46c69f789cd0fa04ed4bca6e7c1d780594789e2167a80bf0dfe3bc21c3"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_world.canonical_bytes()).to_hex(),
            "ccd11b842c868487bd1417fba149d40afe0fb75e012217552da9999a2d081c00"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_world.to_compact_binary()).to_hex(),
            "d6b383bba7293f4ed649f2f2cded1d57a6117077fdbaeb29a3f9b989a5533c3b"
        );
        assert_eq!(
            authored_plan.content_hash().to_hex(),
            "f9e1e5c40ecbfce8d62e71476b59f2f207e6457ae947647c1e44ab1ad86f2e3a"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_plan.canonical_bytes()).to_hex(),
            "a8c0faf32016e717da4e1cf3e8ac99ce59ca80262a363fbf23b714aa5e604579"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_plan.to_compact_binary()).to_hex(),
            "28392e5c96b6e782ade455ceb679c1511d584a41a7b273afdd04a442480ae346"
        );
        assert_eq!(
            authored_properties.content_hash().to_hex(),
            "b20bc725db83e5943ed694b56a51b3b5d099734c9185a466ac6135f1b9ceff13"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_properties.canonical_bytes()).to_hex(),
            "9bc626347b695dea6dc28e300f95a2b7770af8717b681c02185d2bf3fcef6306"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_properties.to_compact_binary()).to_hex(),
            "068432cc28bbd3c94320ad87fda5794710c5fecc065ba81a003c2f6c98766e2a"
        );
        assert_eq!(
            authored_form.id().to_hex(),
            "e13a8e94a43857719319c913ba7036109d033e47263411799a8baee73a50ea94"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_form.canonical_bytes()).to_hex(),
            "d74fc071677d443ee8263436ab9279169085b3e1e121815b902b53339b0f4bb0"
        );
        assert_eq!(
            ContentHash::from_bytes(&authored_form.to_compact_binary()).to_hex(),
            "455912b3f3ad4878d8d40af3b41b75179d3ad06b7038081d2ed8993b42fa2a44"
        );
        assert_eq!(authored_world.id(), canonical_world.id());
        assert_eq!(authored_world.vm_nodes(), canonical_world.vm_nodes());
        assert_eq!(authored_world.links(), canonical_world.links());
        assert!(
            authored_world
                .to_compact_binary()
                .starts_with(b"crucible.world.v1\0")
        );
        assert!(
            authored_plan
                .to_compact_binary()
                .starts_with(b"crucible.plan.v1\0")
        );
        assert!(
            authored_properties
                .to_compact_binary()
                .starts_with(b"crucible.properties.v1\0")
        );
        assert!(
            authored_form
                .to_compact_binary()
                .starts_with(b"crucible.scenario-def-form.v1\0")
        );
        assert_eq!(
            authored_world.canonical_bytes(),
            canonical_world.canonical_bytes()
        );
        assert_eq!(
            authored_world.to_compact_binary(),
            canonical_world.to_compact_binary()
        );
        assert_eq!(
            authored_world
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("world TOML should serialize: {error}")),
            canonical_world
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("canonical world TOML should serialize: {error}"))
        );
        assert_ne!(authored_world.id(), changed_loss_world.id());
        assert_ne!(authored_world.id(), changed_ref_world.id());
        assert_ne!(authored_world.id(), changed_icount_world.id());
        assert_ne!(authored_world.id(), changed_duration_world.id());
        assert_ne!(authored_world.id(), changed_bandwidth_world.id());
        assert_eq!(authored_plan.content_hash(), canonical_plan.content_hash());
        assert_eq!(authored_plan.entries(), canonical_plan.entries());
        assert_eq!(
            authored_plan.canonical_bytes(),
            canonical_plan.canonical_bytes()
        );
        assert_eq!(
            authored_plan.to_compact_binary(),
            canonical_plan.to_compact_binary()
        );
        assert_eq!(
            authored_plan
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("plan TOML should serialize: {error}")),
            canonical_plan
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("canonical plan TOML should serialize: {error}"))
        );
        assert_ne!(
            authored_plan.content_hash(),
            changed_time_plan.content_hash()
        );
        assert_ne!(
            authored_plan.content_hash(),
            changed_tag_plan.content_hash()
        );
        assert_ne!(
            authored_plan.content_hash(),
            changed_fault_plan.content_hash()
        );
        assert_eq!(
            authored_properties.content_hash(),
            canonical_properties.content_hash()
        );
        assert_eq!(
            authored_properties.assertions(),
            canonical_properties.assertions()
        );
        assert_eq!(
            authored_properties.canonical_bytes(),
            canonical_properties.canonical_bytes()
        );
        assert_eq!(
            authored_properties.to_compact_binary(),
            canonical_properties.to_compact_binary()
        );
        assert_eq!(
            authored_properties
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("properties TOML should serialize: {error}")),
            canonical_properties
                .to_canonical_toml()
                .unwrap_or_else(|error| {
                    panic!("canonical properties TOML should serialize: {error}")
                })
        );
        assert_ne!(
            authored_properties.content_hash(),
            changed_message_properties.content_hash()
        );
        assert_ne!(
            authored_properties.content_hash(),
            changed_predicate_properties.content_hash()
        );
        assert_eq!(authored_form.id(), canonical_form.id());
        assert_eq!(authored_form.scenario_def(), canonical_form.scenario_def());
        assert_eq!(
            authored_form.canonical_bytes(),
            canonical_form.canonical_bytes()
        );
        assert_eq!(
            authored_form.to_compact_binary(),
            canonical_form.to_compact_binary()
        );
        assert_eq!(
            authored_form
                .to_canonical_toml()
                .unwrap_or_else(|error| panic!("scenario TOML should serialize: {error}")),
            canonical_form.to_canonical_toml().unwrap_or_else(|error| {
                panic!("canonical scenario TOML should serialize: {error}")
            })
        );
        assert_ne!(authored_form.id(), other_seed_form.id());
        assert_eq!(
            zero_density_instance.form().world(),
            fixed_density_instance.form().world()
        );
        assert_ne!(
            zero_density_instance.form().plan().content_hash(),
            fixed_density_instance.form().plan().content_hash()
        );
        assert_ne!(zero_density_instance.id(), fixed_density_instance.id());
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
            let uses_network_idle =
                matches!(&base_node.ready_point, ReadyPoint::NetworkIdle { .. })
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

        let mismatch_error = match TemporalGraph::empty().with_cached_snapshot(&config, mismatched)
        {
            Ok(_) => panic!("mismatched snapshot should be rejected"),
            Err(error) => error,
        };
        let thin_error = match TemporalGraph::empty().with_cached_snapshot(&config, thin) {
            Ok(_) => panic!("thin snapshot should be rejected"),
            Err(error) => error,
        };
        let scenario_error =
            match TemporalGraph::empty().with_cached_snapshot(&config, wrong_scenario) {
                Ok(_) => panic!("scenario-ref mismatch should be rejected"),
                Err(error) => error,
            };
        let parent_error = match TemporalGraph::empty().with_cached_snapshot(&config, wrong_parent)
        {
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

        let error = match TemporalGraph::empty()
            .with_cached_snapshot(&genesis, fat_checkpoint_for(&genesis))
        {
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

        let mismatch_error = match TemporalGraph::empty().with_baked_genesis(&scenario, mismatched)
        {
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

    fn generated_scenario(seed: u64) -> ScenarioDef {
        ScenarioDef::from_canonical_material_with_seed(
            "crucible.test.configuration.generated",
            &format!("node=a\nseed={seed}\nimage=generated-{seed:04}"),
            Seed::from_u64(seed),
        )
    }

    fn generated_world(seed: u64) -> World {
        World::from_content_hash(ContentHash::from_canonical_material(
            "crucible.test.world.generated",
            &format!("nodes=a,b\nlinks=a-b\nseed={seed}"),
        ))
    }

    fn world_from_nodes(nodes: Vec<WorldNode>) -> World {
        match World::from_nodes(nodes) {
            Ok(world) => world,
            Err(error) => panic!("test world should be valid: {error}"),
        }
    }

    fn world_from_nodes_and_links(nodes: Vec<WorldNode>, links: Vec<LinkDef>) -> World {
        match World::from_nodes_and_links(nodes, links) {
            Ok(world) => world,
            Err(error) => panic!("test world topology should be valid: {error}"),
        }
    }

    fn two_ready_nodes() -> Vec<WorldNode> {
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
    fn shmem_layout(
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
    fn world_with_physical_layout_id(
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

    fn ready_node(name: &str, ready_point: ReadyPoint) -> WorldNode {
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

    fn link(left: &str, right: &str) -> LinkDef {
        match LinkDef::new(node_id(left), node_id(right)) {
            Ok(link) => link,
            Err(error) => panic!("test link should be valid: {error}"),
        }
    }

    fn transport_link(
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

    fn node_id(name: &str) -> NodeId {
        NodeId {
            name: name.to_owned(),
        }
    }

    fn tag(name: &str) -> FaultTag {
        FaultTag::from_name(name)
    }

    fn assertion_id(name: &str) -> AssertionId {
        AssertionId::from_name(name)
    }

    fn marker_id(name: &str) -> MarkerId {
        MarkerId::from_name(name)
    }

    fn named_predicate(name: &str, nodes: &[&str]) -> Predicate {
        Predicate::Named {
            name: name.to_owned(),
            nodes: nodes.iter().map(|node| node_id(node)).collect(),
        }
    }

    fn assertion(name: &str, message: &str, property: Property) -> AssertionDef {
        AssertionDef {
            id: assertion_id(name),
            message: message.to_owned(),
            property,
        }
    }

    fn seeded_stream_map(
        streams: Vec<SeededRngStream>,
    ) -> std::collections::BTreeMap<RngStreamId, u64> {
        streams
            .into_iter()
            .map(|stream| (stream.stream, stream.seed))
            .collect()
    }

    fn device_id(name: &str) -> DeviceId {
        DeviceId {
            name: name.to_owned(),
        }
    }

    fn generated_schedule(seed: u64, len: u64) -> Schedule {
        let mut schedule = Schedule::empty();
        for index in 0..len {
            schedule = schedule.appended(generated_decision(seed, index));
        }
        schedule
    }

    fn drift_rate(numerator: u64, denominator: u64) -> ClockDriftRate {
        match ClockDriftRate::new(numerator, denominator) {
            Ok(rate) => rate,
            Err(error) => panic!("test drift rate should be valid: {error}"),
        }
    }

    fn material_with_skew(base: &str, skew: NodeClockSkew) -> String {
        match skew.scenario_hash_material() {
            Ok(Some(skew_material)) => format!("{base}\n{skew_material}"),
            Ok(None) => base.to_owned(),
            Err(error) => panic!("test clock skew material should be valid: {error}"),
        }
    }

    fn swap_first_two_decisions(schedule: &Schedule) -> Schedule {
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

    fn record_representative_decision(recorder: &mut DecisionRecorder, index: u64) {
        match index % 3 {
            0 => {
                let _ = recorder.draw_u64(RngStreamId::for_node(format!("node-a/faults/{index}")));
            }
            1 => {
                let _ = recorder.decide_fault_basis_points(
                    VirtualTime { ticks: index + 1 },
                    FaultId {
                        name: format!("link-a-b/drop-{index}"),
                    },
                    RngStreamId::for_node("node-b/faults"),
                    FaultRateBasisPoints::from_basis_points(5_000)
                        .unwrap_or_else(|error| panic!("test rate should be valid: {error}")),
                );
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

    fn configuration_execution_fingerprint(configuration: &Configuration) -> ExecutionFingerprint {
        let state = match reduce(&configuration.def, &configuration.schedule) {
            Ok(state) => state,
            Err(error) => panic!("pure configuration fingerprint should reduce: {error}"),
        };
        ExecutionFingerprint { hash: state.id }
    }

    fn reduced_state_id(configuration: &Configuration) -> ContentHash {
        match reduce(&configuration.def, &configuration.schedule) {
            Ok(state) => state.id,
            Err(error) => panic!("pure reduced state should construct: {error}"),
        }
    }

    fn corrupt_checkpoint_node_blob(
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

    fn fat_checkpoint_for(configuration: &Configuration) -> Checkpoint {
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

    fn fat_checkpoint_with_device_overlay(
        configuration: &Configuration,
        device: DeviceId,
    ) -> Checkpoint {
        let mut checkpoint = fat_checkpoint_for(configuration);
        checkpoint.state = Some(MaterializedState::from_components(
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::from([(device.clone(), device_overlay(&device.name))]),
            SchedulerState::empty(),
            DecisionRngState::empty(),
            EventLogOffset::default(),
        ));
        checkpoint
    }

    fn device_overlay(label: &str) -> DeviceOverlayDelta {
        let parent =
            ContentHash::from_canonical_material("crucible.test.device-overlay.parent", label);
        let delta =
            ContentHash::from_canonical_material("crucible.test.device-overlay.delta", label);
        let resolved =
            ContentHash::from_canonical_material("crucible.test.device-overlay.resolved", label);
        DeviceOverlayDelta::new(parent, delta, resolved, DeviceRngState::empty())
    }

    fn genesis_checkpoint_for(configuration: &Configuration) -> GenesisCheckpoint {
        GenesisCheckpoint {
            checkpoint: fat_checkpoint_for(configuration),
        }
    }

    fn event_key(virtual_time: u64, sequence: u64) -> EventKey {
        EventKey::new(
            VirtualTime {
                ticks: virtual_time,
            },
            scheduler_node("consumer"),
            scheduler_node("producer"),
            sequence,
        )
    }

    fn scheduler_node(name: &str) -> SchedulerNodeId {
        SchedulerNodeId {
            node: NodeId {
                name: name.to_owned(),
            },
            kind: SchedulingNodeKind::Vm,
        }
    }

    fn generated_decision(seed: u64, index: u64) -> Decision {
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
            1 => Decision::FaultFires(FaultDecision {
                at: VirtualTime {
                    ticks: seed.saturating_mul(2) + index,
                },
                fault: FaultId {
                    name: format!("fault-{seed}-{index}"),
                },
                fired: index.is_multiple_of(2),
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
