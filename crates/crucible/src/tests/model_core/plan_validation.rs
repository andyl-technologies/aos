//! Precise fault, healing, and virtual-time plan validation tests.

use super::*;

#[test]
fn plan_validation_reports_precise_fault_heal_and_time_errors() {
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

    let unknown_crash_target = Plan::from_entries_for_world(
        &world,
        vec![PlanEntry::Activate {
            at: VirtualTime { ticks: 5 },
            tag: tag("crash-missing"),
            fault: MembershipFault::Crash {
                node: node_id("missing"),
                restart: RestartPolicy::FromReadyPoint,
            },
        }],
    );
    let unknown_isolate_target = Plan::from_entries_for_world(
        &world,
        vec![PlanEntry::Activate {
            at: VirtualTime { ticks: 6 },
            tag: tag("isolate-missing"),
            fault: MembershipFault::Isolate {
                node: node_id("missing-isolate"),
            },
        }],
    );
    let unknown_partition_link = Plan::from_entries_for_world(
        &world,
        vec![PlanEntry::Activate {
            at: VirtualTime { ticks: 7 },
            tag: tag("split-bc"),
            fault: MembershipFault::Partition {
                endpoint_a: node_id("b"),
                endpoint_b: node_id("c"),
                direction: PartitionDirection::EndpointBToEndpointA,
            },
        }],
    );
    let unknown_heal_tag = Plan::from_entries_for_world(
        &world,
        vec![PlanEntry::Heal {
            at: VirtualTime { ticks: 8 },
            tag: tag("never-activated"),
        }],
    );
    let heal_before_activate = Plan::from_entries_for_world(
        &world,
        vec![
            PlanEntry::Activate {
                at: VirtualTime { ticks: 20 },
                tag: tag("split-ab"),
                fault: MembershipFault::Partition {
                    endpoint_a: node_id("a"),
                    endpoint_b: node_id("b"),
                    direction: PartitionDirection::Bidirectional,
                },
            },
            PlanEntry::Heal {
                at: VirtualTime { ticks: 10 },
                tag: tag("split-ab"),
            },
        ],
    );
    let not_yet_joined_after_start = Plan::from_entries_for_world(
        &world,
        vec![PlanEntry::Activate {
            at: VirtualTime { ticks: 1 },
            tag: tag("late-hold"),
            fault: MembershipFault::NotYetJoined { node: node_id("c") },
        }],
    );
    let start_time_not_yet_joined = Plan::from_entries_for_world(
        &world,
        vec![PlanEntry::Activate {
            at: VirtualTime::default(),
            tag: tag("initial-hold"),
            fault: MembershipFault::NotYetJoined { node: node_id("c") },
        }],
    );
    let direction_a_to_b = Plan::from_entries_for_world(
        &world,
        vec![PlanEntry::Activate {
            at: VirtualTime { ticks: 30 },
            tag: tag("one-way-split"),
            fault: MembershipFault::Partition {
                endpoint_a: node_id("a"),
                endpoint_b: node_id("b"),
                direction: PartitionDirection::EndpointAToEndpointB,
            },
        }],
    );
    let direction_b_to_a = Plan::from_entries_for_world(
        &world,
        vec![PlanEntry::Activate {
            at: VirtualTime { ticks: 30 },
            tag: tag("one-way-split"),
            fault: MembershipFault::Partition {
                endpoint_a: node_id("b"),
                endpoint_b: node_id("a"),
                direction: PartitionDirection::EndpointBToEndpointA,
            },
        }],
    );
    let negative_time_toml = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[entry]]
kind = "activate"
at_ticks = -1
tag = "negative-time"

[entry.fault]
kind = "crash"
node = "a"
restart = "stay_down"
"#;
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
    let unsupported_fault_param_toml = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[entry]]
kind = "activate"
at_ticks = 0
tag = "unsupported-rate"

[entry.fault]
kind = "crash"
node = "a"
restart = "stay_down"
rate = 1.5
"#;
    let negative_time = Plan::from_canonical_toml_for_world(&world, negative_time_toml);
    let unknown_direction = Plan::from_canonical_toml_for_world(&world, unknown_direction_toml);
    let unsupported_fault_param =
        Plan::from_canonical_toml_for_world(&world, unsupported_fault_param_toml);
    let valid_scenario_plan = Plan::from_entries_for_world(
        &world,
        vec![PlanEntry::Activate {
            at: VirtualTime::default(),
            tag: tag("scenario-crash"),
            fault: MembershipFault::Crash {
                node: node_id("a"),
                restart: RestartPolicy::StayDown,
            },
        }],
    )
    .unwrap_or_else(|error| panic!("scenario plan should be valid: {error}"));
    let valid_scenario_form = ScenarioDefForm::from_components(
        &world,
        &valid_scenario_plan,
        &Properties::empty(),
        Seed::from_u64(0x0010_0020),
    )
    .unwrap_or_else(|error| panic!("scenario form should be valid: {error}"));
    let scenario_negative_time_toml = valid_scenario_form
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("scenario TOML should serialize: {error}"))
        .replace("at_ticks = 0", "at_ticks = -2");
    let scenario_negative_time = ScenarioDefForm::from_canonical_toml(&scenario_negative_time_toml);

    assert!(matches!(
        unknown_crash_target,
        Err(EngineError::PlanFaultUnknownNode { node })
            if node == node_id("missing")
    ));
    assert!(matches!(
        unknown_isolate_target,
        Err(EngineError::PlanFaultUnknownNode { node })
            if node == node_id("missing-isolate")
    ));
    assert!(matches!(
        unknown_partition_link,
        Err(EngineError::PlanFaultUnknownLink {
            endpoint_a,
            endpoint_b,
        }) if endpoint_a == node_id("b") && endpoint_b == node_id("c")
    ));
    assert!(matches!(
        unknown_heal_tag,
        Err(EngineError::PlanHealUnknownTag { tag })
            if tag == self::tag("never-activated")
    ));
    assert!(matches!(
        heal_before_activate,
        Err(EngineError::PlanHealBeforeActivate {
            tag,
            activate_at,
            heal_at,
        }) if tag == self::tag("split-ab")
            && activate_at.ticks == 20
            && heal_at.ticks == 10
    ));
    assert!(matches!(
        not_yet_joined_after_start,
        Err(EngineError::PlanNotYetJoinedAfterStart { node, at })
            if node == node_id("c") && at.ticks == 1
    ));
    assert!(matches!(
        negative_time,
        Err(EngineError::PlanNegativeTime { entry, at_ticks })
            if entry == 0 && at_ticks == -1
    ));
    assert!(matches!(
        unknown_direction,
        Err(EngineError::PlanFaultUnknownDirection { entry, direction })
            if entry == 0 && direction == "sideways"
    ));
    assert!(matches!(
        unsupported_fault_param,
        Err(EngineError::PlanFaultUnsupportedParam { entry, field })
            if entry == 0 && field == "rate"
    ));
    assert!(matches!(
        scenario_negative_time,
        Err(EngineError::PlanNegativeTime { entry, at_ticks })
            if entry == 0 && at_ticks == -2
    ));

    let start_time_not_yet_joined =
        start_time_not_yet_joined.unwrap_or_else(|error| panic!("{error}"));
    let direction_a_to_b = direction_a_to_b.unwrap_or_else(|error| panic!("{error}"));
    let direction_b_to_a = direction_b_to_a.unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(start_time_not_yet_joined.entries().len(), 1);
    assert_eq!(
        direction_a_to_b.entries(),
        direction_b_to_a.entries(),
        "equivalent one-way partitions should canonicalize to the same fault params",
    );
    assert_eq!(
        direction_a_to_b.content_hash(),
        direction_b_to_a.content_hash()
    );
}
