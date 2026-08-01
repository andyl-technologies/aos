//! Checks T-GHC-3 black-box readiness heuristic resolution.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    EngineError, Icount, LinkDef, LinkId, NodeId, NodeTemplate, ObservableEvent, ReadyPoint,
    ReadyPointResolutionError, ReadyPointResolutionKind, SimDuration, VirtualTime, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode, resolve_ready_point,
};

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn duration(nanos: u64) -> SimDuration {
    SimDuration { nanos }
}

fn ready_node(name: &str, ready_point: ReadyPoint) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
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

#[test]
fn fixed_icount_readiness_resolves_to_deterministic_icount_and_virtual_time() {
    let world = World::from_nodes(vec![WorldNode {
        icount_shift: 2,
        ..ready_node("vm", ReadyPoint::FixedIcount { icount: icount(7) })
    }])
    .expect("fixed icount ready point should validate");

    let resolved = resolve_ready_point(&world, &node("vm"), time(0), &[])
        .expect("fixed icount ready point should resolve without observations");

    assert_eq!(resolved.node(), &node("vm"));
    assert_eq!(resolved.kind(), ReadyPointResolutionKind::FixedIcount);
    assert_eq!(resolved.icount(), icount(7));
    assert_eq!(resolved.virtual_time(), time(28));
}

#[test]
fn shifted_black_box_readiness_reports_one_coherent_icount_boundary() {
    let console_world = World::from_nodes(vec![WorldNode {
        icount_shift: 2,
        ..ready_node(
            "vm",
            ReadyPoint::ConsoleMarker {
                marker: String::from("ready!"),
            },
        )
    }])
    .expect("console marker ready point should validate");
    let console_observations = vec![ObservableEvent::console_output(
        time(11),
        node("vm"),
        b"ready!".to_vec(),
    )];

    let console_resolved =
        resolve_ready_point(&console_world, &node("vm"), time(11), &console_observations)
            .expect("console marker should resolve to the next icount boundary");

    assert_eq!(
        console_resolved.kind(),
        ReadyPointResolutionKind::ConsoleMarker
    );
    assert_eq!(console_resolved.icount(), icount(3));
    assert_eq!(console_resolved.virtual_time(), time(12));

    let network_world = World::from_nodes_and_links(
        vec![
            WorldNode {
                icount_shift: 2,
                ..ready_node(
                    "server",
                    ReadyPoint::NetworkIdle {
                        window: duration(6),
                    },
                )
            },
            ready_node("client", ReadyPoint::FixedIcount { icount: icount(1) }),
        ],
        vec![LinkDef::new(node("client"), node("server")).expect("link endpoints differ")],
    )
    .expect("network idle ready point should validate with an incident link");
    let network_observations = vec![ObservableEvent::network_delivered(
        time(5),
        Some(LinkId::from_name("client--server")),
        b"syn".to_vec(),
    )];

    let network_resolved = resolve_ready_point(
        &network_world,
        &node("server"),
        time(11),
        &network_observations,
    )
    .expect("network idle should resolve to the next icount boundary");

    assert_eq!(
        network_resolved.kind(),
        ReadyPointResolutionKind::FirstNetworkIdle
    );
    assert_eq!(network_resolved.icount(), icount(3));
    assert_eq!(network_resolved.virtual_time(), time(12));
}

#[test]
fn console_marker_readiness_resolves_from_host_side_output_stream() {
    let world = World::from_nodes(vec![ready_node(
        "vm",
        ReadyPoint::ConsoleMarker {
            marker: String::from("ready!"),
        },
    )])
    .expect("console marker ready point should validate");
    let observations = vec![
        ObservableEvent::console_output(time(8), node("vm"), b"boot rea".to_vec()),
        ObservableEvent::console_output(time(9), node("other"), b"ready!".to_vec()),
        ObservableEvent::console_output(time(11), node("vm"), b"dy!\n".to_vec()),
    ];

    let resolved = resolve_ready_point(&world, &node("vm"), time(11), &observations)
        .expect("console marker should resolve at the event that completes the marker");

    assert_eq!(resolved.kind(), ReadyPointResolutionKind::ConsoleMarker);
    assert_eq!(resolved.icount(), icount(11));
    assert_eq!(resolved.virtual_time(), time(11));
}

#[test]
fn console_marker_readiness_canonicalizes_same_time_chunks() {
    let world = World::from_nodes(vec![ready_node(
        "vm",
        ReadyPoint::ConsoleMarker {
            marker: String::from("ab"),
        },
    )])
    .expect("console marker ready point should validate");
    let first_order = vec![
        ObservableEvent::console_output(time(7), node("vm"), b"b".to_vec()),
        ObservableEvent::console_output(time(7), node("vm"), b"a".to_vec()),
    ];
    let second_order = vec![
        ObservableEvent::console_output(time(7), node("vm"), b"a".to_vec()),
        ObservableEvent::console_output(time(7), node("vm"), b"b".to_vec()),
    ];

    let first = resolve_ready_point(&world, &node("vm"), time(7), &first_order)
        .expect("same-time console chunks should have canonical order");
    let second = resolve_ready_point(&world, &node("vm"), time(7), &second_order)
        .expect("same-time console chunks should have canonical order");

    assert_eq!(first, second);
    assert_eq!(first.kind(), ReadyPointResolutionKind::ConsoleMarker);
    assert_eq!(first.icount(), icount(7));
    assert_eq!(first.virtual_time(), time(7));
}

#[test]
fn console_marker_readiness_ignores_observations_after_frontier() {
    let world = World::from_nodes(vec![ready_node(
        "vm",
        ReadyPoint::ConsoleMarker {
            marker: String::from("ready!"),
        },
    )])
    .expect("console marker ready point should validate");
    let observations = vec![
        ObservableEvent::console_output(time(8), node("vm"), b"boot rea".to_vec()),
        ObservableEvent::console_output(time(11), node("vm"), b"dy!\n".to_vec()),
    ];

    assert_eq!(
        resolve_ready_point(&world, &node("vm"), time(10), &observations),
        Err(ReadyPointResolutionError::ConsoleMarkerNotObserved {
            node: node("vm"),
            marker: String::from("ready!"),
        })
    );

    let resolved = resolve_ready_point(&world, &node("vm"), time(11), &observations)
        .expect("console marker should resolve once its completing event is observed");

    assert_eq!(resolved.kind(), ReadyPointResolutionKind::ConsoleMarker);
    assert_eq!(resolved.icount(), icount(11));
    assert_eq!(resolved.virtual_time(), time(11));
}

#[test]
fn network_idle_readiness_resolves_first_quiescent_link_window() {
    let world = World::from_nodes_and_links(
        vec![
            ready_node(
                "server",
                ReadyPoint::NetworkIdle {
                    window: duration(10),
                },
            ),
            ready_node("client", ReadyPoint::FixedIcount { icount: icount(1) }),
        ],
        vec![LinkDef::new(node("client"), node("server")).expect("link endpoints differ")],
    )
    .expect("network idle ready point should validate");
    let link = LinkId::from_name("client--server");
    let observations = vec![
        ObservableEvent::network_delivered(time(5), Some(link.clone()), b"syn".to_vec()),
        ObservableEvent::network_delivered(time(11), Some(link), b"ack".to_vec()),
    ];

    assert_eq!(
        resolve_ready_point(&world, &node("server"), time(20), &observations),
        Err(ReadyPointResolutionError::NetworkIdleWindowNotReached {
            node: node("server"),
            window: duration(10),
        })
    );

    let resolved = resolve_ready_point(&world, &node("server"), time(21), &observations)
        .expect("network idle window should resolve after the first quiet span");

    assert_eq!(resolved.kind(), ReadyPointResolutionKind::FirstNetworkIdle);
    assert_eq!(resolved.icount(), icount(21));
    assert_eq!(resolved.virtual_time(), time(21));
}

#[test]
fn network_idle_readiness_treats_same_tick_activity_as_not_idle() {
    let world = World::from_nodes_and_links(
        vec![
            ready_node(
                "server",
                ReadyPoint::NetworkIdle {
                    window: duration(10),
                },
            ),
            ready_node("client", ReadyPoint::FixedIcount { icount: icount(1) }),
        ],
        vec![LinkDef::new(node("client"), node("server")).expect("link endpoints differ")],
    )
    .expect("network idle ready point should validate");
    let link = LinkId::from_name("client--server");
    let observations = vec![
        ObservableEvent::network_delivered(time(5), Some(link.clone()), b"syn".to_vec()),
        ObservableEvent::network_delivered(time(15), Some(link), b"ack".to_vec()),
    ];

    assert_eq!(
        resolve_ready_point(&world, &node("server"), time(15), &observations),
        Err(ReadyPointResolutionError::NetworkIdleWindowNotReached {
            node: node("server"),
            window: duration(10),
        })
    );

    let resolved = resolve_ready_point(&world, &node("server"), time(25), &observations)
        .expect("network idle should resolve after the same-tick activity starts a new window");

    assert_eq!(resolved.kind(), ReadyPointResolutionKind::FirstNetworkIdle);
    assert_eq!(resolved.icount(), icount(25));
    assert_eq!(resolved.virtual_time(), time(25));
}

#[test]
fn readiness_validation_rejects_nondeterministic_or_degenerate_parameters() {
    assert_eq!(
        World::from_nodes(vec![ready_node(
            "idle",
            ReadyPoint::NetworkIdle {
                window: duration(0),
            },
        )]),
        Err(EngineError::ReadyPointNetworkIdleWindowZero { node: node("idle") })
    );

    assert_eq!(
        World::from_nodes(vec![ready_node(
            "console",
            ReadyPoint::ConsoleMarker {
                marker: String::new(),
            },
        )]),
        Err(EngineError::ReadyPointConsoleMarkerEmpty {
            node: node("console"),
        })
    );

    assert_eq!(
        World::from_nodes(vec![ready_node(
            "isolated",
            ReadyPoint::NetworkIdle {
                window: duration(1),
            },
        )]),
        Err(EngineError::ReadyPointNetworkIdleWithoutLinks {
            node: node("isolated"),
        })
    );
}

#[test]
fn agent_signal_readiness_is_not_black_box_resolvable() {
    let world = World::from_nodes(vec![WorldNode {
        white_box: WhiteBoxPolicy::Enabled,
        ..ready_node("agent", ReadyPoint::AgentSignal)
    }])
    .expect("agent-signal ready point is valid only with white-box opt-in");

    assert_eq!(
        resolve_ready_point(&world, &node("agent"), time(100), &[]),
        Err(
            ReadyPointResolutionError::AgentSignalRequiresWhiteBoxChannel {
                node: node("agent"),
            }
        )
    );
}
