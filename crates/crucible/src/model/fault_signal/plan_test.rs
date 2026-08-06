use super::*;
use crate::model::{
    Icount, LinkDef, MAX_REPRODUCTION_SCENARIO_BLOB_BYTES, MAX_SCENARIO_BINARY_BLOB_BYTES,
    NetworkPolicyArtifactKind, NetworkPolicyIntegerPoint, NetworkPolicyIntegerTable,
    NetworkPolicyInterpolation, NetworkPolicyOutsideRange, NodeId, Plan, ReadyPoint,
    ScenarioBinaryReader, ScenarioBinaryWriter, VmArchitecture, WhiteBoxPolicy, World,
    WorldFaultDomain, WorldFaultTargetRef, WorldFaultTopology, WorldMobileEndpoint,
    WorldNetworkForwarder, WorldNetworkForwarderKind, WorldNetworkInterface, WorldNetworkPath,
    WorldNetworkPathHop, WorldNetworkPolicyArtifact, WorldNetworkQueue,
    WorldNetworkQueueDiscipline, WorldNetworkQueueOverflow, WorldNetworkSegment,
    WorldNetworkSegmentKind, WorldNetworkTechnology, WorldNode, WorldNodeArchitecture,
};

fn test_link() -> LinkDef {
    LinkDef::new(
        NodeId {
            name: String::from("left"),
        },
        NodeId {
            name: String::from("right"),
        },
    )
    .unwrap_or_else(|error| panic!("test link: {error}"))
}

#[test]
fn network_effect_policy_references_are_typed_and_world_owned() {
    let program = program(true);
    let target = ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::NetworkSegment {
            segment: test_segment_id(),
            direction: FaultDirection::AToB,
        }],
        false,
    )
    .unwrap_or_else(|error| panic!("policy test target: {error}"));
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::ProfileDelta {
            latency_nanos: None,
            rate_cap_bps: None,
            loss_hazard: Some(object_id("loss-table")),
            corruption_hazard: None,
            technology_metrics: None,
        }),
    )
    .unwrap_or_else(|error| panic!("policy test effect: {error}"));
    let binding = FaultBinding::new(
        object_id("policy-binding"),
        program.exported_outputs().to_vec(),
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target),
        [FaultPhase::Resolve].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        &program,
    )
    .unwrap_or_else(|error| panic!("policy test binding: {error}"));
    let plan = Plan::empty().with_fault_signals(
        FaultSignalPlan::new(vec![program], vec![binding])
            .unwrap_or_else(|error| panic!("policy test plan: {error}")),
    );
    let world = test_world();
    assert!(plan.validate_for_world(&world).is_err());

    let mut topology = world.fault_topology().clone();
    topology
        .network_policy_artifacts
        .push(WorldNetworkPolicyArtifact {
            id: object_id("loss-table"),
            semantic_version: 1,
            artifact: NetworkPolicyArtifactKind::IntegerLookup(NetworkPolicyIntegerTable {
                input_unit: object_id("load"),
                output_unit: object_id("probability-millionths"),
                interpolation: NetworkPolicyInterpolation::Step,
                outside: NetworkPolicyOutsideRange::Clamp,
                points: vec![NetworkPolicyIntegerPoint {
                    input: 0,
                    output: 10_000,
                }],
            }),
        });
    let world = world
        .with_fault_topology(topology)
        .unwrap_or_else(|error| panic!("policy test topology: {error}"));
    plan.validate_for_world(&world)
        .unwrap_or_else(|error| panic!("typed policy reference should validate: {error}"));
}

fn test_segment_id() -> FaultObjectId {
    test_link()
        .fault_segment_id()
        .unwrap_or_else(|error| panic!("test segment ID: {error}"))
}

fn test_world() -> World {
    test_world_with_shift(0)
}

fn test_world_with_shift(icount_shift: u8) -> World {
    let nodes = ["left", "right"]
        .into_iter()
        .map(|name| WorldNode {
            id: NodeId {
                name: name.to_owned(),
            },
            arch: VmArchitecture::X86_64,
            memory_mib: 128,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: 1,
            icount_shift,
            kernel: None,
            root_image: None,
            initrd: None,
        })
        .collect();
    let world = World::from_nodes_and_links(nodes, vec![test_link()])
        .unwrap_or_else(|error| panic!("test world: {error}"));
    let segment = SignalId::parse(test_segment_id().as_str())
        .unwrap_or_else(|error| panic!("test segment signal ID: {error}"));
    world
        .with_fault_topology(WorldFaultTopology {
            fault_domains: vec![WorldFaultDomain {
                id: signal_id("campus-uplink"),
                targets: vec![WorldFaultTargetRef::NetworkSegment {
                    segment: segment.clone(),
                    direction: FaultDirection::AToB,
                }],
            }],
            network_interfaces: vec![
                WorldNetworkInterface {
                    id: signal_id("left-interface"),
                    endpoint: signal_id("left"),
                    technology: WorldNetworkTechnology::Ethernet,
                    addresses: Vec::new(),
                    fault_domains: Vec::new(),
                },
                WorldNetworkInterface {
                    id: signal_id("right-interface"),
                    endpoint: signal_id("right"),
                    technology: WorldNetworkTechnology::Ethernet,
                    addresses: Vec::new(),
                    fault_domains: Vec::new(),
                },
            ],
            network_segments: vec![WorldNetworkSegment {
                id: segment.clone(),
                kind: WorldNetworkSegmentKind::Ethernet,
                interface_a: signal_id("left-interface"),
                interface_b: signal_id("right-interface"),
                minimum_latency_nanos: 1,
                medium: None,
                forwarders: Vec::new(),
                fault_domains: vec![signal_id("campus-uplink")],
            }],
            network_paths: vec![WorldNetworkPath {
                id: signal_id("active-uplink"),
                hops: vec![WorldNetworkPathHop::Segment {
                    segment,
                    direction: FaultDirection::AToB,
                }],
                mtu_bytes: 1500,
            }],
            ..WorldFaultTopology::default()
        })
        .unwrap_or_else(|error| panic!("test fault topology: {error}"))
}

fn signal_id(value: &str) -> SignalId {
    SignalId::parse(value).unwrap_or_else(|error| panic!("invalid test signal ID: {error}"))
}

fn program(value: bool) -> SignalProgram {
    let output = signal_id(if value { "true-output" } else { "false-output" });
    SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
                .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::Bool(value),
            },
        }],
        vec![output],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test program: {error}"))
}

fn trajectory_program(shape: SignalShape, value: SignalValue) -> SignalProgram {
    let output = signal_id("vehicle-position-truth");
    SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: shape,
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant { value },
        }],
        vec![output],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid trajectory test program: {error}"))
}

fn object_id(value: &str) -> FaultObjectId {
    FaultObjectId::parse(value).unwrap_or_else(|error| panic!("invalid test object ID: {error}"))
}

fn binding(program: &SignalProgram) -> FaultBinding {
    binding_with_sampling(program, BindingSampling::AtBoundary)
}

fn binding_with_sampling(program: &SignalProgram, sampling: BindingSampling) -> FaultBinding {
    let target = ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::NetworkSegment {
            segment: test_segment_id(),
            direction: FaultDirection::AToB,
        }],
        false,
    )
    .unwrap_or_else(|error| panic!("invalid test target: {error}"));
    binding_with_selector(program, sampling, TargetSelector::Exact(target))
}

fn binding_with_selector(
    program: &SignalProgram,
    sampling: BindingSampling,
    selector: TargetSelector,
) -> FaultBinding {
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Down,
            queued_policy: NetworkInFlightPolicy::Drop,
            in_flight_policy: NetworkInFlightPolicy::Drop,
        }),
    )
    .unwrap_or_else(|error| panic!("invalid test effect: {error}"));
    FaultBinding::new(
        object_id("binding-a"),
        program.exported_outputs().to_vec(),
        sampling,
        BindingMapping::ActiveWhenTrue { invert: false },
        selector,
        [FaultPhase::Admit].into_iter().collect(),
        effect,
        None,
        BindingSearchPolicy::Fixed,
        BindingObservabilityPolicy {
            samples: SampleObservation::ChangesAndEffects,
            record_inactive_opportunities: false,
            retain_mapped_values: true,
        },
        program,
    )
    .unwrap_or_else(|error| panic!("invalid test binding: {error}"))
}

fn u64_program(value: u64) -> SignalProgram {
    let output = signal_id("u64-output");
    SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(SignalValueType::U64, SignalUnit::Dimensionless, 0)
                .unwrap_or_else(|error| panic!("invalid u64 shape: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Constant {
                value: SignalValue::U64(value),
            },
        }],
        vec![output],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid u64 program: {error}"))
}

fn periodic_pulse_program() -> SignalProgram {
    let output = signal_id("maintenance-window");
    SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
                .unwrap_or_else(|error| panic!("invalid pulse shape: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Source(SignalSourceSpecification::PeriodicPulse {
                epoch: SignalCoordinate::VirtualTime { nanos: 10 },
                period: 100,
                width: 25,
                phase: 5,
                inactive: SignalValue::Bool(false),
                active: SignalValue::Bool(true),
            }),
        }],
        vec![output],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid pulse program: {error}"))
}

fn trace_program() -> SignalProgram {
    let output = signal_id("recorded-vibration");
    SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::VirtualTime,
            output: SignalShape::new(
                SignalValueType::U64,
                SignalUnit::MicrometresPerSecondSquared,
                0,
            )
            .unwrap_or_else(|error| panic!("invalid trace shape: {error}")),
            inputs: Vec::new(),
            kind: SignalNodeKind::Source(SignalSourceSpecification::Trace {
                artifact: ContentHash::from_bytes(b"normalized-vibration"),
                raw_provenance: ContentHash::from_bytes(b"raw-vibration"),
                channel: signal_id("acceleration-rms"),
                quality_channel: None,
                quality_accept: None,
                interpolation: SignalInterpolation::Linear {
                    rounding: SignalRounding::NearestTiesToEven,
                    overflow: SignalOverflow::Error,
                },
                before: SignalBoundaryBehavior::Error,
                after: SignalBoundaryBehavior::Constant(SignalValue::U64(7)),
                missing: MissingSampleBehavior::Error,
                time_mapping: Some(TraceTimeMapping {
                    source_epoch: 1_720_000_000_000_000_000,
                    virtual_epoch_nanos: 0,
                    scale: ExactRatio::new(1, 1)
                        .unwrap_or_else(|error| panic!("trace scale: {error}")),
                    rounding: SignalRounding::Floor,
                }),
            }),
        }],
        vec![output],
        SignalResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid trace program: {error}"))
}

#[test]
fn one_plan_level_graph_is_required_and_duplicates_fail_closed() {
    let first = program(false);
    let second = program(true);
    assert!(matches!(
        FaultSignalPlan::new(vec![second, first.clone()], Vec::new()),
        Err(FaultSignalPlanError::TooManyPrograms { hard: 1, .. })
    ));
    assert!(matches!(
        FaultSignalPlan::new(vec![first.clone(), first], Vec::new()),
        Err(FaultSignalPlanError::DuplicateProgram)
    ));
}

#[test]
fn outer_plan_identity_commits_to_the_complete_fault_layer() {
    let program = program(true);
    let faults = FaultSignalPlan::new(vec![program], Vec::new())
        .unwrap_or_else(|error| panic!("fault plan admission failed: {error}"));
    let baseline = Plan::empty();
    let plan = baseline.clone().with_fault_signals(faults.clone());

    assert_eq!(plan.fault_signals(), &faults);
    assert_ne!(plan.content_hash(), baseline.content_hash());
    assert!(
        String::from_utf8(plan.canonical_bytes())
            .unwrap_or_else(|error| panic!("canonical material is not UTF-8: {error}"))
            .ends_with(&format!("fault-signal-plan={}", faults.id().to_hex()))
    );
}

#[test]
fn plan_toml_round_trips_an_admitted_signal_program() {
    let program = program(true);
    let faults = FaultSignalPlan::new(vec![program], Vec::new())
        .unwrap_or_else(|error| panic!("fault plan admission failed: {error}"));
    let plan = Plan::empty().with_fault_signals(faults);
    let encoded = plan
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode fault signal plan: {error}"));
    let decoded = Plan::from_canonical_toml_for_world(&test_world(), &encoded)
        .unwrap_or_else(|error| panic!("decode fault signal plan: {error}"));

    assert_eq!(decoded, plan);
    assert!(encoded.contains("[[signal]]"));
    assert!(!encoded.contains("signal_program"));
    assert!(encoded.contains("fault_signal_semantic_version = 1"));

    let without_version = encoded.replace("fault_signal_semantic_version = 1\n", "");
    assert!(Plan::from_canonical_toml_for_world(&test_world(), &without_version,).is_err());
}

#[test]
fn plan_toml_round_trips_a_complete_binding_contract() {
    let program = program(true);
    let binding = binding(&program);
    let faults = FaultSignalPlan::new(vec![program], vec![binding])
        .unwrap_or_else(|error| panic!("fault plan admission failed: {error}"));
    let plan = Plan::empty().with_fault_signals(faults);
    let encoded = plan
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode fault signal plan: {error}"));
    let decoded = Plan::from_canonical_toml_for_world(&test_world(), &encoded)
        .unwrap_or_else(|error| panic!("decode fault signal plan: {error}"));

    assert_eq!(decoded, plan);
    assert!(encoded.contains("[[fault_binding]]"));
    assert!(encoded.contains("kind = \"network.availability\""));
    assert!(encoded.contains("kind = \"network_segment\""));
    assert!(!encoded.contains("parameters ="));
}

#[test]
fn world_resolves_fault_domains_and_dynamic_paths_without_authored_caches() {
    let base_program = program(true);
    let binding = binding(&base_program);
    let plan = Plan::empty().with_fault_signals(
        FaultSignalPlan::new(vec![base_program], vec![binding])
            .unwrap_or_else(|error| panic!("binding plan: {error}")),
    );
    let canonical = plan
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode binding plan: {error}"));

    let resolved = ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::NetworkSegment {
            segment: test_segment_id(),
            direction: FaultDirection::AToB,
        }],
        false,
    )
    .unwrap_or_else(|error| panic!("resolved test path: {error}"));
    for (selector_toml, selector, expected_kind) in [
        (
            "{ kind = \"fault_domain\", domain = \"campus-uplink\" }",
            TargetSelector::FaultDomain {
                domain: object_id("campus-uplink"),
                resolved: resolved.clone(),
            },
            "fault_domain",
        ),
        (
            "{ kind = \"dynamic_path\", path = \"active-uplink\", membership_semantic_version = 1 }",
            TargetSelector::DynamicPath {
                path: object_id("active-uplink"),
                initial: resolved.clone(),
                membership_semantic_version: 1,
            },
            "dynamic_path",
        ),
    ] {
        let expected_program = program(true);
        let expected_binding =
            binding_with_selector(&expected_program, BindingSampling::AtBoundary, selector);
        let expected = Plan::empty().with_fault_signals(
            FaultSignalPlan::new(vec![expected_program], vec![expected_binding])
                .unwrap_or_else(|error| panic!("expected selector plan: {error}")),
        );
        let mut value: toml::Value = toml::from_str(&canonical)
            .unwrap_or_else(|error| panic!("parse canonical plan: {error}"));
        value
            .as_table_mut()
            .unwrap_or_else(|| panic!("plan is a table"))
            .insert(
                String::from("id"),
                toml::Value::String(format!("blake3:{}", expected.content_hash().to_hex())),
            );
        let bindings = value
            .get_mut("fault_binding")
            .and_then(toml::Value::as_array_mut)
            .unwrap_or_else(|| panic!("canonical plan has bindings"));
        let row = bindings[0]
            .as_table_mut()
            .unwrap_or_else(|| panic!("binding is a table"));
        let selector_value: toml::Value = toml::from_str(&format!("selector = {selector_toml}"))
            .unwrap_or_else(|error| panic!("parse selector: {error}"));
        row.insert(
            String::from("selector"),
            selector_value
                .get("selector")
                .cloned()
                .unwrap_or_else(|| panic!("selector value exists")),
        );
        let authored =
            toml::to_string(&value).unwrap_or_else(|error| panic!("render authored plan: {error}"));
        let decoded = Plan::from_canonical_toml_for_world(&test_world(), &authored)
            .unwrap_or_else(|error| panic!("resolve {expected_kind}: {error}"));
        assert_eq!(decoded, expected);
        let emitted = decoded
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("emit {expected_kind}: {error}"));
        assert!(emitted.contains(&format!("kind = \"{expected_kind}\"")));
        assert!(!emitted.contains("resolved_targets"));
        assert!(!emitted.contains("initial_targets"));
    }
}

#[test]
fn world_fault_topology_round_trips_through_only_v4_codecs() {
    let world = test_world();
    let toml = world
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode world TOML: {error}"));
    let from_toml = World::from_canonical_toml(&toml)
        .unwrap_or_else(|error| panic!("decode world TOML: {error}"));
    assert_eq!(from_toml, world);
    assert!(toml.contains("[[network_segment]]"));
    assert!(toml.contains("[[fault_domain]]"));

    let binary = world.to_compact_binary();
    assert!(binary.starts_with(b"crucible.world.v4\0"));
    assert_eq!(
        World::from_compact_binary(&binary)
            .unwrap_or_else(|error| panic!("decode world binary: {error}")),
        world
    );
    let mut old_magic = binary.clone();
    old_magic[..b"crucible.world.v3\0".len()].copy_from_slice(b"crucible.world.v3\0");
    assert!(World::from_compact_binary(&old_magic).is_err());
}

#[test]
fn singleton_signal_alias_canonicalizes_and_closed_tables_reject_unknowns() {
    let program = program(true);
    let binding = binding(&program);
    let plan = Plan::empty().with_fault_signals(
        FaultSignalPlan::new(vec![program], vec![binding])
            .unwrap_or_else(|error| panic!("binding plan: {error}")),
    );
    let canonical = plan
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode binding plan: {error}"));
    let alias = canonical.replace("signals = [\"true-output\"]", "signal = \"true-output\"");
    let decoded = Plan::from_canonical_toml_for_world(&test_world(), &alias)
        .unwrap_or_else(|error| panic!("decode singleton alias: {error}"));
    assert_eq!(decoded, plan);
    assert!(
        decoded
            .to_canonical_toml()
            .unwrap_or_else(|error| panic!("canonicalize singleton alias: {error}"))
            .contains("signals = [\"true-output\"]")
    );

    let unknown_mapping = canonical.replace(
        "invert = false\nkind = \"active_when_true\"",
        "invert = false\nkind = \"active_when_true\"\nunknown = 1",
    );
    assert!(Plan::from_canonical_toml_for_world(&test_world(), &unknown_mapping,).is_err());

    for rejected in [
        canonical.replace("kind = \"network_segment\"", "kind = \"sensor_channel\""),
        canonical.replace(
            "kind = \"network.availability\"",
            "kind = \"sensor.dropout\"",
        ),
    ] {
        assert!(Plan::from_canonical_toml_for_world(&test_world(), &rejected,).is_err());
    }
}

#[test]
fn mobile_truth_trajectory_requires_an_exact_exported_position_contract() {
    let base = test_world();
    let mut topology = base.fault_topology().clone();
    topology.mobile_endpoints.push(WorldMobileEndpoint {
        id: signal_id("delivery-vehicle"),
        node: signal_id("left"),
        truth_trajectory: signal_id("vehicle-position-truth"),
    });
    let world = base
        .with_fault_topology(topology)
        .unwrap_or_else(|error| panic!("mobile world: {error}"));

    assert!(Plan::empty().validate_for_world(&world).is_err());

    let shape = SignalShape::new(
        SignalValueType::Vector3(Box::new(SignalValueType::I64)),
        SignalUnit::Millimetres,
        0,
    )
    .unwrap_or_else(|error| panic!("trajectory shape: {error}"));
    let value = SignalValue::Vector3(vec![
        SignalValue::I64(0),
        SignalValue::I64(0),
        SignalValue::I64(0),
    ]);
    let valid = Plan::empty().with_fault_signals(
        FaultSignalPlan::new(vec![trajectory_program(shape, value)], Vec::new())
            .unwrap_or_else(|error| panic!("trajectory fault layer: {error}")),
    );
    valid
        .validate_for_world(&world)
        .unwrap_or_else(|error| panic!("valid trajectory: {error}"));

    let wrong_shape = SignalShape::new(
        SignalValueType::Vector3(Box::new(SignalValueType::I64)),
        SignalUnit::Millimetres,
        -1,
    )
    .unwrap_or_else(|error| panic!("wrong trajectory shape: {error}"));
    let wrong_value = SignalValue::Vector3(vec![
        SignalValue::I64(0),
        SignalValue::I64(0),
        SignalValue::I64(0),
    ]);
    let invalid = Plan::empty().with_fault_signals(
        FaultSignalPlan::new(
            vec![trajectory_program(wrong_shape, wrong_value)],
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("invalid trajectory fault layer: {error}")),
    );
    assert!(invalid.validate_for_world(&world).is_err());
}

#[test]
fn node_architecture_has_distinct_wire_and_selector_spellings() {
    assert_eq!(WorldNodeArchitecture::X86_64.selector_id(), "x86-64");
    assert_eq!(WorldNodeArchitecture::Aarch64.selector_id(), "aarch64");
    assert_eq!(
        serde_json::to_string(&WorldNodeArchitecture::X86_64)
            .unwrap_or_else(|error| panic!("architecture JSON: {error}")),
        "\"x86_64\""
    );
}

#[test]
fn fault_segments_must_cover_the_world_link_topology_exactly() {
    let world = test_world();
    let mut topology = world.fault_topology().clone();
    topology.network_segments.clear();
    topology.network_paths.clear();
    topology.fault_domains.clear();
    assert!(world.with_fault_topology(topology).is_err());
}

#[test]
fn plan_toml_round_trips_flat_analytic_source_fields() {
    let plan = Plan::empty().with_fault_signals(
        FaultSignalPlan::new(vec![periodic_pulse_program()], Vec::new())
            .unwrap_or_else(|error| panic!("pulse plan: {error}")),
    );
    let encoded = plan
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode pulse plan: {error}"));
    let decoded = Plan::from_canonical_toml_for_world(&test_world(), &encoded)
        .unwrap_or_else(|error| panic!("decode pulse plan: {error}"));

    assert_eq!(decoded, plan);
    assert!(encoded.contains("kind = \"periodic_pulse\""));
    assert!(!encoded.contains("kind = \"source\""));
    assert!(!encoded.contains("parameters ="));
}

#[test]
fn plan_toml_round_trips_flat_trace_arithmetic_and_boundaries() {
    let plan = Plan::empty().with_fault_signals(
        FaultSignalPlan::new(vec![trace_program()], Vec::new())
            .unwrap_or_else(|error| panic!("trace plan: {error}")),
    );
    let encoded = plan
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode trace plan: {error}"));
    let decoded = Plan::from_canonical_toml_for_world(&test_world(), &encoded)
        .unwrap_or_else(|error| panic!("decode trace plan: {error}"));

    assert_eq!(decoded, plan);
    assert!(encoded.contains("interpolation = \"linear\""));
    assert!(encoded.contains("rounding = \"nearest_ties_to_even\""));
    assert!(encoded.contains("after = \"constant\""));
    assert!(encoded.contains("after_value = 7"));
    assert!(encoded.contains("numerator = 1"));
    assert!(!encoded.contains("scale ="));
}

#[test]
fn plan_binary_round_trips_a_complete_binding_contract() {
    let program = program(true);
    let binding = binding(&program);
    let faults = FaultSignalPlan::new(vec![program], vec![binding])
        .unwrap_or_else(|error| panic!("fault plan admission failed: {error}"));
    let plan = Plan::empty().with_fault_signals(faults);
    let encoded = plan.to_compact_binary();
    let decoded = Plan::from_compact_binary_for_world(&test_world(), &encoded)
        .unwrap_or_else(|error| panic!("decode fault signal plan: {error}"));

    assert_eq!(decoded, plan);
    assert!(encoded.starts_with(b"crucible.plan.v4\0"));
    let mut old_magic = encoded.clone();
    old_magic[..b"crucible.plan.v3\0".len()].copy_from_slice(b"crucible.plan.v3\0");
    assert!(Plan::from_compact_binary_for_world(&test_world(), &old_magic,).is_err());
}

#[test]
fn wire_decode_reenters_identity_scalar_and_selector_validation() {
    assert!(serde_json::from_str::<SignalId>(r#""Not-Canonical""#).is_err());
    assert!(serde_json::from_str::<FaultObjectId>(r#""Not-Canonical""#).is_err());
    assert!(serde_json::from_str::<ProbabilityMillionths>("1000001").is_err());
    assert!(serde_json::from_str::<PositiveU64>("0").is_err());
    assert!(serde_json::from_str::<OperationSet>("[]").is_err());

    let valid = ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::NetworkSegment {
            segment: object_id("segment-a"),
            direction: FaultDirection::AToB,
        }],
        false,
    )
    .unwrap_or_else(|error| panic!("valid selector: {error}"));
    let mut value =
        serde_json::to_value(valid).unwrap_or_else(|error| panic!("encode selector JSON: {error}"));
    value["targets"] = serde_json::Value::Array(Vec::new());
    assert!(serde_json::from_value::<ResolvedTargetSet>(value).is_err());
}

#[test]
fn wire_admission_rejects_versions_missing_programs_and_duplicate_contracts() {
    let program = program(true);
    let binding = binding(&program);
    let plan = FaultSignalPlan::new(vec![program], vec![binding])
        .unwrap_or_else(|error| panic!("fault plan admission failed: {error}"));

    let mut wrong_version = FaultSignalPlanWire::from_plan(&plan);
    wrong_version.semantic_version += 1;
    assert!(matches!(
        wrong_version.admit(),
        Err(FaultSignalWireError::Version { .. })
    ));

    let mut missing_program = FaultSignalPlanWire::from_plan(&plan);
    missing_program.fault_binding[0].program = ContentHash::from_bytes(b"missing-program");
    assert!(matches!(
        missing_program.admit(),
        Err(FaultSignalWireError::MissingProgram { .. })
    ));

    let mut duplicate_program = FaultSignalPlanWire::from_plan(&plan);
    duplicate_program
        .signal_program
        .push(duplicate_program.signal_program[0].clone());
    assert!(matches!(
        duplicate_program.admit(),
        Err(FaultSignalWireError::Plan(
            FaultSignalPlanError::DuplicateProgram
        ))
    ));

    let mut unexpected_declaration = FaultSignalPlanWire::from_plan(&plan);
    unexpected_declaration.fault_binding[0].service_declaration = Some(ServiceProfileDeclaration {
        id: object_id("unused-service"),
        semantic_version: 1,
        effect: EffectKind::NetworkAvailability,
        inputs: vec![
            SignalShape::new(SignalValueType::U64, SignalUnit::Dimensionless, 0)
                .unwrap_or_else(|error| panic!("service input shape: {error}")),
        ],
        parameters: vec![MappedEffectParameter::UnsignedCount],
    });
    assert!(matches!(
        unexpected_declaration.admit(),
        Err(FaultSignalWireError::UnexpectedMappingDeclaration { .. })
    ));

    let mut missing_declaration = FaultSignalPlanWire::from_plan(&plan);
    missing_declaration.fault_binding[0].mapping = BindingMapping::StateTransition {
        transition_table: object_id("missing-transition-table"),
    };
    assert!(matches!(
        missing_declaration.admit(),
        Err(FaultSignalWireError::MissingMappingDeclaration { .. })
    ));
}

#[test]
fn wire_encoding_is_bounded_and_empty_encoding_is_canonical() {
    let empty = FaultSignalPlan::empty();
    let decoded = FaultSignalPlan::from_wire_bytes(empty.wire_bytes())
        .unwrap_or_else(|error| panic!("decode empty plan: {error}"));
    assert_eq!(decoded, empty);

    let error = match encode_wire_bounded(&vec![0_u8; 32], 8) {
        Ok(_) => panic!("bounded encoder must reject oversized output"),
        Err(error) => error,
    };
    assert!(error.is_io());
}

#[test]
fn reproduction_scenario_envelope_contains_a_maximum_fault_wire_layer() {
    assert_eq!(
        MAX_REPRODUCTION_SCENARIO_BLOB_BYTES,
        MAX_SCENARIO_BINARY_BLOB_BYTES + HARD_FAULT_SIGNAL_PLAN_WIRE_BYTES,
    );

    let magic = b"blob-boundary-test\0";
    let mut writer = ScenarioBinaryWriter::new(magic);
    writer.write_count(MAX_SCENARIO_BINARY_BLOB_BYTES + 1);
    let bytes = writer.finish();

    let mut ordinary = ScenarioBinaryReader::new(&bytes, magic)
        .unwrap_or_else(|error| panic!("ordinary reader: {error}"));
    let ordinary_error = match ordinary.read_binary_blob("ordinary") {
        Ok(_) => panic!("ordinary blobs stop at their original limit"),
        Err(error) => error,
    };
    assert!(ordinary_error.to_string().contains("blob limit"));

    let mut enclosing = ScenarioBinaryReader::new(&bytes, magic)
        .unwrap_or_else(|error| panic!("enclosing reader: {error}"));
    let enclosing_error = match enclosing
        .read_binary_blob_bounded("scenario", MAX_REPRODUCTION_SCENARIO_BLOB_BYTES)
    {
        Ok(_) => panic!("the synthetic blob has no payload"),
        Err(error) => error,
    };
    assert!(!enclosing_error.to_string().contains("blob limit"));
}

#[test]
fn toml_round_trips_full_range_u64_values_without_narrowing() {
    let numeric_program = u64_program(u64::MAX);
    let numeric_plan = Plan::empty().with_fault_signals(
        FaultSignalPlan::new(vec![numeric_program], Vec::new())
            .unwrap_or_else(|error| panic!("numeric plan: {error}")),
    );
    let numeric_toml = numeric_plan
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode u64::MAX signal: {error}"));
    assert!(numeric_toml.contains("u64:18446744073709551615"));
    assert_eq!(
        Plan::from_canonical_toml_for_world(&test_world(), &numeric_toml,)
            .unwrap_or_else(|error| panic!("decode u64::MAX signal: {error}")),
        numeric_plan,
    );

    let program = program(true);
    let binding = binding_with_sampling(
        &program,
        BindingSampling::CadenceNanos(
            PositiveU64::new("cadence_nanos", u64::MAX)
                .unwrap_or_else(|error| panic!("max cadence: {error}")),
        ),
    );
    let cadence_plan = Plan::empty().with_fault_signals(
        FaultSignalPlan::new(vec![program], vec![binding])
            .unwrap_or_else(|error| panic!("cadence plan: {error}")),
    );
    let cadence_toml = cadence_plan
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode max cadence: {error}"));
    assert_eq!(
        Plan::from_canonical_toml_for_world(&test_world(), &cadence_toml,)
            .unwrap_or_else(|error| panic!("decode max cadence: {error}")),
        cadence_plan,
    );
}

#[test]
fn world_validation_rejects_unrepresentable_binding_wakeups() {
    let program = program(true);
    let binding = binding_with_sampling(
        &program,
        BindingSampling::CadenceNanos(
            PositiveU64::new("cadence_nanos", 6).unwrap_or_else(|error| panic!("cadence: {error}")),
        ),
    );
    let plan = FaultSignalPlan::new(vec![program], vec![binding])
        .unwrap_or_else(|error| panic!("fault plan: {error}"));

    let error = plan
        .validate_for_world(&test_world_with_shift(2))
        .expect_err("6ns cannot be represented when one instruction is 4ns");
    assert!(error.to_string().contains("is not representable"));
    plan.validate_for_world(&test_world())
        .unwrap_or_else(|error| {
            panic!("shift zero should admit every integer nanosecond: {error}")
        });
}

#[test]
fn world_toml_round_trips_wide_topology_u64_values_canonically() {
    let world = test_world();
    let mut topology = world.fault_topology().clone();
    topology.network_queues.push(WorldNetworkQueue {
        id: signal_id("wide-queue"),
        owner: signal_id("left-interface"),
        capacity_packets: 1,
        capacity_bytes: u64::MAX,
        discipline: WorldNetworkQueueDiscipline::Fifo,
        overflow: WorldNetworkQueueOverflow::DropTail,
        fault_domains: Vec::new(),
    });
    let world = world
        .with_fault_topology(topology)
        .unwrap_or_else(|error| panic!("wide topology: {error}"));
    let encoded = world
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("encode wide topology: {error}"));
    assert!(encoded.contains("capacity_bytes = \"u64:18446744073709551615\""));
    assert_eq!(
        World::from_canonical_toml(&encoded)
            .unwrap_or_else(|error| panic!("decode wide topology: {error}")),
        world,
    );
}

#[test]
fn compact_plan_rejects_resolved_targets_absent_from_decode_world() {
    let program = program(true);
    let binding = binding(&program);
    let plan = Plan::empty().with_fault_signals(
        FaultSignalPlan::new(vec![program], vec![binding])
            .unwrap_or_else(|error| panic!("binding plan: {error}")),
    );
    let world_without_targets = test_world()
        .with_fault_topology(WorldFaultTopology::default())
        .unwrap_or_else(|error| panic!("empty fault topology: {error}"));
    assert!(
        Plan::from_compact_binary_for_world(&world_without_targets, &plan.to_compact_binary())
            .is_err()
    );
}

#[test]
fn world_rejects_adjacent_forwarders_in_a_network_path() {
    let world = test_world();
    let mut topology = world.fault_topology().clone();
    for id in ["first-forwarder", "second-forwarder"] {
        topology.network_forwarders.push(WorldNetworkForwarder {
            id: signal_id(id),
            kind: WorldNetworkForwarderKind::Router,
            ports: vec![signal_id("right-interface")],
            table_capacity: 1,
            fault_domains: Vec::new(),
        });
    }
    topology.network_paths[0].hops.extend([
        WorldNetworkPathHop::Forwarder {
            forwarder: signal_id("first-forwarder"),
        },
        WorldNetworkPathHop::Forwarder {
            forwarder: signal_id("second-forwarder"),
        },
    ]);
    assert!(world.with_fault_topology(topology).is_err());
}
