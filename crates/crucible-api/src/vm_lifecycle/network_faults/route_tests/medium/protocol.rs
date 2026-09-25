//! Protocol forwarding, retry, MTU, and RF route tests.

use super::*;

fn ethernet_ipv4_frame(data: &[u8], flags_offset: u16) -> Vec<u8> {
    const ETHERNET_HEADER: usize = 14;
    const IPV4_HEADER: usize = 20;
    let total_length = u16::try_from(IPV4_HEADER + data.len())
        .unwrap_or_else(|error| panic!("test IPv4 packet length: {error}"));
    let mut frame = vec![0_u8; ETHERNET_HEADER + IPV4_HEADER];
    frame[0..6].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
    frame[6..12].copy_from_slice(&[6, 7, 8, 9, 10, 11]);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&total_length.to_be_bytes());
    frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_offset.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
    frame[30..34].copy_from_slice(&[198, 51, 100, 2]);
    frame.extend_from_slice(data);
    frame
}

#[test]
fn forwarding_mutations_use_selectors_canonical_recipients_and_hop_limits() {
    let selector = id("forwarding-selector");
    let mut topology = crucible::model::WorldFaultTopology::default();
    topology
        .network_policy_artifacts
        .push(crucible::model::WorldNetworkPolicyArtifact {
            id: selector.clone(),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::PacketSelector {
                matches: vec![crucible::model::NetworkPolicyByteMatch {
                    offset_bytes: 0,
                    value: vec![0xaa],
                    mask: vec![0xff],
                }],
            },
        });
    let recipients = crucible::model::ObjectIdSet::new(vec![id("receiver-b"), id("receiver-a")])
        .unwrap_or_else(|error| panic!("test recipients: {error}"));
    let flood = action_with_network_effect(NetworkEffectSpecification::ForwardingMutation {
        selector: selector.clone(),
        mutation: crucible::model::NetworkForwardingMutationKind::Flood { recipients },
    });
    let mut payload = vec![0xaa];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    let application = apply_network_frame_actions_with_limits(
        &mut payload,
        &mut effects,
        &[flood],
        &opportunity(1),
        ContentHash::from_bytes(b"forwarding"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("flood mutation: {error}"));
    assert_eq!(
        application.forwarding_recipients,
        Some(vec![id("receiver-a"), id("receiver-b")])
    );
    assert!(effects.is_dropped());

    let loop_action = action_with_network_effect(NetworkEffectSpecification::ForwardingMutation {
        selector,
        mutation: crucible::model::NetworkForwardingMutationKind::Loop {
            next_hop: id("receiver-a"),
            hop_limit: positive(1),
        },
    });
    let exhausted = FaultOpportunity::new(
        loop_action.target.clone(),
        crucible::model::FaultOperation::NetworkTraverse,
        FaultPhase::Resolve,
        FaultCoordinate {
            virtual_ticks: 0,
            retired_instructions: None,
        },
        2,
        Some(crucible::model::FaultDirection::AToB),
        OpportunityPayload::NetworkFrame {
            producer: id("sender"),
            destination: id("receiver"),
            producer_sequence: 2,
            protocol_expansion_path: Vec::new(),
            generated_response_depth: 0,
            generated_response_cause: None,
            forwarding_mutation_path: vec![ContentHash::from_bytes(b"prior-hop")],
            length_bytes: 1,
            payload_digest: ContentHash::from_bytes(&payload),
        },
    )
    .unwrap_or_else(|error| panic!("loop opportunity: {error}"));
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let application = apply_network_frame_actions_with_limits(
        &mut payload,
        &mut effects,
        &[loop_action],
        &exhausted,
        ContentHash::from_bytes(b"forwarding"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("loop mutation: {error}"));
    assert_eq!(application.forwarding_recipients, Some(Vec::new()));
    assert!(effects.is_dropped());
    record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkForwardingMutation],
        "forwarding-recipient-and-loop-matrix",
        "canonical-recipients+hop-limit+drop",
    );
}

#[test]
fn firewall_and_connection_state_are_bounded_exhaustive_and_timed() {
    let selector = id("stateful-selector");
    let key = id("flow-key");
    let machine = id("flow-machine");
    let event = id("packet-event");
    let transition = |from: &str, to: &str, delay_nanos| crucible::model::NetworkPolicyTransition {
        from: id(from),
        event: event.clone(),
        to: id(to),
        delay_nanos,
        traffic_policy: crucible::model::NetworkInFlightPolicy::Preserve,
    };
    let mut topology = crucible::model::WorldFaultTopology {
        network_policy_artifacts: vec![
            crucible::model::WorldNetworkPolicyArtifact {
                id: selector.clone(),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::PacketSelector {
                    matches: vec![crucible::model::NetworkPolicyByteMatch {
                        offset_bytes: 0,
                        value: vec![0xaa],
                        mask: vec![0xff],
                    }],
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: key.clone(),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::PacketKey {
                    ranges: vec![
                        crucible::model::ByteRange::new(0, 1)
                            .unwrap_or_else(|error| panic!("test packet key: {error}")),
                    ],
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: machine.clone(),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::StateMachine {
                    initial: id("cold"),
                    states: vec![id("cold"), id("warm")],
                    transitions: vec![
                        transition("cold", "warm", 10),
                        transition("warm", "warm", 10),
                    ],
                },
            },
        ],
        ..Default::default()
    };
    topology
        .network_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));
    let firewall = action_with_network_effect(NetworkEffectSpecification::FirewallDisposition {
        action: crucible::model::NetworkFirewallAction::Drop,
        typed_reject: None,
        rule: selector,
        state_machine: machine.clone(),
        transition_event: event.clone(),
    });
    let mut payload = vec![0xaa];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    let application = apply_network_frame_actions_with_limits(
        &mut payload,
        &mut effects,
        &[firewall],
        &opportunity(10),
        ContentHash::from_bytes(b"stateful"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("firewall state: {error}"));
    assert!(effects.is_dropped());
    assert_eq!(application.next_wakeup_ticks, Some(80));
    assert_eq!(state.state_machines.len(), 1);

    let bound = crucible::model::BoundedCount::new(CountLimit::LargeStateEntries, 1)
        .unwrap_or_else(|error| panic!("test table bound: {error}"));
    let connection = action_with_network_effect(NetworkEffectSpecification::ConnectionState {
        kind: crucible::model::NetworkConnectionKind::Conntrack,
        table_bound: bound,
        flow_key: key,
        state_machine: machine,
        transition_event: event,
        overflow: crucible::model::NetworkConnectionOverflow::DropNewest,
    });
    let mut first = vec![0xaa];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    apply_network_frame_actions_with_limits(
        &mut first,
        &mut effects,
        std::slice::from_ref(&connection),
        &opportunity(11),
        ContentHash::from_bytes(b"stateful"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("first connection: {error}"));
    assert!(!effects.is_dropped());
    let mut second = vec![0xbb];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    apply_network_frame_actions_with_limits(
        &mut second,
        &mut effects,
        &[connection],
        &opportunity(12),
        ContentHash::from_bytes(b"stateful"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("overflow connection: {error}"));
    assert!(effects.is_dropped());
    assert_eq!(
        state
            .connection_tables
            .values()
            .map(BTreeMap::len)
            .sum::<usize>(),
        1
    );
    record_production_effect_rows(
        &[
            crucible::model::EffectKind::NetworkFirewallDisposition,
            crucible::model::EffectKind::NetworkConnectionState,
        ],
        "stateful-firewall-connection-matrix",
        "timed-state-machine+bounded-flow-table+drop",
    );
}

#[test]
fn mtu_expansion_returns_real_child_frames_before_queue_service() {
    let mut action = action();
    action.phase = FaultPhase::Admit;
    action.effect = Arc::new(
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::Mtu {
                mtu_bytes: positive(42),
                oversize: crucible::model::NetworkOversizeDisposition::Fragment,
                fragmentation_protocol: Some(
                    crucible::model::NetworkFragmentationProtocol::EthernetIpv4,
                ),
                typed_error: None,
            }),
        )
        .unwrap_or_else(|error| panic!("test MTU effect: {error}")),
    );
    let mut payload = ethernet_ipv4_frame(&(0_u8..40).collect::<Vec<_>>(), 0);
    let opportunity = FaultOpportunity::new(
        action.target.clone(),
        crucible::model::FaultOperation::NetworkTraverse,
        FaultPhase::Admit,
        FaultCoordinate {
            virtual_ticks: 0,
            retired_instructions: None,
        },
        1,
        Some(crucible::model::FaultDirection::AToB),
        OpportunityPayload::NetworkFrame {
            producer: id("sender"),
            destination: id("receiver"),
            producer_sequence: 1,
            protocol_expansion_path: Vec::new(),
            generated_response_depth: 0,
            generated_response_cause: None,
            forwarding_mutation_path: Vec::new(),
            length_bytes: u64::try_from(payload.len())
                .unwrap_or_else(|error| panic!("test frame length: {error}")),
            payload_digest: ContentHash::from_bytes(&payload),
        },
    )
    .unwrap_or_else(|error| panic!("test MTU opportunity: {error}"));
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    let application = apply_network_frame_actions_with_limits(
        &mut payload,
        &mut effects,
        std::slice::from_ref(&action),
        &opportunity,
        ContentHash::from_bytes(b"mtu-expansion"),
        &crucible::model::WorldFaultTopology::default(),
        &mut state,
        &mut Vec::new(),
        None,
        None,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("MTU expansion: {error}"));
    assert_eq!(application.expanded_payloads.len(), 5);
    assert!(
        application
            .expanded_payloads
            .iter()
            .all(|fragment| fragment.len() <= 42)
    );
    assert!(state.queues.is_empty());
    record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkMtu],
        "mtu-fragmentation-before-service",
        "exact-child-frames+maximum-length+ordering",
    );
}

#[test]
fn detected_errors_execute_declared_retries_and_timed_link_reset() {
    let retry_count = |value| {
        crucible::model::BoundedCount::new(CountLimit::DuplicatesOrInstructionReplay, value)
            .unwrap_or_else(|error| panic!("test retry count: {error}"))
    };
    let retry = action_with_network_effect(NetworkEffectSpecification::DetectedFrameError {
        kind: crucible::model::DetectedFrameErrorKind::Crc,
        receiver_action: crucible::model::DetectedFrameErrorAction::Retry,
        retry_delay_nanos: Some(positive(10)),
        retry_limit: Some(retry_count(3)),
        retry_attempts: Some(retry_count(2)),
        retry_succeeds: Some(true),
        reset_nanos: None,
    });
    let opportunity = opportunity(1);
    let mut payload = vec![0_u8];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    apply_network_frame_action(
        &mut payload,
        &mut effects,
        &retry,
        &opportunity,
        ContentHash::from_bytes(b"retry-seed"),
        &crucible::model::WorldFaultTopology::default(),
        &mut state,
    )
    .unwrap_or_else(|error| panic!("retry effect: {error}"));
    assert_eq!(effects.additional_delay_ticks(), 160);
    assert!(!effects.is_dropped());

    let reset = action_with_network_effect(NetworkEffectSpecification::DetectedFrameError {
        kind: crucible::model::DetectedFrameErrorKind::FecUncorrectable,
        receiver_action: crucible::model::DetectedFrameErrorAction::LinkReset,
        retry_delay_nanos: None,
        retry_limit: None,
        retry_attempts: None,
        retry_succeeds: None,
        reset_nanos: Some(positive(50)),
    });
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    apply_network_frame_action(
        &mut payload,
        &mut effects,
        &reset,
        &opportunity,
        ContentHash::from_bytes(b"reset-seed"),
        &crucible::model::WorldFaultTopology::default(),
        &mut state,
    )
    .unwrap_or_else(|error| panic!("reset effect: {error}"));
    assert!(effects.is_dropped());
    assert_eq!(state.boundary.next_wakeup_ticks(0), Some(400));
    let mut during_reset = crucible::ResolvedNetworkFrameEffects::default();
    state
        .boundary
        .apply_frame(
            &reset.target,
            None,
            &crucible::model::WorldFaultTopology::default(),
            399,
            &mut during_reset,
        )
        .unwrap_or_else(|error| panic!("apply reset outage: {error}"));
    assert!(during_reset.is_dropped());
    let mut recovered = crucible::ResolvedNetworkFrameEffects::default();
    state
        .boundary
        .apply_frame(
            &reset.target,
            None,
            &crucible::model::WorldFaultTopology::default(),
            400,
            &mut recovered,
        )
        .unwrap_or_else(|error| panic!("apply recovered link: {error}"));
    assert!(!recovered.is_dropped());
    record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkDetectedFrameError],
        "detected-error-retry-reset",
        "retry-delay+success+timed-reset+recovery",
    );
}

#[test]
fn rf_channel_uses_geometry_tables_and_exact_sinr_profile() {
    let probability = crucible::model::ProbabilityMillionths::new(0)
        .unwrap_or_else(|error| panic!("zero probability should be valid: {error}"));
    let integer_table = |input_unit: &str, output| crucible::model::NetworkPolicyIntegerTable {
        input_unit: id(input_unit),
        output_unit: id("ratio-millionths"),
        interpolation: crucible::model::NetworkPolicyInterpolation::Step,
        outside: crucible::model::NetworkPolicyOutsideRange::Clamp,
        points: vec![crucible::model::NetworkPolicyIntegerPoint { input: 0, output }],
    };
    let profile = crucible::model::NetworkPolicyRfProfile {
        minimum_sinr: 0,
        rate_bps: positive(8_000),
        loss: probability,
        corruption: probability,
        corruption_action: crucible::model::NetworkPolicyRfCorruption::Corrected,
        maximum_retries: 0,
        retry_delay_nanos: 0,
    };
    let mut topology = crucible::model::WorldFaultTopology {
        network_policy_artifacts: vec![
            crucible::model::WorldNetworkPolicyArtifact {
                id: id("propagation"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::RfPropagation(
                    crucible::model::NetworkPolicyRfPropagation {
                        path_gain_ratio: integer_table("millimetres", 500_000),
                        antenna_gain_ratio: integer_table("millidegrees", 1_000_000),
                        spatial_cell_mm: positive(1),
                        fading_bucket_nanos: positive(1),
                    },
                ),
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: id("transfer"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::RfTransfer(
                    crucible::model::NetworkPolicyRfTransfer {
                        profiles: vec![profile],
                    },
                ),
            },
        ],
        ..Default::default()
    };
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Opportunity,
        EffectSpecification::Network(NetworkEffectSpecification::RfChannel {
            carrier_hz: positive(2_400_000_000),
            bandwidth_hz: positive(20_000_000),
            transmit_power_femtowatts: 100,
            receiver_noise_femtowatts: 10,
            propagation_fields: id("propagation"),
            sinr_transfer: id("transfer"),
        }),
    )
    .unwrap_or_else(|error| panic!("test RF effect should be valid: {error}"));
    let action = ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: id("rf-binding"),
        target: ResolvedFaultTarget::NetworkSegment {
            segment: id("network-test-segment"),
            direction: crucible::model::FaultDirection::AToB,
        },
        phase: FaultPhase::Resolve,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::ServiceProfile {
            service_profile: id("rf-inputs"),
            input_contracts: vec![
                crucible::model::ServiceProfileInput {
                    role: id("distance"),
                    shape: crucible::model::SignalShape {
                        value_type: crucible::model::SignalValueType::U64,
                        unit: crucible::model::SignalUnit::Millimetres,
                        scale_decimal_exponent: 0,
                    },
                },
                crucible::model::ServiceProfileInput {
                    role: id("orientation"),
                    shape: crucible::model::SignalShape {
                        value_type: crucible::model::SignalValueType::I64,
                        unit: crucible::model::SignalUnit::Millidegrees,
                        scale_decimal_exponent: 0,
                    },
                },
                crucible::model::ServiceProfileInput {
                    role: id("interference"),
                    shape: crucible::model::SignalShape {
                        value_type: crucible::model::SignalValueType::U64,
                        unit: crucible::model::SignalUnit::Femtowatts,
                        scale_decimal_exponent: 0,
                    },
                },
                crucible::model::ServiceProfileInput {
                    role: id("fading"),
                    shape: crucible::model::SignalShape {
                        value_type: crucible::model::SignalValueType::U64,
                        unit: crucible::model::SignalUnit::PartsPerMillion,
                        scale_decimal_exponent: 0,
                    },
                },
            ],
            inputs: vec![
                crucible::model::SignalValue::U64(10),
                crucible::model::SignalValue::I64(0),
                crucible::model::SignalValue::U64(5),
                crucible::model::SignalValue::U64(1_000_000),
            ],
        }),
        mapped_digest: ContentHash::from_bytes(b"rf-inputs"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_ticks: 0,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    };
    let opportunity = FaultOpportunity::new(
        action.target.clone(),
        crucible::model::FaultOperation::NetworkTraverse,
        FaultPhase::Resolve,
        action.coordinate,
        1,
        Some(crucible::model::FaultDirection::AToB),
        OpportunityPayload::NetworkFrame {
            producer: id("sender"),
            destination: id("receiver"),
            producer_sequence: 1,
            protocol_expansion_path: Vec::new(),
            generated_response_depth: 0,
            generated_response_cause: None,
            forwarding_mutation_path: Vec::new(),
            length_bytes: 1,
            payload_digest: ContentHash::from_bytes(b"frame"),
        },
    )
    .unwrap_or_else(|error| panic!("test RF opportunity should be valid: {error}"));
    let mut payload = vec![0_u8];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    apply_network_frame_action(
        &mut payload,
        &mut effects,
        &action,
        &opportunity,
        ContentHash::from_bytes(b"scenario"),
        &topology,
        &mut state,
    )
    .unwrap_or_else(|error| panic!("RF effect should execute: {error}"));
    assert_eq!(effects.serialization_rate_cap_bps(), Some(8_000));
    assert!(!effects.is_dropped());

    let always = crucible::model::ProbabilityMillionths::new(1_000_000)
        .unwrap_or_else(|error| panic!("certain probability: {error}"));
    let transfer = topology
        .network_policy_artifacts
        .iter_mut()
        .find(|artifact| artifact.id == id("transfer"))
        .unwrap_or_else(|| panic!("test transfer artifact"));
    let crucible::model::NetworkPolicyArtifactKind::RfTransfer(transfer) = &mut transfer.artifact
    else {
        panic!("test transfer type")
    };
    transfer.profiles[0].loss = always;
    transfer.profiles[0].maximum_retries = 2;
    transfer.profiles[0].retry_delay_nanos = 7;
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    apply_network_frame_action(
        &mut payload,
        &mut effects,
        &action,
        &opportunity,
        ContentHash::from_bytes(b"scenario"),
        &topology,
        &mut state,
    )
    .unwrap_or_else(|error| panic!("RF retry exhaustion: {error}"));
    assert_eq!(effects.additional_delay_ticks(), 112);
    assert!(effects.is_dropped());

    topology
        .network_policy_artifacts
        .push(crucible::model::WorldNetworkPolicyArtifact {
            id: id("rf-xor"),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::ByteTemplate {
                bytes: vec![0xff],
            },
        });
    topology
        .network_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));
    let transfer = topology
        .network_policy_artifacts
        .iter_mut()
        .find(|artifact| artifact.id == id("transfer"))
        .unwrap_or_else(|| panic!("test transfer artifact"));
    let crucible::model::NetworkPolicyArtifactKind::RfTransfer(transfer) = &mut transfer.artifact
    else {
        panic!("test transfer type")
    };
    transfer.profiles[0].loss = probability;
    transfer.profiles[0].corruption = always;
    transfer.profiles[0].corruption_action =
        crucible::model::NetworkPolicyRfCorruption::Undetected {
            transform: id("rf-xor"),
        };
    transfer.profiles[0].maximum_retries = 0;
    let mut payload = vec![0x0f, 0xf0];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    apply_network_frame_action(
        &mut payload,
        &mut effects,
        &action,
        &opportunity,
        ContentHash::from_bytes(b"scenario"),
        &topology,
        &mut state,
    )
    .unwrap_or_else(|error| panic!("RF undetected corruption: {error}"));
    assert_eq!(payload, vec![0xf0, 0x0f]);
    assert!(!effects.is_dropped());
    record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkRfChannel],
        "rf-channel-geometry-sinr",
        "rate+retry+loss+undetected-corruption",
    );
}
