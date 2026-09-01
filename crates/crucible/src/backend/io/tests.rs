//! Backend network output and fault-continuation tests.

use super::*;

fn target() -> ResolvedFaultTarget {
    ResolvedFaultTarget::NetworkForwarder {
        forwarder: FaultObjectId::parse("forwarder-a")
            .unwrap_or_else(|error| panic!("test target should be valid: {error}")),
    }
}

#[test]
fn network_fault_cursor_retains_release_after_resuming() {
    let mut cursor = BackendNetworkFaultCursor::default();
    cursor.defer_until(41, ContentHash::from_bytes(b"queue"));
    assert_eq!(cursor.not_before_nanos(), 41);
    assert_eq!(cursor.release_nanos(), 41);
    cursor
        .complete(target(), FaultPhase::Resolve)
        .unwrap_or_else(|error| panic!("cursor should advance: {error}"));
    assert_eq!(cursor.not_before_nanos(), 0);
    assert_eq!(cursor.release_nanos(), 41);
    assert!(cursor.is_complete(&target(), FaultPhase::Resolve));
}

#[test]
fn network_fault_cursor_completion_is_idempotent_across_path_reevaluation() {
    let mut cursor = BackendNetworkFaultCursor::default();
    cursor
        .complete(target(), FaultPhase::Resolve)
        .unwrap_or_else(|error| panic!("cursor should complete: {error}"));
    cursor.lock_route_path(
        FaultObjectId::parse("old-path")
            .unwrap_or_else(|error| panic!("test path should be valid: {error}")),
    );
    cursor.reevaluate_route_path();
    cursor
        .complete(target(), FaultPhase::Resolve)
        .unwrap_or_else(|error| panic!("duplicate completion should succeed: {error}"));
    assert_eq!(cursor.completed_phases().len(), 1);
    assert!(cursor.route_path_version().is_none());
}

#[test]
fn protocol_expansion_path_orders_nested_child_frames() {
    let mut first = BackendNetworkFaultContinuation::default();
    first.append_protocol_expansion_ordinal(0);
    first.append_protocol_expansion_ordinal(7);
    let mut second = BackendNetworkFaultContinuation::default();
    second.append_protocol_expansion_ordinal(1);
    assert!(first < second);
    assert_eq!(first.protocol_expansion_path(), &[0, 7]);
}

#[test]
fn generated_response_resets_forward_state_and_enforces_depth() {
    let cause = ContentHash::from_bytes(b"reject");
    let mut parent = BackendNetworkFaultContinuation::default();
    parent.append_protocol_expansion_ordinal(3);
    parent
        .cursor_mut()
        .complete(target(), FaultPhase::Resolve)
        .unwrap_or_else(|error| panic!("parent cursor: {error}"));
    let mut child = parent
        .generated_response(cause)
        .unwrap_or_else(|| panic!("first response must fit"));
    assert_eq!(child.generated_response_depth(), 1);
    assert_eq!(child.generated_response_cause(), Some(cause));
    assert!(child.protocol_expansion_path().is_empty());
    assert!(child.cursor().completed_phases().is_empty());
    for ordinal in 1..crate::model::HARD_NETWORK_RESPONSE_DEPTH {
        child = child
            .generated_response(ContentHash::from_bytes(&[ordinal]))
            .unwrap_or_else(|| panic!("bounded response {ordinal} must fit"));
    }
    assert!(child.generated_response(cause).is_none());
}

#[test]
fn forwarding_mutation_preserves_wire_state_and_records_forced_recipient() {
    let cause = ContentHash::from_bytes(b"wrong-port");
    let destination = NodeId {
        name: String::from("receiver-b"),
    };
    let mut parent = BackendNetworkFaultContinuation::default();
    parent.append_protocol_expansion_ordinal(2);
    parent.cursor_mut().lock_route_path(
        FaultObjectId::parse("old-path").unwrap_or_else(|error| panic!("test path: {error}")),
    );
    let child = parent
        .forwarding_mutation(cause, destination.clone())
        .unwrap_or_else(|| panic!("first forwarding mutation must fit"));
    assert_eq!(child.protocol_expansion_path(), &[2]);
    assert_eq!(child.forwarding_mutation_path(), &[cause]);
    assert_eq!(child.forced_route_destination(), Some(&destination));
    assert!(child.cursor().route_path_version().is_none());
}

#[test]
fn pending_network_output_codec_round_trips_complete_fault_continuation() {
    let mut continuation = BackendNetworkFaultContinuation::default();
    continuation.preserve_availability(
        FaultObjectId::parse("binding-a").unwrap_or_else(|error| panic!("test binding: {error}")),
        target(),
        FaultPhase::Admit,
        7,
    );
    let mut effects = crucible_device::ResolvedNetworkFrameEffects::default();
    effects
        .add_latency_delta(-11)
        .unwrap_or_else(|error| panic!("latency delta: {error}"));
    effects
        .add_delay(29)
        .unwrap_or_else(|error| panic!("delay: {error}"));
    effects
        .constrain_rate(1_000_000)
        .unwrap_or_else(|error| panic!("rate: {error}"));
    effects
        .mark_contact_service_accounted([3; 32])
        .unwrap_or_else(|error| panic!("contact: {error}"));
    effects.mark_drop();
    effects
        .add_duplicate_gap(31)
        .unwrap_or_else(|error| panic!("duplicate: {error}"));
    continuation.set_resolved_frame_effects(effects);
    continuation.append_protocol_expansion_ordinal(2);
    continuation.append_protocol_expansion_ordinal(9);
    assert!(continuation.begin_generated_response(ContentHash::from_bytes(b"response")));
    continuation = continuation
        .forwarding_mutation(
            ContentHash::from_bytes(b"reroute"),
            NodeId {
                name: String::from("receiver-b"),
            },
        )
        .unwrap_or_else(|| panic!("forwarding mutation should fit"));
    continuation
        .cursor_mut()
        .complete(target(), FaultPhase::Resolve)
        .unwrap_or_else(|error| panic!("complete cursor: {error}"));
    continuation.cursor_mut().defer_repeated_effect_until(
        73,
        ContentHash::from_bytes(b"queue"),
        EffectKind::NetworkQueuePolicy,
        Some(4),
    );
    continuation.cursor_mut().lock_route_path(
        FaultObjectId::parse("path-v1").unwrap_or_else(|error| panic!("test path: {error}")),
    );
    let output = BackendNetworkOutput {
        source: NodeId {
            name: String::from("sender-a"),
        },
        destination: NodeId {
            name: String::from("receiver-b"),
        },
        emit_icount: Icount { retired: 41 },
        sequence: 43,
        payload: vec![1, 2, 3, 4],
        route: Some(BackendNetworkRoute {
            link: LinkId::from_name("link-a-b"),
            direction: crate::device::NetworkLinkDirection::EndpointAToEndpointB,
            destination: NodeId {
                name: String::from("receiver-b"),
            },
        }),
        fault_continuation: continuation,
    };

    let bytes = output
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("pending frame encodes: {error}"));
    let restored = BackendNetworkOutput::from_canonical_bytes(&bytes)
        .unwrap_or_else(|error| panic!("pending frame decodes: {error}"));
    assert_eq!(restored, output);
    assert_eq!(
        restored
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("restored frame encodes: {error}")),
        bytes
    );
    let below_representation = u64::try_from(bytes.len().saturating_sub(1))
        .unwrap_or_else(|_| panic!("test frame length should fit u64"));
    assert!(matches!(
        output.canonical_bytes_with_limit(below_representation),
        Err(BackendNetworkOutputCodecError::ResourceLimit {
            field: "encoded frame",
            configured,
            hard: 16_777_216,
            ..
        }) if configured == below_representation
    ));
    assert!(matches!(
        BackendNetworkOutput::from_canonical_bytes_with_limit(&bytes, below_representation),
        Err(BackendNetworkOutputCodecError::ResourceLimit {
            field: "encoded frame",
            configured,
            hard: 16_777_216,
            ..
        }) if configured == below_representation
    ));

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        BackendNetworkOutput::from_canonical_bytes(&trailing),
        Err(BackendNetworkOutputCodecError::Noncanonical)
    );

    let mut oversized_identity = output;
    oversized_identity.source.name = "n".repeat(4_097);
    assert_eq!(
        oversized_identity.canonical_bytes(),
        Err(BackendNetworkOutputCodecError::ResourceLimit {
            field: "source",
            current: 0,
            requested: 4_097,
            configured: 4_096,
            hard: 4_096,
        })
    );
}
