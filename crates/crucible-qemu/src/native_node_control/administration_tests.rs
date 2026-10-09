//! Original socket correlation tests with a mechanical peer, without native qualification.

// crucible-lint: allow panic-shortcut -- These administration tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::{HashRef, Id, Phase, Position, U64};
use crucible_protocol::node_control::{
    NativeInitializationPreparation, NativePhaseMapping, NativePreparation, OwnerScope,
};

fn phase() -> NativePhasePreparation {
    let identity = |value| Id::new(value).unwrap();
    let hash = |domain: &str| HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: "01".repeat(32),
    };
    NativePhasePreparation {
        initialization: NativeInitializationPreparation {
            preparation: NativePreparation {
                scope: OwnerScope {
                    session: identity("test/session"),
                    incarnation: identity("test/incarnation"),
                    activation: identity("test/activation"),
                    node: identity("test/node"),
                    owner: identity("test/owner"),
                    world_generation: U64::new(1),
                    owner_generation: U64::new(1),
                    world_binding: hash("cnp.world-binding.v1"),
                    owner_binding: hash("cnp.owner-binding.v1"),
                },
                boundary: Position {
                    time_ps: U64::new(0),
                    microstep: U64::new(0),
                    phase: Phase::BoundaryControl,
                },
                maximum_commands: U64::new(4),
            },
            realize_operation: identity("test/realize"),
            realize_request_digest: [2; 32],
            policy_digest: [3; 32],
            class_mask: 7,
            maximum_callbacks: 64,
        },
        policy_digest: [4; 32],
        mapping: NativePhaseMapping::InstructionReaction,
        maximum_microstep: U64::new(1024),
    }
}

fn channels() -> (NativeAdministrationTransport, NativeChannel) {
    let (transport, endpoint) =
        NativeAdministrationTransport::prepare(phase(), [5; 32], 9).unwrap();
    let provider = NativeChannel::from_prepared_socket_for_edition(
        endpoint.into_socket(),
        NativeControlEdition::Administration,
    )
    .unwrap();
    assert_eq!(
        provider.receive().unwrap(),
        Some(NativeFrame::PrepareAdministration(Box::new(
            transport.preparation().clone()
        )))
    );
    (transport, provider)
}

fn facts(transport: &NativeAdministrationTransport) -> NativeAdministrativeFacts {
    let preparation = transport.preparation();
    NativeAdministrativeFacts {
        registration_id: U64::new(1),
        thread_id: U64::new(41),
        socket_device: U64::new(preparation.socket_device),
        socket_inode: U64::new(preparation.socket_inode),
        process_id: U64::new(39),
        descriptor_slot: preparation.descriptor_slot,
        prepared_scope_hash: preparation
            .phase
            .initialization
            .preparation
            .scope
            .identity_digest()
            .unwrap(),
        role_commitment: preparation.identity_digest().unwrap(),
        realize_request_digest: preparation.phase.initialization.realize_request_digest,
        policy_digest: preparation.policy_digest,
    }
}

fn request(transport: &mut NativeAdministrationTransport, provider: &NativeChannel) {
    assert!(transport.request_original().unwrap());
    assert!(matches!(
        provider.receive().unwrap(),
        Some(NativeFrame::QueryAdministration { .. })
    ));
}

#[test]
fn original_process_and_endpoint_are_pinned_before_historical_retries() {
    let (mut transport, provider) = channels();
    assert!(transport.preparation().socket_inode > 0);
    assert!(transport.request_original().is_err());
    assert!(transport.bind_process(0).is_err());
    transport.bind_process(39).unwrap();
    assert!(transport.bind_process(40).is_err());
    transport.bind_process(39).unwrap();

    let original = facts(&transport);
    for _ in 0..2 {
        request(&mut transport, &provider);
        provider
            .send(&NativeFrame::AdministrationFacts(Box::new(
                original.clone(),
            )))
            .unwrap();
        assert_eq!(transport.receive_original().unwrap(), Some(&original));
    }
    assert!(transport.bind_process(39).is_err());
}

#[test]
fn foreign_native_process_is_retained_and_cannot_be_rehabilitated() {
    let (mut transport, provider) = channels();
    transport.bind_process(40).unwrap();
    request(&mut transport, &provider);
    let foreign = facts(&transport);
    provider
        .send(&NativeFrame::AdministrationFacts(Box::new(foreign.clone())))
        .unwrap();

    assert!(transport.receive_original().is_err());
    assert_eq!(transport.original, Some(foreign));
    assert!(transport.request_original().is_err());
    assert!(transport.receive_original().is_err());
}

#[test]
fn changed_retry_preserves_first_original_and_permanently_refuses_reenrollment() {
    let (mut transport, provider) = channels();
    transport.bind_process(39).unwrap();
    let original = facts(&transport);
    request(&mut transport, &provider);
    provider
        .send(&NativeFrame::AdministrationFacts(Box::new(
            original.clone(),
        )))
        .unwrap();
    transport.receive_original().unwrap();

    request(&mut transport, &provider);
    let mut changed = original.clone();
    changed.thread_id = U64::new(42);
    provider
        .send(&NativeFrame::AdministrationFacts(Box::new(changed)))
        .unwrap();
    assert!(transport.receive_original().is_err());
    assert_eq!(transport.original, Some(original));
    assert!(transport.request_original().is_err());
}

#[test]
fn malformed_response_cannot_be_followed_by_a_new_successful_enrollment() {
    let (mut transport, endpoint) =
        NativeAdministrationTransport::prepare(phase(), [5; 32], 9).unwrap();
    let raw_provider = endpoint.into_socket();
    let provider = NativeChannel::from_prepared_socket_for_edition(
        raw_provider.try_clone().unwrap(),
        NativeControlEdition::Administration,
    )
    .unwrap();
    provider.receive().unwrap();
    transport.bind_process(39).unwrap();
    request(&mut transport, &provider);

    raw_provider.send(b"invalid-frame").unwrap();
    assert!(transport.receive_original().is_err());
    assert!(transport.original.is_none());
    assert!(transport.request_original().is_err());
    assert!(transport.receive_original().is_err());
}
