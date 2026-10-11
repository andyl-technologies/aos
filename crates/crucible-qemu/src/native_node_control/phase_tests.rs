//! Actual datagram assembly regressions with model facts, without native qualification.

// crucible-lint: allow panic-shortcut -- These phase tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::{HashRef, Id, Phase, Position};
use crucible_protocol::node_control::{
    NativeChannel, NativeCpuParkFacts, NativeInitializationPreparation, NativePhaseMapping,
    NativePreparation, OwnerScope,
};

use super::*;

fn preparation() -> NativePhasePreparation {
    let id = |text| Id::new(text).unwrap();
    let hash = |domain: &str| HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: "01".repeat(32),
    };
    NativePhasePreparation {
        initialization: NativeInitializationPreparation {
            preparation: NativePreparation {
                scope: OwnerScope {
                    session: id("session"),
                    incarnation: id("incarnation"),
                    activation: id("activation"),
                    node: id("node"),
                    owner: id("owner"),
                    world_generation: U64::new(1),
                    owner_generation: U64::new(1),
                    world_binding: hash("cnp.world-binding.v1"),
                    owner_binding: hash("cnp.owner-binding.v1"),
                },
                boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
                maximum_commands: U64::new(4),
            },
            realize_operation: id("realize"),
            realize_request_digest: [1; 32],
            policy_digest: [2; 32],
            class_mask: 7,
            maximum_callbacks: 64,
        },
        policy_digest: [3; 32],
        mapping: NativePhaseMapping::InstructionReaction,
        maximum_microstep: U64::new(16),
    }
}

fn fixture() -> (
    NativeQemuControlTransport,
    NativeChannel,
    NativePhaseTimerObservation,
) {
    let preparation = preparation();
    let (mut transport, endpoint) =
        NativeQemuControlTransport::prepare_phase(preparation.clone()).unwrap();
    assert_eq!(endpoint.phase_projection(), Some(&preparation));
    assert_eq!(endpoint.edition(), NativeControlEdition::PhaseProjection);
    let provider = NativeChannel::from_prepared_socket_for_edition(
        endpoint.into_socket(),
        NativeControlEdition::PhaseProjection,
    )
    .unwrap();
    assert_eq!(
        provider.receive().unwrap(),
        Some(NativeFrame::PreparePhase(Box::new(preparation)))
    );
    let scope = transport.prepared_scope_hash;
    let park = NativeCpuParkFacts {
        prepared_scope_hash: scope,
        roster_sha256: [7; 32],
        coverage: 1,
        cpu_count: 1,
        current_ps: U64::new(0),
        retired_count: U64::new(0),
        next_service_deadline_ps: None,
        pending_service_credit_ps: U64::new(0),
    };
    provider.send(&NativeFrame::CpuPark(park)).unwrap();
    transport.poll_original().unwrap();
    assert!(
        transport
            .request_phase_timer_observation(U64::new(0))
            .unwrap()
    );
    assert!(matches!(
        provider.receive().unwrap(),
        Some(NativeFrame::QueryPhaseTimers(_))
    ));
    let observation = NativePhaseTimerObservation {
        prepared_scope_hash: scope,
        sequence: U64::new(0),
        command_digest: [0; 32],
        current_ps: U64::new(0),
        mutation_generation: U64::new(0),
        gate_generation: U64::new(1),
        lists: Vec::new(),
        timers: Vec::new(),
    };
    (transport, provider, observation)
}

fn chunk(observation: &NativePhaseTimerObservation) -> NativeFrame {
    let bytes = observation.encode().unwrap();
    NativeFrame::PhaseTimerChunk(Box::new(NativePhaseTimerChunk {
        prepared_scope_hash: observation.prepared_scope_hash,
        sequence: observation.sequence,
        object_digest: *blake3::hash(&bytes).as_bytes(),
        total_bytes: U64::new(bytes.len() as u64),
        offset: U64::new(0),
        bytes,
    }))
}

#[test]
fn complete_phase_companion_is_required_instead_of_generic_edition_selection() {
    let original = preparation();
    assert!(
        NativeQemuControlTransport::prepare_for_edition(
            original.initialization.preparation.clone(),
            NativeControlEdition::PhaseProjection,
        )
        .is_err()
    );
    let mut invalid = original;
    invalid.maximum_microstep = U64::new(0);
    assert!(NativeQemuControlTransport::prepare_phase(invalid).is_err());
}

#[test]
fn identical_cached_response_is_authenticated_before_recovery_is_reported() {
    let (mut transport, provider, observation) = fixture();
    let original = chunk(&observation);
    provider.send(&original).unwrap();
    assert_eq!(transport.poll_original().unwrap(), Some(original.clone()));
    assert_eq!(
        transport.phase_timer_observation(U64::new(0)),
        Some(&observation)
    );

    provider.send(&original).unwrap();
    assert_eq!(transport.poll_original().unwrap(), Some(original));
    assert_eq!(
        transport.phase_timer_observation(U64::new(0)),
        Some(&observation)
    );
}

#[test]
fn changed_response_is_refused_without_overwriting_authenticated_original() {
    let (mut transport, provider, observation) = fixture();
    provider.send(&chunk(&observation)).unwrap();
    transport.poll_original().unwrap();
    let mut changed = observation.clone();
    changed.mutation_generation = U64::new(9);
    provider.send(&chunk(&changed)).unwrap();

    assert!(transport.poll_original().is_err());
    assert_eq!(
        transport.phase_timer_observation(U64::new(0)),
        Some(&observation)
    );
}

#[test]
fn unrequested_sequence_and_foreign_scope_never_create_an_original() {
    let (mut transport, provider, observation) = fixture();
    let mut foreign = observation.clone();
    foreign.prepared_scope_hash[0] ^= 1;
    provider.send(&chunk(&foreign)).unwrap();
    assert!(transport.poll_original().is_err());

    let mut unrequested = observation;
    unrequested.sequence = U64::new(1);
    unrequested.command_digest = [4; 32];
    provider.send(&chunk(&unrequested)).unwrap();
    assert!(transport.poll_original().is_err());
    assert!(transport.phase_timer_observation(U64::new(0)).is_none());
    assert!(transport.phase_timer_observation(U64::new(1)).is_none());
}
