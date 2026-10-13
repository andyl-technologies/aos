//! Native-free models for one full-world reservation and three unused peer slots.
//!
//! Activation here is proposal data only. These controls create no native node,
//! Child, Ready, accepted class or completion evidence.

// crucible-lint: allow panic-shortcut -- These native-free reservation controls panic on lost original slots or incorrect finite counts.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible::node_contract::OwnerIdentity;
use crucible_node_contract::{Id, Phase, Position, canonical};

fn proposal(count: usize) -> ActivationRecord {
    ActivationRecord {
        generation: U64::new(1),
        activation_id: Id::new("model-whole-world-activation").unwrap(),
        world_binding_hash: canonical::hash("cnp.world.v1", b"model-only-proposal").unwrap(),
        boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        owners: (0..count)
            .map(|member| OwnerIdentity {
                owner: Id::new(format!("model-owner-{member}")).unwrap(),
                incarnation: Id::new(format!("model-incarnation-{member}")).unwrap(),
                generation: U64::new(1),
            })
            .collect(),
    }
}

#[test]
fn three_peer_reservations_share_one_original_world_slot() {
    let supervisor = PacketWorldHostSupervisor::new().unwrap();
    let original = supervisor
        .reserve_original(&proposal(3), RuntimeLimits::default())
        .unwrap();

    assert_eq!(supervisor.observation().runtime_worlds, 1);
    assert_eq!(
        original.native.each_ref().map(|slot| slot.identity()),
        [U64::new(1), U64::new(2), U64::new(3)]
    );
    assert!(
        supervisor
            .observation()
            .peers
            .iter()
            .all(|peer| peer.native_expected && !peer.native_returned && !peer.kernel_reclaimed)
    );

    // These are actually unused prebirth reservations, not reclaimed native nodes.
    drop(original);
    assert_eq!(supervisor.observation().runtime_worlds, 0);
    assert!(
        supervisor
            .observation()
            .peers
            .iter()
            .all(|peer| !peer.native_expected && !peer.kernel_reclaimed)
    );
}

#[test]
fn complete_original_reservation_cannot_be_recycled() {
    let supervisor = PacketWorldHostSupervisor::new().unwrap();
    let activation = proposal(3);
    let original = supervisor
        .reserve_original(&activation, RuntimeLimits::default())
        .unwrap();

    assert!(
        supervisor
            .reserve_original(&activation, RuntimeLimits::default())
            .is_err()
    );
    assert_eq!(supervisor.observation().runtime_worlds, 1);
    drop(original);

    assert_eq!(supervisor.observation().runtime_worlds, 0);
    assert!(
        supervisor
            .reserve_original(&activation, RuntimeLimits::default())
            .is_err()
    );
    assert!(
        supervisor
            .observation()
            .peers
            .iter()
            .all(|peer| !peer.native_expected)
    );
}

#[test]
fn incomplete_world_proposal_reserves_no_peer_or_runtime_slot() {
    let supervisor = PacketWorldHostSupervisor::new().unwrap();

    assert!(
        supervisor
            .reserve_original(&proposal(2), RuntimeLimits::default())
            .is_err()
    );
    assert_eq!(supervisor.observation().runtime_worlds, 0);
    assert!(
        supervisor
            .observation()
            .peers
            .iter()
            .all(|peer| !peer.native_expected && !peer.native_returned && !peer.kernel_reclaimed)
    );

    // A declined proposal did not consume the actual original reservation.
    let complete = supervisor
        .reserve_original(&proposal(3), RuntimeLimits::default())
        .unwrap();
    assert_eq!(supervisor.observation().runtime_worlds, 1);
    drop(complete);
}
