//! Native-free models for one full-world reservation and three unused peer slots.
//!
//! Activation here is proposal data only. These controls create no native node,
//! Child, Ready, accepted class or completion evidence.

// crucible-lint: allow panic-shortcut -- These native-free reservation controls panic on lost original slots or incorrect finite counts.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_engine::node_contract::OwnerIdentity;
use crucible_node_format::{Id, Phase, Position, canonical};

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

#[test]
fn world_native_trait_slot_observes_actual_reserved_mailbox_backing() {
    let supervisor = PacketWorldHostSupervisor::new().unwrap();
    let original = supervisor
        .reserve_original(&proposal(3), RuntimeLimits::default())
        .unwrap();
    let before = supervisor.observation();
    let mailbox = &supervisor.mailboxes[0];
    let aliases = Rc::strong_count(mailbox);
    // The actual mailbox retains the full process-custody slot inline. Derive
    // its finite Rc request from this compiled layout instead of a fixed ceiling.
    let counter_bytes = std::mem::size_of::<usize>().checked_mul(2).unwrap();
    let padding = std::mem::align_of::<Mailbox>()
        .max(std::mem::align_of::<usize>())
        .checked_sub(1)
        .and_then(|bytes| bytes.checked_mul(2))
        .unwrap();
    let mailbox_requested_bytes = std::mem::size_of::<Mailbox>()
        .checked_add(counter_bytes)
        .and_then(|bytes| bytes.checked_add(padding))
        .unwrap();
    let mut expected =
        crate::node_qualification::packet_collection::complete::retained::Counter::new(
            mailbox_requested_bytes,
        );
    expected.rc(mailbox).unwrap();

    // Dispatch through the actual erased WorldNativeSlot returned by reserve_original.
    // The generic trait default returns None and cannot satisfy this observation.
    let slot = &original.native[0];
    let bytes = slot
        .retained_requested_storage_data(mailbox_requested_bytes)
        .unwrap()
        .unwrap();
    assert_eq!(bytes, expected.bytes());
    assert_eq!(bytes, mailbox_requested_bytes);
    assert!(bytes >= std::mem::size_of::<Mailbox>() + 2 * std::mem::size_of::<usize>());
    assert!(slot.retained_requested_storage_data(bytes - 1).is_err());
    assert_eq!(supervisor.observation(), before);
    assert_eq!(Rc::strong_count(mailbox), aliases);

    mailbox.polling.set(true);
    assert_eq!(
        slot.retained_requested_storage_data(mailbox_requested_bytes)
            .unwrap(),
        None
    );
    mailbox.polling.set(false);
    assert_eq!(
        slot.retained_requested_storage_data(mailbox_requested_bytes)
            .unwrap(),
        Some(bytes)
    );
    assert_eq!(supervisor.observation(), before);
    assert_eq!(Rc::strong_count(mailbox), aliases);
}
