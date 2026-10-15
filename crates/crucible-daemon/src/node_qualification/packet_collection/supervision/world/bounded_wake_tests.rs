//! Exercises selected real custody queues with modeled proposal data, without Child.

use super::*;
use crucible::node_contract::OwnerIdentity;
use crucible_node_contract::{Id, Phase, Position, canonical};

fn proposal(count: usize) -> Result<ActivationRecord, QualificationError> {
    let mut owners = Vec::new();
    for member in 0..count {
        owners.push(OwnerIdentity {
            owner: Id::new(format!("modeled-complete-owner-{member}"))?,
            incarnation: Id::new(format!("modeled-complete-incarnation-{member}"))?,
            generation: U64::new(1),
        });
    }
    Ok(ActivationRecord {
        generation: U64::new(1),
        activation_id: Id::new("modeled-complete-notification")?,
        world_binding_hash: canonical::hash("cnp.world.v1", b"modeled-proposal-only")?,
        boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
        owners,
    })
}

#[test]
fn selected_four_owner_driver_retains_pending_slots_and_releases_only_unused_reservations()
-> Result<(), QualificationError> {
    let supervisor = PacketWorldHostSupervisor::new_complete_original()?;
    assert!(
        supervisor
            .reserve_original(&proposal(3)?, RuntimeLimits::default())
            .is_err()
    );
    let slots = supervisor.reserve_original(&proposal(4)?, RuntimeLimits::default())?;
    let before = supervisor.observation();
    assert!(matches!(
        supervisor.drive_complete_original_reclamation(1)?,
        Poll::Pending
    ));
    assert_eq!(supervisor.observation(), before);
    assert!(supervisor.drive_complete_original_reclamation(0).is_err());
    assert_eq!(supervisor.observation(), before);
    drop(slots);
    assert!(matches!(
        supervisor.drive_complete_original_reclamation(1)?,
        Poll::Ready(Ok(_))
    ));
    assert_eq!(supervisor.observation().runtime_worlds, 0);
    assert!(
        supervisor
            .observation()
            .peers
            .iter()
            .all(|peer| !peer.native_expected && !peer.kernel_reclaimed)
    );
    assert!(
        supervisor
            .reserve_original(&proposal(4)?, RuntimeLimits::default())
            .is_err()
    );
    Ok(())
}

#[test]
fn ordinary_three_owner_constructor_preserves_caller_context_and_rejects_selected_driver()
-> Result<(), QualificationError> {
    let supervisor = PacketWorldHostSupervisor::new()?;
    assert!(
        supervisor
            .reserve_original(&proposal(4)?, RuntimeLimits::default())
            .is_err()
    );
    let slots = supervisor.reserve_original(&proposal(3)?, RuntimeLimits::default())?;
    assert!(supervisor.drive_complete_original_reclamation(1).is_err());
    let before = supervisor.observation();
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        supervisor.poll_reclamation(&mut context),
        Poll::Pending
    ));
    assert_eq!(supervisor.observation(), before);
    drop(slots);
    assert!(matches!(
        supervisor.poll_reclamation(&mut context),
        Poll::Ready(Ok(_))
    ));
    Ok(())
}

#[test]
fn borrowed_supervisor_observer_preserves_all_original_native_obligations()
-> Result<(), QualificationError> {
    let supervisor = PacketWorldHostSupervisor::new_complete_original()?;
    let slots = supervisor.reserve_original(&proposal(4)?, RuntimeLimits::default())?;
    let before = supervisor.observation();
    let aliases = supervisor.mailboxes.each_ref().map(Rc::strong_count);
    let bytes = supervisor.retained_requested_storage_data(16 * 1024 * 1024)?;
    assert!(bytes > 0);
    assert_eq!(supervisor.observation(), before);
    assert_eq!(
        supervisor.mailboxes.each_ref().map(Rc::strong_count),
        aliases
    );
    assert!(
        supervisor
            .retained_requested_storage_data(bytes - 1)
            .is_err()
    );
    assert_eq!(supervisor.observation(), before);
    let PacketWorldOriginalReservations {
        native,
        journal,
        runtime,
    } = slots;
    drop(runtime);
    // Actual native slots are still outstanding. A data observation cannot
    // clear expected flags and make this selected driver falsely complete.
    assert!(matches!(
        supervisor.drive_complete_original_reclamation(1)?,
        Poll::Pending
    ));
    assert!(
        supervisor
            .observation()
            .peers
            .iter()
            .all(|peer| peer.native_expected)
    );
    drop(native);
    drop(journal);
    assert!(matches!(
        supervisor.drive_complete_original_reclamation(1)?,
        Poll::Ready(Ok(_))
    ));
    assert!(
        supervisor
            .observation()
            .peers
            .iter()
            .all(|peer| !peer.kernel_reclaimed)
    );
    Ok(())
}

#[test]
fn foreign_selected_supervisor_refuses_before_original_mailbox_observation_or_poll_mutation()
-> Result<(), QualificationError> {
    let mut supervisor = PacketWorldHostSupervisor::new_complete_original()?;
    let slots = supervisor.reserve_original(&proposal(4)?, RuntimeLimits::default())?;
    let before = supervisor.observation();
    supervisor
        .complete_origin
        .as_mut()
        .ok_or(QualificationError::Refused("missing origin"))?
        .0 = std::process::id().wrapping_add(1);
    assert!(
        supervisor
            .reserve_original(&proposal(4)?, RuntimeLimits::default())
            .is_err()
    );
    assert!(
        supervisor
            .retained_requested_storage_data(16 * 1024 * 1024)
            .is_err()
    );
    assert!(supervisor.drive_complete_original_reclamation(1).is_err());
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        supervisor.poll_reclamation(&mut context),
        Poll::Ready(Err(_))
    ));
    assert_eq!(supervisor.observation(), before);
    assert!(
        supervisor
            .mailboxes
            .iter()
            .all(|mailbox| !mailbox.polling.get())
    );
    // Restore only the private modeled creator field to release truly unused
    // prebirth slots; no production setter, fallback or renewed reservation.
    supervisor
        .complete_origin
        .as_mut()
        .ok_or(QualificationError::Refused("missing origin"))?
        .0 = std::process::id();
    drop(slots);
    assert!(matches!(
        supervisor.drive_complete_original_reclamation(1)?,
        Poll::Ready(Ok(_))
    ));
    Ok(())
}
