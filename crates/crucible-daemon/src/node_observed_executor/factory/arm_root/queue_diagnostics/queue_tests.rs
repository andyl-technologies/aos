//! Checks exact retained-entry diagnostic lookup without a native process.

// crucible-lint: allow panic-shortcut -- Model-only queue tests assert retained-entry identity and never enroll native custody.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::queue_diagnostics::InstalledRootCleanupFailure;
use super::*;
use crucible_node_contract::{Id, Phase, Position, U64, canonical};

fn fixture() -> (RootCustodyQueue, ActivationRecord) {
    let owner = OwnerIdentity {
        owner: Id::new("root-owner").unwrap(),
        incarnation: Id::new("root/source").unwrap(),
        generation: U64::new(1),
    };
    let target = ActivationRecord {
        generation: U64::new(1),
        activation_id: Id::new("world/source").unwrap(),
        world_binding_hash: canonical::json_hash(
            "cnp.world-binding.v1",
            &serde_json::json!({"diagnostic_model": 1}),
        )
        .unwrap(),
        owners: vec![owner.clone()],
        boundary: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
    };
    let entry = Entry {
        scope: RootScope {
            activation: target.clone(),
            owner,
            publication: PublicationKnowledge::NotAttempted,
            backing: RootBacking::Fresh(Vec::new()),
        },
        custody: None,
        in_flight: false,
        reclaimed: false,
        failed: false,
        first_failure: None,
    };
    // This inert registry bypasses reserve deliberately: it contains no native
    // handle, installed artifacts or cleanup thread and grants no authority.
    let queue = RootCustodyQueue(Arc::new(Shared {
        registry: Mutex::new(Registry {
            slots: vec![Some(entry)],
            accepting: false,
        }),
        changed: Condvar::new(),
    }));
    (queue, target)
}

#[test]
fn repeated_status_reads_do_not_advance_or_settle_missing_custody() {
    let (queue, target) = fixture();
    let expected = queue.cleanup_status(&target).unwrap();

    assert!(!expected.custody_present);
    assert!(!expected.in_flight);
    assert!(!expected.reclaimed);
    assert!(!expected.failed);
    assert_eq!(queue.cleanup_status(&target).unwrap(), expected);
    assert!(!queue.original_group_reclaimed(&target).unwrap());
    assert_eq!(queue.0.lock().slots.len(), 1);
}

#[test]
fn foreign_complete_target_cannot_read_the_original_entry() {
    let (queue, target) = fixture();
    let original = queue.cleanup_status(&target).unwrap();
    let mut foreign = target.clone();
    foreign.owners[0].incarnation = Id::new("root/foreign").unwrap();

    assert!(queue.cleanup_status(&foreign).is_err());
    assert_eq!(queue.cleanup_status(&target).unwrap(), original);
}

#[test]
fn failed_in_flight_entry_exposes_original_failure_without_reclamation() {
    let (queue, target) = fixture();
    {
        let mut registry = queue.0.lock();
        let entry = registry.slots[0].as_mut().unwrap();
        entry.in_flight = true;
        entry.failed = true;
        CleanupFailureRecord::retain_first(
            &mut entry.first_failure,
            CleanupFailureRecord::refused(&"original cleanup failed"),
        );
    }

    let status = queue.cleanup_status(&target).unwrap();

    assert!(!status.custody_present);
    assert!(status.in_flight);
    assert!(status.failed);
    assert!(!status.reclaimed);
    assert_eq!(
        status.first_failure,
        Some(InstalledRootCleanupFailure::Refused {
            reason: "original cleanup failed".into(),
        })
    );
    assert!(!queue.original_group_reclaimed(&target).unwrap());
}

#[test]
fn unused_entry_predicate_preserves_original_state_without_reclamation() {
    let (queue, target) = fixture();
    let before = queue.cleanup_status(&target).unwrap();

    let registry = queue.0.lock();
    let entry = original_unused_entry(&registry, &target, &target.owners[0]).unwrap();
    assert!(!entry.reclaimed);
    assert!(entry.custody.is_none());
    drop(registry);

    assert_eq!(queue.cleanup_status(&target).unwrap(), before);
    assert!(!queue.original_group_reclaimed(&target).unwrap());
}

#[test]
fn unused_entry_predicate_rejects_foreign_target_owner_and_absent_reservation() {
    let (queue, target) = fixture();
    let mut foreign_target = target.clone();
    foreign_target.activation_id = Id::new("world/foreign").unwrap();
    let mut foreign_owner = target.owners[0].clone();
    foreign_owner.incarnation = Id::new("root/foreign").unwrap();
    let mut registry = queue.0.lock();

    assert!(original_unused_entry(&registry, &foreign_target, &target.owners[0]).is_err());
    assert!(original_unused_entry(&registry, &target, &foreign_owner).is_err());
    registry.slots[0] = None;
    assert!(original_unused_entry(&registry, &target, &target.owners[0]).is_err());
}

#[test]
fn unused_entry_predicate_rejects_progress_failure_and_publication_knowledge() {
    // The fixture has no native handle or signed backing. These are predicates
    // on inert administrative state, not a positive unused cold lease seal.
    for state in 0..5 {
        let (queue, target) = fixture();
        {
            let mut registry = queue.0.lock();
            let entry = registry.slots[0].as_mut().unwrap();
            match state {
                0 => entry.in_flight = true,
                1 => entry.reclaimed = true,
                2 => entry.failed = true,
                3 => entry.scope.publication = PublicationKnowledge::Unknown,
                _ => entry.scope.publication = PublicationKnowledge::Committed,
            }
        }
        let before = queue.cleanup_status(&target).unwrap();

        let registry = queue.0.lock();
        assert!(original_unused_entry(&registry, &target, &target.owners[0]).is_err());
        drop(registry);

        assert_eq!(queue.cleanup_status(&target).unwrap(), before);
    }
}
