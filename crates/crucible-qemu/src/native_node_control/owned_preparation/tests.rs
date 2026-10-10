//! Real common-supervisor and child tests with graph eligibility explicitly modeled.
//!
//! These tests assemble the private preallocated guard without graph admission.
//! They test the actual reserved RuntimeCustodyQueue and exec-child retention,
//! not installed qualification, native callbacks, ACK authority or readiness.

// SPDX-License-Identifier: Apache-2.0

use std::{cell::RefCell, rc::Rc, task::Context, time::Duration};

use crucible::node_contract::{
    ActivationRecord, OwnerIdentity, RuntimeCustodyQueue, RuntimeCustodySupervisor, RuntimeLimits,
    WholeRuntimeCustody,
};
use crucible_node_contract::{HashRef, Id, Phase, Position, U64};
use crucible_protocol::node_control::{
    NativeChannel, NativeControlEdition, NativeFrame, NativeInitializationPreparation,
    NativeInitializationReceipt, NativeInitializationStatus, NativePhaseMapping,
    NativePhasePreparation, NativePreparation, OwnerScope,
};

use crate::native_node_control::{
    NativeAdministrationTransport,
    owned_operation::{Archive, ArchiveBudget, InitialEvidenceBudget},
};
use crate::supervision::HostSupervisionDeadline;

use super::{
    custody::{Custody, PreparedCapsule, Resources},
    guard::{Guard, QemuInitialReservation},
};

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn hash(domain: &str) -> HashRef {
    HashRef {
        algorithm: "blake3-256".into(),
        domain: domain.into(),
        digest: "01".repeat(32),
    }
}

fn scope() -> OwnerScope {
    OwnerScope {
        session: id("session/a"),
        incarnation: id("incarnation/a"),
        activation: id("activation/a"),
        node: id("node/a"),
        owner: id("owner/a"),
        world_generation: U64::new(1),
        owner_generation: U64::new(1),
        world_binding: hash("cnp.world-binding.v1"),
        owner_binding: hash("cnp.owner-binding.v1"),
    }
}

fn reservation(queue: &RuntimeCustodyQueue) -> QemuInitialReservation {
    let scope = scope();
    let target = ActivationRecord {
        generation: scope.world_generation,
        activation_id: scope.activation,
        world_binding_hash: scope.world_binding,
        owners: vec![OwnerIdentity {
            owner: scope.owner,
            incarnation: scope.incarnation,
            generation: scope.owner_generation,
        }],
        boundary: Position {
            time_ps: U64::new(0),
            microstep: U64::new(0),
            phase: Phase::BoundaryControl,
        },
    };
    let limits = RuntimeLimits {
        maximum_nodes: 1,
        maximum_owners: 1,
        maximum_operations: 1,
        maximum_retained_outputs: 1,
    };
    let slot = queue.reserve_world(&target, limits).unwrap();
    slot.validate_world(&target, limits).unwrap();
    let custody = Rc::new(RefCell::new(Custody {
        resources: Resources::Unspawned,
        target: target.clone(),
        publication: None,
        foreign_quarantine: false,
        cleanup_failure: None,
    }));
    let whole = WholeRuntimeCustody::from_prepared_resources(
        Box::new(PreparedCapsule(Rc::clone(&custody))),
        target.clone(),
        None,
        limits,
    );
    QemuInitialReservation(Guard {
        custody,
        whole: Some(whole),
        slot: Some(slot),
        target,
        limits,
        binding: None,
    })
}

#[test]
fn unused_initial_reservation_releases_only_empty_capacity() {
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let guard = reservation(&queue);
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(queue.retained_worlds(), 0);

    drop(guard);
    assert_eq!(queue.reserved_worlds(), 0);
    assert_eq!(queue.retained_worlds(), 0);
}

#[test]
fn foreign_quarantine_preserves_original_target_and_disposition() {
    use crucible::node_contract::{PreparedNativeResources, PublicationStatus};
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let guard = reservation(&queue);
    let original = guard.0.target.clone();
    let mut foreign = original.clone();
    foreign.generation = U64::new(2);
    let mut capsule = PreparedCapsule(Rc::clone(&guard.0.custody));

    capsule.quarantine_resources(&foreign, Some(PublicationStatus::Committed));
    let custody = guard.0.custody.borrow();
    assert_eq!(custody.target, original);
    assert_eq!(custody.publication, None);
    assert!(custody.foreign_quarantine);
    drop(custody);

    let mut context = Context::from_waker(std::task::Waker::noop());
    let std::task::Poll::Ready(Err(failure)) = capsule.poll_reclamation(&mut context) else {
        panic!("foreign quarantine cannot provide positive reclamation correlation");
    };
    assert_eq!(
        failure.effects,
        crucible::node_contract::EffectKnowledge::Unknown
    );
    assert_eq!(guard.0.custody.borrow().target, original);

    drop(guard);
    assert_eq!(queue.reserved_worlds(), 0);
}

#[test]
fn failed_initial_creation_moves_actual_child_to_original_world_slot() {
    if std::env::var_os("CRUCIBLE_INITIAL_COMMON_CUSTODY_CHILD").is_some() {
        std::thread::park_timeout(Duration::from_secs(30));
        return;
    }
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let guard = reservation(&queue);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("initial.evidence");
    let preparation = NativeInitializationPreparation {
        preparation: NativePreparation {
            scope: scope(),
            boundary: guard.0.target.boundary,
            maximum_commands: U64::new(1),
        },
        realize_operation: id("realize/a"),
        realize_request_digest: [11; 32],
        policy_digest: [12; 32],
        class_mask: 7,
        maximum_callbacks: 64,
    };
    let initialization = NativeInitializationReceipt {
        status: NativeInitializationStatus::Applied,
        applied_callbacks: 0,
        sequence: U64::new(1),
        hold_generation: U64::new(1),
        prepared_scope_hash: scope().identity_digest().unwrap(),
        initialization_commitment: preparation.identity_digest().unwrap(),
        original_cut_digest: [19; 32],
        realize_request_digest: [11; 32],
    };
    let (endpoint, launch) = NativeAdministrationTransport::prepare(
        NativePhasePreparation {
            initialization: preparation,
            policy_digest: [13; 32],
            mapping: NativePhaseMapping::InstructionReaction,
            maximum_microstep: U64::new(1024),
        },
        [14; 32],
        9,
    )
    .unwrap();
    let peer = NativeChannel::from_prepared_socket_for_edition(
        launch.into_socket(),
        NativeControlEdition::Administration,
    )
    .unwrap();
    assert!(matches!(
        peer.receive().unwrap(),
        Some(NativeFrame::PrepareAdministration(_))
    ));
    let archive = Archive::create(
        directory.path().join("command.archive"),
        scope().identity_digest().unwrap(),
        [9; 32],
        ArchiveBudget {
            lifetime_bytes: 65_672,
            lifetime_commands: 1,
            maximum_prefixes: 2,
        },
    )
    .unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_node_control::owned_preparation::tests::failed_initial_creation_moves_actual_child_to_original_world_slot", "--nocapture"])
        .env("CRUCIBLE_INITIAL_COMMON_CUSTODY_CHILD", "1").spawn().unwrap();
    let pid = child.id();

    let failure = match guard.create_session(
        child,
        endpoint,
        archive,
        path.clone(),
        initialization,
        InitialEvidenceBudget {
            lifetime_bytes: 65_536,
        },
    ) {
        Ok(_) => panic!("the old administration endpoint has no Prefix preparation"),
        Err(failure) => failure,
    };
    {
        let custody = failure.preparation.0.custody.borrow();
        let Resources::CreateFailure(original) = &custody.resources else {
            panic!("original creation failure must remain retained");
        };
        assert_eq!(original.process_id(), pid);
        assert!(!original.reaped());
    }
    assert!(!path.exists());
    assert_eq!(peer.receive().unwrap(), None);
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(queue.retained_worlds(), 0);

    drop(failure);
    assert_eq!(queue.retained_worlds(), 1);
    reclaim_same_child(&queue);
    assert_eq!(peer.receive().unwrap(), None);
    assert!(!path.exists());
}

fn reclaim_same_child(queue: &RuntimeCustodyQueue) {
    let deadline = HostSupervisionDeadline::start(Duration::from_secs(5));
    let mut context = Context::from_waker(std::task::Waker::noop());
    loop {
        assert!(
            deadline.has_time_remaining(),
            "same-child common containment deadline"
        );
        match queue.poll_reclamation(&mut context) {
            std::task::Poll::Ready(result) => {
                result.unwrap();
                break;
            }
            std::task::Poll::Pending => std::thread::sleep(Duration::from_millis(1)),
        }
    }
    assert_eq!(queue.reserved_worlds(), 0);
    assert_eq!(queue.retained_worlds(), 0);
}

#[test]
fn archive_collision_before_session_preserves_spawned_child_and_original_slot() {
    const CHILD: &str = "CRUCIBLE_INITIAL_BARE_CUSTODY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        std::thread::park_timeout(Duration::from_secs(30));
        return;
    }
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let reservation = reservation(&queue);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("command.archive");
    let original_bytes = b"existing original archive must survive failed setup";
    std::fs::write(&path, original_bytes).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_node_control::owned_preparation::tests::archive_collision_before_session_preserves_spawned_child_and_original_slot", "--nocapture"])
        .env(CHILD, "1").spawn().unwrap();
    let pid = child.id();

    let mut launching = reservation.attach_spawned_child(child);
    assert_eq!(launching.process_id(), Some(pid));
    let error = launching
        .create_archive(
            path.clone(),
            [1; 32],
            [2; 32],
            ArchiveBudget {
                lifetime_bytes: 65_672,
                lifetime_commands: 1,
                maximum_prefixes: 2,
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        crate::native_node_control::owned_operation::ArchiveError::Io(_)
    ));
    assert_eq!(launching.archive_path(), Some(path.clone()));
    {
        let custody = launching.0.custody.borrow();
        let Resources::Bare(original) = &custody.resources else {
            panic!("same archive offer must remain beneath Bare child custody");
        };
        let offer = original.archive_offer.as_ref().unwrap();
        assert_eq!(offer.scope, [1; 32]);
        assert_eq!(offer.preparation, [2; 32]);
        assert_eq!(
            offer.budget,
            ArchiveBudget {
                lifetime_bytes: 65_672,
                lifetime_commands: 1,
                maximum_prefixes: 2,
            }
        );
    }
    assert!(launching.setup_failure().is_some());
    assert_eq!(launching.process_id(), Some(pid));
    assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
    assert_eq!(queue.reserved_worlds(), 1);
    assert_eq!(queue.retained_worlds(), 0);

    assert!(matches!(
        launching.create_archive(
            directory.path().join("replacement.archive"),
            [1; 32],
            [2; 32],
            ArchiveBudget {
                lifetime_bytes: 65_672,
                lifetime_commands: 1,
                maximum_prefixes: 2,
            }
        ),
        Err(crate::native_node_control::owned_operation::ArchiveError::Failed)
    ));
    assert!(!directory.path().join("replacement.archive").exists());
    {
        let custody = launching.0.custody.borrow();
        let Resources::Bare(original) = &custody.resources else {
            panic!("refused replacement must preserve the original offer");
        };
        assert_eq!(&original.archive_offer.as_ref().unwrap().path, &path);
        assert_eq!(original.archive_offer.as_ref().unwrap().scope, [1; 32]);
        assert_eq!(
            original.archive_offer.as_ref().unwrap().preparation,
            [2; 32]
        );
    }
    drop(launching);
    assert_eq!(queue.retained_worlds(), 1);
    reclaim_same_child(&queue);
    assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
}

#[test]
fn endpoint_refusal_after_archive_creation_retains_child_and_archive() {
    const CHILD: &str = "CRUCIBLE_INITIAL_ENDPOINT_CUSTODY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        std::thread::park_timeout(Duration::from_secs(30));
        return;
    }
    let queue = RuntimeCustodyQueue::new(1).unwrap();
    let reservation = reservation(&queue);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("command.archive");
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_node_control::owned_preparation::tests::endpoint_refusal_after_archive_creation_retains_child_and_archive", "--nocapture"])
        .env(CHILD, "1").spawn().unwrap();
    let pid = child.id();

    let mut launching = reservation.attach_spawned_child(child);
    launching
        .create_archive(
            path.clone(),
            [1; 32],
            [2; 32],
            ArchiveBudget {
                lifetime_bytes: 65_672,
                lifetime_commands: 1,
                maximum_prefixes: 2,
            },
        )
        .unwrap();
    let original_bytes = std::fs::read(&path).unwrap();
    let failure = launching.refuse_setup("actual endpoint setup failure remains owned");
    {
        let custody = failure.preparation.0.custody.borrow();
        let Resources::Bare(original) = &custody.resources else {
            panic!("same Bare child must remain retained");
        };
        assert_eq!(original.child.process_id(), pid);
        assert!(original.archive.is_some());
        assert_eq!(&original.archive_offer.as_ref().unwrap().path, &path);
        assert!(original.setup_failure.is_some());
    }

    drop(failure);
    assert_eq!(queue.retained_worlds(), 1);
    reclaim_same_child(&queue);
    assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
}
