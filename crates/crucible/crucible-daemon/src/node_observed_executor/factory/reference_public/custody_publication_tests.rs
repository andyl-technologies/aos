//! Checks original private journal forwarding with real filesystem publication.
//!
//! These controls reserve no Child and confer no native qualification. Calling
//! the forwarding helper with a scalar storage effect isolates journal ordering;
//! the production public wrapper continues to reject scalar activation.

// crucible-lint: allow panic-shortcut -- Journal and filesystem regressions fail the original control attempt.
#![allow(clippy::unwrap_used)]

use std::{cell::RefCell, rc::Rc, sync::Arc};

use crucible_engine::{node_adapters::cnp::CnpProcessCustodySlot, node_contract::OwnerIdentity};
use crucible_node_format::{Id, Phase, Position, U64, canonical};
use crucible_store::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, MutableRefBackend, RefName,
};

use super::super::custody::PublicPeerScope;
use super::*;
use crate::node_observed_executor::StoredWorldActivationPublisher;

fn fixture() -> (
    PublicReferenceCustodyQueue,
    ActivationRecord,
    Box<dyn CnpProcessCustodySlot>,
) {
    let owner = OwnerIdentity {
        owner: Id::new("owner/reference").unwrap(),
        incarnation: Id::new("incarnation/reference").unwrap(),
        generation: U64::new(1),
    };
    let record = ActivationRecord {
        generation: U64::new(1),
        activation_id: Id::new("activation/reference").unwrap(),
        world_binding_hash: canonical::content_ref(b"world", "text/plain").unwrap().hash,
        owners: vec![owner.clone()],
        boundary: Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl),
    };
    let queue = PublicReferenceCustodyQueue::new(1).unwrap();
    let slot = reserve(&queue, &record, owner);
    (queue, record, slot)
}

fn reserve(
    queue: &PublicReferenceCustodyQueue,
    record: &ActivationRecord,
    owner: OwnerIdentity,
) -> Box<dyn CnpProcessCustodySlot> {
    let implementation = canonical::content_ref(b"source", "text/plain").unwrap();
    queue
        .reserve(PublicPeerScope {
            activation: record.clone(),
            owner,
            implementation: implementation.clone(),
            source_roots: vec![implementation],
            source_custody: None,
            publication: None,
            connection_incident: Rc::new(RefCell::new(None)),
            private_launch: b"private original launch".to_vec(),
            original_hello: b"private original Hello".to_vec(),
            ordinary_negotiation: None,
            collecting_negotiation: None,
        })
        .unwrap()
}

#[test]
fn original_publication_marks_uncertainty_before_real_storage_and_keeps_committed_history() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "original-public-journal",
        directory.path().join("blobs"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let root = RefName::new("node-world-activations/reference").unwrap();
    let stored = StoredWorldActivationPublisher::new(blobs, refs.clone(), root.clone()).unwrap();
    let (queue, record, slot) = fixture();
    let original_identity = slot.identity();
    let mut publisher = PublicReferenceCustodyPublisher::new(stored, queue.clone());

    assert_eq!(queue.publication(&record).unwrap(), None);
    let status = publisher.record_effect(&record, |stored| {
        assert_eq!(
            queue.publication(&record).unwrap(),
            Some(PublicationStatus::Unknown)
        );
        stored.publish(&record)
    });

    assert_eq!(status, PublicationStatus::Committed);
    assert!(refs.read_ref(&root).unwrap().is_some());
    assert_eq!(
        queue.publication(&record).unwrap(),
        Some(PublicationStatus::Committed)
    );
    std::fs::remove_file(
        directory
            .path()
            .join("refs/refs/node-world-activations/reference"),
    )
    .unwrap();
    assert_eq!(
        publisher.record_effect(&record, |stored| stored.reconcile(&record)),
        PublicationStatus::Unknown
    );
    assert_eq!(
        queue.publication(&record).unwrap(),
        Some(PublicationStatus::Committed)
    );
    assert_eq!(slot.identity(), original_identity);
    assert_eq!(queue.outstanding(), 1);
}

#[test]
fn unwinding_publication_keeps_same_original_uncertainty_until_positive_disposition() {
    let (queue, record, slot) = fixture();
    let original_identity = slot.identity();
    let mut publisher = PublicReferenceCustodyPublisher::new((), queue.clone());

    assert_eq!(
        publisher.record_effect(&record, |_| panic!("original storage callback unwind")),
        PublicationStatus::Unknown
    );
    assert_eq!(
        queue.publication(&record).unwrap(),
        Some(PublicationStatus::Unknown)
    );
    assert_eq!(
        publisher.record_effect(&record, |_| PublicationStatus::NotCommitted),
        PublicationStatus::NotCommitted
    );
    assert_eq!(
        queue.publication(&record).unwrap(),
        Some(PublicationStatus::NotCommitted)
    );
    assert_eq!(slot.identity(), original_identity);
    assert_eq!(queue.outstanding(), 1);
}

#[test]
fn foreign_original_record_refuses_before_effect_and_preserves_private_reservation() {
    let (queue, record, slot) = fixture();
    let original_identity = slot.identity();
    let mut publisher = PublicReferenceCustodyPublisher::new((), queue.clone());
    let mut foreign = record.clone();
    foreign.activation_id = Id::new("activation/foreign").unwrap();
    let mut calls = 0;

    assert_eq!(
        publisher.record_effect(&foreign, |_| {
            calls += 1;
            PublicationStatus::Committed
        }),
        PublicationStatus::Unknown
    );
    assert_eq!(calls, 0);
    assert_eq!(queue.publication(&record).unwrap(), None);
    assert_eq!(slot.identity(), original_identity);
    assert_eq!(queue.outstanding(), 1);
}

fn refuse_foreign_queue_scope(duplicate_owner: bool) {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "public-foreign-scope",
        directory.path().join("blobs"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let root = RefName::new("node-world-activations/foreign-scope").unwrap();
    let stored = StoredWorldActivationPublisher::new(blobs, refs.clone(), root.clone()).unwrap();
    let (_, mut original, unused_slot) = fixture();
    drop(unused_slot);
    let first_owner = original.owners[0].clone();
    let second_owner = OwnerIdentity {
        owner: Id::new("owner/foreign").unwrap(),
        incarnation: Id::new("incarnation/foreign").unwrap(),
        generation: U64::new(1),
    };
    original.owners.push(if duplicate_owner {
        first_owner.clone()
    } else {
        second_owner.clone()
    });
    let mut foreign = original.clone();
    foreign.activation_id = Id::new("activation/foreign-entry").unwrap();
    foreign.owners = vec![second_owner.clone()];
    let queue = PublicReferenceCustodyQueue::new(2).unwrap();
    let first = reserve(&queue, &original, first_owner);
    let second = reserve(&queue, &foreign, second_owner);
    let first_identity = first.identity();
    let second_identity = second.identity();
    let mut publisher = PublicReferenceCustodyPublisher::new(stored, queue.clone());
    let mut storage_calls = 0;

    let status = publisher.record_effect(&original, |stored| {
        storage_calls += 1;
        stored.publish(&original)
    });

    assert_eq!(status, PublicationStatus::Unknown);
    assert_eq!(storage_calls, 0);
    assert_eq!(refs.read_ref(&root).unwrap(), None);
    assert_eq!(queue.outstanding(), 2);
    assert_eq!(first.identity(), first_identity);
    assert_eq!(second.identity(), second_identity);
}

#[test]
fn duplicate_owner_roster_cannot_publish_using_an_unrelated_original_slot() {
    refuse_foreign_queue_scope(true);
}

#[test]
fn foreign_entry_cannot_complete_the_original_publication_owner_roster() {
    refuse_foreign_queue_scope(false);
}
