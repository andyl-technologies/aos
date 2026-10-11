//! Data-custody regressions for complete failed publication reconciliation.

// These fixtures exercise retained publisher data, not native readiness or
// installed capture qualification. Assertion panics report protocol misuse.
// crucible-lint: allow panic-shortcut -- These publication tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::node_scheduling::InputPayload;
use crucible_node_contract::{Phase, canonical};

struct CompleteOnlyPublisher {
    original: ActivationRecord,
    prepared: PreparedWorldPublication,
    complete_attempts: usize,
    complete_reconciliations: usize,
    scalar_queries: usize,
}

impl ActivationPublisher for CompleteOnlyPublisher {
    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        self.scalar_queries += 1;
        PublicationStatus::NotCommitted
    }

    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        self.scalar_queries += 1;
        PublicationStatus::NotCommitted
    }

    fn publish_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        assert_eq!(record, &self.original);
        assert_eq!(prepared, &self.prepared);
        self.complete_attempts += 1;
        PublicationStatus::Unknown
    }

    fn reconcile_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        assert_eq!(record, &self.original);
        assert_eq!(prepared, &self.prepared);
        self.complete_reconciliations += 1;
        PublicationStatus::Committed
    }
}

#[test]
fn failed_complete_publication_reconciles_original_bytes_without_scalar_fallback() {
    let original = activation();
    let prepared = preparation(b"original coordinator custody");
    let mut publisher = CompleteOnlyPublisher {
        original: original.clone(),
        prepared: prepared.clone(),
        complete_attempts: 0,
        complete_reconciliations: 0,
        scalar_queries: 0,
    };
    let mut knowledge = PublicationKnowledge::NotAttempted;
    let mut retained = None;
    {
        let mut recording = RecordingPublisher {
            publisher: &mut publisher,
            status: None,
            publication: &mut knowledge,
            prepared: &mut retained,
        };
        assert_eq!(
            recording.publish_complete(&original, &prepared),
            PublicationStatus::Unknown
        );
    }
    assert_eq!(knowledge, PublicationKnowledge::Unknown);
    let retained = retained.unwrap();
    assert_eq!(*retained, prepared);
    let mut failure = RestoreFailure::refused(incomplete("publication", "containment failed"));
    failure.activation = Some(Box::new(original.clone()));
    failure.publication = PublicationKnowledge::Unknown;
    failure.prepared_publication = Some(retained);

    assert_eq!(
        failure.reconcile_publication(&mut publisher).unwrap(),
        PublicationKnowledge::Committed
    );

    assert_eq!(failure.original_activation(), Some(&original));
    assert!(failure.reconcile_publication(&mut publisher).is_err());
    assert_eq!(publisher.complete_attempts, 1);
    assert_eq!(publisher.complete_reconciliations, 1);
    assert_eq!(publisher.scalar_queries, 0);
}

#[test]
fn uncertain_complete_retry_retains_first_original_coordinator_object() {
    let original = activation();
    let prepared = preparation(b"original complete coordinator object");
    let mut publisher = CompleteOnlyPublisher {
        original: original.clone(),
        prepared: prepared.clone(),
        complete_attempts: 0,
        complete_reconciliations: 0,
        scalar_queries: 0,
    };
    let mut knowledge = PublicationKnowledge::Unknown;
    let mut retained = None;
    {
        let mut recording = RecordingPublisher {
            publisher: &mut publisher,
            status: None,
            publication: &mut knowledge,
            prepared: &mut retained,
        };
        assert_eq!(
            recording.reconcile_complete(&original, &prepared),
            PublicationStatus::Committed
        );
        assert_eq!(recording.status, Some(PublicationStatus::Committed));
    }
    assert_eq!(knowledge, PublicationKnowledge::Committed);
    assert_eq!(retained.as_deref(), Some(&prepared));
    assert_eq!(publisher.complete_attempts, 0);
    assert_eq!(publisher.complete_reconciliations, 1);
    assert_eq!(publisher.scalar_queries, 0);
}

#[test]
fn publisher_unwind_retains_original_complete_bytes_and_uncertainty() {
    struct PanickingPublisher;

    impl ActivationPublisher for PanickingPublisher {
        fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
            panic!("unexpected scalar publication")
        }

        fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
            panic!("unexpected scalar reconciliation")
        }

        fn publish_complete(
            &mut self,
            _: &ActivationRecord,
            _: &PreparedWorldPublication,
        ) -> PublicationStatus {
            panic!("trusted publisher failed after its durable write")
        }
    }

    let original = activation();
    let prepared = preparation(b"original bytes retained across publisher unwind");
    let mut publisher = PanickingPublisher;
    let mut knowledge = PublicationKnowledge::NotAttempted;
    let mut retained = None;

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut recording = RecordingPublisher {
            publisher: &mut publisher,
            status: None,
            publication: &mut knowledge,
            prepared: &mut retained,
        };
        recording.publish_complete(&original, &prepared);
    }));

    assert!(outcome.is_err());
    assert_eq!(knowledge, PublicationKnowledge::Unknown);
    assert_eq!(retained.as_deref(), Some(&prepared));
}

fn activation() -> ActivationRecord {
    ActivationRecord {
        generation: U64::new(3),
        activation_id: Id::new("original/complete-publication").unwrap(),
        world_binding_hash: canonical::hash("cnp.world-binding.v1", b"world").unwrap(),
        owners: vec![OwnerIdentity {
            owner: Id::new("owner/a").unwrap(),
            incarnation: Id::new("fresh/a").unwrap(),
            generation: U64::new(3),
        }],
        boundary: Position {
            time_ps: U64::new(12),
            microstep: U64::new(2),
            phase: Phase::BoundaryControl,
        },
    }
}

fn preparation(bytes: &[u8]) -> PreparedWorldPublication {
    PreparedWorldPublication {
        nodes: Rc::from([]),
        owners: Vec::new(),
        coordinator: InputPayload {
            reference: canonical::content_ref(bytes, "application/octet-stream").unwrap(),
            bytes: bytes.to_vec(),
        },
    }
}
