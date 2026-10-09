//! Model-only activation regressions for original preparation and publication custody.

use crucible_node_contract::{Extensions, Phase, PreparedOwner, canonical};

use super::*;
use crate::node_contract::ReadyAttestation;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn payload(bytes: &[u8]) -> InputPayload {
    InputPayload {
        reference: canonical::content_ref(bytes, "application/json").unwrap(),
        bytes: bytes.to_vec(),
    }
}

fn fixture(public: bool) -> (ActivationRecord, Vec<ValidatedNodePreparation>) {
    let owner = OwnerIdentity {
        owner: id("owner/a"),
        incarnation: id("incarnation/a"),
        generation: 1.into(),
    };
    let boundary = Position::new(0.into(), 0.into(), Phase::BoundaryControl);
    let ready = payload(b"{\"model_ready\":true}").reference;
    let binding = HashRef {
        algorithm: "blake3-256".into(),
        domain: "cnp.node-binding.v1".into(),
        digest: "1".repeat(64),
    };
    let record = ActivationRecord {
        generation: 1.into(),
        activation_id: id("activation/a"),
        world_binding_hash: HashRef {
            domain: "cnp.world-binding.v1".into(),
            ..binding.clone()
        },
        owners: vec![owner.clone()],
        boundary,
    };
    let prepared = PreparedOwner {
        owner_id: owner.owner.clone(),
        incarnation_id: owner.incarnation.clone(),
        owner_generation: owner.generation,
        prepared_token: id("original/prepared/a"),
        binding_hashes: vec![binding],
        ready_receipt: ready.clone(),
        extensions: Extensions::new(),
    };
    let nodes = vec![ValidatedNodePreparation {
        node: id("a"),
        readiness: ReadyAttestation {
            owners: vec![owner],
            boundary,
            state_inventory: payload(b"{\"model_inventory\":true}").reference,
            ready_receipt: ready,
        },
        prepared_owners: public.then_some(vec![prepared]),
    }];
    (record, nodes)
}

#[derive(Default)]
struct Publisher {
    preparations: usize,
    scalar_calls: usize,
    committed: bool,
    original: Option<PreparedWorldPublication>,
}

impl ActivationPublisher for Publisher {
    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        self.scalar_calls += 1;
        PublicationStatus::Committed
    }

    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        panic!("complete uncertainty must not query scalar publication")
    }

    fn prepare_coordinator(
        &mut self,
        _: &ActivationRecord,
        _: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, RuntimeError> {
        self.preparations += 1;
        Ok(payload(b"{\"model_coordinator\":1}"))
    }

    fn publish_complete(
        &mut self,
        _: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        self.original = Some(prepared.clone());
        PublicationStatus::Unknown
    }

    fn reconcile_complete(
        &mut self,
        _: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        assert_eq!(Some(prepared), self.original.as_ref());
        if self.committed {
            PublicationStatus::Committed
        } else {
            PublicationStatus::Unknown
        }
    }
}

#[test]
fn complete_uncertainty_keeps_original_bytes_and_never_reprepares_or_uses_scalar_publication() {
    let (record, nodes) = fixture(true);
    let mut barrier = ActivationBarrier::new(record).unwrap();
    barrier.ready(nodes.clone()).unwrap();
    let authority = Rc::new(());
    let mut publisher = Publisher::default();

    assert!(matches!(
        barrier.publish(&authority, &mut publisher),
        Err(RuntimeError::PublicationFailed)
    ));
    assert!(!barrier.can_arm());
    assert!(matches!(
        barrier.reconcile(&authority, &mut publisher),
        Err(RuntimeError::PublicationFailed)
    ));
    publisher.committed = true;
    let activation = barrier.reconcile(&authority, &mut publisher).unwrap();

    assert_eq!(activation.node_preparations(), nodes);
    assert_eq!(
        activation.coordinator_snapshot(),
        Some(&payload(b"{\"model_coordinator\":1}"))
    );
    assert_eq!(activation.prepared_owners(), nodes[0].prepared_owners());
    assert_eq!(publisher.preparations, 1);
    assert_eq!(publisher.scalar_calls, 0);
    let clone = activation.clone();
    assert!(Rc::ptr_eq(
        activation.preparation.as_ref().unwrap(),
        clone.preparation.as_ref().unwrap()
    ));
}

#[test]
fn partial_public_roster_refuses_before_any_publication_effect() {
    let (mut record, mut nodes) = fixture(true);
    let second = OwnerIdentity {
        owner: id("owner/b"),
        incarnation: id("incarnation/b"),
        generation: 1.into(),
    };
    record.owners.push(second.clone());
    let mut unsupported = nodes[0].clone();
    unsupported.node = id("b");
    unsupported.readiness.owners = vec![second];
    unsupported.prepared_owners = None;
    nodes.push(unsupported);
    let mut barrier = ActivationBarrier::new(record).unwrap();
    barrier.ready(nodes).unwrap();
    let mut publisher = Publisher::default();

    assert!(matches!(
        barrier.publish(&Rc::new(()), &mut publisher),
        Err(RuntimeError::InvalidReceipt)
    ));
    assert_eq!(publisher.preparations, 0);
    assert_eq!(publisher.scalar_calls, 0);
}

#[test]
fn unsupported_complete_reconciliation_retains_uncertainty() {
    struct PublishOnly(Publisher);
    impl ActivationPublisher for PublishOnly {
        fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
            panic!("scalar fallback")
        }
        fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
            panic!("scalar fallback")
        }
        fn prepare_coordinator(
            &mut self,
            record: &ActivationRecord,
            nodes: &[ValidatedNodePreparation],
        ) -> Result<InputPayload, RuntimeError> {
            self.0.prepare_coordinator(record, nodes)
        }
        fn publish_complete(
            &mut self,
            record: &ActivationRecord,
            prepared: &PreparedWorldPublication,
        ) -> PublicationStatus {
            self.0.publish_complete(record, prepared)
        }
    }
    let (record, nodes) = fixture(true);
    let mut barrier = ActivationBarrier::new(record).unwrap();
    barrier.ready(nodes).unwrap();
    let mut publisher = PublishOnly(Publisher::default());
    let authority = Rc::new(());

    assert!(barrier.publish(&authority, &mut publisher).is_err());
    assert!(barrier.reconcile(&authority, &mut publisher).is_err());
    assert_eq!(
        barrier.publication_status_or_not_attempted(),
        Some(PublicationStatus::Unknown)
    );
}

#[test]
fn failed_later_preparation_keeps_successful_original_readiness() {
    let (record, nodes) = fixture(false);
    let mut barrier = ActivationBarrier::new(record).unwrap();
    barrier.abandon(nodes.clone());

    assert_eq!(barrier.retained_nodes().as_ref(), nodes);
    assert!(!barrier.can_arm());
    assert!(
        barrier
            .publish(&Rc::new(()), &mut Publisher::default())
            .is_err()
    );
}

#[test]
fn public_mapping_rejects_foreign_binding_generation_and_readiness() {
    let (_, original) = fixture(true);
    let owner = original[0].prepared_owners().unwrap()[0].clone();
    let bindings =
        std::collections::BTreeMap::from([(owner.owner_id.clone(), owner.binding_hashes.clone())]);
    super::super::activation_preparation::validate_owner_mapping(&original[0], &bindings).unwrap();
    for mutation in 0..4 {
        let mut changed = original[0].clone();
        let prepared = &mut changed.prepared_owners.as_mut().unwrap()[0];
        match mutation {
            0 => prepared.owner_generation = 2.into(),
            1 => prepared.ready_receipt = payload(b"foreign").reference,
            2 => prepared.binding_hashes[0].digest = "2".repeat(64),
            _ => prepared.incarnation_id = id("foreign/incarnation"),
        }
        assert!(
            super::super::activation_preparation::validate_owner_mapping(&changed, &bindings)
                .is_err()
        );
    }
}
