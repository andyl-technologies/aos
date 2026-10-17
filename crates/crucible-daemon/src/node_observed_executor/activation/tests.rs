//! Actual public native readiness and faulted durable complete-world publication.
//!
//! Every opaque publication is obtained through the actual common runtime.
//! Storage fault injection tests publication semantics; it confers no additional
//! native timing, snapshot or device fidelity qualification.

// crucible-lint: allow clippy-disallowed-method -- Operational deadlines in these activation tests bound native supervision and never enter modeled state.
// crucible-lint: allow panic-shortcut -- These activation tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod faults;
mod native;

use std::{path::PathBuf, sync::Arc};

use crucible::node_contract::{PreparedWorldPublication, RuntimeError, ValidatedNodePreparation};
use crucible::node_scheduling::InputPayload;
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};

use super::*;

struct CapturingPublisher {
    stored: StoredWorldActivationPublisher,
    original: Option<PreparedWorldPublication>,
}

impl ActivationPublisher for CapturingPublisher {
    fn prepare_coordinator(
        &mut self,
        record: &ActivationRecord,
        nodes: &[ValidatedNodePreparation],
    ) -> Result<InputPayload, RuntimeError> {
        self.stored.prepare_coordinator(record, nodes)
    }

    fn publish_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        assert!(
            self.original.is_none(),
            "original complete publication is prepared once"
        );
        self.original = Some(prepared.clone());
        self.stored.publish_complete(record, prepared)
    }

    fn reconcile_complete(
        &mut self,
        record: &ActivationRecord,
        prepared: &PreparedWorldPublication,
    ) -> PublicationStatus {
        assert_eq!(self.original.as_ref(), Some(prepared));
        self.stored.reconcile_complete(record, prepared)
    }

    fn publish(&mut self, _: &ActivationRecord) -> PublicationStatus {
        panic!("actual all-public world cannot use scalar publication")
    }

    fn reconcile(&mut self, _: &ActivationRecord) -> PublicationStatus {
        panic!("actual all-public world cannot use scalar reconciliation")
    }
}

struct Store {
    directory: tempfile::TempDir,
    blobs: Arc<DirectoryBlobBackend>,
    refs: Arc<DirectoryRefBackend>,
    activation: RefName,
    coordinator: RefName,
}

impl Store {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        Self {
            blobs: Arc::new(DirectoryBlobBackend::new(
                "actual-public-activation",
                directory.path().join("blobs"),
            )),
            refs: Arc::new(DirectoryRefBackend::new(directory.path().join("refs"))),
            activation: RefName::new("node-world-activations/original").unwrap(),
            coordinator: RefName::new("node-world-coordinators/original").unwrap(),
            directory,
        }
    }

    fn publisher(
        &self,
        world: &mut native::NativeWorld,
        refs: Arc<dyn MutableRefBackend>,
    ) -> CapturingPublisher {
        let nodes = world.runtime().prepared_node_records().unwrap().to_vec();
        CapturingPublisher {
            stored: StoredWorldActivationPublisher::new(
                self.blobs.clone(),
                refs,
                self.activation.clone(),
            )
            .unwrap()
            .with_prepared_coordinator(world.record.clone(), nodes, world.coordinator.clone())
            .unwrap(),
            original: None,
        }
    }

    fn fresh(&self) -> StoredWorldActivationPublisher {
        StoredWorldActivationPublisher::new(
            self.blobs.clone(),
            self.refs.clone(),
            self.activation.clone(),
        )
        .unwrap()
    }

    fn raw(&self, reference: &RefName) -> Vec<u8> {
        let id = self.refs.read_ref(reference).unwrap().unwrap();
        self.blobs
            .read(id, None)
            .unwrap()
            .read_all(16 * 1024 * 1024)
            .unwrap()
    }

    fn object_path(&self, id: ContentId) -> PathBuf {
        let encoded = id.encode();
        let digest = encoded.rsplit('.').next().unwrap();
        self.blobs
            .root()
            .join("objects")
            .join(&digest[..2])
            .join(encoded)
    }
}

#[test]
#[ignore = "requires source-built CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE and CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"]
fn actual_public_world_roots_exact_complete_coordinator_before_activation_and_reconciles_fresh_publisher()
 {
    let mut world = native::NativeWorld::prepare();
    let store = Store::new();
    let mut publisher = store.publisher(&mut world, store.refs.clone());

    let activation = world.runtime().activate(&mut publisher).unwrap();

    assert_eq!(activation.prepared_owners().unwrap().len(), 2);
    assert_eq!(activation.coordinator_snapshot(), Some(&world.coordinator));
    let original = publisher.original.as_ref().unwrap();
    assert_eq!(original.coordinator_snapshot(), &world.coordinator);
    assert_eq!(store.raw(&store.coordinator), world.coordinator.bytes);
    let coordinator: serde_json::Value = serde_json::from_slice(&world.coordinator.bytes).unwrap();
    assert_eq!(coordinator["schema"], "crucible/coordinator-initial/1");
    assert_eq!(coordinator["nodes"].as_array().unwrap().len(), 2);
    assert_eq!(coordinator["connections"].as_array().unwrap().len(), 1);
    assert_eq!(coordinator["scheduler"]["state"], "not_initialized");
    for inventory in [
        "operations",
        "inputs",
        "publications",
        "deliveries",
        "reservations",
    ] {
        assert!(
            coordinator["scheduler"][inventory]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    let raw = store.raw(&store.activation);
    let document: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(document["version"], 2);
    assert_eq!(document["node_preparations"].as_array().unwrap().len(), 2);
    assert_eq!(document["prepared_owners"].as_array().unwrap().len(), 2);
    assert_eq!(
        document["coordinator_state_ref"],
        serde_json::to_value(&world.coordinator.reference).unwrap()
    );
    assert_eq!(
        store.fresh().reconcile_complete(&world.record, original),
        PublicationStatus::Committed
    );

    for reference in [&store.activation, &store.coordinator] {
        let original_id = store.refs.read_ref(reference).unwrap().unwrap();
        let replacement = ContentId::for_bytes(ObjectKind::Trace, 2, b"replacement");
        assert!(
            matches!(store.refs.compare_exchange(reference, None, replacement).unwrap(),
            RefCasOutcome::Conflict { current: Some(actual), .. } if actual == original_id)
        );
        assert_eq!(store.refs.read_ref(reference).unwrap(), Some(original_id));
    }
    assert!(
        store
            .directory
            .path()
            .join("refs/refs/node-world-activations/original")
            .is_file()
    );
    assert!(
        store
            .directory
            .path()
            .join("refs/refs/node-world-coordinators/original")
            .is_file()
    );
    assert!(
        world.reclaim(),
        "both actual provider groups must be positively reclaimed"
    );
}

#[test]
#[ignore = "requires source-built CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE and CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"]
fn actual_committed_activation_refuses_missing_and_corrupt_original_coordinator_bytes() {
    let mut world = native::NativeWorld::prepare();
    let store = Store::new();
    let mut publisher = store.publisher(&mut world, store.refs.clone());
    world.runtime().activate(&mut publisher).unwrap();
    let original = publisher.original.as_ref().unwrap();
    let coordinator_id = store.refs.read_ref(&store.coordinator).unwrap().unwrap();
    let path = store.object_path(coordinator_id);

    std::fs::remove_file(&path).unwrap();

    assert_eq!(
        store.fresh().reconcile_complete(&world.record, original),
        PublicationStatus::Unknown
    );
    // Restore the unchanged original through the actual durable backend, then
    // separately simulate corruption below the immutable-store contract.
    assert!(
        store
            .blobs
            .put_if_absent(
                coordinator_id,
                &BlobHandle::from_bytes(world.coordinator.bytes.clone())
            )
            .unwrap()
            .is_durable()
    );
    assert_eq!(
        store.fresh().reconcile_complete(&world.record, original),
        PublicationStatus::Committed
    );
    let wrong = ContentId::for_bytes(ObjectKind::Trace, 2, b"foreign coordinator");
    assert!(
        store
            .blobs
            .put_if_absent(
                wrong,
                &BlobHandle::from_bytes(b"foreign coordinator".to_vec())
            )
            .unwrap()
            .is_durable()
    );
    assert!(matches!(
        store.refs.compare_exchange(&store.coordinator, Some(coordinator_id), wrong).unwrap(),
        RefCasOutcome::Advanced { next } if next == wrong
    ));
    assert_eq!(
        store.fresh().reconcile_complete(&world.record, original),
        PublicationStatus::Unknown
    );
    assert!(matches!(
        store.refs.compare_exchange(&store.coordinator, Some(wrong), coordinator_id).unwrap(),
        RefCasOutcome::Advanced { next } if next == coordinator_id
    ));
    std::fs::write(&path, b"corrupted coordinator").unwrap();
    assert_eq!(
        store.fresh().reconcile_complete(&world.record, original),
        PublicationStatus::Unknown
    );
    assert!(
        world.reclaim(),
        "corrupt storage cannot lose original native retirement custody"
    );
}

#[test]
#[ignore = "requires source-built CRUCIBLE_REFERENCE_PROVIDER_EXECUTABLE and CRUCIBLE_REFERENCE_DEVICE_EXECUTABLE"]
fn actual_directory_partial_publication_and_lost_commit_acknowledgement_preserve_original_gate() {
    for point in [
        faults::FailurePoint::BeforeActivationRoot,
        faults::FailurePoint::AfterActivationRoot,
    ] {
        let mut world = native::NativeWorld::prepare();
        let store = Store::new();
        let faulted = Arc::new(faults::FaultRefs::new(store.refs.clone(), point));
        let mut publisher = store.publisher(&mut world, faulted);

        assert!(matches!(
            world.runtime().activate(&mut publisher),
            Err(RuntimeError::PublicationFailed)
        ));

        let original = publisher.original.as_ref().unwrap();
        assert_eq!(store.raw(&store.coordinator), world.coordinator.bytes);
        assert_eq!(original.coordinator_snapshot(), &world.coordinator);
        assert!(
            world.runtime().arm_all().is_err(),
            "uncertainty cannot re-arm original native owners"
        );
        let mut fresh = store.fresh();
        match point {
            faults::FailurePoint::BeforeActivationRoot => {
                assert_eq!(store.refs.read_ref(&store.activation).unwrap(), None);
                assert_eq!(
                    fresh.reconcile_complete(&world.record, original),
                    PublicationStatus::NotCommitted
                );
                assert!(world.runtime().reconcile_activation(&mut fresh).is_err());
            }
            faults::FailurePoint::AfterActivationRoot => {
                assert!(store.refs.read_ref(&store.activation).unwrap().is_some());
                assert_eq!(
                    fresh.reconcile_complete(&world.record, original),
                    PublicationStatus::Committed
                );
                let activation = world.runtime().reconcile_activation(&mut fresh).unwrap();
                assert_eq!(activation.coordinator_snapshot(), Some(&world.coordinator));
                assert_eq!(activation.node_preparations(), original.nodes());
                assert_eq!(
                    activation.prepared_owners(),
                    Some(original.prepared_owners())
                );
            }
        }
        assert!(
            world.reclaim(),
            "original inactive public processes must be reclaimed"
        );
    }
}
