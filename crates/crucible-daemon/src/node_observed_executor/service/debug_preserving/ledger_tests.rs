//! Exercises exact immutable placement after original data sealing uncertainty.
//!
//! The runtime here is inert schema data. These controls grant no native owner,
//! Stop barrier or restoration permission, and do not assert native fault credit.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Data controls deliberately panic on assertion failure and injected placement unwind.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible::node_contract::{RuntimeSnapshot, SavedRuntimeActivation};
use crucible_cas::content_store::{
    BackendCapabilities, ByteRange, DirectoryBlobBackend, DirectoryRefBackend, PutReceipt,
    StoreError,
};
use crucible_node_contract::{Id, Phase, Position};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy)]
enum PlacementFailure {
    Before,
    After,
    Nondurable,
    UnwindBefore,
    UnwindAfter,
}

struct OriginalPlacement {
    inner: Arc<dyn ImmutableBlobBackend>,
    failure: PlacementFailure,
    armed: AtomicBool,
    writes: Mutex<Vec<(ContentId, Vec<u8>)>>,
}

impl ImmutableBlobBackend for OriginalPlacement {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        self.writes
            .lock()
            .unwrap()
            .push((id, source.read_all(32 << 20)?));
        if !self.armed.swap(false, Ordering::AcqRel) {
            return self.inner.put_if_absent(id, source);
        }

        let placed = if matches!(
            self.failure,
            PlacementFailure::After | PlacementFailure::Nondurable | PlacementFailure::UnwindAfter
        ) {
            Some(self.inner.put_if_absent(id, source)?)
        } else {
            None
        };
        if matches!(
            self.failure,
            PlacementFailure::UnwindBefore | PlacementFailure::UnwindAfter
        ) {
            panic!("original sealed suffix placement unwound");
        }
        if matches!(self.failure, PlacementFailure::Nondurable) {
            let mut receipt = placed.ok_or(StoreError::Incompatible)?;
            for placement in &mut receipt.placements {
                placement.durable = false;
            }
            return Ok(receipt);
        }
        Err(StoreError::Incompatible)
    }
}

fn inert_runtime() -> RuntimeSnapshot {
    let boundary = Position::new(1.into(), 0.into(), Phase::BoundaryControl);
    RuntimeSnapshot {
        schema_version: 1,
        source_activation: SavedRuntimeActivation {
            generation: 1.into(),
            activation_id: Id::new("inert/activation").unwrap(),
            world_binding_hash: canonical::content_ref(b"inert world", "application/octet-stream")
                .unwrap()
                .hash,
            owners: Vec::new(),
            boundary,
        },
        capture_cut: boundary,
        capture_ordinal: 1.into(),
        owners: Vec::new(),
        operations: Vec::new(),
        inputs: Vec::new(),
        terminal: None,
        condition_stop: None,
    }
}

#[test]
fn placement_uncertainty_reconciles_exact_sealed_bytes_and_identity() {
    for failure in [
        PlacementFailure::Before,
        PlacementFailure::After,
        PlacementFailure::Nondurable,
        PlacementFailure::UnwindBefore,
        PlacementFailure::UnwindAfter,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let backend = Arc::new(OriginalPlacement {
            inner: Arc::new(DirectoryBlobBackend::new(
                "sealed",
                directory.path().join("blobs"),
            )),
            failure,
            armed: AtomicBool::new(true),
            writes: Mutex::new(Vec::new()),
        });
        let ledger = Ledger::new(
            backend.clone(),
            Arc::new(DirectoryRefBackend::new(directory.path().join("refs"))),
        )
        .unwrap();
        let original = ledger
            .seal_outputs(
                "edededededededededededededededed",
                &[],
                &inert_runtime(),
                32 << 20,
            )
            .unwrap();
        let fixed_bytes = original.bytes.clone();
        let fixed_identity = original.identity;

        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ledger.place_outputs(&original)
        }));
        assert!(!matches!(refused, Ok(Ok(_))));
        assert_eq!(original.bytes, fixed_bytes);
        assert_eq!(original.identity, fixed_identity);

        let placed = ledger.place_outputs(&original).unwrap();
        assert_eq!(placed, original.reference);
        placed
            .verify(&ledger.bytes(fixed_identity, 32 << 20).unwrap())
            .unwrap();
        let attempts = backend.writes.lock().unwrap();
        assert_eq!(attempts.len(), 2);
        assert!(
            attempts
                .iter()
                .all(|(id, bytes)| *id == fixed_identity && bytes == &fixed_bytes)
        );
    }
}

#[test]
fn authored_output_credit_binds_the_complete_envelope_before_sealing() {
    let directory = tempfile::tempdir().unwrap();
    let ledger = Ledger::new(
        Arc::new(DirectoryBlobBackend::new(
            "credit",
            directory.path().join("blobs"),
        )),
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs"))),
    )
    .unwrap();
    let execution = "edededededededededededededededed";
    let runtime = inert_runtime();
    let original = ledger
        .seal_outputs(execution, &[], &runtime, 32 << 20)
        .unwrap();
    let exact = original.bytes.len();

    // These inert helper credits test the exact production serializer boundary;
    // they do not create an operator request or any native custody.
    let at_limit = ledger
        .seal_outputs(execution, &[], &runtime, exact)
        .unwrap();
    assert_eq!(at_limit.bytes, original.bytes);
    assert!(
        ledger
            .seal_outputs(execution, &[], &runtime, exact - 1)
            .is_err()
    );
    assert!(ledger.refs.read_ref(&original.name).unwrap().is_none());

    let payload_bytes = vec![0x61; 64 << 10];
    let publication = crucible::node_scheduling::NativePublication {
        publication_id: Id::new("inert/publication").unwrap(),
        endpoint: crucible_node_contract::Endpoint {
            node_id: Id::new("inert").unwrap(),
            port_id: Id::new("output").unwrap(),
            lane_id: Id::new("data").unwrap(),
        },
        native_sequence: 0.into(),
        publication: Position::new(1.into(), 0.into(), Phase::Publication),
        evaluation: None,
        causal_parents: Vec::new(),
        payload: canonical::content_ref(&payload_bytes, "application/octet-stream").unwrap(),
        payload_bytes,
    };
    let publications = vec![publication.clone(); 32];
    // Each numeric payload stays within the unchanged 65,536-element grammar.
    // A valid 8 MiB operator credit refuses the conservative complete-publication
    // expansion, while its separately declared 32 MiB counterpart can seal it.
    assert!(
        ledger
            .seal_outputs(execution, &publications, &runtime, 8 << 20)
            .is_err()
    );
    let accepted = ledger
        .seal_outputs(execution, &publications, &runtime, 32 << 20)
        .unwrap();
    assert!(accepted.bytes.len() < 32 << 20);
    assert!(ledger.refs.read_ref(&accepted.name).unwrap().is_none());

    let above_server = vec![publication; 128];
    assert!(
        ledger
            .seal_outputs(execution, &above_server, &runtime, 64 << 20)
            .is_err()
    );
}
