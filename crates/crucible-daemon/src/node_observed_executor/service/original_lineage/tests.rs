//! Checks durable reciprocal nonce exclusion before original source inspection.
//!
//! Real directory CAS and the actual Debug/Conditional reservation methods own
//! these records. No source inspector, native participant or readiness issuer
//! is installed; a successful claim is only an original inspection ticket.

// crucible-lint: allow panic-shortcut -- Durable nonce custody controls deliberately panic on a changed ownership assertion.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::{
    conditional_preparation::{
        ConditionalPreparationRequest, ConditionalPreparationState, encode,
        ledger::ConditionalPreparationLedger,
    },
    debug::{DebugLedger, NodeDebugStartRequest, NodeDebugState},
    original_claim::{OriginalClaims, Reservation, Route},
};
use super::reserve_original_claim;
use crate::node_control::NodeOriginalLineageRequest;
use crate::node_observed_executor::{
    InstalledNodeKind, InstalledNodeSelection, factory::InstalledConditionDebugProfile,
};
use crucible_cas::content_store::{
    BlobHandle, ContentId, DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend,
    MutableRefBackend, ObjectKind, RefCasOutcome, RefName,
};
use crucible_node_contract::{Bytes, Id, U64, canonical};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Barrier},
};

const EXECUTION: &str = "82828282828282828282828282828282";
const CONFIGURATION: &[u8] = br#"{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"3000","maximum_rounds":"3"}"#;

#[derive(Clone)]
struct Stores {
    blobs: Arc<dyn ImmutableBlobBackend>,
    refs: Arc<dyn MutableRefBackend>,
}

impl Stores {
    fn new(path: &Path) -> Self {
        Self {
            blobs: Arc::new(DirectoryBlobBackend::new(
                "lineage-nonce-control",
                path.join("blobs"),
            )),
            refs: Arc::new(DirectoryRefBackend::new(path.join("refs"))),
        }
    }

    fn claims(&self) -> OriginalClaims {
        OriginalClaims::new(self.blobs.clone(), self.refs.clone()).unwrap()
    }

    fn reserve_lineage(&self, request: &NodeOriginalLineageRequest) -> bool {
        reserve_original_claim(request, self.blobs.clone(), self.refs.clone()).is_ok()
    }

    fn debug(&self) -> DebugLedger {
        DebugLedger::new(self.blobs.clone(), self.refs.clone()).unwrap()
    }

    fn conditional(&self) -> ConditionalPreparationLedger {
        ConditionalPreparationLedger::new(self.blobs.clone(), self.refs.clone()).unwrap()
    }
}

fn lineage_request() -> NodeOriginalLineageRequest {
    let reference = canonical::content_ref(b"{}", "application/json").unwrap();
    NodeOriginalLineageRequest::new(
        EXECUTION.into(),
        BTreeMap::from([
            (Id::new("disk").unwrap(), reference.clone()),
            (Id::new("link").unwrap(), reference.clone()),
            (Id::new("source").unwrap(), reference),
        ]),
        CONFIGURATION.to_vec(),
    )
    .unwrap()
}

fn debug_request() -> NodeDebugStartRequest {
    let observer = Id::new("observer").unwrap();
    NodeDebugStartRequest {
        format: "crucible.live-debug-start".into(),
        version: 1,
        execution: EXECUTION.into(),
        selections: vec![InstalledNodeSelection {
            node: observer.clone(),
            owner: Id::new("observer-owner").unwrap(),
            kind: InstalledNodeKind::HostConditionDebug {
                profile: InstalledConditionDebugProfile {
                    program: canonical::content_ref(b"{}", "application/json").unwrap(),
                },
            },
        }],
        observer,
        maximum_physical_cut: U64::new(3000),
    }
}

fn conditional_request() -> ConditionalPreparationRequest {
    let reference = canonical::content_ref(b"{}", "application/json").unwrap();
    ConditionalPreparationRequest {
        ledger: "conditional-nonce-control".into(),
        execution: EXECUTION.into(),
        sources: BTreeMap::from([
            (Id::new("producer").unwrap(), reference.clone()),
            (Id::new("consumer").unwrap(), reference),
        ]),
        configuration: Bytes::new(CONFIGURATION.to_vec()),
    }
}

#[test]
fn pending_debug_reservation_refuses_original_lineage_before_inspection() {
    let directory = tempfile::tempdir().unwrap();
    let stores = Stores::new(directory.path());
    let reserved = stores.debug().reserve_start(&debug_request()).unwrap();
    assert!(reserved.original_dispatch);
    assert!(matches!(
        reserved.record.outcome,
        NodeDebugState::AwaitingAdmission {}
    ));
    let roots = stores.claims().retention_roots().unwrap();

    assert!(!stores.reserve_lineage(&lineage_request()));
    assert_eq!(stores.claims().retention_roots().unwrap(), roots);
}

#[test]
fn pending_conditional_reservation_refuses_original_lineage_before_inspection() {
    let directory = tempfile::tempdir().unwrap();
    let stores = Stores::new(directory.path());
    let reserved = stores
        .conditional()
        .reserve(&conditional_request())
        .unwrap();
    assert!(reserved.original_dispatch);
    assert!(matches!(
        reserved.record.outcome,
        ConditionalPreparationState::AwaitingAdmission {}
    ));
    let roots = stores.claims().retention_roots().unwrap();

    assert!(!stores.reserve_lineage(&lineage_request()));
    assert_eq!(stores.claims().retention_roots().unwrap(), roots);
}

#[test]
fn original_lineage_claim_refuses_later_debug_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let stores = Stores::new(directory.path());
    assert!(stores.reserve_lineage(&lineage_request()));
    let roots = stores.claims().retention_roots().unwrap();

    assert!(stores.debug().reserve_start(&debug_request()).is_err());
    assert_eq!(stores.claims().retention_roots().unwrap(), roots);
}

#[test]
fn original_lineage_claim_refuses_later_conditional_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let stores = Stores::new(directory.path());
    assert!(stores.reserve_lineage(&lineage_request()));
    let roots = stores.claims().retention_roots().unwrap();

    assert!(
        stores
            .conditional()
            .reserve(&conditional_request())
            .is_err()
    );
    assert_eq!(stores.claims().retention_roots().unwrap(), roots);
}

#[test]
fn retained_original_claim_after_restart_cannot_repeat_source_inspection() {
    let directory = tempfile::tempdir().unwrap();
    let stores = Stores::new(directory.path());
    let request = lineage_request();
    assert!(stores.reserve_lineage(&request));
    let roots = stores.claims().retention_roots().unwrap();
    let original_bytes = encode(&request).unwrap();
    let original = ContentId::for_bytes(ObjectKind::Trace, 1, &original_bytes);
    assert!(roots.contains(&original));
    assert_eq!(
        stores
            .blobs
            .read(original, None)
            .unwrap()
            .read_all(65536)
            .unwrap(),
        original_bytes
    );
    drop(stores);

    let restarted = Stores::new(directory.path());
    assert!(!restarted.reserve_lineage(&request));
    assert!(restarted.debug().reserve_start(&debug_request()).is_err());
    assert!(
        restarted
            .conditional()
            .reserve(&conditional_request())
            .is_err()
    );
    assert_eq!(restarted.claims().retention_roots().unwrap(), roots);
}

#[test]
fn claim_without_route_record_still_refuses_foreign_original_lineage() {
    for (route, bytes) in [
        (Route::Debug, encode(&debug_request()).unwrap()),
        (Route::Conditional, encode(&conditional_request()).unwrap()),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let stores = Stores::new(directory.path());
        assert_eq!(
            stores.claims().reserve(EXECUTION, route, &bytes).unwrap(),
            Reservation::Original
        );
        let roots = stores.claims().retention_roots().unwrap();

        assert!(!stores.reserve_lineage(&lineage_request()));
        assert_eq!(stores.claims().retention_roots().unwrap(), roots);
    }
}

fn publish_legacy(stores: &Stores, namespace: &str, record: Vec<u8>, request: Vec<u8>) {
    // Copies exact actual pending record/request bodies, deliberately omitting
    // the newer common claim to reproduce a durable legacy reservation.
    for body in [request, record.clone()] {
        let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &body);
        stores
            .blobs
            .put_if_absent(identity, &BlobHandle::from_bytes(body))
            .unwrap();
    }
    let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &record);
    let name = RefName::new(format!("{namespace}/{EXECUTION}")).unwrap();
    assert!(matches!(
        stores.refs.compare_exchange(&name, None, identity).unwrap(),
        RefCasOutcome::Advanced { .. }
    ));
}

#[test]
fn actual_legacy_debug_and_conditional_records_refuse_original_lineage() {
    let original_directory = tempfile::tempdir().unwrap();
    let originals = Stores::new(original_directory.path());
    let debug = originals.debug().reserve_start(&debug_request()).unwrap();

    let legacy_directory = tempfile::tempdir().unwrap();
    let legacy = Stores::new(legacy_directory.path());
    publish_legacy(
        &legacy,
        "node-debug-preparations",
        encode(&debug.record).unwrap(),
        encode(&debug_request()).unwrap(),
    );
    assert!(!legacy.reserve_lineage(&lineage_request()));
    assert!(legacy.claims().retention_roots().unwrap().is_empty());

    let original_directory = tempfile::tempdir().unwrap();
    let originals = Stores::new(original_directory.path());
    let conditional = originals
        .conditional()
        .reserve(&conditional_request())
        .unwrap();

    let legacy_directory = tempfile::tempdir().unwrap();
    let legacy = Stores::new(legacy_directory.path());
    publish_legacy(
        &legacy,
        "node-conditional-preparations",
        encode(&conditional.record).unwrap(),
        encode(&conditional_request()).unwrap(),
    );
    assert!(!legacy.reserve_lineage(&lineage_request()));
    assert!(legacy.claims().retention_roots().unwrap().is_empty());
}

#[test]
fn concurrent_original_lineage_and_actual_debug_reservation_have_one_winner() {
    let directory = tempfile::tempdir().unwrap();
    let stores = Stores::new(directory.path());
    let barrier = Arc::new(Barrier::new(3));
    let lineage = {
        let stores = stores.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            stores.reserve_lineage(&lineage_request())
        })
    };
    let debug = {
        let stores = stores.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            stores.debug().reserve_start(&debug_request()).is_ok()
        })
    };

    barrier.wait();
    assert_ne!(lineage.join().unwrap(), debug.join().unwrap());
    assert_eq!(stores.claims().retention_roots().unwrap().len(), 3);
}

#[test]
fn malformed_original_request_cannot_consume_claim_or_lifetime_credit() {
    let directory = tempfile::tempdir().unwrap();
    let stores = Stores::new(directory.path());
    let mut request = lineage_request();
    request.sources.remove(&Id::new("disk").unwrap());

    assert!(!stores.reserve_lineage(&request));
    assert!(stores.claims().retention_roots().unwrap().is_empty());
}
