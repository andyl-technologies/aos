//! Tests durable nonce commitments without issuing native qualification.

// crucible-lint: allow rust-allow -- test setup and exact authority regressions deliberately panic on failure.
// crucible-lint: allow panic-shortcut -- Invalid durable requests and authority fixtures fail the test immediately.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::{
    node_observed_executor::{InstalledNodeKind, InstalledNodeSelection},
    node_scenario::NodeScenario,
};
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};
use crucible_node_contract::{Bytes, U64};

fn request() -> NodeHostStateRequest {
    // This synthetic schema fixture tests storage commitments only. It is never
    // enrolled by an installed factory or offered as native preservation proof.
    let (graph, _) = crucible::node_admission::test_double_graph(false);
    let scenario = NodeScenario {
        format: "crucible.node-scenario".into(),
        version: 1,
        world: graph.world().clone(),
        descriptors: graph
            .node_ids()
            .map(|node| graph.descriptor(node).unwrap().clone())
            .collect(),
        compatibility: graph
            .node_ids()
            .map(|node| graph.binding(node).unwrap().compatibility.clone())
            .collect(),
        owners: graph.owners().cloned().collect(),
        requirements: graph.requirements().clone(),
        content: vec![],
    };
    NodeHostStateRequest::Capture {
        execution: "33333333333333333333333333333333".into(),
        selections: graph
            .node_ids()
            .map(|node| InstalledNodeSelection {
                node: node.clone(),
                owner: graph
                    .binding(node)
                    .unwrap()
                    .compatibility
                    .execution_owner
                    .id
                    .clone(),
                kind: InstalledNodeKind::HostClock,
            })
            .collect(),
        scenario: Bytes::new(scenario.canonical_bytes().unwrap()),
        horizon_ps: U64::new(100),
    }
}

#[test]
fn original_nonce_custody_survives_restart_and_refuses_changed_request() {
    let directory = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "host-state-ledger-test",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let ledger = HostStateLedger::new(blobs.clone(), refs.clone()).unwrap();
    let original = request();

    let reserved = ledger.reserve(&original).unwrap();
    assert!(reserved.original_dispatch);
    assert!(!ledger.reserve(&original).unwrap().original_dispatch);
    assert!(
        ledger
            .retention_roots()
            .unwrap()
            .contains(&reserved.record.request)
    );
    drop(ledger);

    let ledger = HostStateLedger::new(blobs, refs).unwrap();
    let recovered = ledger.reserve(&original).unwrap();
    assert!(
        !recovered.original_dispatch,
        "a new actor cannot inherit native dispatch permission"
    );
    assert_eq!(recovered.identity, reserved.identity);
    let mut changed = original.clone();
    let NodeHostStateRequest::Capture { horizon_ps, .. } = &mut changed else {
        unreachable!()
    };
    *horizon_ps = U64::new(101);
    assert!(ledger.reserve(&changed).is_err());

    let completed = ledger
        .complete(
            &reserved,
            NodeHostStateOutcome::Refused {
                reason: "original test request refused".into(),
            },
        )
        .unwrap();
    let recovered = ledger.reserve(&original).unwrap();
    assert!(!recovered.original_dispatch);
    assert_eq!(
        serde_json::to_value(completed).unwrap(),
        serde_json::to_value(&recovered.record).unwrap()
    );
    assert!(
        ledger
            .complete(
                &recovered,
                NodeHostStateOutcome::Refused {
                    reason: "replacement".into(),
                }
            )
            .is_err(),
        "a read borrower cannot publish a different original result"
    );
}

#[test]
fn capture_none_selection_is_refused_before_persistent_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let blobs: Arc<dyn ImmutableBlobBackend> = Arc::new(DirectoryBlobBackend::new(
        "host-state-refusal-test",
        directory.path().join("blobs"),
    ));
    let refs: Arc<dyn MutableRefBackend> =
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let ledger = HostStateLedger::new(blobs, refs).unwrap();
    let mut request = request();
    let NodeHostStateRequest::Capture { selections, .. } = &mut request else {
        unreachable!()
    };
    selections[0].kind = InstalledNodeKind::ReferenceDevice {
        quantum_ps: U64::new(50),
        host_budget_ns: U64::new(1000),
    };

    assert!(ledger.reserve(&request).is_err());
    assert!(ledger.state(request.execution()).is_err());
    assert!(ledger.retention_roots().unwrap().is_empty());
}

#[test]
fn separate_ledgers_cannot_consume_the_same_last_durable_record_credit() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "host-state-credit",
        directory.path().join("blobs"),
    ));
    let refs = DirectoryRefBackend::new(directory.path().join("refs"));
    // Consumed credits include uncertain attempts, so 4095 need not imply 4095
    // successful records. Both independent publishers must still share one CAS.
    let bytes = canonical::canonical_json(&serde_json::json!({
        "format":"crucible.host-state-record-quota", "version":1, "consumed":4095,
    }))
    .unwrap();
    let initial = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    blobs
        .put_if_absent(initial, &BlobHandle::from_bytes(bytes))
        .unwrap();
    refs.compare_exchange(&record_quota_ref().unwrap(), None, initial)
        .unwrap();
    let start = Arc::new(std::sync::Barrier::new(2));
    let mut workers = Vec::new();
    for execution in [
        "61616161616161616161616161616161",
        "71717171717171717171717171717171",
    ] {
        let ledger = HostStateLedger::new(
            blobs.clone(),
            Arc::new(DirectoryRefBackend::new(directory.path().join("refs"))),
        )
        .unwrap();
        let mut original = request();
        let NodeHostStateRequest::Capture {
            execution: nonce, ..
        } = &mut original
        else {
            unreachable!()
        };
        *nonce = execution.into();
        let start = start.clone();
        workers.push(std::thread::spawn(move || {
            start.wait();
            (original.clone(), ledger.reserve(&original).is_ok())
        }));
    }
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|(_, accepted)| *accepted).count(), 1);
    let page = refs
        .scan_refs(&RefName::new("node-state-operations").unwrap(), None, 64)
        .unwrap();
    assert_eq!(page.entries().len(), 1);
    let current = refs
        .read_ref(&record_quota_ref().unwrap())
        .unwrap()
        .unwrap();
    let bytes = blobs.read(current, None).unwrap().read_all(1024).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["consumed"],
        4096
    );
    let ledger = HostStateLedger::new(blobs, Arc::new(refs)).unwrap();
    let original = &results.iter().find(|(_, accepted)| *accepted).unwrap().0;
    assert!(!ledger.reserve(original).unwrap().original_dispatch);
    assert!(ledger.retention_roots().unwrap().contains(&current));
}

#[test]
fn understated_quota_refuses_new_admission_without_changing_original_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "host-state-migration",
        directory.path().join("blobs"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let ledger = HostStateLedger::new(blobs, refs.clone()).unwrap();
    let reserved = ledger.reserve(&request()).unwrap();
    assert_eq!(reserved.record.version, 1);
    let original = reserved.identity;
    // A deliberately understated budget is refused before another dispatch;
    // original nonce reads remain byte-identical and consume no further credit.
    let quota = canonical::canonical_json(&serde_json::json!({
        "format":"crucible.host-state-record-quota", "version":1, "consumed":0,
    }))
    .unwrap();
    let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &quota);
    ledger.put(identity, quota).unwrap();
    let current = refs.read_ref(&record_quota_ref().unwrap()).unwrap();
    refs.compare_exchange(&record_quota_ref().unwrap(), current, identity)
        .unwrap();
    assert_eq!(ledger.reserve(&request()).unwrap().identity, original);
    let mut next = request();
    let NodeHostStateRequest::Capture { execution, .. } = &mut next else {
        unreachable!()
    };
    *execution = "81818181818181818181818181818181".into();
    assert!(ledger.reserve(&next).is_err());
    assert!(ledger.state(next.execution()).is_err());
    assert_eq!(
        ledger.state(request().execution()).unwrap().request,
        reserved.record.request
    );
}

#[test]
fn absent_quota_migrates_authentic_legacy_records_before_new_admission() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "host-state-legacy",
        directory.path().join("blobs"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let ledger = HostStateLedger::new(blobs, refs.clone()).unwrap();
    let original = request();
    let bytes = canonical::canonical_json(&serde_json::to_value(&original).unwrap()).unwrap();
    let request_identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    ledger.put(request_identity, bytes).unwrap();
    let record = NodeHostStateRecord {
        format: "crucible.node-state-operation".into(),
        version: 1,
        execution: original.execution().into(),
        request: request_identity,
        state: NodeHostStateOutcome::Reserved {},
    };
    let identity = ledger.put_record(&record).unwrap();
    refs.compare_exchange(
        &operation_ref(original.execution()).unwrap(),
        None,
        identity,
    )
    .unwrap();
    assert!(
        refs.read_ref(&record_quota_ref().unwrap())
            .unwrap()
            .is_none()
    );

    let mut next = original.clone();
    let NodeHostStateRequest::Capture { execution, .. } = &mut next else {
        unreachable!()
    };
    *execution = "91919191919191919191919191919191".into();
    assert!(ledger.reserve(&next).unwrap().original_dispatch);
    let quota = refs
        .read_ref(&record_quota_ref().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(ledger.read_quota(quota).unwrap(), 2);
    assert_eq!(ledger.reserve(&original).unwrap().identity, identity);
    assert_eq!(
        refs.read_ref(&operation_ref(original.execution()).unwrap())
            .unwrap(),
        Some(identity)
    );
}

#[test]
fn corrupt_existing_original_record_refuses_credit_before_new_admission() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "host-state-corrupt",
        directory.path().join("blobs"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let ledger = HostStateLedger::new(blobs, refs.clone()).unwrap();
    let bytes = b"corrupt original record".to_vec();
    let corrupt = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    ledger.put(corrupt, bytes).unwrap();
    refs.compare_exchange(
        &operation_ref("92929292929292929292929292929292").unwrap(),
        None,
        corrupt,
    )
    .unwrap();

    assert!(ledger.reserve(&request()).is_err());
    assert!(ledger.state(request().execution()).is_err());
    assert!(
        refs.read_ref(&record_quota_ref().unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn missing_existing_original_request_refuses_credit_before_new_admission() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = Arc::new(DirectoryBlobBackend::new(
        "host-state-missing",
        directory.path().join("blobs"),
    ));
    let refs = Arc::new(DirectoryRefBackend::new(directory.path().join("refs")));
    let ledger = HostStateLedger::new(blobs, refs.clone()).unwrap();
    let record = NodeHostStateRecord {
        format: "crucible.node-state-operation".into(),
        version: 1,
        execution: "93939393939393939393939393939393".into(),
        request: ContentId::for_bytes(ObjectKind::Trace, 1, b"missing original request"),
        state: NodeHostStateOutcome::Reserved {},
    };
    let identity = ledger.put_record(&record).unwrap();
    refs.compare_exchange(&operation_ref(&record.execution).unwrap(), None, identity)
        .unwrap();

    assert!(ledger.reserve(&request()).is_err());
    assert!(ledger.state(request().execution()).is_err());
    assert!(
        refs.read_ref(&record_quota_ref().unwrap())
            .unwrap()
            .is_none()
    );
}
