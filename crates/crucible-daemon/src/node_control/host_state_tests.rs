//! Tests durable nonce commitments without issuing native qualification.

// crucible-lint: allow rust-allow -- test setup and exact authority regressions deliberately panic on failure.
// crucible-lint: allow panic-shortcut -- These host state tests deliberately panic on invalid fixtures or failed invariants.
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
