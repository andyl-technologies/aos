//! Models durable Stop placement before the owning actor's local reconciliation.
//!
//! The fabricated capture is inert ledger data. No native constructor, opaque
//! barrier, publication permit or restoration authority is supplied by this test.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- The test asserts exact original reservation retention and durable refusal.
#![allow(clippy::unwrap_used)]

use super::super::encode;
use super::*;
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};
use crucible_node_contract::{Bytes, Position, canonical};
use std::sync::Arc;

#[test]
fn durable_stop_before_local_reconciliation_retains_incoming_resume() {
    let directory = tempfile::tempdir().unwrap();
    let (selections, _) = super::super::tests::fixture(directory.path());
    let request = NodePreservingDebugRequest {
        format: "crucible.preserving-debug-request".into(),
        version: 1,
        execution: "abababababababababababababababab".into(),
        selections,
        scenario: Bytes::new(Vec::new()),
        observer: Id::new("observer").unwrap(),
        maximum_physical_cut: 1.into(),
        maximum_record_bytes: (32 << 20).into(),
        action: NodePreservingDebugAction::Capture {},
    };
    let ledger = super::super::Ledger::new(
        Arc::new(DirectoryBlobBackend::new(
            "race-ledger",
            directory.path().join("blobs"),
        )),
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs"))),
    )
    .unwrap();
    let pending = ledger.reserve_prepare(&request).unwrap();
    let reference =
        canonical::content_ref(b"inert ledger-only capture", "application/json").unwrap();
    let capture = NodePreservingDebugCapture {
        source_execution: request.execution.clone(),
        source_request: pending.record.request.clone(),
        artifact: reference.clone(),
        cut: Position::new(
            1.into(),
            0.into(),
            crucible_node_contract::Phase::BoundaryControl,
        ),
        barrier: reference.clone(),
        report: reference,
    };
    ledger
        .complete(
            &pending,
            NodePreservingDebugState::Stopped {},
            Some(capture.clone()),
        )
        .unwrap();
    let resume = NodePreservingDebugResumeRequest {
        format: "crucible.preserving-debug-resume".into(),
        version: 1,
        execution: request.execution.clone(),
        horizon_ps: 2.into(),
    };
    let incoming = ledger.reserve_resume(&resume).unwrap();
    let incoming_id = incoming.record.resume_request.clone();
    assert!(incoming.original_dispatch);

    let mut worker = Worker {
        reservation: pending,
        outcome: Some(NodePreservingDebugState::Stopped {}),
        published: false,
        request,
        graph: None,
        runtime: None,
        restored: None,
        activation: None,
        archive: HostArchive::open(directory.path().join("archive"), StateLimits::default())
            .unwrap(),
        capture: Some(capture),
        original_record: None,
        driver: ConditionExecution::new(8192).unwrap(),
        token: None,
        resume: None,
        completed: None,
        completed_receipt: None,
        completed_ledger: None,
        suffix_unsealed: false,
        sealed_suffix: None,
        phase: Phase::Held,
    };
    let error = worker.adopt_resume(resume, incoming).unwrap_err();
    worker.fail(error);
    assert_eq!(worker.reservation.record.resume_request, incoming_id);
    let completed = ledger
        .complete(
            &worker.reservation,
            worker.outcome.clone().unwrap(),
            worker.capture(),
        )
        .unwrap();
    assert!(matches!(
        completed.outcome,
        NodePreservingDebugState::Unknown { .. }
    ));
    assert_eq!(completed.resume_request, incoming_id);
    assert_eq!(
        ledger.state(&completed.execution).unwrap().resume_request,
        incoming_id
    );
    assert!(worker.runtime.is_none() && worker.restored.is_none() && worker.token.is_none());
}

#[test]
fn failed_suffix_seal_or_unwind_keeps_original_owner_and_blocks_containment() {
    let directory = tempfile::tempdir().unwrap();
    let (selections, _) = super::super::tests::fixture(directory.path());
    let request = NodePreservingDebugRequest {
        format: "crucible.preserving-debug-request".into(),
        version: 1,
        execution: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".into(),
        selections,
        scenario: Bytes::new(Vec::new()),
        observer: Id::new("observer").unwrap(),
        maximum_physical_cut: 1.into(),
        maximum_record_bytes: (32 << 20).into(),
        action: NodePreservingDebugAction::Capture {},
    };
    let ledger = super::super::Ledger::new(
        Arc::new(DirectoryBlobBackend::new(
            "held-ledger",
            directory.path().join("blobs"),
        )),
        Arc::new(DirectoryRefBackend::new(directory.path().join("refs"))),
    )
    .unwrap();
    let reservation = ledger.reserve_prepare(&request).unwrap();
    let original_record = encode(&reservation.record).unwrap();
    let receipt =
        canonical::content_ref(b"inert original suffix receipt", "application/json").unwrap();
    let mut worker = Worker {
        reservation,
        outcome: None,
        published: false,
        request,
        graph: None,
        runtime: None,
        restored: None,
        activation: None,
        archive: HostArchive::open(directory.path().join("archive"), StateLimits::default())
            .unwrap(),
        capture: None,
        original_record: None,
        driver: ConditionExecution::new(8192).unwrap(),
        token: None,
        resume: None,
        completed: None,
        completed_receipt: Some(receipt.clone()),
        completed_ledger: None,
        suffix_unsealed: true,
        sealed_suffix: None,
        phase: Phase::StoreSuffix,
    };

    // These are ownership-state controls with inert data, not native failures.
    // The same production fail/contain functions must keep the original seal
    // premise even if cleanup itself would have no native work to perform.
    worker.fail(refused("original suffix encoding refused"));
    worker.contain();
    assert!(matches!(worker.phase, Phase::Held));
    assert!(worker.suffix_unsealed && !worker.released());
    assert_eq!(worker.completed_receipt.as_ref(), Some(&receipt));
    assert_eq!(encode(&worker.reservation.record).unwrap(), original_record);
    assert!(
        !ledger
            .reserve_prepare(&worker.request)
            .unwrap()
            .original_dispatch
    );

    let original_unknown = encode(worker.outcome.as_ref().unwrap()).unwrap();
    let unwind = std::panic::catch_unwind(|| panic!("original suffix seal unwind"));
    assert!(unwind.is_err());
    worker.fail("original suffix seal unwound");
    worker.contain();
    assert!(matches!(worker.phase, Phase::Held));
    assert!(worker.suffix_unsealed && !worker.released());
    assert_eq!(worker.completed_receipt.as_ref(), Some(&receipt));
    assert_eq!(
        encode(worker.outcome.as_ref().unwrap()).unwrap(),
        original_unknown
    );
    assert_eq!(encode(&worker.reservation.record).unwrap(), original_record);
}
