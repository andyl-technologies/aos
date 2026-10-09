//! Original publication/fence custody regressions using explicit model fixtures.

use super::*;
use crate::node_contract::{
    SavedWorldTerminal, TerminalPublicationState, TerminalResultPublisher, WorldTerminalRecord,
};
use crate::node_scheduling::InputPayload;

fn completed_terminal_fixture() -> (NodeRuntime, OperationToken, Rc<RefCell<NativeState>>) {
    let (mut runtime, native) = runtime(OperatingMode::Exact);
    let activation = activate(&mut runtime);
    let route = runtime.checked_route(&id("a")).unwrap();
    let record = WorldTerminalRecord {
        version: 1,
        operation: id("original-terminal"),
        node: id("a"),
        source: activation.record().into(),
        cut: position(0),
        scheduler: crucible_node_contract::Bytes::new(b"fixture terminal coordinator".to_vec()),
        native: Vec::new(),
    };
    let bytes =
        crucible_node_contract::canonical::canonical_json(&serde_json::to_value(&record).unwrap())
            .unwrap();
    let reference =
        crucible_node_contract::canonical::content_ref(&bytes, "application/json").unwrap();
    let report = InputPayload {
        reference: crucible_node_contract::canonical::content_ref(
            b"actual fixture native report",
            "text/plain",
        )
        .unwrap(),
        bytes: b"actual fixture native report".to_vec(),
    };
    let token = OperationToken {
        authority: Rc::clone(&runtime.authority),
        operation: record.operation.clone(),
        route,
    };
    let admission = OperationAdmission {
        token: token.clone(),
        activation,
        inputs: None,
        request: OperationRequest::FinalizeAssertions {
            barrier: Box::new(record.clone()),
            receipt: reference.clone(),
        },
    };
    let outcome = OperationOutcome {
        operation: token.operation().clone(),
        node: token.route().node.clone(),
        owners: token.route().owners.clone(),
        progress: ProgressEvidence::AssertionsFinalized {
            reached: record.cut,
            barrier: reference.clone(),
            report: report.reference.clone(),
        },
        retained_outputs: Vec::new(),
        scheduling: None,
    };
    runtime.reserve(&token);
    runtime.operations.insert(
        token.operation().clone(),
        RetainedOperation {
            admission: admission.clone(),
            result: RetainedResult::Complete(outcome),
            close_submission: None,
            submission_effects: Some(EffectKnowledge::Unknown),
            scheduling_commit: None,
        },
    );
    runtime.terminal = Some(crate::node_contract::terminal::TerminalState {
        saved: SavedWorldTerminal {
            record,
            reference,
            submitted: true,
            report: None,
            publication: None,
            acknowledged: false,
        },
    });
    native[0].borrow_mut().admission = Some(admission);
    native[0].borrow_mut().evidence_objects.push(report);
    (runtime, token, Rc::clone(&native[0]))
}

struct ReportPublisher {
    status: PublicationStatus,
    publications: usize,
    reconciliations: usize,
    original: Option<(InputPayload, InputPayload)>,
}

impl TerminalResultPublisher for ReportPublisher {
    fn publish(&mut self, barrier: &InputPayload, report: &InputPayload) -> PublicationStatus {
        self.publications += 1;
        self.original = Some((barrier.clone(), report.clone()));
        self.status
    }

    fn reconcile(&mut self, barrier: &InputPayload, report: &InputPayload) -> PublicationStatus {
        self.reconciliations += 1;
        assert_eq!(
            self.original.as_ref(),
            Some(&(barrier.clone(), report.clone()))
        );
        self.status
    }
}

#[test]
fn terminal_uncertain_publication_reconciles_original_report_before_native_ack() {
    let (mut runtime, token, native) = completed_terminal_fixture();
    let mut publisher = ReportPublisher {
        status: PublicationStatus::Unknown,
        publications: 0,
        reconciliations: 0,
        original: None,
    };

    let (status, commit) = runtime
        .publish_terminal_result(&token, &mut publisher, 65_536)
        .unwrap();
    assert_eq!(status, PublicationStatus::Unknown);
    assert!(commit.is_none());
    assert_eq!(
        runtime.terminal_checkpoint().unwrap().publication,
        Some(TerminalPublicationState::Unknown)
    );
    assert_eq!(native.borrow().ack_calls, 0);
    publisher.status = PublicationStatus::Committed;
    let (_, commit) = runtime
        .publish_terminal_result(&token, &mut publisher, 65_536)
        .unwrap();
    let commit = commit.unwrap();
    assert_eq!(publisher.publications, 1);
    assert_eq!(publisher.reconciliations, 1);

    runtime
        .acknowledge_terminal_result(&token, &commit)
        .unwrap();
    runtime
        .acknowledge_terminal_result(&token, &commit)
        .unwrap();
    assert_eq!(native.borrow().ack_calls, 1);
    assert!(runtime.terminal_checkpoint().unwrap().acknowledged);
    assert_eq!(native.borrow().begin_calls, 0);
}

#[test]
fn terminal_ack_failure_retains_original_report_and_effects_fence() {
    let (mut runtime, token, native) = completed_terminal_fixture();
    let mut publisher = ReportPublisher {
        status: PublicationStatus::Committed,
        publications: 0,
        reconciliations: 0,
        original: None,
    };
    let (_, commit) = runtime
        .publish_terminal_result(&token, &mut publisher, 65_536)
        .unwrap();
    let commit = commit.unwrap();
    native.borrow_mut().ack_fail = true;

    assert!(
        runtime
            .acknowledge_terminal_result(&token, &commit)
            .is_err()
    );
    let saved = runtime.terminal_checkpoint().unwrap().clone();
    assert!(!saved.acknowledged);
    let activation = runtime.operations[token.operation()]
        .admission
        .activation()
        .clone();
    assert!(
        runtime
            .begin(
                &activation,
                &id("a"),
                id("replacement"),
                OperationRequest::Observe
            )
            .is_err()
    );
    assert_eq!(native.borrow().begin_calls, 0);
    assert_eq!(runtime.terminal_checkpoint(), Some(&saved));

    native.borrow_mut().ack_fail = false;
    runtime
        .acknowledge_terminal_result(&token, &commit)
        .unwrap();
    assert!(runtime.terminal_checkpoint().unwrap().acknowledged);
    assert_eq!(publisher.publications, 1);
    assert_eq!(publisher.reconciliations, 0);
}

#[test]
fn terminal_foreign_commit_cannot_ack_an_equal_named_original_operation() {
    let (mut first, first_token, _) = completed_terminal_fixture();
    let (mut second, second_token, native) = completed_terminal_fixture();
    let mut publisher = ReportPublisher {
        status: PublicationStatus::Committed,
        publications: 0,
        reconciliations: 0,
        original: None,
    };
    let (_, commit) = first
        .publish_terminal_result(&first_token, &mut publisher, 65_536)
        .unwrap();

    assert!(
        second
            .acknowledge_terminal_result(&second_token, &commit.unwrap())
            .is_err()
    );
    assert_eq!(native.borrow().ack_calls, 0);
    assert!(!second.terminal_checkpoint().unwrap().acknowledged);
}

#[test]
fn terminal_historical_committed_status_requires_current_durable_reconciliation() {
    let (mut runtime, token, native) = completed_terminal_fixture();
    let mut publisher = ReportPublisher {
        status: PublicationStatus::Committed,
        publications: 0,
        reconciliations: 0,
        original: None,
    };
    let (_, original_commit) = runtime
        .publish_terminal_result(&token, &mut publisher, 65_536)
        .unwrap();
    assert!(original_commit.is_some());
    let saved = runtime.terminal_checkpoint().unwrap().clone();
    publisher.status = PublicationStatus::Unknown;

    let (status, commit) = runtime
        .publish_terminal_result(&token, &mut publisher, 65_536)
        .unwrap();

    assert_eq!(status, PublicationStatus::Unknown);
    assert!(commit.is_none());
    assert_eq!(publisher.publications, 1);
    assert_eq!(publisher.reconciliations, 1);
    let current = runtime.terminal_checkpoint().unwrap();
    assert_eq!(current.record, saved.record);
    assert_eq!(current.report, saved.report);
    assert_eq!(
        current.publication,
        Some(TerminalPublicationState::Committed)
    );
    assert!(!current.acknowledged);
    assert_eq!(native.borrow().ack_calls, 0);
    assert_eq!(native.borrow().begin_calls, 0);
}

#[test]
fn terminal_original_ack_history_survives_failed_current_store_reconciliation() {
    let (mut runtime, token, native) = completed_terminal_fixture();
    let mut publisher = ReportPublisher {
        status: PublicationStatus::Committed,
        publications: 0,
        reconciliations: 0,
        original: None,
    };
    let (_, commit) = runtime
        .publish_terminal_result(&token, &mut publisher, 65_536)
        .unwrap();
    runtime
        .acknowledge_terminal_result(&token, &commit.unwrap())
        .unwrap();
    let original = runtime.terminal_checkpoint().unwrap().clone();
    for status in [PublicationStatus::NotCommitted, PublicationStatus::Unknown] {
        publisher.status = status;
        let (actual, permit) = runtime
            .publish_terminal_result(&token, &mut publisher, 65_536)
            .unwrap();
        assert_eq!(actual, status);
        assert!(permit.is_none());
        assert_eq!(runtime.terminal_checkpoint(), Some(&original));
    }
    assert_eq!(publisher.publications, 1);
    assert_eq!(publisher.reconciliations, 2);
    assert_eq!(native.borrow().ack_calls, 1);
    assert_eq!(native.borrow().begin_calls, 0);
}
