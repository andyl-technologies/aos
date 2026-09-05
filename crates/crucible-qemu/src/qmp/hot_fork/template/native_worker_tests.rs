//! Checks native-worker proof withholding at the retained-template boundary.

use super::{QMP_HOT_FORK_AIO_PROOF, QmpHotForkTemplateOutcome, parse_hot_fork_template_state};
use serde_json::{Value, json};

#[test]
fn quiescent_aio_without_retired_native_workers_remains_draining() -> Result<(), crate::QmpError> {
    let mut report = prepared_report();
    report["acknowledged-proofs"] = json!(127 & !QMP_HOT_FORK_AIO_PROOF);
    report["missing-proofs"] = json!(QMP_HOT_FORK_AIO_PROOF);
    report["outcome"] = json!("draining");
    report["ready"] = json!(false);

    let state = parse_hot_fork_template_state(&report)?;
    assert_eq!(state.outcome(), QmpHotForkTemplateOutcome::Draining);
    assert!(state.bh_timer_barrier().quiescent());
    assert!(!state.ready());
    assert_eq!(state.missing_proofs(), QMP_HOT_FORK_AIO_PROOF);
    Ok(())
}

#[test]
fn missing_native_worker_proof_cannot_claim_prepared() {
    let mut report = prepared_report();
    report["acknowledged-proofs"] = json!(127 & !QMP_HOT_FORK_AIO_PROOF);
    report["missing-proofs"] = json!(QMP_HOT_FORK_AIO_PROOF);

    assert!(parse_hot_fork_template_state(&report).is_err());
}

#[test]
fn aio_proof_still_requires_closed_quiescent_admission() {
    let mut report = prepared_report();
    report["bh-timer-barrier"]["admissions-in-flight"] = json!(1);
    report["bh-timer-barrier"]["quiescent"] = json!(false);
    report["outcome"] = json!("draining");
    report["ready"] = json!(false);

    assert!(parse_hot_fork_template_state(&report).is_err());
}

/// Reproduces the complete prepared response used by the typed QMP fixture.
pub(super) fn prepared_report() -> Value {
    json!({
        "schema-version": 24,
        "generation": 4,
        "outcome": "prepared",
        "transaction-active": true,
        "required-proofs": 127,
        "acknowledged-proofs": 127,
        "missing-proofs": 0,
        "plugin-barrier": {
            "schema-version": 6,
            "generation": 8,
            "registered": true,
            "manifest-consistent": true,
            "held": true,
            "teardown-closed": false,
            "mapping-dontfork": true,
            "in-flight": 0,
            "ring-count": 9,
            "rings-held": 9,
            "ring-producers-in-flight": 0,
            "ring-consumers-in-flight": 0,
            "worker-mask": 3,
            "parked-worker-mask": 3,
            "pending-worker-mask": 0,
            "worker-operations-in-flight": 0,
            "quiescent": true
        },
        "rcu-barrier": {
            "schema-version": 1,
            "generation": 6,
            "owner-thread-id": 44,
            "held": true,
            "complete": true,
            "registered-readers": 2,
            "active-readers": 0,
            "admissions-in-flight": 0,
            "pending-callbacks": 0,
            "drain-active": false,
            "quiescent": true
        },
        "bh-timer-barrier": {
            "schema-version": 2,
            "generation": 6,
            "owner-thread-id": 44,
            "held": true,
            "complete": true,
            "bottom-halves-complete": true,
            "timers-complete": true,
            "admissions-in-flight": 0,
            "bottom-half-count": 4,
            "pending-bottom-halves": 2,
            "scheduled-bottom-halves": 1,
            "active-bottom-half-callbacks": 0,
            "pending-timers": 3,
            "active-timer-callbacks": 0,
            "aio-context-count": 2,
            "active-aio-polls": 0,
            "active-aio-dispatches": 0,
            "queued-coroutines": 1,
            "aio-handler-count": 3,
            "active-aio-handler-callbacks": 0,
            "aio-contexts-complete": true,
            "aio-handlers-complete": true,
            "quiescent": true
        },
        "block-barrier": {
            "schema-version": 3,
            "generation": 4,
            "owner-thread-id": 44,
            "graph-barrier-generation": 5,
            "graph-mutation-generation": 9,
            "held-graph-mutation-generation": 9,
            "graph-owner-thread-id": 44,
            "held": true,
            "graph-held": true,
            "graph-writer-active": false,
            "graph-waiting-writers": 0,
            "graph-stable": true,
            "snapshot-generation": 1,
            "snapshot-backend-generation": 5,
            "snapshot-graph-mutation-generation": 9,
            "snapshot-owner-thread-id": 44,
            "snapshot-bound": true,
            "snapshot-complete": true,
            "snapshot-roots": [
                {
                    "backend-id": 1,
                    "backend-name": "drive0",
                    "overlay-node-name": "overlay0",
                    "snapshot-node-name": "snapshot0",
                    "snapshot-content-id": "abababababababababababababababababababababababababababababababab",
                    "virtual-size": 4096,
                    "overlay-empty": true,
                    "snapshot-read-only": true
                }
            ],
            "complete": true,
            "backend-count": 3,
            "rooted-backends": 2,
            "writable-backends": 2,
            "writable-rooted-backends": 1,
            "quiesced-rooted-backends": 2,
            "in-flight": 0,
            "quiescent": true
        },
        "resource-stage": {
            "schema-version": 13,
            "template-generation": 4,
            "private-ring-staged": true,
            "private-ring-generation": 11,
            "diagnostics-staged": true,
            "diagnostic-generation": 13,
            "diagnostics-resource-plan-bound": true,
            "qmp-staged": true,
            "qmp-generation": 14,
            "qmp-resource-plan-bound": true,
            "console-staged": true,
            "console-generation": 15,
            "console-resource-plan-bound": true,
            "plugin-endpoints-staged": true,
            "plugin-endpoint-generation": 12,
            "plugin-private-ring-generation": 11,
            "plugin-barrier-generation": 8,
            "worker-mask": 3,
            "parent-resume-worker-mask": 3,
            "child-reinitialize-worker-mask": 3,
            "pending-worker-mask": 0,
            "worker-disposition-bound": true,
            "transaction-bound": true,
            "parent-process-generation": 21,
            "child-process-generation": 22,
            "plugin-child-plan-bound": true,
            "plugin-child-resource-plan-bound": true,
            "readiness-proof-acknowledged": true
        },
        "rollback-complete": false,
        "ready": true
    })
}
