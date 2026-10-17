//! Actual shared artifact verification and incomplete observation boundaries.

use std::cell::RefCell;

use super::*;

fn selected(sink: Rc<dyn Fn(&str) -> bool>) -> Trace {
    Trace::new(
        Configuration {
            version: 1,
            capture_id: "a".repeat(32),
            placement_prefix: "actual".into(),
            document_digest: format!("sha256:{}", "e".repeat(64)),
        },
        Original {
            request_sha256: "b".repeat(64),
            document_digest: format!("sha256:{}", "e".repeat(64)),
            nonce: "c".repeat(64),
            key: "actual/oci/object".into(),
            issued_at: 110,
            expires_at: 140,
            clock_uncertainty_seconds: 2,
            source_digest: "10".repeat(32),
            script_version: "observed-script".into(),
            protected_profile_digest: "d".repeat(64),
        },
        sink,
    )
    .unwrap()
}

fn records() -> (Trace, Rc<RefCell<Vec<serde_json::Value>>>) {
    let records = Rc::new(RefCell::new(Vec::new()));
    let output = Rc::clone(&records);
    let trace = selected(Rc::new(move |body| {
        output
            .borrow_mut()
            .push(serde_json::from_str(body).unwrap());
        true
    }));
    (trace, records)
}

#[test]
fn actual_same_source_signed_artifact_refuses_another_origin_before_dispatch() {
    let (artifact, key) = aos_hub_core::oci_sdk_emulation::oci_sdk_emulation_fixture();
    let bytes = serde_json::to_vec(&artifact).unwrap();
    let (trace, output) = records();
    let result = verify_artifact(
        Some(&trace),
        &artifact,
        &bytes,
        &artifact.profile.deployment_id,
        "https://other.oci.test",
        &key,
        110,
    );
    assert!(result.is_err());
    trace.finish(&result);

    let rows = output.borrow();
    assert_eq!(rows.len(), 4);
    assert_eq!(
        rows[1]["event"]["source_digest"],
        artifact.profile.worker_source_digest
    );
    assert_eq!(
        rows[1]["event"]["artifact_sha256"],
        hex::encode(Sha256::digest(&bytes))
    );
    assert_eq!(rows[1]["event"]["current_origin"], "https://other.oci.test");
    assert_eq!(rows[3]["event"]["outcome"], "refused");
    assert_eq!(rows[3]["event"]["healthy"], true);
    assert_eq!(
        rows[0]["event"]["before"]["dispatches"],
        rows[3]["event"]["after"]["dispatches"]
    );
}

#[test]
fn same_actual_verifier_accepts_its_original_origin_and_refuses_changed_signature() {
    let (mut artifact, key) = aos_hub_core::oci_sdk_emulation::oci_sdk_emulation_fixture();
    let bytes = serde_json::to_vec(&artifact).unwrap();
    verify_artifact(
        None,
        &artifact,
        &bytes,
        &artifact.profile.deployment_id,
        &artifact.profile.public_origin,
        &key,
        110,
    )
    .unwrap();
    artifact.signature.replace_range(..2, "00");
    assert!(verify_artifact(
        None,
        &artifact,
        &serde_json::to_vec(&artifact).unwrap(),
        &artifact.profile.deployment_id,
        &artifact.profile.public_origin,
        &key,
        110
    )
    .is_err());
}

#[test]
fn actual_dispatch_counter_is_retained_instead_of_a_caller_zero() {
    let (trace, output) = records();
    provider_capacity::record_dispatch();
    trace.finish::<()>(&Err(anyhow::anyhow!("actual loader error")));
    let rows = output.borrow();
    assert_eq!(
        rows[2]["event"]["after"]["dispatches"].as_u64().unwrap(),
        rows[0]["event"]["before"]["dispatches"].as_u64().unwrap() + 1
    );
}

#[test]
fn cancellation_and_failed_sink_cannot_emit_a_healthy_refusal() {
    let (trace, output) = records();
    drop(trace);
    assert_eq!(output.borrow()[1]["event"]["outcome"], "unknown");
    assert_eq!(output.borrow()[1]["event"]["healthy"], false);

    let trace = selected(Rc::new(|_| false));
    trace.finish::<()>(&Err(anyhow::anyhow!("actual loader error")));
    assert!(!trace.healthy.get());
}

#[test]
fn oversized_error_marks_coverage_incomplete_and_does_not_change_result() {
    let (trace, output) = records();
    let result: Result<()> = Err(anyhow::anyhow!("x".repeat(MAX_RECORD_BYTES)));
    trace.finish(&result);
    assert!(result.is_err());
    let rows = output.borrow();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["ordinal"], 3);
    assert_eq!(rows[1]["event"]["healthy"], false);
}
