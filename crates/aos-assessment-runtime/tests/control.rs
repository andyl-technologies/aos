//! Authority injection, selector ambiguity and lifecycle document boundary tests.

use anyhow::Result;
use aos_assessment_runtime::control::{ScanCancellationV1, ScanSubmissionV1};
use aos_assessment_runtime::scan::ScanLimits;
use aos_contract::Sha256Digest;
use serde_json::{Value, json};

fn submission() -> Value {
    json!({
        "schema":"aos.assessment-scan-submission/v1", "inventoryRevision":1,
        "inventoryDigest":Sha256Digest::of_bytes("inventory"),
        "policyDigest":Sha256Digest::of_bytes("policy"), "subjects":["subject"],
        "profiles":["updates","vulnerabilities"], "freshness":"offline",
        "idempotencyKey":"request-1", "limits":ScanLimits::default()
    })
}

#[test]
fn authority_is_bound_by_the_host_and_cannot_be_injected_through_selection() -> Result<()> {
    let mut value = submission();
    let selection = ScanSubmissionV1::from_slice(&serde_json::to_vec(&value)?)?;
    let request = selection.bind("registry:one", "registry:one", "principal:one")?;
    assert_eq!(request.actor_ref, "principal:one");
    assert_eq!(request.authorization_partition, "registry:one");
    assert_ne!(
        request.digest()?,
        selection
            .bind("registry:two", "registry:two", "principal:one")?
            .digest()?
    );

    for name in [
        "actorRef",
        "authorizationPartition",
        "resourceScope",
        "trigger",
    ] {
        value[name] = json!("forged-authority");
        assert!(ScanSubmissionV1::from_slice(&serde_json::to_vec(&value)?).is_err());
        value.as_object_mut().unwrap().remove(name);
    }
    Ok(())
}

#[test]
fn empty_duplicate_unsorted_or_excessive_selection_never_means_scan_everything() -> Result<()> {
    for subjects in [json!([]), json!(["subject", "subject"]), json!(["z", "a"])] {
        let mut value = submission();
        value["subjects"] = subjects;
        assert!(ScanSubmissionV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    }
    let mut value = submission();
    value["limits"]["providerRequests"] = json!(4097);
    assert!(ScanSubmissionV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value = submission();
    value["profiles"] = json!(["vulnerabilities", "updates"]);
    assert!(ScanSubmissionV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn cancellations_require_a_portably_exact_nonzero_revision() -> Result<()> {
    let mut value = json!({"schema":"aos.assessment-scan-cancellation/v1", "scanId":"scan", "expectedRevision":1});
    ScanCancellationV1::from_slice(&serde_json::to_vec(&value)?)?;
    for revision in [
        json!(0),
        json!(9_007_199_254_740_992_u64),
        json!(1.5),
        Value::Null,
    ] {
        value["expectedRevision"] = revision;
        assert!(ScanCancellationV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    }
    Ok(())
}
