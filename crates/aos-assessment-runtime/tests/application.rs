//! Closed application payloads and inventory-bound status continuation tests.

use anyhow::Result;
use aos_assessment_runtime::application::{AssessmentStatusV1, StatusQueryV1};
use aos_contract::Sha256Digest;
use serde_json::json;

fn query() -> serde_json::Value {
    json!({"schema":"aos.assessment-status-query/v1", "profiles":["updates","vulnerabilities"], "limit":100})
}

fn status() -> serde_json::Value {
    json!({
        "schema":"aos.assessment-status/v1", "resourceScope":"registry:00000000000000000000000000000001",
        "inventoryDigest":Sha256Digest::of_bytes("inventory"), "inventoryRevision":1, "policyDigest":Sha256Digest::of_bytes("policy"),
        "asOf":"2026-10-09T12:00:00Z", "subjects":[{
            "subjectRef":"subject", "packageCoordinate":"publisher/fixture", "version":"1.2.0", "platform":"x86_64-linux", "output":"source",
            "profiles":[{"profile":"updates", "desiredGeneration":0, "committedGeneration":0, "fresh":false, "pending":false}]
        }]
    })
}

#[test]
fn status_continuations_require_the_exact_inventory_and_decision_policy() -> Result<()> {
    let mut value = query();
    StatusQueryV1::from_slice(&serde_json::to_vec(&value)?)?;
    value["afterSubject"] = json!("subject");
    assert!(StatusQueryV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value["inventoryDigest"] = json!(Sha256Digest::of_bytes("inventory"));
    assert!(StatusQueryV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value["policyDigest"] = json!(Sha256Digest::of_bytes("policy"));
    StatusQueryV1::from_slice(&serde_json::to_vec(&value)?)?;
    value["profiles"] = json!(["updates", "updates"]);
    assert!(StatusQueryV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn status_round_trip_preserves_unassessed_members_without_inventing_freshness() -> Result<()> {
    let parsed = AssessmentStatusV1::from_slice(&serde_json::to_vec(&status())?)?;
    assert_eq!(parsed.subjects[0].version, "1.2.0");
    assert!(!parsed.subjects[0].profiles[0].fresh);
    assert!(parsed.subjects[0].profiles[0].assessment_digest.is_none());
    assert_eq!(AssessmentStatusV1::from_slice(&parsed.to_bytes()?)?, parsed);
    let mut value = status();
    value["subjects"][0]["profiles"][0]["fresh"] = json!(true);
    assert!(AssessmentStatusV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn source_status_is_optional_closed_and_sorted_independently_of_findings() -> Result<()> {
    let mut value = status();
    let original = AssessmentStatusV1::from_slice(&serde_json::to_vec(&value)?)?;
    assert!(original.source_status.is_empty());
    value["sourceStatus"] = json!([
        {"provider":"nvd", "availability":{"state":"unconfigured"}},
        {"provider":"osv", "availability":{"state":"waiting", "retryAt":"2026-10-09T12:01:00Z", "cause":"spacing-or-cooldown"}}
    ]);
    let projected = AssessmentStatusV1::from_slice(&serde_json::to_vec(&value)?)?;
    assert_eq!(projected.subjects, original.subjects);
    assert_eq!(projected.inventory_digest, original.inventory_digest);
    assert_eq!(AssessmentStatusV1::from_slice(&projected.to_bytes()?)?, projected);
    value["sourceStatus"][0]["availability"]["account"] = json!("private-account");
    assert!(AssessmentStatusV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value["sourceStatus"] = json!([
        {"provider":"osv", "availability":{"state":"eligible"}},
        {"provider":"nvd", "availability":{"state":"eligible"}}
    ]);
    assert!(AssessmentStatusV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value["sourceStatus"] = json!([
        {"provider":"osv", "availability":{"state":"eligible"}},
        {"provider":"osv", "availability":{"state":"eligible"}}
    ]);
    assert!(AssessmentStatusV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn status_deadlines_are_exclusive_and_terminal_generations_can_be_uncommitted() -> Result<()> {
    let mut value = status();
    let profile = &mut value["subjects"][0]["profiles"][0];
    profile["desiredGeneration"] = json!(2);
    profile["committedGeneration"] = json!(1);
    profile["pending"] = json!(true);
    profile["assessmentDigest"] = json!(Sha256Digest::of_bytes("assessment"));
    profile["inputDigest"] = json!(Sha256Digest::of_bytes("input"));
    profile["validatedUntil"] = json!("2026-10-09T12:00:00Z");
    AssessmentStatusV1::from_slice(&serde_json::to_vec(&value)?)?;
    value["subjects"][0]["profiles"][0]["fresh"] = json!(true);
    assert!(AssessmentStatusV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value["subjects"][0]["profiles"][0]["fresh"] = json!(false);
    value["subjects"][0]["profiles"][0]["pending"] = json!(false);
    AssessmentStatusV1::from_slice(&serde_json::to_vec(&value)?)?;
    value["subjects"][0]["profiles"][0]["desiredGeneration"] = json!(1);
    value["subjects"][0]["profiles"][0]["pending"] = json!(true);
    assert!(AssessmentStatusV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn status_payloads_reject_unknown_and_null_fields_before_display() -> Result<()> {
    let mut value = status();
    value["nextSubject"] = serde_json::Value::Null;
    assert!(AssessmentStatusV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value = status();
    value["sourceResponse"] = json!("unadmitted bytes");
    assert!(AssessmentStatusV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    value = status();
    value["nextSubject"] = json!("different-subject");
    assert!(AssessmentStatusV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}
