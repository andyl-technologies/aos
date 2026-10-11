//! Provider freshness and provenance admission regression tests.

use anyhow::Result;
use aos_assessment::observation::{PROVIDER_OBSERVATION_V1, ProviderObservationV1};
use aos_assessment::time::Timestamp;
use aos_contract::Sha256Digest;
use serde_json::json;

fn observation() -> serde_json::Value {
    let raw = Sha256Digest::of_bytes("raw response");
    json!({
        "schema": PROVIDER_OBSERVATION_V1,
        "provider":"osv", "project":"example", "adapterVersion":"osv/v1",
        "requestIdentityDigest":Sha256Digest::of_bytes("request"),
        "retrievedAt":"2026-10-09T12:00:00Z",
        "validatedAt":"2026-10-09T13:00:00Z",
        "expiresAt":"2026-10-10T13:00:00Z",
        "responseDigest":raw, "payloadDigest":Sha256Digest::of_bytes("normalized"),
        "coverage":{"state":"complete", "proof":"pagination-exhausted"},
        "sourceRefs":[{"digest":raw,"byteLength":12,"origin":"osv"}]
    })
}

#[test]
fn freshness_is_explicit_and_revalidation_preserves_original_acquisition() -> Result<()> {
    let value = observation();
    let first = ProviderObservationV1::from_slice(&serde_json::to_vec(&value)?)?;
    assert!(first.is_fresh_at(&Timestamp::parse("2026-10-09T14:00:00Z")?)?);
    assert!(!first.is_fresh_at(&first.expires_at)?);
    assert!(
        first
            .is_fresh_at(&Timestamp::parse("2026-10-09T12:00:00Z")?)
            .is_err()
    );

    let mut revalidated = value;
    revalidated["validatedAt"] = json!("2026-10-09T14:00:00Z");
    let second = ProviderObservationV1::from_slice(&serde_json::to_vec(&revalidated)?)?;
    assert_eq!(first.retrieved_at, second.retrieved_at);
    assert_eq!(first.response_digest, second.response_digest);
    assert_ne!(first.digest()?, second.digest()?);
    Ok(())
}

#[test]
fn incomplete_answers_and_unverified_boundaries_never_claim_complete() -> Result<()> {
    for coverage in [
        json!({"state":"partial", "reason":"page-budget-exhausted"}),
        json!({"state":"through-boundary", "identity":"v1.0", "proof":"current-version-found"}),
        json!({"state":"unknown", "reason":"provider-unavailable"}),
    ] {
        let mut value = observation();
        value["coverage"] = coverage;
        let parsed = ProviderObservationV1::from_slice(&serde_json::to_vec(&value)?)?;
        assert!(!parsed.coverage.is_complete());
    }
    Ok(())
}

#[test]
fn forged_times_missing_response_and_unsafe_origins_are_rejected() -> Result<()> {
    for (field, replacement) in [
        ("expiresAt", json!("2026-10-09T11:00:00Z")),
        ("sourceRefs", json!([])),
        ("validators", serde_json::Value::Null),
        ("responseDigest", json!(Sha256Digest::of_bytes("missing"))),
    ] {
        let mut value = observation();
        value[field] = replacement;
        assert!(ProviderObservationV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    }
    let mut value = observation();
    value["sourceRefs"][0]["origin"] = json!("https://token@example.invalid");
    assert!(ProviderObservationV1::from_slice(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}
