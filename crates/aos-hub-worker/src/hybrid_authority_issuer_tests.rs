//! Conservative metadata request deadlines without provider or runtime effects.

use super::*;
use aos_hub_core::storage_authority::lease::LeaseInteger;

fn request() -> IssuerRequest {
    serde_json::from_value(serde_json::json!({
        "protocol_version": 1,
        "installation": {
            "format_version": 1,
            "authority": {
                "authority_id": "11111111-1111-4111-8111-111111111111",
                "guard_namespace_id": "test-namespace",
                "physical_resource_evidence_digest": "a".repeat(64),
                "qualification_digest": "b".repeat(64),
                "qualified_managed_prefix": "managed"
            },
            "issuer_resource_id": "test-resource",
            "runtime_identity": "test-issuer",
            "executor_identity": "test-executor"
        },
        "nonce": "c".repeat(64),
        "issued_at": "100",
        "expires_at": "130",
        "operation": { "kind": "current" }
    }))
    .unwrap()
}

#[test]
fn request_deadline_uses_exclusive_conservative_latest_bound() {
    let request = request();

    validate_request_deadline(
        &request,
        LeaseClock {
            observed_at: 128,
            uncertainty: 1,
        },
    )
    .unwrap();

    assert!(validate_request_deadline(
        &request,
        LeaseClock {
            observed_at: 129,
            uncertainty: 1,
        },
    )
    .is_err());
    assert!(validate_request_deadline(
        &request,
        LeaseClock {
            observed_at: 99,
            uncertainty: 1,
        },
    )
    .is_err());
}

#[test]
fn request_deadline_rejects_uncertainty_and_checked_time_overflow() {
    let mut request = request();
    assert!(validate_request_deadline(
        &request,
        LeaseClock {
            observed_at: 100,
            uncertainty: -1,
        },
    )
    .is_err());

    request.issued_at = LeaseInteger::new(i64::MAX - 30).unwrap();
    request.expires_at = LeaseInteger::new(i64::MAX).unwrap();
    assert!(validate_request_deadline(
        &request,
        LeaseClock {
            observed_at: i64::MAX - 1,
            uncertainty: 2,
        },
    )
    .is_err());
}
