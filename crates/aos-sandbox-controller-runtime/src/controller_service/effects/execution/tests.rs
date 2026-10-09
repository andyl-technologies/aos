//! Original regression fixture for the retained Delete effect refusal.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture construction and regression assertions intentionally panic."
)]

use super::*;
use buffa::Message as _;

#[test]
fn retained_public_delete_effect_is_permanently_blocked() {
    let request = aos_proto::aos::sandbox::v1::DeleteSandboxRequest {
        sandbox_id: vec![0x11; 16],
        expected_plan_digest: vec![0x22; 32],
        mutation: Some(aos_proto::aos::sandbox::v1::MutationContext {
            idempotency_key: vec![0x33; 16],
            expected_resource_version: vec![0x44; 32],
            operation_timeout: Some(aos_proto::aos::sandbox::v1::Duration {
                nanoseconds: 1,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    };
    let envelope = aos_sandbox::cli_model::PublicMutationRequestV1::new(
        aos_sandbox::cli_model::PublicApiAuditMethodV1::DeleteSandbox,
        &request.encode_to_vec(),
    )
    .unwrap()
    .encode();
    let effect = EffectPlan::authorized_public_mutation(
        aos_sandbox_protocol::public_api::PublicOperationMethodV1::DeleteSandbox,
        PublicMutationEffectV1::new(
            aos_sandbox_core::PrincipalId::from_bytes([0x55; 16]),
            aos_sandbox_core::ProjectId::from_bytes([0x66; 16]),
            1,
            envelope,
        )
        .unwrap(),
    )
    .unwrap();

    assert!(matches!(
        reject_unqualified_delete_effect(&effect),
        Err(EffectFailure::Permanent(_))
    ));
}
