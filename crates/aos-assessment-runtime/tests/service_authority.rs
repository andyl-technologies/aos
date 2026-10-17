//! Service review input and secret-free receipt contract qualification.

use anyhow::Result;
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::service_authority::{
    ServiceAuthorityV1, validate_service_credential_id,
};
use aos_contract::Sha256Digest;

#[test]
fn service_credential_identity_refuses_aliases_secrets_and_other_uuid_kinds() -> Result<()> {
    let original = "af738afb-8b2f-4b58-a835-c20b7f6b2d51";
    validate_service_credential_id(original)?;
    for invalid in [
        original.to_uppercase(),
        original.replace('-', ""),
        original.replacen("4b58", "1b58", 1),
        original.replacen("a835", "c835", 1),
        format!(" {original}"),
        "credential-secret".into(),
    ] {
        assert!(validate_service_credential_id(&invalid).is_err());
    }
    Ok(())
}

#[test]
fn receipt_is_closed_descriptive_and_bound_to_a_finite_deadline() -> Result<()> {
    let receipt = ServiceAuthorityV1 {
        schema: "aos.assessment-service-authority/v1".into(),
        actor_ref: Sha256Digest::of_bytes("service principal"),
        credential_ref: Sha256Digest::of_bytes("credential generation"),
        reviewer_ref: Sha256Digest::of_bytes("reviewing principal"),
        expires_at: Timestamp::parse("2026-10-11T00:00:00Z")?,
    };
    assert_eq!(
        ServiceAuthorityV1::from_slice(&receipt.to_bytes()?)?,
        receipt
    );
    for key in ["claims", "credentialId", "secret", "scope", "permissions"] {
        let mut injected = serde_json::to_value(&receipt)?;
        injected[key] = serde_json::json!("injected");
        assert!(ServiceAuthorityV1::from_slice(&serde_json::to_vec(&injected)?).is_err());
    }
    Ok(())
}
