//! Tenancy regression cases and contract checks.

use super::*;

#[test]
fn signing_usage_rejects_cross_organization_key_ownership() {
    let key = crate::db::SigningKeyRecord {
        stable_id: "signing-key:one".into(),
        scope_key: "org:11111111111111111111111111111111".into(),
        name: "release".into(),
        resource_version: 1,
        generation: 1,
        algorithm: "ed25519".into(),
        public_key: "AQ".into(),
        public_key_fingerprint: "fingerprint".into(),
        custody: "external".into(),
        state: "active".into(),
        generation_created_at: 1,
        created_at: 1,
        updated_at: 1,
        retired_at: None,
    };
    let consumer = crate::db::SigningKeyConsumerRecord {
        stable_id: "registry:33333333333333333333333333333333".into(),
        kind: "registry".into(),
        scope_key: "registry:33333333333333333333333333333333".into(),
        owner_scope_key: "org:22222222222222222222222222222222".into(),
        name: None,
    };
    assert!(matches!(
        validate_signing_key_consumer_compatibility(&key, &consumer),
        Err(RpcError::PermissionDenied(_))
    ));
}
