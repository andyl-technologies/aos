//! Live identity continuity across deployment namespaces and token rotation.

use super::*;

async fn fixture() -> (RpcService, crate::db::TokenAuth, String) {
    let (service, db) = cache_upload_tests::delivery_test_service().await;
    let user = db
        .user_by_email("writer@example.test")
        .await
        .unwrap()
        .unwrap();
    let (_, secret) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::IamAdmin],
            Some("identity continuity"),
            None,
        )
        .await
        .unwrap();
    let auth = db.validate_token(&secret).await.unwrap().unwrap();
    let bearer = format!("Bearer {}", service.jwt_keys.mint(&auth, 300).unwrap());
    (service, auth, bearer)
}

#[tokio::test]
async fn legacy_identity_has_no_invented_deployment_or_principal_commitment() {
    let (service, _, bearer) = fixture().await;
    let reply = service
        .who_am_i(Some(&bearer), pb::WhoAmIRequest {})
        .await
        .unwrap();

    assert!(reply.deployment_id.is_empty());
    assert!(reply.principal_id.is_empty());
    assert_eq!(reply.transfer_mode, "legacy");
}

#[tokio::test]
async fn current_identity_is_deployment_scoped_and_preserved_by_token_rotation() {
    let (service, auth, bearer) = fixture().await;
    let mut service = service
        .with_deployment_id(Some("deployment-one".into()))
        .unwrap();
    let before = service
        .who_am_i(Some(&bearer), pb::WhoAmIRequest {})
        .await
        .unwrap();
    assert_eq!(before.deployment_id, "deployment-one");
    assert_eq!(before.principal_id.len(), 64);

    let (_, secret) = service
        .db
        .rotate_token(&auth.token_id)
        .await
        .unwrap()
        .unwrap();
    let rotated = service.db.validate_token(&secret).await.unwrap().unwrap();
    let rotated_bearer = format!("Bearer {}", service.jwt_keys.mint(&rotated, 300).unwrap());
    let after = service
        .who_am_i(Some(&rotated_bearer), pb::WhoAmIRequest {})
        .await
        .unwrap();
    assert_eq!(after.principal_id, before.principal_id);
    // The existing rotation grace window remains authoritative. Both live
    // credentials resolve the same account incarnation during that window.
    let during_grace = service
        .who_am_i(Some(&bearer), pb::WhoAmIRequest {})
        .await
        .unwrap();
    assert_eq!(during_grace.principal_id, before.principal_id);

    service = service
        .with_deployment_id(Some("deployment-two".into()))
        .unwrap();
    let replaced = service
        .who_am_i(Some(&rotated_bearer), pb::WhoAmIRequest {})
        .await
        .unwrap();
    assert_ne!(replaced.principal_id, before.principal_id);
}

#[tokio::test]
async fn explicit_invalid_deployment_identity_is_refused() {
    let (service, _, _) = fixture().await;
    assert!(service.with_deployment_id(Some(String::new())).is_err());
}

#[tokio::test]
async fn direct_policy_requires_identity_without_claiming_provider_readiness() {
    let (service, _, bearer) = fixture().await;
    let service = service.with_hybrid_delivery();
    assert!(matches!(
        service.who_am_i(Some(&bearer), pb::WhoAmIRequest {}).await,
        Err(RpcError::FailedPrecondition(_))
    ));

    let configured = service
        .with_deployment_id(Some("deployment-one".into()))
        .unwrap();
    let reply = configured
        .who_am_i(Some(&bearer), pb::WhoAmIRequest {})
        .await
        .unwrap();
    assert_eq!(reply.transfer_mode, "direct_required");
    assert_eq!(reply.deployment_id, "deployment-one");
    assert_eq!(reply.principal_id.len(), 64);
}
