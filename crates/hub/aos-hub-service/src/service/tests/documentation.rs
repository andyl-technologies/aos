//! Documentation regression cases and contract checks.

use super::*;

#[tokio::test]
async fn package_ability_reference_authorizes_before_lookup() {
    let (service, db, _lease, underprivileged_auth) = injected_service(vec![], vec![]).await;
    let org_id = db.create_org("ability-auth", "Ability auth").await.unwrap();
    db.create_managed_registry(org_id, "", "packages", "private", &[], true)
        .await
        .unwrap();
    let request = pb::GetPackageAbilityReferenceRequest {
        registry: "ability-auth/packages".into(),
        package: "missing".into(),
        version: String::new(),
        platform: String::new(),
        release: String::new(),
    };

    assert!(matches!(
        service
            .get_package_ability_reference(None, request.clone())
            .await,
        Err(RpcError::Unauthenticated(_))
    ));
    assert!(matches!(
        service
            .get_package_ability_reference(Some(&underprivileged_auth), request)
            .await,
        Err(RpcError::PermissionDenied(_))
    ));
}
