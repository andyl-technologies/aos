//! Registries regression cases and contract checks.

use super::*;

#[tokio::test]
async fn package_tooling_schema_authorizes_before_lookup() {
    let (service, db, _lease, underprivileged_auth) = injected_service(vec![], vec![]).await;
    let org_id = db.create_org("tooling-auth", "Tooling auth").await.unwrap();
    db.create_managed_registry(org_id, "", "packages", "private", &[], true)
        .await
        .unwrap();
    let request = pb::GetPackageDocumentationSchemaRequest {
        registry: "tooling-auth/packages".into(),
        package: "missing".into(),
        version: String::new(),
        platform: String::new(),
        release: String::new(),
    };

    assert!(matches!(
        service
            .get_package_documentation_schema(None, request.clone())
            .await,
        Err(RpcError::Unauthenticated(_))
    ));
    assert!(matches!(
        service
            .get_package_documentation_schema(Some(&underprivileged_auth), request)
            .await,
        Err(RpcError::PermissionDenied(_))
    ));
}

#[tokio::test]
async fn registry_trust_update_refreshes_the_signed_index() {
    let reindex_calls = Arc::new(AtomicUsize::new(0));
    let (service, db, _lease, auth) =
        injected_service_with_reindexer(Arc::new(InjectedReindexer {
            calls: Some(Arc::clone(&reindex_calls)),
        }))
        .await;
    let org_id = db
        .create_org("trust-refresh", "Trust refresh")
        .await
        .unwrap();
    db.create_managed_registry(org_id, "", "packages", "public", &[], true)
        .await
        .unwrap();
    let registry = db
        .registry_by_slug("trust-refresh/packages")
        .await
        .unwrap()
        .unwrap();
    let trust_key =
        "test:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIEtMspYqYtUjGxOcRGRwn4WVoEYXgbIV+4crzbmtYAXy";

    let planned = service
        .plan_update_registry(
            Some(&auth),
            pb::PlanUpdateRegistryRequest {
                slug: registry.slug,
                trust_keys: vec![trust_key.into()],
                update_mask: vec!["trust_keys".into()],
                expected_resource_version: registry.resource_version.to_string(),
                idempotency_key: "plan-trust-refresh".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .plan
        .unwrap();
    let response = service
        .apply_update_registry(
            Some(&auth),
            pb::ApplyRegistryMutationRequest {
                plan_id: planned.plan_id,
                idempotency_key: "apply-trust-refresh".into(),
                confirmation_hash: planned.confirmation_hash,
            },
        )
        .await
        .unwrap();

    assert_eq!(reindex_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        response.registry.unwrap().trust_keys,
        vec![trust_key.to_string()]
    );
}

#[tokio::test]
async fn git_log_is_empty_before_the_first_indexed_commit() {
    let (service, db, _lease, _auth) = injected_service(vec![], vec![]).await;
    let org_id = db.create_org("empty-log", "Empty log").await.unwrap();
    db.create_managed_registry(org_id, "", "packages", "public", &[], false)
        .await
        .unwrap();

    let response = service
        .git_log(
            None,
            pb::GitLogRequest {
                slug: "empty-log/packages".into(),
                page_size: 100,
                page_token: String::new(),
            },
        )
        .await
        .unwrap();

    assert!(response.commits.is_empty());
    assert!(response.next_page_token.is_empty());

    let error = service
        .git_log(
            None,
            pb::GitLogRequest {
                slug: "empty-log/packages".into(),
                page_size: 100,
                page_token: "not-a-page-token".into(),
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), "invalid_argument");
}
