//! Actual signed Native ingress and current IAM for External OCI allocation.
//!
//! This gate uses no provider, Worker artifact or candidate acceptance. It
//! checks only genuine empty-body Distribution allocation and quota authority.

use super::*;
use aos_hub_core::hybrid_ingress::{
    HYBRID_INGRESS_HEADER, HybridIngressAssertion, HybridIngressKey, body_sha256,
};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use tower::ServiceExt as _;

#[tokio::test]
async fn external_initial_distribution_allocation_checks_actor_without_direct_session_or_provider()
{
    let (db, placement) = fixture().await;
    route::install(&db, &placement, 443).await;
    let mut state =
        crate::server::AppState::new(db.clone(), "https://native.fixture.test".into()).await;
    state.deployment_id = Some("fixture-deployment".into());
    let user = db
        .create_user("oci-allocation@example.test", None)
        .await
        .unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let (token, _) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::Publish],
            None,
            None,
        )
        .await
        .unwrap();
    let auth = db.current_token_authority(&token).await.unwrap().unwrap();
    let registry = db
        .registry_by_id(placement.registry_id.unwrap())
        .await
        .unwrap()
        .unwrap();
    let authorization = state
        .auth
        .jwt_keys
        .mint_oci(
            &OciTokenGrant {
                subject: format!("token:{token}"),
                owner_kind: Some("user".into()),
                owner_incarnation: auth.owner_incarnation,
                authority: "s3.fleet.test".into(),
                registry_stable_id: registry.stable_id,
                grants: vec![OciRepositoryGrant {
                    repository: aos_oci_types::RepositoryName::parse("aos").unwrap(),
                    actions: vec!["pull".into(), "push".into()],
                }],
            },
            600,
        )
        .unwrap();
    let key = Arc::new(HybridIngressKey::new(INGRESS).unwrap());
    // Any attempted control hop is a concrete error: this endpoint is not a
    // Worker emulator and the fixture supplies no provider or Direct authority.
    let work = Arc::new(
        RemoteStorageWorkClient::new(
            "https://unavailable.fixture.test",
            "fixture-deployment".into(),
            configuration::APPLICATION.as_bytes(),
        )
        .unwrap(),
    );
    let router = crate::server::router_with_hybrid_ingress(
        Arc::new(state),
        key.clone(),
        "fixture-deployment".into(),
        work,
    )
    .await;
    let request = || {
        let now = aos_hub_core::clock::now_unix_secs();
        let assertion = HybridIngressAssertion {
            version: 1,
            deployment_id: "fixture-deployment".into(),
            issued_at: now,
            expires_at: now + 30,
            request_id: uuid::Uuid::new_v4().simple().to_string(),
            scheme: "https".into(),
            authority: "s3.fleet.test".into(),
            method: "POST".into(),
            path_and_query: "/v2/aos/blobs/uploads/?size=16".into(),
            body_sha256: body_sha256(b""),
            upload_phase: None,
            client_ip: "192.0.2.1".into(),
        };
        Request::builder()
            .method(Method::POST)
            .uri(&assertion.path_and_query)
            .header(HYBRID_INGRESS_HEADER, key.sign(&assertion).unwrap())
            .header("authorization", format!("Bearer {authorization}"))
            .header("host", "native.fixture.test")
            .body(Body::empty())
            .unwrap()
    };
    let response = router.clone().oneshot(request()).await.unwrap();
    let status = response.status();
    let location = response.headers().get("location").cloned();
    let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let upload_id = location
        .unwrap()
        .to_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let owner = format!("token:{token}");
    let upload = db
        .oci_upload(
            &upload_id,
            &owner,
            &owner,
            aos_hub_core::clock::now_unix_secs(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(upload.expected_size, Some(16));
    assert_eq!(upload.uploaded_size, 0);
    assert_eq!(upload.state, "active");
    assert_eq!(upload.staging_placement_id, None);

    db.revoke_token(&token).await.unwrap();
    let refused = router.oneshot(request()).await.unwrap();
    assert!(matches!(
        refused.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ));
    assert_eq!(
        db.oci_upload(
            &upload_id,
            &owner,
            &owner,
            aos_hub_core::clock::now_unix_secs()
        )
        .await
        .unwrap()
        .unwrap(),
        upload
    );
}
