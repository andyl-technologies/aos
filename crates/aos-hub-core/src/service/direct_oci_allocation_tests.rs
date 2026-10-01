//! Actual core handler/SQLite allocation and signed owner-pin regressions.

use super::*;
use crate::auth::jwt::{OciRepositoryGrant, OciTokenGrant};
use crate::oci::parse_start_query;
use aos_oci_types::{RepositoryName, Sha256Digest};
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};

macro_rules! sql_values {
    ($($value:expr),* $(,)?) => {
        vec![$(crate::value::ToValue::to_value(&$value)),*]
    };
}

struct Fixture {
    service: Arc<RpcService>,
    registry: crate::db::RegistryRecord,
    repository: crate::db::OciRepositoryRecord,
    auth: crate::db::TokenAuth,
}

async fn fixture() -> Fixture {
    let (service, db) = cache_upload_tests::delivery_test_service().await;
    let service = service
        .with_hybrid_delivery()
        .with_deployment_id(Some("deployment-one".into()))
        .unwrap();
    let user = db
        .user_by_email("writer@example.test")
        .await
        .unwrap()
        .unwrap();
    db.grant_membership("user", user, "instance", "owner")
        .await
        .unwrap();
    let (_, secret) = db
        .create_token(
            Principal::user(user),
            "instance",
            &[Permission::Publish],
            None,
            None,
        )
        .await
        .unwrap();
    let auth = db.validate_token(&secret).await.unwrap().unwrap();
    let org = db
        .create_org("allocation-handler", "Allocation")
        .await
        .unwrap();
    let registry = db
        .create_managed_registry(org, "", "images", "private", &[], false)
        .await
        .unwrap();
    let repository = db
        .ensure_oci_repository(
            registry,
            &RepositoryName::parse("team/image").unwrap(),
            clock::now_unix_secs(),
        )
        .await
        .unwrap();
    let registry = db.registry_by_id(registry).await.unwrap().unwrap();
    Fixture {
        service: Arc::new(service),
        registry,
        repository,
        auth,
    }
}

fn headers(fixture: &Fixture, pins: bool) -> HeaderMap {
    headers_for(fixture, pins, &fixture.repository.name)
}

fn headers_for(fixture: &Fixture, pins: bool, repository: &RepositoryName) -> HeaderMap {
    let grant = OciTokenGrant {
        subject: format!("token:{}", fixture.auth.token_id),
        owner_kind: pins.then(|| fixture.auth.owner.kind.as_str().to_owned()),
        owner_incarnation: if pins {
            fixture.auth.owner_incarnation.clone()
        } else {
            None
        },
        authority: "registry.example.test".into(),
        registry_stable_id: fixture.registry.stable_id.clone(),
        grants: vec![OciRepositoryGrant {
            repository: repository.clone(),
            actions: vec!["push".into()],
        }],
    };
    let bearer = fixture.service.jwt_keys.mint_oci(&grant, 300).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {bearer}")).unwrap(),
    );
    headers
}

fn query(operation: char) -> String {
    format!(
        "digest={}&size=16&aos_operation_id={}",
        Sha256Digest::digest(b"immutable source"),
        operation.to_string().repeat(64),
    )
}

fn panic_body() -> Body {
    Body::from_stream(futures_util::stream::poll_fn(
        |_| -> std::task::Poll<Option<Result<axum::body::Bytes, std::io::Error>>> {
            panic!("invalid direct metadata request polled its body")
        },
    ))
}

#[tokio::test]
async fn exact_metadata_allocation_reply_loss_and_rotation_return_original_upload() {
    let mut fixture = fixture().await;
    let original_headers = headers(&fixture, true);
    let original_query = query('1');
    let response = fixture
        .service
        .begin_direct_blob_upload(
            &fixture.registry,
            &fixture.repository,
            "registry.example.test",
            &original_headers,
            parse_start_query(&original_query).unwrap(),
            Body::empty(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let original_id = response
        .headers()
        .get("docker-upload-uuid")
        .unwrap()
        .clone();
    drop(response);

    let (_, secret) = fixture
        .service
        .db
        .rotate_token(&fixture.auth.token_id)
        .await
        .unwrap()
        .unwrap();
    fixture.auth = fixture
        .service
        .db
        .validate_token(&secret)
        .await
        .unwrap()
        .unwrap();
    let replay = fixture
        .service
        .begin_direct_blob_upload(
            &fixture.registry,
            &fixture.repository,
            "registry.example.test",
            &headers(&fixture, true),
            parse_start_query(&original_query).unwrap(),
            Body::empty(),
        )
        .await;
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(
        replay.headers().get("docker-upload-uuid"),
        Some(&original_id)
    );
    let location = replay
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with("/v2/team/image/blobs/uploads/"));
}

#[tokio::test]
async fn legacy_oci_grant_without_original_owner_pin_refuses_before_body() {
    let fixture = fixture().await;
    let response = fixture
        .service
        .begin_direct_blob_upload(
            &fixture.registry,
            &fixture.repository,
            "registry.example.test",
            &headers(&fixture, false),
            parse_start_query(&query('2')).unwrap(),
            panic_body(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn changed_owner_pin_and_kind_cannot_reuse_original_signed_oci_subject() {
    let fixture = fixture().await;
    let original_headers = headers(&fixture, true);
    let human = fixture
        .service
        .db
        .create_user("replacement@example.test", None)
        .await
        .unwrap();
    let org = fixture
        .service
        .db
        .create_org("replacement", "Replacement")
        .await
        .unwrap();
    let account = fixture
        .service
        .db
        .create_service_account(org, "replacement")
        .await
        .unwrap();

    for replacement in [Principal::user(human), Principal::service_account(account)] {
        fixture
            .service
            .db
            .grant_membership(
                replacement.kind.as_str(),
                replacement.id,
                "instance",
                "owner",
            )
            .await
            .unwrap();
        let incarnation = fixture
            .service
            .db
            .principal_incarnation(replacement)
            .await
            .unwrap()
            .unwrap();
        fixture.service.db.backend.execute(
            "UPDATE tokens SET owner_kind = ?2, owner_id = ?3, owner_incarnation = ?4 WHERE id = ?1",
            &sql_values![fixture.auth.token_id, replacement.kind.as_str(), replacement.id, incarnation],
        ).await.unwrap();

        // The reused token row genuinely authenticates its replacement owner.
        // The original signed OCI grant must still refuse that new authority.
        let current = fixture
            .service
            .db
            .current_token_authority(&fixture.auth.token_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.owner, replacement);
        assert!(current.permissions.contains(&Permission::Publish));
        let response = fixture
            .service
            .begin_direct_blob_upload(
                &fixture.registry,
                &fixture.repository,
                "registry.example.test",
                &original_headers,
                parse_start_query(&query('3')).unwrap(),
                panic_body(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn wrong_actual_authority_and_missing_operation_refuse_before_body() {
    let fixture = fixture().await;
    let response = fixture
        .service
        .begin_direct_blob_upload(
            &fixture.registry,
            &fixture.repository,
            "another-registry.example.test",
            &headers(&fixture, true),
            parse_start_query(&query('4')).unwrap(),
            panic_body(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let query = format!(
        "digest={}&size=16",
        Sha256Digest::digest(b"immutable source")
    );
    let response = fixture
        .service
        .begin_direct_blob_upload(
            &fixture.registry,
            &fixture.repository,
            "registry.example.test",
            &headers(&fixture, true),
            parse_start_query(&query).unwrap(),
            panic_body(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn operation_query_is_singleton_canonical_and_covered_by_original_uri() {
    assert!(parse_start_query(&query('a')).is_ok());
    for invalid in [
        format!("{}&aos_operation_id={}", query('a'), "a".repeat(64)),
        query('A'),
        query('a').replace("aos_operation_id=", "%61os_operation_id="),
        query('a').replace("size=16", "size=016"),
        query('a').replace("aos_operation_id=a", "aos_operation_id=%61"),
    ] {
        assert!(parse_start_query(&invalid).is_err());
    }
}

fn initial_route(fixture: &Fixture, repository: &RepositoryName) -> crate::oci::ResolvedOciRoute {
    crate::oci::ResolvedOciRoute {
        registry_id: fixture.registry.id,
        authority: "registry.example.test".into(),
        scheme: "https".into(),
        access_policy_kind: "hub_auth".into(),
        request: crate::oci::OciRequest::BlobUploadCollection {
            repository: repository.clone(),
        },
    }
}

#[tokio::test]
async fn actual_outer_initial_denials_do_not_poll_or_create_repository() {
    for case in ["legacy", "missing_operation", "revoked", "wrong_domain"] {
        let fixture = fixture().await;
        let name = RepositoryName::parse("fresh/image").unwrap();
        let mut authorization = headers_for(&fixture, case != "legacy", &name);
        if case == "revoked" {
            fixture
                .service
                .db
                .revoke_token(&fixture.auth.token_id)
                .await
                .unwrap();
        }
        if case == "wrong_domain" {
            let token = fixture.service.jwt_keys.mint(&fixture.auth, 300).unwrap();
            authorization.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            );
        }
        let original_query = if case == "missing_operation" {
            format!(
                "digest={}&size=16",
                Sha256Digest::digest(b"immutable source")
            )
        } else {
            query('5')
        };

        let response = fixture
            .service
            .clone()
            .serve_oci(
                initial_route(&fixture, &name),
                axum::http::Method::POST,
                authorization,
                Some(&original_query),
                panic_body(),
            )
            .await;
        assert!(response.status().is_client_error(), "{case}");
        assert!(
            fixture
                .service
                .db
                .oci_repository(fixture.registry.id, &name)
                .await
                .unwrap()
                .is_none(),
            "{case}"
        );
        let count = fixture
            .service
            .db
            .backend
            .query_opt("SELECT COUNT(*) FROM direct_oci_allocations", &[])
            .await
            .unwrap()
            .unwrap()
            .get::<i64>(0)
            .unwrap();
        assert_eq!(count, 0, "{case}");
    }
}

#[tokio::test]
async fn actual_outer_empty_initial_control_creates_and_replays_one_original_owner() {
    let fixture = fixture().await;
    let name = RepositoryName::parse("fresh/image").unwrap();
    let authorization = headers_for(&fixture, true, &name);
    let original_query = query('6');
    let response = fixture
        .service
        .clone()
        .serve_oci(
            initial_route(&fixture, &name),
            axum::http::Method::POST,
            authorization.clone(),
            Some(&original_query),
            Body::empty(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let original = response
        .headers()
        .get("docker-upload-uuid")
        .unwrap()
        .clone();
    assert!(fixture
        .service
        .db
        .oci_repository(fixture.registry.id, &name)
        .await
        .unwrap()
        .is_some());
    drop(response);

    let replay = fixture
        .service
        .clone()
        .serve_oci(
            initial_route(&fixture, &name),
            axum::http::Method::POST,
            authorization,
            Some(&original_query),
            Body::empty(),
        )
        .await;
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(replay.headers().get("docker-upload-uuid"), Some(&original));
}

#[tokio::test]
async fn held_empty_outer_body_iam_revocation_prevents_first_catalog_and_allocation_write() {
    let fixture = fixture().await;
    let name = RepositoryName::parse("fresh/image").unwrap();
    let authorization = headers_for(&fixture, true, &name);
    let original_query = query('7');
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, continue_body) = tokio::sync::oneshot::channel();
    let stream = futures_util::stream::once(async move {
        entered.send(()).unwrap();
        continue_body.await.unwrap();
        Ok::<_, std::io::Error>(axum::body::Bytes::new())
    });
    let body = Body::from_stream(stream);
    let service = fixture.service.clone();
    let route = initial_route(&fixture, &name);
    let pending = tokio::spawn(async move {
        service
            .serve_oci(
                route,
                axum::http::Method::POST,
                authorization,
                Some(&original_query),
                body,
            )
            .await
    });
    observed.await.unwrap();
    // The token and account remain live; only current publishing IAM is removed.
    fixture
        .service
        .db
        .backend
        .execute(
            "DELETE FROM memberships WHERE principal_kind = 'user' AND principal_id = ?1",
            &sql_values![fixture.auth.owner.id],
        )
        .await
        .unwrap();
    // The usable-authority loader filters removed grants. Check retained
    // credential/account lifecycle directly to isolate the IAM change.
    let retained = fixture
        .service
        .db
        .backend
        .query_opt(
            "SELECT token.id FROM tokens token JOIN users actor ON actor.id = token.owner_id
         WHERE token.id = ?1 AND token.owner_kind = 'user' AND token.owner_id = ?2
           AND token.owner_incarnation = ?3 AND actor.principal_incarnation = ?3
           AND actor.deleted_at IS NULL AND token.revoked_at IS NULL
           AND token.rotated_at IS NULL
           AND (token.expires_at IS NULL OR token.expires_at > ?4)",
            &sql_values![
                fixture.auth.token_id.as_str(),
                fixture.auth.owner.id,
                fixture.auth.owner_incarnation.as_deref().unwrap(),
                clock::now_unix_secs()
            ],
        )
        .await
        .unwrap();
    assert!(retained.is_some());
    release.send(()).unwrap();

    let response = pending.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(fixture
        .service
        .db
        .oci_repository(fixture.registry.id, &name)
        .await
        .unwrap()
        .is_none());
    for table in [
        "direct_oci_allocations",
        "oci_upload_sessions",
        "oci_quota_reservations",
    ] {
        let count = fixture
            .service
            .db
            .backend
            .query_opt(&format!("SELECT COUNT(*) FROM {table}"), &[])
            .await
            .unwrap()
            .unwrap()
            .get::<i64>(0)
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
}

mod held_ensure;
