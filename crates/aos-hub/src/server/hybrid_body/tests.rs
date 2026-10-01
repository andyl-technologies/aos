//! Router-level proofs that refused hybrid upload requests never poll a body.

use super::*;
use aos_hub_core::hybrid_ingress::{body_sha256, HybridIngressKey, HYBRID_INGRESS_HEADER};
use axum::body::{Body, Bytes};
use axum::response::IntoResponse as _;
use axum::Router;
use std::sync::Arc;
use std::task::Poll;
use tower::ServiceExt as _;

fn assertion(
    method: Method,
    uri: &str,
    phase: Option<&str>,
    body: &[u8],
) -> HybridIngressAssertion {
    let now = aos_hub_core::clock::now_unix_secs();
    HybridIngressAssertion {
        version: 1,
        deployment_id: "guard-deployment".into(),
        issued_at: now,
        expires_at: now + 30,
        request_id: "guard-request".into(),
        scheme: "https".into(),
        authority: "guard.example.test".into(),
        method: method.to_string(),
        path_and_query: uri.into(),
        body_sha256: body_sha256(body),
        upload_phase: phase.map(str::to_owned),
        client_ip: "192.0.2.10".into(),
    }
}

fn never_poll_body() -> Body {
    Body::from_stream(futures_util::stream::poll_fn(
        |_| -> Poll<Option<Result<Bytes, std::io::Error>>> {
            panic!("rejected artifact body was polled")
        },
    ))
}

fn router(key: Arc<HybridIngressKey>, db: Option<Arc<Database>>) -> Router {
    Router::new()
        .fallback(|body: Bytes| async move {
            assert_eq!(body.as_ref(), b"{\"size\":0,\"sha256\":\"test\"}");
            StatusCode::NO_CONTENT.into_response()
        })
        .layer(axum::middleware::from_fn(move |request, next| {
            let key = Arc::clone(&key);
            let db = db.clone();
            async move {
                super::super::verify_hybrid_ingress(
                    key,
                    "guard-deployment".into(),
                    "https://guard.example.test".into(),
                    db,
                    request,
                    next,
                )
                .await
            }
        }))
}

#[tokio::test]
async fn rejected_artifact_routes_do_not_poll_actual_body() {
    let key = Arc::new(HybridIngressKey::new([31; 32]).unwrap());
    for (method, uri, phase) in [
        (
            Method::PUT,
            "/aos.hub.v1.BinaryCacheService/UploadObject/cache/ticket/path",
            None,
        ),
        (
            Method::PUT,
            "/aos.hub.v1.PublishService/UploadObject/publication/1",
            None,
        ),
        (
            Method::PUT,
            "/aos.hub.v1.PublishService/UploadPart/upload/1",
            Some("bytes"),
        ),
        (
            Method::POST,
            "/aos.hub.v1.RegistryService/ListRegistries",
            Some("complete"),
        ),
        (
            Method::PATCH,
            "/unknown/v2/repo/blobs/uploads/upload",
            Some("complete"),
        ),
        (Method::PUT, "/v2/repo/manifests/latest", None),
        (
            Method::PUT,
            "/aos.hub.v1.PublishService/UploadObject/publication/1?raw=1",
            Some("complete"),
        ),
        (
            Method::POST,
            "/aos.hub.v1.DirectUploadService/BeginBatch",
            Some("commit"),
        ),
    ] {
        let signed = assertion(method.clone(), uri, phase, &[]);
        let mut request = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header(HYBRID_INGRESS_HEADER, key.sign(&signed).unwrap());
        if let Some(phase) = phase {
            request = request.header(HYBRID_UPLOAD_PHASE_HEADER, phase);
        }

        let response = router(Arc::clone(&key), None)
            .oneshot(request.body(never_poll_body()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
    }
}

#[tokio::test]
async fn private_phase_is_authenticated_before_body_poll() {
    let key = Arc::new(HybridIngressKey::new([31; 32]).unwrap());
    let uri = "/aos.hub.v1.BinaryCacheService/UploadObject/cache/ticket/path";
    for (signed_phase, actual_phases) in [
        (None, vec!["admit"]),
        (Some("admit"), vec!["complete"]),
        (Some("admit"), vec!["admit", "admit"]),
        (Some("admit"), vec![]),
    ] {
        let signed = assertion(Method::PUT, uri, signed_phase, &[]);
        let mut request = axum::http::Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header(HYBRID_INGRESS_HEADER, key.sign(&signed).unwrap());
        for phase in actual_phases {
            request = request.header(HYBRID_UPLOAD_PHASE_HEADER, phase);
        }

        let response = router(Arc::clone(&key), None)
            .oneshot(request.body(never_poll_body()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn declared_over_cap_and_nonempty_preflight_never_poll() {
    let key = Arc::new(HybridIngressKey::new([31; 32]).unwrap());
    let uri = "/aos.hub.v1.BinaryCacheService/UploadPart/ticket/1";
    for (phase, declared, expected) in [
        ("complete", 4097, StatusCode::PAYLOAD_TOO_LARGE),
        ("preflight", 1, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let signed = assertion(Method::PUT, uri, Some(phase), &[]);
        let request = axum::http::Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header(HYBRID_INGRESS_HEADER, key.sign(&signed).unwrap())
            .header(HYBRID_UPLOAD_PHASE_HEADER, phase)
            .header(header::CONTENT_LENGTH, declared)
            .body(never_poll_body())
            .unwrap();

        let response = router(Arc::clone(&key), None)
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn body_commitment_rejects_nonempty_empty_phase_before_poll() {
    let key = Arc::new(HybridIngressKey::new([31; 32]).unwrap());
    let uri = "/aos.hub.v1.BinaryCacheService/UploadPart/ticket/1";
    let signed = assertion(Method::PUT, uri, Some("preflight"), b"artifact");
    let request = axum::http::Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header(HYBRID_INGRESS_HEADER, key.sign(&signed).unwrap())
        .header(HYBRID_UPLOAD_PHASE_HEADER, "preflight")
        .body(never_poll_body())
        .unwrap();

    let response = router(key, None).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unregistered_oci_prefix_does_not_gain_phase_body_admission() {
    let key = Arc::new(HybridIngressKey::new([31; 32]).unwrap());
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let uri = "/forged-prefix/v2/repo/blobs/uploads/upload";
    let signed = assertion(Method::PATCH, uri, Some("complete"), &[]);
    let request = axum::http::Request::builder()
        .method(Method::PATCH)
        .uri(uri)
        .header(HYBRID_INGRESS_HEADER, key.sign(&signed).unwrap())
        .header(HYBRID_UPLOAD_PHASE_HEADER, "complete")
        .body(never_poll_body())
        .unwrap();

    let response = router(key, Some(db)).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn compact_authenticated_metadata_reaches_body_handler() {
    let key = Arc::new(HybridIngressKey::new([31; 32]).unwrap());
    let uri = "/aos.hub.v1.BinaryCacheService/UploadObject/cache/ticket/path";
    let body = b"{\"size\":0,\"sha256\":\"test\"}";
    let signed = assertion(Method::PUT, uri, Some("complete"), body);
    let request = axum::http::Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header(HYBRID_INGRESS_HEADER, key.sign(&signed).unwrap())
        .header(HYBRID_UPLOAD_PHASE_HEADER, "complete")
        .body(Body::from(body.as_slice()))
        .unwrap();

    let response = router(key, None).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[test]
fn canonical_oci_path_and_manifest_query_select_exact_metadata_caps() {
    let chunk = aos_hub_core::oci::parse_oci_path("v2/repo/blobs/uploads/upload").unwrap();
    assert_eq!(
        oci_limit(&Method::PATCH, &chunk, None, Some("complete")),
        Ok(16 * 1024)
    );
    assert_eq!(
        oci_limit(&Method::PATCH, &chunk, Some("part=1"), Some("complete")),
        Err(StatusCode::BAD_REQUEST)
    );

    let manifest = aos_hub_core::oci::parse_oci_path("v2/repo/manifests/latest").unwrap();
    let query = "aos_hybrid_manifest_upload=0123456789abcdef0123456789abcdef";
    assert_eq!(
        oci_limit(&Method::PUT, &manifest, Some(query), Some("complete")),
        Ok(MANIFEST_CONTROL_BYTES)
    );
    assert_eq!(
        oci_limit(
            &Method::PUT,
            &manifest,
            Some(&format!("{query}&{query}")),
            Some("complete")
        ),
        Err(StatusCode::BAD_REQUEST)
    );
    assert_eq!(
        oci_limit(&Method::PUT, &manifest, None, Some("complete")),
        Err(StatusCode::BAD_REQUEST)
    );
}

#[tokio::test]
async fn wrong_signed_path_and_control_authority_reject_before_body_poll() {
    let key = Arc::new(HybridIngressKey::new([31; 32]).unwrap());
    let uri = "/aos.hub.v1.BinaryCacheService/UploadObject/cache/ticket/path";
    for (wrong_path, wrong_authority, expected) in [
        (true, false, StatusCode::UNAUTHORIZED),
        (false, true, StatusCode::MISDIRECTED_REQUEST),
    ] {
        let mut signed = assertion(Method::PUT, uri, Some("admit"), &[]);
        if wrong_path {
            signed.path_and_query.push_str("-another");
        }
        if wrong_authority {
            signed.authority = "other.example.test".into();
        }
        let request = axum::http::Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header(HYBRID_INGRESS_HEADER, key.sign(&signed).unwrap())
            .header(HYBRID_UPLOAD_PHASE_HEADER, "admit")
            .body(never_poll_body())
            .unwrap();

        let response = router(Arc::clone(&key), None)
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn invalid_mac_never_polls_control_body() {
    let key = Arc::new(HybridIngressKey::new([31; 32]).unwrap());
    let uri = "/aos.hub.v1.RegistryService/ListRegistries";
    let signed = assertion(Method::POST, uri, None, &[]);
    let wrong_key = HybridIngressKey::new([32; 32]).unwrap();
    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(HYBRID_INGRESS_HEADER, wrong_key.sign(&signed).unwrap())
        .body(never_poll_body())
        .unwrap();

    let response = router(key, None).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unrelated_rpc_put_and_patch_never_select_generic_body_cap() {
    let key = Arc::new(HybridIngressKey::new([31; 32]).unwrap());
    let uri = "/aos.hub.v1.RegistryService/ListRegistries";
    for method in [Method::PUT, Method::PATCH] {
        let signed = assertion(method.clone(), uri, None, &[]);
        let request = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header(HYBRID_INGRESS_HEADER, key.sign(&signed).unwrap())
            .body(never_poll_body())
            .unwrap();

        let response = router(Arc::clone(&key), None)
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}

#[tokio::test]
async fn legacy_raw_narinfo_rpc_and_misleading_phase_never_poll_body() {
    let key = Arc::new(HybridIngressKey::new([31; 32]).unwrap());
    for method in ["RegisterCacheNarinfos", "ReportCacheNarinfos"] {
        let uri = format!("/aos.hub.v1.BinaryCacheService/{method}");
        for phase in [None, Some("admit"), Some("complete")] {
            let signed = assertion(Method::POST, &uri, phase, b"raw narinfo hidden in JSON");
            let mut request = axum::http::Request::builder()
                .method(Method::POST)
                .uri(&uri)
                .header(HYBRID_INGRESS_HEADER, key.sign(&signed).unwrap());
            if let Some(phase) = phase {
                request = request.header(HYBRID_UPLOAD_PHASE_HEADER, phase);
            }
            let response = router(Arc::clone(&key), None)
                .oneshot(request.body(never_poll_body()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
    }
}

mod oci_completion;
