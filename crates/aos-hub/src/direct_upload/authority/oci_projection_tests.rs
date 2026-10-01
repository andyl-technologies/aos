//! Exact independent OCI metadata admission over real Native SQL and TLS.

use std::sync::atomic::{AtomicUsize, Ordering};

use aos_hub_core::{
    backend::SqlxBackend,
    db::NewSurfacePlacementSpec,
    fetch::SurfaceProvider as _,
    oci_projection::{guard::*, OciDocumentProjection, MAX_OCI_PROJECTION_BYTES},
    storage_work::StorageObjectIdentity,
};
use aos_oci_types::{Annotations, Descriptor, MediaType, Sha256Digest};
use axum::{body::Bytes, http::HeaderMap, routing::post, Router};

use super::*;

#[tokio::test]
async fn managed_oci_projection_tls_bounds_mac_and_current_sql_without_body_fallback() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("https://localhost:{}", address.port());
    let current = current_time().unwrap();
    let (accepted, profile) = acceptance::tests::managed_fixture(&origin, current, current + 600);
    let uncertainty = match profile {
        DirectProtectedProfile::Managed { profile, .. } => profile.clock_uncertainty_seconds.get(),
        _ => panic!("managed fixture required"),
    };
    let guard = StorageWorkKey::new([17; 32]).unwrap();
    let backend = SqlxBackend::connect_sqlite(":memory:").await.unwrap();
    let pool = match &backend {
        SqlxBackend::Sqlite(pool) => pool.clone(),
        #[cfg(feature = "postgres")]
        SqlxBackend::Postgres(_) => panic!("SQLite fixture required"),
        #[cfg(feature = "mysql")]
        SqlxBackend::Mysql(_) => panic!("SQLite fixture required"),
    };
    let db = Arc::new(Database::with_backend(Box::new(backend)).await.unwrap());
    let binding = db
        .ensure_instance_default_binding("deployment_r2", None, Some("hub-private-objects"))
        .await
        .unwrap();
    let org = db
        .create_org("oci-projection", "OCI projection")
        .await
        .unwrap();
    let owner = db.org_by_id(org).await.unwrap().unwrap();
    db.grant_consumer_scope(
        aos_hub_core::db::GrantResource::Binding {
            id: binding.id,
            stable_id: &binding.stable_id,
        },
        &owner.stable_id,
        "explicit",
        "fixture",
        "projection-grant",
    )
    .await
    .unwrap();
    let registry = db
        .create_managed_registry(org, "", "main", "private", &[], false)
        .await
        .unwrap();
    let placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(registry),
            name: "primary".into(),
            binding_id: binding.id,
            prefix: "projection/main".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: 0,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();

    // The signed envelope exceeds the generic 1 MiB control cap, while remaining
    // inside the shared 4 MiB document plus explicitly bounded envelope budget.
    let bytes = format!("{{\"architecture\":\"amd64\",\"os\":\"linux\",\"author\":\"{}\",\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[]}}}}", "a".repeat(1024 * 1024));
    let descriptor = Descriptor {
        media_type: MediaType::OciImageConfig,
        digest: Sha256Digest::digest(bytes.as_bytes()),
        size: bytes.len() as u64,
        urls: Vec::new(),
        annotations: Annotations::new(),
        data: None,
        artifact_type: None,
        platform: None,
    };
    let document = OciDocumentProjection::from_stored_bytes(&descriptor, bytes.as_bytes()).unwrap();
    let mode = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let endpoint_mode = mode.clone();
    let endpoint_calls = calls.clone();
    let endpoint_guard = guard.clone();
    let app = Router::new().route(OCI_PROJECTION_PATH, post(move |headers: HeaderMap, body: Bytes| {
        let guard = endpoint_guard.clone();
        let mode = endpoint_mode.clone();
        let calls = endpoint_calls.clone();
        let pool = pool.clone();
        let document = document.clone();
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            let request = verify_oci_projection_lookup(&guard,
                headers.get(OCI_PROJECTION_SIGNATURE_HEADER).unwrap().to_str().unwrap(),
                &body, "deployment-1", current_time().unwrap() + uncertainty).unwrap();
            let selected = mode.load(Ordering::SeqCst);
            if selected == 3 {
                sqlx::query("UPDATE surface_placements SET resource_version = resource_version + 1 WHERE id = ?1")
                    .bind(placement.id).execute(&pool).await.unwrap();
            }
            let mut reply = OciProjectionReply {
                object: StorageObjectIdentity { key: request.key.clone(), size: request.descriptor.size,
                    etag: "\"actual-controlled-incarnation\"".into(), provider_version: Some("controlled-positive-version".into()) },
                request, projection: document, observed_at: current_time().unwrap() + uncertainty,
            };
            if selected == 2 { reply.request.nonce = "f".repeat(64); }
            let signing = if selected == 1 { StorageWorkKey::new([18; 32]).unwrap() } else { guard };
            let signed = sign_oci_projection_reply(&signing, &reply).unwrap();
            assert!(signed.body.len() > 1024 * 1024 && signed.body.len() < MAX_OCI_PROJECTION_BYTES);
            ([(OCI_PROJECTION_SIGNATURE_HEADER, signed.signature)], signed.body)
        }
    }));
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let tls = crate::native_tls::NativeTlsListener::new(
        listener,
        &fixtures.join("hub-hybrid-fleet-server.crt"),
        &fixtures.join("hub-hybrid-fleet-server.key"),
        "localhost".into(),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        axum::serve(tls, app).await.unwrap();
    });
    let ca = reqwest::Certificate::from_pem(
        &std::fs::read(fixtures.join("hub-hybrid-fleet-ca.crt")).unwrap(),
    )
    .unwrap();
    let http = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(ca)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let work = crate::storage_work::RemoteStorageWorkClient::new(
        &origin,
        "deployment-1".into(),
        &[16; 32],
    )
    .unwrap()
    .with_mirror_profiles(accepted)
    .with_mirror_guard_key(&[17; 32])
    .unwrap()
    .with_controlled_http(http);
    let provider = crate::storage_work::HybridSurfaceProvider::new(db.clone(), Arc::new(work));
    let fetcher = provider.placement_fetcher(&placement).await.unwrap();
    let path = aos_hub_core::db::oci_blob_object_key(descriptor.digest);

    assert!(fetcher.fetch(&path).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let proof = fetcher
        .oci_document_projection(&path, &descriptor, None)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        proof
            .check(&descriptor, aos_hub_core::clock::now_unix_secs())
            .unwrap(),
        OciDocumentProjection::Config(_)
    ));
    for failure in [1, 2, 3] {
        mode.store(failure, Ordering::SeqCst);
        assert!(fetcher
            .oci_document_projection(&path, &descriptor, None)
            .await
            .is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    server.abort();
}
