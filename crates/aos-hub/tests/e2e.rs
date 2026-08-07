//! End-to-end: fixture surface → verified index → typed delivery + pages.
//!
//! The local-first loop from RFC-0004's testing story, tier 3: a complete
//! registry surface on disk, indexed fail-closed with real signature
//! verification, then served — machine paths byte-faithful with the right
//! cache headers, human pages rendered from the verified index.

mod common;

use std::sync::Arc;

use aos_hub::db::Database;
use aos_hub::fetch::LocalFsFetch;
use aos_hub::indexer::{
    index_and_record, index_and_record_from_placement, reconcile_registry_replica,
};
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;

async fn get(app: &axum::Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::HOST, "127.0.0.1:8420")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

async fn request(
    app: &axum::Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "127.0.0.1:8420")
        .header("connect-protocol-version", "1");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}

#[tokio::test]
async fn signed_system_images_work_end_to_end_for_public_and_private_registries() {
    use aos_hub::db::{
        NewSurfacePlacementSpec, SurfaceTarget, TokenAuth, UpdateSurfacePlacementSpec,
    };
    use aos_hub::domain::{Permission, Principal, Scope};
    use sha2::{Digest as _, Sha256};

    let root = tempfile::tempdir().unwrap();
    let image_snapshots = aos_hub::image_snapshot::ImageSnapshotStore::open(root.path()).unwrap();
    let public_surface = root.path().join("public");
    let private_surface = root.path().join("private");
    std::fs::create_dir_all(&public_surface).unwrap();
    std::fs::create_dir_all(&private_surface).unwrap();
    let public_fixture = common::system_image_registry(&public_surface);
    let private_fixture = common::system_image_registry(&private_surface);

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let org = db.create_org("images", "Images").await.unwrap();
    let binding =
        common::create_local_binding(&db, org, "image-origin", root.path().to_str().unwrap()).await;
    let public_id = db
        .create_managed_registry(
            org,
            "",
            "public",
            "public",
            std::slice::from_ref(&public_fixture.registry.trust_key),
            true,
        )
        .await
        .unwrap();
    let private_id = db
        .create_managed_registry(
            org,
            "",
            "private",
            "private",
            std::slice::from_ref(&private_fixture.registry.trust_key),
            true,
        )
        .await
        .unwrap();
    let mut public_placement_id = None;
    let mut private_placement_id = None;
    for (registry_id, prefix, fixture) in [
        (public_id, "public", &public_fixture),
        (private_id, "private", &private_fixture),
    ] {
        let placement = common::create_ready_placement(
            &db,
            SurfaceTarget::Registry(registry_id),
            binding,
            &format!("{prefix}-placement"),
            prefix,
        )
        .await;
        if public_placement_id.is_none() {
            common::configure_write_authority(
                &db,
                SurfaceTarget::Registry(registry_id),
                binding,
                &placement,
                &format!("image-publication-{prefix}"),
            )
            .await;
        } else {
            let revision = db
                .storage_binding_write_state(binding)
                .await
                .unwrap()
                .unwrap()
                .current_write_revision
                .unwrap();
            db.bind_surface_placement_write_capability(placement.id, revision)
                .await
                .unwrap();
            db.create_surface_write_authority(
                SurfaceTarget::Registry(registry_id),
                &format!("image-publication-{prefix}"),
                placement.id,
                placement.resource_version,
                placement.write_spec_version,
                revision,
            )
            .await
            .unwrap();
        }
        let registry = db.registry_by_id(registry_id).await.unwrap().unwrap();
        let outcome = index_and_record_from_placement(
            &db,
            &LocalFsFetch::new(&fixture.registry.root)
                .with_image_snapshots(Arc::clone(&image_snapshots))
                .with_image_snapshot_indexing(),
            &registry,
            Some(placement.id),
        )
        .await
        .unwrap();
        assert_eq!(outcome.packages, 1);
        assert_eq!(db.list_system_images(registry_id).await.unwrap().len(), 2);
        if registry_id == public_id {
            public_placement_id = Some(placement.id);
        } else {
            private_placement_id = Some(placement.id);
        }
    }

    let owner_scope = common::org_scope(&db, "images").await;
    common::configure_hub_delivery_route(
        &db,
        SurfaceTarget::Registry(public_id),
        public_placement_id.unwrap(),
        &owner_scope,
        "endpoint:image-fixture",
        "route:image-public",
        "/images/public",
        "git",
    )
    .await;
    common::configure_hub_delivery_route(
        &db,
        SurfaceTarget::Registry(private_id),
        private_placement_id.unwrap(),
        &owner_scope,
        "endpoint:image-fixture",
        "route:image-private",
        "/images/private",
        "git",
    )
    .await;

    // Move default-branch HEAD to a signed commit with no packages while the
    // immutable release tag remains pinned to the original image catalog.
    // Image discovery must continue to project the tag commit, never HEAD.
    let registry_toml = public_fixture
        .registry
        .put_blob("[registry]\nname = \"demo\"\ndescription = \"HEAD without images\"\n");
    let keys_toml = public_fixture.registry.put_blob(&format!(
        "schema = 1\n\n[[keys]]\nid = \"maintainer\"\nkey = \"{}\"\n",
        public_fixture.registry.trust_key,
    ));
    let head_tree = public_fixture.registry.put_tree(&[
        ("100644", "keys.toml", keys_toml),
        ("100644", "registry.toml", registry_toml),
    ]);
    let divergent_head = public_fixture
        .registry
        .put_signed_commit(head_tree, "HEAD intentionally differs from release");
    public_fixture.registry.put_refs(
        "stable",
        &[("stable", divergent_head)],
        &[(
            "1.0.0",
            public_fixture.release_tag,
            public_fixture.release_commit,
        )],
    );
    let public_registry = db.registry_by_id(public_id).await.unwrap().unwrap();
    let outcome = index_and_record_from_placement(
        &db,
        &LocalFsFetch::new(&public_fixture.registry.root)
            .with_image_snapshots(Arc::clone(&image_snapshots))
            .with_image_snapshot_indexing(),
        &public_registry,
        public_placement_id,
    )
    .await
    .unwrap();
    assert_eq!(outcome.packages, 0);
    assert_eq!(db.list_system_images(public_id).await.unwrap().len(), 2);

    let user = db
        .create_user("image-reader@example.invalid", None)
        .await
        .unwrap();
    let org_scope = common::org_scope(&db, "images").await;
    db.grant_membership("user", user, &org_scope, "owner")
        .await
        .unwrap();
    let session = db.create_session(user, 3600, 0).await.unwrap();
    let cookie = format!("__Host-aos_session={session}");
    let mut state = AppState::new(Arc::clone(&db), "http://127.0.0.1:8420".into()).await;
    state.image_snapshots = Some(Arc::clone(&image_snapshots));
    let state = Arc::new(state);
    let token = state
        .auth
        .jwt_keys
        .mint(
            &TokenAuth {
                token_id: "image-reader".into(),
                owner: Principal::user(user),
                scope: Scope::parse(&org_scope),
                permissions: vec![Permission::Read, Permission::Publish],
            },
            900,
        )
        .unwrap();
    let app = router(state).await;

    // Publish the signed image-bearing surface through the typed producer API.
    // The manifest declares disk bytes directly; no NAR/store indirection or
    // Publication uses only the typed manifest and object-upload transaction.
    let refs = std::fs::read(public_surface.join("info/refs")).unwrap();
    let raw_info = std::fs::read(public_surface.join(&public_fixture.raw_info_key)).unwrap();
    let qcow2_info = std::fs::read(public_surface.join(&public_fixture.qcow2_info_key)).unwrap();
    let publication_files = [
        (
            public_fixture.raw_key.as_str(),
            public_fixture.raw.as_slice(),
            "immutable",
        ),
        (
            public_fixture.qcow2_key.as_str(),
            public_fixture.qcow2.as_slice(),
            "immutable",
        ),
        (
            public_fixture.raw_info_key.as_str(),
            raw_info.as_slice(),
            "immutable",
        ),
        (
            public_fixture.qcow2_info_key.as_str(),
            qcow2_info.as_slice(),
            "immutable",
        ),
        ("info/refs", refs.as_slice(), "mutable_pointer"),
    ];
    let objects = publication_files
        .iter()
        .map(|(path, bytes, kind)| {
            serde_json::json!({
                "path": path,
                "sha256": hex::encode(Sha256::digest(bytes)),
                "byteSize": bytes.len(),
                "kind": kind,
                "mediaType": match path.rsplit_once('.').map(|(_, extension)| extension) {
                    Some("json") => "application/json",
                    Some("qcow2") => "application/x-qemu-disk",
                    _ => "application/octet-stream",
                },
            })
        })
        .collect::<Vec<_>>();
    let authorization = format!("Bearer {token}");
    let (status, _, body) = request(
        &app,
        Method::POST,
        "/aos.hub.v1.PublishService/BeginRegistryPublication",
        &[
            ("content-type", "application/json"),
            ("authorization", &authorization),
        ],
        serde_json::to_vec(&serde_json::json!({
            "registry": "images/public",
            "generation": "signed-images-e2e-v1",
            "refsDigest": hex::encode(Sha256::digest(&refs)),
            "defaultCommit": divergent_head.to_hex(),
            "objects": objects,
        }))
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let publication: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(publication["placements"].as_array().unwrap().len(), 1);
    for object in publication["objects"].as_array().unwrap() {
        let object_path = object["path"].as_str().unwrap();
        let (_, bytes, _) = publication_files
            .iter()
            .find(|(path, _, _)| *path == object_path)
            .unwrap();
        let upload_path = url::Url::parse(object["uploadUrl"].as_str().unwrap())
            .unwrap()
            .path()
            .to_string();
        let (status, _, body) = request(
            &app,
            Method::PUT,
            &upload_path,
            &[("authorization", &authorization)],
            bytes.to_vec(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{}: {}",
            object_path,
            String::from_utf8_lossy(&body)
        );
    }
    let (status, _, body) = request(
        &app,
        Method::POST,
        "/aos.hub.v1.PublishService/CommitRegistryPublication",
        &[
            ("content-type", "application/json"),
            ("authorization", &authorization),
        ],
        serde_json::to_vec(&serde_json::json!({
            "publicationId": publication["publicationId"],
        }))
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let committed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(committed["state"], "ready");

    let list_body = br#"{"slug":"images/public","channel":"stable"}"#.to_vec();
    let (status, _, body) = request(
        &app,
        Method::POST,
        "/aos.hub.v1.ImageService/ListImages",
        &[("content-type", "application/json")],
        list_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let body_text = String::from_utf8(body).unwrap();
    assert!(body_text.contains("raw"));
    assert!(body_text.contains("qcow2"));
    assert!(body_text.contains(&public_fixture.raw_key));
    let raw_sha256 = hex::encode(Sha256::digest(&public_fixture.raw));
    let qcow2_sha256 = hex::encode(Sha256::digest(&public_fixture.qcow2));
    assert!(body_text.contains(&raw_sha256));
    assert!(body_text.contains(&qcow2_sha256));
    assert!(body_text.contains("\"releaseVerification\":\"verified\""));
    assert!(body_text.contains("\"bootVerification\":\"unsigned\""));

    let get_body = br#"{"slug":"images/public","release":"1.0.0","architecture":"x86_64","format":"raw","package":"aos-system"}"#.to_vec();
    let (status, _, body) = request(
        &app,
        Method::POST,
        "/aos.hub.v1.ImageService/GetImage",
        &[("content-type", "application/json")],
        get_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let body = String::from_utf8(body).unwrap();
    assert!(body.contains(&public_fixture.raw_key));
    assert!(body.contains(&public_fixture.raw_info_key));
    assert!(body.contains(&raw_sha256));

    let resolve_body = br#"{"slug":"images/public","channel":"stable","architecture":"x86_64","target":"qemu-kvm"}"#.to_vec();
    let (status, _, body) = request(
        &app,
        Method::POST,
        "/aos.hub.v1.ImageService/ResolveImage",
        &[("content-type", "application/json")],
        resolve_body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(String::from_utf8(body).unwrap().contains("qcow2"));

    let image_uri = format!("/images/public/{}", public_fixture.raw_key);
    let (status, headers, body) = request(&app, Method::GET, &image_uri, &[], Vec::new()).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body, public_fixture.raw);
    assert_eq!(
        headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"aos-1.0.0-x86_64.img\""
    );
    assert_eq!(headers["x-aos-sha256"].to_str().unwrap(), raw_sha256);
    assert!(headers[header::CACHE_CONTROL]
        .to_str()
        .unwrap()
        .contains("immutable"));

    let (status, headers, body) = request(
        &app,
        Method::GET,
        &image_uri,
        &[("range", "bytes=4-11")],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        headers[header::CONTENT_RANGE].to_str().unwrap(),
        format!("bytes 4-11/{}", public_fixture.raw.len())
    );
    assert_eq!(body, public_fixture.raw[4..=11]);

    let (status, headers, body) = request(&app, Method::HEAD, &image_uri, &[], Vec::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty());
    assert_eq!(
        headers[header::CONTENT_LENGTH].to_str().unwrap(),
        public_fixture.raw.len().to_string()
    );
    let (status, headers, body) = request(
        &app,
        Method::GET,
        &image_uri,
        &[("range", "bytes=9999-")],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert!(body.is_empty());
    assert_eq!(
        headers[header::CONTENT_RANGE].to_str().unwrap(),
        format!("bytes */{}", public_fixture.raw.len())
    );

    let info_uri = format!("/images/public/{}", public_fixture.raw_info_key);
    let (status, _, info) = request(&app, Method::GET, &info_uri, &[], Vec::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&info).unwrap()["format"],
        "raw"
    );

    let (status, _, page) = get(&app, "/images/public/-/images").await;
    assert_eq!(status, StatusCode::OK);
    let page = String::from_utf8(page).unwrap();
    assert!(page.contains("Images"));
    assert!(page.contains("href=\"/images/public/-/images\""));
    assert!(page.contains("aria-current=\"page\">Images"));
    assert!(page.to_ascii_lowercase().contains("qcow2"));
    assert!(page.contains("1.0.0"));
    assert!(page.contains("stable"));
    assert!(page.contains("x86_64"));
    assert!(page.contains("bare-metal"));
    assert!(page.contains("qemu-kvm"));
    assert!(page.contains(&format!("{} B", public_fixture.raw.len())));
    assert!(page.contains(&raw_sha256));
    assert!(page.contains("unsigned"));
    assert!(page.contains("verified"));
    assert!(page.contains("Download"));

    let private_uri = format!("/images/private/{}", private_fixture.qcow2_key);
    let (status, _, _) = request(&app, Method::GET, &private_uri, &[], Vec::new()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, headers, bytes) = request(
        &app,
        Method::GET,
        &private_uri,
        &[("cookie", &cookie)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, private_fixture.qcow2);
    assert_eq!(
        headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"aos-1.0.0-x86_64.qcow2\""
    );
    assert_eq!(headers["x-aos-sha256"], qcow2_sha256);
    assert!(headers[header::CACHE_CONTROL]
        .to_str()
        .unwrap()
        .contains("no-store"));
    assert_eq!(headers[header::VARY], "Authorization, Cookie");

    let (status, _, _) = request(
        &app,
        Method::POST,
        "/aos.hub.v1.ImageService/ListImages",
        &[("content-type", "application/json")],
        br#"{"slug":"images/private"}"#.to_vec(),
    )
    .await;
    assert_ne!(status, StatusCode::OK);
    let authorization = format!("Bearer {token}");
    let (status, _, body) = request(
        &app,
        Method::POST,
        "/aos.hub.v1.ImageService/ListImages",
        &[
            ("content-type", "application/json"),
            ("authorization", &authorization),
        ],
        br#"{"slug":"images/private","format":"qcow2"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(String::from_utf8(body)
        .unwrap()
        .contains(&private_fixture.qcow2_key));

    // A stale inventory row on an earlier placement must not authorize its
    // same-size corrupt bytes. Request-time verification skips it and serves
    // the independently verified primary placement.
    let corrupt_surface = root.path().join("corrupt-first");
    let replica_fixture = common::system_image_registry(&corrupt_surface);
    assert_eq!(replica_fixture.raw_key, public_fixture.raw_key);
    std::fs::copy(
        public_fixture.registry.root.join("info/refs"),
        corrupt_surface.join("info/refs"),
    )
    .unwrap();
    let corrupt_raw_path = corrupt_surface.join(&public_fixture.raw_key);
    let corrupt_placement = db
        .create_surface_placement(&NewSurfacePlacementSpec {
            surface: SurfaceTarget::Registry(public_id),
            name: "corrupt-first".into(),
            storage_binding_id: binding,
            prefix: "corrupt-first".into(),
            kind: "complete".into(),
            desired_state: "active".into(),
            hash_range: None,
            desired_read_enabled: true,
            read_order: -10,
            requires_conditional_writes: false,
        })
        .await
        .unwrap();
    db.observe_surface_placement(corrupt_placement.id, "ready", "complete", 1)
        .await
        .unwrap();
    reconcile_registry_replica(
        &db,
        &LocalFsFetch::new(&corrupt_surface)
            .with_image_snapshots(Arc::clone(&image_snapshots))
            .with_image_snapshot_indexing(),
        &public_registry,
        corrupt_placement.id,
    )
    .await
    .unwrap();
    let mut corrupt_first = public_fixture.raw.clone();
    corrupt_first[0] ^= 0xff;
    std::fs::write(&corrupt_raw_path, &corrupt_first).unwrap();
    let (status, _, bytes) = request(&app, Method::GET, &image_uri, &[], Vec::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, public_fixture.raw);
    db.update_surface_placement(
        corrupt_placement.id,
        &UpdateSurfacePlacementSpec {
            expected_version: corrupt_placement.resource_version,
            desired_state: "active".to_string(),
            desired_read_enabled: true,
            read_order: 10,
        },
    )
    .await
    .unwrap();

    // A source mutation cannot change already-published bytes: delivery keeps
    // serving the retained immutable snapshot until authoritative reindexing
    // rejects the corrupt release root and withdraws its catalog entries.
    let raw_path = public_fixture.registry.root.join(&public_fixture.raw_key);
    let mut corrupted = public_fixture.raw.clone();
    corrupted[0] ^= 0xff;
    std::fs::write(&raw_path, &corrupted).unwrap();
    let (status, _, bytes) = request(&app, Method::GET, &image_uri, &[], Vec::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, public_fixture.raw);
    let (status, _, _) = request(&app, Method::HEAD, &image_uri, &[], Vec::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(index_and_record_from_placement(
        &db,
        &LocalFsFetch::new(&public_fixture.registry.root)
            .with_image_snapshots(Arc::clone(&image_snapshots))
            .with_image_snapshot_indexing(),
        &public_registry,
        public_placement_id,
    )
    .await
    .is_err());
    assert_eq!(
        db.index_status(public_id).await.unwrap().unwrap().state,
        "failed"
    );
    assert!(db.list_system_images(public_id).await.unwrap().is_empty());
    let (status, _, _) = request(&app, Method::GET, &image_uri, &[], Vec::new()).await;
    assert_ne!(status, StatusCode::OK);

    std::fs::write(&raw_path, &public_fixture.raw).unwrap();
    index_and_record_from_placement(
        &db,
        &LocalFsFetch::new(&public_fixture.registry.root)
            .with_image_snapshots(Arc::clone(&image_snapshots))
            .with_image_snapshot_indexing(),
        &public_registry,
        public_placement_id,
    )
    .await
    .unwrap();
    assert_eq!(db.list_system_images(public_id).await.unwrap().len(), 2);

    // A successful authoritative read with no publication pointer is an empty
    // catalog, not a reason to retain stale release roots or presence.
    let preserved_image_objects = [
        public_fixture.registry.root.join(&public_fixture.raw_key),
        public_fixture
            .registry
            .root
            .join(&public_fixture.raw_info_key),
        corrupt_surface.join(&public_fixture.raw_key),
        corrupt_surface.join(&public_fixture.raw_info_key),
        corrupt_surface.join(&public_fixture.qcow2_key),
        corrupt_surface.join(&public_fixture.qcow2_info_key),
    ]
    .map(|path| {
        let bytes = std::fs::read(&path).unwrap();
        (path, bytes)
    });
    std::fs::remove_file(public_fixture.registry.root.join("info/refs")).unwrap();
    index_and_record_from_placement(
        &db,
        &LocalFsFetch::new(&public_fixture.registry.root)
            .with_image_snapshots(Arc::clone(&image_snapshots))
            .with_image_snapshot_indexing(),
        &public_registry,
        public_placement_id,
    )
    .await
    .unwrap();
    assert!(db.list_system_images(public_id).await.unwrap().is_empty());
    assert!(db
        .list_system_image_root_keys(public_id)
        .await
        .unwrap()
        .is_empty());
    assert!(!db.has_system_image_catalog(public_id).await.unwrap());
    for (path, original_bytes) in preserved_image_objects {
        assert!(
            path.exists(),
            "empty indexing deleted physical image object {}",
            path.display()
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original_bytes,
            "empty indexing rewrote physical image object {}",
            path.display()
        );
    }
}

#[tokio::test]
async fn fixture_surface_indexes_and_serves() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);

    // Register fail-closed with the fixture's trust anchor and index.
    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.register_registry("demo", std::slice::from_ref(&fixture.trust_key), true)
        .await
        .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let fetch = LocalFsFetch::new(&surface);
    let outcome = index_and_record(&db, &fetch, &registry).await.unwrap();
    assert_eq!(outcome.packages, 1);
    assert_eq!(outcome.releases, 1);
    assert_eq!(outcome.channels, 1);

    // The index reflects the verified surface.
    let status = db.index_status(registry.id).await.unwrap().unwrap();
    assert_eq!(status.state, "fresh");
    assert_eq!(status.name.as_deref(), Some("demo"));
    let packages = db.list_packages(registry.id).await.unwrap();
    assert_eq!(packages[0].name, "curl");
    let channels = db.list_channels(registry.id).await.unwrap();
    assert_eq!(channels[0].frontier.as_deref(), Some("1.0.0"));
    assert_eq!(channels[0].partitions.iter().flatten().count(), 256);
    let releases = db.list_releases(registry.id).await.unwrap();
    assert!(
        releases[0].signer.is_some(),
        "release must record its signer"
    );

    // Serve the indexed control-plane views. Byte delivery is covered through
    // explicit delivery routes in the image and routing fixtures below.
    let app = router(Arc::new(
        AppState::new(Arc::clone(&db), "http://127.0.0.1:8420".into()).await,
    ))
    .await;

    // Human pages render from the verified index.
    let (status, _, body) = get(&app, "/demo/-/").await;
    assert_eq!(status, StatusCode::OK);
    let home = String::from_utf8(body).unwrap();
    assert!(home.contains("Fixture registry"));
    assert!(home.contains("stable"));

    let (status, _, body) = get(&app, "/demo/-/packages/curl").await;
    assert_eq!(status, StatusCode::OK);
    let page = String::from_utf8(body).unwrap();
    assert!(page.contains("URL transfers"));
    assert!(page.contains("x86_64-linux"));

    let (status, _, body) = get(&app, "/demo/-/channels/stable").await;
    assert_eq!(status, StatusCode::OK);
    let page = String::from_utf8(body).unwrap();
    assert!(page.contains("256 partitions") || page.contains("256 of 256"));

    let (status, _, body) = get(&app, "/demo/-/releases").await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(body).unwrap().contains("1.0.0"));

    // Instance home and health.
    let (status, _, body) = get(&app, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(body).unwrap().contains("/demo/"));
    let (status, _, _) = get(&app, "/healthz").await;
    assert_eq!(status, StatusCode::OK);

    // Non-machine, non-page paths 404 rather than leaking files.
    let (status, _, _) = get(&app, "/demo/hub.db").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = get(&app, "/missing/HEAD").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tampered_partition_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);

    // Tamper one partition's signed bytes (the target oid).
    let partition = surface.join("channels/stable/07");
    let mut payload = std::fs::read(&partition).unwrap();
    payload[8] = if payload[8] == b'f' { b'0' } else { b'f' };
    std::fs::write(&partition, payload).unwrap();

    let db = Database::open_in_memory().await.unwrap();
    db.register_registry("demo", std::slice::from_ref(&fixture.trust_key), true)
        .await
        .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let fetch = LocalFsFetch::new(&surface);
    let err = index_and_record(&db, &fetch, &registry).await.unwrap_err();
    assert!(format!("{err:#}").contains("channels/stable/07"));
    let status = db.index_status(registry.id).await.unwrap().unwrap();
    assert_eq!(status.state, "failed");
}

#[tokio::test]
async fn untrusted_key_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    common::standard_registry(&surface);

    // Pin a *different* key than the one that signed the surface. The
    // committed roster must not rescue it: the roster only extends trust
    // after the commit itself verifies against pinned anchors.
    let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let wrong_anchor = aos_hub::surface::sshsig::trusted_key_line("demo", &other.verifying_key());

    let db = Database::open_in_memory().await.unwrap();
    db.register_registry("demo", &[wrong_anchor], true)
        .await
        .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let fetch = LocalFsFetch::new(&surface);
    let err = index_and_record(&db, &fetch, &registry).await.unwrap_err();
    assert!(format!("{err:#}").contains("not trusted"), "got: {err:#}");
}

#[tokio::test]
async fn connectrpc_read_path_serves_index() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    db.register_registry("demo", std::slice::from_ref(&fixture.trust_key), true)
        .await
        .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    index_and_record(&db, &LocalFsFetch::new(&surface), &registry)
        .await
        .unwrap();

    let app = router(Arc::new(
        AppState::new(db, "http://127.0.0.1:8420".into()).await,
    ))
    .await;

    let post = |uri: &'static str, body: &'static str| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header(header::HOST, "127.0.0.1:8420")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header("connect-protocol-version", "1")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    // PackageService over Connect-JSON.
    let (status, body) = post(
        "/aos.hub.v1.PackageService/ListPackages",
        r#"{"slug":"demo"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("curl"), "body: {body}");
    assert!(body.contains("8.5.0"), "body: {body}");

    // ChannelService returns the full partition map.
    let (status, body) = post(
        "/aos.hub.v1.ChannelService/GetChannel",
        r#"{"slug":"demo","name":"stable"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("1.0.0"), "body: {body}");

    // RegistryService reports verified index state and trust anchors.
    let (status, body) = post(
        "/aos.hub.v1.RegistryService/GetRegistry",
        r#"{"slug":"demo"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("fresh"), "body: {body}");
    assert!(body.contains("AAAAC3NzaC1lZDI1NTE5"), "body: {body}");

    // Unknown registries are NotFound, not empty success.
    let (status, body) = post(
        "/aos.hub.v1.RegistryService/GetRegistry",
        r#"{"slug":"missing"}"#,
    )
    .await;
    assert_ne!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("not_found"), "body: {body}");

    // The renamed identity service is mounted. An anonymous request reaches
    // the handler and is rejected by authentication rather than routing.
    let (status, body) = post("/aos.hub.v1.IdentityService/ListAccessTokens", "{}").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");

    // The RFC-0012 cutover is deliberately hard: neither the former package
    // nor any of the ambiguous service names remains mounted as an alias.
    for uri in [
        "/aos.registry.v1.RegistryService/ListRegistries",
        "/aos.hub.v1.OrgService/ListOrgs",
        "/aos.hub.v1.StorageService/ListBindings",
        "/aos.hub.v1.ConfigService/ListChangesets",
        "/aos.hub.v1.IamService/ListTokens",
        "/aos.hub.v1.CacheService/ListCaches",
    ] {
        let (status, _) = post(uri, "{}").await;
        assert!(
            !status.is_success(),
            "removed RPC unexpectedly succeeded: {uri}"
        );
    }
}

/// An RPC request whose body exceeds the small inbound RPC cap is rejected
/// before the handler runs, while a normal small RPC body is served — proving
/// the `DefaultBodyLimit` is scoped to the RPC surface.
#[tokio::test]
async fn rpc_inbound_body_cap_rejects_oversized_request() {
    use aos_hub::server::RPC_MAX_BODY_BYTES;

    let db = Arc::new(Database::open_in_memory().await.unwrap());
    let app = router(Arc::new(
        AppState::new(db, "http://127.0.0.1:8420".into()).await,
    ))
    .await;

    let post = |body: Vec<u8>| {
        let app = app.clone();
        async move {
            // Set an explicit Content-Length (real Connect clients always do)
            // so the body-limit layer can reject an over-cap request up front
            // with 413, exactly as it would in production.
            let len = body.len();
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/aos.hub.v1.PackageService/ListPackages")
                    .header(header::HOST, "127.0.0.1:8420")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_LENGTH, len)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }
    };

    // A body just over the cap is rejected with 413 Payload Too Large; the
    // handler (which would otherwise return NotFound for an unknown slug) is
    // never reached.
    let oversized = post(vec![b' '; RPC_MAX_BODY_BYTES + 1]).await;
    assert_eq!(
        oversized,
        StatusCode::PAYLOAD_TOO_LARGE,
        "an over-cap RPC body must be rejected"
    );

    // A small, well-formed body is accepted by the layer and handled normally
    // (NotFound for the missing registry — not a 413).
    let small = post(br#"{"slug":"missing"}"#.to_vec()).await;
    assert_ne!(
        small,
        StatusCode::PAYLOAD_TOO_LARGE,
        "a small RPC body must not be capped"
    );
}
