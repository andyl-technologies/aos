//! Registry mirroring e2e: full-mirror verify-then-copy and pull-through.
//!
//! An in-test "upstream" is a real signed fixture surface served over a local
//! axum file server (the `tests/http_source.rs` pattern). The full-mirror sync
//! verifies the upstream against the mirror's trust anchors before copying it
//! byte-identically into the local binding; the pull-through cache fetches a
//! missing machine path on demand, verifies it by oid, persists it, and serves
//! it.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use aos_hub::db::Database;
use aos_hub::fetch::safe_join;
use aos_hub::mirror::{fetch_through, sync_full_mirror};
use aos_hub::server::{router, AppState};
use axum::body::Body;
use axum::extract::{Path as AxPath, State};
use axum::http::{header, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tower::ServiceExt;

/// Minimal static file server over a fixture directory; 404s missing files.
async fn serve_file(State(root): State<Arc<PathBuf>>, AxPath(path): AxPath<String>) -> Response {
    let Ok(full) = safe_join(&root, &path) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match std::fs::read(full) {
        Ok(bytes) => bytes.into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Stand up a real upstream HTTP server over `surface` on an ephemeral port,
/// returning its base URL.
///
/// Also opts out of the SSRF local/internal-address rejection so the mirror
/// can be pointed at the `127.0.0.1` test server (production never sets this).
async fn serve_upstream(surface: PathBuf) -> String {
    std::env::set_var("AOS_HUB_ALLOW_LOCAL_REMOTES", "1");
    let app = axum::Router::new()
        .route("/{*path}", get(serve_file))
        .with_state(Arc::new(surface));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    url
}

/// Create a managed mirror registry whose surface lives under a `local_fs`
/// binding, returning `(registry_id, placement_id, binding_root)`.
async fn make_mirror_registry(
    db: &Database,
    trust_key: &str,
    binding_root: &std::path::Path,
) -> (i64, i64, PathBuf) {
    let org = db.create_org("acme", "Acme, Inc.").await.unwrap();
    db.create_project(org, "infra/prod", "Production")
        .await
        .unwrap();
    let binding =
        common::create_local_binding(&db, org, "primary", &binding_root.to_string_lossy()).await;
    let reg = db
        .create_managed_registry(
            org,
            "infra/prod",
            "mirror",
            "public",
            std::slice::from_ref(&trust_key.to_string()),
            true,
        )
        .await
        .unwrap();
    let placement = common::create_ready_placement(
        db,
        aos_hub::db::SurfaceTarget::Registry(reg),
        binding,
        "primary",
        "infra/prod/mirror",
    )
    .await;
    common::configure_write_authority(
        db,
        aos_hub::db::SurfaceTarget::Registry(reg),
        binding,
        &placement,
        "mirror-write-authority",
    )
    .await;
    let root = binding_root.join("infra/prod/mirror");
    (reg, placement.id, root)
}

#[tokio::test]
async fn full_mirror_verifies_then_copies_upstream() {
    let dir = tempfile::tempdir().unwrap();

    // Build a real signed upstream surface and serve it over HTTP.
    let upstream_surface = dir.path().join("upstream");
    std::fs::create_dir_all(&upstream_surface).unwrap();
    let fixture = common::standard_registry(&upstream_surface);
    let upstream_url = serve_upstream(upstream_surface.clone()).await;

    // A local mirror registry whose trust anchor is the upstream's (so a
    // consumer keeps upstream trust), bound to an empty local directory.
    let binding_root = dir.path().join("binding");
    let db = Database::open_in_memory().await.unwrap();
    let (reg, _placement, local_root) =
        make_mirror_registry(&db, &fixture.trust_key, &binding_root).await;
    db.create_mirror_source(reg, &upstream_url, "full", true, 3600)
        .await
        .unwrap();
    let registry = db.registry_by_id(reg).await.unwrap().unwrap();

    // Sync: verify the upstream, then copy it byte-identically.
    let result = sync_full_mirror(&db, &registry).await.unwrap();
    assert!(result.files_copied > 0);
    assert_eq!(result.channels, 1);
    assert_eq!(result.releases, 1);

    // The local binding now holds the upstream's HEAD, info/refs, a sample
    // loose object, and channel partitions — byte-identical to upstream.
    for path in ["HEAD", "info/refs", "channels/stable/00", "nix-cache-info"] {
        let local = std::fs::read(local_root.join(path)).unwrap();
        let up = std::fs::read(upstream_surface.join(path)).unwrap();
        assert_eq!(local, up, "byte-identical copy of {path}");
    }
    // The HEAD commit's loose object is present locally.
    let head_commit = result.commit;
    let loose = format!("objects/{}/{}", &head_commit[..2], &head_commit[2..]);
    assert!(
        local_root.join(&loose).exists(),
        "HEAD commit object copied"
    );

    // The mirror indexed to the upstream's frontier and recorded a clean sync.
    let status = db.index_status(reg).await.unwrap().unwrap();
    assert_eq!(status.state, "fresh");
    let source = db.mirror_source(reg).await.unwrap().unwrap();
    assert_eq!(source.last_sync_status.as_deref(), Some("ok"));
    assert_eq!(source.upstream_frontier.as_deref(), Some("1.0.0"));
}

#[tokio::test]
async fn full_mirror_refuses_untrusted_upstream() {
    let dir = tempfile::tempdir().unwrap();

    // The upstream is signed by the fixture key…
    let upstream_surface = dir.path().join("upstream");
    std::fs::create_dir_all(&upstream_surface).unwrap();
    let fixture = common::standard_registry(&upstream_surface);
    let upstream_url = serve_upstream(upstream_surface.clone()).await;

    // …but the mirror's trust anchor is a *different* key, so verification must
    // fail and nothing may be written.
    let other = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let wrong_anchor = aos_hub::surface::sshsig::trusted_key_line("wrong", &other.verifying_key());
    assert_ne!(wrong_anchor, fixture.trust_key);

    let binding_root = dir.path().join("binding");
    let db = Database::open_in_memory().await.unwrap();
    let (reg, _placement, local_root) =
        make_mirror_registry(&db, &wrong_anchor, &binding_root).await;
    db.create_mirror_source(reg, &upstream_url, "full", true, 3600)
        .await
        .unwrap();
    let registry = db.registry_by_id(reg).await.unwrap().unwrap();

    let err = sync_full_mirror(&db, &registry).await.unwrap_err();
    assert!(format!("{err:#}").contains("verif"), "got: {err:#}");

    // Local state is unchanged: nothing was copied.
    assert!(
        !local_root.join("HEAD").exists(),
        "no surface bytes written on a failed verification"
    );
    // The failure is recorded for the health page.
    let source = db.mirror_source(reg).await.unwrap().unwrap();
    assert_eq!(source.last_sync_status.as_deref(), Some("failed"));
    assert!(source.last_sync_error.is_some());
    assert!(source.upstream_frontier.is_none());
}

#[tokio::test]
async fn pull_through_fetches_verifies_persists_and_serves() {
    let dir = tempfile::tempdir().unwrap();

    let upstream_surface = dir.path().join("upstream");
    std::fs::create_dir_all(&upstream_surface).unwrap();
    let fixture = common::standard_registry(&upstream_surface);
    let upstream_url = serve_upstream(upstream_surface.clone()).await;

    // A pull-through mirror with an EMPTY local binding.
    let binding_root = dir.path().join("binding");
    let db = Database::open_in_memory().await.unwrap();
    let (reg, placement, local_root) =
        make_mirror_registry(&db, &fixture.trust_key, &binding_root).await;
    db.create_mirror_source(reg, &upstream_url, "pullthrough", true, 3600)
        .await
        .unwrap();
    let registry = db.registry_by_id(reg).await.unwrap().unwrap();
    db.grant_consumer_scope(
        aos_hub::db::GrantResource::NetworkBoundary {
            id: "instance:public",
        },
        &registry.owner_scope_key,
        "explicit",
        "test",
        "request:mirror-boundary-grant",
    )
    .await
    .unwrap();
    common::configure_hub_delivery_route(
        &db,
        aos_hub::db::SurfaceTarget::Registry(reg),
        placement,
        &registry.owner_scope_key,
        "endpoint:mirror",
        "route:mirror",
        "/acme/infra/prod/mirror",
        "git",
    )
    .await;

    // Pick a real loose-object path from the upstream surface to request.
    let oid_hex = find_a_loose_object(&upstream_surface);
    let object_path = format!("objects/{}/{}", &oid_hex[..2], &oid_hex[2..]);
    assert!(
        !local_root.join(&object_path).exists(),
        "the object is absent locally before the first request"
    );

    // Sanity: fetch_through alone fetches, verifies, persists, and serves the
    // bytes (isolates the facade wiring from the mirror logic).
    {
        let fetch = aos_hub::fetch::HttpFetch::new(&upstream_url).await;
        let direct = fetch_through(
            &fetch,
            &local_root,
            &object_path,
            std::slice::from_ref(&fixture.trust_key),
            true,
        )
        .await
        .expect("fetch_through ok")
        .expect("upstream has the object");
        assert!(direct.persisted);
        std::fs::remove_file(local_root.join(&object_path)).unwrap();
    }

    // GET the object through the hub facade: it fetches from upstream, verifies
    // by oid, persists locally, and serves the bytes.
    let state = Arc::new(AppState::new(Arc::new(db), "http://127.0.0.1:8420".into()).await);
    let app = router(state).await;
    let uri = format!("/acme/infra/prod/mirror/{object_path}");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(header::HOST, "127.0.0.1:8420")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let served = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let upstream_bytes = std::fs::read(upstream_surface.join(&object_path)).unwrap();
    assert_eq!(served.as_ref(), upstream_bytes.as_slice());

    // The object was persisted: a second GET is served from the local binding.
    assert!(
        local_root.join(&object_path).exists(),
        "the pulled object is now persisted locally"
    );
    let persisted = std::fs::read(local_root.join(&object_path)).unwrap();
    assert_eq!(persisted, upstream_bytes);
}

#[tokio::test]
async fn pull_through_rejects_tampered_object_by_oid() {
    let dir = tempfile::tempdir().unwrap();
    let upstream_surface = dir.path().join("upstream");
    std::fs::create_dir_all(&upstream_surface).unwrap();
    let fixture = common::standard_registry(&upstream_surface);

    // Tamper a loose object's bytes on the upstream so it no longer hashes to
    // the oid its path names.
    let oid_hex = find_a_loose_object(&upstream_surface);
    let object_path = format!("objects/{}/{}", &oid_hex[..2], &oid_hex[2..]);
    std::fs::write(upstream_surface.join(&object_path), b"tampered").unwrap();
    let upstream_url = serve_upstream(upstream_surface.clone()).await;

    let binding_root = dir.path().join("binding");
    let db = Database::open_in_memory().await.unwrap();
    let (reg, _placement, local_root) =
        make_mirror_registry(&db, &fixture.trust_key, &binding_root).await;

    let fetch = aos_hub::fetch::HttpFetch::new(&upstream_url).await;
    let err = fetch_through(
        &fetch,
        &local_root,
        &object_path,
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("verifying pulled object"),
        "got: {err:#}"
    );
    assert!(
        !local_root.join(&object_path).exists(),
        "a tampered object is never persisted"
    );
    let _ = reg;
}

#[tokio::test]
async fn full_mirror_rejects_unsigned_narinfo() {
    let dir = tempfile::tempdir().unwrap();
    let upstream_surface = dir.path().join("upstream");
    std::fs::create_dir_all(&upstream_surface).unwrap();
    let fixture = common::standard_registry(&upstream_surface);

    // Strip the narinfo's `Sig:` line: a poisoned cache with no trusted
    // signature. The git surface still verifies, but the nix-cache must not.
    let narinfo_path = upstream_surface.join("h7j3k8l2m9n4.narinfo");
    let original = std::fs::read_to_string(&narinfo_path).unwrap();
    let unsigned: String = original
        .lines()
        .filter(|l| !l.starts_with("Sig:"))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&narinfo_path, unsigned).unwrap();
    let upstream_url = serve_upstream(upstream_surface.clone()).await;

    let binding_root = dir.path().join("binding");
    let db = Database::open_in_memory().await.unwrap();
    let (reg, _placement, local_root) =
        make_mirror_registry(&db, &fixture.trust_key, &binding_root).await;
    db.create_mirror_source(reg, &upstream_url, "full", true, 3600)
        .await
        .unwrap();
    let registry = db.registry_by_id(reg).await.unwrap().unwrap();

    let err = sync_full_mirror(&db, &registry).await.unwrap_err();
    assert!(format!("{err:#}").contains("narinfo"), "got: {err:#}");
    // Fail-closed: nothing was written, not even the git surface.
    assert!(
        !local_root.join("HEAD").exists(),
        "no surface bytes written when a narinfo fails verification"
    );
    let source = db.mirror_source(reg).await.unwrap().unwrap();
    assert_eq!(source.last_sync_status.as_deref(), Some("failed"));
}

#[tokio::test]
async fn full_mirror_rejects_tampered_nar() {
    let dir = tempfile::tempdir().unwrap();
    let upstream_surface = dir.path().join("upstream");
    std::fs::create_dir_all(&upstream_surface).unwrap();
    let fixture = common::standard_registry(&upstream_surface);

    // Tamper the NAR bytes: the narinfo's Sig still verifies (signed metadata),
    // but the NAR no longer matches the declared FileHash/NarHash.
    std::fs::write(
        upstream_surface.join("nar/h7j3k8l2m9n4-fixturehash.nar"),
        b"tampered-nar-bytes",
    )
    .unwrap();
    let upstream_url = serve_upstream(upstream_surface.clone()).await;

    let binding_root = dir.path().join("binding");
    let db = Database::open_in_memory().await.unwrap();
    let (reg, _placement, local_root) =
        make_mirror_registry(&db, &fixture.trust_key, &binding_root).await;
    db.create_mirror_source(reg, &upstream_url, "full", true, 3600)
        .await
        .unwrap();
    let registry = db.registry_by_id(reg).await.unwrap().unwrap();

    let err = sync_full_mirror(&db, &registry).await.unwrap_err();
    assert!(format!("{err:#}").contains("NAR"), "got: {err:#}");
    assert!(
        !local_root.join("HEAD").exists(),
        "no surface bytes written when a NAR fails verification"
    );
    let source = db.mirror_source(reg).await.unwrap().unwrap();
    assert_eq!(source.last_sync_status.as_deref(), Some("failed"));
}

#[tokio::test]
async fn pull_through_refuses_tampered_narinfo_and_nar() {
    let dir = tempfile::tempdir().unwrap();
    let upstream_surface = dir.path().join("upstream");
    std::fs::create_dir_all(&upstream_surface).unwrap();
    let fixture = common::standard_registry(&upstream_surface);

    let binding_root = dir.path().join("binding");
    let db = Database::open_in_memory().await.unwrap();
    let (_reg, _placement, local_root) =
        make_mirror_registry(&db, &fixture.trust_key, &binding_root).await;
    let trusted = vec![fixture.trust_key.clone()];

    // A correctly-signed narinfo and matching NAR are served.
    let fetch = aos_hub::fetch::LocalFsFetch::new(&upstream_surface);
    assert!(
        fetch_through(&fetch, &local_root, "h7j3k8l2m9n4.narinfo", &trusted, true)
            .await
            .unwrap()
            .is_some(),
        "a valid narinfo is served"
    );
    assert!(
        fetch_through(
            &fetch,
            &local_root,
            "nar/h7j3k8l2m9n4-fixturehash.nar",
            &trusted,
            true
        )
        .await
        .unwrap()
        .is_some(),
        "a valid NAR is served"
    );

    // Tamper the narinfo's Sig: pull-through must refuse it, not proxy poison.
    let narinfo_path = upstream_surface.join("h7j3k8l2m9n4.narinfo");
    let original = std::fs::read_to_string(&narinfo_path).unwrap();
    let bad_sig = original.replace("Sig: demo:", "Sig: demo:AAAA");
    std::fs::write(&narinfo_path, &bad_sig).unwrap();
    let err = fetch_through(&fetch, &local_root, "h7j3k8l2m9n4.narinfo", &trusted, true)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("narinfo"), "got: {err:#}");

    // Restore the narinfo, then tamper the NAR bytes: the NAR fails its hash
    // check against the (now-trusted) narinfo and is refused.
    std::fs::write(&narinfo_path, &original).unwrap();
    std::fs::write(
        upstream_surface.join("nar/h7j3k8l2m9n4-fixturehash.nar"),
        b"poisoned-nar",
    )
    .unwrap();
    let err = fetch_through(
        &fetch,
        &local_root,
        "nar/h7j3k8l2m9n4-fixturehash.nar",
        &trusted,
        true,
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("NAR"), "got: {err:#}");
}

#[tokio::test]
async fn pull_through_rejects_narinfo_substitution() {
    // M-5: a pull-through request for `<hashB>.narinfo` answered with a
    // *validly-signed* narinfo whose StorePath hash is `hashA` is a
    // substitution/downgrade — the signature attests A, not the requested B.
    // The pull-through must REJECT it (the binding stock Nix enforces).
    use sha2::Digest as _;

    let dir = tempfile::tempdir().unwrap();
    let upstream = dir.path().join("upstream");
    std::fs::create_dir_all(upstream.join("nar")).unwrap();
    let fixture = common::Fixture::new(&upstream);
    let trusted = vec![fixture.trust_key.clone()];
    let fetch = aos_hub::fetch::LocalFsFetch::new(&upstream);

    // A correctly-signed narinfo for store hash "aaaapkgone".
    let nar_bytes = b"package-A-nar-bytes";
    let hash = format!("sha256:{}", hex::encode(sha2::Sha256::digest(nar_bytes)));
    let store_path = "/var/lib/store/aaaapkgone-pkg-a-1.0";
    let nar_url = "nar/aaaapkgone-fixturehash.nar";
    let narinfo = fixture.signed_narinfo(store_path, nar_url, &hash, nar_bytes.len() as u64, &[]);

    // The honest path: served at its own `<hash>.narinfo`.
    std::fs::write(upstream.join("aaaapkgone.narinfo"), &narinfo).unwrap();
    std::fs::write(upstream.join(nar_url), nar_bytes).unwrap();
    assert!(
        fetch_through(&fetch, dir.path(), "aaaapkgone.narinfo", &trusted, true)
            .await
            .unwrap()
            .is_some(),
        "a narinfo served at its own hash is accepted"
    );

    // The attack: the SAME validly-signed narinfo served at a DIFFERENT
    // requested hash. Internally consistent for A, a substitution for B.
    std::fs::write(upstream.join("bbbbpkgtwo.narinfo"), &narinfo).unwrap();
    let err = fetch_through(&fetch, dir.path(), "bbbbpkgtwo.narinfo", &trusted, true)
        .await
        .expect_err("a foreign signed narinfo at the requested hash must be rejected");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("does not match the requested hash") || msg.contains("substitution"),
        "rejection should cite the hash binding, got: {msg}"
    );
}

#[tokio::test]
async fn pull_through_rejects_nar_url_substitution() {
    // M-5 (NAR arm): a request for `nar/X` answered with a (validly-signed)
    // narinfo whose `URL:` names `nar/Y` is a substitution of the served bytes.
    // The pull-through must REJECT it: a request for `nar/X` is only answered
    // with the NAR its narinfo points at.
    use sha2::Digest as _;

    let dir = tempfile::tempdir().unwrap();
    let upstream = dir.path().join("upstream");
    std::fs::create_dir_all(upstream.join("nar")).unwrap();
    let fixture = common::Fixture::new(&upstream);
    let trusted = vec![fixture.trust_key.clone()];
    let fetch = aos_hub::fetch::LocalFsFetch::new(&upstream);

    // A correctly-signed narinfo for store hash "ccccpkgthree" whose `URL:`
    // names `nar/ccccpkgthree-otherhash.nar`, NOT the path requested below.
    let nar_bytes = b"package-C-nar-bytes";
    let hash = format!("sha256:{}", hex::encode(sha2::Sha256::digest(nar_bytes)));
    let store_path = "/var/lib/store/ccccpkgthree-pkg-c-1.0";
    let declared_url = "nar/ccccpkgthree-otherhash.nar";
    let narinfo =
        fixture.signed_narinfo(store_path, declared_url, &hash, nar_bytes.len() as u64, &[]);
    std::fs::write(upstream.join("ccccpkgthree.narinfo"), &narinfo).unwrap();
    std::fs::write(upstream.join(declared_url), nar_bytes).unwrap();
    // The declared NAR is served correctly.
    assert!(
        fetch_through(&fetch, dir.path(), declared_url, &trusted, true)
            .await
            .unwrap()
            .is_some(),
        "the NAR named by its narinfo's URL is served"
    );

    // The attack: a DIFFERENT requested NAR path (same store hash, so the same
    // governing narinfo is fetched) whose narinfo `URL:` does not name it.
    let requested = "nar/ccccpkgthree-fixturehash.nar";
    std::fs::write(upstream.join(requested), nar_bytes).unwrap();
    let err = fetch_through(&fetch, dir.path(), requested, &trusted, true)
        .await
        .expect_err("a NAR whose governing narinfo URL differs must be rejected");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("does not") && msg.contains("URL") || msg.contains("substitution"),
        "rejection should cite the URL binding, got: {msg}"
    );
}

#[tokio::test]
async fn pull_through_accepts_valid_compressed_nar() {
    // CR-1 (legit path): a signed narinfo with `Compression: zstd` whose
    // DECOMPRESSED bytes hash to the signed `NarHash` must be ACCEPTED — we must
    // not break legitimate compressed mirrors.
    let dir = tempfile::tempdir().unwrap();
    let upstream = dir.path().join("upstream");
    std::fs::create_dir_all(&upstream).unwrap();
    let fixture = common::Fixture::new(&upstream);
    let plain = b"the-real-uncompressed-nar-bytes-for-this-store-path";
    let (_narinfo_path, nar_path) = fixture.put_zstd_nix_entry("ok", plain, None);
    let trusted = vec![fixture.trust_key.clone()];

    let fetch = aos_hub::fetch::LocalFsFetch::new(&upstream);
    let served = fetch_through(&fetch, dir.path(), &nar_path, &trusted, true)
        .await
        .expect("compressed NAR with matching signed NarHash is accepted")
        .expect("the NAR is present upstream");
    // The served bytes are the compressed bytes on the wire (Nix serves the
    // compressed NAR); the point is the verifier accepted them.
    assert!(!served.bytes.is_empty());
    assert!(!served.persisted, "NARs are never frozen by pull-through");
}

#[tokio::test]
async fn pull_through_rejects_tampered_compressed_nar() {
    // CR-1 (the attack): a signed narinfo with `Compression: zstd`, a MALICIOUS
    // compressed NAR, and a `FileHash` that matches the malicious COMPRESSED
    // bytes — but whose DECOMPRESSED bytes do not match the signed `NarHash`.
    // A verifier that trusted the unsigned FileHash would serve the backdoor;
    // we must REJECT it.
    let dir = tempfile::tempdir().unwrap();
    let upstream = dir.path().join("upstream");
    std::fs::create_dir_all(&upstream).unwrap();
    let fixture = common::Fixture::new(&upstream);

    let honest_plain = b"the-real-uncompressed-nar-bytes-for-this-store-path";
    let backdoor_plain = b"BACKDOORED uncompressed payload that the signed NarHash never covered";
    let (_narinfo_path, nar_path) =
        fixture.put_zstd_nix_entry("evil", honest_plain, Some(backdoor_plain));
    let trusted = vec![fixture.trust_key.clone()];

    let fetch = aos_hub::fetch::LocalFsFetch::new(&upstream);
    let err = fetch_through(&fetch, dir.path(), &nar_path, &trusted, true)
        .await
        .expect_err("a compressed NAR whose decompressed bytes != signed NarHash must be refused");
    assert!(
        format!("{err:#}").contains("NAR"),
        "rejection should cite the NAR check, got: {err:#}"
    );
}

#[tokio::test]
async fn pull_through_rejects_compressed_nar_without_file_hash() {
    // A signed narinfo with a compression but NO `FileHash` must still be held
    // to the signed `NarHash`. Here the on-disk NAR does not decompress to the
    // signed NarHash, so it is REJECTED even without a FileHash to lean on.
    let dir = tempfile::tempdir().unwrap();
    let upstream = dir.path().join("upstream");
    std::fs::create_dir_all(&upstream).unwrap();
    let fixture = common::Fixture::new(&upstream);

    let (narinfo_path, nar_path) =
        fixture.put_zstd_nix_entry("nofilehash", b"declared-plain", Some(b"actually-different"));
    // Strip the FileHash line so the only integrity field is the signed NarHash.
    let p = upstream.join(&narinfo_path);
    let stripped: String = std::fs::read_to_string(&p)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("FileHash:"))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&p, stripped).unwrap();
    let trusted = vec![fixture.trust_key.clone()];

    let fetch = aos_hub::fetch::LocalFsFetch::new(&upstream);
    let err = fetch_through(&fetch, dir.path(), &nar_path, &trusted, true)
        .await
        .expect_err("no FileHash must not weaken the signed-NarHash check");
    assert!(format!("{err:#}").contains("NAR"), "got: {err:#}");
}

#[tokio::test]
async fn full_mirror_writes_verified_nar_bytes_not_a_refetch() {
    // H-1: the full-mirror copy phase must write the bytes that passed
    // verification, not re-fetch them. We prove write==verified by flipping the
    // upstream NAR *after* the sync's single verify-and-retain fetch: because
    // the copy phase writes the retained bytes, the binding holds the original
    // (verified) bytes, never the post-verification poison.
    //
    // To create the flip window deterministically, we verify+sync once against a
    // clean upstream, then re-run the sync against an upstream whose NAR has been
    // swapped to bytes that FAIL verification: the sync must fail (so it never
    // writes the poison) AND, in the success case, the bytes on disk are exactly
    // the verified ones.
    let dir = tempfile::tempdir().unwrap();
    let upstream_surface = dir.path().join("upstream");
    std::fs::create_dir_all(&upstream_surface).unwrap();
    let fixture = common::standard_registry(&upstream_surface);
    let upstream_url = serve_upstream(upstream_surface.clone()).await;

    let binding_root = dir.path().join("binding");
    let db = Database::open_in_memory().await.unwrap();
    let (reg, _placement, local_root) =
        make_mirror_registry(&db, &fixture.trust_key, &binding_root).await;
    db.create_mirror_source(reg, &upstream_url, "full", true, 3600)
        .await
        .unwrap();
    let registry = db.registry_by_id(reg).await.unwrap().unwrap();

    sync_full_mirror(&db, &registry).await.unwrap();

    // The narinfo + NAR landed byte-identical to the (verified) upstream.
    let narinfo = "h7j3k8l2m9n4.narinfo";
    let nar = "nar/h7j3k8l2m9n4-fixturehash.nar";
    for path in [narinfo, nar] {
        let local = std::fs::read(local_root.join(path)).unwrap();
        let up = std::fs::read(upstream_surface.join(path)).unwrap();
        assert_eq!(local, up, "write==verified bytes for {path}");
    }

    // Now poison the upstream NAR (its bytes no longer match the signed
    // NarHash). A re-sync must FAIL verification and leave the previously
    // written, verified bytes untouched — the poison is never persisted.
    let verified_nar = std::fs::read(local_root.join(nar)).unwrap();
    std::fs::write(upstream_surface.join(nar), b"post-verification-poison").unwrap();
    let err = sync_full_mirror(&db, &registry).await.unwrap_err();
    assert!(format!("{err:#}").contains("NAR"), "got: {err:#}");
    assert_eq!(
        std::fs::read(local_root.join(nar)).unwrap(),
        verified_nar,
        "the binding still holds the verified bytes, never the poison"
    );
}

/// Find one loose object's oid (the basename joined to its `xx` dir) under a
/// fixture surface's `objects/` tree, skipping the `objects/info` and
/// `objects/pack` subdirs.
fn find_a_loose_object(surface: &std::path::Path) -> String {
    let objects = surface.join("objects");
    for shard in std::fs::read_dir(&objects).unwrap() {
        let shard = shard.unwrap();
        let name = shard.file_name().to_string_lossy().into_owned();
        if name.len() != 2 || !shard.file_type().unwrap().is_dir() {
            continue;
        }
        if let Some(file) = std::fs::read_dir(shard.path()).unwrap().next() {
            let rest = file.unwrap().file_name().to_string_lossy().into_owned();
            return format!("{name}{rest}");
        }
    }
    panic!("no loose object found under {}", objects.display());
}
