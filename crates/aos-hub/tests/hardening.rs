//! Hardening and spec-feature integration tests: symlink containment,
//! anti-rollback floors, stale-vs-failed classification, incremental
//! channel refresh, and presence validation.

mod common;

use std::path::Path;

use aos_hub::db::Database;
use aos_hub::fetch::{fetch_for_url, is_fetch_error, LocalFsFetch, SurfaceFetch};
use aos_hub::indexer::index_and_record;
use aos_hub::validation::validate_presence;

/// Like `common::standard_registry` but with a custom committed
/// `[[caches]]` list, for validation tests that need local cache dirs.
fn registry_with_caches(root: &Path, caches: &[(&str, u32)]) -> common::Fixture {
    let fixture = common::Fixture::new(root);

    let mut registry_text =
        String::from("[registry]\nname = \"demo\"\ndescription = \"Fixture registry\"\n");
    for (url, priority) in caches {
        registry_text.push_str(&format!(
            "\n[[caches]]\nurl = \"{url}\"\npriority = {priority}\n"
        ));
    }
    let registry_toml = fixture.put_blob(&registry_text);
    let keys_toml = fixture.put_blob(&format!(
        "schema = 1\n\n[[keys]]\nid = \"maintainer\"\nkey = \"{}\"\n",
        fixture.trust_key,
    ));
    let curl_toml = fixture.put_blob(
        "[package]\nname = \"curl\"\ndescription = \"URL transfers\"\nlicense = \"MIT\"\n\
         maintainer = \"aos\"\n\n[[versions]]\nversion = \"8.5.0\"\n\n\
         [versions.platforms.x86_64-linux]\nstore_path = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0\"\n\
         nar_hash = \"sha256:aa\"\nnar_size = 10\nclosure_size = 20\n\
         source_drv = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0.drv\"\n\
         source_nar_hash = \"sha256:bb\"\nreferences = []\n",
    );
    let closure_blob = fixture.put_blob("h7j3k8l2m9n4\n");

    let bucket_c = fixture.put_tree(&[("100644", "curl.toml", curl_toml)]);
    let packages = fixture.put_tree(&[("40000", "c", bucket_c)]);
    let closures = fixture.put_tree(&[("100644", "h7j3k8l2m9n4", closure_blob)]);
    let root_tree = fixture.put_tree(&[
        ("100644", "keys.toml", keys_toml),
        ("100644", "registry.toml", registry_toml),
        ("40000", "closures", closures),
        ("40000", "packages", packages),
    ]);

    let commit = fixture.put_signed_commit(root_tree, "release 1.0.0");
    let release_tag = fixture.put_release_tag("1.0.0", commit);
    fixture.put_channel("stable", release_tag);
    fixture.put_refs(
        "stable",
        &[("stable", commit)],
        &[("1.0.0", release_tag, commit)],
    );
    fixture
}

async fn register(db: &Database, fixture: &common::Fixture, surface: &Path) {
    db.register_registry(
        "demo",
        surface.to_str().unwrap(),
        std::slice::from_ref(&fixture.trust_key),
        true,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn symlink_escape_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    common::standard_registry(&surface);

    // A secret outside the surface, reachable via a planted symlink.
    let secret = dir.path().join("secret");
    std::fs::write(&secret, b"private key material").unwrap();
    std::fs::create_dir_all(surface.join("objects/zz")).unwrap();
    std::os::unix::fs::symlink(&secret, surface.join("objects/zz/secret")).unwrap();

    let fetch = LocalFsFetch::new(&surface);
    let err = fetch.fetch("objects/zz/secret").await.unwrap_err();
    assert!(is_fetch_error(&err), "got: {err:#}");
    assert!(
        err.to_string().contains("escapes"),
        "must not return the linked-to contents: {err:#}"
    );
}

#[tokio::test]
async fn channel_rollback_fails_closed() {
    let dir = tempfile::tempdir().unwrap();

    // First surface releases 1.0.0; the floor rises to it.
    let surface_a = dir.path().join("a");
    std::fs::create_dir_all(&surface_a).unwrap();
    let fixture_a = common::standard_registry_versioned(&surface_a, "1.0.0");
    let db = Database::open_in_memory().await.unwrap();
    register(&db, &fixture_a, &surface_a).await;
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    index_and_record(&db, &LocalFsFetch::new(&surface_a), &registry)
        .await
        .unwrap();
    assert_eq!(
        db.channel_floor(registry.id, "stable")
            .await
            .unwrap()
            .as_deref(),
        Some("1.0.0")
    );

    // The same slug re-registered at a surface whose channel frontier is
    // *older* must be rejected as a rollback.
    let surface_b = dir.path().join("b");
    std::fs::create_dir_all(&surface_b).unwrap();
    let fixture_b = common::standard_registry_versioned(&surface_b, "0.9.0");
    register(&db, &fixture_b, &surface_b).await;
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let err = index_and_record(&db, &LocalFsFetch::new(&surface_b), &registry)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("rollback"), "got: {err:#}");

    let status = db.index_status(registry.id).await.unwrap().unwrap();
    assert_eq!(status.state, "failed");
    // The floor never lowers.
    assert_eq!(
        db.channel_floor(registry.id, "stable")
            .await
            .unwrap()
            .as_deref(),
        Some("1.0.0")
    );
}

#[tokio::test]
async fn unreachable_source_marks_stale_not_failed() {
    let db = Database::open_in_memory().await.unwrap();
    // Port 1 is essentially never bound; connection is refused immediately.
    db.register_registry("demo", "http://127.0.0.1:1", &[], true)
        .await
        .unwrap();
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let fetch =
        aos_hub::coreports::into_core_fetch(fetch_for_url(&registry.source_url).await.unwrap());

    let err = index_and_record(&db, fetch.as_ref(), &registry)
        .await
        .unwrap_err();
    assert!(is_fetch_error(&err), "got: {err:#}");
    let status = db.index_status(registry.id).await.unwrap().unwrap();
    assert_eq!(status.state, "stale");
    assert!(status.error.is_some());
}

#[tokio::test]
async fn unchanged_refs_take_incremental_path() {
    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::standard_registry(&surface);
    // The per-release pack listing exists, so pack presence is recorded.
    std::fs::create_dir_all(surface.join("releases/1/0/0/objects/info")).unwrap();
    std::fs::write(
        surface.join("releases/1/0/0/objects/info/packs"),
        "P pack-aaaa.pack\n",
    )
    .unwrap();

    let db = Database::open_in_memory().await.unwrap();
    register(&db, &fixture, &surface).await;
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    let fetch = LocalFsFetch::new(&surface);

    let first = index_and_record(&db, &fetch, &registry).await.unwrap();
    assert!(!first.incremental, "first index must do the full walk");
    assert!(
        db.list_releases(registry.id).await.unwrap()[0].pack_present,
        "full walk records pack presence"
    );

    let second = index_and_record(&db, &fetch, &registry).await.unwrap();
    assert!(
        second.incremental,
        "unchanged refs must refresh incrementally"
    );
    assert_eq!(second.commit, first.commit);
    assert_eq!(second.packages, first.packages);
    assert_eq!(second.releases, first.releases);
    assert_eq!(second.channels, 1);

    // The index is still fresh and the channels still correct.
    let status = db.index_status(registry.id).await.unwrap().unwrap();
    assert_eq!(status.state, "fresh");
    let channels = db.list_channels(registry.id).await.unwrap();
    assert_eq!(channels[0].frontier.as_deref(), Some("1.0.0"));
    assert_eq!(channels[0].partitions.iter().flatten().count(), 256);
}

#[tokio::test]
async fn presence_validation_records_coverage_and_findings() {
    let dir = tempfile::tempdir().unwrap();

    // A complete file:// cache, an incomplete one, and an unreachable
    // HTTP endpoint.
    let good_cache = dir.path().join("good-cache");
    std::fs::create_dir_all(&good_cache).unwrap();
    std::fs::write(
        good_cache.join("h7j3k8l2m9n4.narinfo"),
        "StorePath: /var/lib/store/h7j3k8l2m9n4-curl-8.5.0\n",
    )
    .unwrap();
    let bad_cache = dir.path().join("bad-cache");
    std::fs::create_dir_all(&bad_cache).unwrap();

    let good_url = format!("file://{}", good_cache.display());
    let bad_url = format!("file://{}", bad_cache.display());
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = registry_with_caches(
        &surface,
        &[
            (good_url.as_str(), 50),
            (bad_url.as_str(), 40),
            ("http://127.0.0.1:1/", 30),
        ],
    );

    let db = Database::open_in_memory().await.unwrap();
    register(&db, &fixture, &surface).await;
    let registry = db.registry_by_slug("demo").await.unwrap().unwrap();
    index_and_record(&db, &LocalFsFetch::new(&surface), &registry)
        .await
        .unwrap();

    let summaries = validate_presence(&db, &registry).await.unwrap();
    assert_eq!(summaries.len(), 3);

    let good = &summaries[0];
    assert_eq!(good.cache_url, good_url);
    assert!(good.reachable);
    assert_eq!(good.checked, 1);
    assert_eq!(good.missing, 0);
    assert_eq!(good.coverage_percent, 100.0);

    let bad = &summaries[1];
    assert_eq!(bad.cache_url, bad_url);
    assert!(bad.reachable);
    assert_eq!(bad.checked, 1);
    assert_eq!(bad.missing, 1);
    assert_eq!(bad.coverage_percent, 0.0);

    let dead = &summaries[2];
    assert_eq!(dead.cache_url, "http://127.0.0.1:1/");
    assert!(!dead.reachable);
    assert_eq!(dead.checked, 0);

    // Runs and findings are persisted.
    let runs = db.latest_validation_runs(registry.id).await.unwrap();
    assert_eq!(runs.len(), 3);
    let bad_run = runs.iter().find(|r| r.cache_url == bad_url).unwrap();
    assert_eq!(bad_run.missing, 1);
    assert_eq!(
        db.validation_missing(bad_run.id).await.unwrap(),
        vec!["h7j3k8l2m9n4".to_string()]
    );
    let dead_run = runs
        .iter()
        .find(|r| r.cache_url == "http://127.0.0.1:1/")
        .unwrap();
    assert!(!dead_run.reachable);
    assert_eq!(dead_run.checked, 0);
}

#[tokio::test]
async fn closure_cap_aborts_oversized_index() {
    use aos_hub::surface::load::{load_registry_tree, MAX_CLOSURE_ENTRIES};
    use aos_hub::surface::object::ObjectKind;

    let dir = tempfile::tempdir().unwrap();
    let surface = dir.path().join("surface");
    std::fs::create_dir_all(&surface).unwrap();
    let fixture = common::Fixture::new(&surface);

    // A minimal but valid tree whose single closures file carries more
    // adjacency lines than the cap. Each line is a distinct head hash so it
    // contributes one map entry; the loader must abort before reading them all.
    let registry_toml =
        fixture.put_blob("[registry]\nname = \"demo\"\ndescription = \"Fixture\"\n");
    let mut closure_text = String::with_capacity((MAX_CLOSURE_ENTRIES + 1) * 9);
    for i in 0..=MAX_CLOSURE_ENTRIES {
        closure_text.push_str(&format!("h{i:08x}\n"));
    }
    let closure_blob = fixture.put_object(ObjectKind::Blob, closure_text.as_bytes());
    let closures = fixture.put_tree(&[("100644", "all", closure_blob)]);
    let root_tree = fixture.put_tree(&[
        ("100644", "registry.toml", registry_toml),
        ("40000", "closures", closures),
    ]);
    let commit = fixture.put_signed_commit(root_tree, "oversized closures");

    let err = load_registry_tree(&LocalFsFetch::new(&surface), commit)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("closure cap"),
        "must abort over the closure cap, got: {err:#}"
    );

    // A small tree well under the caps still loads cleanly.
    let ok_surface = dir.path().join("ok");
    std::fs::create_dir_all(&ok_surface).unwrap();
    let ok = common::Fixture::new(&ok_surface);
    let ok_registry = ok.put_blob("[registry]\nname = \"demo\"\ndescription = \"Fixture\"\n");
    let ok_curl = ok.put_blob(
        "[package]\nname = \"curl\"\ndescription = \"URL transfers\"\nlicense = \"MIT\"\n\
         maintainer = \"aos\"\n\n[[versions]]\nversion = \"8.5.0\"\n\n\
         [versions.platforms.x86_64-linux]\nstore_path = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0\"\n\
         nar_hash = \"sha256:aa\"\nnar_size = 10\nclosure_size = 20\n\
         source_drv = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0.drv\"\n\
         source_nar_hash = \"sha256:bb\"\nreferences = []\n",
    );
    let ok_bucket = ok.put_tree(&[("100644", "curl.toml", ok_curl)]);
    let ok_packages = ok.put_tree(&[("40000", "c", ok_bucket)]);
    let ok_closure = ok.put_blob("h7j3k8l2m9n4\n");
    let ok_closures = ok.put_tree(&[("100644", "h7j3k8l2m9n4", ok_closure)]);
    let ok_root = ok.put_tree(&[
        ("100644", "registry.toml", ok_registry),
        ("40000", "closures", ok_closures),
        ("40000", "packages", ok_packages),
    ]);
    let ok_commit = ok.put_signed_commit(ok_root, "small tree");
    let tree = load_registry_tree(&LocalFsFetch::new(&ok_surface), ok_commit)
        .await
        .unwrap();
    assert_eq!(tree.packages.len(), 1, "small tree loads its packages");
}
