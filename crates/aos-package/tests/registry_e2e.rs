mod common;

use anyhow::Result;
use aos_package::registry::{Registry, git, keys, store_path_hash};
use aos_package::registry_ops::resolve_mirrors_for_registry;
use aos_package::security::verify_tag_signature;
use aos_package::types::{CacheEntry, RegistryState, TrackingMode};

use common::{RegistryFixture, StaticHttpServer};

fn publish_release(
    fixture: &RegistryFixture,
    version: &str,
    channel: &str,
) -> Result<(String, String, Vec<u8>)> {
    let store_path = fixture.write_package("hello", version)?;
    fixture.write_closure(&store_path)?;
    let commit = fixture.commit_all(&format!("release {version}"))?;
    fixture.signed_tag(version, "HEAD")?;
    let channel_tag = fixture.signed_channel_tag_bytes(channel, version)?;
    fixture.set_branch(channel, "HEAD")?;
    fixture.publish_bare_origin()?;
    Ok((store_path, commit, channel_tag))
}

#[tokio::test]
async fn fixture_syncs_git_native_registry_over_static_http() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    fixture.write_registry_toml_with_caches(&[
        ("https://cache-low.example/nar", 50),
        ("https://cache-high.example/nar", 900),
    ])?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    let store_path = fixture.write_package("hello", "1.0.0")?;
    fixture.write_closure(&store_path)?;
    let source_commit = fixture.commit_all("release 1.0.0")?;
    let release_tag = fixture.signed_tag("1.0.0", "HEAD")?;

    assert_eq!(source_commit.len(), 64);
    assert_eq!(release_tag.len(), 64);
    assert!(verify_tag_signature(
        fixture.source_path(),
        "1.0.0",
        fixture.trusted_key(),
    )?);

    fixture.publish_bare_origin()?;
    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = fixture.registry_config(server.base_url());
    let mut state = RegistryState::default();
    let result = git::sync_git(
        &config,
        &TrackingMode::Branch("main".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &mut state,
        &fixture.printer(),
    )
    .await?;

    assert_eq!(result.new_commit, source_commit);
    assert_eq!(result.packages_added, 1);
    assert_eq!(state.last_commit.as_deref(), Some(source_commit.as_str()));
    assert!(state.last_update.is_some());
    assert!(
        fixture
            .cache_dir()
            .join("aos-core/packages/h/hello.toml")
            .exists()
    );
    assert!(
        fixture
            .registries_dir()
            .join("aos-core/registry.toml")
            .exists()
    );

    let registry = Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?;
    let package = registry.get("hello").expect("synced package exists");
    assert_eq!(package.version, "1.0.0");
    assert_eq!(package.store_path, store_path);

    let saved = fixture.assert_state_roundtrip(&state)?;
    assert_eq!(saved.last_commit, state.last_commit);
    assert_eq!(saved.last_update, state.last_update);
    Ok(())
}

#[tokio::test]
async fn signed_channel_http_e2e_advances_persisted_bucket() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    fixture.write_registry_toml_with_caches(&[
        ("https://cache-low.example/nar", 50),
        ("https://cache-high.example/nar", 900),
    ])?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    let v1_store_path = fixture.write_package("hello", "1.0.0")?;
    fixture.write_closure(&v1_store_path)?;
    let v1_commit = fixture.commit_all("release 1.0.0")?;
    fixture.signed_tag("1.0.0", "HEAD")?;
    let v1_channel_tag = fixture.signed_channel_tag_bytes("stable", "1.0.0")?;
    fixture.set_branch("stable", "HEAD")?;
    fixture.publish_bare_origin()?;
    fixture.write_all_channel_partitions("stable", &v1_channel_tag)?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let mut config = fixture.signed_registry_config(server.base_url(), "stable");
    config.caches.push(CacheEntry {
        url: "https://client-cache.example/nar".into(),
        priority: 1200,
    });
    let mut state = RegistryState::default();
    let first = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &mut state,
        &fixture.printer(),
    )
    .await?;

    assert_eq!(first.new_commit, v1_commit);
    assert_eq!(state.floor.as_deref(), Some("1.0.0"));
    assert!(state.bucket.is_some());
    assert_eq!(state.retained, vec!["1.0.0"]);
    let assigned_bucket = state.bucket.expect("bucket persisted after first sync");

    let v2_store_path = fixture.write_package("hello", "1.1.0")?;
    fixture.write_closure(&v2_store_path)?;
    let v2_commit = fixture.commit_all("release 1.1.0")?;
    fixture.signed_tag("1.1.0", "HEAD")?;
    let v2_channel_tag = fixture.signed_channel_tag_bytes("stable", "1.1.0")?;
    fixture.set_branch("stable", "HEAD")?;
    fixture.publish_bare_origin()?;
    fixture.write_channel_partition("stable", assigned_bucket, &v2_channel_tag)?;

    let second = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &mut state,
        &fixture.printer(),
    )
    .await?;

    assert_eq!(second.new_commit, v2_commit);
    assert_eq!(second.packages_updated, 1);
    assert_eq!(state.bucket, Some(assigned_bucket));
    assert_eq!(state.floor.as_deref(), Some("1.1.0"));
    assert_eq!(state.retained, vec!["1.0.0", "1.1.0"]);
    assert_eq!(state.last_commit.as_deref(), Some(v2_commit.as_str()));

    let registry = Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?;
    let package = registry.get("hello").expect("synced package exists");
    assert_eq!(package.version, "1.1.0");
    assert_eq!(package.store_path, v2_store_path);
    let store_hash = store_path_hash(&v2_store_path);
    let closure = registry
        .get_closure(store_hash)
        .expect("closure was materialized from the committed tree");
    assert!(closure.contains(store_hash));

    let registry_root = fixture.registries_dir().join("aos-core");
    assert!(registry_root.join("registry.toml").exists());
    assert!(registry_root.join("keys.toml").exists());
    assert!(registry_root.join(".gitattributes").exists());
    let roster = keys::load_keys_toml(&registry_root)?.expect("keys.toml loaded");
    assert_eq!(roster.active.len(), 1);
    assert_eq!(roster.active[0].key, fixture.trusted_key());
    let mirrors = resolve_mirrors_for_registry(&registry_root, &config);
    let mirror_urls: Vec<&str> = mirrors.iter().map(|cache| cache.url.as_str()).collect();
    assert_eq!(
        mirror_urls,
        vec![
            "https://client-cache.example/nar",
            "https://cache-high.example/nar",
            "https://cache-low.example/nar",
        ],
    );

    let saved = fixture.assert_state_roundtrip(&state)?;
    assert_eq!(saved.floor, state.floor);
    assert_eq!(saved.bucket, state.bucket);
    assert_eq!(saved.retained, state.retained);
    Ok(())
}

#[tokio::test]
async fn channel_rollout_e2e_enforces_safety_gates_and_fix_forward() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 100)])?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    let (_, v1_commit, v1_channel_tag) = publish_release(&fixture, "1.0.0", "stable")?;
    let bad_name_tag = fixture.signed_channel_tag_bytes("wrong", "1.0.0")?;
    fixture.write_channel_partition("stable", 42, &bad_name_tag)?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = fixture.signed_registry_config(server.base_url(), "stable");
    let mut state = RegistryState {
        bucket: Some(42),
        ..RegistryState::default()
    };
    let err = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &mut state,
        &fixture.printer(),
    )
    .await
    .expect_err("bad embedded channel tag name is rejected");
    assert!(format!("{err:#}").contains("name-binding mismatch"));

    fixture.write_channel_partition("stable", 43, &v1_channel_tag)?;
    let first = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &mut state,
        &fixture.printer(),
    )
    .await?;
    assert_eq!(first.new_commit, v1_commit);
    assert_eq!(state.bucket, Some(42));
    assert_eq!(state.floor.as_deref(), Some("1.0.0"));

    let (_, v2_commit, v2_channel_tag) = publish_release(&fixture, "1.1.0", "stable")?;
    fixture.write_channel_partition("stable", 42, &v2_channel_tag)?;
    let second = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &mut state,
        &fixture.printer(),
    )
    .await?;
    assert_eq!(second.new_commit, v2_commit);
    assert_eq!(state.floor.as_deref(), Some("1.1.0"));
    assert_eq!(state.retained, vec!["1.0.0", "1.1.0"]);

    fixture.write_channel_partition("stable", 42, &v1_channel_tag)?;
    let err = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &mut state,
        &fixture.printer(),
    )
    .await
    .expect_err("rollback below semver floor is rejected");
    assert!(format!("{err:#}").contains("rollback refused"));
    assert_eq!(state.floor.as_deref(), Some("1.1.0"));

    let (v3_store_path, v3_commit, v3_channel_tag) =
        publish_release(&fixture, "1.2.0-beta.1+exp.sha", "stable")?;
    fixture.write_channel_partition("stable", 42, &v3_channel_tag)?;
    let third = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &mut state,
        &fixture.printer(),
    )
    .await?;
    assert_eq!(third.new_commit, v3_commit);
    assert_eq!(state.floor.as_deref(), Some("1.2.0-beta.1+exp.sha"));
    let registry = Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?;
    let package = registry.get("hello").expect("synced package exists");
    assert_eq!(package.version, "1.2.0-beta.1+exp.sha");
    assert_eq!(package.store_path, v3_store_path);
    Ok(())
}

#[tokio::test]
async fn channel_first_sync_fails_closed_when_no_partition_is_usable() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 100)])?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    publish_release(&fixture, "1.0.0", "stable")?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = fixture.signed_registry_config(server.base_url(), "stable");
    let mut state = RegistryState::default();
    let err = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &mut state,
        &fixture.printer(),
    )
    .await
    .expect_err("missing first-sync partitions fail closed");
    let message = format!("{err:#}");
    assert!(message.contains("no previous successful freshness observation"));
    assert!(message.contains("no usable partition"));
    Ok(())
}
