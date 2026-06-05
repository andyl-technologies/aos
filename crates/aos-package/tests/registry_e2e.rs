mod common;

use anyhow::Result;
use aos_package::registry::{Registry, git};
use aos_package::security::verify_tag_signature;
use aos_package::types::{RegistryState, TrackingMode};

use common::{RegistryFixture, StaticHttpServer};

#[tokio::test]
async fn fixture_syncs_git_native_registry_over_static_http() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    fixture.write_registry_toml("file:///fixture-cache")?;
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
