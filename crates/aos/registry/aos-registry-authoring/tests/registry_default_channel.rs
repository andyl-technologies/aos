//! End-to-end default-channel selection over local registry transports.

mod common;

use std::fs;

use anyhow::Result;
use aos_registry_client::registry::{Registry, git, transport::RegistryTransport};
use aos_registry_format::consumer::{RegistryConfig, RegistryState, TrackingMode};
use common::RegistryFixture;

fn publish_release(fixture: &RegistryFixture, version: &str, channel: &str) -> Result<String> {
    let store_path = fixture.write_package("hello", version)?;
    fixture.write_closure(&store_path)?;
    fixture.commit_all(&format!("release {version}"))?;
    aos_registry_authoring::registry::tuf::write_release_metadata_worktree(
        fixture.source_path(),
        fixture.name(),
        &semver::Version::parse(version)?,
        &[aos_registry_authoring::registry::tuf::MetadataSigningKey {
            key_id: "initial".into(),
            key_path: fixture.private_key_path().to_path_buf(),
            key: fixture.trusted_key().to_string(),
            role_key: true,
        }],
    )?;
    let commit = fixture.commit_all(&format!("release metadata {version}"))?;
    fixture.signed_tag(version, "HEAD")?;
    let partition = fixture.signed_channel_tag_bytes(channel, version)?;
    fixture.set_branch(channel, "HEAD")?;
    fixture.publish_bare_origin()?;
    fixture.write_all_channel_partitions(channel, &partition)?;
    Ok(commit)
}

fn initialize(fixture: &RegistryFixture) -> Result<String> {
    fixture.write_registry_toml("https://cache.example/nar")?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    let commit = publish_release(fixture, "1.0.0", "stable")?;
    set_default_channel(fixture.origin_path(), "stable")?;
    Ok(commit)
}

fn set_default_channel(path: &std::path::Path, channel: &str) -> Result<()> {
    git2::Repository::open(path)?.reference_symbolic(
        "HEAD",
        &format!("refs/heads/{channel}"),
        true,
        "fixture default channel",
    )?;
    Ok(())
}

async fn sync(
    fixture: &RegistryFixture,
    config: &RegistryConfig,
    tracking: &TrackingMode,
    state: &mut RegistryState,
) -> Result<aos_registry_client::sync::SyncResult> {
    git::sync_git(
        config,
        tracking,
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        state,
        &fixture.printer(),
    )
    .await
}

#[tokio::test]
async fn default_channel_local_paths_and_file_urls_verify_signed_release() -> Result<()> {
    for file_url in [false, true] {
        let fixture = RegistryFixture::new("local-default")?;
        let expected_commit = initialize(&fixture)?;
        let origin = if file_url {
            url::Url::from_directory_path(fixture.origin_path())
                .unwrap()
                .to_string()
        } else {
            fixture.origin_path().to_str().unwrap().to_string()
        };
        let mut config = fixture.signed_registry_config(origin, "stable");
        config.channel = None;
        let mut state = RegistryState::default();

        let result = sync(&fixture, &config, &TrackingMode::Default, &mut state).await?;

        assert_eq!(result.new_commit, expected_commit);
        assert_eq!(state.selected_channel.as_deref(), Some("stable"));
        assert_eq!(state.default_channel.as_deref(), Some("stable"));
        assert_eq!(state.floor.as_deref(), Some("1.0.0"));
        assert!(state.bucket.is_some());
        let persisted = fixture.assert_state_roundtrip(&state)?;
        assert_eq!(persisted.selected_channel, state.selected_channel);
        assert_eq!(persisted.default_channel, state.default_channel);
        let registry = Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?;
        assert_eq!(registry.get("hello").unwrap().version, "1.0.0");
        assert_eq!(registry.release_trust().unwrap().release_tag, "1.0.0");
    }
    Ok(())
}

#[tokio::test]
async fn exported_file_surface_without_git_configuration_verifies_default_channel() -> Result<()> {
    for file_url in [false, true] {
        let fixture = RegistryFixture::new("exported-default")?;
        let expected_commit = initialize(&fixture)?;
        // APR exports the static reference/object namespace without Git's
        // repository configuration. Native local fetch would assume SHA-1.
        fs::remove_file(fixture.origin_path().join("config"))?;
        let origin = if file_url {
            url::Url::from_directory_path(fixture.origin_path())
                .unwrap()
                .to_string()
        } else {
            fixture.origin_path().to_str().unwrap().to_string()
        };
        let mut config = fixture.signed_registry_config(origin, "stable");
        config.channel = None;
        let mut state = RegistryState::default();

        let result = sync(&fixture, &config, &TrackingMode::Default, &mut state).await?;

        assert_eq!(result.new_commit, expected_commit);
        assert_eq!(state.default_channel.as_deref(), Some("stable"));
        assert_eq!(state.floor.as_deref(), Some("1.0.0"));
        assert_eq!(
            Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?
                .get("hello")
                .unwrap()
                .version,
            "1.0.0"
        );
    }
    Ok(())
}

#[tokio::test]
async fn default_channel_ignores_draft_frontier_and_preserves_selected_channel() -> Result<()> {
    let fixture = RegistryFixture::new("draft-default")?;
    let released_commit = initialize(&fixture)?;
    let mut config =
        fixture.signed_registry_config(fixture.origin_path().to_str().unwrap().into(), "stable");
    config.channel = None;
    let mut state = RegistryState::default();
    sync(&fixture, &config, &TrackingMode::Default, &mut state).await?;
    let bucket = state.bucket;

    let draft_path = fixture.write_package("hello", "99.0.0")?;
    fixture.write_closure(&draft_path)?;
    let draft_commit = fixture.commit_all("draft catalog")?;
    fixture.set_branch("draft", "HEAD")?;
    fixture.set_branch("stable", "HEAD")?;
    fixture.publish_bare_origin()?;

    let result = sync(&fixture, &config, &TrackingMode::Default, &mut state).await?;

    assert_eq!(result.new_commit, released_commit);
    assert_ne!(result.new_commit, draft_commit);
    assert_eq!(state.bucket, bucket);
    assert_eq!(state.floor.as_deref(), Some("1.0.0"));
    assert_eq!(
        state.last_roster_commit.as_deref(),
        Some(draft_commit.as_str())
    );
    assert_eq!(
        Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?
            .get("hello")
            .unwrap()
            .version,
        "1.0.0"
    );

    // An unauthenticated HEAD change cannot switch an established consumer.
    set_default_channel(fixture.origin_path(), "draft")?;
    let result = sync(&fixture, &config, &TrackingMode::Default, &mut state).await?;
    assert_eq!(result.new_commit, released_commit);
    assert_eq!(state.selected_channel.as_deref(), Some("stable"));
    assert_eq!(state.default_channel.as_deref(), Some("stable"));
    Ok(())
}

#[tokio::test]
async fn removing_explicit_selector_discovers_the_origin_default_channel() -> Result<()> {
    let fixture = RegistryFixture::new("configured-default")?;
    let expected_commit = initialize(&fixture)?;
    let edge_partition = fixture.signed_channel_tag_bytes("edge", "1.0.0")?;
    fixture.set_branch("edge", "HEAD")?;
    fixture.publish_bare_origin()?;
    fixture.write_all_channel_partitions("edge", &edge_partition)?;
    let mut config =
        fixture.signed_registry_config(fixture.origin_path().to_str().unwrap().into(), "edge");
    let mut state = RegistryState::default();

    sync(&fixture, &config, &config.tracking_mode()?, &mut state).await?;
    assert_eq!(state.selected_channel.as_deref(), Some("edge"));
    assert_eq!(state.default_channel, None);

    config.channel = None;
    let result = sync(&fixture, &config, &config.tracking_mode()?, &mut state).await?;

    assert_eq!(result.new_commit, expected_commit);
    assert_eq!(state.selected_channel.as_deref(), Some("stable"));
    assert_eq!(state.default_channel.as_deref(), Some("stable"));
    Ok(())
}

#[tokio::test]
async fn nonbare_origin_uses_git_directory_for_partitions() -> Result<()> {
    let fixture = RegistryFixture::new("working-default")?;
    let expected_commit = initialize(&fixture)?;
    set_default_channel(fixture.source_path(), "stable")?;
    let repository = git2::Repository::open(fixture.source_path())?;
    let partitions = repository.path().join("channels/stable");
    fs::create_dir_all(&partitions)?;
    for entry in fs::read_dir(fixture.origin_path().join("channels/stable"))? {
        let entry = entry?;
        fs::copy(entry.path(), partitions.join(entry.file_name()))?;
    }
    let mut config =
        fixture.signed_registry_config(fixture.source_path().to_str().unwrap().into(), "stable");
    config.channel = None;
    let mut state = RegistryState::default();

    assert_eq!(
        RegistryTransport::new(&config.url)?
            .default_channel()
            .await?,
        "stable"
    );
    let result = sync(&fixture, &config, &TrackingMode::Default, &mut state).await?;

    assert_eq!(result.new_commit, expected_commit);
    assert_eq!(state.selected_channel.as_deref(), Some("stable"));
    Ok(())
}

#[tokio::test]
async fn exact_tag_and_semver_selection_keep_release_identity() -> Result<()> {
    for tracking in [
        TrackingMode::Tag("1.0.0".into()),
        TrackingMode::Version(semver::VersionReq::parse("=1.0.0")?),
    ] {
        let fixture = RegistryFixture::new("pinned-local")?;
        let expected_commit = initialize(&fixture)?;
        publish_release(&fixture, "1.1.0", "stable")?;
        let config = fixture
            .signed_registry_config(fixture.origin_path().to_str().unwrap().into(), "stable");
        let mut state = RegistryState::default();

        let result = sync(&fixture, &config, &tracking, &mut state).await?;

        assert_eq!(result.new_commit, expected_commit);
        assert_eq!(state.selected_channel, None);
        assert_eq!(
            Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?
                .release_trust()
                .unwrap()
                .release_tag,
            "1.0.0"
        );
    }
    Ok(())
}

#[tokio::test]
async fn default_channel_refuses_missing_or_untrusted_partitions() -> Result<()> {
    let fixture = RegistryFixture::new("untrusted-default")?;
    initialize(&fixture)?;
    let mut config =
        fixture.signed_registry_config(fixture.origin_path().to_str().unwrap().into(), "stable");
    config.channel = None;
    let mut state = RegistryState::default();
    fs::remove_dir_all(fixture.origin_path().join("channels"))?;

    assert!(
        sync(&fixture, &config, &TrackingMode::Default, &mut state)
            .await
            .is_err()
    );
    assert!(state.last_commit.is_none());
    assert!(state.selected_channel.is_none());

    fixture.write_all_channel_partitions("stable", b"unsigned partition")?;
    assert!(
        sync(&fixture, &config, &TrackingMode::Default, &mut state)
            .await
            .is_err()
    );
    assert!(state.last_commit.is_none());
    assert!(state.selected_channel.is_none());
    Ok(())
}
