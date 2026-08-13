//! End-to-end coverage for multi-maintainer registry PKI: any-active-key
//! verification, in-band rotation continuity, revocation with read-only
//! anchor masking, forged-roster rejection, the fail-closed no-anchor
//! default, and roster rollback resistance.

mod common;

use std::fs;
use std::path::Path;

use anyhow::Result;
use common::{RegistryFixture, StaticHttpServer};

use aos_package::registry::git;
use aos_package::registry::{Registry, tuf};
use aos_package::types::{RegistryConfig, RegistryState, SigningConfig, TrackingMode};

/// Branch-tracking config with verification enforced and the given
/// bootstrap anchor.
fn enforced_config(
    fixture: &RegistryFixture,
    url: String,
    anchor: Option<String>,
) -> RegistryConfig {
    let mut config = fixture.registry_config(url);
    config.signing = Some(SigningConfig {
        required: true,
        public_key: anchor,
        root_owner_signers: Vec::new(),
    });
    config
}

async fn sync(
    fixture: &RegistryFixture,
    config: &RegistryConfig,
    state: &mut RegistryState,
) -> Result<git::SyncResult> {
    git::sync_git(
        config,
        &TrackingMode::Branch("main".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        state,
        &fixture.printer(),
    )
    .await
}

fn tuf_signer(id: &str, key: &str, key_path: &Path, role_key: bool) -> tuf::MetadataSigningKey {
    tuf::MetadataSigningKey {
        key_id: id.to_string(),
        key_path: key_path.to_path_buf(),
        key: key.to_string(),
        role_key,
    }
}

fn fixture_tuf_signer(
    fixture: &RegistryFixture,
    id: &str,
    role_key: bool,
) -> tuf::MetadataSigningKey {
    tuf_signer(
        id,
        fixture.trusted_key(),
        fixture.private_key_path(),
        role_key,
    )
}

fn commit_tuf_metadata(
    fixture: &RegistryFixture,
    version: &str,
    signers: &[tuf::MetadataSigningKey],
    commit_key: Option<&Path>,
) -> Result<String> {
    let version = semver::Version::parse(version)?;
    let changed = tuf::write_release_metadata_worktree(
        fixture.source_path(),
        fixture.name(),
        &version,
        signers,
    )?;
    assert!(changed, "TUF metadata should change for release {version}");
    let message = format!("registry: update TUF metadata {version}");
    if let Some(key_path) = commit_key {
        fixture.commit_all_with_key(&message, key_path)
    } else {
        fixture.commit_all(&message)
    }
}

/// §11 item 2: a registry with two active roster keys, releases signed
/// alternately by each maintainer; the client syncs and resolves both.
#[tokio::test]
async fn two_maintainer_releases_sync_and_verify() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    let key_a = fixture.trusted_key().to_string();
    let (key_b, key_b_path) = fixture.make_keypair([42_u8; 32], "maintainer_b")?;
    let signer_a = fixture_tuf_signer(&fixture, "a", true);
    let signer_b = tuf_signer("b", &key_b, &key_b_path, true);

    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 50)])?;
    fixture.write_keys_toml_with(&[("a", &key_a), ("b", &key_b)], &[])?;
    fixture.write_package("hello", "1.0.0")?;
    // Maintainer A signs the first release.
    fixture.commit_all("release 1.0.0")?;
    commit_tuf_metadata(
        &fixture,
        "1.0.0",
        &[signer_a.clone(), signer_b.clone()],
        None,
    )?;
    fixture.signed_tag("1.0.0", "HEAD")?;
    fixture.publish_bare_origin()?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = enforced_config(&fixture, server.base_url(), Some(key_a.clone()));
    let mut state = RegistryState::default();
    sync(&fixture, &config, &mut state).await?;

    // Both roster keys are pinned after the first verified sync.
    let pinned = fs::read_to_string(fixture.pinned_keys_path())?;
    assert!(pinned.contains(&key_a), "{pinned}");
    assert!(pinned.contains(&key_b), "{pinned}");

    // Maintainer B signs the second release; the sync verifies it via the
    // pinned roster, not the bootstrap anchor.
    fixture.write_package("world", "1.1.0")?;
    fixture.commit_all_with_key("release 1.1.0", &key_b_path)?;
    let second_commit =
        commit_tuf_metadata(&fixture, "1.1.0", &[signer_a, signer_b], Some(&key_b_path))?;
    fixture.signed_tag_with_key("1.1.0", "HEAD", &key_b_path)?;
    fixture.publish_bare_origin()?;

    let result = sync(&fixture, &config, &mut state).await?;
    assert_eq!(result.new_commit, second_commit);

    let registry = Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?;
    assert!(registry.get("hello").is_some());
    assert!(registry.get("world").is_some());
    Ok(())
}

/// §11 item 3: client pins {A}; a commit signed by A adds B to the
/// roster; the sync pins {A, B} and a head signed by B then verifies.
#[tokio::test]
async fn roster_addition_signed_by_trusted_key_pins_new_key() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    let key_a = fixture.trusted_key().to_string();
    let (key_b, key_b_path) = fixture.make_keypair([43_u8; 32], "maintainer_b")?;
    let signer_a = fixture_tuf_signer(&fixture, "a", true);
    let signer_b = tuf_signer("b", &key_b, &key_b_path, true);

    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 50)])?;
    fixture.write_keys_toml_with(&[("a", &key_a)], &[])?; // roster {A}
    fixture.write_package("hello", "1.0.0")?;
    fixture.commit_all("release 1.0.0")?;
    commit_tuf_metadata(&fixture, "1.0.0", std::slice::from_ref(&signer_a), None)?;
    fixture.publish_bare_origin()?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = enforced_config(&fixture, server.base_url(), Some(key_a.clone()));
    let mut state = RegistryState::default();
    sync(&fixture, &config, &mut state).await?;
    let pinned = fs::read_to_string(fixture.pinned_keys_path())?;
    assert!(pinned.contains(&key_a));
    assert!(!pinned.contains(&key_b));

    // A enrolls B (continuity proof: the enrolling commit is signed by A).
    fixture.write_keys_toml_with(&[("a", &key_a), ("b", &key_b)], &[])?;
    fixture.commit_all("registry: add signing key b")?;
    commit_tuf_metadata(
        &fixture,
        "1.0.1",
        &[signer_a.clone(), signer_b.clone()],
        None,
    )?;
    fixture.publish_bare_origin()?;
    sync(&fixture, &config, &mut state).await?;
    let pinned = fs::read_to_string(fixture.pinned_keys_path())?;
    assert!(pinned.contains(&key_a), "{pinned}");
    assert!(pinned.contains(&key_b), "{pinned}");

    // A head signed by B now verifies.
    fixture.write_package("world", "1.1.0")?;
    fixture.commit_all_with_key("release 1.1.0", &key_b_path)?;
    let head = commit_tuf_metadata(&fixture, "1.1.0", &[signer_a, signer_b], Some(&key_b_path))?;
    fixture.publish_bare_origin()?;
    let result = sync(&fixture, &config, &mut state).await?;
    assert_eq!(result.new_commit, head);
    Ok(())
}

/// §11 item 4 (client half): retiring A vouched by B unpins A, masks an
/// A entry in a read-only anchor directory, and tags signed only by A
/// stop verifying.
#[tokio::test]
async fn retired_key_unpinned_and_masked_in_readonly_anchor() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    let key_a = fixture.trusted_key().to_string();
    let (key_b, key_b_path) = fixture.make_keypair([44_u8; 32], "maintainer_b")?;
    let signer_a = fixture_tuf_signer(&fixture, "a", true);
    let signer_b = tuf_signer("b", &key_b, &key_b_path, true);

    // The image-baked read-only anchor still ships A.
    fixture.write_anchor_keys(&[&key_a])?;

    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 50)])?;
    fixture.write_keys_toml_with(&[("a", &key_a), ("b", &key_b)], &[])?;
    fixture.write_package("hello", "1.0.0")?;
    fixture.commit_all("release 1.0.0")?;
    commit_tuf_metadata(
        &fixture,
        "1.0.0",
        &[signer_a.clone(), signer_b.clone()],
        None,
    )?;
    fixture.signed_tag("1.0.0", "HEAD")?; // signed by A
    fixture.publish_bare_origin()?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = enforced_config(&fixture, server.base_url(), Some(key_a.clone()));
    let mut state = RegistryState::default();
    sync(&fixture, &config, &mut state).await?;

    // Retire A, vouched by B; the retiring commit is signed by B.
    fixture.write_keys_toml_with(&[("b", &key_b)], &["a"])?;
    fixture.commit_all_with_key("registry: retire signing key a", &key_b_path)?;
    let mut transition_a = signer_a;
    transition_a.role_key = false;
    commit_tuf_metadata(
        &fixture,
        "1.0.1",
        &[transition_a, signer_b.clone()],
        Some(&key_b_path),
    )?;
    fixture.publish_bare_origin()?;
    sync(&fixture, &config, &mut state).await?;

    let pinned = fs::read_to_string(fixture.pinned_keys_path())?;
    assert!(pinned.contains(&key_b), "{pinned}");
    assert!(
        pinned.contains(&format!("# revoked: {key_a}")),
        "anchor entry for A must be masked:\n{pinned}"
    );

    // The trusted set no longer contains A, despite the read-only anchor.
    let store = aos_package::security::KeyStore::new(fixture.trusted_keys_dirs());
    let lines: Vec<String> = store
        .lookup_all("aos-core")
        .iter()
        .map(aos_package::security::TrustedKey::key_line)
        .collect();
    assert_eq!(lines, vec![key_b.clone()]);

    // A tag signed only by A no longer verifies against the trusted set.
    assert!(!aos_package::security::verify_tag_signature(
        fixture.source_path(),
        "1.0.0",
        &lines,
    )?);

    // A new head signed by the retired key is rejected.
    fixture.write_package("evil", "1.2.0")?;
    fixture.commit_all("release 1.2.0")?; // fixture default key = A
    fixture.publish_bare_origin()?;
    let err = sync(&fixture, &config, &mut state)
        .await
        .expect_err("head signed by retired key must fail");
    assert!(
        format!("{err:#}").contains("not signed by any trusted key"),
        "{err:#}"
    );
    Ok(())
}

/// §11 item 5: a roster-changing commit signed by a key outside the
/// trusted set aborts the sync and leaves pins and state untouched.
#[tokio::test]
async fn forged_roster_rejected_without_state_change() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    let key_a = fixture.trusted_key().to_string();
    let (key_c, key_c_path) = fixture.make_keypair([45_u8; 32], "attacker")?;
    let signer_a = fixture_tuf_signer(&fixture, "a", true);

    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 50)])?;
    fixture.write_keys_toml_with(&[("a", &key_a)], &[])?; // roster {A}
    fixture.write_package("hello", "1.0.0")?;
    fixture.commit_all("release 1.0.0")?;
    commit_tuf_metadata(&fixture, "1.0.0", std::slice::from_ref(&signer_a), None)?;
    fixture.publish_bare_origin()?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = enforced_config(&fixture, server.base_url(), Some(key_a.clone()));
    let mut state = RegistryState::default();
    sync(&fixture, &config, &mut state).await?;
    let pinned_before = fs::read_to_string(fixture.pinned_keys_path())?;
    let commit_before = state.last_commit.clone();

    // An attacker holding key C rewrites the roster to only itself and
    // signs the commit with C.
    fixture.write_keys_toml_with(&[("c", &key_c)], &[])?;
    fixture.commit_all_with_key("registry: take over roster", &key_c_path)?;
    fixture.publish_bare_origin()?;

    let err = sync(&fixture, &config, &mut state)
        .await
        .expect_err("forged roster commit must fail verification");
    assert!(
        format!("{err:#}").contains("not signed by any trusted key"),
        "{err:#}"
    );
    assert_eq!(
        fs::read_to_string(fixture.pinned_keys_path())?,
        pinned_before
    );
    assert_eq!(state.last_commit, commit_before);
    assert!(!pinned_before.contains(&key_c));
    Ok(())
}

#[tokio::test]
async fn tuf_failure_does_not_persist_roster_change() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    let key_a = fixture.trusted_key().to_string();
    let (key_b, key_b_path) = fixture.make_keypair([47_u8; 32], "maintainer_b")?;
    let signer_a = fixture_tuf_signer(&fixture, "a", true);
    let signer_b = tuf_signer("b", &key_b, &key_b_path, true);

    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 50)])?;
    fixture.write_keys_toml_with(&[("a", &key_a), ("b", &key_b)], &[])?;
    fixture.write_package("hello", "1.0.0")?;
    fixture.commit_all("release 1.0.0")?;
    let accepted = commit_tuf_metadata(&fixture, "1.0.0", &[signer_a.clone(), signer_b], None)?;
    fixture.publish_bare_origin()?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = enforced_config(&fixture, server.base_url(), Some(key_a.clone()));
    let mut state = RegistryState::default();
    sync(&fixture, &config, &mut state).await?;
    let pinned_before = fs::read_to_string(fixture.pinned_keys_path())?;
    assert!(pinned_before.contains(&key_a));
    assert!(pinned_before.contains(&key_b));

    fixture.write_keys_toml_with(&[("a", &key_a)], &["b"])?;
    fixture.commit_all("registry: maliciously drop b without TUF update")?;
    fixture.publish_bare_origin()?;
    let err = sync(&fixture, &config, &mut state)
        .await
        .expect_err("stale TUF catalog must reject the roster change");
    assert!(
        format!("{err:#}").contains("catalog does not match"),
        "{err:#}"
    );
    assert_eq!(
        fs::read_to_string(fixture.pinned_keys_path())?,
        pinned_before
    );
    assert_eq!(state.last_commit.as_deref(), Some(accepted.as_str()));
    Ok(())
}

/// §11 item 6: verification is fail-closed — with no pinned key and no
/// bootstrap anchor the sync aborts with an instructive error, both with
/// an explicit `required = true` and with the signing section absent.
#[tokio::test]
async fn no_anchor_sync_fails_with_instructive_error() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 50)])?;
    fixture.write_keys_toml()?;
    fixture.write_package("hello", "1.0.0")?;
    fixture.commit_all("release 1.0.0")?;
    fixture.publish_bare_origin()?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let mut state = RegistryState::default();

    // Explicit required = true, no public_key, no pins.
    let config = enforced_config(&fixture, server.base_url(), None);
    let err = sync(&fixture, &config, &mut state)
        .await
        .expect_err("enforced sync without any trusted key must fail");
    let text = format!("{err:#}");
    assert!(text.contains("no trusted key"), "{text}");
    assert!(text.contains("apr trust pin"), "{text}");

    // An absent [registry.signing] section enforces as well.
    let mut config = fixture.registry_config(server.base_url());
    config.signing = None;
    let err = sync(&fixture, &config, &mut state)
        .await
        .expect_err("absent signing section must fail closed");
    assert!(format!("{err:#}").contains("no trusted key"), "{err:#}");
    Ok(())
}

/// §11 item 7: a force-pushed history that reverts a roster change is
/// rejected as a non-fast-forward, keeping the newer pinned set.
#[tokio::test]
async fn force_pushed_roster_downgrade_rejected() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    let key_a = fixture.trusted_key().to_string();
    let (key_b, key_b_path) = fixture.make_keypair([46_u8; 32], "maintainer_b")?;
    let signer_a = fixture_tuf_signer(&fixture, "a", true);

    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 50)])?;
    fixture.write_keys_toml_with(&[("a", &key_a)], &[])?; // roster {A}
    fixture.write_package("hello", "1.0.0")?;
    fixture.commit_all("release 1.0.0")?;
    let first_commit =
        commit_tuf_metadata(&fixture, "1.0.0", std::slice::from_ref(&signer_a), None)?;
    fixture.publish_bare_origin()?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = enforced_config(&fixture, server.base_url(), Some(key_a.clone()));
    let mut state = RegistryState::default();
    sync(&fixture, &config, &mut state).await?;

    // Roster gains B in a signed fast-forward; the client pins it.
    fixture.write_keys_toml_with(&[("a", &key_a), ("b", &key_b)], &[])?;
    let signer_b = tuf_signer("b", &key_b, &key_b_path, true);
    fixture.commit_all("registry: add signing key b")?;
    let second_commit = commit_tuf_metadata(&fixture, "1.0.1", &[signer_a, signer_b], None)?;
    fixture.publish_bare_origin()?;
    sync(&fixture, &config, &mut state).await?;
    assert_eq!(state.last_commit.as_deref(), Some(second_commit.as_str()));
    assert!(fs::read_to_string(fixture.pinned_keys_path())?.contains(&key_b));

    // The attacker force-pushes the pre-rotation history (a signed,
    // previously valid commit) to revive the smaller roster.
    fixture.reset_hard(&first_commit)?;
    fixture.publish_bare_origin()?;
    let err = sync(&fixture, &config, &mut state)
        .await
        .expect_err("roster downgrade via force-push must fail");
    let text = format!("{err:#}");
    assert!(text.contains("downgrade"), "{text}");
    // The newer pinned set survives.
    assert!(fs::read_to_string(fixture.pinned_keys_path())?.contains(&key_b));
    assert_eq!(state.last_commit.as_deref(), Some(second_commit.as_str()));
    Ok(())
}
