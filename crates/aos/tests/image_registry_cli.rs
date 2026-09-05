//! Image consumption from signed static Git/HTTP registries without a Hub or Nix.

#[path = "../../aos-package/tests/common/mod.rs"]
mod registry_fixture;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use anyhow::{Context, Result};
use aos_core::nar::cache::{NarCompression, StaticNarInfoInput, nar_url, render_static_narinfo};
use aos_package::registry::{objectstore, pack, tuf};
use registry_fixture::{RegistryFixture, StaticHttpServer};
use sha2::{Digest, Sha256};

fn regular_file_nar(bytes: &[u8]) -> Vec<u8> {
    let mut nar = Vec::new();
    for field in [
        b"nix-archive-1".as_slice(),
        b"(",
        b"type",
        b"regular",
        b"contents",
        bytes,
        b")",
    ] {
        nar.extend_from_slice(&(field.len() as u64).to_le_bytes());
        nar.extend_from_slice(field);
        nar.resize(nar.len().next_multiple_of(8), 0);
    }
    nar
}

fn publish_image(
    cache: &Path,
    platform: &str,
    version: &str,
    number: u8,
) -> Result<(String, Vec<u8>, PathBuf)> {
    let bytes = format!("QFI fixture disk bytes for {platform} {version}").into_bytes();
    let nar = regular_file_nar(&bytes);
    let hash = format!("sha256:{:x}", Sha256::digest(&nar));
    let store_hash = number.to_string().repeat(32);
    let store = format!("/nix/store/{store_hash}-aos-{version}.qcow2");
    let payload = nar_url(&store, &hash, NarCompression::None)?;
    fs::create_dir_all(cache.join(&payload).parent().context("NAR parent")?)?;
    fs::write(cache.join(&payload), &nar)?;
    let narinfo = render_static_narinfo(
        &StaticNarInfoInput {
            store_path: &store,
            nar_hash: &hash,
            nar_size: nar.len() as u64,
            references: &[],
            deriver: None,
            signatures: &[],
            file_hash: &hash,
            file_size: nar.len() as u64,
            compression: NarCompression::None,
        },
        "/nix/store",
        None,
    )?;
    fs::write(cache.join(format!("{store_hash}.narinfo")), narinfo)?;
    let architecture = platform.split_once('-').context("platform")?.0;
    let sha = format!("{:x}", Sha256::digest(&bytes));
    let fixture_hash = "a".repeat(64);
    let metadata = format!(
        r#"
[versions.platforms.{platform}]
store_path = "/nix/store/{store_hash}-aos-{version}"
nar_hash = "{hash}"
nar_size = {nar_size}
closure_size = {nar_size}
source_drv = "/nix/store/{store_hash}-aos-{version}.drv"
source_nar_hash = "{hash}"
references = []

[[versions.platforms.{platform}.images]]
format = "qcow2"
store_path = "{store}"
nar_hash = "{hash}"
nar_size = {nar_size}

[versions.platforms.{platform}.images.delivery]
schema_version = 2
release = "{version}"
platform = "{platform}"
architecture = "{architecture}"
logical_image_id = "{fixture_hash}"
logical_disk_sha256 = "{fixture_hash}"
rootfs_sha256 = "{fixture_hash}"
filename = "aos-{architecture}-{version}.qcow2"
media_type = "application/vnd.aos.disk-image.qcow2"
compression = "none"
byte_size = {byte_size}
sha256 = "{sha}"
compatible_targets = ["qemu-kvm", "openstack"]

[versions.platforms.{platform}.images.delivery.uki]
filename = "aos.efi"
esp_path = "EFI/Linux/aos.efi"
byte_size = 16
sha256 = "{fixture_hash}"
verification = "unsigned"
sbat = []
measured = false

[versions.platforms.{platform}.images.delivery.image_info]
filename = "image-info.json"
store_path = "/nix/store/{store_hash}-image-info.json"
nar_hash = "{hash}"
nar_size = {nar_size}
media_type = "application/vnd.aos.image-info+json"
byte_size = 16
sha256 = "{fixture_hash}"
"#,
        nar_size = nar.len(),
        byte_size = bytes.len()
    );
    Ok((metadata, bytes, cache.join(payload)))
}

fn publish_release(fixture: &RegistryFixture, version: &str, metadata: &str) -> Result<()> {
    let path = fixture.source_path().join("packages/a/aos.toml");
    fs::create_dir_all(path.parent().context("package parent")?)?;
    fs::write(
        path,
        format!(
            r#"[package]
name = "aos"
description = "Portable image fixture"
license = "MIT"
maintainer = "test"
sysroot = true

[[versions]]
version = "{version}"
{metadata}
"#
        ),
    )?;
    aos_registry_surface::manifest::parse_package_file(&fs::read_to_string(
        fixture.source_path().join("packages/a/aos.toml"),
    )?)?;
    fixture.commit_all(&format!("images {version}"))?;
    tuf::write_release_metadata_worktree(
        fixture.source_path(),
        fixture.name(),
        &semver::Version::parse(version)?,
        &[tuf::MetadataSigningKey {
            key_id: "initial".into(),
            key_path: fixture.private_key_path().to_path_buf(),
            key: fixture.trusted_key().to_string(),
            role_key: true,
        }],
    )?;
    fixture.commit_all(&format!("TUF metadata {version}"))?;
    fixture.signed_tag(version, "HEAD")?;
    Ok(())
}

fn process(home: &Path, arguments: &[&str]) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_aos"));
    command
        .args(arguments)
        .env_clear()
        .env("HOME", home)
        .env("AOS_ROOT", home.join("system"))
        .env("PATH", "")
        .current_dir(home);
    command
}

async fn command(home: &Path, arguments: &[&str]) -> Result<Output> {
    Ok(process(home, arguments).output().await?)
}

async fn success(home: &Path, arguments: &[&str]) -> Result<serde_json::Value> {
    let output = command(home, arguments).await?;
    anyhow::ensure!(
        output.status.success(),
        "{arguments:?}: {} {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).context("CLI JSON")
}

async fn full_pack(fixture: &RegistryFixture, version: &str) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let source = pack::full_pack(fixture.source_path(), version, temp.path()).await?;
    let name = source.file_name().context("pack filename")?;
    let root = fixture
        .origin_path()
        .join("releases")
        .join(objectstore::release_object_dir(&semver::Version::parse(
            version,
        )?));
    fs::create_dir_all(root.join("pack"))?;
    fs::create_dir_all(root.join("info"))?;
    fs::copy(&source, root.join("pack").join(name))?;
    fs::copy(
        source.with_extension("idx"),
        root.join("pack")
            .join(Path::new(name).with_extension("idx")),
    )?;
    fs::write(
        root.join("info/packs"),
        format!("P {}\n", name.to_string_lossy()),
    )?;
    Ok(())
}

/// Snapshots published trust/catalog files while excluding fetched Git objects.
fn published_files(root: &Path) -> Result<std::collections::BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(
        root: &Path,
        path: &Path,
        files: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
    ) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_name() == "repo.git" {
                continue;
            }
            if path.is_dir() {
                visit(root, &path, files)?;
            } else {
                files.insert(path.strip_prefix(root)?.to_path_buf(), fs::read(path)?);
            }
        }
        Ok(())
    }
    let mut files = std::collections::BTreeMap::new();
    visit(root, root, &mut files)?;
    Ok(files)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_static_registry_lists_selects_downloads_and_preserves_trust() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let home = temp.path().join("consumer");
    let cache = temp.path().join("cache");
    fs::create_dir_all(&cache)?;
    fs::create_dir_all(home.join(".config/apm/registries.d"))?;
    fs::write(
        cache.join("nix-cache-info"),
        "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n",
    )?;
    let cache_server = StaticHttpServer::spawn(cache.clone()).await?;
    let fixture = RegistryFixture::new("images")?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    fixture.write_registry_toml(&cache_server.base_url())?;
    let (first, first_bytes, _) = publish_image(&cache, "x86_64-linux", "1.0.0", 1)?;
    publish_release(&fixture, "1.0.0", &first)?;
    let (second, expected_bytes, payload) = publish_image(&cache, "x86_64-linux", "2.0.0", 2)?;
    let (arm, _, _) = publish_image(&cache, "aarch64-linux", "2.0.0", 3)?;
    publish_release(&fixture, "2.0.0", &(second + &arm))?;
    fixture.set_branch("stable", "HEAD")?;
    fixture.set_branch("beta", "HEAD")?;
    fixture.publish_bare_origin()?;
    fs::write(fixture.origin_path().join("HEAD"), "ref: refs/heads/main\n")?;
    full_pack(&fixture, "1.0.0").await?;
    full_pack(&fixture, "2.0.0").await?;
    fixture.write_all_channel_partitions(
        "stable",
        &fixture.signed_channel_tag_bytes("stable", "2.0.0")?,
    )?;
    let origin = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let configuration = format!(
        r#"[registry]
url = "{}"
tag = "2.0.0"
[registry.signing]
required = true
public_key = "{}"
"#,
        origin.base_url(),
        fixture.trusted_key()
    );
    let config_path = home.join(".config/apm/registries.d/images.toml");
    fs::write(&config_path, &configuration)?;
    // A higher-priority unrelated registry must never supply this image's cache.
    fs::write(
        home.join(".config/apm/registries.d/unrelated.toml"),
        r#"[registry]
url = "http://127.0.0.1:1/"
priority = 9999
[[registry.caches]]
url = "http://127.0.0.1:1/"
priority = 9999
"#,
    )?;

    let list = success(&home, &["--json", "image", "list", "--registry", "images"]).await?;
    assert_eq!(list.as_array().context("image list")?.len(), 2);
    let ambient_token = process(&home, &["--json", "image", "list", "--registry", "images"])
        .env("AOS_TOKEN", "unrelated-hub-secret")
        .output()
        .await?;
    assert!(
        ambient_token.status.success(),
        "an ambient Hub credential must not require Hub for portable registry reads"
    );
    assert!(!String::from_utf8_lossy(&ambient_token.stdout).contains("unrelated-hub-secret"));

    let output = command(&home, &["image", "show", "--registry", "images"]).await?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ambiguous"));
    let shown = success(
        &home,
        &[
            "--json",
            "image",
            "show",
            "--registry",
            "images",
            "--architecture",
            "x86_64",
            "--format",
            "qcow2",
            "--target",
            "qemu-kvm",
        ],
    )
    .await?;
    assert_eq!(shown["release"], "2.0.0");
    assert_eq!(shown["platform"], "x86_64-linux");
    assert_eq!(
        shown["cacheUrls"][0]
            .as_str()
            .map(|value| value.trim_end_matches('/')),
        Some(cache_server.base_url().trim_end_matches('/'))
    );
    let destination = home.join("selected.qcow2");
    success(
        &home,
        &[
            "--json",
            "image",
            "download",
            "--registry",
            "images",
            "--architecture",
            "x86_64",
            "--output",
            destination.to_str().context("output path")?,
        ],
    )
    .await?;
    assert_eq!(fs::read(&destination)?, expected_bytes);
    let historical = success(
        &home,
        &[
            "--json",
            "image",
            "show",
            "--registry",
            "images",
            "--release",
            "1.0.0",
        ],
    )
    .await?;
    assert_eq!(historical["release"], "1.0.0");
    assert_eq!(
        historical["sha256"],
        format!("{:x}", Sha256::digest(first_bytes))
    );
    assert_eq!(
        fs::read_to_string(&config_path)?,
        configuration,
        "one-off release selection must not change package tracking"
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let hub = format!("http://{}", listener.local_addr()?);
    let application = axum::Router::new().route("/aos.hub.v1.ImageService/ResolveImage", axum::routing::post(|| async {
        (axum::http::StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"code":"unauthenticated", "message":"fixture authorization required"})))
    }));
    let server = tokio::spawn(async move { axum::serve(listener, application).await });
    let rejected = command(
        &home,
        &[
            "image",
            "show",
            "--registry",
            "images",
            "--architecture",
            "x86_64",
            "--hub",
            &hub,
        ],
    )
    .await?;
    server.abort();
    assert!(
        !rejected.status.success(),
        "explicit Hub authorization failure cannot fall back to configured registry"
    );
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("fixture authorization required"));

    success(
        &home,
        &[
            "--json",
            "image",
            "show",
            "--registry",
            "images",
            "--channel",
            "stable",
            "--architecture",
            "x86_64",
        ],
    )
    .await?;
    success(
        &home,
        &[
            "--json",
            "image",
            "show",
            "--registry",
            "images",
            "--release",
            "1.0.0",
        ],
    )
    .await?;
    fixture.write_all_channel_partitions(
        "beta",
        &fixture.signed_channel_tag_bytes("beta", "2.0.0")?,
    )?;
    success(
        &home,
        &[
            "--json",
            "image",
            "list",
            "--registry",
            "images",
            "--channel",
            "beta",
        ],
    )
    .await?;
    let published = published_files(&home)?;
    let catalog_bytes = published
        .iter()
        .find(|(path, _)| path.ends_with("image-catalog-v1/images/state.json"))
        .context("catalog state")?
        .1;
    let catalog: serde_json::Value = serde_json::from_slice(catalog_bytes)?;
    let mut baseline: aos_package::types::RegistryState =
        serde_json::from_value(catalog["trust"].clone())?;
    baseline.last_commit = catalog["tuf_commit"].as_str().map(str::to_owned);
    let baseline_home = temp.path().join("configured-consumer");
    fs::create_dir_all(baseline_home.join(".config/apm/registries.d"))?;
    fs::write(
        baseline_home.join(".config/apm/registries.d/images.toml"),
        format!(
            "{configuration}\n[registry.state]\n{}",
            format!(
                "last_commit = {:?}\nlast_roster_commit = {:?}\ntuf_root_version = {}\ntuf_targets_version = {}\ntuf_snapshot_version = {}\ntuf_timestamp_version = {}\n",
                baseline.last_commit.as_deref().context("baseline commit")?,
                baseline
                    .last_roster_commit
                    .as_deref()
                    .context("baseline roster")?,
                baseline.tuf_root_version.context("root version")?,
                baseline.tuf_targets_version.context("targets version")?,
                baseline.tuf_snapshot_version.context("snapshot version")?,
                baseline
                    .tuf_timestamp_version
                    .context("timestamp version")?,
            )
        ),
    )?;
    success(
        &baseline_home,
        &[
            "--json",
            "image",
            "list",
            "--registry",
            "images",
            "--channel",
            "beta",
        ],
    )
    .await?;
    fixture.write_all_channel_partitions(
        "beta",
        &fixture.signed_channel_tag_bytes("beta", "1.0.0")?,
    )?;
    let beta_rollback = command(
        &home,
        &["image", "list", "--registry", "images", "--channel", "beta"],
    )
    .await?;
    assert!(!beta_rollback.status.success());
    assert!(String::from_utf8_lossy(&beta_rollback.stderr).contains("floor"));
    fixture.write_all_channel_partitions(
        "stable",
        &fixture.signed_channel_tag_bytes("stable", "1.0.0")?,
    )?;
    let rollback = command(
        &home,
        &[
            "image",
            "show",
            "--registry",
            "images",
            "--channel",
            "stable",
            "--architecture",
            "aarch64",
        ],
    )
    .await?;
    assert!(
        !rollback.status.success(),
        "changing architecture cannot reset channel floor"
    );
    assert!(
        String::from_utf8_lossy(&rollback.stderr).contains("floor"),
        "{}",
        String::from_utf8_lossy(&rollback.stderr)
    );

    fs::write(&payload, b"corrupt NAR bytes")?;
    let corrupt_output = home.join("corrupt.qcow2");
    let corrupted = command(
        &home,
        &[
            "image",
            "download",
            "--registry",
            "images",
            "--architecture",
            "x86_64",
            "--output",
            corrupt_output.to_str().context("output path")?,
        ],
    )
    .await?;
    assert!(
        !corrupted.status.success(),
        "untrusted cache bytes must fail"
    );
    assert!(
        !corrupt_output.exists(),
        "corrupt image cannot become a completed download"
    );
    let before_retag = published_files(&home)?;
    let (rotated_key, _) = fixture.make_keypair([87; 32], "rotated")?;
    fixture.write_keys_toml_with(
        &[
            ("initial", fixture.trusted_key()),
            ("rotated", &rotated_key),
        ],
        &[],
    )?;
    fixture.commit_all("rotate roster before attempted release retag")?;
    let deletion = std::process::Command::new("git")
        .current_dir(fixture.source_path())
        .args(["tag", "-d", "2.0.0"])
        .output()?;
    assert!(deletion.status.success());
    fixture.signed_tag("2.0.0", "HEAD")?;
    fixture.publish_bare_origin()?;
    full_pack(&fixture, "2.0.0").await?;
    let retag = command(&home, &["image", "list", "--registry", "images"]).await?;
    assert!(!retag.status.success());
    assert!(
        String::from_utf8_lossy(&retag.stderr).contains("immutable image release changed"),
        "{}",
        String::from_utf8_lossy(&retag.stderr)
    );
    assert_eq!(
        published_files(&home)?,
        before_retag,
        "retag rejection must not publish catalog files, trust keys, or state"
    );
    fixture.reset_hard("1.0.0")?;
    fixture.publish_bare_origin()?;
    let ancestry = command(
        &home,
        &[
            "image",
            "show",
            "--registry",
            "images",
            "--release",
            "1.0.0",
        ],
    )
    .await?;
    assert!(
        !ancestry.status.success(),
        "historical selection cannot reset current roster continuity"
    );
    assert!(
        String::from_utf8_lossy(&ancestry.stderr).contains("downgrade detected"),
        "{}",
        String::from_utf8_lossy(&ancestry.stderr)
    );
    Ok(())
}
