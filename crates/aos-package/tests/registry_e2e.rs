mod common;

use anyhow::{Context, Result};
use aos_cache::AuthOptions;
use aos_oci_types::{
    Annotations, CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA, CONTAINER_RELEASE_SCHEMA_VERSION,
    ContainerEvidenceMappingQualification, ContainerEvidenceQualification,
    ContainerEvidenceQualificationCheck, ContainerNixProvenance, ContainerOciRelease,
    ContainerRelease, ContainerReleaseEvidence, ContainerReleaseIdentity, Descriptor, MediaType,
    NixDefinitionIdentity, NixOutputIdentity, Platform, Sha256Digest, to_canonical_json,
};
use aos_package::registry::{
    Registry, fetch, git, keys, objectstore, pack, static_upload, store_path_hash, tuf,
};
use aos_package::registry_ops::{
    ContainerReleaseAttachment, ReleaseTreeOptions, release_registry_tree,
    resolve_mirrors_for_registry,
};
use aos_package::security::{verify_commit_signature, verify_tag_signature};
use aos_package::types::{CacheEntry, RegistryState, TrackingMode};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::{env, fs};

use common::{RegistryFixture, StaticHttpServer};

fn container_release_attachment(version: &str) -> Result<ContainerReleaseAttachment> {
    fn descriptor(media_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            media_type,
            digest: Sha256Digest::digest(label.as_bytes()),
            size: u64::try_from(label.len()).expect("fixture size"),
            urls: Vec::new(),
            annotations: Annotations::new(),
            data: None,
            artifact_type: None,
            platform: None,
        }
    }

    fn evidence_descriptor(artifact_type: MediaType, label: &str) -> Descriptor {
        Descriptor {
            artifact_type: Some(artifact_type),
            ..descriptor(MediaType::OciImageManifest, label)
        }
    }

    let mut manifest = descriptor(MediaType::OciImageManifest, "manifest");
    manifest.platform = Some(Platform::linux_amd64());
    let release = ContainerRelease {
        schema_version: CONTAINER_RELEASE_SCHEMA_VERSION,
        media_type: MediaType::AosContainerRelease,
        identity: ContainerReleaseIdentity {
            release: version.to_string(),
            package: "aos".to_string(),
            package_version: "0.1.0".to_string(),
            image: "aos".to_string(),
        },
        oci: ContainerOciRelease {
            index: descriptor(MediaType::OciImageIndex, "index"),
            platform_manifests: vec![manifest],
        },
        nix: ContainerNixProvenance {
            definition: NixDefinitionIdentity {
                attribute: "containerImages.aos".to_string(),
                derivation_path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container.drv"
                    .to_string(),
            },
            output: NixOutputIdentity {
                name: "out".to_string(),
                store_path: "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-aos-container".to_string(),
            },
            closure: evidence_descriptor(MediaType::AosNixClosure, "closure"),
        },
        qualification: ContainerEvidenceQualification {
            schema: CONTAINER_EVIDENCE_QUALIFICATION_SCHEMA.to_string(),
            mapping: ContainerEvidenceMappingQualification {
                complete: true,
                unknown_paths: Vec::new(),
            },
            corresponding_source: ContainerEvidenceQualificationCheck {
                complete: true,
                unknown_paths: Vec::new(),
            },
            licensing: ContainerEvidenceQualificationCheck {
                complete: true,
                unknown_paths: Vec::new(),
            },
            ready_for_verified_publication: true,
        },
        evidence: ContainerReleaseEvidence {
            sbom: evidence_descriptor(MediaType::SpdxJson, "sbom"),
            source: evidence_descriptor(MediaType::AosSourceClosure, "source"),
            license: evidence_descriptor(MediaType::AosLicenseReport, "license"),
            provenance: evidence_descriptor(MediaType::InTotoJson, "provenance"),
            signature: evidence_descriptor(MediaType::DsseEnvelope, "signature"),
        },
    };
    let canonical_bytes = to_canonical_json(&release)?;
    Ok(ContainerReleaseAttachment {
        release,
        canonical_bytes,
    })
}

fn publish_release(
    fixture: &RegistryFixture,
    version: &str,
    channel: &str,
) -> Result<(String, String, Vec<u8>)> {
    let store_path = fixture.write_package("hello", version)?;
    fixture.write_closure(&store_path)?;
    fixture.commit_all(&format!("release {version}"))?;
    let commit = commit_tuf_release_metadata(fixture, version)?;
    fixture.signed_tag(version, "HEAD")?;
    let channel_tag = fixture.signed_channel_tag_bytes(channel, version)?;
    fixture.set_branch(channel, "HEAD")?;
    fixture.publish_bare_origin()?;
    Ok((store_path, commit, channel_tag))
}

fn commit_tuf_release_metadata(fixture: &RegistryFixture, version: &str) -> Result<String> {
    let changed = tuf::write_release_metadata_worktree(
        fixture.source_path(),
        fixture.name(),
        &v(version),
        &[tuf::MetadataSigningKey {
            key_id: "initial".into(),
            key_path: fixture.private_key_path().to_path_buf(),
            key: fixture.trusted_key().to_string(),
            role_key: true,
        }],
    )?;
    assert!(changed, "TUF metadata should change for release {version}");
    fixture.commit_all(&format!("TUF metadata {version}"))
}

async fn publish_full_pack(fixture: &RegistryFixture, version: &str) -> Result<String> {
    let version_semver = semver::Version::parse(version)?;
    let tmp = tempfile::TempDir::new()?;
    let pack_path = pack::full_pack(fixture.source_path(), version, tmp.path()).await?;
    let pack_name = pack_path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("pack filename is UTF-8")
        .to_string();
    let objects_dir = fixture
        .origin_path()
        .join("releases")
        .join(objectstore::release_object_dir(&version_semver));
    let pack_dir = objects_dir.join("pack");
    let info_dir = objects_dir.join("info");
    fs::create_dir_all(&pack_dir)?;
    fs::create_dir_all(&info_dir)?;
    fs::copy(&pack_path, pack_dir.join(&pack_name))?;
    let idx_path = pack_path.with_extension("idx");
    if idx_path.exists() {
        fs::copy(
            &idx_path,
            pack_dir.join(pack_name.trim_end_matches(".pack").to_string() + ".idx"),
        )?;
    }
    fs::write(info_dir.join("packs"), format!("P {pack_name}\n"))?;
    Ok(pack_name)
}

async fn publish_delta_pack(
    fixture: &RegistryFixture,
    target: &str,
    base: &str,
    from_commit: &str,
    to_commit: &str,
    compressed: bool,
) -> Result<String> {
    let target_semver = semver::Version::parse(target)?;
    let base_semver = semver::Version::parse(base)?;
    let tmp = tempfile::TempDir::new()?;
    let delta = pack::thin_delta(
        fixture.source_path(),
        from_commit,
        to_commit,
        &base_semver,
        tmp.path(),
    )
    .await?;
    let artifact = if compressed {
        pack::zstd_compress(&delta, None).await?
    } else {
        delta
    };
    let artifact_name = artifact
        .file_name()
        .and_then(|name| name.to_str())
        .expect("pack filename is UTF-8")
        .to_string();
    let pack_dir = fixture
        .origin_path()
        .join("releases")
        .join(objectstore::release_object_dir(&target_semver))
        .join("pack");
    fs::create_dir_all(&pack_dir)?;
    fs::copy(&artifact, pack_dir.join(&artifact_name))?;
    Ok(artifact_name)
}

fn init_consumer_repo(root: &Path) -> Result<std::path::PathBuf> {
    let repo = root.join("consumer.git");
    objectstore::init_bare_sha256(&repo, "stable")?;
    Ok(repo)
}

fn assert_git_object_exists(repo: &Path, rev: &str) {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "-e", &format!("{rev}^{{commit}}")])
        .output()
        .expect("running git cat-file");
    assert!(
        output.status.success(),
        "expected git object {rev} to exist\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn git_stdout(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .with_context(|| format!("running git {} in {}", args.join(" "), repo.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "git {} failed\nstdout:\n{}\nstderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_success(repo: &Path, args: &[&str]) -> Result<()> {
    git_stdout(repo, args).map(|_| ())
}

const GIT_MATRIX_ENV: &str = "AOS_PACKAGE_TEST_GIT_MATRIX";
const MIN_STOCK_GIT_VERSION: (u32, u32, u32) = (2, 42, 0);
static GIT_MATRIX_ENV_LOCK: Mutex<()> = Mutex::new(());

fn git_version_for(git: impl AsRef<OsStr>) -> Result<(String, (u32, u32, u32))> {
    let output = Command::new(git).arg("--version").output()?;
    if !output.status.success() {
        anyhow::bail!(
            "git --version failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let token = text
        .strip_prefix("git version ")
        .and_then(|rest| rest.split_whitespace().next())
        .ok_or_else(|| anyhow::anyhow!("could not parse {text}"))?;
    let mut parts = token.split('.');
    let version = (
        parse_optional_leading_u32(parts.next())?,
        parse_optional_leading_u32(parts.next())?,
        parse_optional_leading_u32(parts.next())?,
    );
    Ok((text, version))
}

fn current_git_version() -> Result<(String, (u32, u32, u32))> {
    git_version_for("git")
}

fn ensure_supported_stock_git(version_text: &str, version: (u32, u32, u32)) -> Result<()> {
    if version < MIN_STOCK_GIT_VERSION {
        anyhow::bail!(
            "expected stock Git 2.42.0 or newer for sha256 dumb-HTTP compatibility, found {version_text}",
        );
    }
    Ok(())
}

fn parse_optional_leading_u32(part: Option<&str>) -> Result<u32> {
    let Some(part) = part else {
        return Ok(0);
    };
    let digits = part
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits
        .parse()
        .with_context(|| format!("parsing git version component {part}"))
}

fn v(input: &str) -> semver::Version {
    semver::Version::parse(input).unwrap()
}

#[tokio::test]
async fn stock_git_current_version_syncs_sha256_dumb_http_registry() -> Result<()> {
    assert_stock_git_syncs_sha256_dumb_http_registry("stock-git").await
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires AOS_PACKAGE_TEST_GIT_MATRIX and pinned git binaries; run with --test-threads=1"]
async fn stock_git_configured_version_matrix_syncs_sha256_dumb_http_registry() -> Result<()> {
    let Some(matrix) = env::var_os(GIT_MATRIX_ENV) else {
        eprintln!(
            "skipping stock Git matrix e2e: set {GIT_MATRIX_ENV} to a PATH-style list of git binaries or bin directories"
        );
        return Ok(());
    };
    let entries = env::split_paths(&matrix).collect::<Vec<_>>();
    if entries.is_empty() {
        eprintln!("skipping stock Git matrix e2e: {GIT_MATRIX_ENV} is empty");
        return Ok(());
    }

    let _guard = GIT_MATRIX_ENV_LOCK
        .lock()
        .expect("stock Git matrix environment lock poisoned");
    let _path_restore = PathRestore::capture();

    for entry in entries {
        let git_binary = matrix_git_binary(&entry);
        let (version_text, version) = git_version_for(&git_binary)
            .with_context(|| format!("checking {}", git_binary.display()))?;
        ensure_supported_stock_git(&version_text, version)?;

        let shim = git_path_shim(&git_binary)?;
        set_process_path(path_with_prefix(shim.path())?);
        assert_stock_git_syncs_sha256_dumb_http_registry("stock-git-matrix")
            .await
            .with_context(|| {
                format!(
                    "running sha256 dumb-HTTP sync under {} ({version_text})",
                    git_binary.display(),
                )
            })?;
    }

    Ok(())
}

async fn assert_stock_git_syncs_sha256_dumb_http_registry(fixture_name: &str) -> Result<()> {
    let (version_text, version) = current_git_version()?;
    ensure_supported_stock_git(&version_text, version)?;

    let fixture = RegistryFixture::new(fixture_name)?;
    fixture.write_registry_toml_with_caches(&[])?;
    fixture.write_gitattributes()?;
    let store_path = fixture.write_package("hello", "1.0.0")?;
    fixture.write_closure(&store_path)?;
    let source_commit = fixture.commit_all("release 1.0.0")?;
    fixture.publish_bare_origin()?;

    let object_format = Command::new("git")
        .arg("--git-dir")
        .arg(fixture.origin_path())
        .args(["config", "--get", "extensions.objectformat"])
        .output()?;
    assert!(object_format.status.success());
    assert_eq!(
        String::from_utf8_lossy(&object_format.stdout).trim(),
        "sha256"
    );

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = fixture.registry_config(server.base_url());
    let mut state = RegistryState::default();
    let result = git::sync_git(
        &config,
        &TrackingMode::Branch("main".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        &mut state,
        &fixture.printer(),
    )
    .await?;

    assert_eq!(result.new_commit, source_commit);
    assert_eq!(result.packages_added, 1);
    assert_eq!(state.last_commit.as_deref(), Some(source_commit.as_str()));
    assert!(
        fixture
            .cache_dir()
            .join(format!("{fixture_name}/repo.git/HEAD"))
            .exists()
    );
    let registry = Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?;
    let package = registry.get("hello").expect("synced package exists");
    assert_eq!(package.store_path, store_path);

    Ok(())
}

fn matrix_git_binary(entry: &Path) -> PathBuf {
    if entry.is_dir() {
        entry.join("git")
    } else {
        entry.to_path_buf()
    }
}

fn path_with_prefix(prefix: &Path) -> Result<std::ffi::OsString> {
    let mut paths = vec![prefix.to_path_buf()];
    if let Some(current) = env::var_os("PATH") {
        paths.extend(env::split_paths(&current));
    }
    env::join_paths(paths).context("joining PATH for stock Git matrix")
}

struct PathRestore {
    original: Option<std::ffi::OsString>,
}

impl PathRestore {
    fn capture() -> Self {
        Self {
            original: env::var_os("PATH"),
        }
    }
}

impl Drop for PathRestore {
    fn drop(&mut self) {
        // The stock-Git matrix test is ignored and documented as single-threaded
        // because PATH is process-global.
        unsafe {
            if let Some(original) = &self.original {
                env::set_var("PATH", original);
            } else {
                env::remove_var("PATH");
            }
        }
    }
}

fn set_process_path(path: std::ffi::OsString) {
    // The stock-Git matrix test is ignored and documented as single-threaded
    // because PATH is process-global.
    unsafe {
        env::set_var("PATH", path);
    }
}

#[cfg(unix)]
fn git_path_shim(git_binary: &Path) -> Result<tempfile::TempDir> {
    let dir = tempfile::TempDir::new()?;
    std::os::unix::fs::symlink(git_binary, dir.path().join("git"))
        .with_context(|| format!("creating git shim for {}", git_binary.display()))?;
    Ok(dir)
}

#[cfg(not(unix))]
fn git_path_shim(_git_binary: &Path) -> Result<tempfile::TempDir> {
    anyhow::bail!("stock Git matrix path shims are only implemented on Unix test hosts")
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
        &[fixture.trusted_key().to_string()],
    )?);

    fixture.publish_bare_origin()?;
    assert!(!fixture.origin_path().join("bundle-list.toml").exists());
    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = fixture.registry_config(server.base_url());
    let mut state = RegistryState::default();
    let result = git::sync_git(
        &config,
        &TrackingMode::Branch("main".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
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
async fn static_origin_upload_e2e_syncs_uploaded_filesystem_destination() -> Result<()> {
    let (version_text, version) = current_git_version()?;
    ensure_supported_stock_git(&version_text, version)?;

    let fixture = RegistryFixture::new("origin-upload")?;
    fixture.write_registry_toml_with_caches(&[])?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    let store_path = fixture.write_package("hello", "1.0.0")?;
    fixture.write_closure(&store_path)?;
    let source_commit = fixture.commit_all("release 1.0.0")?;
    fixture.publish_bare_origin()?;
    git_success(fixture.origin_path(), &["repack", "-ad"])?;
    git_success(fixture.origin_path(), &["update-server-info"])?;

    let uploaded = tempfile::TempDir::new()?;
    let upload_urls = vec![format!("file://{}", uploaded.path().display())];
    let report = static_upload::upload_static_origin_to_all(
        fixture.origin_path(),
        &upload_urls,
        &AuthOptions::default(),
        false,
        &fixture.printer(),
    )
    .await?;
    assert!(report.files > 0);
    assert!(uploaded.path().join("HEAD").exists());
    assert!(uploaded.path().join("info/refs").exists());
    assert!(uploaded.path().join("objects/info").exists());
    let uploaded_pack_dir = uploaded.path().join("objects/pack");
    assert!(
        std::fs::read_dir(&uploaded_pack_dir)?
            .filter_map(std::result::Result::ok)
            .any(|entry| entry.path().extension() == Some(OsStr::new("idx")))
    );

    let server = StaticHttpServer::spawn(uploaded.path().to_path_buf()).await?;
    let stock_clone = tempfile::TempDir::new()?;
    let clone_path = stock_clone.path().join("registry");
    let clone_output = tokio::process::Command::new("git")
        .env_remove("LD_LIBRARY_PATH")
        .env("GIT_SMART_HTTP", "0")
        .arg("clone")
        .arg(server.base_url())
        .arg(&clone_path)
        .output()
        .await?;
    if !clone_output.status.success() {
        anyhow::bail!(
            "stock dumb-HTTP clone failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&clone_output.stdout),
            String::from_utf8_lossy(&clone_output.stderr),
        );
    }
    assert_eq!(
        git_stdout(
            &clone_path,
            &["rev-parse", &format!("{source_commit}^{{commit}}")],
        )?,
        source_commit
    );

    let config = fixture.registry_config(server.base_url());
    let mut state = RegistryState::default();
    let result = git::sync_git(
        &config,
        &TrackingMode::Branch("main".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        &mut state,
        &fixture.printer(),
    )
    .await?;

    assert_eq!(result.new_commit, source_commit);
    assert_eq!(state.last_commit.as_deref(), Some(source_commit.as_str()));
    let registry = Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?;
    let package = registry.get("hello").expect("synced package exists");
    assert_eq!(package.store_path, store_path);

    Ok(())
}

#[tokio::test]
async fn release_orchestrator_e2e_uploads_channel_origin_and_syncs_consumer() -> Result<()> {
    let fixture = RegistryFixture::new("release-orchestrator")?;
    fixture.write_registry_toml_with_caches(&[])?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    let store_path = fixture.write_package("hello", "1.1.0")?;
    fixture.write_closure(&store_path)?;
    let source_commit = fixture.commit_all("release 1.1.0")?;

    let uploaded = tempfile::TempDir::new()?;
    let options = ReleaseTreeOptions {
        version: v("1.1.0"),
        signing_key: fixture.private_key_path().to_string_lossy().into_owned(),
        tuf_signing_keys: Vec::new(),
        channel: Some("stable".into()),
        init_channel: true,
        count: None,
        partitions: None,
        cache_dir: fixture.cache_dir().join("release-cache"),
        cache_key: None,
        cache_url: None,
        cache_url_explicit: false,
        cache_priority: 40,
        cache_priority_explicit: false,
        has_store_roots: false,
        no_skip: false,
        upload_urls: vec![format!("file://{}", uploaded.path().display())],
        upload_auth: AuthOptions::default(),
        dry_run: false,
        resume: false,
        jobs: None,
        store_publish: None,
        container_release: None,
        cache_max_age_days: 30,
    };

    let report = release_registry_tree(
        fixture.source_path(),
        "release-orchestrator",
        &options,
        &fixture.printer(),
    )
    .await?;
    let release_commit = git_stdout(fixture.source_path(), &["rev-parse", "1.1.0^{commit}"])?;
    git_success(
        fixture.source_path(),
        &[
            "merge-base",
            "--is-ancestor",
            &source_commit,
            &release_commit,
        ],
    )?;

    assert!(
        report
            .full_pack
            .as_deref()
            .is_some_and(|name| name.starts_with("pack-"))
    );
    assert!(report.deltas.is_empty());
    assert!(report.uploaded_files.unwrap_or_default() > 0);
    assert!(verify_tag_signature(
        fixture.source_path(),
        "1.1.0",
        &[fixture.trusted_key().to_string()],
    )?);
    assert!(uploaded.path().join("channels/stable/00").exists());
    assert!(
        uploaded
            .path()
            .join("releases/1/1/0/objects/pack")
            .read_dir()?
            .any(|entry| {
                entry
                    .ok()
                    .and_then(|entry| entry.file_name().into_string().ok())
                    .is_some_and(|name| name.starts_with("pack-") && name.ends_with(".pack"))
            })
    );
    assert!(
        uploaded
            .path()
            .join("releases/1/1/0/objects/pack")
            .read_dir()?
            .any(|entry| {
                entry
                    .ok()
                    .and_then(|entry| entry.file_name().into_string().ok())
                    .is_some_and(|name| name.starts_with("pack-") && name.ends_with(".idx"))
            })
    );

    let server = StaticHttpServer::spawn(uploaded.path().to_path_buf()).await?;
    let config = fixture.signed_registry_config(server.base_url(), "stable");
    let mut state = RegistryState::default();
    let result = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        &mut state,
        &fixture.printer(),
    )
    .await?;

    assert_eq!(result.new_commit, release_commit);
    assert_eq!(state.floor.as_deref(), Some("1.1.0"));
    for path in [
        "tuf/root.json",
        "tuf/targets.json",
        "tuf/snapshot.json",
        "tuf/timestamp.json",
    ] {
        let spec = format!("{release_commit}:{path}");
        git_success(fixture.source_path(), &["cat-file", "-e", &spec])?;
    }
    assert_eq!(state.tuf_root_version, Some(1));
    assert_eq!(state.tuf_targets_version, Some(1));
    assert_eq!(state.tuf_snapshot_version, Some(1));
    assert_eq!(state.tuf_timestamp_version, Some(1));
    let registry = Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?;
    let package = registry.get("hello").expect("synced package exists");
    assert_eq!(package.store_path, store_path);

    Ok(())
}

#[tokio::test]
async fn release_orchestrator_commits_container_sidecar_before_signed_tag_and_resumes_exactly()
-> Result<()> {
    let fixture = RegistryFixture::new("container-release")?;
    fixture.write_registry_toml_with_caches(&[])?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    fixture.commit_all("initialize container registry")?;

    let attachment = container_release_attachment("1.0.0")?;
    let mut options = ReleaseTreeOptions {
        version: v("1.0.0"),
        signing_key: fixture.private_key_path().to_string_lossy().into_owned(),
        tuf_signing_keys: Vec::new(),
        channel: None,
        init_channel: false,
        count: None,
        partitions: None,
        cache_dir: fixture.cache_dir().join("release-cache"),
        cache_key: None,
        cache_url: None,
        cache_url_explicit: false,
        cache_priority: 40,
        cache_priority_explicit: false,
        has_store_roots: false,
        no_skip: false,
        upload_urls: Vec::new(),
        upload_auth: AuthOptions::default(),
        dry_run: true,
        resume: false,
        jobs: None,
        store_publish: None,
        container_release: Some(attachment.clone()),
        cache_max_age_days: 30,
    };

    let initial_head = git_stdout(fixture.source_path(), &["rev-parse", "HEAD"])?;
    release_registry_tree(
        fixture.source_path(),
        fixture.name(),
        &options,
        &fixture.printer(),
    )
    .await?;
    assert_eq!(
        git_stdout(fixture.source_path(), &["rev-parse", "HEAD"])?,
        initial_head
    );
    assert!(
        !fixture
            .source_path()
            .join("containers/v1/index.json")
            .exists()
    );

    options.dry_run = false;
    release_registry_tree(
        fixture.source_path(),
        fixture.name(),
        &options,
        &fixture.printer(),
    )
    .await?;

    let tagged_commit = git_stdout(fixture.source_path(), &["rev-parse", "1.0.0^{commit}"])?;
    let sidecar_commit = git_stdout(
        fixture.source_path(),
        &["log", "-1", "--format=%H", "--", "containers/v1/index.json"],
    )?;
    git_success(
        fixture.source_path(),
        &[
            "merge-base",
            "--is-ancestor",
            &sidecar_commit,
            &tagged_commit,
        ],
    )?;
    assert!(verify_commit_signature(
        fixture.source_path(),
        &sidecar_commit,
        &[fixture.trusted_key().to_string()],
    )?);
    assert!(verify_tag_signature(
        fixture.source_path(),
        "1.0.0",
        &[fixture.trusted_key().to_string()],
    )?);
    assert_eq!(
        git_stdout(
            fixture.source_path(),
            &["show", "1.0.0^{commit}:containers/v1/index.json"],
        )?
        .as_bytes(),
        attachment.canonical_bytes
    );

    options.resume = true;
    let resume_head = git_stdout(fixture.source_path(), &["rev-parse", "HEAD"])?;
    release_registry_tree(
        fixture.source_path(),
        fixture.name(),
        &options,
        &fixture.printer(),
    )
    .await?;
    assert_eq!(
        git_stdout(fixture.source_path(), &["rev-parse", "HEAD"])?,
        resume_head
    );

    options
        .container_release
        .as_mut()
        .expect("container attachment")
        .canonical_bytes
        .push(b' ');
    let error = release_registry_tree(
        fixture.source_path(),
        fixture.name(),
        &options,
        &fixture.printer(),
    )
    .await
    .expect_err("resume rejects different exact sidecar bytes");
    assert!(format!("{error:#}").contains("different containers/v1/index.json bytes"));
    assert_eq!(
        git_stdout(fixture.source_path(), &["rev-parse", "HEAD"])?,
        resume_head
    );
    assert!(git_stdout(fixture.source_path(), &["status", "--porcelain"])?.is_empty());

    Ok(())
}

#[tokio::test]
async fn legacy_bundle_only_http_origin_fails_with_clean_break_error() -> Result<()> {
    let fixture = RegistryFixture::new("legacy-only")?;
    fs::create_dir_all(fixture.origin_path())?;
    fs::write(
        fixture.origin_path().join("bundle-list.toml"),
        "schema = 1\n[[bundles]]\nname = \"legacy.bundle\"\n",
    )?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = fixture.registry_config(server.base_url());
    let mut state = RegistryState::default();
    let err = git::sync_git(
        &config,
        &TrackingMode::Branch("main".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        &mut state,
        &fixture.printer(),
    )
    .await
    .expect_err("legacy bundle-only origin is rejected by model gate");

    let message = format!("{err:#}");
    assert!(
        message.contains("legacy bundle-mode registry"),
        "got: {message}",
    );
    assert!(
        message.contains("no longer supports the bundle/creation_token registry model"),
        "got: {message}",
    );
    assert!(state.last_commit.is_none());
    assert!(state.floor.is_none());
    Ok(())
}

#[tokio::test]
async fn dual_surface_http_origin_prefers_git_native_over_legacy_manifest() -> Result<()> {
    let fixture = RegistryFixture::new("dual-surface")?;
    fixture.write_registry_toml_with_caches(&[])?;
    fixture.write_gitattributes()?;
    let store_path = fixture.write_package("hello", "2.0.0")?;
    fixture.write_closure(&store_path)?;
    let source_commit = fixture.commit_all("release 2.0.0")?;
    fixture.publish_bare_origin()?;
    fs::write(
        fixture.origin_path().join("bundle-list.toml"),
        "schema = 1\n[[bundles]]\nname = \"legacy.bundle\"\n",
    )?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = fixture.registry_config(server.base_url());
    let mut state = RegistryState::default();
    let result = git::sync_git(
        &config,
        &TrackingMode::Branch("main".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        &mut state,
        &fixture.printer(),
    )
    .await?;

    assert_eq!(result.new_commit, source_commit);
    assert_eq!(state.last_commit.as_deref(), Some(source_commit.as_str()));
    let registry = Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?;
    let package = registry.get("hello").expect("synced package exists");
    assert_eq!(package.version, "2.0.0");
    assert_eq!(package.store_path, store_path);
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
    fixture.commit_all("release 1.0.0")?;
    let v1_commit = commit_tuf_release_metadata(&fixture, "1.0.0")?;
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
        &fixture.trusted_keys_dirs(),
        &mut state,
        &fixture.printer(),
    )
    .await?;

    assert_eq!(first.new_commit, v1_commit);
    assert_eq!(state.floor.as_deref(), Some("1.0.0"));
    assert!(state.bucket.is_some());
    assert_eq!(state.retained, vec!["1.0.0"]);
    let assigned_bucket = state.bucket.expect("bucket persisted after first sync");
    let releases_dir = fixture.cache_dir().join("aos-core/repo.git/releases");
    let retained_release_dir = releases_dir.join("1/0/0");
    let stale_release_dir = releases_dir.join("9/9/9");
    fs::create_dir_all(retained_release_dir.join("objects/pack"))?;
    fs::create_dir_all(stale_release_dir.join("objects/pack"))?;

    let v2_store_path = fixture.write_package("hello", "1.1.0")?;
    fixture.write_closure(&v2_store_path)?;
    fixture.commit_all("release 1.1.0")?;
    let v2_commit = commit_tuf_release_metadata(&fixture, "1.1.0")?;
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
        &fixture.trusted_keys_dirs(),
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
    assert!(retained_release_dir.exists());
    assert!(!stale_release_dir.exists());

    let registry = Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?;
    let package = registry.get("hello").expect("synced package exists");
    assert_eq!(package.version, "1.1.0");
    assert_eq!(package.store_path, v2_store_path);
    let store_hash = store_path_hash(&v2_store_path);
    assert!(
        registry.store_map().is_present(),
        "store/ realisation graph materialized from the committed tree"
    );
    assert!(
        registry.store_map().get(store_hash).is_some(),
        "root has a store/ record"
    );
    assert!(
        !registry.store_map().blessed_nars(store_hash).is_empty(),
        "root record carries a blessed NAR"
    );

    let registry_root = fixture.registries_dir().join("aos-core");
    assert!(registry_root.join("registry.toml").exists());
    assert!(registry_root.join("keys.toml").exists());
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
        &fixture.trusted_keys_dirs(),
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
        &fixture.trusted_keys_dirs(),
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
        &fixture.trusted_keys_dirs(),
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
        &fixture.trusted_keys_dirs(),
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
        &fixture.trusted_keys_dirs(),
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
        &fixture.trusted_keys_dirs(),
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

#[tokio::test]
async fn channel_reachable_unchanged_partition_fails_when_freshness_is_stale() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 100)])?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    let (_, _, channel_tag) = publish_release(&fixture, "1.0.0", "stable")?;
    fixture.write_all_channel_partitions("stable", &channel_tag)?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let mut config = fixture.signed_registry_config(server.base_url(), "stable");
    config.max_staleness_seconds = Some(60);
    let mut state = RegistryState::default();
    let first = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        &mut state,
        &fixture.printer(),
    )
    .await?;
    assert_eq!(first.packages_added, 1);
    assert_eq!(state.floor.as_deref(), Some("1.0.0"));
    assert!(state.last_update.is_some());

    state.last_update = Some("1970-01-01T00:00:00Z".to_string());
    let err = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        &mut state,
        &fixture.printer(),
    )
    .await
    .expect_err("unchanged stale-but-valid partition fails closed");
    let message = format!("{err:#}");
    assert!(message.contains("resolved unchanged release 1.0.0"));
    assert!(message.contains("frozen-but-valid channel pointer"));

    Ok(())
}

#[tokio::test]
async fn channel_torn_publish_keeps_old_floor_when_partition_leads_objects() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 100)])?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    let (v1_store_path, v1_commit, v1_channel_tag) = publish_release(&fixture, "1.0.0", "stable")?;
    fixture.write_all_channel_partitions("stable", &v1_channel_tag)?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = fixture.signed_registry_config(server.base_url(), "stable");
    let mut state = RegistryState::default();
    let first = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        &mut state,
        &fixture.printer(),
    )
    .await?;
    assert_eq!(first.new_commit, v1_commit);
    assert_eq!(state.floor.as_deref(), Some("1.0.0"));
    let assigned_bucket = state.bucket.expect("first sync persisted bucket");

    let v2_store_path = fixture.write_package("hello", "1.1.0")?;
    fixture.write_closure(&v2_store_path)?;
    fixture.commit_all("release 1.1.0")?;
    fixture.signed_tag("1.1.0", "HEAD")?;
    let early_v2_partition = fixture.signed_channel_tag_bytes("stable", "1.1.0")?;
    fixture.write_channel_partition("stable", assigned_bucket, &early_v2_partition)?;

    let second = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        &mut state,
        &fixture.printer(),
    )
    .await?;

    assert_eq!(second.new_commit, v1_commit);
    assert_eq!(state.floor.as_deref(), Some("1.0.0"));
    assert_eq!(state.last_commit.as_deref(), Some(v1_commit.as_str()));
    let registry = Registry::load(fixture.cache_dir(), &config, "x86_64-linux")?;
    let package = registry.get("hello").expect("synced package exists");
    assert_eq!(package.version, "1.0.0");
    assert_eq!(package.store_path, v1_store_path);
    Ok(())
}

#[tokio::test]
async fn channel_interleaved_partition_advances_reject_stale_publisher_rollback() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 100)])?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    let (_, v1_commit, v1_channel_tag) = publish_release(&fixture, "1.0.0", "stable")?;
    fixture.write_all_channel_partitions("stable", &v1_channel_tag)?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let config = fixture.signed_registry_config(server.base_url(), "stable");
    let mut state = RegistryState {
        bucket: Some(7),
        ..RegistryState::default()
    };
    let first = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        &mut state,
        &fixture.printer(),
    )
    .await?;
    assert_eq!(first.new_commit, v1_commit);
    assert_eq!(state.floor.as_deref(), Some("1.0.0"));

    let (_, v2_commit, v2_channel_tag) = publish_release(&fixture, "1.1.0", "stable")?;
    let (_, v3_commit, v3_channel_tag) = publish_release(&fixture, "1.2.0", "stable")?;
    fixture.write_channel_partition("stable", 7, &v3_channel_tag)?;
    fixture.write_channel_partition("stable", 8, &v2_channel_tag)?;

    let second = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        &mut state,
        &fixture.printer(),
    )
    .await?;
    assert_eq!(second.new_commit, v3_commit);
    assert_eq!(state.floor.as_deref(), Some("1.2.0"));
    assert_eq!(state.last_commit.as_deref(), Some(v3_commit.as_str()));

    fixture.write_channel_partition("stable", 7, &v2_channel_tag)?;
    let err = git::sync_git(
        &config,
        &TrackingMode::Channel("stable".into()),
        fixture.cache_dir(),
        fixture.registries_dir(),
        &fixture.trusted_keys_dirs(),
        &mut state,
        &fixture.printer(),
    )
    .await
    .expect_err("stale publisher partition rollback is rejected");
    let message = format!("{err:#}");
    assert!(message.contains("rollback refused"), "got: {message}");
    assert!(
        message.contains("last successful freshness observation"),
        "got: {message}",
    );
    assert_eq!(state.floor.as_deref(), Some("1.2.0"));
    assert_eq!(state.last_commit.as_deref(), Some(v3_commit.as_str()));
    assert_ne!(state.last_commit.as_deref(), Some(v2_commit.as_str()));
    Ok(())
}

#[tokio::test]
async fn pack_delta_e2e_fetches_full_pack_and_compressed_thin_delta() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 100)])?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    let (_, base_commit, _) = publish_release(&fixture, "1.1.0", "stable")?;
    let (_, target_commit, _) = publish_release(&fixture, "1.1.1", "stable")?;
    let full_pack = publish_full_pack(&fixture, "1.1.0").await?;
    let delta_pack = publish_delta_pack(
        &fixture,
        "1.1.1",
        "1.1.0",
        &base_commit,
        &target_commit,
        true,
    )
    .await?;

    assert!(full_pack.starts_with("pack-"));
    assert_eq!(delta_pack, "delta-1.1.0.pack.zst");

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let tmp = tempfile::TempDir::new()?;
    let repo = init_consumer_repo(tmp.path())?;
    let printer = aos_core::output::Printer::new(1, false, false);
    let full_plan =
        fetch::resolve_objects(&repo, &server.base_url(), &v("1.1.0"), &[], &printer).await?;
    assert_eq!(
        full_plan.steps,
        vec![fetch::FetchStep::Full {
            version: v("1.1.0"),
            pack: full_pack,
        }],
    );
    assert_git_object_exists(&repo, &base_commit);

    let delta_plan = fetch::resolve_objects(
        &repo,
        &server.base_url(),
        &v("1.1.1"),
        &[v("1.1.0")],
        &printer,
    )
    .await?;
    assert_eq!(
        delta_plan.steps,
        vec![fetch::FetchStep::Delta {
            target: v("1.1.1"),
            base: v("1.1.0"),
            compressed: true,
        }],
    );
    assert_git_object_exists(&repo, &target_commit);
    Ok(())
}

#[tokio::test]
async fn pack_delta_e2e_falls_back_from_corrupt_artifacts() -> Result<()> {
    let fixture = RegistryFixture::new("aos-core")?;
    fixture.write_registry_toml_with_caches(&[("https://cache.example/nar", 100)])?;
    fixture.write_gitattributes()?;
    fixture.write_keys_toml()?;
    let (_, base_commit, _) = publish_release(&fixture, "1.3.0", "stable")?;
    let (_, target_commit, _) = publish_release(&fixture, "1.3.1", "stable")?;
    let full_pack = publish_full_pack(&fixture, "1.3.0").await?;
    let corrupt_delta_dir = fixture
        .origin_path()
        .join("releases")
        .join(objectstore::release_object_dir(&v("1.3.1")))
        .join("pack");
    fs::create_dir_all(&corrupt_delta_dir)?;
    fs::write(
        corrupt_delta_dir.join("delta-1.3.0.pack"),
        b"not a git pack",
    )?;

    let server = StaticHttpServer::spawn(fixture.origin_path().to_path_buf()).await?;
    let tmp = tempfile::TempDir::new()?;
    let repo = init_consumer_repo(tmp.path())?;
    let printer = aos_core::output::Printer::new(1, false, false);
    let plan = fetch::resolve_objects(
        &repo,
        &server.base_url(),
        &v("1.3.1"),
        &[v("1.3.0")],
        &printer,
    )
    .await?;
    assert_eq!(
        plan.steps,
        vec![
            fetch::FetchStep::Full {
                version: v("1.3.0"),
                pack: full_pack.clone(),
            },
            fetch::FetchStep::GitFetchFallback {
                refspec: "refs/tags/1.3.1:refs/tags/1.3.1".into(),
            },
        ],
    );
    assert_git_object_exists(&repo, &base_commit);
    assert_git_object_exists(&repo, &target_commit);

    let corrupt_full = fixture
        .origin_path()
        .join("releases")
        .join(objectstore::release_object_dir(&v("1.3.0")));
    let corrupt_full_pack = corrupt_full.join("pack").join(&full_pack);
    fs::remove_file(&corrupt_full_pack)?;
    fs::write(corrupt_full_pack, b"not a git pack")?;
    let tmp = tempfile::TempDir::new()?;
    let repo = init_consumer_repo(tmp.path())?;
    let plan =
        fetch::resolve_objects(&repo, &server.base_url(), &v("1.3.0"), &[], &printer).await?;
    assert_eq!(
        plan.steps,
        vec![fetch::FetchStep::GitFetchFallback {
            refspec: "refs/tags/1.3.0:refs/tags/1.3.0".into(),
        }],
    );
    assert_git_object_exists(&repo, &base_commit);
    Ok(())
}
