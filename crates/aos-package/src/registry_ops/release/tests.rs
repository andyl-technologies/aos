//! Tests for signed release orchestration, container attachments, and static pack artifacts.

use super::{
    ContainerReleaseAttachment, attach_container_release, ensure_release_tag_available,
    ensure_release_worktree_clean, existing_release_tag_commit, load_container_release_attachment,
    validate_release_options,
};
use crate::registry_ops::git::git;
use crate::registry_ops::tags::sign_tag;
use crate::registry_ops::test_support::{
    container_release_inputs, test_release_options, write_test_signing_key,
};
use aos_core::output::Printer;
use aos_oci_types::to_canonical_json;
use std::fs;
use tempfile::TempDir;

#[test]
fn release_validation_rejects_cache_flags_without_publishing() {
    let tmp = TempDir::new().unwrap();

    let mut options = test_release_options(&tmp);
    options.cache_url = Some("https://cache.example".to_string());
    options.cache_url_explicit = true;
    assert!(
        format!("{:#}", validate_release_options(&options).unwrap_err())
            .contains("--cache-url requires an upload destination")
    );

    let mut options = test_release_options(&tmp);
    options.cache_key = Some(tmp.path().join("narinfo.key"));
    assert!(
        format!("{:#}", validate_release_options(&options).unwrap_err())
            .contains("--cache-key signs published narinfos")
    );

    let mut options = test_release_options(&tmp);
    options.cache_priority_explicit = true;
    assert!(
        format!("{:#}", validate_release_options(&options).unwrap_err())
            .contains("--cache-priority requires an upload destination")
    );

    let mut options = test_release_options(&tmp);
    options.no_skip = true;
    assert!(
        format!("{:#}", validate_release_options(&options).unwrap_err())
            .contains("--no-skip requires an upload destination")
    );
}

#[test]
fn container_release_attachment_requires_paired_canonical_inputs() {
    let tmp = TempDir::new().unwrap();
    let release_path = tmp.path().join("containers-v1-index.json");
    let input_path = tmp.path().join("signature-input.json");
    let version = semver::Version::parse("1.0.0").unwrap();

    assert!(
        load_container_release_attachment(&version, None, None)
            .unwrap()
            .is_none()
    );

    let error = load_container_release_attachment(&version, Some(&release_path), None)
        .expect_err("missing signature input");
    assert!(format!("{error:#}").contains("paired --container-signature-input"));
    let error = load_container_release_attachment(&version, None, Some(&input_path))
        .expect_err("missing release sidecar");
    assert!(format!("{error:#}").contains("paired --container-release"));

    let (release, input) = container_release_inputs("1.0.0");
    fs::write(&release_path, serde_json::to_vec_pretty(&release).unwrap()).unwrap();
    fs::write(&input_path, to_canonical_json(&input).unwrap()).unwrap();
    let error = load_container_release_attachment(&version, Some(&release_path), Some(&input_path))
        .expect_err("noncanonical sidecar");
    assert!(format!("{error:#}").contains("canonical JSON"));
}

#[test]
fn container_release_attachment_rejects_unsigned_mismatch_and_release_identity() {
    let tmp = TempDir::new().unwrap();
    let release_path = tmp.path().join("containers-v1-index.json");
    let input_path = tmp.path().join("signature-input.json");
    let version = semver::Version::parse("1.0.0").unwrap();
    let (mut release, mut input) = container_release_inputs("1.0.0");
    release.nix.definition.attribute = "systems.aos-testing.build.containers.aos".to_string();
    input.nix.definition.attribute = release.nix.definition.attribute.clone();
    fs::write(&release_path, to_canonical_json(&release).unwrap()).unwrap();
    fs::write(&input_path, to_canonical_json(&input).unwrap()).unwrap();
    load_container_release_attachment(&version, Some(&release_path), Some(&input_path))
        .expect("system-owned definition attribute");

    let (release, mut input) = container_release_inputs("1.0.0");
    fs::write(&release_path, to_canonical_json(&release).unwrap()).unwrap();
    input.identity.package_version = "0.2.0".to_string();
    fs::write(&input_path, to_canonical_json(&input).unwrap()).unwrap();

    let error = load_container_release_attachment(&version, Some(&release_path), Some(&input_path))
        .expect_err("unsigned identity mismatch");
    assert!(format!("{error:#}").contains("final sidecar identity differs"));

    let (release, input) = container_release_inputs("2.0.0");
    fs::write(&release_path, to_canonical_json(&release).unwrap()).unwrap();
    fs::write(&input_path, to_canonical_json(&input).unwrap()).unwrap();
    let error = load_container_release_attachment(&version, Some(&release_path), Some(&input_path))
        .expect_err("release semver mismatch");
    assert!(format!("{error:#}").contains("does not match apr release semver '1.0.0'"));

    let (mut release, mut input) = container_release_inputs("1.0.0");
    release.identity.image = "other".to_string();
    input.identity.image = "other".to_string();
    fs::write(&release_path, to_canonical_json(&release).unwrap()).unwrap();
    fs::write(&input_path, to_canonical_json(&input).unwrap()).unwrap();
    let error = load_container_release_attachment(&version, Some(&release_path), Some(&input_path))
        .expect_err("initial image policy");
    assert!(format!("{error:#}").contains("requires package 'aos' and image 'aos'"));
}

#[test]
fn container_release_attachment_retries_exact_signed_head_before_tag() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    git(
        tmp.path(),
        &[
            "init",
            "--object-format=sha256",
            "--initial-branch=main",
            repo.to_str().unwrap(),
        ],
    )
    .unwrap();
    git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
    git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
    git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
    fs::write(
        repo.join("registry.toml"),
        "[registry]\nname = \"aos-core\"\n",
    )
    .unwrap();
    git(&repo, &["add", "."]).unwrap();
    git(&repo, &["commit", "-m", "init"]).unwrap();

    let signing = write_test_signing_key(tmp.path(), "aos-core");
    let (release, _) = container_release_inputs("1.0.0");
    let attachment = ContainerReleaseAttachment {
        canonical_bytes: to_canonical_json(&release).unwrap(),
        release,
    };
    let mut options = test_release_options(&tmp);
    options.signing_key = signing.private_key.to_string_lossy().into_owned();
    options.container_release = Some(attachment.clone());
    let printer = Printer::new(0, true, false);

    attach_container_release(&repo, "aos-core", &options, &printer).unwrap();
    let committed_head = git(&repo, &["rev-parse", "HEAD"]).unwrap();
    assert!(
        existing_release_tag_commit(&repo, &options.version)
            .unwrap()
            .is_none()
    );

    attach_container_release(&repo, "aos-core", &options, &printer).unwrap();
    assert_eq!(git(&repo, &["rev-parse", "HEAD"]).unwrap(), committed_head);
    ensure_release_worktree_clean(&repo).unwrap();

    options
        .container_release
        .as_mut()
        .unwrap()
        .canonical_bytes
        .push(b' ');
    let error = attach_container_release(&repo, "aos-core", &options, &printer)
        .expect_err("same-release conflicting retry");
    assert!(format!("{error:#}").contains("different bytes for release 1.0.0"));
    assert_eq!(git(&repo, &["rev-parse", "HEAD"]).unwrap(), committed_head);
    ensure_release_worktree_clean(&repo).unwrap();
}

#[test]
fn release_validation_rejects_cache_flags_when_publishing_without_roots() {
    let tmp = TempDir::new().unwrap();
    let mut options = test_release_options(&tmp);
    options.upload_urls = vec!["file:///tmp/origin".to_string()];
    options.cache_url = Some("https://cache.example".to_string());
    options.cache_url_explicit = true;

    assert!(
        format!("{:#}", validate_release_options(&options).unwrap_err())
            .contains("cache flags require registry store paths")
    );
}

#[test]
fn release_tag_preflight_rejects_existing_tag_unless_resume() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    git(
        tmp.path(),
        &[
            "init",
            "--object-format=sha256",
            "--initial-branch=main",
            repo.to_str().unwrap(),
        ],
    )
    .unwrap();
    git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
    git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
    git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
    fs::write(
        repo.join("registry.toml"),
        "[registry]\nname = \"aos-core\"\n",
    )
    .unwrap();
    git(&repo, &["add", "."]).unwrap();
    git(&repo, &["commit", "-m", "init"]).unwrap();
    // Create the annotated release tag the way production does, via
    // `sign_tag` (libgit2). The `git()` porcelain dispatcher only supports
    // `tag --list` / `tag -d`, so `git tag -a` is an unsupported invocation.
    let signing = write_test_signing_key(tmp.path(), "aos-core");
    sign_tag(
        &repo,
        "1.0.0",
        "HEAD",
        Some("release 1.0.0"),
        signing.private_key.to_str().unwrap(),
        false,
    )
    .unwrap();

    let taken = semver::Version::parse("1.0.0").unwrap();
    let unused = semver::Version::parse("2.0.0").unwrap();

    // A version already released is rejected before any mutating work.
    let err = ensure_release_tag_available(&repo, &taken, false).unwrap_err();
    assert!(
        format!("{err:#}").contains("already exists"),
        "unexpected error: {err:#}"
    );

    // An unused version passes the preflight.
    ensure_release_tag_available(&repo, &unused, false).unwrap();

    // `resume` legitimately reuses an existing tag, so the preflight is skipped.
    ensure_release_tag_available(&repo, &taken, true).unwrap();
}
