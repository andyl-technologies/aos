//! Release tag creation, verification, and SSH signature formatting.

use crate::config::ApmConfig;
use crate::registry_ops::config::resolve_registry_name;
use crate::registry_ops::git::{
    ensure_commit_identity, git, git2_identity, refresh_registry_object_store,
};
use crate::registry_ops::signing::resolve_producer_signing_key;
use crate::types::validate_git_ref_name;
use anyhow::{Context, Result, bail};
use aos_core::output::{OutputMode, Printer};
use std::path::Path;

/// `apr tag <NAME>` — creates an SSH-signed annotated tag at HEAD in the
/// registry clone and refreshes the dumb-HTTP object store.
///
/// The tag message defaults to `AOS registry release`.
///
/// # Errors
///
/// Fails when the tag name is not a safe Git refname, when the signing key
/// cannot be resolved, when the tag already exists, or when git tag signing
/// fails.
pub async fn tag(
    config: &ApmConfig,
    name: &str,
    message: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    validate_git_ref_name(name)?;
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;
    let tag_message = message.unwrap_or("AOS registry release");

    sign_tag(
        &dir,
        name,
        "HEAD",
        Some(tag_message),
        signing_key.path(),
        false,
    )?;
    refresh_registry_object_store(&dir).context("refreshing dumb-HTTP object store after tag")?;

    if printer.mode() == OutputMode::Json {
        let tag_object = git(&dir, &["rev-parse", &format!("{name}^{{tag}}")])
            .with_context(|| format!("resolving tag object for '{name}'"))?;
        let target = git(&dir, &["rev-parse", &format!("{name}^{{commit}}")])
            .with_context(|| format!("resolving tag target for '{name}'"))?;
        printer.json(&serde_json::json!({
            "action": "tag",
            "status": "tagged",
            "registry": registry_name,
            "tag": name,
            "message": tag_message,
            "target": target,
            "tag_object": tag_object,
        }));
        return Ok(());
    }

    printer.success(&format!("Created signed tag '{name}'."));
    Ok(())
}

/// `apr sign <TAG>` — re-signs an existing tag in place.
///
/// The tag is force-recreated against its current target commit with a
/// fresh SSH signature, and the dumb-HTTP object store is refreshed.
///
/// # Errors
///
/// Fails when no tag name is given, when the tag name is not a safe Git
/// refname, when the tag cannot be resolved, when the signing key cannot be
/// resolved, or when git tag signing fails.
pub async fn sign(
    config: &ApmConfig,
    tag: Option<&str>,
    key: Option<&str>,
    key_id: Option<&str>,
    registry: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let registry_name = resolve_registry_name(config, registry)?;
    let dir = config.scope.registries_path().join(&registry_name);
    let tag_name = tag.ok_or_else(|| {
        anyhow::anyhow!("`apr sign` now signs tag objects; pass the existing tag name to re-sign")
    })?;
    validate_git_ref_name(tag_name)?;
    let signing_key = resolve_producer_signing_key(config, &dir, &registry_name, key, key_id)?;
    let previous_tag_object = git(&dir, &["rev-parse", &format!("{tag_name}^{{tag}}")])
        .with_context(|| format!("resolving existing tag object for '{tag_name}'"))?;
    let target = git(&dir, &["rev-list", "-n", "1", tag_name])
        .with_context(|| format!("resolving tag '{tag_name}' target commit"))?;

    sign_tag(
        &dir,
        tag_name,
        &target,
        Some("AOS registry release"),
        signing_key.path(),
        true,
    )?;
    refresh_registry_object_store(&dir).context("refreshing dumb-HTTP object store after sign")?;
    if printer.mode() == OutputMode::Json {
        let tag_object = git(&dir, &["rev-parse", &format!("{tag_name}^{{tag}}")])
            .with_context(|| format!("resolving re-signed tag object for '{tag_name}'"))?;
        printer.json(&serde_json::json!({
            "action": "sign",
            "status": "signed",
            "registry": registry_name,
            "tag": tag_name,
            "target": target,
            "previous_tag_object": previous_tag_object,
            "tag_object": tag_object,
        }));
        return Ok(());
    }
    printer.success(&format!("Re-signed tag '{tag_name}'."));

    Ok(())
}

/// Require the signed release tag for `version` to exist, returning the
/// tag object id.
pub(in crate::registry_ops) fn assert_release_tag_exists(
    dir: &Path,
    version: &semver::Version,
) -> Result<String> {
    let tag = version.to_string();
    git(dir, &["rev-parse", &format!("{tag}^{{tag}}")])
        .with_context(|| format!("resolving signed release tag '{tag}'"))
}

/// Resolve the commit a release tag points at.
pub(in crate::registry_ops) fn release_commit(
    dir: &Path,
    version: &semver::Version,
) -> Result<String> {
    let tag = version.to_string();
    git(dir, &["rev-parse", &format!("{tag}^{{commit}}")])
        .with_context(|| format!("resolving release tag '{tag}' commit"))
}

/// Create an SSH-signed annotated tag object.
///
/// Builds the tag object directly and appends the armored SSH signature after
/// the message — the same on-disk layout `git tag -s` produces and that
/// [`crate::security::verify_tag_signature`] verifies (the signed payload is
/// everything before the signature block).
pub(in crate::registry_ops) fn sign_tag(
    dir: &Path,
    tag_name: &str,
    target: &str,
    message: Option<&str>,
    signing_key: &str,
    force: bool,
) -> Result<()> {
    validate_git_ref_name(tag_name)?;
    let message = message.unwrap_or("AOS registry release");
    ensure_commit_identity(dir)?;

    let repo = git2::Repository::open(dir)
        .with_context(|| format!("opening git repository at {}", dir.display()))?;
    let target_object = repo
        .revparse_single(target)
        .with_context(|| format!("resolving tag target {target}"))?;
    let target_type = match target_object.kind() {
        Some(git2::ObjectType::Commit) => "commit",
        Some(git2::ObjectType::Tag) => "tag",
        Some(git2::ObjectType::Tree) => "tree",
        Some(git2::ObjectType::Blob) => "blob",
        _ => bail!("cannot tag object {} of unknown type", target_object.id()),
    };
    let tagger = git2_identity(&repo)?;

    // Build the unsigned tag payload, then sign exactly those bytes.
    let mut payload = Vec::new();
    payload.extend_from_slice(format!("object {}\n", target_object.id()).as_bytes());
    payload.extend_from_slice(format!("type {target_type}\n").as_bytes());
    payload.extend_from_slice(format!("tag {tag_name}\n").as_bytes());
    payload.extend_from_slice(
        format!(
            "tagger {} <{}> {} {}\n",
            tagger.name().unwrap_or(""),
            tagger.email().unwrap_or(""),
            tagger.when().seconds(),
            format_git_tz(tagger.when()),
        )
        .as_bytes(),
    );
    payload.push(b'\n');
    payload.extend_from_slice(message.as_bytes());
    payload.push(b'\n');

    let armored = crate::security::sign_payload_signature(Path::new(signing_key), "git", &payload)?;
    payload.extend_from_slice(armored.as_bytes());

    let odb = repo.odb().context("opening object database")?;
    let oid = odb
        .write(git2::ObjectType::Tag, &payload)
        .context("writing tag object")?;
    let refname = format!("refs/tags/{tag_name}");
    repo.reference(&refname, oid, force, &format!("apr tag {tag_name}"))
        .with_context(|| format!("creating tag ref '{tag_name}'"))?;
    Ok(())
}

/// Format a git timezone offset (`+HHMM`/`-HHMM`) from a [`git2::Time`].
fn format_git_tz(when: git2::Time) -> String {
    let offset = when.offset_minutes();
    let sign = if offset < 0 { '-' } else { '+' };
    let abs = offset.abs();
    format!("{sign}{:02}{:02}", abs / 60, abs % 60)
}
