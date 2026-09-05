//! Registry Git commands, commit identities, signed commits, and index refresh.

use crate::registry::objectstore;
use crate::registry_ops::images::receipts::persist_image_publication_receipt;
use crate::registry_ops::provenance::staged::{
    staged_package_provenance_transparency_validation_needed,
    validate_staged_package_provenance_transparency_log,
    validate_staged_package_toml_provenance_requirements,
};
use crate::registry_ops::publish::RegistryPublishLock;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// Run a git command in the registry directory, returning stdout.
///
/// Runs hermetically (see [`crate::registry::porcelain`]): host git configuration is
/// hidden. Network transport commands must use [`git_transport`] instead.
pub(in crate::registry_ops) fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let output = crate::registry::porcelain::dispatch(dir, args)
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;
    if !output.success {
        bail!("git {} failed: {}", args.join(" "), output.stderr);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a git network-transport command (push, pull) in the registry
/// directory, returning stdout.
///
/// Unlike [`git`], the host configuration stays visible: credential
/// helpers, proxies, and URL rewrites live there.
pub(in crate::registry_ops) fn git_transport(dir: &Path, args: &[&str]) -> Result<String> {
    let output = crate::registry::porcelain::dispatch(dir, args)
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;
    if !output.success {
        bail!("git {} failed: {}", args.join(" "), output.stderr);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a git command in the registry directory, returning raw stdout bytes.
pub(in crate::registry_ops) fn git_raw(dir: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = crate::registry::porcelain::dispatch(dir, args)
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;
    if !output.success {
        bail!("git {} failed: {}", args.join(" "), output.stderr);
    }
    Ok(output.stdout)
}

/// Run a git command that is allowed to fail, returning (success, stdout, stderr).
#[allow(dead_code)]
pub(in crate::registry_ops) fn git_try(
    dir: &Path,
    args: &[&str],
) -> Result<(bool, String, String)> {
    let output = crate::registry::porcelain::dispatch(dir, args)
        .with_context(|| format!("running git {} in {}", args.join(" "), dir.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok((output.success, stdout, output.stderr.trim().to_string()))
}

/// Whether the `GIT_AUTHOR_*`/`GIT_COMMITTER_*` environment variables fully
/// specify a commit identity. They take precedence over any git config and
/// are how hermetic environments (VM tests, build sandboxes) provide one.
fn env_commit_identity() -> bool {
    [
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
    ]
    .iter()
    .all(|var| std::env::var_os(var).is_some_and(|value| !value.is_empty()))
}

/// Read `key` from the host's global git config, failing when it is unset.
///
/// Registry commits record who published, so a missing identity is a setup
/// error, not something to paper over with a placeholder.
fn host_identity_value(key: &str) -> Result<String> {
    host_global_config_value(key).ok_or_else(|| {
        anyhow::anyhow!(
            "registry commits record the maintainer's identity, but git {key} is not set.\n\
             Set it with `git config --global {key} <value>`."
        )
    })
}

/// Read `key` from the host's global git configuration, returning `None`
/// when the config or key is absent or empty.
///
/// "Global" matches what `git config --global` resolves, which is *two*
/// files: the classic `~/.gitconfig` and the XDG
/// `$XDG_CONFIG_HOME/git/config` (defaulting to `~/.config/git/config`).
/// libgit2's [`git2::Config::find_global`] locates only the former, so the
/// XDG file is loaded explicitly via [`git2::Config::find_xdg`]. Skipping it
/// makes identities kept solely under `~/.config/git/config` — the
/// home-manager default — invisible. When both files set `key`, the `global`
/// level outranks `xdg`, exactly as git prioritizes the two.
fn host_global_config_value(key: &str) -> Option<String> {
    let mut config = git2::Config::new().ok()?;
    let mut loaded = false;
    if let Ok(path) = git2::Config::find_xdg() {
        loaded |= config
            .add_file(&path, git2::ConfigLevel::XDG, false)
            .is_ok();
    }
    if let Ok(path) = git2::Config::find_global() {
        loaded |= config
            .add_file(&path, git2::ConfigLevel::Global, false)
            .is_ok();
    }
    if !loaded {
        return None;
    }
    let value = config.get_string(key).ok()?;
    (!value.is_empty()).then_some(value)
}

/// Check that a commit identity is available, without touching any repo.
///
/// Used by [`crate::registry_ops::create`] to refuse before creating anything on disk.
pub(in crate::registry_ops) fn require_commit_identity() -> Result<()> {
    if env_commit_identity() {
        return Ok(());
    }
    for key in ["user.email", "user.name"] {
        host_identity_value(key)?;
    }
    Ok(())
}

/// Ensure the maintainer's identity is available for commits in `dir`.
///
/// Registry git invocations are hermetic (see [`crate::registry::porcelain`]), so an
/// identity living only in the maintainer's global config is invisible to
/// them; capture it into the clone, preserving commit attribution.
///
/// # Errors
///
/// Fails when no identity is configured in the environment, the clone, or
/// the host's global config.
pub(in crate::registry_ops) fn ensure_commit_identity(dir: &Path) -> Result<()> {
    if env_commit_identity() {
        return Ok(());
    }

    for key in ["user.email", "user.name"] {
        if git(dir, &["config", key]).is_ok() {
            continue;
        }
        let host = host_identity_value(key)?;
        git(dir, &["config", key, &host])?;
    }
    Ok(())
}

/// Render `path` relative to the registry root as a UTF-8 string suitable
/// for `git add -- <path>`.
pub(in crate::registry_ops) fn registry_relative_path(dir: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(dir)
        .with_context(|| format!("{} is not under {}", path.display(), dir.display()))?;
    rel.to_str()
        .map(ToString::to_string)
        .ok_or_else(|| anyhow::anyhow!("registry path is not UTF-8: {}", path.display()))
}

/// Commit whatever is currently staged, SSH-signing the commit when
/// `signing_key` points at an OpenSSH private key.
pub(in crate::registry_ops) fn commit_staged_registry(
    dir: &Path,
    message: &str,
    signing_key: Option<&str>,
) -> Result<()> {
    let _commit_lock = RegistryPublishLock::acquire_or_join_current_process(dir)?;
    validate_staged_package_toml_provenance_requirements(dir)?;
    if staged_package_provenance_transparency_validation_needed(dir)? {
        validate_staged_package_provenance_transparency_log(dir)?;
    }

    match signing_key {
        Some(key) => create_signed_commit(dir, message, key)?,
        None => {
            git(dir, &["commit", "-m", message])?;
        }
    }
    Ok(())
}

/// Applies the deep staged-index checks shared by legacy APR commits and the
/// canonical isolated release transaction.
pub(crate) fn validate_canonical_release_registry_index(dir: &Path) -> Result<()> {
    validate_staged_package_toml_provenance_requirements(dir)?;
    if staged_package_provenance_transparency_validation_needed(dir)? {
        validate_staged_package_provenance_transparency_log(dir)?;
    }
    Ok(())
}

/// Create an SSH-signed commit of the current index, attaching the armored
/// signature in the `gpgsig-sha256` header git uses for SHA-256 repositories.
///
/// The signed payload is the commit object without the signature header, which
/// is exactly what [`crate::security::verify_commit_signature`] reconstructs.
fn create_signed_commit(dir: &Path, message: &str, signing_key: &str) -> Result<()> {
    let repo = git2::Repository::open(dir)
        .with_context(|| format!("opening git repository at {}", dir.display()))?;
    let mut index = repo.index().context("opening index")?;
    let tree_oid = index.write_tree().context("writing tree")?;
    let tree = repo.find_tree(tree_oid).context("reading tree")?;
    let sig = git2_identity(&repo)?;
    let parents = match repo.head() {
        Ok(head) => vec![head.peel_to_commit().context("reading HEAD commit")?],
        Err(_) => Vec::new(),
    };
    let parent_refs: Vec<&git2::Commit> = parents.iter().collect();

    let buffer = repo
        .commit_create_buffer(&sig, &sig, message, &tree, &parent_refs)
        .context("building commit object")?;
    let buffer_str = std::str::from_utf8(&buffer).context("commit object is not valid UTF-8")?;
    let armored = crate::security::sign_payload_signature(
        Path::new(signing_key),
        "git",
        buffer_str.as_bytes(),
    )?;
    let commit_oid = repo
        .commit_signed(buffer_str, &armored, Some("gpgsig-sha256"))
        .context("writing signed commit")?;

    // commit_signed writes the object but does not move any ref.
    update_head_target(&repo, commit_oid)?;
    Ok(())
}

/// Resolve the commit/tagger identity the way git does: repository (and
/// global) config first, then the `GIT_AUTHOR_*`/`GIT_COMMITTER_*` environment
/// variables that [`ensure_commit_identity`] leaves in place rather than
/// copying into config.
pub(in crate::registry_ops) fn git2_identity(
    repo: &git2::Repository,
) -> Result<git2::Signature<'static>> {
    if let Ok(sig) = repo.signature() {
        return Ok(sig);
    }
    let name = std::env::var("GIT_AUTHOR_NAME")
        .or_else(|_| std::env::var("GIT_COMMITTER_NAME"))
        .map_err(|_| anyhow::anyhow!("no commit identity configured (user.name unset)"))?;
    let email = std::env::var("GIT_AUTHOR_EMAIL")
        .or_else(|_| std::env::var("GIT_COMMITTER_EMAIL"))
        .map_err(|_| anyhow::anyhow!("no commit identity configured (user.email unset)"))?;
    git2::Signature::now(&name, &email).context("building commit identity")
}

/// Point the current branch (or the unborn HEAD's target) at `oid`.
fn update_head_target(repo: &git2::Repository, oid: git2::Oid) -> Result<()> {
    let refname = match repo.head() {
        Ok(head) => head.name().context("HEAD has no name")?.to_string(),
        Err(_) => repo
            .find_reference("HEAD")
            .context("reading HEAD")?
            .symbolic_target()
            .context("reading HEAD symbolic target")?
            .context("HEAD is not symbolic")?
            .to_string(),
    };
    repo.reference(&refname, oid, true, "apr signed commit")
        .with_context(|| format!("updating {refname}"))?;
    Ok(())
}

/// Create a git commit for a constrained set of registry paths.
pub(in crate::registry_ops) fn commit_registry_paths(
    dir: &Path,
    message: &str,
    paths: &[PathBuf],
    signing_key: Option<&str>,
) -> Result<()> {
    if paths.is_empty() {
        bail!("no registry paths supplied for commit");
    }

    let _commit_lock = RegistryPublishLock::acquire_or_join_current_process(dir)?;
    ensure_commit_identity(dir)?;

    let relative_paths = paths
        .iter()
        .map(|path| registry_relative_path(dir, path))
        .collect::<Result<Vec<_>>>()?;

    let mut args: Vec<&str> = vec!["add", "-A", "--"];
    args.extend(relative_paths.iter().map(String::as_str));
    git(dir, &args).with_context(|| {
        format!(
            "running git add for {} constrained path(s) in {}",
            relative_paths.len(),
            dir.display()
        )
    })?;

    commit_staged_registry(dir, message, signing_key)
}

/// Create a git commit in the registry directory.
///
/// When `signing_key` is the path to an OpenSSH Ed25519 private key, the
/// commit is SSH-signed (`gpg.format=ssh`), matching the tag-signing setup
/// in [`crate::registry_ops::tags::sign_tag`]. Clients verify head-commit signatures during sync, so
/// commits on registries with a non-empty trust roster should always be
/// signed.
pub(in crate::registry_ops) fn commit_registry(
    dir: &Path,
    message: &str,
    signing_key: Option<&str>,
) -> Result<()> {
    let _commit_lock = RegistryPublishLock::acquire_or_join_current_process(dir)?;
    ensure_commit_identity(dir)?;
    git(dir, &["add", "-A"])?;
    commit_staged_registry(dir, message, signing_key)
}

/// Refresh the static dumb-HTTP object indexes after refs or commits change.
pub(crate) fn refresh_registry_object_store(dir: &Path) -> Result<()> {
    let _publish_lock = RegistryPublishLock::acquire_or_join_current_process(dir)?;
    objectstore::assert_sha256(dir)?;
    let releases = semver_tag_versions(dir)?;
    for release in &releases {
        objectstore::write_release_objects(dir, release, &release.to_string())
            .with_context(|| format!("preparing release object dir for {release}"))?;
    }
    objectstore::write_alternates(dir, &releases)?;
    objectstore::ensure_loose_completeness(dir)?;
    objectstore::write_index_bundles(dir)?;
    objectstore::refresh_server_info(dir)?;
    persist_image_publication_receipt(dir)?;
    Ok(())
}

/// List the registry's release versions: every git tag whose name parses
/// as semver, sorted ascending and deduplicated.
pub(in crate::registry_ops) fn semver_tag_versions(dir: &Path) -> Result<Vec<semver::Version>> {
    let tags = git(dir, &["tag", "--list"])?;
    Ok(semver_versions_from_tag_list(&tags))
}

fn semver_versions_from_tag_list(tags: &str) -> Vec<semver::Version> {
    let mut versions: Vec<semver::Version> = tags
        .lines()
        .filter_map(|tag| semver::Version::parse(tag.trim()).ok())
        .collect();
    versions.sort();
    versions.dedup();
    versions
}

pub(in crate::registry_ops) fn current_git_head(dir: &Path) -> Result<String> {
    git(dir, &["rev-parse", "HEAD"])
}

#[cfg(test)]
mod tests;
