//! Producer signing-key resolution and ephemeral command-backed key material.

use crate::config::ApmConfig;
use crate::registry::keys;
use crate::registry_ops::trust::{load_committed_roster, validate_roster_key_id};
use crate::security::{KeySource, TrustedKey, key_fingerprint, parse_signing_key};
use crate::types::{RegistryConfig, SigningKeySource};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// Parse a `registry:Algorithm:<base64>` line into a [`TrustedKey`] pinned
/// via TOFU, verifying it belongs to `expected_registry`.
pub(in crate::registry_ops) fn trusted_key_from_line(
    expected_registry: &str,
    key: &str,
) -> Result<TrustedKey> {
    let (registry, algorithm, public_key) = parse_signing_key(key)?;
    if registry != expected_registry {
        bail!(
            "trust key belongs to registry '{}', expected '{}'",
            registry,
            expected_registry,
        );
    }
    let fingerprint = key_fingerprint(&public_key);
    Ok(TrustedKey {
        registry,
        algorithm,
        public_key,
        fingerprint,
        source: KeySource::Tofu,
    })
}

/// A producer signing key resolved to a filesystem path that git can open.
///
/// For path sources [`path`](Self::path) points at the user's key file
/// directly. For command sources the key material is materialized into a
/// private temporary file (mode `0600`, in a tmpfs-backed directory when one
/// is available) whose lifetime is bound to this value: the file is removed
/// when the `ResolvedSigningKey` is dropped.
///
/// Because `ResolvedSigningKey` owns a [`tempfile::NamedTempFile`], Rust drops
/// it — and thus deletes the materialized key — at the end of its enclosing
/// scope, not at last use. Callers therefore keep it in a local binding for
/// the whole signing operation: `ssh-keygen` opens the key path more than
/// once per signature, so the path cannot be a pipe and the file must outlive
/// every git invocation that reads it.
#[derive(Debug)]
pub(in crate::registry_ops) struct ResolvedSigningKey {
    pub(in crate::registry_ops) path: String,
    /// Present for command sources; dropping it removes the temporary file.
    pub(in crate::registry_ops) _materialized: Option<tempfile::NamedTempFile>,
}

impl ResolvedSigningKey {
    /// Wrap an on-disk key path that the tool does not own or manage.
    pub(in crate::registry_ops) fn from_path(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            _materialized: None,
        }
    }

    /// The path to hand to `git -c user.signingkey=<path>`.
    pub(in crate::registry_ops) fn path(&self) -> &str {
        &self.path
    }
}

/// Candidate directories for short-lived materialized keys, most-preferred
/// first: a tmpfs-backed runtime directory when available (`$XDG_RUNTIME_DIR`,
/// then `/dev/shm`), falling back to the system temp directory. Keeping the
/// plaintext key in RAM-backed storage avoids it ever touching persistent
/// disk.
fn ephemeral_key_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let path = PathBuf::from(dir);
        if path.is_dir() {
            dirs.push(path);
        }
    }
    let shm = PathBuf::from("/dev/shm");
    if shm.is_dir() {
        dirs.push(shm);
    }
    dirs.push(std::env::temp_dir());
    dirs
}

/// Create an empty private temporary file in the most-preferred writable
/// [`ephemeral_key_dirs`] candidate.
///
/// A preferred directory may exist yet be unwritable (e.g. a read-only
/// `$XDG_RUNTIME_DIR`), so each candidate is tried in turn and the first that
/// accepts the file wins.
fn create_ephemeral_key_file() -> Result<tempfile::NamedTempFile> {
    let mut last_err: Option<(PathBuf, std::io::Error)> = None;
    for dir in ephemeral_key_dirs() {
        match tempfile::Builder::new()
            .prefix(".apm-signing-key-")
            .tempfile_in(&dir)
        {
            Ok(file) => return Ok(file),
            Err(err) => last_err = Some((dir, err)),
        }
    }
    match last_err {
        Some((dir, err)) => Err(anyhow::Error::new(err))
            .with_context(|| format!("creating temporary key file in {}", dir.display())),
        // `ephemeral_key_dirs` always yields the system temp dir, so the loop
        // runs at least once and records an error on total failure.
        None => bail!("no candidate directory available for a temporary key file"),
    }
}

/// Run a signing-key command via `bash -c` and materialize its stdout into a
/// private temporary file that `git`/`ssh-keygen` can open.
///
/// The command must print the unencrypted OpenSSH private key to stdout. The
/// returned [`ResolvedSigningKey`] owns the temporary file; the key is removed
/// from disk as soon as it is dropped.
///
/// The `aos`/`apm`/`apr` wrapper scripts replace `PATH` with a minimal
/// hermetic tool set and stash the caller's original value in
/// `AOS_HOST_PATH`. A key command is user-supplied and expects the user's
/// own environment (secret managers like `op`, filters like `jq`), so when
/// `AOS_HOST_PATH` is present the command runs with the caller's `PATH`
/// restored verbatim.
fn materialize_signing_key_command(command: &str) -> Result<ResolvedSigningKey> {
    materialize_signing_key_command_with_path(command, std::env::var_os("AOS_HOST_PATH"))
}

/// [`materialize_signing_key_command`] with an explicit `PATH` override for
/// the spawned `bash -c` process; `None` inherits this process's `PATH`.
fn materialize_signing_key_command_with_path(
    command: &str,
    search_path: Option<std::ffi::OsString>,
) -> Result<ResolvedSigningKey> {
    let runtime_path = std::env::var_os("PATH");
    let shell_program = runtime_path
        .as_deref()
        .and_then(|path| executable_on_path("bash", path))
        .unwrap_or_else(|| PathBuf::from("bash"));
    let mut shell = std::process::Command::new(shell_program);
    shell
        .arg("-c")
        .arg(command)
        .stdin(std::process::Stdio::null());
    if let Some(search_path) = search_path {
        shell.env("PATH", search_path);
    }
    let output = shell
        .output()
        .with_context(|| format!("running signing key command `{command}`"))?;
    if !output.status.success() {
        bail!(
            "signing key command `{command}` failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        bail!("signing key command `{command}` produced no key material on stdout");
    }

    // `tempfile` creates the file with mode 0600 and O_EXCL on Unix and
    // removes it when the handle drops.
    let mut file = create_ephemeral_key_file()?;
    std::io::Write::write_all(file.as_file_mut(), &output.stdout)
        .context("writing materialized signing key to a temporary file")?;
    file.as_file()
        .sync_all()
        .context("flushing materialized signing key")?;

    let path = file
        .path()
        .to_str()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "temporary key path is not valid UTF-8: {}",
                file.path().display()
            )
        })?
        .to_string();
    Ok(ResolvedSigningKey {
        path,
        _materialized: Some(file),
    })
}

/// Return the first regular executable candidate named `program` on `path`.
fn executable_on_path(program: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// Resolve a configured [`SigningKeySource`] to a path git can open.
///
/// A path source is validated for existence and returned as-is; a command
/// source is run and its output materialized via
/// [`materialize_signing_key_command`].
pub(in crate::registry_ops) fn resolve_signing_key_source(
    key_id: &str,
    source: &SigningKeySource,
) -> Result<ResolvedSigningKey> {
    match (source.path(), source.command()) {
        (Some(_), Some(_)) => {
            bail!("signing key id '{key_id}' configures both 'path' and 'command'; set exactly one")
        }
        (None, None) => {
            bail!("signing key id '{key_id}' configures neither 'path' nor 'command'")
        }
        (Some(path), None) => {
            let path = path.trim();
            if path.is_empty() {
                bail!("local private key path for signing key id '{key_id}' is empty");
            }
            let path_buf = PathBuf::from(path);
            if !path_buf.exists() {
                bail!(
                    "local private key path for signing key id '{key_id}' does not exist: {}",
                    path_buf.display(),
                );
            }
            Ok(ResolvedSigningKey::from_path(path))
        }
        (None, Some(command)) => {
            let command = command.trim();
            if command.is_empty() {
                bail!("signing key command for id '{key_id}' is empty");
            }
            materialize_signing_key_command(command)
                .with_context(|| format!("resolving signing key id '{key_id}' via command"))
        }
    }
}

/// Resolve the maintainer signing key for tag and commit signing.
///
/// `--key` names a private key file used as-is. `--key-id` is looked up in
/// the committed `keys.toml` roster — rejecting revoked ids and keys bound
/// to another registry — and resolved to local key material through the
/// registry config's `[registry.signing_keys]` table (a path or a
/// command). Exactly one of the two must be provided.
pub(in crate::registry_ops) fn resolve_producer_signing_key(
    config: &ApmConfig,
    dir: &Path,
    registry_name: &str,
    key: Option<&str>,
    key_id: Option<&str>,
) -> Result<ResolvedSigningKey> {
    match (key, key_id) {
        (Some(_), Some(_)) => bail!("use only one of --key or --key-id"),
        (Some(key), None) => Ok(ResolvedSigningKey::from_path(key)),
        (None, Some(key_id)) => {
            validate_roster_key_id(key_id)?;
            let roster = load_committed_roster(dir)?;
            if keys::is_revoked(&roster, key_id) {
                bail!("signing key id '{key_id}' is revoked in keys.toml");
            }
            let active = keys::active_key_by_id(&roster, key_id).ok_or_else(|| {
                anyhow::anyhow!("active signing key id '{key_id}' does not exist in keys.toml")
            })?;
            let (entry_registry, _algorithm, _public_key) = parse_signing_key(&active.key)
                .with_context(|| format!("invalid active key '{key_id}'"))?;
            if entry_registry != registry_name {
                bail!(
                    "active signing key id '{key_id}' belongs to registry '{}', expected '{}'",
                    entry_registry,
                    registry_name,
                );
            }

            let registry_config =
                registry_config_by_name(config, registry_name).ok_or_else(|| {
                    anyhow::anyhow!(
                        "--key-id requires registry '{}' to be configured in registries.d",
                        registry_name,
                    )
                })?;
            let source = registry_config.signing_keys.get(key_id).ok_or_else(|| {
                anyhow::anyhow!(
                    "no local private key configured for signing key id '{key_id}'; add [registry.signing_keys] {key_id} = \"/path/to/private-key\" (or {{ command = \"...\" }}) to the registry config or pass --key"
                )
            })?;
            resolve_signing_key_source(key_id, source)
        }
        (None, None) => bail!(
            "--key or --key-id is required: registry release and channel tags must be signed tag objects"
        ),
    }
}

pub(in crate::registry_ops) fn registry_config_by_name<'a>(
    config: &'a ApmConfig,
    registry_name: &str,
) -> Option<&'a RegistryConfig> {
    config
        .registries
        .iter()
        .find(|(registry, _state)| registry.name == registry_name)
        .map(|(registry, _state)| registry)
}

#[cfg(test)]
mod tests;
