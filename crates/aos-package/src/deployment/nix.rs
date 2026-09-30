//! Fixed-NAR module inputs and pure stock-Nix command construction.
//!
//! Source locations and canonical artifact identities are kept separate so a
//! caller can provide an immutable store view without changing generated plans.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;

/// Keeps one canonical store identity separate from its selected readable path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluatorInput {
    /// Canonical package-store identity used by Nix store operations.
    pub identity: PathBuf,
    /// Physical immutable path used only for direct byte reads.
    pub read_path: PathBuf,
}

impl EvaluatorInput {
    /// Uses the canonical immutable store path as its readable location.
    pub fn canonical(path: PathBuf) -> Self {
        Self {
            read_path: path.clone(),
            identity: path,
        }
    }
}

/// Resolves an AOS-built executable before constructing a scrubbed command.
fn command_from_path(name: &str) -> Result<Command> {
    let path = std::env::var_os("PATH").context("PATH is unavailable while resolving evaluator")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Ok(Command::new(candidate));
        }
    }
    anyhow::bail!("cannot find {name} in the AOS command path")
}

/// Constructs a scrubbed stock-Nix command for an explicit evaluator store.
///
/// The executable is resolved before the environment is cleared. Callers add
/// only exact authenticated inputs and the expression/attribute they need.
pub(crate) fn pure_eval_command_in(
    store: Option<&OsStr>,
    read_root: Option<&Path>,
    eval_root: &Path,
) -> Result<Command> {
    let mut command = command_from_path("nix-instantiate")?;
    let nix_cache_home = std::env::var_os("XDG_CACHE_HOME");
    configure_pure_eval_command(
        &mut command,
        eval_root,
        nix_cache_home.as_deref(),
        store,
        read_root,
    )?;
    Ok(command)
}

pub(crate) fn configure_pure_eval_command(
    command: &mut Command,
    eval_root: &Path,
    nix_cache_home: Option<&OsStr>,
    store: Option<&OsStr>,
    read_root: Option<&Path>,
) -> Result<()> {
    let nix_cache_home = match nix_cache_home.filter(|path| !path.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => std::path::absolute(eval_root.join("nix-cache"))
            .context("resolving the evaluator's Nix cache directory")?,
    };

    command.env_clear();
    if let Some(store) = store {
        command.arg("--store").arg(store);
    }
    // Nix creates client cache state even for pure evaluation. The service
    // supplies a persistent cache; interactive evaluation instead uses its
    // writable staging root and never falls back to the image's read-only home.
    command.env("XDG_CACHE_HOME", nix_cache_home);
    let allowed_uris = read_root.map_or_else(
        || "path:/nix/store/".to_string(),
        |root| format!("path:/nix/store/ path:{}/", root.display()),
    );
    command
        .args(["--extra-experimental-features", "nix-command flakes"])
        .args(["--eval", "--strict", "--json", "--pure-eval"])
        .args(["--option", "restrict-eval", "true"])
        .args(["--option", "allow-import-from-derivation", "false"])
        .args(["--option", "allowed-uris", &allowed_uris]);

    Ok(())
}

pub(crate) fn locked_evaluator_input_in(
    input: &EvaluatorInput,
    expected_nar_hash: Option<&str>,
    eval_store: Option<&OsStr>,
) -> Result<String> {
    let (identity_root, suffix) = store_root_and_suffix(&input.identity)?;
    let read_root = input
        .read_path
        .ancestors()
        .nth(suffix.components().count())
        .context("evaluator read path is shorter than its canonical suffix")?;
    let nar_hash = expected_nar_hash.map_or_else(
        || retained_store_path_nar_hash_in(&identity_root, eval_store),
        |hash| Ok(hash.to_string()),
    )?;
    let nar_hash = sha256_sri(&nar_hash)?;
    let root = read_root
        .to_str()
        .context("evaluator store input path is not UTF-8")?;
    let fetched = format!(
        "(builtins.fetchTree {{ type = \"path\"; path = {}; narHash = {}; }}).outPath",
        nix_string(root),
        nix_string(&nar_hash),
    );
    if suffix.as_os_str().is_empty() {
        Ok(fetched)
    } else {
        let suffix = suffix
            .to_str()
            .context("evaluator store input suffix is not UTF-8")?;
        Ok(format!(
            "({fetched} + {})",
            nix_string(&format!("/{suffix}"))
        ))
    }
}

pub(crate) fn store_root_and_suffix(path: &Path) -> Result<(PathBuf, PathBuf)> {
    let relative = path
        .strip_prefix("/nix/store")
        .with_context(|| format!("evaluator input {} is outside /nix/store", path.display()))?;
    let mut components = relative.components();
    let Some(std::path::Component::Normal(root_name)) = components.next() else {
        bail!("evaluator input has no valid store object component");
    };
    let root_name = root_name
        .to_str()
        .context("evaluator store object name is not UTF-8")?;
    let (hash, name) = root_name
        .split_at_checked(32)
        .and_then(|(hash, suffix)| suffix.strip_prefix('-').map(|name| (hash, name)))
        .context("evaluator input has a malformed store object name")?;
    ensure!(
        hash.bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte)),
        "evaluator input has an invalid Nix store hash"
    );
    ensure!(
        !name.is_empty()
            && name.len() <= 211
            && name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
            }),
        "evaluator input has an invalid Nix store name"
    );

    let root = Path::new("/nix/store").join(root_name);
    let mut suffix = PathBuf::new();
    for component in components {
        let std::path::Component::Normal(component) = component else {
            bail!("evaluator input has a non-canonical store-path suffix");
        };
        suffix.push(component);
    }
    Ok((root, suffix))
}

fn sha256_sri(hash: &str) -> Result<String> {
    let hex = crate::verify::sha256_digest_hex(hash)?;
    let digest = hex::decode(hex).context("decoding normalized evaluator input hash")?;
    Ok(format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    ))
}

/// Renders a Rust string as a quoted Nix string literal.
pub(crate) fn nix_string(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace("${", "\\${")
    )
}

/// Recomputes a store path's NAR hash through one exact evaluator store.
pub(crate) fn retained_store_path_nar_hash_in(
    path: &Path,
    eval_store: Option<&std::ffi::OsStr>,
) -> Result<String> {
    let mut command = std::process::Command::new("nix");
    command
        .args(["--extra-experimental-features", "nix-command"])
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("NIX_REMOTE")
        .env_remove("NIX_STORE_DIR")
        .env_remove("NIX_STATE_DIR")
        .env_remove("NIX_LOG_DIR");
    if let Some(eval_store) = eval_store {
        command.arg("--store").arg(eval_store);
    }
    let mut child = command
        .args(["store", "dump-path"])
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running nix store dump-path {}", path.display()))?;
    let stdout = child
        .stdout
        .take()
        .context("nix store dump-path did not provide stdout")?;
    let hash = crate::verify::sha256_stream(stdout);
    let output = child
        .wait_with_output()
        .with_context(|| format!("waiting for nix store dump-path {}", path.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "nix store dump-path failed for {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    hash
}
