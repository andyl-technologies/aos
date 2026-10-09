//! Fixed-NAR module inputs and pure stock-Nix command construction.
//!
//! Source locations and canonical artifact identities are kept separate so a
//! caller can provide an immutable store view without changing generated plans.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use base64::Engine as _;

/// Constructs a scrubbed stock-Nix command for an explicit evaluator store.
///
/// The supplied immutable Nix suite is shared with source admission. Callers
/// add only exact authenticated inputs and the expression/attribute they need.
///
/// # Errors
/// Returns an error for an invalid or unavailable Nix suite, missing evaluator, or an
/// unresolved cache directory.
pub(crate) fn pure_eval_command_in(
    nix_store: &Path,
    store: Option<&OsStr>,
    read_root: Option<&Path>,
    eval_root: &Path,
) -> Result<Command> {
    let selected = aos_nix::identity::store_command(nix_store)?;
    let executable = Path::new(selected.get_program())
        .parent()
        .context("selected Nix suite has no directory")?
        .join("nix-instantiate");
    ensure!(executable.is_file(), "selected Nix suite has no evaluator");
    let mut command = Command::new(executable);
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

/// Scrubs an evaluator command and restricts it to the selected immutable inputs.
///
/// # Errors
/// Returns an error if the evaluator cache directory cannot be resolved to an absolute
/// path.
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
        // Inputs are exported from the selected store before evaluation. A
        // fetchTree cache miss must use those inputs, never a global cache.
        .args(["--option", "substituters", ""])
        .args(["--option", "allow-import-from-derivation", "false"])
        .args(["--option", "allowed-uris", &allowed_uris]);

    Ok(())
}

/// Builds a fixed-NAR fetch expression preserving the canonical input identity.
///
/// # Errors
/// Returns an error for a noncanonical identity, an insufficient read-path suffix, a
/// non-UTF-8 path, or an invalid SHA-256 hash.
pub(crate) fn locked_evaluator_input(identity: &Path, read_path: &Path, nar_hash: &str) -> Result<String> {
    let (_, suffix) = store_root_and_suffix(identity)?;
    let read_root = read_path
        .ancestors()
        .nth(suffix.components().count())
        .context("evaluator read path is shorter than its canonical suffix")?;
    let nar_hash = sha256_sri(nar_hash)?;
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

// Parsing is shared with portable deployment envelopes and performs no I/O.
pub use aos_deployment_format::locator::store_root_and_suffix;

fn sha256_sri(hash: &str) -> Result<String> {
    let hex = aos_nar::cache::canonical_sha256_hex(hash)?;
    let digest = hex::decode(hex).context("decoding normalized evaluator input hash")?;
    Ok(format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    ))
}

/// Renders a Rust string as a quoted Nix string literal.
pub fn nix_string(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace("${", "\\${")
    )
}
