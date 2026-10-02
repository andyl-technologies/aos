//! Fixed-NAR module inputs and pure stock-Nix command construction.
//!
//! Source locations and canonical artifact identities are kept separate so a
//! caller can provide an immutable store view without changing generated plans.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;

/// Constructs a scrubbed stock-Nix command for an explicit evaluator store.
///
/// The supplied immutable Nix suite is shared with source admission. Callers
/// add only exact authenticated inputs and the expression/attribute they need.
pub(crate) fn pure_eval_command_in(
    nix_store: &Path,
    store: Option<&OsStr>,
    read_root: Option<&Path>,
    eval_root: &Path,
) -> Result<Command> {
    let selected = aos_core::nix::identity::store_command(nix_store)?;
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

pub(crate) fn locked_evaluator_input(
    identity: &Path,
    read_path: &Path,
    nar_hash: &str,
) -> Result<String> {
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
