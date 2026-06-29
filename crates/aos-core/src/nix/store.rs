//! Per-path wrappers around the classic `nix-*` command-line tools.
//!
//! [`NixCli`] shells out to `nix-instantiate`, `nix-build`, and
//! `nix-store` for instantiation, realisation, closure queries, path
//! metadata, validity checks, and NAR dump/export/import. Unlike
//! [`NixRunner`](crate::nix::NixRunner) it has no notion of a project
//! root: every operation takes explicit file paths, attributes, or
//! store paths, making it suitable for cache and package-manager code
//! that operates on arbitrary stores.
//!
//! All subprocesses inherit the `AOS_ROOT`-derived environment from
//! [`aos_nix_env`], so they target the AOS store layout when
//! `AOS_ROOT` is set and the canonical `/nix/store` otherwise.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::env::aos_nix_env;

/// Metadata for a store path, from nix-store queries or Nix DB.
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// The store path itself.
    pub path: String,
    /// Hash of the path's uncompressed NAR serialisation.
    pub nar_hash: String,
    /// Size in bytes of the uncompressed NAR serialisation.
    pub nar_size: u64,
    /// Store paths referenced by this path.
    pub references: Vec<String>,
    /// The deriver `.drv` path, if known.
    pub deriver: Option<String>,
    /// `name:base64` signatures attached to the path (empty when the
    /// metadata came from plain `nix-store -q` queries, which do not
    /// expose signatures).
    pub signatures: Vec<String>,
}

/// One entry in a `nix path-info --json` response object (keyed by store path).
///
/// Only the fields [`path_info_batch`](NixCli::path_info_batch) needs are
/// deserialized; the JSON carries more (`ca`, `registrationTime`, `ultimate`,
/// `signatures`, `storeDir`).
#[derive(Deserialize)]
struct NixPathInfoJson {
    /// SRI-encoded NAR hash (`sha256-<base64>`); normalised to `sha256:<base32>`.
    #[serde(rename = "narHash")]
    nar_hash: String,
    /// Uncompressed NAR size in bytes.
    #[serde(rename = "narSize")]
    nar_size: u64,
    /// Store paths this path references (may include itself).
    #[serde(default)]
    references: Vec<String>,
    /// The deriver `.drv` path, `null` when unknown.
    #[serde(default)]
    deriver: Option<String>,
}

/// Portable classic Nix command wrapper.
///
/// Wraps `nix-instantiate`, `nix-build`, `nix-store` — works on any Nix
/// installation without experimental features.
pub struct NixCli {
    verbose: u8,
}

impl NixCli {
    /// Creates a wrapper with the given verbosity level; `verbose > 0`
    /// adds `--show-trace` to evaluation commands.
    pub fn new(verbose: u8) -> Self {
        Self { verbose }
    }

    /// Instantiates an attribute from a Nix file, returning the `.drv` path.
    ///
    /// Runs `nix-instantiate -f <file> -A <attr>`; the child's stderr is
    /// passed through to the terminal.
    ///
    /// # Errors
    ///
    /// Returns an error if `nix-instantiate` cannot be spawned, exits
    /// non-zero, or prints non-UTF-8 output.
    pub fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let mut cmd = Command::new("nix-instantiate");
        cmd.envs(aos_nix_env())
            .arg("-f")
            .arg(file)
            .arg("-A")
            .arg(attr);
        if self.verbose > 0 {
            cmd.arg("--show-trace");
        }
        let output = cmd
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run nix-instantiate")?;
        if !output.status.success() {
            anyhow::bail!("nix-instantiate failed for {}", attr);
        }
        let drv = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-instantiate")?
            .trim()
            .to_string();
        Ok(PathBuf::from(drv))
    }

    /// Instantiates a raw Nix expression, returning the `.drv` path.
    ///
    /// Runs `nix-instantiate -E <expr>`; the expression must be
    /// self-contained (responsible for its own imports).
    ///
    /// # Errors
    ///
    /// Returns an error if `nix-instantiate` cannot be spawned, exits
    /// non-zero, or prints non-UTF-8 output.
    pub fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        let mut cmd = Command::new("nix-instantiate");
        cmd.envs(aos_nix_env()).arg("-E").arg(expr);
        if self.verbose > 0 {
            cmd.arg("--show-trace");
        }
        let output = cmd
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run nix-instantiate -E")?;
        if !output.status.success() {
            anyhow::bail!("nix-instantiate -E failed");
        }
        let drv = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-instantiate")?
            .trim()
            .to_string();
        Ok(PathBuf::from(drv))
    }

    /// Builds an attribute from a Nix file, returning the output store path.
    ///
    /// Runs `nix-build <file> -A <attr> --no-out-link`, so no `result`
    /// symlink is created.
    ///
    /// # Errors
    ///
    /// Returns an error if `nix-build` cannot be spawned, exits
    /// non-zero (i.e. the build failed), or prints non-UTF-8 output.
    pub fn build(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let mut cmd = Command::new("nix-build");
        cmd.envs(aos_nix_env())
            .arg(file)
            .arg("-A")
            .arg(attr)
            .arg("--no-out-link");
        if self.verbose > 0 {
            cmd.arg("--show-trace");
        }
        let output = cmd
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run nix-build")?;
        if !output.status.success() {
            anyhow::bail!("nix-build failed for {}", attr);
        }
        let path = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-build")?
            .trim()
            .to_string();
        Ok(PathBuf::from(path))
    }

    /// Realises a `.drv` directly via `nix-store --realise`, returning
    /// the output store path.
    ///
    /// # Errors
    ///
    /// Returns an error if `nix-store` cannot be spawned, the
    /// realisation fails, or the output is not UTF-8.
    pub fn realise(&self, drv: &str) -> Result<String> {
        let output = Command::new("nix-store")
            .envs(aos_nix_env())
            .args(["--realise", drv])
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run nix-store --realise")?;
        if !output.status.success() {
            anyhow::bail!("nix-store --realise failed for {}", drv);
        }
        let path = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-store --realise")?
            .trim()
            .to_string();
        Ok(path)
    }

    /// Returns the recursive closure of a store path (the path itself
    /// plus everything it transitively references), via `nix-store -qR`.
    ///
    /// # Errors
    ///
    /// Returns an error if `nix-store` cannot be spawned, the query
    /// fails (e.g. the path is not valid), or the output is not UTF-8.
    pub fn closure(&self, path: &str) -> Result<Vec<String>> {
        let output = Command::new("nix-store")
            .envs(aos_nix_env())
            .args(["-qR", path])
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run nix-store -qR")?;
        if !output.status.success() {
            anyhow::bail!("nix-store -qR failed for {}", path);
        }
        let text = String::from_utf8(output.stdout).context("invalid utf-8 from nix-store -qR")?;
        Ok(text
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect())
    }

    /// Returns the union recursive closure of many store paths in a single
    /// `nix-store -qR` invocation.
    ///
    /// Equivalent to calling [`closure`](Self::closure) for each path and
    /// unioning the results, but with one subprocess instead of one per path —
    /// the difference between a handful of milliseconds and tens of seconds for a
    /// few-hundred-path installable set. The result is **not** deduplicated or
    /// ordered (overlapping closures repeat); callers that need a unique set
    /// should `sort`/`dedup`.
    ///
    /// # Errors
    ///
    /// Returns an error if `nix-store` cannot be spawned, the query fails (e.g. a
    /// path is not valid), or the output is not UTF-8.
    pub fn closure_many(&self, paths: &[&str]) -> Result<Vec<String>> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let output = Command::new("nix-store")
            .envs(aos_nix_env())
            .arg("-qR")
            .args(paths)
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run nix-store -qR")?;
        if !output.status.success() {
            anyhow::bail!("nix-store -qR failed");
        }
        let text = String::from_utf8(output.stdout).context("invalid utf-8 from nix-store -qR")?;
        Ok(text
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect())
    }

    /// Queries metadata for a store path via individual `nix-store -q`
    /// commands (`--hash`, `--size`, `--references`, `--deriver`).
    ///
    /// A deriver of `unknown-deriver` is mapped to `None`, and
    /// signatures are always empty (the classic CLI does not expose
    /// them).
    ///
    /// # Errors
    ///
    /// Returns an error if any of the underlying queries fails (e.g.
    /// the path is not valid in the store) or the reported size is not
    /// a valid integer.
    pub fn path_info(&self, store_path: &str) -> Result<PathInfo> {
        let hash = run_nix_store_query(store_path, "--hash")?;
        let size_str = run_nix_store_query(store_path, "--size")?;
        let refs_str = run_nix_store_query(store_path, "--references")?;
        let deriver_str = run_nix_store_query(store_path, "--deriver")?;

        let nar_size: u64 = size_str
            .parse()
            .with_context(|| format!("invalid nar size '{size_str}'"))?;

        let references: Vec<String> = refs_str
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect();

        let deriver = if deriver_str == "unknown-deriver" || deriver_str.is_empty() {
            None
        } else {
            Some(deriver_str)
        };

        Ok(PathInfo {
            path: store_path.to_string(),
            nar_hash: hash,
            nar_size,
            references,
            deriver,
            signatures: Vec::new(),
        })
    }

    /// Queries path metadata for many paths in a single `nix path-info --json`
    /// invocation, preserving the input order.
    ///
    /// This is dramatically faster than calling [`path_info`](Self::path_info)
    /// per path: that fans out to ~four `nix-store -q` subprocesses *each*, so a
    /// few-hundred-path closure spent tens of seconds purely on process spawns
    /// (measured ~70x slower than this batch). One `nix path-info --json` returns
    /// every path's hash, size, references, and deriver at once. The NAR hash is
    /// normalised from the JSON's SRI form (`sha256-<base64>`) back to Nix's
    /// `sha256:<base32>` (the narinfo `NarHash` format) via
    /// [`normalize_sha256_nix32`](crate::nar::cache::normalize_sha256_nix32), so
    /// the result is byte-for-byte what the per-path path is built from.
    ///
    /// # Errors
    ///
    /// Returns an error if `nix path-info` cannot be spawned, exits non-zero,
    /// its JSON cannot be parsed, or a requested path is missing from the result.
    pub fn path_info_batch(&self, paths: &[&str]) -> Result<Vec<PathInfo>> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        // `nix path-info` is a new-CLI command; enable `nix-command` explicitly
        // so this works regardless of the ambient experimental-features config.
        let output = Command::new("nix")
            .envs(aos_nix_env())
            .args([
                "--extra-experimental-features",
                "nix-command",
                "path-info",
                "--json",
            ])
            .args(paths)
            .stderr(Stdio::null())
            .output()
            .context("failed to run nix path-info --json")?;
        if !output.status.success() {
            anyhow::bail!("nix path-info --json failed");
        }
        // The response is a JSON object keyed by store path.
        let entries: HashMap<String, NixPathInfoJson> =
            serde_json::from_slice(&output.stdout).context("parsing nix path-info --json")?;
        paths
            .iter()
            .map(|&path| {
                let entry = entries
                    .get(path)
                    .with_context(|| format!("nix path-info returned no entry for {path}"))?;
                Ok(PathInfo {
                    path: path.to_string(),
                    nar_hash: crate::nar::cache::normalize_sha256_nix32(&entry.nar_hash),
                    nar_size: entry.nar_size,
                    references: entry.references.clone(),
                    deriver: entry
                        .deriver
                        .clone()
                        .filter(|d| !d.is_empty() && d != "unknown-deriver"),
                    // Match the per-path `path_info`: upstream signatures are not
                    // carried into the re-published narinfo.
                    signatures: Vec::new(),
                })
            })
            .collect()
    }

    /// Checks whether a store path is valid (registered) in the local
    /// store, via `nix-store --check-validity`.
    ///
    /// # Errors
    ///
    /// Returns an error only if `nix-store` cannot be spawned; an
    /// invalid path yields `Ok(false)`.
    pub fn is_valid(&self, path: &str) -> Result<bool> {
        let status = Command::new("nix-store")
            .envs(aos_nix_env())
            .args(["--check-validity", path])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("failed to run nix-store --check-validity")?;
        Ok(status.success())
    }

    /// Spawns `nix-store --dump <path>` with piped stdout, producing a
    /// bare NAR stream.
    ///
    /// The caller owns the returned [`Child`] and must read its stdout
    /// and `wait` on it.
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be spawned. A dump
    /// failure surfaces later through the child's exit status.
    #[allow(dead_code)] // public API
    pub fn nar_dump(&self, path: &str) -> Result<Child> {
        Command::new("nix-store")
            .envs(aos_nix_env())
            .args(["--dump", path])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning nix-store --dump {path}"))
    }

    /// Spawns `nix-store --export <path>` with piped stdout, producing
    /// an export stream (NAR plus metadata trailer; see
    /// [`crate::nar::export`]).
    ///
    /// The caller owns the returned [`Child`] and must read its stdout
    /// and `wait` on it.
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be spawned. An export
    /// failure surfaces later through the child's exit status.
    #[allow(dead_code)] // public API
    pub fn nar_export(&self, path: &str) -> Result<Child> {
        Command::new("nix-store")
            .envs(aos_nix_env())
            .args(["--export", path])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning nix-store --export {path}"))
    }

    /// Pipes an export stream to `nix-store --import` and returns the
    /// imported store paths.
    ///
    /// The data must be a framed import stream as produced by
    /// `nix-store --export` (or
    /// [`ExportTrailer::write_import_stream`](crate::nar::export::ExportTrailer::write_import_stream)).
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be spawned, the data
    /// cannot be written to its stdin, the import fails, or the output
    /// is not UTF-8.
    #[allow(dead_code)] // public API
    pub fn nar_import(&self, mut data: impl Read) -> Result<Vec<String>> {
        let mut child = Command::new("nix-store")
            .envs(aos_nix_env())
            .arg("--import")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("failed to spawn nix-store --import")?;

        {
            let stdin = child
                .stdin
                .as_mut()
                .context("no stdin for nix-store --import")?;
            std::io::copy(&mut data, stdin).context("writing to nix-store --import")?;
        }

        let output = child
            .wait_with_output()
            .context("waiting for nix-store --import")?;
        if !output.status.success() {
            anyhow::bail!("nix-store --import failed");
        }

        let text =
            String::from_utf8(output.stdout).context("invalid utf-8 from nix-store --import")?;
        Ok(text
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect())
    }
}

/// Runs a single `nix-store -q <flag> <path>` query and returns its
/// trimmed stdout. Stderr is discarded; failures map to an error.
fn run_nix_store_query(path: &str, flag: &str) -> Result<String> {
    let output = Command::new("nix-store")
        .envs(aos_nix_env())
        .args(["-q", flag, path])
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("nix-store -q {flag} {path}"))?;
    if !output.status.success() {
        anyhow::bail!("nix-store -q {flag} failed for {path}");
    }
    Ok(String::from_utf8(output.stdout)
        .context("invalid utf-8")?
        .trim()
        .to_string())
}
