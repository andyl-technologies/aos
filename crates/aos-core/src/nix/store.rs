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
//! `aos_nix_env`, so they target the AOS store layout when
//! `AOS_ROOT` is set and the canonical `/nix/store` otherwise.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Deserialize;

use super::env::{aos_nix_command, aos_nix_env};
use super::eval::{DrvClosure, NixEval, NixEvalConfig};
use aos_nix_compat::drv::parse_drv_input_drvs_from_bytes;

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

/// Instantiation output plus raw C++ Nix evaluation statistics and wall time.
#[derive(Debug, Clone, PartialEq)]
pub struct NixInstantiateStats {
    /// The `.drv` path emitted by `nix-instantiate`.
    pub drv_path: PathBuf,
    /// The raw `NIX_SHOW_STATS=1` JSON object emitted by C++ Nix.
    pub stats: serde_json::Value,
    /// Wall-clock time spent waiting for the `nix-instantiate` oracle process.
    pub elapsed: Duration,
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
    eval_config: NixEvalConfig,
}

impl NixCli {
    /// Creates a wrapper with the given verbosity level; `verbose > 0`
    /// adds `--show-trace` to evaluation commands.
    pub fn new(verbose: u8) -> Self {
        Self::with_eval_config(verbose, NixEvalConfig::default())
    }

    /// Creates a wrapper with explicit evaluator settings.
    pub fn with_eval_config(verbose: u8, eval_config: NixEvalConfig) -> Self {
        Self {
            verbose,
            eval_config,
        }
    }

    /// Instantiates an attribute from a Nix file, returning the `.drv` path.
    ///
    /// Runs `nix-instantiate <file> -A <attr>`; the child's stderr is
    /// replayed to the terminal and included in failure errors.
    ///
    /// # Errors
    ///
    /// Returns an error if `nix-instantiate` cannot be spawned, exits
    /// non-zero, or prints non-UTF-8 output.
    pub fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let mut cmd = self.nix_command("nix-instantiate");
        let file = self.eval_config.resolve_eval_file_path(file);
        cmd.arg(file).arg("-A").arg(attr);
        self.append_eval_options(&mut cmd);
        if self.verbose > 0 {
            cmd.arg("--show-trace");
        }
        let output = output_with_replayed_stderr(cmd, "failed to run nix-instantiate")?;
        if !output.status.success() {
            return Err(command_status_error(
                format!("nix-instantiate failed for {attr}"),
                &output,
            ));
        }
        let drv = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-instantiate")?
            .trim()
            .to_string();
        Ok(PathBuf::from(drv))
    }

    /// Instantiates an attribute and captures `NIX_SHOW_STATS` output.
    ///
    /// Runs `NIX_SHOW_STATS=1 nix-instantiate <file> -A <attr>` and returns both
    /// the emitted `.drv` path and the raw stats JSON object. Stats are captured
    /// through `NIX_SHOW_STATS_PATH` when available, with stdout/stderr parsing
    /// retained as a compatibility fallback.
    ///
    /// # Errors
    ///
    /// Returns an error if `nix-instantiate` cannot be spawned, exits non-zero,
    /// prints invalid UTF-8, or its output does not contain exactly one `.drv`
    /// path line plus a parseable `NIX_SHOW_STATS` JSON object.
    pub fn instantiate_with_stats(&self, file: &Path, attr: &str) -> Result<NixInstantiateStats> {
        let mut cmd = self.nix_command("nix-instantiate");
        let file = self.eval_config.resolve_eval_file_path(file);
        cmd.arg(file).arg("-A").arg(attr);
        let stats_dir = tempfile::Builder::new()
            .prefix("aos-nix-show-stats-")
            .tempdir()
            .context("creating temporary NIX_SHOW_STATS directory")?;
        let stats_path = stats_dir.path().join("stats.json");
        cmd.env("NIX_SHOW_STATS", "1");
        cmd.env("NIX_SHOW_STATS_PATH", &stats_path);
        self.append_eval_options(&mut cmd);
        if self.verbose > 0 {
            cmd.arg("--show-trace");
        }
        let started = Instant::now();
        let output = match cmd.stderr(Stdio::piped()).output() {
            Ok(output) => output,
            Err(error) => return Err(error).context("failed to run nix-instantiate with stats"),
        };
        let elapsed = started.elapsed();
        if !output.status.success() {
            return Err(command_status_error(
                format!("nix-instantiate with stats failed for {attr}"),
                &output,
            ));
        }
        let stats = parse_instantiate_stats_output_with_file(
            &output.stdout,
            &output.stderr,
            elapsed,
            &stats_path,
        );
        stats
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
        let mut cmd = self.nix_command("nix-instantiate");
        cmd.arg("-E").arg(expr);
        self.append_eval_options(&mut cmd);
        if self.verbose > 0 {
            cmd.arg("--show-trace");
        }
        let output = output_with_replayed_stderr(cmd, "failed to run nix-instantiate -E")?;
        if !output.status.success() {
            return Err(command_status_error("nix-instantiate -E failed", &output));
        }
        let drv = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-instantiate")?
            .trim()
            .to_string();
        Ok(PathBuf::from(drv))
    }

    /// Instantiates an attribute and reads its input-derivation closure.
    ///
    /// # Errors
    ///
    /// Returns an error if instantiation fails, a `.drv` file cannot be read,
    /// or a `.drv` input-derivation section cannot be parsed.
    pub fn instantiate_closure(&self, file: &Path, attr: &str) -> Result<DrvClosure> {
        let root = self.instantiate(file, attr)?;
        read_drv_closure(root)
    }

    /// Evaluates a raw Nix expression with strict JSON rendering.
    ///
    /// Runs `nix-instantiate --eval --strict --json -E <expr>` and
    /// returns the raw JSON text emitted by Nix.
    ///
    /// # Errors
    ///
    /// Returns an error if `nix-instantiate` cannot be spawned, exits
    /// non-zero, or prints non-UTF-8 output.
    pub fn eval_expr(&self, expr: &str) -> Result<String> {
        let mut cmd = self.nix_command("nix-instantiate");
        cmd.args(["--eval", "--strict", "--json", "-E"]).arg(expr);
        self.append_eval_options(&mut cmd);
        if self.verbose > 0 {
            cmd.arg("--show-trace");
        }
        let output =
            output_with_replayed_stderr(cmd, "failed to run nix-instantiate --eval --json -E")?;
        if !output.status.success() {
            return Err(command_status_error(
                "nix-instantiate --eval --json -E failed",
                &output,
            ));
        }
        let value = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-instantiate --eval --json")?
            .trim()
            .to_string();
        Ok(value)
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
        let mut cmd = self.nix_command("nix-build");
        let file = self.eval_config.resolve_eval_file_path(file);
        cmd.arg(file).arg("-A").arg(attr).arg("--no-out-link");
        self.append_eval_options(&mut cmd);
        if self.verbose > 0 {
            cmd.arg("--show-trace");
        }
        let output = output_with_replayed_stderr(cmd, "failed to run nix-build")?;
        if !output.status.success() {
            return Err(command_status_error(
                format!("nix-build failed for {attr}"),
                &output,
            ));
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
        let mut cmd = self.nix_command("nix-store");
        cmd.args(["--realise", drv]);
        let output = output_with_replayed_stderr(cmd, "failed to run nix-store --realise")?;
        if !output.status.success() {
            return Err(command_status_error(
                format!("nix-store --realise failed for {drv}"),
                &output,
            ));
        }
        let path = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-store --realise")?
            .trim()
            .to_string();
        Ok(path)
    }

    fn nix_command(&self, program: &str) -> Command {
        let mut cmd = aos_nix_command(program);
        self.eval_config.apply_cli_env(&mut cmd);
        cmd
    }

    fn append_eval_options(&self, cmd: &mut Command) {
        for arg in self.eval_config.cli_search_path_args() {
            cmd.arg(arg);
        }
        for arg in self.eval_config.cli_option_args() {
            cmd.arg(arg);
        }
    }

    /// Returns the recursive closure of a store path (the path itself
    /// plus everything it transitively references), via `nix-store -qR`.
    ///
    /// # Errors
    ///
    /// Returns an error if `nix-store` cannot be spawned, the query
    /// fails (e.g. the path is not valid), or the output is not UTF-8.
    pub fn closure(&self, path: &str) -> Result<Vec<String>> {
        let mut cmd = self.nix_command("nix-store");
        cmd.args(["-qR", path]);
        let output = output_with_replayed_stderr(cmd, "failed to run nix-store -qR")?;
        if !output.status.success() {
            return Err(command_status_error(
                format!("nix-store -qR failed for {path}"),
                &output,
            ));
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
        let hash = self.run_nix_store_query(store_path, "--hash")?;
        let size_str = self.run_nix_store_query(store_path, "--size")?;
        let refs_str = self.run_nix_store_query(store_path, "--references")?;
        let deriver_str = self.run_nix_store_query(store_path, "--deriver")?;

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
        let status = self
            .nix_command("nix-store")
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
        self.nix_command("nix-store")
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
        self.nix_command("nix-store")
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
        let mut child = self
            .nix_command("nix-store")
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

    /// Runs a single `nix-store -q <flag> <path>` query and returns its
    /// trimmed stdout. Stderr is discarded; failures map to an error.
    fn run_nix_store_query(&self, path: &str, flag: &str) -> Result<String> {
        let output = self
            .nix_command("nix-store")
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
}

fn parse_instantiate_stats_output_with_file(
    stdout: &[u8],
    stderr: &[u8],
    elapsed: Duration,
    stats_path: &Path,
) -> Result<NixInstantiateStats> {
    parse_instantiate_stats_output_from(stdout, stderr, elapsed, Some(stats_path))
}

fn parse_instantiate_stats_output_from(
    stdout: &[u8],
    stderr: &[u8],
    elapsed: Duration,
    stats_path: Option<&Path>,
) -> Result<NixInstantiateStats> {
    let text = String::from_utf8(stdout.to_vec())
        .context("invalid utf-8 from nix-instantiate with stats")?;
    let mut path_line_index = None;
    let mut path_line = None;
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && trimmed.ends_with(".drv") {
            if path_line.is_some() {
                anyhow::bail!("nix-instantiate with stats emitted multiple .drv path lines");
            }
            path_line_index = Some(index);
            path_line = Some(trimmed.to_string());
        }
    }

    let path_line_index =
        path_line_index.context("nix-instantiate with stats emitted no .drv path line")?;
    let drv_path = PathBuf::from(path_line.context("missing .drv path line")?);
    let stats_text = text
        .lines()
        .enumerate()
        .filter_map(|(index, line)| (index != path_line_index).then_some(line))
        .collect::<Vec<_>>()
        .join("\n");
    let stats = parse_nix_show_stats(stats_path, stderr, &stats_text)?;

    Ok(NixInstantiateStats {
        drv_path,
        stats,
        elapsed,
    })
}

fn parse_nix_show_stats(
    stats_path: Option<&Path>,
    stderr: &[u8],
    stdout_without_drv_path: &str,
) -> Result<serde_json::Value> {
    if let Some(stats_path) = stats_path {
        match fs::read_to_string(stats_path) {
            Ok(text) => {
                return parse_nix_show_stats_json(&text).with_context(|| {
                    format!("parsing NIX_SHOW_STATS file {}", stats_path.display())
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("reading NIX_SHOW_STATS file {}", stats_path.display())
                });
            }
        }
    }

    let stderr = String::from_utf8(stderr.to_vec())
        .context("invalid utf-8 from nix-instantiate with stats stderr")?;
    parse_nix_show_stats_json(&stderr)
        .or_else(|_| parse_nix_show_stats_json(stdout_without_drv_path))
        .context("parsing NIX_SHOW_STATS JSON from nix-instantiate")
}

fn parse_nix_show_stats_json(text: &str) -> Result<serde_json::Value> {
    let mut parsed = Vec::new();
    let mut consumed_until = 0;
    for (start, _) in text.match_indices('{') {
        if start < consumed_until {
            continue;
        }
        let mut stream =
            serde_json::Deserializer::from_str(&text[start..]).into_iter::<serde_json::Value>();
        let Some(Ok(value)) = stream.next() else {
            continue;
        };
        if is_nix_show_stats_object(&value) {
            consumed_until = start + stream.byte_offset();
            parsed.push(value);
        }
    }

    match parsed.len() {
        1 => Ok(parsed.remove(0)),
        0 => anyhow::bail!("NIX_SHOW_STATS output contained no JSON object"),
        count => anyhow::bail!("NIX_SHOW_STATS output contained {count} JSON objects"),
    }
}

fn is_nix_show_stats_object(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.contains_key("cpuTime")
        || object.contains_key("nrThunks")
        || object.contains_key("nrExprs")
}

impl NixEval for NixCli {
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        Self::instantiate(self, file, attr)
    }

    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        Self::instantiate_expr(self, expr)
    }

    fn instantiate_closure(&self, file: &Path, attr: &str) -> Result<Option<DrvClosure>> {
        Self::instantiate_closure(self, file, attr).map(Some)
    }

    fn eval_expr(&self, expr: &str) -> Result<String> {
        Self::eval_expr(self, expr)
    }

    fn name(&self) -> &'static str {
        "nix-cli"
    }
}

pub(crate) fn read_drv_closure(root: PathBuf) -> Result<DrvClosure> {
    // Instantiation can yield a *deriving path* — a `.drv` with an output
    // selector, e.g. `…-glibc-2.39.drv!getent` from `lib.getOutput "getent"
    // stdenv.glibc`. The selector names an output but the on-disk artifact is the
    // plain `.drv`; resolve to it so the file can be read and the closure rooted
    // consistently with the candidate evaluator.
    let root = resolve_drv_file_path(root);
    let mut drvs = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    read_drv_closure_at(&root, &mut visiting, &mut drvs)?;
    Ok(DrvClosure::new(root, drvs))
}

/// Strips a trailing `!<output>` deriving-path selector to the `.drv` file path.
fn resolve_drv_file_path(path: PathBuf) -> PathBuf {
    if let Some(text) = path.to_str() {
        if let Some(marker) = text.find(".drv!") {
            return PathBuf::from(&text[..marker + ".drv".len()]);
        }
    }
    path
}

fn read_drv_closure_at(
    path: &Path,
    visiting: &mut BTreeSet<PathBuf>,
    drvs: &mut BTreeMap<PathBuf, Vec<u8>>,
) -> Result<()> {
    if drvs.contains_key(path) || !visiting.insert(path.to_path_buf()) {
        return Ok(());
    }

    let bytes = std::fs::read(path).with_context(|| format!("reading drv {}", path.display()))?;
    let inputs = parse_drv_input_drvs_from_bytes(&bytes)
        .with_context(|| format!("parsing input derivations from {}", path.display()))?;
    drvs.insert(path.to_path_buf(), bytes);
    visiting.remove(path);

    for input in inputs {
        read_drv_closure_at(Path::new(&input.drv_path), visiting, drvs)?;
    }

    Ok(())
}

fn output_with_replayed_stderr(
    mut cmd: Command,
    context: impl std::fmt::Display,
) -> Result<Output> {
    let output = cmd
        .stderr(Stdio::piped())
        .output()
        .with_context(|| context.to_string())?;
    if !output.stderr.is_empty() {
        let _ = std::io::stderr().write_all(&output.stderr);
    }
    Ok(output)
}

fn command_status_error(summary: impl Into<String>, output: &Output) -> anyhow::Error {
    anyhow::anyhow!(command_failure_message(summary.into(), &output.stderr))
}

fn command_failure_message(mut summary: String, stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let stderr = stderr.trim();
    if !stderr.is_empty() {
        summary.push_str(": ");
        summary.push_str(stderr);
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_args(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn command_env(command: &Command, name: &str) -> Option<String> {
        command
            .get_envs()
            .find(|(key, _)| *key == name)
            .and_then(|(_, value)| value.map(|value| value.to_string_lossy().into_owned()))
    }

    #[test]
    fn eval_config_emits_cpp_nix_system_option() -> Result<()> {
        let nix =
            NixCli::with_eval_config(0, NixEvalConfig::with_current_system("aos-test-target")?);
        let mut command = Command::new("nix-instantiate");
        nix.append_eval_options(&mut command);

        assert_eq!(
            command_args(&command),
            ["--option", "system", "aos-test-target"]
        );
        Ok(())
    }

    #[test]
    fn eval_config_emits_cpp_nix_trace_verbose_option() {
        let mut config = NixEvalConfig::new();
        config.set_trace_verbose(true);
        let nix = NixCli::with_eval_config(0, config);
        let mut command = Command::new("nix-instantiate");
        nix.append_eval_options(&mut command);

        assert_eq!(
            command_args(&command),
            ["--option", "trace-verbose", "true"]
        );
    }

    #[test]
    fn eval_config_emits_restricted_paths_as_cpp_nix_search_paths() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(crate::nix::NixEvalMode::Restricted);
        config.set_allowed_paths(["/aos/src", "/aos/store"])?;
        let nix = NixCli::with_eval_config(0, config);
        let mut command = Command::new("nix-instantiate");
        nix.append_eval_options(&mut command);

        assert_eq!(
            command_args(&command),
            [
                "-I",
                "/aos/src",
                "-I",
                "/aos/store",
                "--option",
                "pure-eval",
                "false",
                "--option",
                "restrict-eval",
                "true",
                "--option",
                "allowed-impure-host-deps",
                "/aos/src /aos/store",
                "--option",
                "allowed-uris",
                ""
            ]
        );
        Ok(())
    }

    #[test]
    fn eval_config_emits_cpp_nix_store_env() -> Result<()> {
        let config =
            NixEvalConfig::with_store_dirs("/aos/store", "/aos/var/nix", "/aos/var/nix/log/nix")?;
        let nix = NixCli::with_eval_config(0, config);
        let command = nix.nix_command("nix-instantiate");

        assert_eq!(
            command_env(&command, "NIX_STORE_DIR").as_deref(),
            Some("/aos/store")
        );
        assert_eq!(
            command_env(&command, "NIX_STATE_DIR").as_deref(),
            Some("/aos/var/nix")
        );
        assert_eq!(
            command_env(&command, "NIX_LOG_DIR").as_deref(),
            Some("/aos/var/nix/log/nix")
        );
        Ok(())
    }

    #[test]
    fn parse_instantiate_stats_output_accepts_stderr_stats_and_stdout_drv_path() -> Result<()> {
        let stdout = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo.drv\n";
        let stderr = br#"warning: you did not specify '--add-root'
{
  "cpuTime": 0.125,
  "nrThunks": 7,
  "time": {
    "cpu": 0.125
  }
}
"#;

        let parsed =
            parse_instantiate_stats_output_from(stdout, stderr, Duration::from_millis(125), None)?;

        assert_eq!(
            parsed.drv_path,
            PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo.drv")
        );
        assert_eq!(parsed.stats["nrThunks"], 7);
        assert_eq!(parsed.stats["time"]["cpu"], 0.125);
        assert_eq!(parsed.elapsed, Duration::from_millis(125));
        Ok(())
    }

    #[test]
    fn parse_instantiate_stats_output_accepts_stdout_fallback() -> Result<()> {
        let stdout = br#"{
  "cpuTime": 0.125,
  "nrThunks": 7
}
/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo.drv
"#;

        let parsed =
            parse_instantiate_stats_output_from(stdout, b"", Duration::from_millis(250), None)?;

        assert_eq!(
            parsed.drv_path,
            PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo.drv")
        );
        assert_eq!(parsed.stats["nrThunks"], 7);
        assert_eq!(parsed.elapsed, Duration::from_millis(250));
        Ok(())
    }

    #[test]
    fn parse_instantiate_stats_output_ignores_json_warning() -> Result<()> {
        let stdout = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo.drv\n";
        let stderr = br#"warning: {"x":true}
{
  "cpuTime": 0.125,
  "nrThunks": 7
}
"#;

        let parsed =
            parse_instantiate_stats_output_from(stdout, stderr, Duration::from_millis(375), None)?;

        assert_eq!(parsed.stats["nrThunks"], 7);
        assert_eq!(parsed.stats.get("x"), None);
        assert_eq!(parsed.elapsed, Duration::from_millis(375));
        Ok(())
    }

    #[test]
    fn parse_instantiate_stats_output_prefers_stats_file() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let stats_path = temp.path().join("stats.json");
        fs::write(&stats_path, br#"{"cpuTime":0.5,"nrThunks":9,"nrExprs":11}"#)?;

        let parsed = parse_instantiate_stats_output_with_file(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo.drv\n",
            br#"{"cpuTime":0.1,"nrThunks":1,"nrExprs":2}"#,
            Duration::from_millis(50),
            &stats_path,
        )?;

        assert_eq!(parsed.stats["nrThunks"], 9);
        assert_eq!(parsed.stats["nrExprs"], 11);
        assert_eq!(parsed.stats["cpuTime"], 0.5);
        assert_eq!(parsed.elapsed, Duration::from_millis(50));
        Ok(())
    }

    #[test]
    fn parse_instantiate_stats_output_with_stats_file_ignores_non_utf8_stderr() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let stats_path = temp.path().join("stats.json");
        fs::write(&stats_path, br#"{"cpuTime":0.5,"nrThunks":9,"nrExprs":11}"#)?;

        let parsed = parse_instantiate_stats_output_with_file(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo.drv\n",
            b"\xff",
            Duration::from_millis(50),
            &stats_path,
        )?;

        assert_eq!(parsed.stats["nrThunks"], 9);
        assert_eq!(parsed.stats["nrExprs"], 11);
        assert_eq!(parsed.stats["cpuTime"], 0.5);
        Ok(())
    }

    #[test]
    fn parse_instantiate_stats_output_falls_back_when_stats_file_is_missing() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let missing_stats_path = temp.path().join("missing.json");

        let parsed = parse_instantiate_stats_output_with_file(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo.drv\n",
            br#"{"cpuTime":0.25,"nrThunks":3,"nrExprs":5}"#,
            Duration::from_millis(75),
            &missing_stats_path,
        )?;

        assert_eq!(parsed.stats["nrThunks"], 3);
        assert_eq!(parsed.stats["nrExprs"], 5);
        assert_eq!(parsed.stats["cpuTime"], 0.25);
        assert_eq!(parsed.elapsed, Duration::from_millis(75));
        Ok(())
    }

    #[test]
    fn parse_instantiate_stats_output_rejects_malformed_stats_file() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let stats_path = temp.path().join("stats.json");
        fs::write(&stats_path, "not json")?;

        let error = parse_instantiate_stats_output_with_file(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-demo.drv\n",
            br#"{"cpuTime":0.25,"nrThunks":3,"nrExprs":5}"#,
            Duration::from_millis(75),
            &stats_path,
        )
        .expect_err("malformed stats file should not fall back to stderr");

        assert!(
            error.to_string().contains("parsing NIX_SHOW_STATS file"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn parse_instantiate_stats_output_rejects_missing_drv_path() {
        let error =
            parse_instantiate_stats_output_from(b"", br#"{"nrThunks":0}"#, Duration::ZERO, None)
                .expect_err("stats without a drv path should fail");

        assert!(
            error.to_string().contains("emitted no .drv path line"),
            "{error:#}"
        );
    }

    #[test]
    fn read_drv_closure_follows_input_derivations() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("root.drv");
        let input = dir.path().join("input.drv");
        let input_text = input.to_string_lossy();
        let root_bytes = format!(
            r#"Derive([("out","/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root","","")],[("{input_text}",["out"])],[],"x86_64-linux","/nix/store/cccccccccccccccccccccccccccccccc-builder",[],[])"#
        )
        .into_bytes();
        let input_bytes =
            br#"Derive([("out","/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-input","","")],[],[],"x86_64-linux","/nix/store/cccccccccccccccccccccccccccccccc-builder",[],[])"#
                .to_vec();
        std::fs::write(&root, &root_bytes)?;
        std::fs::write(&input, &input_bytes)?;

        let closure = read_drv_closure(root.clone())?;

        assert_eq!(closure.root(), root.as_path());
        assert_eq!(closure.drvs().len(), 2);
        assert_eq!(closure.drvs().get(&root), Some(&root_bytes));
        assert_eq!(closure.drvs().get(&input), Some(&input_bytes));
        Ok(())
    }

    #[test]
    fn command_failure_message_includes_stderr() {
        assert_eq!(
            command_failure_message("nix-instantiate failed".to_string(), b"error: bad attr\n"),
            "nix-instantiate failed: error: bad attr"
        );
        assert_eq!(
            command_failure_message("nix-instantiate failed".to_string(), b""),
            "nix-instantiate failed"
        );
    }
}
