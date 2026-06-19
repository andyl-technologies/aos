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

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use anyhow::{Context, Result};

use super::env::aos_nix_command;
use super::eval::{NixEval, NixEvalConfig};

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

    /// Queries [`path_info`](Self::path_info) for multiple paths.
    ///
    /// Paths are queried sequentially; results preserve the input order.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered; later paths are not queried.
    pub fn path_info_batch(&self, paths: &[&str]) -> Result<Vec<PathInfo>> {
        paths.iter().map(|p| self.path_info(p)).collect()
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

impl NixEval for NixCli {
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        Self::instantiate(self, file, attr)
    }

    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        Self::instantiate_expr(self, expr)
    }

    fn eval_expr(&self, expr: &str) -> Result<String> {
        Self::eval_expr(self, expr)
    }

    fn name(&self) -> &'static str {
        "nix-cli"
    }
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
