//! Project-rooted wrapper around the Nix CLI tools.
//!
//! [`NixRunner`] is the high-level entry point used by `aos build`,
//! `aos test`, and friends. On construction it verifies that
//! `nix-build` is on `PATH` and locates the project root (the directory
//! containing `default.nix`) via `AOS_ROOT`, an upward walk from the
//! working directory, or the binary's own location. Every subsequent
//! operation -- build, evaluate, instantiate, garbage-collect, repl --
//! runs against that root.
//!
//! Verbosity shapes how subprocess output is handled: at `verbose >= 2`
//! the child's stderr streams live to the terminal, at `verbose >= 3`
//! the exact command line is echoed, and otherwise stderr is captured
//! and replayed only on failure (suppressed entirely in quiet mode). Evaluation
//! commands also stream stderr when `builtins.traceVerbose` output is explicitly
//! enabled, so successful trace output remains user-visible. Failures are
//! reported as [`AosError::NixBuild`] /
//! [`AosError::NixNotFound`] / [`AosError::RootNotFound`] so callers
//! can map them to the standard exit codes.

use std::env;
use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus, Output, Stdio};

use anyhow::{Context, Result};

use crate::error::AosError;
use crate::nix::{NixEval, NixEvalConfig, aos_nix_command, select_evaluator_with_config};

/// Wraps interactions with the Nix CLI tools (`nix-build`, `nix-instantiate`,
/// `nix-store`, `nix-collect-garbage`, `nix-shell`).
pub struct NixRunner {
    /// Path to the directory containing `default.nix`.
    root: PathBuf,
    evaluator: Box<dyn NixEval>,
    eval_config: NixEvalConfig,
    verbose: u8,
    quiet: bool,
}

impl NixRunner {
    /// Creates a new `NixRunner`, locating the project root and verifying that
    /// the `nix-build` binary is available.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixNotFound`] if `nix-build` is not on
    /// `PATH`, or [`AosError::RootNotFound`] if no `default.nix` can be
    /// located (see `find_root` for the search order).
    pub fn new(verbose: u8, quiet: bool) -> Result<Self> {
        Self::with_eval_config(verbose, quiet, NixEvalConfig::default())
    }

    /// Creates a new `NixRunner` with explicit evaluator settings.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixNotFound`] if `nix-build` is not on
    /// `PATH`, [`AosError::RootNotFound`] if no `default.nix` can be
    /// located, or another error if the configured evaluator cannot be
    /// initialized.
    pub fn with_eval_config(verbose: u8, quiet: bool, eval_config: NixEvalConfig) -> Result<Self> {
        // Verify nix is available.
        which("nix-build").map_err(|_| AosError::NixNotFound)?;

        let root = Self::find_root()?;
        let evaluator = select_evaluator_with_config(verbose, eval_config.clone())?;

        Ok(Self {
            root,
            evaluator,
            eval_config,
            verbose,
            quiet,
        })
    }

    /// Returns the project root path (the directory containing
    /// `default.nix`).
    pub fn root(&self) -> &Path {
        &self.root
    }

    // ------------------------------------------------------------------
    // Public high-level operations
    // ------------------------------------------------------------------

    /// Runs `nix-build default.nix -A <attr>` and returns the resulting store
    /// path.  An optional `out_link` places the result symlink at the given
    /// path; when `None`, `--no-out-link` is passed so no symlink is created.
    ///
    /// For multi-output attributes the last printed path is returned;
    /// use [`build_all`](Self::build_all) to collect every path.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if `nix-build` exits non-zero, or
    /// another error if it cannot be spawned or prints no output.
    pub fn build(&self, attr: &str, out_link: Option<&str>) -> Result<PathBuf> {
        self.build_inner(attr, out_link, None)
    }

    /// Like [`build`](Self::build) but also passes `--max-jobs <n>` to
    /// `nix-build` so derivations within this build run in parallel up
    /// to `n` at a time. Used by `aos test` to drive the test layer at
    /// host parallelism without depending on system-wide `nix.conf`.
    ///
    /// # Errors
    ///
    /// Same conditions as [`build`](Self::build).
    pub fn build_with_max_jobs(
        &self,
        attr: &str,
        out_link: Option<&str>,
        max_jobs: usize,
    ) -> Result<PathBuf> {
        self.build_inner(attr, out_link, Some(max_jobs))
    }

    fn build_inner(
        &self,
        attr: &str,
        out_link: Option<&str>,
        max_jobs: Option<usize>,
    ) -> Result<PathBuf> {
        let mut args: Vec<String> = vec![
            self.default_nix().to_string_lossy().to_string(),
            "-A".to_string(),
            attr.to_string(),
        ];

        if let Some(link) = out_link {
            args.push("-o".to_string());
            args.push(link.to_string());
        } else {
            args.push("--no-out-link".to_string());
        }

        if let Some(jobs) = max_jobs {
            args.push("--max-jobs".to_string());
            args.push(jobs.to_string());
        }

        let output = self.run_nix("nix-build", &args)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let path = stdout
            .lines()
            .last()
            .map(|l| PathBuf::from(l.trim()))
            .context("nix-build produced no output")?;

        Ok(path)
    }

    /// Runs `nix-build -E <expr>` and returns the resulting store path.
    /// The expression is responsible for any imports it needs (e.g.
    /// `(import /path/to/. {}).foo.bar`).
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if `nix-build` exits non-zero, or
    /// another error if it cannot be spawned or prints no output.
    pub fn build_expr(&self, expr: &str) -> Result<PathBuf> {
        let args: Vec<String> = vec![
            "-E".to_string(),
            expr.to_string(),
            "--no-out-link".to_string(),
        ];

        let output = self.run_nix("nix-build", &args)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let path = stdout
            .lines()
            .last()
            .map(|l| PathBuf::from(l.trim()))
            .context("nix-build produced no output")?;

        Ok(path)
    }

    /// Builds an attribute that evaluates to a set / list and returns all
    /// resulting store paths (one per non-empty line of `nix-build`
    /// output).
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if `nix-build` exits non-zero, or
    /// another error if it cannot be spawned.
    pub fn build_all(&self, attr: &str) -> Result<Vec<PathBuf>> {
        let args: Vec<String> = vec![
            self.default_nix().to_string_lossy().to_string(),
            "-A".to_string(),
            attr.to_string(),
            "--no-out-link".to_string(),
        ];

        let output = self.run_nix("nix-build", &args)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let paths: Vec<PathBuf> = stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| PathBuf::from(l.trim()))
            .collect();

        Ok(paths)
    }

    /// Evaluates an attribute of `default.nix` to JSON via
    /// `nix-instantiate --eval --strict --json`.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if evaluation fails, or another
    /// error if `nix-instantiate` cannot be spawned or its output is
    /// not valid JSON.
    pub fn eval_json(&self, attr: &str) -> Result<serde_json::Value> {
        let args: Vec<String> = vec![
            "--eval".to_string(),
            "--strict".to_string(),
            "--json".to_string(),
            self.default_nix().to_string_lossy().to_string(),
            "-A".to_string(),
            attr.to_string(),
        ];

        let output = self.run_nix("nix-instantiate", &args)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let value: serde_json::Value = serde_json::from_str(stdout.trim()).with_context(|| {
            format!("failed to parse JSON from nix-instantiate for attr '{attr}'")
        })?;

        Ok(value)
    }

    /// Evaluates an arbitrary Nix expression to JSON via
    /// `nix-instantiate --eval --strict --json -E <expr>`.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if evaluation fails, or another
    /// error if `nix-instantiate` cannot be spawned or its output is
    /// not valid JSON.
    pub fn eval_expr_json(&self, expr: &str) -> Result<serde_json::Value> {
        let stdout = self.evaluator.eval_expr(expr)?;
        let value: serde_json::Value = serde_json::from_str(stdout.trim())
            .context("failed to parse JSON from nix-instantiate expression")?;

        Ok(value)
    }

    /// Evaluates an attribute of `default.nix` to a string, stripping the
    /// surrounding quotes that `nix-instantiate --eval` adds to string
    /// results.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if evaluation fails, or another
    /// error if `nix-instantiate` cannot be spawned.
    pub fn eval_str(&self, attr: &str) -> Result<String> {
        let args: Vec<String> = vec![
            "--eval".to_string(),
            "--strict".to_string(),
            self.default_nix().to_string_lossy().to_string(),
            "-A".to_string(),
            attr.to_string(),
        ];

        let output = self.run_nix("nix-instantiate", &args)?;
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // nix-instantiate wraps string results in quotes; strip them.
        let unquoted = stdout.trim_matches('"').to_string();
        Ok(unquoted)
    }

    /// Queries the Nix store about a store path, running
    /// `nix-store <args>... <path>` and returning raw stdout.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if `nix-store` exits non-zero, or
    /// another error if it cannot be spawned.
    pub fn store_query(&self, path: &Path, args: &[&str]) -> Result<String> {
        let mut full_args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        full_args.push(path.to_string_lossy().to_string());

        let output = self.run_nix("nix-store", &full_args)?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Instantiates (but does not build) a derivation from `default.nix`,
    /// returning the `.drv` path.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if instantiation fails, or
    /// another error if `nix-instantiate` cannot be spawned or prints
    /// no output.
    pub fn instantiate(&self, attr: &str) -> Result<PathBuf> {
        self.evaluator.instantiate(&self.default_nix(), attr)
    }

    /// Runs garbage collection via `nix-collect-garbage`, optionally
    /// deleting only generations older than a given duration (e.g. `"7d"`).
    /// When `older_than` is `None`, `-d` is passed to delete all old
    /// generations.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if `nix-collect-garbage` exits
    /// non-zero, or another error if it cannot be spawned.
    pub fn collect_garbage(&self, older_than: Option<&str>) -> Result<()> {
        let mut args: Vec<String> = Vec::new();
        if let Some(age) = older_than {
            args.push("--delete-older-than".to_string());
            args.push(age.to_string());
        } else {
            args.push("-d".to_string());
        }

        self.run_nix("nix-collect-garbage", &args)?;
        Ok(())
    }

    /// Lists system generations via `nix-env --list-generations` against
    /// the `/nix/var/nix/profiles/system` profile, returning raw stdout.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if `nix-env` exits non-zero, or
    /// another error if it cannot be spawned.
    pub fn list_generations(&self) -> Result<String> {
        let args: Vec<String> = vec![
            "--list-generations".to_string(),
            "--profile".to_string(),
            "/nix/var/nix/profiles/system".to_string(),
        ];

        let output = self.run_nix("nix-env", &args)?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Runs an interactive `nix repl` session loading the given Nix file,
    /// blocking until the user exits the repl.
    ///
    /// Unlike the other operations, the child inherits the terminal
    /// directly (no output capture).
    ///
    /// # Errors
    ///
    /// Returns an error if `nix` cannot be started or the repl exits
    /// with a non-zero status.
    pub fn repl(&self, nix_file: &Path) -> Result<()> {
        let status = aos_nix_command("nix")
            .args(self.repl_args(nix_file))
            .current_dir(&self.root)
            .status()
            .context("failed to start nix repl")?;

        if !status.success() {
            anyhow::bail!("nix repl exited with status {status}");
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Return the path to `default.nix` within the project root.
    fn default_nix(&self) -> PathBuf {
        self.root.join("default.nix")
    }

    /// Locate the project root by:
    ///   1. Checking the `AOS_ROOT` environment variable.
    ///   2. Walking upward from the current directory looking for `default.nix`.
    ///   3. Checking relative to the binary's own location.
    fn find_root() -> Result<PathBuf> {
        // 1. Environment variable.
        if let Ok(root) = env::var("AOS_ROOT") {
            let p = PathBuf::from(&root);
            if p.join("default.nix").is_file() {
                return Ok(p);
            }
        }

        // 2. Walk upward from CWD.
        if let Ok(cwd) = env::current_dir() {
            let mut dir = cwd.as_path();
            loop {
                if dir.join("default.nix").is_file() {
                    return Ok(dir.to_path_buf());
                }
                match dir.parent() {
                    Some(parent) => dir = parent,
                    None => break,
                }
            }
        }

        // 3. Relative to the binary itself.
        if let Ok(exe) = env::current_exe() {
            if let Some(bin_dir) = exe.parent() {
                // Try alongside the binary.
                if bin_dir.join("default.nix").is_file() {
                    return Ok(bin_dir.to_path_buf());
                }
                // Try one level up (e.g. bin/ -> project root).
                if let Some(parent) = bin_dir.parent() {
                    if parent.join("default.nix").is_file() {
                        return Ok(parent.to_path_buf());
                    }
                }
            }
        }

        Err(AosError::RootNotFound.into())
    }

    /// Core runner: spawn a Nix subprocess and capture its output.  When
    /// `verbose >= 2` or trace-verbose output is enabled for an eval command,
    /// the child's stderr is streamed to the terminal in real time; otherwise
    /// it is captured and only shown on failure.
    fn run_nix(&self, cmd: &str, args: &[String]) -> Result<Output> {
        let args = self.args_with_eval_options(cmd, args);
        if self.verbose >= 3 {
            eprintln!("+ {} {}", cmd, args.join(" "));
        }

        let stream_stderr = self.should_stream_stderr(cmd);
        let stderr_behavior = if stream_stderr {
            Stdio::inherit()
        } else {
            Stdio::piped()
        };

        let child = aos_nix_command(cmd)
            .args(&args)
            .current_dir(&self.root)
            .stdout(Stdio::piped())
            .stderr(stderr_behavior)
            .spawn()
            .with_context(|| format!("failed to spawn {cmd}"))?;

        // When stderr is inherited, it goes directly to the terminal, so we
        // only need to read stdout. Otherwise we capture both.
        if stream_stderr {
            let output = child
                .wait_with_output()
                .with_context(|| format!("{cmd} failed"))?;

            if !output.status.success() {
                let code = output.status.code().unwrap_or(-1);
                return Err(AosError::NixBuild {
                    exit_code: code,
                    stderr: String::new(), // already displayed
                }
                .into());
            }

            Ok(output)
        } else {
            let output = child
                .wait_with_output()
                .with_context(|| format!("{cmd} failed"))?;

            if !output.status.success() {
                let code = output.status.code().unwrap_or(-1);
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();

                // In non-quiet mode, print the captured stderr so the user
                // can see what went wrong.
                if !self.quiet {
                    eprint!("{stderr}");
                }

                return Err(AosError::NixBuild {
                    exit_code: code,
                    stderr,
                }
                .into());
            }

            Ok(output)
        }
    }

    fn args_with_eval_options(&self, cmd: &str, args: &[String]) -> Vec<String> {
        let mut args = args.to_vec();
        if command_accepts_eval_options(cmd) {
            args.extend(self.eval_config.cli_option_args());
        }
        args
    }

    fn should_stream_stderr(&self, cmd: &str) -> bool {
        self.verbose >= 2 || (self.eval_config.trace_verbose() && command_accepts_eval_options(cmd))
    }

    fn repl_args(&self, nix_file: &Path) -> Vec<OsString> {
        let mut args = vec![OsString::from("repl")];
        args.extend(
            self.eval_config
                .cli_option_args()
                .into_iter()
                .map(OsString::from),
        );
        args.push(OsString::from("--file"));
        args.push(nix_file.as_os_str().to_owned());
        args
    }

    /// Stream a child process's stdout and stderr line-by-line to the
    /// terminal.  Used for interactive / long-running commands where the user
    /// wants to see real-time output.
    #[allow(dead_code)] // intended for future use by interactive commands
    fn stream_output(&self, child: &mut Child) -> Result<ExitStatus> {
        // Drain stderr in a background thread so we don't deadlock.
        let stderr_handle = child.stderr.take().map(|stderr| {
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines().flatten() {
                    eprintln!("{line}");
                }
            })
        });

        // Drain stdout on the main thread.
        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines().flatten() {
                println!("{line}");
            }
        }

        if let Some(handle) = stderr_handle {
            let _ = handle.join();
        }

        let status = child.wait().context("waiting for child process")?;
        Ok(status)
    }
}

fn command_accepts_eval_options(cmd: &str) -> bool {
    matches!(cmd, "nix-build" | "nix-instantiate")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs as unix_fs;
    use std::sync::{Mutex, OnceLock};

    const FAKE_NIX_CHILD_ENV: &str = "AOS_RUN_FAKE_NIX_CHILD";

    struct EnvVarGuard {
        key: &'static str,
        saved_value: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let saved_value = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, saved_value }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.saved_value {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    struct PathEnvGuard {
        saved_path: Option<OsString>,
    }

    impl PathEnvGuard {
        fn prepend(path: &Path) -> Self {
            let saved_path = std::env::var_os("PATH");
            let mut paths = vec![path.to_path_buf()];
            if let Some(saved_path) = &saved_path {
                paths.extend(std::env::split_paths(saved_path));
            }
            let joined = std::env::join_paths(paths).expect("test PATH entries are valid");
            unsafe { std::env::set_var("PATH", joined) };
            Self { saved_path }
        }
    }

    impl Drop for PathEnvGuard {
        fn drop(&mut self) {
            match &self.saved_path {
                Some(path) => unsafe { std::env::set_var("PATH", path) },
                None => unsafe { std::env::remove_var("PATH") },
            }
        }
    }

    fn os_args_to_strings(args: Vec<OsString>) -> Vec<String> {
        args.into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn path_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn runner_with_config(eval_config: NixEvalConfig) -> NixRunner {
        NixRunner {
            root: PathBuf::from("/aos"),
            evaluator: Box::new(crate::nix::NixCli::new(0)),
            eval_config,
            verbose: 0,
            quiet: true,
        }
    }

    fn link_fake_nix_command(dir: &Path, name: &str) -> Result<()> {
        let path = dir.join(name);
        unix_fs::symlink(std::env::current_exe()?, path)?;
        Ok(())
    }

    #[test]
    fn fake_nix_instantiate_child() {
        if std::env::var_os(FAKE_NIX_CHILD_ENV).is_none() {
            return;
        }
        println!("fake stdout");
        eprintln!("trace: visible");
    }

    #[test]
    fn runner_appends_eval_options_to_eval_commands() -> Result<()> {
        let runner = runner_with_config(NixEvalConfig::with_current_system("aos-test-target")?);
        let args = vec!["--eval".to_string(), "default.nix".to_string()];

        assert_eq!(
            runner.args_with_eval_options("nix-instantiate", &args),
            [
                "--eval",
                "default.nix",
                "--option",
                "system",
                "aos-test-target"
            ]
        );
        assert_eq!(
            runner.args_with_eval_options("nix-build", &args),
            [
                "--eval",
                "default.nix",
                "--option",
                "system",
                "aos-test-target"
            ]
        );
        Ok(())
    }

    #[test]
    fn runner_appends_trace_verbose_to_eval_commands() {
        let mut config = NixEvalConfig::new();
        config.set_trace_verbose(true);
        let runner = runner_with_config(config);
        let args = vec!["--eval".to_string(), "default.nix".to_string()];

        assert_eq!(
            runner.args_with_eval_options("nix-instantiate", &args),
            ["--eval", "default.nix", "--option", "trace-verbose", "true"]
        );
    }

    #[test]
    fn runner_streams_successful_eval_stderr_when_trace_verbose_is_enabled() {
        let mut config = NixEvalConfig::new();
        config.set_trace_verbose(true);
        let runner = runner_with_config(config);

        assert!(runner.should_stream_stderr("nix-instantiate"));
        assert!(runner.should_stream_stderr("nix-build"));
        assert!(!runner.should_stream_stderr("nix-store"));
    }

    #[test]
    fn runner_streams_stderr_for_verbose_commands() {
        let mut runner = runner_with_config(NixEvalConfig::default());
        runner.verbose = 2;

        assert!(runner.should_stream_stderr("nix-store"));
    }

    #[test]
    fn run_nix_inherits_successful_eval_stderr_when_trace_verbose_is_enabled() -> Result<()> {
        let _lock = path_env_lock().lock().expect("PATH env test lock");
        let temp = tempfile::tempdir()?;
        let bin_dir = temp.path().join("bin");
        fs::create_dir(&bin_dir)?;
        link_fake_nix_command(&bin_dir, "nix-instantiate")?;
        let _path_guard = PathEnvGuard::prepend(&bin_dir);
        let _child_guard = EnvVarGuard::set(FAKE_NIX_CHILD_ENV, "1");
        let args = vec![
            "fake_nix_instantiate_child".to_string(),
            "--nocapture".to_string(),
            "--".to_string(),
        ];

        let runner = NixRunner {
            root: temp.path().to_path_buf(),
            ..runner_with_config(NixEvalConfig::default())
        };
        let output = runner.run_nix("nix-instantiate", &args)?;
        assert!(String::from_utf8_lossy(&output.stderr).contains("trace: visible\n"));

        let mut config = NixEvalConfig::new();
        config.set_trace_verbose(true);
        let runner = NixRunner {
            root: temp.path().to_path_buf(),
            ..runner_with_config(config)
        };
        let output = runner.run_nix("nix-instantiate", &args)?;
        assert!(output.stderr.is_empty());
        Ok(())
    }

    #[test]
    fn runner_leaves_non_eval_commands_unchanged() -> Result<()> {
        let runner = runner_with_config(NixEvalConfig::with_current_system("aos-test-target")?);
        let args = vec!["--query".to_string(), "/nix/store/path".to_string()];

        assert_eq!(
            runner.args_with_eval_options("nix-store", &args),
            ["--query", "/nix/store/path"]
        );
        assert_eq!(
            runner.args_with_eval_options("nix-collect-garbage", &args),
            ["--query", "/nix/store/path"]
        );
        Ok(())
    }

    #[test]
    fn runner_appends_eval_options_to_repl() -> Result<()> {
        let mut config = NixEvalConfig::with_current_system("aos-test-target")?;
        config.set_trace_verbose(true);
        let runner = runner_with_config(config);

        assert_eq!(
            os_args_to_strings(runner.repl_args(Path::new("default.nix"))),
            [
                "repl",
                "--option",
                "system",
                "aos-test-target",
                "--option",
                "trace-verbose",
                "true",
                "--file",
                "default.nix"
            ]
        );
        Ok(())
    }
}

// ------------------------------------------------------------------
// Utility
// ------------------------------------------------------------------

/// Minimal `which`-like lookup: checks if a binary is on `PATH`.
fn which(binary: &str) -> Result<PathBuf, ()> {
    let path_var = env::var_os("PATH").ok_or(())?;
    for dir in env::split_paths(&path_var) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(())
}
