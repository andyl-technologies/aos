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
//! commands stream stderr so successful `builtins.trace` output remains
//! user-visible. Failures are
//! reported as [`AosError::NixBuild`] /
//! [`AosError::NixNotFound`] / [`AosError::RootNotFound`] so callers
//! can map them to the standard exit codes.

use std::env;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
#[cfg(test)]
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::error::AosError;
use crate::nix::{NixCli, NixEval, NixEvalConfig, aos_nix_command, select_evaluator_with_config};

#[cfg(test)]
type ReplRealizer = dyn Fn(&Path) -> Result<String> + Send + Sync;

/// Wraps interactions with the Nix CLI tools (`nix-build`, `nix-instantiate`,
/// `nix-store`, `nix-collect-garbage`, `nix-shell`).
pub struct NixRunner {
    /// Path to the directory containing `default.nix`.
    root: PathBuf,
    evaluator: Box<dyn NixEval>,
    eval_config: NixEvalConfig,
    verbose: u8,
    quiet: bool,
    #[cfg(test)]
    repl_realizer: Option<Arc<ReplRealizer>>,
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
    pub fn with_eval_config(
        verbose: u8,
        quiet: bool,
        mut eval_config: NixEvalConfig,
    ) -> Result<Self> {
        // Verify nix is available.
        which("nix-build").map_err(|_| AosError::NixNotFound)?;

        let root = Self::find_root()?;
        eval_config.set_working_dir(root.clone())?;
        let evaluator = select_evaluator_with_config(verbose, eval_config.clone())?;

        Ok(Self {
            root,
            evaluator,
            eval_config,
            verbose,
            quiet,
            #[cfg(test)]
            repl_realizer: None,
        })
    }

    /// Returns the project root path (the directory containing
    /// `default.nix`).
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the selected evaluator's stable diagnostic name.
    pub fn evaluator_name(&self) -> &'static str {
        self.evaluator.name()
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
        tracing::info!(
            evaluator = self.evaluator.name(),
            "evaluating Nix expression"
        );
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
        let file = self.default_nix();
        tracing::info!(
            evaluator = self.evaluator.name(),
            attr,
            file = %file.display(),
            "instantiating Nix attribute"
        );
        self.evaluator.instantiate(&file, attr)
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

    /// Runs an interactive REPL session loading the given Nix file.
    ///
    /// When the selected evaluator is `nix-cli`, this delegates to `nix repl`.
    /// Native or shadow evaluators use the in-process AOS REPL backed by the
    /// same [`NixEval`] implementation as non-interactive commands.
    ///
    /// Unlike the other operations, the child inherits the terminal
    /// directly (no output capture).
    ///
    /// # Errors
    ///
    /// Returns an error if `nix` cannot be started or the repl exits
    /// with a non-zero status.
    pub fn repl(&self, nix_file: &Path) -> Result<()> {
        if self.evaluator.name() != "nix-cli" {
            return self.native_repl(nix_file);
        }

        let mut command = aos_nix_command("nix");
        self.eval_config.apply_cli_env(&mut command);
        let status = command
            .args(self.repl_args(nix_file))
            .status()
            .context("failed to start nix repl")?;

        if !status.success() {
            anyhow::bail!("nix repl exited with status {status}");
        }
        Ok(())
    }

    fn native_repl(&self, nix_file: &Path) -> Result<()> {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        let stdout = io::stdout();
        let mut output = stdout.lock();
        self.run_native_repl_session(nix_file, &mut input, &mut output)
    }

    fn run_native_repl_session<R: BufRead, W: Write>(
        &self,
        nix_file: &Path,
        input: &mut R,
        output: &mut W,
    ) -> Result<()> {
        let mut state = NativeReplState {
            loaded_file: Some(nix_file.to_path_buf()),
        };
        self.validate_repl_load(&state)?;
        writeln!(
            output,
            "AOS native REPL ({}) loaded {}",
            self.evaluator.name(),
            nix_file.display()
        )?;
        writeln!(output, "Type :? for help, :q to quit.")?;

        let mut line = String::new();
        loop {
            line.clear();
            write!(output, "aos-nix> ")?;
            output.flush()?;
            if input.read_line(&mut line)? == 0 {
                writeln!(output)?;
                break;
            }
            if matches!(
                self.handle_native_repl_line(&mut state, line.trim_end(), output)?,
                ReplControl::Quit
            ) {
                break;
            }
        }
        Ok(())
    }

    fn handle_native_repl_line<W: Write>(
        &self,
        state: &mut NativeReplState,
        line: &str,
        output: &mut W,
    ) -> Result<ReplControl> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(ReplControl::Continue);
        }

        if let Some(command) = trimmed.strip_prefix(':') {
            return self.handle_native_repl_command(state, command.trim(), output);
        }

        self.write_repl_eval(state, trimmed, output)?;
        Ok(ReplControl::Continue)
    }

    fn handle_native_repl_command<W: Write>(
        &self,
        state: &mut NativeReplState,
        command: &str,
        output: &mut W,
    ) -> Result<ReplControl> {
        let (name, rest) = command
            .split_once(char::is_whitespace)
            .unwrap_or((command, ""));
        let rest = rest.trim();
        match name {
            "?" | "help" => {
                write_native_repl_help(output)?;
            }
            "q" | "quit" => return Ok(ReplControl::Quit),
            "l" | "load" => {
                if rest.is_empty() {
                    writeln!(output, "error: :load requires a file path")?;
                } else {
                    let path = self.resolve_repl_load_path(rest);
                    let next_state = NativeReplState {
                        loaded_file: Some(path.clone()),
                    };
                    match self.validate_repl_load(&next_state) {
                        Ok(()) => {
                            state.loaded_file = Some(path.clone());
                            writeln!(output, "loaded {}", path.display())?;
                        }
                        Err(error) => writeln!(output, "error: {error:#}")?,
                    }
                }
            }
            "r" | "reload" => match &state.loaded_file {
                Some(path) => match self.validate_repl_load(state) {
                    Ok(()) => writeln!(output, "reloaded {}", path.display())?,
                    Err(error) => writeln!(output, "error: {error:#}")?,
                },
                None => writeln!(output, "error: no file loaded")?,
            },
            "p" => {
                if rest.is_empty() {
                    writeln!(output, "error: :p requires an expression")?;
                } else {
                    self.write_repl_eval(state, rest, output)?;
                }
            }
            "t" => {
                if rest.is_empty() {
                    writeln!(output, "error: :t requires an expression")?;
                } else {
                    self.write_repl_type(state, rest, output)?;
                }
            }
            "scope" => {
                if rest.is_empty() {
                    writeln!(output, "error: :scope requires an expression")?;
                } else {
                    self.write_repl_scope(state, rest, output)?;
                }
            }
            "b" => {
                if rest.is_empty() {
                    writeln!(output, "error: :b requires an expression")?;
                } else {
                    self.write_repl_build(state, rest, output)?;
                }
            }
            _ => writeln!(output, "error: unknown command :{name}")?,
        }
        Ok(ReplControl::Continue)
    }

    fn write_repl_eval<W: Write>(
        &self,
        state: &NativeReplState,
        expr: &str,
        output: &mut W,
    ) -> Result<()> {
        let (source, user_range) =
            repl_context_expr_with_user_range(state.loaded_file.as_deref(), expr);
        match self.evaluator.eval_expr_with_diagnostic_source(
            &source,
            "repl-input.nix",
            expr,
            user_range,
        ) {
            Ok(value) => writeln!(output, "{value}")?,
            Err(error) => writeln!(output, "error: {error:#}")?,
        }
        Ok(())
    }

    fn write_repl_type<W: Write>(
        &self,
        state: &NativeReplState,
        expr: &str,
        output: &mut W,
    ) -> Result<()> {
        let type_prefix = "builtins.typeOf (";
        let type_expr = format!("{type_prefix}{expr})");
        let (source, type_range) =
            repl_context_expr_with_user_range(state.loaded_file.as_deref(), &type_expr);
        let user_start = type_range.start + type_prefix.len();
        let user_range = user_start..user_start + expr.len();
        match self.evaluator.eval_expr_with_diagnostic_source(
            &source,
            "repl-input.nix",
            expr,
            user_range,
        ) {
            Ok(value) => match serde_json::from_str::<String>(&value) {
                Ok(kind) => writeln!(output, "{kind}")?,
                Err(_) => writeln!(output, "{value}")?,
            },
            Err(error) => writeln!(output, "error: {error:#}")?,
        }
        Ok(())
    }

    fn write_repl_scope<W: Write>(
        &self,
        state: &NativeReplState,
        expr: &str,
        output: &mut W,
    ) -> Result<()> {
        match repl_scope_report(state.loaded_file.as_deref(), expr) {
            Ok(report) => write!(output, "{report}")?,
            Err(error) => writeln!(output, "error: {error:#}")?,
        }
        Ok(())
    }

    fn write_repl_build<W: Write>(
        &self,
        state: &NativeReplState,
        expr: &str,
        output: &mut W,
    ) -> Result<()> {
        let (source, user_range) =
            repl_context_expr_with_user_range(state.loaded_file.as_deref(), expr);
        match self.evaluator.instantiate_expr_with_diagnostic_source(
            &source,
            "repl-input.nix",
            expr,
            user_range,
        ) {
            Ok(path) => match self.realise_repl_drv(&path) {
                Ok(output_path) => writeln!(output, "{output_path}")?,
                Err(error) => writeln!(output, "error: {error:#}")?,
            },
            Err(error) => writeln!(output, "error: {error:#}")?,
        }
        Ok(())
    }

    fn validate_repl_load(&self, state: &NativeReplState) -> Result<()> {
        let Some(path) = state.loaded_file.as_deref() else {
            return Ok(());
        };
        let kind_expr = repl_context_expr(Some(path), "builtins.typeOf __aos_repl_scope");
        let rendered = self
            .evaluator
            .eval_expr(&kind_expr)
            .with_context(|| format!("loading {}", path.display()))?;
        let kind = serde_json::from_str::<String>(&rendered).with_context(|| {
            format!(
                "loading {} produced an invalid type response: {rendered}",
                path.display()
            )
        })?;
        if kind != "set" {
            anyhow::bail!(
                "loading {} produced {kind}, expected an attribute set",
                path.display()
            );
        }
        Ok(())
    }

    fn realise_repl_drv(&self, drv: &Path) -> Result<String> {
        #[cfg(test)]
        if let Some(realizer) = &self.repl_realizer {
            return realizer(drv);
        }

        let cli = NixCli::with_eval_config(self.verbose, self.eval_config.clone());
        cli.realise(&drv.to_string_lossy())
    }

    fn resolve_repl_load_path(&self, path: &str) -> PathBuf {
        let path = PathBuf::from(path);
        if path.is_absolute() {
            path
        } else {
            self.root.join(path)
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Return the path to `default.nix` within the project root.
    fn default_nix(&self) -> PathBuf {
        self.root.join("default.nix")
    }

    /// Locates the project root.
    ///
    /// The search order is:
    ///
    /// 1. `AOS_ROOT`, when it points at a directory containing `default.nix`.
    /// 2. The current directory and its parents.
    /// 3. The binary directory, then the binary directory's parent.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::RootNotFound`] if no `default.nix` can be located.
    pub fn find_root() -> Result<PathBuf> {
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

    /// Verifies that `nix-instantiate` is available on `PATH`.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixNotFound`] if `nix-instantiate` cannot be
    /// located.
    pub fn ensure_nix_instantiate_available() -> Result<()> {
        which("nix-instantiate").map_err(|_| AosError::NixNotFound)?;
        Ok(())
    }

    /// Verifies that `nix-build` is available on `PATH`.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixNotFound`] if `nix-build` cannot be located.
    pub fn ensure_nix_build_available() -> Result<()> {
        which("nix-build").map_err(|_| AosError::NixNotFound)?;
        Ok(())
    }

    /// Core runner: spawn a Nix subprocess and capture its output.
    ///
    /// Evaluation commands stream the child's stderr so successful
    /// `builtins.trace` output remains user-visible. Non-evaluation commands
    /// stream stderr only at `verbose >= 2`; otherwise stderr is captured and
    /// shown on failure.
    fn run_nix(&self, cmd: &str, args: &[String]) -> Result<Output> {
        self.run_nix_with_command(cmd, args, aos_nix_command(cmd))
    }

    fn run_nix_with_command(
        &self,
        cmd: &str,
        args: &[String],
        mut command: Command,
    ) -> Result<Output> {
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

        self.eval_config.apply_cli_env(&mut command);
        let child = command
            .args(&args)
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
            args.extend(self.eval_config.cli_search_path_args());
            args.extend(self.eval_config.cli_option_args());
        }
        args
    }

    fn should_stream_stderr(&self, cmd: &str) -> bool {
        self.verbose >= 2 || command_accepts_eval_options(cmd)
    }

    fn repl_args(&self, nix_file: &Path) -> Vec<OsString> {
        let mut args = vec![OsString::from("repl")];
        args.extend(
            self.eval_config
                .cli_search_path_args()
                .into_iter()
                .map(OsString::from),
        );
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

#[derive(Debug)]
struct NativeReplState {
    loaded_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ReplControl {
    Continue,
    Quit,
}

fn write_native_repl_help(output: &mut impl Write) -> Result<()> {
    writeln!(output, ":load PATH, :l PATH   load a Nix file")?;
    writeln!(output, ":reload, :r          reload the current file")?;
    writeln!(output, ":p EXPR              evaluate EXPR as strict JSON")?;
    writeln!(output, ":t EXPR              print the Nix type of EXPR")?;
    writeln!(
        output,
        ":scope EXPR          inspect resolver frames and variable coordinates (native-eval)"
    )?;
    writeln!(
        output,
        ":b EXPR              build EXPR and print its output path"
    )?;
    writeln!(output, ":quit, :q            exit")?;
    Ok(())
}

fn repl_context_expr(loaded_file: Option<&Path>, expr: &str) -> String {
    repl_context_expr_with_user_range(loaded_file, expr).0
}

fn repl_context_expr_with_user_range(
    loaded_file: Option<&Path>,
    expr: &str,
) -> (String, Range<usize>) {
    let Some(loaded_file) = loaded_file else {
        return (expr.to_string(), 0..expr.len());
    };

    let prefix = format!(
        "let \
         __aos_repl_loaded = import (builtins.toPath {}); \
         __aos_repl_scope = if builtins.isFunction __aos_repl_loaded \
         then __aos_repl_loaded {{}} else __aos_repl_loaded; \
         in with __aos_repl_scope; (",
        nix_string_literal(&loaded_file.to_string_lossy())
    );
    let start = prefix.len();
    let mut source = prefix;
    source.push_str(expr);
    let end = source.len();
    source.push(')');
    (source, start..end)
}

#[cfg(feature = "native-eval")]
fn repl_scope_report(loaded_file: Option<&Path>, expr: &str) -> Result<String> {
    use std::fmt::Write as _;

    use aos_nix::syntax::Span;
    use aos_nix::syntax::ast::{NodeData, NodeKind, Symbol};

    let (source, user_range) = repl_context_expr_with_user_range(loaded_file, expr);
    let parsed = aos_nix::syntax::parse_str(&source)
        .map_err(|error| repl_scope_parse_error(error, &source, expr, &user_range))?;
    let resolved = aos_nix::compile::resolve(parsed)
        .map_err(|error| repl_scope_resolve_error(error, &source, expr, &user_range))?;

    let mut report = String::new();
    writeln!(&mut report, "scope for: {expr}")?;
    writeln!(&mut report, "frames:")?;
    let mut user_frames = std::collections::BTreeSet::new();
    for (index, node) in resolved.arena.nodes().iter().enumerate() {
        if !span_within(node.span, &user_range) {
            continue;
        }
        if let Some(frame_id) = resolved.scopes.node_frames().get(index).copied().flatten() {
            user_frames.insert(frame_id.index());
        }
    }
    if user_frames.is_empty() {
        writeln!(&mut report, "  <none>")?;
    } else {
        for index in user_frames {
            let Some(frame) = resolved.scopes.frames().get(index) else {
                continue;
            };
            writeln!(
                &mut report,
                "  frame {index}: slots={} rec={} with={} captures={}",
                frame.slot_count,
                frame.rec,
                frame.has_with,
                format_upvalues(frame.captures.iter().copied())
            )?;
        }
    }

    writeln!(&mut report, "references:")?;
    let mut references = 0usize;
    for (index, node) in resolved.arena.nodes().iter().enumerate() {
        if !span_within(node.span, &user_range) {
            continue;
        }
        match node.kind {
            NodeKind::LocalVar => {
                let NodeData::Local { slot } = node.data else {
                    continue;
                };
                references += 1;
                writeln!(
                    &mut report,
                    "  node {index}: {} -> local slot={slot}",
                    span_snippet(&source, node.span, user_range.start)
                )?;
            }
            NodeKind::UpvalVar => {
                let NodeData::Upval { depth, slot } = node.data else {
                    continue;
                };
                references += 1;
                writeln!(
                    &mut report,
                    "  node {index}: {} -> upvalue depth={depth} slot={slot}",
                    span_snippet(&source, node.span, user_range.start)
                )?;
            }
            NodeKind::WithVar => {
                let NodeData::WithVar { symbol, chain } = node.data else {
                    continue;
                };
                references += 1;
                writeln!(
                    &mut report,
                    "  node {index}: {} -> with {} chain={chain}",
                    span_snippet(&source, node.span, user_range.start),
                    symbol_text(&resolved.symbols, symbol)
                )?;
            }
            NodeKind::GlobalVar => {
                let NodeData::Symbol(symbol) = node.data else {
                    continue;
                };
                references += 1;
                writeln!(
                    &mut report,
                    "  node {index}: {} -> global {}",
                    span_snippet(&source, node.span, user_range.start),
                    symbol_text(&resolved.symbols, symbol)
                )?;
            }
            _ => {}
        }
    }

    if references == 0 {
        writeln!(&mut report, "  <none>")?;
    }

    fn format_upvalues(upvalues: impl IntoIterator<Item = aos_nix::compile::Upvalue>) -> String {
        let mut rendered = Vec::new();
        for upvalue in upvalues {
            rendered.push(format!("depth={} slot={}", upvalue.depth, upvalue.slot));
        }
        if rendered.is_empty() {
            "[]".to_string()
        } else {
            format!("[{}]", rendered.join(", "))
        }
    }

    fn span_within(span: Span, range: &Range<usize>) -> bool {
        let start = span.start as usize;
        let end = span.end as usize;
        range.start <= start && end <= range.end
    }

    fn span_snippet(source: &str, span: Span, base: usize) -> String {
        let start = span.start as usize;
        let end = span.end as usize;
        match source.get(start..end) {
            Some(snippet) => {
                let relative_start = start.saturating_sub(base);
                let relative_end = end.saturating_sub(base);
                format!(
                    "{relative_start}..{relative_end} \"{}\"",
                    snippet.escape_debug()
                )
            }
            None => {
                let relative_start = start.saturating_sub(base);
                let relative_end = end.saturating_sub(base);
                format!("{relative_start}..{relative_end} <invalid utf-8 boundary>")
            }
        }
    }

    fn symbol_text(symbols: &aos_nix::syntax::ast::SymbolTable, symbol: Symbol) -> String {
        symbols
            .resolve(symbol)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .unwrap_or_else(|| format!("<invalid-symbol:{}>", symbol.as_u32()))
    }

    Ok(report)
}

#[cfg(feature = "native-eval")]
fn repl_scope_parse_error(
    error: aos_nix::syntax::ParseError,
    source: &str,
    expr: &str,
    user_range: &Range<usize>,
) -> anyhow::Error {
    anyhow::anyhow!(repl_scope_parse_diagnostic(error, source, expr, user_range))
}

#[cfg(feature = "native-eval")]
fn repl_scope_parse_diagnostic(
    error: aos_nix::syntax::ParseError,
    source: &str,
    expr: &str,
    user_range: &Range<usize>,
) -> String {
    use aos_nix::diagnostic::{ParseDiagnostic, render_fancy_report};

    let fallback = error.to_string();
    let (name, source, error) = match repl_user_parse_error(&error, user_range) {
        Some(error) => ("repl-input.nix", expr.to_string(), error),
        None => ("repl-expanded.nix", source.to_string(), error),
    };
    let diagnostic = ParseDiagnostic::new(name, source, error);
    render_fancy_report(&diagnostic).unwrap_or(fallback)
}

#[cfg(feature = "native-eval")]
fn repl_scope_resolve_error(
    error: aos_nix::compile::ScopeError,
    source: &str,
    expr: &str,
    user_range: &Range<usize>,
) -> anyhow::Error {
    anyhow::anyhow!(repl_scope_resolve_diagnostic(
        error, source, expr, user_range
    ))
}

#[cfg(feature = "native-eval")]
fn repl_scope_resolve_diagnostic(
    error: aos_nix::compile::ScopeError,
    source: &str,
    expr: &str,
    user_range: &Range<usize>,
) -> String {
    use aos_nix::diagnostic::{ScopeDiagnostic, render_fancy_report};

    let fallback = error.to_string();
    let (name, source, error) = match repl_user_scope_error(&error, user_range) {
        Some(error) => ("repl-input.nix", expr.to_string(), error),
        None => ("repl-expanded.nix", source.to_string(), error),
    };
    let diagnostic = ScopeDiagnostic::new(name, source, error);
    render_fancy_report(&diagnostic).unwrap_or(fallback)
}

#[cfg(feature = "native-eval")]
fn repl_user_parse_error(
    error: &aos_nix::syntax::ParseError,
    user_range: &Range<usize>,
) -> Option<aos_nix::syntax::ParseError> {
    use aos_nix::syntax::ParseErrorKind;

    let span = repl_user_span(error.span(), user_range)?;
    let kind = match error.kind() {
        ParseErrorKind::DuplicateAttribute { first, second } => {
            ParseErrorKind::DuplicateAttribute {
                first: repl_user_span(*first, user_range)?,
                second: repl_user_span(*second, user_range)?,
            }
        }
        kind => kind.clone(),
    };
    Some(aos_nix::syntax::ParseError::new(kind, span))
}

#[cfg(feature = "native-eval")]
fn repl_user_scope_error(
    error: &aos_nix::compile::ScopeError,
    user_range: &Range<usize>,
) -> Option<aos_nix::compile::ScopeError> {
    let span = repl_user_span(error.span(), user_range)?;
    Some(aos_nix::compile::ScopeError::new(
        error.kind().clone(),
        span,
    ))
}

#[cfg(feature = "native-eval")]
fn repl_user_span(
    span: aos_nix::syntax::Span,
    user_range: &Range<usize>,
) -> Option<aos_nix::syntax::Span> {
    let start = usize::try_from(span.start).ok()?;
    let end = usize::try_from(span.end).ok()?;
    let suffix_end = user_range.end.saturating_add(1);
    if start < user_range.start || start > suffix_end {
        return None;
    }
    if end > suffix_end {
        return None;
    }
    let expr_len = user_range.end.checked_sub(user_range.start)?;
    if start >= user_range.end {
        let start = u32::try_from(expr_len.checked_sub(1)?).ok()?;
        let end = u32::try_from(expr_len).ok()?;
        return Some(aos_nix::syntax::Span { start, end });
    }
    let start = u32::try_from(start - user_range.start).ok()?;
    let end = u32::try_from(end.min(user_range.end) - user_range.start).ok()?;
    Some(aos_nix::syntax::Span { start, end })
}

#[cfg(not(feature = "native-eval"))]
fn repl_scope_report(_loaded_file: Option<&Path>, _expr: &str) -> Result<String> {
    anyhow::bail!(":scope requires the native-eval feature")
}

fn nix_string_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '$' => escaped.push_str("\\$"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

fn command_accepts_eval_options(cmd: &str) -> bool {
    matches!(cmd, "nix-build" | "nix-instantiate")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::{Event, Level, Metadata, Subscriber, span};

    const FAKE_NIX_CHILD_ENV: &str = "AOS_RUN_FAKE_NIX_CHILD";

    fn os_args_to_strings(args: Vec<OsString>) -> Vec<String> {
        args.into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn runner_with_config(eval_config: NixEvalConfig) -> NixRunner {
        NixRunner {
            root: PathBuf::from("/aos"),
            evaluator: Box::new(crate::nix::NixCli::new(0)),
            eval_config,
            verbose: 0,
            quiet: true,
            repl_realizer: None,
        }
    }

    fn runner_with_evaluator(evaluator: Box<dyn NixEval>) -> NixRunner {
        NixRunner {
            root: PathBuf::from("/aos"),
            evaluator,
            eval_config: NixEvalConfig::default(),
            verbose: 0,
            quiet: true,
            repl_realizer: None,
        }
    }

    fn runner_with_evaluator_and_repl_realizer(
        evaluator: Box<dyn NixEval>,
        realizer: impl Fn(&Path) -> Result<String> + Send + Sync + 'static,
    ) -> NixRunner {
        NixRunner {
            repl_realizer: Some(Arc::new(realizer)),
            ..runner_with_evaluator(evaluator)
        }
    }

    struct FakeEval;

    impl NixEval for FakeEval {
        fn instantiate(&self, _file: &Path, _attr: &str) -> Result<PathBuf> {
            Ok(PathBuf::from("/nix/store/fake.drv"))
        }

        fn instantiate_expr(&self, _expr: &str) -> Result<PathBuf> {
            Ok(PathBuf::from("/nix/store/fake-expr.drv"))
        }

        fn eval_expr(&self, _expr: &str) -> Result<String> {
            Ok("1".to_string())
        }

        fn name(&self) -> &'static str {
            "fake-eval"
        }
    }

    #[derive(Default)]
    struct ReplRecordingEval {
        eval_exprs: Mutex<Vec<String>>,
        instantiate_exprs: Mutex<Vec<String>>,
        diagnostic_eval_exprs: Mutex<Vec<DiagnosticExpression>>,
        diagnostic_instantiate_exprs: Mutex<Vec<DiagnosticExpression>>,
    }

    impl ReplRecordingEval {
        fn eval_exprs(&self) -> Vec<String> {
            self.eval_exprs.lock().expect("eval exprs lock").clone()
        }

        fn instantiate_exprs(&self) -> Vec<String> {
            self.instantiate_exprs
                .lock()
                .expect("instantiate exprs lock")
                .clone()
        }

        fn diagnostic_eval_exprs(&self) -> Vec<DiagnosticExpression> {
            self.diagnostic_eval_exprs
                .lock()
                .expect("diagnostic eval exprs lock")
                .clone()
        }

        fn diagnostic_instantiate_exprs(&self) -> Vec<DiagnosticExpression> {
            self.diagnostic_instantiate_exprs
                .lock()
                .expect("diagnostic instantiate exprs lock")
                .clone()
        }
    }

    #[derive(Clone, Debug)]
    struct DiagnosticExpression {
        expr: String,
        diagnostic_name: String,
        diagnostic_source: String,
        diagnostic_range: Range<usize>,
    }

    impl NixEval for Arc<ReplRecordingEval> {
        fn instantiate(&self, _file: &Path, _attr: &str) -> Result<PathBuf> {
            Ok(PathBuf::from("/nix/store/fake.drv"))
        }

        fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
            self.instantiate_exprs
                .lock()
                .expect("instantiate exprs lock")
                .push(expr.to_string());
            Ok(PathBuf::from("/nix/store/fake-expr.drv"))
        }

        fn instantiate_expr_with_diagnostic_source(
            &self,
            expr: &str,
            diagnostic_name: &str,
            diagnostic_source: &str,
            diagnostic_range: Range<usize>,
        ) -> Result<PathBuf> {
            self.diagnostic_instantiate_exprs
                .lock()
                .expect("diagnostic instantiate exprs lock")
                .push(DiagnosticExpression {
                    expr: expr.to_string(),
                    diagnostic_name: diagnostic_name.to_string(),
                    diagnostic_source: diagnostic_source.to_string(),
                    diagnostic_range,
                });
            self.instantiate_expr(expr)
        }

        fn eval_expr(&self, expr: &str) -> Result<String> {
            self.eval_exprs
                .lock()
                .expect("eval exprs lock")
                .push(expr.to_string());
            if expr.contains("bad.nix") {
                anyhow::bail!("bad fixture");
            }
            if expr.contains("builtins.typeOf __aos_repl_scope")
                || expr.contains("builtins.typeOf (pkgs)")
            {
                Ok(r#""set""#.to_string())
            } else {
                Ok(r#"{"ok":true}"#.to_string())
            }
        }

        fn eval_expr_with_diagnostic_source(
            &self,
            expr: &str,
            diagnostic_name: &str,
            diagnostic_source: &str,
            diagnostic_range: Range<usize>,
        ) -> Result<String> {
            self.diagnostic_eval_exprs
                .lock()
                .expect("diagnostic eval exprs lock")
                .push(DiagnosticExpression {
                    expr: expr.to_string(),
                    diagnostic_name: diagnostic_name.to_string(),
                    diagnostic_source: diagnostic_source.to_string(),
                    diagnostic_range,
                });
            self.eval_expr(expr)
        }

        fn name(&self) -> &'static str {
            "aos-nix"
        }
    }

    #[derive(Clone)]
    struct RecordingSubscriber {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl Subscriber for RecordingSubscriber {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            *metadata.level() <= Level::INFO
        }

        fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }

        fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}
        fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}
        fn enter(&self, _span: &span::Id) {}
        fn exit(&self, _span: &span::Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut visitor = EventFields::default();
            event.record(&mut visitor);
            self.events
                .lock()
                .expect("recorded events lock")
                .push(visitor.render());
        }
    }

    #[derive(Default)]
    struct EventFields {
        message: String,
        fields: Vec<String>,
    }

    impl EventFields {
        fn render(self) -> String {
            let mut output = self.message;
            for field in self.fields {
                if !output.is_empty() {
                    output.push(' ');
                }
                output.push_str(&field);
            }
            output
        }
    }

    impl Visit for EventFields {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = format!("{value:?}");
            } else {
                self.fields.push(format!("{}={value:?}", field.name()));
            }
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            if field.name() == "message" {
                self.message = value.to_string();
            } else {
                self.fields.push(format!("{}={value}", field.name()));
            }
        }
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
    fn runner_logs_evaluator_name_for_eval_seam_operations() -> Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = RecordingSubscriber {
            events: Arc::clone(&events),
        };
        let dispatch = tracing::Dispatch::new(subscriber);
        let runner = runner_with_evaluator(Box::new(FakeEval));

        tracing::dispatcher::with_default(&dispatch, || -> Result<()> {
            assert_eq!(runner.eval_expr_json("1")?, serde_json::Value::from(1));
            assert_eq!(
                runner.instantiate("pkg")?,
                PathBuf::from("/nix/store/fake.drv")
            );
            Ok(())
        })?;

        let events = events.lock().expect("recorded events lock");
        let eval_event = events
            .iter()
            .find(|event| event.contains("evaluating Nix expression"))
            .expect("expression evaluation event recorded");
        assert!(eval_event.contains("evaluator=fake-eval"));

        let instantiate_event = events
            .iter()
            .find(|event| event.contains("instantiating Nix attribute"))
            .expect("attribute instantiation event recorded");
        assert!(instantiate_event.contains("evaluator=fake-eval"));
        assert!(instantiate_event.contains("attr=pkg"));
        assert!(instantiate_event.contains("file=/aos/default.nix"));
        Ok(())
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
    fn runner_appends_restricted_paths_to_eval_commands() -> Result<()> {
        let mut config = NixEvalConfig::new();
        config.set_eval_mode(crate::nix::NixEvalMode::Restricted);
        config.set_allowed_paths(["/aos/src"])?;
        let runner = runner_with_config(config);
        let args = vec!["--eval".to_string(), "default.nix".to_string()];

        assert_eq!(
            runner.args_with_eval_options("nix-instantiate", &args),
            [
                "--eval",
                "default.nix",
                "-I",
                "/aos/src",
                "--option",
                "pure-eval",
                "false",
                "--option",
                "restrict-eval",
                "true",
                "--option",
                "allowed-impure-host-deps",
                "/aos/src",
                "--option",
                "allowed-uris",
                ""
            ]
        );
        Ok(())
    }

    #[test]
    fn runner_streams_successful_eval_stderr_for_eval_commands() {
        let runner = runner_with_config(NixEvalConfig::default());

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
    fn run_nix_inherits_successful_eval_stderr_for_eval_commands() -> Result<()> {
        let args = vec![
            "fake_nix_instantiate_child".to_string(),
            "--nocapture".to_string(),
            "--".to_string(),
        ];

        let runner = runner_with_config(NixEvalConfig::default());
        let mut command = Command::new(std::env::current_exe()?);
        command.env(FAKE_NIX_CHILD_ENV, "1");
        let output = runner.run_nix_with_command("nix-instantiate", &args, command)?;
        assert!(
            output.stderr.is_empty(),
            "eval stderr should inherit instead of being captured"
        );

        let mut config = NixEvalConfig::new();
        config.set_trace_verbose(true);
        let runner = runner_with_config(config);
        let mut command = Command::new(std::env::current_exe()?);
        command.env(FAKE_NIX_CHILD_ENV, "1");
        let output = runner.run_nix_with_command("nix-instantiate", &args, command)?;
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
        config.set_eval_mode(crate::nix::NixEvalMode::Restricted);
        config.set_allowed_paths(["/aos/src"])?;
        config.set_trace_verbose(true);
        let runner = runner_with_config(config);

        assert_eq!(
            os_args_to_strings(runner.repl_args(Path::new("default.nix"))),
            [
                "repl",
                "-I",
                "/aos/src",
                "--option",
                "system",
                "aos-test-target",
                "--option",
                "pure-eval",
                "false",
                "--option",
                "restrict-eval",
                "true",
                "--option",
                "allowed-impure-host-deps",
                "/aos/src",
                "--option",
                "allowed-uris",
                "",
                "--option",
                "trace-verbose",
                "true",
                "--file",
                "default.nix"
            ]
        );
        Ok(())
    }

    #[test]
    fn native_repl_context_wraps_loaded_file() {
        let expr = repl_context_expr(Some(Path::new("/aos/default.nix")), "pkgs.hello");

        assert!(expr.contains("__aos_repl_loaded = import (builtins.toPath"));
        assert!(expr.contains(r#""/aos/default.nix""#));
        assert!(expr.contains("with __aos_repl_scope; (pkgs.hello)"));
    }

    #[test]
    fn native_repl_context_escapes_loaded_file_string() {
        let expr = repl_context_expr(Some(Path::new("/aos/a\"${x}.nix")), "1");

        assert!(expr.contains(r#""/aos/a\"\${x}.nix""#));
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_repl_scope_command_reports_resolver_coordinates() -> Result<()> {
        let evaluator = Arc::new(ReplRecordingEval::default());
        let runner = runner_with_evaluator(Box::new(Arc::clone(&evaluator)));
        let mut input = io::Cursor::new(
            b":scope let x = 1; in (y: x + y)\n\
              :q\n",
        );
        let mut output = Vec::new();

        runner.run_native_repl_session(Path::new("/aos/default.nix"), &mut input, &mut output)?;

        let output = String::from_utf8(output)?;
        assert!(
            output.contains("scope for: let x = 1; in (y: x + y)"),
            "{output}"
        );
        assert!(
            output.contains("slots=1 rec=true with=true captures=[]"),
            "{output}"
        );
        assert!(
            output.contains("slots=1 rec=false with=true captures=[depth=1 slot=0]"),
            "{output}"
        );
        assert!(
            output.contains("\"x\" -> upvalue depth=1 slot=0"),
            "{output}"
        );
        assert!(output.contains("\"y\" -> local slot=0"), "{output}");
        assert!(!output.contains("__aos_repl_loaded"), "{output}");
        assert!(!output.contains("__aos_repl_scope"), "{output}");
        assert!(!output.contains("\"builtins\" -> global"), "{output}");
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_repl_scope_command_reports_parse_diagnostic() -> Result<()> {
        let evaluator = Arc::new(ReplRecordingEval::default());
        let runner = runner_with_evaluator(Box::new(Arc::clone(&evaluator)));
        let mut input = io::Cursor::new(
            b":scope let x = ; in x\n\
              :q\n",
        );
        let mut output = Vec::new();

        runner.run_native_repl_session(Path::new("/aos/default.nix"), &mut input, &mut output)?;

        let output = String::from_utf8(output)?;
        assert!(
            output.contains("aos_nix::parse::unexpected_token"),
            "{output}"
        );
        assert!(output.contains("repl-input.nix"), "{output}");
        assert!(output.contains("let x = ; in x"), "{output}");
        assert!(
            !output.contains("parsing REPL scope expression"),
            "{output}"
        );
        assert!(!output.contains("__aos_repl_loaded"), "{output}");
        assert!(!output.contains("__aos_repl_scope"), "{output}");
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_repl_scope_command_maps_suffix_parse_diagnostic_to_input() -> Result<()> {
        let evaluator = Arc::new(ReplRecordingEval::default());
        let runner = runner_with_evaluator(Box::new(Arc::clone(&evaluator)));
        let mut input = io::Cursor::new(
            b":scope let x =\n\
              :q\n",
        );
        let mut output = Vec::new();

        runner.run_native_repl_session(Path::new("/aos/default.nix"), &mut input, &mut output)?;

        let output = String::from_utf8(output)?;
        assert!(
            output.contains("aos_nix::parse::unexpected_token"),
            "{output}"
        );
        assert!(output.contains("repl-input.nix"), "{output}");
        assert!(output.contains("let x ="), "{output}");
        assert!(
            !output.contains("parsing REPL scope expression"),
            "{output}"
        );
        assert!(!output.contains("repl-expanded.nix"), "{output}");
        assert!(!output.contains("__aos_repl_loaded"), "{output}");
        assert!(!output.contains("__aos_repl_scope"), "{output}");
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_repl_scope_command_maps_trailing_comment_parse_diagnostic_to_input() -> Result<()> {
        let evaluator = Arc::new(ReplRecordingEval::default());
        let runner = runner_with_evaluator(Box::new(Arc::clone(&evaluator)));
        let mut input = io::Cursor::new(
            b":scope 1 # comment\n\
              :q\n",
        );
        let mut output = Vec::new();

        runner.run_native_repl_session(Path::new("/aos/default.nix"), &mut input, &mut output)?;

        let output = String::from_utf8(output)?;
        assert!(
            output.contains("aos_nix::parse::unexpected_token"),
            "{output}"
        );
        assert!(output.contains("repl-input.nix"), "{output}");
        assert!(output.contains("1 # comment"), "{output}");
        assert!(!output.contains("repl-expanded.nix"), "{output}");
        assert!(!output.contains("__aos_repl_loaded"), "{output}");
        assert!(!output.contains("__aos_repl_scope"), "{output}");
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_repl_scope_command_maps_unterminated_string_diagnostic_to_input() -> Result<()> {
        let evaluator = Arc::new(ReplRecordingEval::default());
        let runner = runner_with_evaluator(Box::new(Arc::clone(&evaluator)));
        let mut input = io::Cursor::new(
            b":scope let x = \"\n\
              :q\n",
        );
        let mut output = Vec::new();

        runner.run_native_repl_session(Path::new("/aos/default.nix"), &mut input, &mut output)?;

        let output = String::from_utf8(output)?;
        assert!(
            output.contains("aos_nix::lex::unterminated_string"),
            "{output}"
        );
        assert!(output.contains("repl-input.nix"), "{output}");
        assert!(output.contains("let x = \""), "{output}");
        assert!(!output.contains("repl-expanded.nix"), "{output}");
        assert!(!output.contains("__aos_repl_loaded"), "{output}");
        assert!(!output.contains("__aos_repl_scope"), "{output}");
        Ok(())
    }

    #[cfg(feature = "native-eval")]
    #[test]
    fn native_repl_scope_command_reports_resolve_diagnostic() -> Result<()> {
        let evaluator = Arc::new(ReplRecordingEval::default());
        let runner = runner_with_evaluator(Box::new(Arc::clone(&evaluator)));
        let mut input = io::Cursor::new(
            b":scope let ${name} = 1; in 1\n\
              :q\n",
        );
        let mut output = Vec::new();

        runner.run_native_repl_session(Path::new("/aos/default.nix"), &mut input, &mut output)?;

        let output = String::from_utf8(output)?;
        assert!(
            output.contains("aos_nix::resolve::dynamic_let_binding"),
            "{output}"
        );
        assert!(output.contains("repl-input.nix"), "{output}");
        assert!(output.contains("let ${name} = 1; in 1"), "{output}");
        assert!(
            !output.contains("resolving REPL scope expression"),
            "{output}"
        );
        assert!(!output.contains("__aos_repl_loaded"), "{output}");
        assert!(!output.contains("__aos_repl_scope"), "{output}");
        Ok(())
    }

    #[cfg(not(feature = "native-eval"))]
    #[test]
    fn native_repl_scope_command_reports_feature_requirement_without_native_eval() -> Result<()> {
        let evaluator = Arc::new(ReplRecordingEval::default());
        let runner = runner_with_evaluator(Box::new(Arc::clone(&evaluator)));
        let mut input = io::Cursor::new(
            b":scope 1\n\
              :q\n",
        );
        let mut output = Vec::new();

        runner.run_native_repl_session(Path::new("/aos/default.nix"), &mut input, &mut output)?;

        let output = String::from_utf8(output)?;
        assert!(
            output.contains("error: :scope requires the native-eval feature"),
            "{output}"
        );
        Ok(())
    }

    #[test]
    fn native_repl_session_uses_selected_evaluator_and_meta_commands() -> Result<()> {
        let evaluator = Arc::new(ReplRecordingEval::default());
        let realised_drvs = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
        let realised_drvs_for_hook = Arc::clone(&realised_drvs);
        let runner =
            runner_with_evaluator_and_repl_realizer(Box::new(Arc::clone(&evaluator)), move |drv| {
                realised_drvs_for_hook
                    .lock()
                    .expect("realised drvs lock")
                    .push(drv.to_path_buf());
                Ok("/nix/store/fake-output".to_string())
            });
        let mut input = io::Cursor::new(
            b"pkgs.hello\n\
              :t pkgs\n\
              :b pkgs.hello\n\
              :load systems/server.nix\n\
              :reload\n\
              :p config.system.build.toplevel\n\
              :q\n",
        );
        let mut output = Vec::new();

        runner.run_native_repl_session(Path::new("/aos/default.nix"), &mut input, &mut output)?;

        let output = String::from_utf8(output)?;
        assert!(output.contains("AOS native REPL (aos-nix) loaded /aos/default.nix"));
        assert!(output.contains(r#"{"ok":true}"#));
        assert!(output.contains("set"));
        assert!(output.contains("/nix/store/fake-output"));
        assert!(output.contains("loaded /aos/systems/server.nix"));
        assert!(output.contains("reloaded /aos/systems/server.nix"));

        let eval_exprs = evaluator.eval_exprs();
        assert_eq!(eval_exprs.len(), 6);
        assert!(eval_exprs[0].contains(r#""/aos/default.nix""#));
        assert!(eval_exprs[0].contains("builtins.typeOf __aos_repl_scope"));
        assert!(eval_exprs[1].contains("with __aos_repl_scope; (pkgs.hello)"));
        assert!(eval_exprs[2].contains("builtins.typeOf (pkgs)"));
        assert!(eval_exprs[3].contains(r#""/aos/systems/server.nix""#));
        assert!(eval_exprs[3].contains("builtins.typeOf __aos_repl_scope"));
        assert!(eval_exprs[4].contains(r#""/aos/systems/server.nix""#));
        assert!(eval_exprs[4].contains("builtins.typeOf __aos_repl_scope"));
        assert!(eval_exprs[5].contains(r#""/aos/systems/server.nix""#));
        assert!(eval_exprs[5].contains("config.system.build.toplevel"));

        let instantiate_exprs = evaluator.instantiate_exprs();
        assert_eq!(instantiate_exprs.len(), 1);
        assert!(instantiate_exprs[0].contains(r#""/aos/default.nix""#));
        assert!(instantiate_exprs[0].contains("pkgs.hello"));

        let realised_drvs = realised_drvs.lock().expect("realised drvs lock");
        assert_eq!(
            realised_drvs.as_slice(),
            [PathBuf::from("/nix/store/fake-expr.drv")]
        );
        Ok(())
    }

    #[test]
    fn native_repl_eval_type_and_build_pass_user_diagnostic_source() -> Result<()> {
        let evaluator = Arc::new(ReplRecordingEval::default());
        let runner =
            runner_with_evaluator_and_repl_realizer(Box::new(Arc::clone(&evaluator)), |_| {
                Ok("/nix/store/fake-output".to_string())
            });
        let mut input = io::Cursor::new(
            b":p 1 + true\n\
              :t pkgs\n\
              :b pkgs.hello\n\
              :q\n",
        );
        let mut output = Vec::new();

        runner.run_native_repl_session(Path::new("/aos/default.nix"), &mut input, &mut output)?;

        let diagnostic_eval_exprs = evaluator.diagnostic_eval_exprs();
        assert_eq!(diagnostic_eval_exprs.len(), 2);
        assert_diagnostic_slice(&diagnostic_eval_exprs[0], "1 + true");
        assert_diagnostic_slice(&diagnostic_eval_exprs[1], "pkgs");

        let diagnostic_instantiate_exprs = evaluator.diagnostic_instantiate_exprs();
        assert_eq!(diagnostic_instantiate_exprs.len(), 1);
        assert_diagnostic_slice(&diagnostic_instantiate_exprs[0], "pkgs.hello");

        fn assert_diagnostic_slice(expression: &DiagnosticExpression, expected: &str) {
            assert_eq!(expression.diagnostic_name, "repl-input.nix");
            assert_eq!(expression.diagnostic_source, expected);
            assert_eq!(
                &expression.expr[expression.diagnostic_range.clone()],
                expected,
                "{}",
                expression.expr
            );
            assert!(!expression.diagnostic_source.contains("__aos_repl_scope"));
        }

        Ok(())
    }

    #[test]
    fn native_repl_load_error_keeps_previous_scope() -> Result<()> {
        let evaluator = Arc::new(ReplRecordingEval::default());
        let runner = runner_with_evaluator(Box::new(Arc::clone(&evaluator)));
        let mut input = io::Cursor::new(
            b":load bad.nix\n\
              :p pkgs.hello\n\
              :q\n",
        );
        let mut output = Vec::new();

        runner.run_native_repl_session(Path::new("/aos/default.nix"), &mut input, &mut output)?;

        let output = String::from_utf8(output)?;
        assert!(output.contains("error: loading /aos/bad.nix"));

        let eval_exprs = evaluator.eval_exprs();
        assert_eq!(eval_exprs.len(), 3);
        assert!(eval_exprs[0].contains(r#""/aos/default.nix""#));
        assert!(eval_exprs[1].contains(r#""/aos/bad.nix""#));
        assert!(eval_exprs[2].contains(r#""/aos/default.nix""#));
        assert!(eval_exprs[2].contains("pkgs.hello"));
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
