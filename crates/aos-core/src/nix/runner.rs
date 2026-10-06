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
//! and replayed only on failure (suppressed entirely in quiet mode).
//! Failures are reported as [`AosError::NixBuild`] /
//! [`AosError::NixNotFound`] / [`AosError::RootNotFound`] so callers
//! can map them to the standard exit codes.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;

use anyhow::{Context, Result};

use crate::error::AosError;

mod derivation_outputs;

/// Wraps interactions with the Nix CLI tools (`nix-build`, `nix-instantiate`,
/// `nix-store`, `nix-collect-garbage`, `nix-shell`).
pub struct NixRunner {
    /// Path to the directory containing `default.nix`.
    root: PathBuf,
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
        // Verify nix is available.
        which("nix-build").map_err(|_| AosError::NixNotFound)?;

        let root = Self::find_root()?;

        Ok(Self {
            root,
            verbose,
            quiet,
        })
    }

    /// Creates a runner bound to one explicit candidate repository root.
    ///
    /// This constructor prevents maintenance and release controllers from
    /// accidentally evaluating their own checkout when validating an isolated
    /// worktree.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixNotFound`] when `nix-build` is unavailable, or
    /// [`AosError::RootNotFound`] when `root` does not contain `default.nix`.
    pub fn for_root(root: impl Into<PathBuf>, verbose: u8, quiet: bool) -> Result<Self> {
        which("nix-build").map_err(|_| AosError::NixNotFound)?;
        let root = root.into();
        if !root.join("default.nix").is_file() {
            return Err(AosError::RootNotFound.into());
        }
        Ok(Self {
            root,
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
        self.build_inner(attr, out_link, None, None)
    }

    /// Runs `nix-build` for a cross-compilation target.
    ///
    /// The target is passed to the repository's top-level expression as
    /// `--argstr crossSystem <target>`. The target uses a Nix system name such
    /// as `x86_64-darwin` or `aarch64-darwin`.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if `nix-build` exits non-zero, or
    /// another error if it cannot be spawned or prints no output.
    pub fn build_for_target(
        &self,
        attr: &str,
        out_link: Option<&str>,
        target: &str,
    ) -> Result<PathBuf> {
        self.build_inner(attr, out_link, None, Some(target))
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
        self.build_inner(attr, out_link, Some(max_jobs), None)
    }

    fn build_inner(
        &self,
        attr: &str,
        out_link: Option<&str>,
        max_jobs: Option<usize>,
        cross_system: Option<&str>,
    ) -> Result<PathBuf> {
        let mut args: Vec<String> = vec![
            self.default_nix().to_string_lossy().to_string(),
            "-A".to_string(),
            attr.to_string(),
        ];
        add_cross_system_arg(&mut args, cross_system);

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

    /// Builds the repository's filtered package roots for a target platform.
    ///
    /// This evaluates `pkgs.targetPackagesFor target`, whose package-support
    /// policy excludes packages that cannot produce artifacts for the chosen
    /// platform. It therefore does not accidentally build the native package
    /// set or unsupported Linux-only roots during `aos build --all --target`.
    ///
    /// # Errors
    ///
    /// Returns an error if `target` is not a safe Nix system name, if
    /// evaluation fails, or if `nix-build` cannot be spawned or exits
    /// non-zero.
    pub fn build_target_packages(&self, target: &str) -> Result<Vec<PathBuf>> {
        if !target_platform_name_is_safe(target) {
            anyhow::bail!("invalid target platform '{target}'");
        }

        let expression = target_packages_expression();
        let arguments = vec![
            "-E".to_string(),
            expression.to_string(),
            "--argstr".to_string(),
            "defaultNix".to_string(),
            self.default_nix().to_string_lossy().to_string(),
            "--argstr".to_string(),
            "target".to_string(),
            target.to_string(),
            "--no-out-link".to_string(),
        ];

        let output = self.run_nix("nix-build", &arguments)?;
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| PathBuf::from(line.trim()))
            .collect())
    }

    /// Evaluates an attribute of `default.nix` to JSON without allowing IFD.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if evaluation fails, or another
    /// error if `nix-instantiate` cannot be spawned or its output is
    /// not valid JSON.
    pub fn eval_json(&self, attr: &str) -> Result<serde_json::Value> {
        self.eval_json_for_target(attr, None)
    }

    /// Evaluates an attribute for an explicit cross target to strict JSON.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if evaluation fails, an error when the
    /// target name is unsafe, or another error when output is not valid JSON.
    pub fn eval_json_for_target(
        &self,
        attr: &str,
        target: Option<&str>,
    ) -> Result<serde_json::Value> {
        if target.is_some_and(|target| !target_platform_name_is_safe(target)) {
            anyhow::bail!("invalid target platform");
        }
        let args: Vec<String> = vec![
            "--eval".to_string(),
            "--strict".to_string(),
            "--json".to_string(),
            "--option".to_string(),
            "allow-import-from-derivation".to_string(),
            "false".to_string(),
            self.default_nix().to_string_lossy().to_string(),
            "-A".to_string(),
            attr.to_string(),
        ];

        let mut args = args;
        add_cross_system_arg(&mut args, target);

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
        let args: Vec<String> = vec![
            "--eval".to_string(),
            "--strict".to_string(),
            "--json".to_string(),
            "-E".to_string(),
            expr.to_string(),
        ];

        let output = self.run_nix("nix-instantiate", &args)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
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

    /// Realizes exact derivation paths, or repeat-builds them with `check`.
    ///
    /// Without `check`, derivations are passed to as few
    /// `nix-store --realise --keep-going` invocations as the command-line
    /// budget allows, so a typical release of a few thousand derivations runs
    /// as one invocation and Nix schedules builds against its own job limit
    /// and the dependency graph. Fixed-count batches would add a barrier at
    /// every boundary, leaving the machine idle behind the slowest derivation
    /// of each batch.
    ///
    /// With `check`, Nix rebuilds already-realized derivations and fails when
    /// any output is not byte-for-byte reproducible. Each derivation is
    /// checked in its own `nix-store --realise --keep-going --check` process,
    /// with a bounded number (currently 32) running at a time. Separate
    /// processes are required for parallelism: within one invocation Nix
    /// reuses a check goal as the input goal of any dependent target, so
    /// checks serialize along dependency chains. The inputs were realized by
    /// a preceding normal pass, so independent check processes never wait for
    /// one another.
    ///
    /// Both modes keep going after a failure so that one failing or
    /// nondeterministic derivation does not hide the others.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or non-store derivation path before any
    /// command runs. Without `check`, returns the first failing batch's
    /// [`AosError::NixBuild`] after every batch has run, with context naming
    /// the number of failed batches when there is more than one. With
    /// `check`, returns [`AosError::NixBuild`] after every derivation has been
    /// checked, naming each derivation whose check failed together with its
    /// exit status and the tail of its captured stderr. Nix's check-mode
    /// nondeterminism exit status is preserved as a build failure.
    pub fn realise_derivations(&self, derivations: &[PathBuf], check: bool) -> Result<()> {
        if check {
            return self
                .check_derivations(derivations)?
                .require_all_reproduced();
        }

        require_exact_derivation_paths(derivations)?;
        self.realise_derivation_batches(derivations)
    }

    /// Repeat-builds every derivation with Nix `--check` and reports each
    /// failed check instead of failing on the first.
    ///
    /// This is the per-derivation form of
    /// [`realise_derivations`](Self::realise_derivations) with `check`: the
    /// same bounded pool of independent `nix-store --realise --keep-going
    /// --check` processes runs to completion, and the returned
    /// [`CheckReport`] names every derivation whose repeat build differed or
    /// failed. Callers decide whether a failed check is fatal; use
    /// [`CheckReport::require_all_reproduced`] to fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or non-store derivation path before any
    /// command runs. After every check has run, returns
    /// [`AosError::NixBuild`] naming every failure when any `nix-store`
    /// process could not be spawned or awaited: such a check never ran, so it
    /// is evidence of a broken environment rather than of an unreproducible
    /// derivation.
    pub fn check_derivations(&self, derivations: &[PathBuf]) -> Result<CheckReport> {
        require_exact_derivation_paths(derivations)?;

        let report = self.check_derivations_independently(derivations);
        if report
            .failures
            .iter()
            .any(|failure| failure.exit_code.is_none())
        {
            return Err(AosError::NixBuild {
                exit_code: -1,
                stderr: report.to_string(),
            }
            .into());
        }

        Ok(report)
    }

    /// Realizes derivations in command-line-bounded `nix-store` batches.
    fn realise_derivation_batches(&self, derivations: &[PathBuf]) -> Result<()> {
        let batches = batches_by_argument_bytes(derivations, REALISE_ARGUMENT_BYTE_BUDGET);
        let batch_count = batches.len();

        // Run every batch even after a failure so that all failing
        // derivations are reported in one pass.
        let mut failures = Vec::new();
        for batch in batches {
            let mut arguments = vec!["--realise".to_string(), "--keep-going".to_string()];
            arguments.extend(batch.iter().map(|path| path.to_string_lossy().into_owned()));

            if let Err(error) = self.run_nix("nix-store", &arguments) {
                failures.push(error);
            }
        }

        let failure_count = failures.len();
        match failures.into_iter().next() {
            None => Ok(()),
            Some(first) if batch_count == 1 => Err(first),
            Some(first) => Err(first.context(format!(
                "nix-store --realise failed in {failure_count} of {batch_count} batches"
            ))),
        }
    }

    /// Repeat-builds each derivation in its own `nix-store --check` process.
    ///
    /// Outside quiet mode `run_nix` replays each failing process's stderr as
    /// it finishes, so defects are visible during a long pass; the returned
    /// report repeats them together once every check has run.
    fn check_derivations_independently(&self, derivations: &[PathBuf]) -> CheckReport {
        let failures = run_with_bounded_workers(derivations, CHECK_WORKERS, |derivation| {
            let arguments = vec![
                "--realise".to_string(),
                "--keep-going".to_string(),
                "--check".to_string(),
                derivation.to_string_lossy().into_owned(),
            ];
            self.run_nix("nix-store", &arguments)
                .map(drop)
                .map_err(|error| CheckFailure::from_error(derivation, &error))
        });

        CheckReport {
            checked: derivations.len(),
            failures: failures.into_iter().map(|(_, failure)| failure).collect(),
        }
    }

    /// Returns Nix JSON path information for exact realized store paths.
    ///
    /// The result is one object keyed by store path and includes NAR hash,
    /// NAR size, recursive closure size, deriver, and direct references.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-store path, a failed `nix path-info` batch,
    /// invalid JSON, a non-object response, or a duplicate response key.
    pub fn path_info_json(&self, paths: &[PathBuf]) -> Result<serde_json::Value> {
        let mut combined = serde_json::Map::new();
        for path in paths {
            if !path.to_string_lossy().starts_with("/nix/store/") {
                anyhow::bail!("invalid exact Nix store path: {}", path.display());
            }
        }
        // Package aliases and configuration companions share store paths.
        // Query each path once so shared inputs cannot cross batch boundaries.
        let unique_paths: Vec<_> = paths.iter().collect::<BTreeSet<_>>().into_iter().collect();

        for batch in unique_paths.chunks(128) {
            // The packaged Nix 2.24 emits v1 object JSON by default and does not
            // recognize the --json-format flag introduced in later releases.
            let mut arguments = vec![
                "path-info".to_string(),
                "--json".to_string(),
                "--closure-size".to_string(),
            ];
            arguments.extend(batch.iter().map(|path| path.to_string_lossy().into_owned()));
            let output = self.run_nix("nix", &arguments)?;
            let value: serde_json::Value =
                serde_json::from_slice(&output.stdout).context("parsing Nix path-info JSON")?;
            let object = value
                .as_object()
                .context("Nix path-info JSON is not an object")?;
            for (path, info) in object {
                if combined.insert(path.clone(), info.clone()).is_some() {
                    anyhow::bail!("Nix path-info repeated store path {path}");
                }
            }
        }
        Ok(serde_json::Value::Object(combined))
    }

    /// Returns every output of a store derivation and the store path it
    /// produces, keyed by Nix output name.
    ///
    /// The map is read with `nix derivation show`, which describes the
    /// derivation itself. Unlike `nix-store --query --binding outputs`, this
    /// also works for derivations built with structured attributes, which
    /// have no `outputs` environment binding. Both the older document keyed
    /// by derivation path and the newer versioned document are accepted.
    ///
    /// # Errors
    ///
    /// Returns an error for a path that is not an exact `/nix/store/*.drv`
    /// path, when `nix derivation show` fails, or when its JSON omits the
    /// derivation, lists no outputs, or names an output without a static
    /// store path.
    pub fn derivation_outputs(&self, derivation: &Path) -> Result<BTreeMap<String, String>> {
        require_exact_derivation_paths(&[derivation.to_path_buf()])?;

        let arguments = [
            "derivation".to_string(),
            "show".to_string(),
            derivation.to_string_lossy().into_owned(),
        ];
        let output = self.run_nix("nix", &arguments)?;
        derivation_outputs::parse(derivation, &output.stdout)
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
        self.instantiate_inner(attr, None)
    }

    /// Instantiates a derivation for a cross-compilation target.
    ///
    /// The target is passed as the top-level `crossSystem` string argument.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] if instantiation fails, or another
    /// error if `nix-instantiate` cannot be spawned or prints no output.
    pub fn instantiate_for_target(&self, attr: &str, target: &str) -> Result<PathBuf> {
        self.instantiate_inner(attr, Some(target))
    }

    /// Instantiates every derivation returned by a derivation list.
    ///
    /// This registers the derivations in the local Nix store without realizing
    /// their outputs. An empty list is valid and returns no paths. `target`
    /// is passed as the top-level `crossSystem` string argument; `None`
    /// evaluates the repository's ordinary native package set, which differs
    /// from passing the native platform as a cross target.
    ///
    /// # Errors
    ///
    /// Returns an error if `target` is not a safe Nix system name,
    /// [`AosError::NixBuild`] if instantiation fails, or another error if
    /// `nix-instantiate` cannot be spawned.
    pub fn instantiate_all_for_target(
        &self,
        attr: &str,
        target: Option<&str>,
    ) -> Result<Vec<PathBuf>> {
        if let Some(target) = target
            && !target_platform_name_is_safe(target)
        {
            anyhow::bail!("invalid target platform '{target}'");
        }

        let mut args = vec![
            self.default_nix().to_string_lossy().to_string(),
            "-A".to_string(),
            attr.to_string(),
        ];
        add_cross_system_arg(&mut args, target);

        let output = self.run_nix("nix-instantiate", &args)?;
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| PathBuf::from(strip_nix_output_selector(line.trim())))
            .collect())
    }

    fn instantiate_inner(&self, attr: &str, cross_system: Option<&str>) -> Result<PathBuf> {
        let mut args: Vec<String> = vec![
            self.default_nix().to_string_lossy().to_string(),
            "-A".to_string(),
            attr.to_string(),
        ];
        add_cross_system_arg(&mut args, cross_system);

        let output = self.run_nix("nix-instantiate", &args)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let path = stdout
            .lines()
            .last()
            .map(|l| PathBuf::from(l.trim()))
            .context("nix-instantiate produced no output")?;

        Ok(path)
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
        let status = Command::new("nix")
            .args(["repl", "--file"])
            .arg(nix_file)
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
        if let Ok(exe) = env::current_exe()
            && let Some(bin_dir) = exe.parent()
        {
            // Try alongside the binary.
            if bin_dir.join("default.nix").is_file() {
                return Ok(bin_dir.to_path_buf());
            }
            // Try one level up (e.g. bin/ -> project root).
            if let Some(parent) = bin_dir.parent()
                && parent.join("default.nix").is_file()
            {
                return Ok(parent.to_path_buf());
            }
        }

        Err(AosError::RootNotFound.into())
    }

    /// Core runner: spawn a Nix subprocess and capture its output.  When
    /// `verbose >= 2` the child's stderr is streamed to the terminal in
    /// real-time; otherwise it is captured and only shown on failure.
    fn run_nix(&self, cmd: &str, args: &[String]) -> Result<Output> {
        if self.verbose >= 3 {
            eprintln!("+ {} {}", cmd, args.join(" "));
        }

        let stderr_behavior = if self.verbose >= 2 {
            Stdio::inherit()
        } else {
            Stdio::piped()
        };

        let child = Command::new(cmd)
            .args(args)
            .current_dir(&self.root)
            .stdout(Stdio::piped())
            .stderr(stderr_behavior)
            .spawn()
            .with_context(|| format!("failed to spawn {cmd}"))?;

        // When verbose >= 2, stderr goes directly to the terminal (Inherit),
        // so we only need to read stdout.  Otherwise we capture both.
        if self.verbose >= 2 {
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

    /// Stream a child process's stdout and stderr line-by-line to the
    /// terminal.  Used for interactive / long-running commands where the user
    /// wants to see real-time output.
    #[allow(dead_code)] // intended for future use by interactive commands
    fn stream_output(&self, child: &mut Child) -> Result<ExitStatus> {
        // Drain stderr in a background thread so we don't deadlock.
        let stderr_handle = child.stderr.take().map(|stderr| {
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines().map_while(std::result::Result::ok) {
                    eprintln!("{line}");
                }
            })
        });

        // Drain stdout on the main thread.
        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(std::result::Result::ok) {
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

/// Appends the top-level cross-compilation argument when a target was chosen.
fn add_cross_system_arg(args: &mut Vec<String>, cross_system: Option<&str>) {
    if let Some(target) = cross_system {
        args.extend([
            "--argstr".to_string(),
            "crossSystem".to_string(),
            target.to_string(),
        ]);
    }
}

/// Returns whether a target can be embedded in the generated Nix expression.
fn target_platform_name_is_safe(target: &str) -> bool {
    !target.is_empty()
        && target
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

/// Rejects anything other than an exact `/nix/store/*.drv` path.
fn require_exact_derivation_paths(derivations: &[PathBuf]) -> Result<()> {
    for derivation in derivations {
        let text = derivation.to_string_lossy();
        if !text.starts_with("/nix/store/") || !text.ends_with(".drv") {
            anyhow::bail!("invalid exact derivation path: {text}");
        }
    }
    Ok(())
}

/// Removes the output selector that `nix-instantiate` prints for a non-default output.
fn strip_nix_output_selector(path: &str) -> &str {
    path.split_once('!')
        .map_or(path, |(derivation, _)| derivation)
}

/// Maximum command-line bytes of derivation paths in one `nix-store --realise`.
///
/// Linux limits the combined size of arguments and environment (`ARG_MAX`,
/// commonly 2 MiB) and each single argument to 128 KiB. One MiB of path
/// bytes leaves ample room for the environment while still fitting roughly
/// sixteen thousand `/nix/store/<hash>-<name>.drv` paths per invocation.
const REALISE_ARGUMENT_BYTE_BUDGET: usize = 1024 * 1024;

/// Splits `paths` into consecutive batches whose argument bytes fit `budget`.
///
/// Each path costs its byte length plus the NUL terminator `execve` stores
/// after it. A path that alone exceeds the budget still gets its own batch,
/// so every path appears in exactly one batch and order is preserved. Empty
/// input yields no batches.
fn batches_by_argument_bytes(paths: &[PathBuf], budget: usize) -> Vec<&[PathBuf]> {
    let mut batches = Vec::new();
    let mut start = 0;
    let mut batch_bytes = 0;

    for (index, path) in paths.iter().enumerate() {
        let argument_bytes = path.as_os_str().len() + 1;

        // Close the current batch when this path would overflow it. A batch
        // never closes empty, which keeps oversized paths in their own batch.
        if index > start && batch_bytes + argument_bytes > budget {
            batches.push(&paths[start..index]);
            start = index;
            batch_bytes = 0;
        }
        batch_bytes += argument_bytes;
    }

    if start < paths.len() {
        batches.push(&paths[start..]);
    }
    batches
}

/// Maximum concurrent `nix-store --check` processes in a repeat-build pass.
///
/// Each process asks the Nix daemon for one rebuild, so this bounds the
/// number of simultaneous check builds independently of `max-jobs`.
const CHECK_WORKERS: usize = 32;

/// Number of trailing stderr lines kept for each failed check.
const CHECK_STDERR_TAIL_LINES: usize = 20;

/// Outcome of a Nix `--check` repeat-build pass over exact derivations.
///
/// Produced by [`NixRunner::check_derivations`]. Failures are listed in the
/// order of the checked derivations, independent of worker scheduling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    checked: usize,
    failures: Vec<CheckFailure>,
}

impl CheckReport {
    /// Creates a report for `checked` derivations with the given failures.
    ///
    /// [`NixRunner::check_derivations`] produces reports from real checks;
    /// this constructor lets callers test how they act on an outcome.
    #[must_use]
    pub fn new(checked: usize, failures: Vec<CheckFailure>) -> Self {
        Self { checked, failures }
    }

    /// Returns the number of derivations that were repeat-built.
    #[must_use]
    pub fn checked(&self) -> usize {
        self.checked
    }

    /// Returns every derivation whose repeat build did not succeed.
    #[must_use]
    pub fn failures(&self) -> &[CheckFailure] {
        &self.failures
    }

    /// Reports whether every checked derivation reproduced byte-identically.
    #[must_use]
    pub fn all_reproduced(&self) -> bool {
        self.failures.is_empty()
    }

    /// Requires every checked derivation to have reproduced.
    ///
    /// # Errors
    ///
    /// Returns [`AosError::NixBuild`] when any check failed, carrying the
    /// first failure's exit status and a report naming every failed
    /// derivation with its exit status and the tail of its captured stderr.
    /// Nix's check-mode nondeterminism exit status is preserved as a build
    /// failure.
    pub fn require_all_reproduced(&self) -> Result<()> {
        let Some(first) = self.failures.first() else {
            return Ok(());
        };

        Err(AosError::NixBuild {
            exit_code: first.exit_code.unwrap_or(-1),
            stderr: self.to_string(),
        }
        .into())
    }
}

/// Formats every failed check into one report, one derivation per entry.
impl std::fmt::Display for CheckReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&check_failure_report(&self.failures, self.checked))
    }
}

/// One derivation whose `nix-store --realise --check` process failed.
///
/// A failure means the repeat build did not prove a byte-identical output:
/// Nix found a differing output, the rebuild itself failed, or (with no exit
/// status) the process could not be run at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckFailure {
    /// Exact derivation path that was repeat-built.
    pub derivation: PathBuf,
    /// Exit status of `nix-store`, or `None` when it could not be run.
    pub exit_code: Option<i32>,
    /// Captured stderr tail, or the spawn error when there is no status.
    ///
    /// The tail is empty when stderr was streamed live at high verbosity.
    pub detail: String,
}

impl CheckFailure {
    /// Records a failed check from the error returned by `run_nix`.
    ///
    /// The captured stderr is empty when it was already streamed live at
    /// high verbosity; the derivation and exit status are still reported.
    fn from_error(derivation: &Path, error: &anyhow::Error) -> Self {
        let (exit_code, detail) = match error.downcast_ref::<AosError>() {
            Some(AosError::NixBuild { exit_code, stderr }) => (
                Some(*exit_code),
                stderr_tail(stderr, CHECK_STDERR_TAIL_LINES),
            ),
            _ => (None, format!("{error:#}")),
        };

        Self {
            derivation: derivation.to_path_buf(),
            exit_code,
            detail,
        }
    }

    /// Returns a one-line reason suitable for a summary listing.
    ///
    /// This is the first `error:` line of the captured stderr tail, which is
    /// where Nix names a differing output or a failed builder. Without one it
    /// falls back to the last non-empty line, and without any captured text
    /// to the exit status.
    #[must_use]
    pub fn reason(&self) -> String {
        let lines = || {
            self.detail
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
        };

        if let Some(error) = lines().find(|line| line.starts_with("error:")) {
            return error.to_owned();
        }
        if let Some(last) = lines().last() {
            return last.to_owned();
        }
        match self.exit_code {
            Some(code) => format!("nix-store exited with status {code}"),
            None => "nix-store did not run".to_owned(),
        }
    }
}

/// Returns the last `lines` lines of `stderr`, ignoring trailing blank lines.
fn stderr_tail(stderr: &str, lines: usize) -> String {
    let all: Vec<_> = stderr.trim_end().lines().collect();
    let start = all.len().saturating_sub(lines);
    all[start..].join("\n")
}

/// Formats every failed check into one fail-closed error report.
fn check_failure_report(failures: &[CheckFailure], checked: usize) -> String {
    let mut report = format!(
        "{} of {checked} derivations failed nix-store --realise --check:",
        failures.len()
    );

    for failure in failures {
        let status = match failure.exit_code {
            Some(code) => format!("exit code {code}"),
            None => "not run".to_string(),
        };
        report.push_str(&format!("\n  {} ({status})", failure.derivation.display()));

        for line in failure.detail.lines() {
            report.push_str("\n    ");
            report.push_str(line);
        }
    }
    report
}

/// Runs `task` on every item with at most `workers` concurrent threads.
///
/// Workers pull the next unclaimed index from a shared counter, so a slow
/// item never holds back the others. Every item runs exactly once, even
/// after failures. Failures are returned with their item index, sorted by
/// index so reports do not depend on thread scheduling. A `workers` of zero
/// is treated as one.
fn run_with_bounded_workers<T, E, F>(items: &[T], workers: usize, task: F) -> Vec<(usize, E)>
where
    T: Sync,
    E: Send,
    F: Fn(&T) -> Result<(), E> + Sync,
{
    let worker_count = workers.max(1).min(items.len());
    let next_index = AtomicUsize::new(0);
    let (sender, receiver) = mpsc::channel();

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let sender = sender.clone();
            let next_index = &next_index;
            let task = &task;

            scope.spawn(move || {
                loop {
                    let index = next_index.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(index) else {
                        break;
                    };
                    if let Err(error) = task(item) {
                        // The receiver outlives the scope, so sending cannot fail.
                        let _ = sender.send((index, error));
                    }
                }
            });
        }
    });
    drop(sender);

    let mut failures: Vec<_> = receiver.into_iter().collect();
    failures.sort_by_key(|(index, _)| *index);
    failures
}

/// Returns the Nix function used to select platform-supported target roots.
fn target_packages_expression() -> &'static str {
    "{ defaultNix, target }: let aos = import (builtins.toPath defaultNix) { crossSystem = target; }; in builtins.attrValues (aos.pkgs.targetPackagesFor target)"
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use super::{
        CheckFailure, CheckReport, add_cross_system_arg, batches_by_argument_bytes,
        check_failure_report, require_exact_derivation_paths, run_with_bounded_workers,
        stderr_tail, strip_nix_output_selector, target_packages_expression,
    };

    /// Builds a store-like derivation path of exactly `length` bytes.
    fn derivation_of_length(length: usize) -> PathBuf {
        let prefix = "/nix/store/";
        let suffix = ".drv";
        let name = "x".repeat(length - prefix.len() - suffix.len());
        PathBuf::from(format!("{prefix}{name}{suffix}"))
    }

    #[test]
    fn argument_batches_of_empty_input_are_empty() {
        let batches = batches_by_argument_bytes(&[], 1024);

        assert!(batches.is_empty());
    }

    #[test]
    fn argument_batches_keep_paths_under_budget_together() {
        let paths: Vec<_> = (0..3000).map(|_| derivation_of_length(64)).collect();

        let batches = batches_by_argument_bytes(&paths, super::REALISE_ARGUMENT_BYTE_BUDGET);

        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), paths.len());
    }

    #[test]
    fn argument_batches_split_when_budget_is_exceeded() {
        // Each path costs 20 bytes including its NUL terminator, so a
        // 50-byte budget fits two paths per batch.
        let paths: Vec<_> = (0..5).map(|_| derivation_of_length(19)).collect();

        let batches = batches_by_argument_bytes(&paths, 50);

        let lengths: Vec<_> = batches.iter().map(|batch| batch.len()).collect();
        assert_eq!(lengths, [2, 2, 1]);
        assert_eq!(batches.concat(), paths);
    }

    #[test]
    fn argument_batches_count_the_terminator_at_the_boundary() {
        // Two 19-byte paths cost exactly 40 bytes and fit; a 39-byte budget
        // does not fit both.
        let paths = vec![derivation_of_length(19), derivation_of_length(19)];

        assert_eq!(batches_by_argument_bytes(&paths, 40).len(), 1);
        assert_eq!(batches_by_argument_bytes(&paths, 39).len(), 2);
    }

    #[test]
    fn argument_batches_isolate_a_path_larger_than_the_budget() {
        let paths = vec![
            derivation_of_length(20),
            derivation_of_length(200),
            derivation_of_length(20),
        ];

        let batches = batches_by_argument_bytes(&paths, 100);

        let lengths: Vec<_> = batches.iter().map(|batch| batch.len()).collect();
        assert_eq!(lengths, [1, 1, 1]);
        assert_eq!(batches[1], &paths[1..2]);
    }

    #[test]
    fn bounded_workers_run_every_item_once_and_keep_going() {
        let items: Vec<usize> = (0..100).collect();
        let seen = Mutex::new(Vec::new());

        let failures = run_with_bounded_workers(&items, 8, |item| {
            seen.lock().expect("lock").push(*item);
            if item % 10 == 3 { Err(*item) } else { Ok(()) }
        });

        let mut seen = seen.into_inner().expect("lock");
        seen.sort_unstable();
        assert_eq!(seen, items);
        let failed: Vec<_> = failures.iter().map(|(_, item)| *item).collect();
        assert_eq!(failed, [3, 13, 23, 33, 43, 53, 63, 73, 83, 93]);
        assert!(failures.iter().all(|(index, item)| index == item));
    }

    #[test]
    fn bounded_workers_never_exceed_the_limit() {
        let items = vec![(); 24];
        let running = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);

        let failures = run_with_bounded_workers(&items, 4, |_| {
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(5));
            running.fetch_sub(1, Ordering::SeqCst);
            Ok::<(), ()>(())
        });

        assert!(failures.is_empty());
        let peak = peak.load(Ordering::SeqCst);
        assert!((1..=4).contains(&peak), "peak concurrency was {peak}");
    }

    #[test]
    fn bounded_workers_handle_empty_input_and_zero_workers() {
        let empty: [u8; 0] = [];
        assert!(run_with_bounded_workers(&empty, 4, |_| Err(())).is_empty());

        let failures = run_with_bounded_workers(&[1, 2], 0, |item| Err(*item));
        assert_eq!(failures, [(0, 1), (1, 2)]);
    }

    #[test]
    fn stderr_tail_keeps_only_the_last_lines() {
        assert_eq!(stderr_tail("a\nb\nc\nd\n\n", 2), "c\nd");
        assert_eq!(stderr_tail("only\n", 5), "only");
        assert_eq!(stderr_tail("", 5), "");
    }

    #[test]
    fn check_failures_from_nix_build_errors_keep_status_and_tail() {
        let error = anyhow::Error::from(crate::error::AosError::NixBuild {
            exit_code: 104,
            stderr: "building\nerror: may not be deterministic\n".to_string(),
        });

        let failure = CheckFailure::from_error(Path::new("/nix/store/a-x.drv"), &error);

        assert_eq!(failure.exit_code, Some(104));
        assert_eq!(failure.detail, "building\nerror: may not be deterministic");
    }

    #[test]
    fn check_failure_report_names_every_failed_derivation() {
        let failures = [
            CheckFailure {
                derivation: PathBuf::from("/nix/store/a-x.drv"),
                exit_code: Some(104),
                detail: "error: may not be deterministic".to_string(),
            },
            CheckFailure {
                derivation: PathBuf::from("/nix/store/b-y.drv"),
                exit_code: None,
                detail: "failed to spawn nix-store".to_string(),
            },
        ];

        let report = check_failure_report(&failures, 1960);

        assert_eq!(
            report,
            "2 of 1960 derivations failed nix-store --realise --check:\n  \
             /nix/store/a-x.drv (exit code 104)\n    \
             error: may not be deterministic\n  \
             /nix/store/b-y.drv (not run)\n    \
             failed to spawn nix-store"
        );
    }

    fn failure(derivation: &str, exit_code: Option<i32>, detail: &str) -> CheckFailure {
        CheckFailure {
            derivation: PathBuf::from(derivation),
            exit_code,
            detail: detail.to_string(),
        }
    }

    #[test]
    fn check_failure_reason_prefers_the_first_nix_error_line() {
        let nondeterministic = failure(
            "/nix/store/a-x.drv",
            Some(104),
            "checking outputs of '/nix/store/a-x.drv'...\n  \
             error: derivation '/nix/store/a-x.drv' may not be deterministic\n\
             error: build of '/nix/store/a-x.drv' failed",
        );
        let unlabelled = failure("/nix/store/b-y.drv", Some(1), "line one\nlast line\n\n");
        let silent = failure("/nix/store/c-z.drv", Some(100), "");

        assert_eq!(
            nondeterministic.reason(),
            "error: derivation '/nix/store/a-x.drv' may not be deterministic"
        );
        assert_eq!(unlabelled.reason(), "last line");
        assert_eq!(silent.reason(), "nix-store exited with status 100");
    }

    #[test]
    fn check_report_without_failures_is_reproduced() {
        let report = CheckReport {
            checked: 3,
            failures: vec![],
        };

        assert!(report.all_reproduced());
        assert!(report.require_all_reproduced().is_ok());
    }

    #[test]
    fn check_report_with_failures_fails_closed_with_every_derivation() {
        let report = CheckReport {
            checked: 3,
            failures: vec![
                failure("/nix/store/a-x.drv", Some(104), "error: differs"),
                failure("/nix/store/b-y.drv", Some(1), "error: builder failed"),
            ],
        };

        let error = report
            .require_all_reproduced()
            .expect_err("failed checks must fail closed");

        assert!(!report.all_reproduced());
        let Some(crate::error::AosError::NixBuild { exit_code, stderr }) =
            error.downcast_ref::<crate::error::AosError>()
        else {
            panic!("expected a Nix build error, got {error:#}");
        };
        assert_eq!(*exit_code, 104);
        assert!(stderr.starts_with("2 of 3 derivations failed"));
        assert!(stderr.contains("/nix/store/a-x.drv (exit code 104)"));
        assert!(stderr.contains("/nix/store/b-y.drv (exit code 1)"));
    }

    #[test]
    fn exact_derivation_paths_must_be_store_derivations() {
        assert!(require_exact_derivation_paths(&[PathBuf::from("/nix/store/a-x.drv")]).is_ok());
        assert!(require_exact_derivation_paths(&[PathBuf::from("/tmp/a-x.drv")]).is_err());
        assert!(require_exact_derivation_paths(&[PathBuf::from("/nix/store/a-x")]).is_err());
    }

    #[test]
    fn cross_system_argument_uses_canonical_nix_spelling() {
        let mut arguments = vec!["default.nix".to_string()];

        add_cross_system_arg(&mut arguments, Some("aarch64-darwin"));

        assert_eq!(
            arguments,
            ["default.nix", "--argstr", "crossSystem", "aarch64-darwin"]
        );
    }

    #[test]
    fn native_evaluation_adds_no_cross_system_argument() {
        let mut arguments = vec!["default.nix".to_string()];

        add_cross_system_arg(&mut arguments, None);

        assert_eq!(arguments, ["default.nix"]);
    }

    #[test]
    fn target_package_build_rejects_expression_characters() {
        assert!(super::target_platform_name_is_safe("aarch64-darwin"));
        assert!(!super::target_platform_name_is_safe(
            "aarch64-darwin\"; abort"
        ));
    }

    #[test]
    fn target_package_build_selects_filtered_cross_roots() {
        let expression = target_packages_expression();

        assert!(expression.contains("{ crossSystem = target; }"));
        assert!(expression.contains("aos.pkgs.targetPackagesFor target"));
        assert!(!expression.contains("builtins.attrValues aos.pkgs"));
    }

    #[test]
    fn instantiated_output_selectors_are_removed() {
        assert_eq!(
            strip_nix_output_selector("/nix/store/example.drv!config"),
            "/nix/store/example.drv"
        );
        assert_eq!(
            strip_nix_output_selector("/nix/store/example.drv"),
            "/nix/store/example.drv"
        );
    }
}
