use std::env;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};

use anyhow::{Context, Result};

use crate::error::AosError;

/// Wraps interactions with the Nix CLI tools (`nix-build`, `nix-instantiate`,
/// `nix-store`, `nix-collect-garbage`, `nix-shell`).
pub struct NixRunner {
    /// Path to the directory containing `default.nix`.
    root: PathBuf,
    verbose: u8,
    quiet: bool,
}

impl NixRunner {
    /// Create a new `NixRunner`, locating the project root and verifying that
    /// the `nix-build` binary is available.
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

    /// Return the project root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    // ------------------------------------------------------------------
    // Public high-level operations
    // ------------------------------------------------------------------

    /// Run `nix-build default.nix -A <attr>` and return the resulting store
    /// path.  An optional `out_link` places the result symlink at the given
    /// path instead of the default `./result`.
    pub fn build(&self, attr: &str, out_link: Option<&str>) -> Result<PathBuf> {
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

        let output = self.run_nix("nix-build", &args)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let path = stdout
            .lines()
            .last()
            .map(|l| PathBuf::from(l.trim()))
            .context("nix-build produced no output")?;

        Ok(path)
    }

    /// Run `nix-build -E <expr>` and return the resulting store path.
    /// The expression is responsible for any imports it needs (e.g.
    /// `(import /path/to/. {}).foo.bar`).
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

    /// Build an attribute that evaluates to a set / list and return all
    /// resulting store paths.
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

    /// Evaluate a Nix expression to JSON via `nix-instantiate --eval --strict --json`.
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
        let value: serde_json::Value = serde_json::from_str(stdout.trim())
            .with_context(|| format!("failed to parse JSON from nix-instantiate for attr '{attr}'"))?;

        Ok(value)
    }

    /// Evaluate an arbitrary Nix expression to JSON.
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

    /// Evaluate a Nix expression to a string.
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

    /// Query the Nix store for information about a store path.
    pub fn store_query(&self, path: &Path, args: &[&str]) -> Result<String> {
        let mut full_args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        full_args.push(path.to_string_lossy().to_string());

        let output = self.run_nix("nix-store", &full_args)?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Instantiate (but do not build) a derivation, returning the .drv path.
    pub fn instantiate(&self, attr: &str) -> Result<PathBuf> {
        let args: Vec<String> = vec![
            self.default_nix().to_string_lossy().to_string(),
            "-A".to_string(),
            attr.to_string(),
        ];

        let output = self.run_nix("nix-instantiate", &args)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let path = stdout
            .lines()
            .last()
            .map(|l| PathBuf::from(l.trim()))
            .context("nix-instantiate produced no output")?;

        Ok(path)
    }

    /// Run garbage collection, optionally deleting only generations older than
    /// a given duration (e.g. "7d").
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

    /// List system generations via `nix-env --list-generations`.
    pub fn list_generations(&self) -> Result<String> {
        let args: Vec<String> = vec![
            "--list-generations".to_string(),
            "--profile".to_string(),
            "/nix/var/nix/profiles/system".to_string(),
        ];

        let output = self.run_nix("nix-env", &args)?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Execute into a `nix-shell` session (replaces the current process on
    /// Unix).
    pub fn shell(&self, nix_file: &Path) -> Result<()> {
        let status = Command::new("nix-shell")
            .arg(nix_file)
            .current_dir(&self.root)
            .status()
            .context("failed to start nix-shell")?;

        if !status.success() {
            anyhow::bail!("nix-shell exited with status {status}");
        }
        Ok(())
    }

    /// Execute into a `nix repl` session, loading `default.nix`.
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
