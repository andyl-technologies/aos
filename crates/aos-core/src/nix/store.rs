use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};

/// Metadata for a store path, from nix-store queries or Nix DB.
#[derive(Debug, Clone)]
pub struct PathInfo {
    pub path: String,
    pub nar_hash: String,
    pub nar_size: u64,
    pub references: Vec<String>,
    pub deriver: Option<String>,
    pub signatures: Vec<String>,
}

/// Portable classic Nix command wrapper.
///
/// Wraps `nix-instantiate`, `nix-build`, `nix-store` — works on any Nix
/// installation without experimental features.
pub struct NixCli {
    verbose: u8,
}

impl NixCli {
    pub fn new(verbose: u8) -> Self {
        Self { verbose }
    }

    /// Instantiate an attribute from a file -> .drv path.
    pub fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let mut cmd = Command::new("nix-instantiate");
        cmd.arg("-f").arg(file).arg("-A").arg(attr);
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

    /// Instantiate a raw expression -> .drv path.
    pub fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> {
        let mut cmd = Command::new("nix-instantiate");
        cmd.arg("-E").arg(expr);
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

    /// Build a derivation from a file + attribute -> store path.
    pub fn build(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        let mut cmd = Command::new("nix-build");
        cmd.arg(file).arg("-A").arg(attr).arg("--no-out-link");
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

    /// Build a .drv directly -> output store path.
    pub fn realise(&self, drv: &str) -> Result<String> {
        let output = Command::new("nix-store")
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

    /// Get recursive closure of a store path.
    pub fn closure(&self, path: &str) -> Result<Vec<String>> {
        let output = Command::new("nix-store")
            .args(["-qR", path])
            .stderr(Stdio::inherit())
            .output()
            .context("failed to run nix-store -qR")?;
        if !output.status.success() {
            anyhow::bail!("nix-store -qR failed for {}", path);
        }
        let text = String::from_utf8(output.stdout)
            .context("invalid utf-8 from nix-store -qR")?;
        Ok(text.lines().filter(|l| !l.is_empty()).map(String::from).collect())
    }

    /// Query metadata for a store path via CLI commands.
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

    /// Batch path_info for multiple paths via CLI queries.
    pub fn path_info_batch(&self, paths: &[&str]) -> Result<Vec<PathInfo>> {
        paths.iter().map(|p| self.path_info(p)).collect()
    }

    /// Check if a store path is valid locally.
    pub fn is_valid(&self, path: &str) -> Result<bool> {
        let status = Command::new("nix-store")
            .args(["--check-validity", path])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("failed to run nix-store --check-validity")?;
        Ok(status.success())
    }

    /// Spawn `nix-store --dump <path>` with piped stdout.
    #[allow(dead_code)]
    pub fn nar_dump(&self, path: &str) -> Result<Child> {
        Command::new("nix-store")
            .args(["--dump", path])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning nix-store --dump {path}"))
    }

    /// Spawn `nix-store --export <path>` with piped stdout.
    #[allow(dead_code)]
    pub fn nar_export(&self, path: &str) -> Result<Child> {
        Command::new("nix-store")
            .args(["--export", path])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning nix-store --export {path}"))
    }

    /// Pipe data to `nix-store --import` stdin, return imported paths.
    #[allow(dead_code)]
    pub fn nar_import(&self, mut data: impl Read) -> Result<Vec<String>> {
        let mut child = Command::new("nix-store")
            .arg("--import")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("failed to spawn nix-store --import")?;

        {
            let stdin = child.stdin.as_mut().context("no stdin for nix-store --import")?;
            std::io::copy(&mut data, stdin).context("writing to nix-store --import")?;
        }

        let output = child.wait_with_output().context("waiting for nix-store --import")?;
        if !output.status.success() {
            anyhow::bail!("nix-store --import failed");
        }

        let text = String::from_utf8(output.stdout).context("invalid utf-8 from nix-store --import")?;
        Ok(text.lines().filter(|l| !l.is_empty()).map(String::from).collect())
    }
}

/// Run a single `nix-store -q <flag> <path>` query.
fn run_nix_store_query(path: &str, flag: &str) -> Result<String> {
    let output = Command::new("nix-store")
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
