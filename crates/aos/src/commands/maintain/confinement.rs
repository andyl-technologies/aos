//! Fail-closed local confinement for candidate evaluation and repair workers.
//!
//! Linux execution composes private user, mount, PID, IPC, UTS, and network
//! namespaces with the AOS-owned Landlock wrapper. The controller supplies an
//! explicit read/write filesystem policy and never falls back to an ordinary
//! subprocess when either primitive is unavailable.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context as _, Result, bail};
use aos_contract::Sha256Digest;
use aos_maintain::run::ConfinementEvidence;
use serde::Serialize;

const MINIMUM_LANDLOCK_ABI: u32 = 4;

/// A verified Linux candidate-execution boundary.
pub(super) struct Backend {
    unshare: PathBuf,
    landlock: PathBuf,
    landlock_abi: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FilesystemPolicy<'a> {
    read_only: &'a [PathBuf],
    read_write: &'a [PathBuf],
}

impl Backend {
    /// Resolves and probes the project-owned confinement executables.
    ///
    /// # Errors
    ///
    /// Returns an error unless Linux, the configured executables, Landlock ABI
    /// 4, and unprivileged namespace creation are all available.
    pub(super) fn detect() -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        bail!("no verified local maintenance confinement backend is available on this platform");

        #[cfg(target_os = "linux")]
        {
            let unshare = configured_executable("AOS_UNSHARE")?;
            let landlock = configured_executable("AOS_LANDLOCK_WRAPPER")?;
            let output = Command::new(&landlock)
                .arg("--print-abi")
                .env_clear()
                .output()
                .context("probing the AOS Landlock wrapper")?;
            if !output.status.success() {
                bail!("the AOS Landlock wrapper could not probe the running kernel");
            }
            let abi = String::from_utf8(output.stdout)
                .context("Landlock ABI probe emitted non-UTF-8 output")?
                .trim()
                .parse::<u32>()
                .context("Landlock ABI probe emitted an invalid version")?;
            if abi < MINIMUM_LANDLOCK_ABI {
                bail!("Landlock ABI {abi} is below the required ABI {MINIMUM_LANDLOCK_ABI}");
            }
            let backend = Self {
                unshare,
                landlock,
                landlock_abi: abi,
            };
            backend.probe_namespaces()?;
            Ok(backend)
        }
    }

    /// Constructs a network-isolated command with explicit filesystem grants.
    ///
    /// The returned command has no inherited environment. Callers add only the
    /// variables required by the exact operation before spawning it.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, relative, symlinked, or overlapping grant
    /// paths, or when the executable cannot be resolved safely.
    pub(super) fn command(
        &self,
        executable: &Path,
        arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
        read_only: &[PathBuf],
        read_write: &[PathBuf],
    ) -> Result<(Command, ConfinementEvidence)> {
        let executable = checked_existing_path(executable, "confined executable")?;
        let mut ro = normalize_paths(read_only, "read-only grant")?;
        let mut rw = normalize_paths(read_write, "read-write grant")?;
        add_if_present(&mut ro, Path::new("/nix/store"))?;
        add_if_present(&mut ro, Path::new("/nix/var/nix/daemon-socket"))?;
        add_if_present(&mut ro, Path::new("/etc/nix"))?;
        add_if_present(&mut ro, Path::new("/etc/ssl"))?;
        add_if_present(&mut ro, Path::new("/proc"))?;
        add_if_present(&mut rw, Path::new("/dev/null"))?;
        add_if_present(&mut ro, Path::new("/dev/urandom"))?;
        if !path_covered(&executable, &ro) && !path_covered(&executable, &rw) {
            ro.push(executable.clone());
        }
        ro.sort();
        ro.dedup();
        rw.sort();
        rw.dedup();
        ro.retain(|path| !path_covered(path, &rw));
        let policy = FilesystemPolicy {
            read_only: &ro,
            read_write: &rw,
        };
        let policy_digest =
            Sha256Digest::of_canonical("aos.maintain.confinement-filesystem-policy/v1", &policy)?;

        let mut command = Command::new(&self.unshare);
        command.args([
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "--pid",
            "--fork",
            "--kill-child=KILL",
            "--ipc",
            "--uts",
            "--net",
            "--mount-proc=/proc",
            "--",
        ]);
        command.arg(&self.landlock).args([
            OsString::from("--require-abi"),
            OsString::from(MINIMUM_LANDLOCK_ABI.to_string()),
        ]);
        for path in &ro {
            command.arg("--fs-ro").arg(path);
        }
        for path in &rw {
            command.arg("--fs-rw").arg(path);
        }
        command
            .arg("--")
            .arg(executable)
            .args(arguments)
            .env_clear();

        Ok((
            command,
            ConfinementEvidence {
                backend: "aos.linux-userns-landlock/v1".to_string(),
                landlock_abi: self.landlock_abi,
                filesystem_policy_digest: policy_digest,
                private_user_namespace: true,
                private_process_namespaces: true,
                network_isolated: true,
                worker_tree_reaped: true,
            },
        ))
    }

    fn probe_namespaces(&self) -> Result<()> {
        let executable = checked_existing_path(&self.unshare, "namespace probe executable")?;
        let (mut command, _) = self.command(&executable, [OsStr::new("--version")], &[], &[])?;
        let output = command
            .output()
            .context("probing local namespace confinement")?;
        if !output.status.success() {
            bail!(
                "the host cannot create the required private maintenance namespaces: {}",
                bounded_stderr(&output)
            );
        }
        Ok(())
    }
}

fn configured_executable(variable: &str) -> Result<PathBuf> {
    let value = std::env::var_os(variable)
        .ok_or_else(|| anyhow::anyhow!("{variable} is not configured by the AOS runtime"))?;
    checked_existing_path(Path::new(&value), variable)
}

fn checked_existing_path(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("{label} must be an absolute path");
    }
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspecting {label} {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("{label} must be a regular non-symlink file");
    }
    Ok(path.to_path_buf())
}

fn normalize_paths(paths: &[PathBuf], label: &str) -> Result<Vec<PathBuf>> {
    paths
        .iter()
        .map(|path| checked_existing_path_or_directory(path, label))
        .collect()
}

fn checked_existing_path_or_directory(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("{label} must be absolute: {}", path.display());
    }
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspecting {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
        bail!(
            "{label} must be a regular file or directory: {}",
            path.display()
        );
    }
    Ok(path.to_path_buf())
}

fn add_if_present(paths: &mut Vec<PathBuf>, path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if !metadata.file_type().is_symlink() && (metadata.is_file() || metadata.is_dir()) =>
        {
            paths.push(path.to_path_buf());
            Ok(())
        }
        Ok(_) => bail!(
            "confinement support path is not a regular file or directory: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("inspecting confinement support path {}", path.display())),
    }
}

fn path_covered(path: &Path, grants: &[PathBuf]) -> bool {
    grants
        .iter()
        .any(|grant| path == grant || path.starts_with(grant))
}

fn bounded_stderr(output: &Output) -> String {
    let retained = &output.stderr[..output.stderr.len().min(4096)];
    String::from_utf8_lossy(retained).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_coverage_respects_component_boundaries() {
        let grants = vec![PathBuf::from("/allowed/tree")];
        assert!(path_covered(Path::new("/allowed/tree/file"), &grants));
        assert!(!path_covered(Path::new("/allowed/treehouse"), &grants));
    }
}
