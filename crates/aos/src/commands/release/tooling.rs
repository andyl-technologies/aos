//! The release tooling environment: the Nix closure the coordinator runs from.
//!
//! Release commands do not read the coordinator's own store path or the
//! qualification executors from the maintainer configuration. Both belong to
//! the tooling the operator installed, so they are discovered from it:
//!
//! - the **tooling closure** is `$AOS_RELEASE_TOOLING` when the
//!   `aos-release-tooling` wrapper set it, else the `/nix/store/<name>` root
//!   that contains the running executable. Its path is the `tooling` fitness
//!   binding, so a storage-restore attestation recorded by one tooling build
//!   does not vouch for another.
//! - the **native executors** live inside that closure at
//!   `libexec/aos-release/executors/<platform>/`, each holding the `run`
//!   program and an `identity` file naming the identity it must report.
//!
//! A binary outside the Nix store (a plain `cargo build`) has no closure. It
//! can inspect state, but a command that freezes or qualifies a release
//! refuses to run from it, so a development build cannot masquerade as the
//! installed release tooling.
//!
//! ```text
//! /nix/store/<hash>-aos-release-tooling-<version>/
//! ├── bin/aos                      wrapper exporting AOS_RELEASE_TOOLING
//! └── libexec/aos-release/executors/
//!     └── x86_64-linux/
//!         ├── run                  qualification executor program
//!         └── identity             "aos-x86_64-linux-qualification-v1"
//! ```

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aos_release::digest::Sha256Digest;
use aos_release::platform::Platform;

/// Environment variable through which the tooling wrapper names its closure.
pub(super) const TOOLING_ENVIRONMENT: &str = "AOS_RELEASE_TOOLING";

/// Domain separating the tooling-closure fitness binding.
const TOOLING_DOMAIN: &str = "aos.release.tooling-closure/v1";

/// Root of every Nix store closure.
const STORE_ROOT: &str = "/nix/store";

/// Executor directory inside the tooling closure.
const EXECUTORS_DIRECTORY: &str = "libexec/aos-release/executors";

/// Executor program file name inside a platform directory.
const EXECUTOR_PROGRAM: &str = "run";

/// Executor identity file name inside a platform directory.
const EXECUTOR_IDENTITY: &str = "identity";

/// One installed native qualification executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Executor {
    /// Absolute executor program path.
    pub(super) path: PathBuf,
    /// Identity the executor must report in every response.
    pub(super) identity: String,
}

/// The tooling closure and the executors it ships.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ToolingEnvironment {
    closure: PathBuf,
    executors: BTreeMap<Platform, Executor>,
}

impl ToolingEnvironment {
    /// Detects the tooling environment of the running process.
    ///
    /// Returns `None` when the process runs outside any Nix store closure and
    /// the wrapper variable is unset, so inspection commands keep working on
    /// a development build.
    ///
    /// # Errors
    /// Returns an error for a wrapper variable that is not an absolute
    /// existing directory, an unreadable executable path, or a malformed
    /// executor directory inside the closure.
    pub(super) fn detect() -> Result<Option<Self>> {
        if let Some(value) = std::env::var_os(TOOLING_ENVIRONMENT).filter(|value| !value.is_empty())
        {
            let closure = PathBuf::from(value);
            if !closure.is_absolute() {
                bail!("{TOOLING_ENVIRONMENT} must be an absolute path");
            }
            return Self::from_closure(&closure).map(Some);
        }
        let executable =
            std::env::current_exe().context("resolving the running executable's path")?;
        let executable = executable
            .canonicalize()
            .with_context(|| format!("canonicalizing {}", executable.display()))?;
        match closure_root(&executable) {
            Some(closure) => Self::from_closure(&closure).map(Some),
            None => Ok(None),
        }
    }

    /// Detects the tooling environment and refuses a development build.
    ///
    /// # Errors
    /// Returns an error when the process does not run from a Nix store
    /// closure, in addition to the errors of [`Self::detect`].
    pub(super) fn require() -> Result<Self> {
        Self::detect()?.context(
            "release tooling must run from an installed Nix closure; \
             enter the release tooling environment or set AOS_RELEASE_TOOLING",
        )
    }

    /// Reads the tooling environment rooted at `closure`.
    ///
    /// # Errors
    /// Returns an error when `closure` is not a directory or its executor
    /// directory is malformed.
    pub(super) fn from_closure(closure: &Path) -> Result<Self> {
        if !closure.is_dir() {
            bail!("tooling closure {} is not a directory", closure.display());
        }
        let executors = read_executors(&closure.join(EXECUTORS_DIRECTORY))?;
        Ok(Self {
            closure: closure.to_path_buf(),
            executors,
        })
    }

    /// Returns the closure root.
    pub(super) fn closure(&self) -> &Path {
        &self.closure
    }

    /// Returns the digest bound by `tooling` fitness.
    ///
    /// # Errors
    /// Returns an error when the closure path is not UTF-8.
    pub(super) fn digest(&self) -> Result<Sha256Digest> {
        let closure = self
            .closure
            .to_str()
            .context("tooling closure path is not UTF-8")?;
        Sha256Digest::of_canonical(TOOLING_DOMAIN, &closure.to_owned())
    }

    /// Returns the installed executors keyed by platform.
    pub(super) fn executors(&self) -> &BTreeMap<Platform, Executor> {
        &self.executors
    }

    /// Renders one `PLATFORM=VALUE` specification per installed executor.
    ///
    /// # Errors
    /// Returns an error when the closure ships no executor at all.
    pub(super) fn executor_specs(
        &self,
        value: impl Fn(&Executor) -> String,
    ) -> Result<Vec<String>> {
        if self.executors.is_empty() {
            bail!(
                "tooling closure {} ships no qualification executor under {EXECUTORS_DIRECTORY}",
                self.closure.display()
            );
        }
        Ok(self
            .executors
            .iter()
            .map(|(platform, executor)| format!("{}={}", platform.as_str(), value(executor)))
            .collect())
    }
}

/// Returns the `tooling` fitness binding of the detected environment.
///
/// A development build outside the store binds nothing, which a profile
/// requiring `storage-restore` fitness then reports as a mismatch.
///
/// # Errors
/// Returns the errors of [`ToolingEnvironment::detect`] and
/// [`ToolingEnvironment::digest`].
pub(super) fn detected_digest() -> Result<Option<Sha256Digest>> {
    ToolingEnvironment::detect()?
        .map(|tooling| tooling.digest())
        .transpose()
}

/// Returns the `/nix/store/<name>` root containing `path`, if any.
fn closure_root(path: &Path) -> Option<PathBuf> {
    let store = Path::new(STORE_ROOT);
    let relative = path.strip_prefix(store).ok()?;
    let name = match relative.components().next()? {
        Component::Normal(name) => name,
        _ => return None,
    };
    Some(store.join(name))
}

/// Reads every `<platform>/{run,identity}` executor under `directory`.
///
/// A missing directory yields no executors; a present one must be well
/// formed, since a half-installed executor set would otherwise silently
/// narrow the qualification matrix.
fn read_executors(directory: &Path) -> Result<BTreeMap<Platform, Executor>> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", directory.display()));
        }
    };

    let mut executors = BTreeMap::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", directory.display()))?;
        let name = entry.file_name();
        let name = name.to_str().with_context(|| {
            format!(
                "executor directory name in {} is not UTF-8",
                directory.display()
            )
        })?;
        let platform: Platform = serde_json::from_value(serde_json::Value::String(name.to_owned()))
            .with_context(|| format!("executor directory {name} does not name a platform"))?;

        let platform_directory = entry.path();
        let path = platform_directory.join(EXECUTOR_PROGRAM);
        super::signer::validate_signer_executable(&path)
            .with_context(|| format!("inspecting executor {}", path.display()))?;
        let identity = std::fs::read_to_string(platform_directory.join(EXECUTOR_IDENTITY))
            .with_context(|| format!("reading executor identity for {name}"))?;
        let identity = identity.trim().to_owned();
        if identity.is_empty() || identity.lines().count() != 1 {
            bail!("executor identity for {name} must be one non-empty line");
        }

        executors.insert(platform, Executor { path, identity });
    }
    Ok(executors)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn write_executor(root: &Path, platform: &str, identity: &str) -> Result<()> {
        let directory = root.join(EXECUTORS_DIRECTORY).join(platform);
        fs::create_dir_all(&directory)?;
        let program = directory.join(EXECUTOR_PROGRAM);
        fs::write(&program, b"#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700))?;
        fs::write(directory.join(EXECUTOR_IDENTITY), format!("{identity}\n"))?;
        Ok(())
    }

    #[test]
    fn closure_root_is_the_first_store_component() {
        assert_eq!(
            closure_root(Path::new("/nix/store/abc-aos-0.1.0/bin/.aos-unwrapped")),
            Some(PathBuf::from("/nix/store/abc-aos-0.1.0"))
        );
        assert_eq!(closure_root(Path::new("/home/dev/target/debug/aos")), None);
        assert_eq!(closure_root(Path::new("/nix/store")), None);
    }

    #[test]
    fn reads_executors_and_binds_the_closure() -> Result<()> {
        let root = tempfile::tempdir()?;
        write_executor(
            root.path(),
            "x86_64-linux",
            "aos-x86_64-linux-qualification-v1",
        )?;
        write_executor(
            root.path(),
            "aarch64-linux",
            "aos-aarch64-linux-qualification-v1",
        )?;

        let tooling = ToolingEnvironment::from_closure(root.path())?;
        let executors = tooling.executors();
        assert_eq!(executors.len(), 2);
        assert_eq!(
            executors[&Platform::X86_64Linux].identity,
            "aos-x86_64-linux-qualification-v1"
        );
        let specs = tooling.executor_specs(|executor| executor.identity.clone())?;
        assert_eq!(specs[0], "x86_64-linux=aos-x86_64-linux-qualification-v1");

        let other = tempfile::tempdir()?;
        assert_ne!(
            tooling.digest()?,
            ToolingEnvironment::from_closure(other.path())?.digest()?
        );
        Ok(())
    }

    #[test]
    fn rejects_malformed_executor_directories() -> Result<()> {
        let root = tempfile::tempdir()?;
        assert!(
            ToolingEnvironment::from_closure(root.path())?
                .executor_specs(|executor| executor.identity.clone())
                .is_err()
        );

        write_executor(root.path(), "riscv64-linux", "identity")?;
        assert!(ToolingEnvironment::from_closure(root.path()).is_err());
        fs::remove_dir_all(root.path().join(EXECUTORS_DIRECTORY))?;

        write_executor(root.path(), "x86_64-linux", "")?;
        assert!(ToolingEnvironment::from_closure(root.path()).is_err());
        Ok(())
    }
}
