//! Builders for git commands run against apm-managed repositories.
//!
//! Registry clones and cache repositories are apm's data store: their
//! behavior must not change with the host's git configuration. A
//! `~/.gitconfig` that enables `commit.gpgsign`, redirects `core.hooksPath`,
//! or seeds `init.templateDir` would otherwise alter — or break — registry
//! operations. Signing in particular is managed entirely by apm, through
//! inline `-c gpg.format=ssh -c user.signingkey=…` configuration and the
//! committed trust roster.
//!
//! Local object and ref operations therefore run **hermetically**: global
//! and system git configuration are hidden ([`hermetic`]). Network
//! transport — push, pull, fetch — keeps the host environment
//! ([`transport`]): credential helpers, proxies, and `url.<base>.insteadOf`
//! rewrites are host concerns apm must honor.
//!
//! This module is **test-only** (gated by `#[cfg(test)]`): production registry operations
//! moved to libgit2 ([`crate::registry::repo`], [`crate::registry::porcelain`])
//! and never exec `git`. It survives to build hermetic git fixtures in tests,
//! so not every builder here is exercised.
#![allow(dead_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Environment overrides hiding the host's git configuration.
const HERMETIC_ENV: [(&str, &str); 2] = [
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_SYSTEM", "/dev/null"),
];

static SSH_KEYGEN: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Build a git command for local object and ref operations.
///
/// Global and system configuration are hidden; only repo-local
/// configuration and inline `-c` flags apply.
pub(crate) fn hermetic() -> std::process::Command {
    let mut cmd = std::process::Command::new("git");
    cmd.envs(HERMETIC_ENV);
    cmd
}

/// Async variant of [`hermetic`].
// Unused once the apm fetch + pack paths moved to libgit2; retained while the
// apr write-side (registry_ops, lib) still shells out to git.
#[allow(dead_code)]
pub(crate) fn hermetic_async() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("git");
    cmd.envs(HERMETIC_ENV);
    cmd
}

/// Build a git command for network transport (push, pull, fetch).
///
/// Deliberately inherits the host configuration network operations depend on:
/// credential helpers, proxies, and `url.<base>.insteadOf` rewrites. Proxies
/// and rewrites travel through the environment and git config we inherit, but
/// a bare-name credential helper (`helper = manager`, `osxkeychain`, …) is a
/// host binary git resolves through `PATH` — and the `aos`/`apm`/`apr`
/// wrappers have replaced `PATH` with a minimal hermetic tool set, stashing
/// the caller's original value in `AOS_HOST_PATH`. We therefore append
/// `AOS_HOST_PATH` *after* the hermetic entries ([`transport_env_path`]): the
/// AOS-built git, ssh, and friends still win, while host-only helpers become
/// resolvable. Outside the wrappers (`AOS_HOST_PATH` unset) `PATH` is left
/// untouched.
pub(crate) fn transport() -> std::process::Command {
    let mut cmd = std::process::Command::new("git");
    if let Some(path) = transport_env_path() {
        cmd.env("PATH", path);
    }
    cmd
}

/// Async variant of [`transport`].
// Retained while the apr write-side still shells out to git; the apm fetch
// path now uses libgit2 (`registry::repo`), leaving this temporarily unused.
#[allow(dead_code)]
pub(crate) fn transport_async() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("git");
    if let Some(path) = transport_env_path() {
        cmd.env("PATH", path);
    }
    cmd
}

/// Resolve the `PATH` a network-transport command should run with, reading
/// the live process environment.
///
/// Returns `None` when `AOS_HOST_PATH` is unset, signaling that the command
/// should inherit the process `PATH` unchanged.
fn transport_env_path() -> Option<OsString> {
    transport_path(std::env::var_os("PATH"), std::env::var_os("AOS_HOST_PATH"))
}

/// Concatenate the hermetic `PATH` and the caller's host `PATH`, hermetic
/// first, dropping duplicate directories while preserving order.
///
/// `host_path` is the caller's original `PATH` (stashed in `AOS_HOST_PATH` by
/// the wrappers). Returns `None` when it is absent — the command then inherits
/// the process `PATH` rather than reconstructing it — so AOS-built tools keep
/// priority and host-only credential helpers are reachable as a fallback.
fn transport_path(
    hermetic_path: Option<OsString>,
    host_path: Option<OsString>,
) -> Option<OsString> {
    let host_path = host_path?;
    let mut dirs: Vec<PathBuf> = Vec::new();
    for source in [hermetic_path, Some(host_path)].into_iter().flatten() {
        for dir in std::env::split_paths(&source) {
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
    }
    std::env::join_paths(dirs).ok()
}

/// Add a `gpg.ssh.program` override when a working signer was discovered.
///
/// Some non-AOS host environments can execute the AOS-built `git` but the
/// matching AOS-built `ssh-keygen` cannot resolve the caller's uid through
/// host NSS, causing Git SSH signing to fail before it reads the key. The
/// wrapper still keeps host Git configuration hidden; this only points Git's
/// SSH signing/verifying subprocess at a signer that proved it can complete an
/// actual `ssh-keygen -Y sign` operation.
pub(crate) fn add_ssh_program_config(command: &mut std::process::Command) {
    if let Some(path) = ssh_keygen_path() {
        command
            .arg("-c")
            .arg(format!("gpg.ssh.program={}", path.display()));
    }
}

/// Build an `ssh-keygen` command using the same working signer selection.
pub(crate) fn ssh_keygen() -> std::process::Command {
    match ssh_keygen_path() {
        Some(path) => std::process::Command::new(path),
        None => std::process::Command::new("ssh-keygen"),
    }
}

fn ssh_keygen_path() -> Option<&'static Path> {
    SSH_KEYGEN.get_or_init(find_working_ssh_keygen).as_deref()
}

fn find_working_ssh_keygen() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("AOS_GIT_SSH_PROGRAM") {
        candidates.push(PathBuf::from(path));
    }
    for env_var in ["AOS_HOST_PATH", "PATH"] {
        let Some(path) = std::env::var_os(env_var) else {
            continue;
        };
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("ssh-keygen");
            if !candidates.iter().any(|seen| seen == &candidate) {
                candidates.push(candidate);
            }
        }
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.is_file() && ssh_keygen_can_sign(candidate))
}

fn ssh_keygen_can_sign(candidate: &Path) -> bool {
    let Ok(tmp) = tempfile::TempDir::new() else {
        return false;
    };
    let key = tmp.path().join("key");
    let Ok(keygen) = std::process::Command::new(candidate)
        .env_remove("LD_LIBRARY_PATH")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "aos-registry", "-f"])
        .arg(&key)
        .output()
    else {
        return false;
    };
    if !keygen.status.success() {
        return false;
    }

    let payload = tmp.path().join("payload");
    if std::fs::write(&payload, b"aos-registry").is_err() {
        return false;
    }

    std::process::Command::new(candidate)
        .env_remove("LD_LIBRARY_PATH")
        .arg("-Y")
        .arg("sign")
        .arg("-f")
        .arg(&key)
        .arg("-n")
        .arg("git")
        .arg(&payload)
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Read a value from the host's *global* git configuration.
///
/// This is the one deliberate host-configuration read: it captures the
/// maintainer's identity into a freshly created registry clone so that
/// commit attribution survives the hermetic invocations above. Returns
/// `None` when the key is unset (or git itself is unavailable).
pub(crate) fn host_config_value(key: &str) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["config", "--global", "--get", key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn assert_hermetic_envs<'a>(envs: impl Iterator<Item = (&'a OsStr, Option<&'a OsStr>)>) {
        let envs: Vec<_> = envs.collect();
        for (key, value) in HERMETIC_ENV {
            assert!(
                envs.contains(&(OsStr::new(key), Some(OsStr::new(value)))),
                "expected {key}={value} in {envs:?}"
            );
        }
    }

    #[test]
    fn hermetic_hides_host_config() {
        assert_hermetic_envs(hermetic().get_envs());
        assert_hermetic_envs(hermetic_async().as_std().get_envs());
    }

    #[test]
    fn transport_does_not_hide_host_config() {
        // Unlike `hermetic()`, transport must never neutralize the host git
        // config network operations depend on (credential helpers, proxies,
        // URL rewrites). It may set `PATH`, but never the config-hiding vars.
        for (key, _) in HERMETIC_ENV {
            assert!(
                transport().get_envs().all(|(k, _)| k != OsStr::new(key)),
                "transport must not set {key}"
            );
            assert!(
                transport_async()
                    .as_std()
                    .get_envs()
                    .all(|(k, _)| k != OsStr::new(key)),
                "transport_async must not set {key}"
            );
        }
    }

    #[test]
    fn transport_path_appends_host_after_hermetic() {
        let hermetic = std::env::join_paths(["/aos/bin", "/aos/git/bin"]).unwrap();
        let host = std::env::join_paths(["/usr/bin", "/aos/bin"]).unwrap();
        let combined = transport_path(Some(hermetic), Some(host)).expect("host path present");
        let dirs: Vec<_> = std::env::split_paths(&combined).collect();
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/aos/bin"),
                PathBuf::from("/aos/git/bin"),
                PathBuf::from("/usr/bin"),
            ],
            "hermetic entries first, host-only entries appended, duplicates dropped"
        );
    }

    #[test]
    fn transport_path_without_host_inherits() {
        let hermetic = std::env::join_paths(["/aos/bin"]).unwrap();
        assert!(transport_path(Some(hermetic), None).is_none());
    }
}
