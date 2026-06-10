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

/// Environment overrides hiding the host's git configuration.
const HERMETIC_ENV: [(&str, &str); 2] = [
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_SYSTEM", "/dev/null"),
];

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
pub(crate) fn hermetic_async() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("git");
    cmd.envs(HERMETIC_ENV);
    cmd
}

/// Build a git command for network transport (push, pull, fetch).
///
/// Deliberately inherits the host configuration: credential helpers,
/// proxies, and URL rewrites must keep working.
pub(crate) fn transport() -> std::process::Command {
    std::process::Command::new("git")
}

/// Async variant of [`transport`].
pub(crate) fn transport_async() -> tokio::process::Command {
    tokio::process::Command::new("git")
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
    fn transport_inherits_host_config() {
        assert_eq!(transport().get_envs().count(), 0);
        assert_eq!(transport_async().as_std().get_envs().count(), 0);
    }
}
