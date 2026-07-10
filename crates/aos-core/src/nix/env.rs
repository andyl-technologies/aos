//! Env-var bindings to propagate to `nix-store` / `nix-build` /
//! `nix-instantiate` subprocesses so they operate on the AOS_ROOT-
//! rooted store rather than the canonical `/nix/store`.
//!
//! Vanilla Nix looks at `NIX_STORE_DIR`, `NIX_STATE_DIR`, and `NIX_LOG_DIR` to
//! locate the store layout (binaries under `<NIX_STORE_DIR>/<hash>-<name>`,
//! the ValidPaths DB under `<NIX_STATE_DIR>/nix/db/db.sqlite`, and build logs
//! under `<NIX_LOG_DIR>`).
//! AOS uses a single `AOS_ROOT` knob with the convention:
//!
//! ```text
//! <AOS_ROOT>/store/      -> NIX_STORE_DIR
//! <AOS_ROOT>/var/nix/    -> NIX_STATE_DIR
//! <AOS_ROOT>/var/nix/log/nix -> NIX_LOG_DIR
//! ```
//!
//! Tests and advanced tooling may override any derived value with
//! `AOS_NIX_STORE_DIR`, `AOS_NIX_STATE_DIR`, or `AOS_NIX_LOG_DIR`. This is
//! useful when a client and server need separate ValidPaths databases for the
//! same store directory.
//!
//! Mirrors `aos_server::aos_root()`'s reading of the same env var, but
//! lives in `aos-core` so the CLI side (`aos-cache`, `aos`) doesn't
//! pull in `aos-server` as a dependency.

use std::process::Command;

/// Returns the Nix store/state env bindings derived from `AOS_ROOT`.
///
/// Produces `NIX_STORE_DIR`, `NIX_STATE_DIR`, and `NIX_LOG_DIR` pairs pointing
/// at `<AOS_ROOT>/store`, `<AOS_ROOT>/var/nix`, and
/// `<AOS_ROOT>/var/nix/log/nix` (a trailing slash on the root is normalised
/// away). Values can be overridden explicitly with `AOS_NIX_STORE_DIR`,
/// `AOS_NIX_STATE_DIR`, or `AOS_NIX_LOG_DIR`.
///
/// Returns an empty `Vec` when `AOS_ROOT` is unset — callers can
/// unconditionally chain `.envs(aos_nix_env())` on a
/// `std::process::Command` without branching on the env-var presence
/// themselves.
pub fn aos_nix_env() -> Vec<(&'static str, String)> {
    aos_nix_env_with(|key| std::env::var(key).ok())
}

fn aos_nix_env_with(mut lookup: impl FnMut(&str) -> Option<String>) -> Vec<(&'static str, String)> {
    let Some(root) = lookup("AOS_ROOT") else {
        return Vec::new();
    };
    let root = root.trim_end_matches('/');
    let store_dir = lookup("AOS_NIX_STORE_DIR").unwrap_or_else(|| format!("{root}/store"));
    let state_dir = lookup("AOS_NIX_STATE_DIR").unwrap_or_else(|| format!("{root}/var/nix"));
    let log_dir = lookup("AOS_NIX_LOG_DIR").unwrap_or_else(|| format!("{root}/var/nix/log/nix"));
    vec![
        ("NIX_STORE_DIR", store_dir),
        ("NIX_STATE_DIR", state_dir),
        ("NIX_LOG_DIR", log_dir),
    ]
}

/// Resolves a real-Nix `program` name to the binary that should run it.
///
/// When `AOS_NIX_ORACLE` points at a `nix-instantiate` binary, sibling tools
/// (`nix-instantiate`, `nix-store`, `nix-build`, …) are resolved from the same
/// directory so the whole real-Nix toolchain comes from one pinned
/// distribution. This is what makes the acceptance gate's C++ oracle honor the
/// pinned conformance version (e.g. 2.24.12) instead of silently using whatever
/// `nix-instantiate` happens to be first on `PATH` (which produces version-drift
/// divergences, e.g. nix 2.34 stripping `__impure = false` from fixed-output
/// derivation environments where 2.24 keeps it). Falls back to the bare program
/// name (PATH lookup) when the variable is unset or its directory lacks the
/// requested tool.
fn resolve_nix_program(program: &str) -> std::ffi::OsString {
    if let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") {
        if let Some(dir) = std::path::Path::new(&oracle).parent() {
            let candidate = dir.join(program);
            if candidate.is_file() {
                return candidate.into_os_string();
            }
        }
    }
    program.into()
}

/// Creates a real-Nix subprocess command with AOS store env bindings applied.
///
/// Private evaluator-control flags are removed so evaluator selection and
/// canary verification never leak into C++ Nix subprocesses. `AOS_ROOT`-derived
/// store bindings are then applied through [`aos_nix_env`]. The program is
/// resolved through `resolve_nix_program` so `AOS_NIX_ORACLE` pins the oracle
/// nix distribution.
pub fn aos_nix_command(program: &str) -> Command {
    let mut command = Command::new(resolve_nix_program(program));
    command
        .env_remove("AOS_NIX_NATIVE")
        .env_remove("AOS_NIX_NATIVE_VERIFY")
        .envs(aos_nix_env());
    command
}

/// Creates a Tokio real-Nix subprocess command with AOS store env bindings.
///
/// This is the async equivalent of [`aos_nix_command`].
pub fn aos_tokio_nix_command(program: &str) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(resolve_nix_program(program));
    command
        .env_remove("AOS_NIX_NATIVE")
        .env_remove("AOS_NIX_NATIVE_VERIFY")
        .envs(aos_nix_env());
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aos_nix_env_from_root() {
        // Unset → empty, so callers can chain `.envs(aos_nix_env())`
        // unconditionally.
        assert!(aos_nix_env_with(|_| None).is_empty());
        let command = aos_nix_command("nix-store");
        assert!(
            matches!(
                command.get_envs().find(|(key, _)| *key == "AOS_NIX_NATIVE"),
                Some((_, None))
            ),
            "AOS_NIX_NATIVE should be explicitly removed from real-Nix commands"
        );
        assert!(
            matches!(
                command
                    .get_envs()
                    .find(|(key, _)| *key == "AOS_NIX_NATIVE_VERIFY"),
                Some((_, None))
            ),
            "AOS_NIX_NATIVE_VERIFY should be explicitly removed from real-Nix commands"
        );

        // Set → both store and state dirs derived from the root.
        let env =
            aos_nix_env_with(|key| (key == "AOS_ROOT").then(|| String::from("/var/lib/aos-test")));
        assert_eq!(env.len(), 3);
        assert_eq!(env[0].0, "NIX_STORE_DIR");
        assert_eq!(env[0].1, "/var/lib/aos-test/store");
        assert_eq!(env[1].0, "NIX_STATE_DIR");
        assert_eq!(env[1].1, "/var/lib/aos-test/var/nix");
        assert_eq!(env[2].0, "NIX_LOG_DIR");
        assert_eq!(env[2].1, "/var/lib/aos-test/var/nix/log/nix");

        // A trailing slash on the root is normalised away.
        let env =
            aos_nix_env_with(|key| (key == "AOS_ROOT").then(|| String::from("/var/lib/aos-test/")));
        assert_eq!(env[0].1, "/var/lib/aos-test/store");
        assert_eq!(env[1].1, "/var/lib/aos-test/var/nix");
        assert_eq!(env[2].1, "/var/lib/aos-test/var/nix/log/nix");

        // Explicit store/state/log overrides are respected while AOS_ROOT still
        // provides the default root context for callers that need it.
        let env = aos_nix_env_with(|key| {
            match key {
                "AOS_ROOT" => Some("/var/lib/aos-test"),
                "AOS_NIX_STORE_DIR" => Some("/shared/aos/store"),
                "AOS_NIX_STATE_DIR" => Some("/client/aos/var/nix"),
                "AOS_NIX_LOG_DIR" => Some("/client/aos/log/nix"),
                _ => None,
            }
            .map(String::from)
        });
        assert_eq!(env[0].1, "/shared/aos/store");
        assert_eq!(env[1].1, "/client/aos/var/nix");
        assert_eq!(env[2].1, "/client/aos/log/nix");
    }
}
