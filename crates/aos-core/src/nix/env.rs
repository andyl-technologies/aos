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
    let Ok(root) = std::env::var("AOS_ROOT") else {
        return Vec::new();
    };
    let root = root.trim_end_matches('/');
    let store_dir = std::env::var("AOS_NIX_STORE_DIR").unwrap_or_else(|_| format!("{root}/store"));
    let state_dir =
        std::env::var("AOS_NIX_STATE_DIR").unwrap_or_else(|_| format!("{root}/var/nix"));
    let log_dir =
        std::env::var("AOS_NIX_LOG_DIR").unwrap_or_else(|_| format!("{root}/var/nix/log/nix"));
    vec![
        ("NIX_STORE_DIR", store_dir),
        ("NIX_STATE_DIR", state_dir),
        ("NIX_LOG_DIR", log_dir),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // `AOS_ROOT` is process-global state, and cargo runs tests in
    // parallel within one binary. Splitting the scenarios across
    // separate `#[test]` functions made them race: one test's
    // `set_var("AOS_ROOT", …)` could land between another's
    // `remove_var` and its assertion, so the "unset" case observed a
    // value set by a sibling and failed intermittently. The only
    // race-free way to exercise multiple `AOS_ROOT` values is to drive
    // them sequentially from a single test with one save/restore, so
    // they are consolidated here. The other in-crate reader of
    // `AOS_ROOT` (`nix::runner::find_project_root`, runtime-only) has
    // no test that depends on a particular value, so it tolerates
    // whichever value is transiently set while this test runs.

    #[test]
    fn aos_nix_env_from_root() {
        // Snapshot whatever the ambient environment had; restore at the
        // end so this test leaves `AOS_ROOT` exactly as it found it.
        let saved_root = std::env::var("AOS_ROOT").ok();
        let saved_store_dir = std::env::var("AOS_NIX_STORE_DIR").ok();
        let saved_state_dir = std::env::var("AOS_NIX_STATE_DIR").ok();
        let saved_log_dir = std::env::var("AOS_NIX_LOG_DIR").ok();

        // Unset → empty, so callers can chain `.envs(aos_nix_env())`
        // unconditionally.
        // SAFETY: see module-level note on parallelism.
        unsafe { std::env::remove_var("AOS_ROOT") };
        // SAFETY: see module-level note on parallelism.
        unsafe { std::env::remove_var("AOS_NIX_STORE_DIR") };
        // SAFETY: see module-level note on parallelism.
        unsafe { std::env::remove_var("AOS_NIX_STATE_DIR") };
        // SAFETY: see module-level note on parallelism.
        unsafe { std::env::remove_var("AOS_NIX_LOG_DIR") };
        assert!(aos_nix_env().is_empty());

        // Set → both store and state dirs derived from the root.
        // SAFETY: see module-level note on parallelism.
        unsafe { std::env::set_var("AOS_ROOT", "/var/lib/aos-test") };
        let env = aos_nix_env();
        assert_eq!(env.len(), 3);
        assert_eq!(env[0].0, "NIX_STORE_DIR");
        assert_eq!(env[0].1, "/var/lib/aos-test/store");
        assert_eq!(env[1].0, "NIX_STATE_DIR");
        assert_eq!(env[1].1, "/var/lib/aos-test/var/nix");
        assert_eq!(env[2].0, "NIX_LOG_DIR");
        assert_eq!(env[2].1, "/var/lib/aos-test/var/nix/log/nix");

        // A trailing slash on the root is normalised away.
        // SAFETY: see module-level note on parallelism.
        unsafe { std::env::set_var("AOS_ROOT", "/var/lib/aos-test/") };
        let env = aos_nix_env();
        assert_eq!(env[0].1, "/var/lib/aos-test/store");
        assert_eq!(env[1].1, "/var/lib/aos-test/var/nix");
        assert_eq!(env[2].1, "/var/lib/aos-test/var/nix/log/nix");

        // Explicit store/state/log overrides are respected while AOS_ROOT still
        // provides the default root context for callers that need it.
        // SAFETY: see module-level note on parallelism.
        unsafe { std::env::set_var("AOS_NIX_STORE_DIR", "/shared/aos/store") };
        // SAFETY: see module-level note on parallelism.
        unsafe { std::env::set_var("AOS_NIX_STATE_DIR", "/client/aos/var/nix") };
        // SAFETY: see module-level note on parallelism.
        unsafe { std::env::set_var("AOS_NIX_LOG_DIR", "/client/aos/log/nix") };
        let env = aos_nix_env();
        assert_eq!(env[0].1, "/shared/aos/store");
        assert_eq!(env[1].1, "/client/aos/var/nix");
        assert_eq!(env[2].1, "/client/aos/log/nix");

        // Restore the ambient value.
        match saved_root {
            // SAFETY: see module-level note on parallelism.
            Some(v) => unsafe { std::env::set_var("AOS_ROOT", v) },
            None => unsafe { std::env::remove_var("AOS_ROOT") },
        }
        match saved_store_dir {
            // SAFETY: see module-level note on parallelism.
            Some(v) => unsafe { std::env::set_var("AOS_NIX_STORE_DIR", v) },
            None => unsafe { std::env::remove_var("AOS_NIX_STORE_DIR") },
        }
        match saved_state_dir {
            // SAFETY: see module-level note on parallelism.
            Some(v) => unsafe { std::env::set_var("AOS_NIX_STATE_DIR", v) },
            None => unsafe { std::env::remove_var("AOS_NIX_STATE_DIR") },
        }
        match saved_log_dir {
            // SAFETY: see module-level note on parallelism.
            Some(v) => unsafe { std::env::set_var("AOS_NIX_LOG_DIR", v) },
            None => unsafe { std::env::remove_var("AOS_NIX_LOG_DIR") },
        }
    }
}
