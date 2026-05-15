//! Env-var bindings to propagate to `nix-store` / `nix-build` /
//! `nix-instantiate` subprocesses so they operate on the AOS_ROOT-
//! rooted store rather than the canonical `/nix/store`.
//!
//! Vanilla Nix looks at `NIX_STORE_DIR` and `NIX_STATE_DIR` to locate
//! the store layout (binaries under `<NIX_STORE_DIR>/<hash>-<name>`
//! and the ValidPaths DB under `<NIX_STATE_DIR>/nix/db/db.sqlite`).
//! AOS uses a single `AOS_ROOT` knob with the convention:
//!
//!   `<AOS_ROOT>/store/`         → `NIX_STORE_DIR`
//!   `<AOS_ROOT>/var/nix/`       → `NIX_STATE_DIR`
//!
//! Mirrors `aos_server::aos_root()`'s reading of the same env var, but
//! lives in `aos-core` so the CLI side (`aos-cache`, `aos`) doesn't
//! pull in `aos-server` as a dependency.

/// Env bindings derived from `AOS_ROOT`. Returns an empty `Vec` when
/// `AOS_ROOT` is unset — callers can unconditionally chain
/// `.envs(aos_nix_env())` on a `std::process::Command` without
/// branching on the env-var presence themselves.
pub fn aos_nix_env() -> Vec<(&'static str, String)> {
    let Ok(root) = std::env::var("AOS_ROOT") else {
        return Vec::new();
    };
    let root = root.trim_end_matches('/');
    vec![
        ("NIX_STORE_DIR", format!("{root}/store")),
        ("NIX_STATE_DIR", format!("{root}/var/nix")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // SAFETY: tests in this module set process-global env vars. Cargo
    // runs tests in parallel by default; mutating `AOS_ROOT` here can
    // race with other test threads. The other tests in this crate
    // that touch `AOS_ROOT` live in `nix::runner` (read-only) — they
    // observe whichever value is currently set, which is acceptable
    // for the runner's project-root lookup. If a future test depends
    // on `AOS_ROOT` being unset, we'll need to gate this module with
    // `--test-threads=1` or use the `serial_test` crate.

    #[test]
    fn aos_nix_env_empty_when_unset() {
        // Snapshot whatever is set; restore after.
        let saved = std::env::var("AOS_ROOT").ok();
        // SAFETY: see module-level note on parallelism.
        unsafe {
            std::env::remove_var("AOS_ROOT");
        }
        assert!(aos_nix_env().is_empty());
        if let Some(v) = saved {
            // SAFETY: see module-level note on parallelism.
            unsafe {
                std::env::set_var("AOS_ROOT", v);
            }
        }
    }

    #[test]
    fn aos_nix_env_translates_to_store_and_state_dirs() {
        let saved = std::env::var("AOS_ROOT").ok();
        // SAFETY: see module-level note on parallelism.
        unsafe {
            std::env::set_var("AOS_ROOT", "/var/lib/aos-test");
        }
        let env = aos_nix_env();
        assert_eq!(env.len(), 2);
        assert_eq!(env[0].0, "NIX_STORE_DIR");
        assert_eq!(env[0].1, "/var/lib/aos-test/store");
        assert_eq!(env[1].0, "NIX_STATE_DIR");
        assert_eq!(env[1].1, "/var/lib/aos-test/var/nix");
        // Restore.
        match saved {
            // SAFETY: see module-level note on parallelism.
            Some(v) => unsafe { std::env::set_var("AOS_ROOT", v) },
            None => unsafe { std::env::remove_var("AOS_ROOT") },
        }
    }

    #[test]
    fn aos_nix_env_strips_trailing_slash() {
        let saved = std::env::var("AOS_ROOT").ok();
        // SAFETY: see module-level note on parallelism.
        unsafe {
            std::env::set_var("AOS_ROOT", "/var/lib/aos-test/");
        }
        let env = aos_nix_env();
        assert_eq!(env[0].1, "/var/lib/aos-test/store");
        assert_eq!(env[1].1, "/var/lib/aos-test/var/nix");
        match saved {
            // SAFETY: see module-level note on parallelism.
            Some(v) => unsafe { std::env::set_var("AOS_ROOT", v) },
            None => unsafe { std::env::remove_var("AOS_ROOT") },
        }
    }
}
