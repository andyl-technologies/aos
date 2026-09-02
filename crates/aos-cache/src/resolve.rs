//! Installable resolution: CLI arguments to concrete store paths.
//!
//! Cache operations accept several spellings for "the thing to act on":
//! bare package names (resolved as `pkgs.<name>` per the AOS convention),
//! explicit `-A` attributes, raw `--expr` Nix expressions, and direct
//! store paths. [`resolve_installables`] normalises all of them to built
//! store paths, building through the Nix CLI where necessary.

use std::path::Path;

use anyhow::Result;

use aos_core::nix::NixCli;

/// Resolves installable arguments to built store paths.
///
/// The selectors are tried in priority order:
///
/// 1. `expr` — instantiated and realised as a raw Nix expression.
/// 2. `attr` — built from `file` (default `./default.nix`).
/// 3. `installables` — each entry is either a direct store path (used
///    as-is; see `is_direct_store_path` below) or a bare package name
///    built as `pkgs.<name>` from `file`.
///
/// When `target` is present, file/attribute builds receive it as the
/// top-level `crossSystem` string argument. Raw expressions must carry their
/// own import arguments and therefore cannot be combined with `target`.
///
/// # Errors
///
/// Returns an error if a build or instantiation fails, or if no
/// installables were specified at all.
pub fn resolve_installables(
    nix: &NixCli,
    installables: &[String],
    file: Option<&str>,
    attr: Option<&str>,
    expr: Option<&str>,
    target: Option<&str>,
) -> Result<Vec<String>> {
    // Raw expression.
    if let Some(expr) = expr {
        if target.is_some() {
            anyhow::bail!(
                "--target cannot be combined with --expr; pass crossSystem in the expression"
            );
        }
        let drv = nix.instantiate_expr(expr)?;
        let path = nix.realise(&drv.to_string_lossy())?;
        return Ok(vec![path]);
    }

    // Explicit -A attr.
    if let Some(attr) = attr {
        let file_path = Path::new(file.unwrap_or("./default.nix"));
        let path = match target {
            Some(target) => nix.build_for_target(file_path, attr, target)?,
            None => nix.build(file_path, attr)?,
        };
        return Ok(vec![path.to_string_lossy().to_string()]);
    }

    let mut paths = Vec::new();
    let file_path = Path::new(file.unwrap_or("./default.nix"));

    for installable in installables {
        if is_direct_store_path(installable) {
            paths.push(installable.clone());
            continue;
        }

        // Bare name -> pkgs.<name> (AOS convention).
        let attr = format!("pkgs.{installable}");
        let path = match target {
            Some(target) => nix.build_for_target(file_path, &attr, target)?,
            None => nix.build(file_path, &attr)?,
        };
        paths.push(path.to_string_lossy().to_string());
    }

    if paths.is_empty() {
        anyhow::bail!("no installables specified");
    }

    Ok(paths)
}

/// Decide whether an installable string should be treated as a direct
/// store path rather than a bare attribute name to resolve through
/// `pkgs.<name>`.
///
/// Two acceptance shapes, both Nix-store-shaped:
///
/// - The canonical `/nix/store/<hash>-<name>` prefix.
/// - `<aos_root()>/store/<hash>-<name>`, where `aos_root()` mirrors
///   `aos_server::aos_root()`'s resolution (`AOS_ROOT` env var, default
///   `/var/lib/aos`). An AOS host that re-roots its Nix store still has
///   a valid store layout; pushes from that layout are legitimate. The
///   test harnesses also use this — `tests/fleet/apm-e2e.nix` exports
///   `AOS_ROOT=/var/lib/aos-registry-server/store-root` and fabricates
///   paths under `$AOS_ROOT/store/`.
///
/// We deliberately do NOT accept arbitrary absolute paths. A NAR pushed
/// to a binary cache is identified by its store-path hash; the receiver
/// re-materialises it under its own store. A path outside any store
/// layout has no hash-based identity and `nix-store --import` would
/// reject it on the server. Treating arbitrary absolute paths as direct
/// pushes would silently accept obviously-broken inputs.
fn is_direct_store_path(installable: &str) -> bool {
    is_direct_store_path_in_root(installable, &resolve_aos_root())
}

/// Resolve the AOS store root. Mirrors `aos_server::aos_root()`.
fn resolve_aos_root() -> String {
    std::env::var("AOS_ROOT").unwrap_or_else(|_| "/var/lib/aos".to_string())
}

/// Pure predicate suitable for testing — takes the AOS root explicitly
/// so unit tests don't have to mutate process env (which is global and
/// order-dependent under cargo's parallel test runner).
fn is_direct_store_path_in_root(installable: &str, aos_root: &str) -> bool {
    if installable.starts_with("/nix/store/") {
        return true;
    }
    let store_prefix = format!("{}/store/", aos_root.trim_end_matches('/'));
    installable.starts_with(&store_prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_AOS_ROOT: &str = "/var/lib/aos";
    const TEST_AOS_ROOT: &str = "/var/lib/aos-registry-server/store-root";

    #[test]
    fn recognises_canonical_nix_store() {
        // Default-rooted host: /nix/store paths are always accepted.
        assert!(is_direct_store_path_in_root(
            "/nix/store/abcd-pkg-1.0",
            DEFAULT_AOS_ROOT,
        ));
        // Even on a re-rooted host (AOS_ROOT set), /nix/store still
        // works — a host may host both layouts.
        assert!(is_direct_store_path_in_root(
            "/nix/store/abcd-pkg-1.0",
            TEST_AOS_ROOT,
        ));
    }

    #[test]
    fn recognises_aos_root_rooted_store() {
        // The fleet test's path shape. With AOS_ROOT pointing at the
        // server's store root, paths under <AOS_ROOT>/store/ resolve
        // as direct.
        assert!(is_direct_store_path_in_root(
            "/var/lib/aos-registry-server/store-root/store/aaaa-testpkg-1.0",
            TEST_AOS_ROOT,
        ));
        // Default AOS_ROOT path also accepted on a default-rooted host.
        assert!(is_direct_store_path_in_root(
            "/var/lib/aos/store/abcd-pkg-1.0",
            DEFAULT_AOS_ROOT,
        ));
    }

    #[test]
    fn rejects_paths_under_a_different_aos_root() {
        // A path under one AOS_ROOT does NOT resolve when a different
        // AOS_ROOT is active — pushes are tied to the active store.
        assert!(!is_direct_store_path_in_root(
            "/var/lib/aos-registry-server/store-root/store/aaaa-testpkg-1.0",
            DEFAULT_AOS_ROOT,
        ));
    }

    #[test]
    fn rejects_bare_names() {
        // Bare names go through `pkgs.<name>` resolution.
        assert!(!is_direct_store_path_in_root("hello", DEFAULT_AOS_ROOT));
        assert!(!is_direct_store_path_in_root("aos", TEST_AOS_ROOT));
    }

    #[test]
    fn rejects_arbitrary_absolute_paths() {
        // /tmp, /home/user/work/etc are not store paths under any
        // store layout. Must NOT be accepted as direct pushes; would
        // silently accept inputs the server can't actually import.
        assert!(!is_direct_store_path_in_root("/tmp", DEFAULT_AOS_ROOT));
        assert!(!is_direct_store_path_in_root(
            "/home/user/build/result",
            DEFAULT_AOS_ROOT,
        ));
        assert!(!is_direct_store_path_in_root("/", DEFAULT_AOS_ROOT));
    }

    #[test]
    fn handles_trailing_slash_in_aos_root() {
        // Defensive: AOS_ROOT may or may not have a trailing slash.
        assert!(is_direct_store_path_in_root(
            "/var/lib/aos/store/abcd-pkg",
            "/var/lib/aos/",
        ));
    }
}
