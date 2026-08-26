//! The `aos cache list` operation: compare local store and cache contents.
//!
//! For every path in the closure of the requested installables, this
//! reports whether the path is present in the local Nix store, present in
//! the remote cache, both ("synced"), or neither ("missing").

use anyhow::Result;

use aos_core::nar::info as narinfo;
use aos_core::nix::NixCli;
use aos_core::output::Printer;

use crate::backend::CacheBackend;
use crate::resolve::resolve_installables;

/// Lists closure paths with their local-store and cache status.
///
/// Resolves the installables (see [`resolve_installables`]), enumerates
/// the combined closure, and prints one row per store path showing local
/// validity, cache presence, and a combined status (`synced`,
/// `local only`, `cache only`, or `missing`), followed by summary counts.
///
/// Per-path check failures (local validity or cache lookup) are reported
/// as warnings and treated as "not present" rather than aborting the
/// listing.
///
/// # Errors
///
/// Returns an error if installable resolution or closure enumeration
/// fails. A missing installable argument is not an error: a warning is
/// printed and the function returns successfully.
pub async fn run_list(
    printer: &Printer,
    backend: &dyn CacheBackend,
    installables: &[String],
    file: Option<&str>,
    attr: Option<&str>,
    expr: Option<&str>,
    target: Option<&str>,
) -> Result<()> {
    let nix = NixCli::new(0);

    if installables.is_empty() && attr.is_none() && expr.is_none() {
        printer.warning(
            "No installable specified. Provide an installable to check against the cache.",
        );
        return Ok(());
    }

    // Resolve and enumerate closure.
    let store_paths = resolve_installables(&nix, installables, file, attr, expr, target)?;
    let mut all_paths = Vec::new();
    for path in &store_paths {
        let closure = nix.closure(path)?;
        all_paths.extend(closure);
    }
    all_paths.sort();
    all_paths.dedup();

    // Check each path against local store and cache.
    printer.header(&format!(
        "{:<44} {:>10} {:>10} {}",
        "Path", "Local", "Cached", "Status"
    ));

    let mut local_count = 0u64;
    let mut cached_count = 0u64;

    for path in &all_paths {
        let hash = narinfo::store_hash(path);
        let basename = narinfo::basename(path);

        let in_local = match nix.is_valid(path) {
            Ok(v) => v,
            Err(e) => {
                printer.warning(&format!("failed to check local validity of {path}: {e}"));
                false
            }
        };
        let in_cache = match backend.has_narinfo(hash).await {
            Ok(v) => v,
            Err(e) => {
                printer.warning(&format!("failed to check cache for {hash}: {e}"));
                false
            }
        };

        let local_str = if in_local { "yes" } else { "no" };
        let cached_str = if in_cache { "yes" } else { "no" };

        let status = match (in_local, in_cache) {
            (true, true) => "synced",
            (true, false) => "local only",
            (false, true) => "cache only",
            (false, false) => "missing",
        };

        if in_local {
            local_count += 1;
        }
        if in_cache {
            cached_count += 1;
        }

        let display_name = if basename.chars().count() > 42 {
            let truncated: String = basename.chars().take(39).collect();
            format!("{truncated}...")
        } else {
            basename.to_string()
        };

        printer.plain(&format!(
            "{:<44} {:>10} {:>10} {}",
            display_name, local_str, cached_str, status
        ));
    }

    printer.plain("");
    printer.info(&format!(
        "Total: {} paths, {} local, {} cached",
        all_paths.len(),
        local_count,
        cached_count
    ));

    Ok(())
}
