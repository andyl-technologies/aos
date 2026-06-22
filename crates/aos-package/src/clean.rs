//! `apm clean` and `apm gc` — reclaim disk space.
//!
//! Two complementary mechanisms:
//!
//! - **NAR cache cleaning** (`apm clean`): deletes downloaded NAR archives
//!   from the cache directory. These are pure download artifacts — removing
//!   them never affects installed packages, only future re-download cost.
//! - **Generation pruning** (`apm clean --generations --keep=N`): removes
//!   old profile generations beyond the latest `N`, always preserving the
//!   current generation. Pruned generations can no longer be rolled back to.
//! - **Garbage collection** (`apm gc`): delegates to `nix-store --gc` to
//!   delete store paths unreachable from any GC root (profile generations
//!   are roots, so pruning generations first frees more).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::config::ApmConfig;
use super::profile::Profile;
use crate::types::ProfileScope;
use aos_core::nix::aos_nix_env;
use aos_core::output::{OutputMode, Printer};

/// Outcome of clearing the NAR download cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NarCacheCleanResult {
    freed_bytes: u64,
    files_removed: usize,
}

/// Run `apm clean [--generations] [--keep=N]`.
///
/// Without `--generations`: clears the NAR download cache.
/// With `--generations`: prunes old profile generations, keeping the
/// latest `keep` (and always keeping the current generation).
///
/// # Errors
///
/// Returns an error if the profile cannot be opened or its generations
/// listed/pruned (e.g. the profile lock is held by another process), or if
/// the NAR cache directory or one of its files cannot be read or removed.
pub async fn run(
    config: &ApmConfig,
    generations: bool,
    keep: u32,
    printer: &Printer,
) -> Result<()> {
    let json_mode = printer.mode() == OutputMode::Json;
    if generations {
        let profile = Profile::open_readonly(config.scope);
        let all_generations = profile.list_generations()?;
        let current_generation = profile.current_generation()?.map(|g| g.number);
        let generations_before: Vec<u32> = all_generations
            .iter()
            .map(|generation| generation.number)
            .collect();

        if all_generations.len() <= keep as usize {
            if json_mode {
                printer.json(&clean_generations_json(
                    "current",
                    keep,
                    current_generation,
                    &generations_before,
                    &generations_before,
                    &[],
                ));
            }
            printer.info("No old generations to remove.");
            return Ok(());
        }

        let cutoff = all_generations.len() - keep as usize;
        let has_prunable_generation = all_generations[..cutoff]
            .iter()
            .any(|generation| Some(generation.number) != current_generation);

        if !has_prunable_generation {
            if json_mode {
                printer.json(&clean_generations_json(
                    "current",
                    keep,
                    current_generation,
                    &generations_before,
                    &generations_before,
                    &[],
                ));
            }
            printer.info("No old generations to remove.");
            return Ok(());
        }

        let profile = Profile::open(config.scope)?;
        let removed = profile.prune_generations(keep)?;
        let generations_after: Vec<u32> = profile
            .list_generations()?
            .iter()
            .map(|generation| generation.number)
            .collect();
        let removed_generations: Vec<u32> =
            removed.iter().map(|generation| generation.number).collect();
        if removed.is_empty() {
            if json_mode {
                printer.json(&clean_generations_json(
                    "current",
                    keep,
                    current_generation,
                    &generations_before,
                    &generations_after,
                    &removed_generations,
                ));
            }
            printer.info("No old generations to remove.");
        } else {
            // Best-effort: reclaim each pruned generation's /etc overlay upper
            // from the /run/etc tmpfs (system scope on a live host only). The
            // generation is already gone and tmpfs clears any remainder at
            // reboot, so a failure here is cosmetic — warn (to stderr) rather
            // than fail the command.
            if let Err(error) =
                prune_runtime_uppers(config.scope, &removed_generations, Path::new(RUN_ETC_DIR))
            {
                printer.warning(&format!(
                    "could not reclaim runtime /etc upper(s): {error:#}"
                ));
            }

            if json_mode {
                printer.json(&clean_generations_json(
                    "cleaned",
                    keep,
                    current_generation,
                    &generations_before,
                    &generations_after,
                    &removed_generations,
                ));
            }
            printer.success(&format!("Removed {} old generation(s).", removed.len()));
        }
    } else {
        let cache_dir = config.nar_cache_path();
        let cleaned = clear_nar_cache(&cache_dir)?;
        if json_mode {
            printer.json(&serde_json::json!({
                "action": "clean",
                "mode": "cache",
                "status": if cleaned.files_removed == 0 { "current" } else { "cleaned" },
                "cache_dir": cache_dir.to_string_lossy(),
                "files_removed": cleaned.files_removed,
                "freed_bytes": cleaned.freed_bytes,
                "freed": format_size(cleaned.freed_bytes),
            }));
        }
        printer.success(&format!(
            "Cleared NAR cache, freed {}.",
            format_size(cleaned.freed_bytes)
        ));
    }

    Ok(())
}

/// Run `apm gc`.
///
/// Prunes orphaned writable-layer registry overlays (see
/// [`prune_orphaned_overlays`]), then delegates to the system's
/// `nix-store --gc` to reclaim unreachable store paths.
///
/// # Errors
///
/// Returns an error if a `/var` overlay cannot be removed, or if `nix-store`
/// cannot be spawned or exits with a non-zero status.
pub async fn run_gc(scope: ProfileScope, printer: &Printer) -> Result<()> {
    run_gc_impl(scope, printer, true).await
}

/// Run automatic GC after another mutating command.
///
/// Text output is preserved for normal mode, but JSON mode stays silent so the
/// parent command remains a single JSON document.
///
/// # Errors
///
/// Returns an error if a `/var` overlay cannot be removed, or if `nix-store`
/// cannot be spawned or exits with a non-zero status.
pub async fn run_gc_after_mutation(scope: ProfileScope, printer: &Printer) -> Result<()> {
    run_gc_impl(scope, printer, false).await
}

async fn run_gc_impl(scope: ProfileScope, printer: &Printer, emit_json: bool) -> Result<()> {
    let pruned = prune_orphaned_overlays(scope)?;
    if !pruned.is_empty() && printer.mode() != OutputMode::Json {
        printer.info(&format!(
            "Pruned {} orphaned registry overlay(s): {}",
            pruned.len(),
            pruned.join(", ")
        ));
    }

    printer.info("Running garbage collection...");

    let nix_env = aos_nix_env();
    let output = tokio::process::Command::new("nix-store")
        .envs(nix_env.iter().cloned())
        .arg("--gc")
        .output()
        .await
        .context("failed to run nix-store --gc")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nix-store --gc failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if emit_json && printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "gc",
            "status": "completed",
            "success": true,
            "nix_store_dir": nix_env_value(&nix_env, "NIX_STORE_DIR"),
            "nix_state_dir": nix_env_value(&nix_env, "NIX_STATE_DIR"),
            "overlays_pruned": pruned,
            "stdout": stdout.trim_end(),
            "stderr": stderr.trim_end(),
        }));
        return Ok(());
    }

    if !stdout.is_empty() {
        printer.plain(stdout.trim_end());
    }

    printer.success("Garbage collection complete.");
    Ok(())
}

/// Prune orphaned writable-layer registry overlays for `scope`.
///
/// A `registries.d/<stem>.toml` in the writable layer
/// (`/var/lib/apm/config` for system scope) that carries no `url` — and whose
/// stem is no longer defined by any read-only seed below it — is a dead
/// override left behind when its seed was blanked. Such an orphan can wedge
/// anti-rollback by resurrecting a stale `floor`/`last_commit` if the registry
/// is later re-added, so it is removed here. Self-sufficient definitions (the
/// overlay itself carries a `url`) and live overlays (a seed still defines the
/// stem) are kept.
///
/// Returns the stems that were pruned, in sorted order.
///
/// # Errors
///
/// Returns an error if the writable directory cannot be read or an orphaned
/// overlay cannot be removed.
pub(crate) fn prune_orphaned_overlays(scope: ProfileScope) -> Result<Vec<String>> {
    let layers = scope.config_layers();
    let writable_dir = scope.writable_config_dir().join("registries.d");
    // Everything below the writable layer (the last entry) is a read-only seed.
    let seed_dirs: Vec<PathBuf> = layers[..layers.len().saturating_sub(1)]
        .iter()
        .map(|layer| layer.join("registries.d"))
        .collect();
    prune_orphaned_overlays_in(&writable_dir, &seed_dirs)
}

/// Prune orphaned overlays in an explicit `writable_dir`, treating each
/// directory in `seed_dirs` as a read-only seed.
///
/// This is the directory-level core of [`prune_orphaned_overlays`], split out
/// so it can be unit-tested without the process-global path resolvers.
fn prune_orphaned_overlays_in(writable_dir: &Path, seed_dirs: &[PathBuf]) -> Result<Vec<String>> {
    if !writable_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<_> = std::fs::read_dir(writable_dir)
        .with_context(|| format!("reading {}", writable_dir.display()))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "toml"))
        .collect();
    entries.sort_by_key(|entry| entry.file_name());

    let mut pruned = Vec::new();
    for entry in entries {
        let path = entry.path();
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        // A self-sufficient definition (its own url) is never an orphan.
        if crate::config::registry_file_has_url(&path) {
            continue;
        }
        // A lower seed layer still defines the stem → the overlay is live.
        let seeded = seed_dirs
            .iter()
            .any(|dir| crate::config::registry_file_has_url(&dir.join(format!("{stem}.toml"))));
        if seeded {
            continue;
        }
        std::fs::remove_file(&path)
            .with_context(|| format!("removing orphaned overlay {}", path.display()))?;
        pruned.push(stem.to_string());
    }

    Ok(pruned)
}

/// Look up a single variable in the AOS nix environment slice.
fn nix_env_value(env: &[(&'static str, String)], key: &str) -> Option<String> {
    env.iter()
        .find_map(|(name, value)| (*name == key).then(|| value.clone()))
}

/// Clear the NAR cache directory and return the number of bytes freed.
///
/// Removes all regular files in the directory. Subdirectories are left
/// intact (the directory structure itself is cheap).
fn clear_nar_cache(cache_dir: &Path) -> Result<NarCacheCleanResult> {
    let entries = match std::fs::read_dir(cache_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(NarCacheCleanResult {
                freed_bytes: 0,
                files_removed: 0,
            });
        }
        Err(e) => {
            return Err(e)
                .with_context(|| format!("reading NAR cache directory {}", cache_dir.display()));
        }
    };

    let mut freed: u64 = 0;
    let mut files_removed = 0;

    for entry in entries {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_file() {
            freed += meta.len();
            files_removed += 1;
            std::fs::remove_file(entry.path())
                .with_context(|| format!("removing cached file {}", entry.path().display()))?;
        }
    }

    Ok(NarCacheCleanResult {
        freed_bytes: freed,
        files_removed,
    })
}

/// Format a byte count as a human-readable size string.
fn format_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;

    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Build the JSON document emitted for `apm clean --generations`.
fn clean_generations_json(
    status: &str,
    keep: u32,
    current_generation: Option<u32>,
    generations_before: &[u32],
    generations_after: &[u32],
    removed_generations: &[u32],
) -> serde_json::Value {
    serde_json::json!({
        "action": "clean",
        "mode": "generations",
        "status": status,
        "keep": keep,
        "current_generation": current_generation,
        "generations_before": generations_before,
        "generations_after": generations_after,
        "generations_before_count": generations_before.len(),
        "generations_after_count": generations_after.len(),
        "removed_generations": removed_generations,
        "removed": removed_generations.len(),
    })
}

/// Absolute path of the boot-time tmpfs that holds per-generation `/etc`
/// overlay state on a live system (populated by `etc-overlay-setup.service`
/// and the `activate` script).
const RUN_ETC_DIR: &str = "/run/etc";

/// Reclaim the `/etc` overlay uppers left in `/run/etc` by pruned generations.
///
/// On a live system each generation has one `upper-<N>/` directory under the
/// `/run/etc` tmpfs holding that generation's runtime `/etc` writes. Those
/// uppers are deliberately preserved across generation switches so a rollback
/// can restore them, so pruning a generation is the moment its upper becomes
/// unreachable and can be removed. This is purely cosmetic reclamation: the
/// tmpfs clears any remainder at reboot.
///
/// Only system-scope generations have an `/etc` overlay, so for any other
/// scope this is a no-op. Generations that predate the current boot were never
/// activated this boot and have no `upper-<N>` directory; that absence is
/// expected, not an error. `run_etc` is the `/run/etc` base, injectable so
/// tests can point it at a scratch directory.
///
/// Returns the generation numbers whose upper was actually removed.
///
/// # Errors
///
/// Returns an error if an existing `upper-<N>/` directory cannot be removed
/// (for example, a permissions failure). A missing directory is not an error.
fn prune_runtime_uppers(scope: ProfileScope, removed: &[u32], run_etc: &Path) -> Result<Vec<u32>> {
    if scope != ProfileScope::System {
        return Ok(Vec::new());
    }
    let mut reclaimed = Vec::new();
    for &number in removed {
        let upper = run_etc.join(format!("upper-{number}"));
        match std::fs::remove_dir_all(&upper) {
            Ok(()) => reclaimed.push(number),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("removing runtime /etc upper {}", upper.display()));
            }
        }
    }
    Ok(reclaimed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn prune_removes_orphan_keeps_seeded_and_self_sufficient() {
        let tmp = TempDir::new().unwrap();
        let seed = tmp.path().join("etc/registries.d");
        let writable = tmp.path().join("var/registries.d");
        std::fs::create_dir_all(&seed).unwrap();
        std::fs::create_dir_all(&writable).unwrap();

        // Orphan: a pure state overlay whose seed is gone → pruned.
        std::fs::write(
            writable.join("orphan.toml"),
            "[registry.state]\nlast_commit = \"x\"\n",
        )
        .unwrap();
        // Live overlay: a pure state overlay, but a seed still defines it → kept.
        std::fs::write(
            writable.join("live.toml"),
            "[registry.state]\nlast_commit = \"y\"\n",
        )
        .unwrap();
        std::fs::write(
            seed.join("live.toml"),
            "[registry]\nname = \"live\"\nurl = \"https://example.com/live\"\n",
        )
        .unwrap();
        // Self-sufficient: the overlay itself carries a url → kept.
        std::fs::write(
            writable.join("operator.toml"),
            "[registry]\nname = \"operator\"\nurl = \"https://example.com/op\"\n",
        )
        .unwrap();

        let pruned = prune_orphaned_overlays_in(&writable, &[seed]).unwrap();
        assert_eq!(pruned, vec!["orphan".to_string()]);
        assert!(!writable.join("orphan.toml").exists());
        assert!(writable.join("live.toml").exists());
        assert!(writable.join("operator.toml").exists());
    }

    #[test]
    fn prune_is_noop_when_writable_dir_absent() {
        let tmp = TempDir::new().unwrap();
        let writable = tmp.path().join("does/not/exist");
        let pruned = prune_orphaned_overlays_in(&writable, &[]).unwrap();
        assert!(pruned.is_empty());
    }

    #[test]
    fn prune_runtime_uppers_removes_present_and_tolerates_absent() {
        let tmp = TempDir::new().unwrap();
        let run_etc = tmp.path();
        // gen 1 and gen 3 left a populated upper; gen 2 has none (e.g. it
        // predates this boot and was never activated since).
        for n in [1u32, 3] {
            let dir = run_etc.join(format!("upper-{n}/dir"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("runtime-write.conf"), b"x").unwrap();
        }

        let reclaimed = prune_runtime_uppers(ProfileScope::System, &[1, 2, 3], run_etc).unwrap();

        // The missing gen-2 upper is tolerated, not an error; only the
        // present ones are reported reclaimed.
        assert_eq!(reclaimed, vec![1, 3]);
        assert!(!run_etc.join("upper-1").exists());
        assert!(!run_etc.join("upper-2").exists());
        assert!(!run_etc.join("upper-3").exists());
    }

    #[test]
    fn prune_runtime_uppers_skips_non_system_scope() {
        let tmp = TempDir::new().unwrap();
        let run_etc = tmp.path();
        std::fs::create_dir_all(run_etc.join("upper-1/dir")).unwrap();

        let reclaimed = prune_runtime_uppers(ProfileScope::User, &[1], run_etc).unwrap();

        // User-scope generations have no /etc overlay, so the upper is left
        // untouched.
        assert!(reclaimed.is_empty());
        assert!(run_etc.join("upper-1").exists());
    }

    #[test]
    fn clear_nar_cache_removes_files_and_returns_size() {
        let tmp = TempDir::new().unwrap();

        // Create some fake cached NAR files.
        let file_a = tmp.path().join("abc123.nar.zst");
        let file_b = tmp.path().join("def456.nar.zst");
        std::fs::write(&file_a, vec![0u8; 1024]).unwrap();
        std::fs::write(&file_b, vec![0u8; 2048]).unwrap();

        let cleaned = clear_nar_cache(tmp.path()).unwrap();
        assert_eq!(cleaned.freed_bytes, 3072);
        assert_eq!(cleaned.files_removed, 2);

        // Files should be gone.
        assert!(!file_a.exists());
        assert!(!file_b.exists());
    }

    #[test]
    fn clear_nar_cache_empty_dir_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let cleaned = clear_nar_cache(tmp.path()).unwrap();
        assert_eq!(cleaned.freed_bytes, 0);
        assert_eq!(cleaned.files_removed, 0);
    }

    #[test]
    fn clear_nar_cache_nonexistent_dir_returns_zero() {
        let cleaned = clear_nar_cache(Path::new("/tmp/nonexistent-apm-test-dir")).unwrap();
        assert_eq!(cleaned.freed_bytes, 0);
        assert_eq!(cleaned.files_removed, 0);
    }

    #[test]
    fn format_size_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
    }

    #[test]
    fn format_size_kib() {
        assert_eq!(format_size(1024), "1.0 KiB");
        assert_eq!(format_size(1536), "1.5 KiB");
    }

    #[test]
    fn format_size_mib() {
        assert_eq!(format_size(1048576), "1.0 MiB");
        assert_eq!(format_size(10 * 1048576), "10.0 MiB");
    }

    #[test]
    fn format_size_gib() {
        assert_eq!(format_size(1073741824), "1.0 GiB");
    }
}
