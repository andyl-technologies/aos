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
//! - **Garbage collection** (`apm gc`): delegates to `nix-store --gc` under
//!   the global system-switch lock, deleting store paths unreachable from any
//!   GC root (profile generations are roots, so pruning generations first
//!   frees more).

use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

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

/// Result of pruning one package-generation profile.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageGenerationPruneResult {
    current: Option<u32>,
    before: Vec<u32>,
    after: Vec<u32>,
    removed: Vec<u32>,
}

/// Result of pruning the RFC-0011 configuration-generation profile.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigGenerationPruneResult {
    current: u32,
    before: Vec<u32>,
    after: Vec<u32>,
    removed: Vec<u32>,
    runtime_upper_warning: Option<String>,
}

/// Durable intent used to finish generation-directory cleanup after a crash.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigPruneJournal {
    schema: String,
    before: Vec<u32>,
    removed: Vec<u32>,
    state_after: crate::types::ConfigGenerationState,
}

const CONFIG_PRUNE_JOURNAL: &str = ".prune-intent.json";
const CONFIG_PRUNE_SCHEMA: &str = "aos.config-prune/v1";

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
        // Configuration activation and its profile publication use this same
        // lock. Holding it while pruning both system profiles gives operators
        // one coherent `--system --generations` operation and prevents a
        // rollback target from disappearing underneath activation.
        let _switch_guard = if config.scope == ProfileScope::System {
            let path = crate::config_eval::activation::ActivateConfigParams::default().switch_lock;
            Some(crate::config_eval::activation::acquire_switch_lock_pub(
                &path,
            )?)
        } else {
            None
        };

        let package = prune_package_generations(config.scope, keep)?;
        let configuration = if config.scope == ProfileScope::System {
            let profile = config.scope.profile_path();
            let image_profile = profile
                .parent()
                .context("system profile has no profiles parent")?
                .join("image");
            let state = crate::sysroot::recover_generation_state_pub(&profile)?;
            Some(prune_config_generations_with(
                &profile,
                Path::new(RUN_ETC_DIR),
                state,
                keep,
                |state| reconcile_config_baselib_roots(&image_profile, state),
                remove_config_generation_dir,
            )?)
        } else {
            None
        };

        let removed_count = package.removed.len()
            + configuration
                .as_ref()
                .map_or(0, |result| result.removed.len());
        if let Some(warning) = configuration
            .as_ref()
            .and_then(|result| result.runtime_upper_warning.as_deref())
        {
            printer.warning(warning);
        }
        if json_mode {
            printer.json(&clean_generations_json(
                if removed_count == 0 {
                    "current"
                } else {
                    "cleaned"
                },
                keep,
                &package,
                configuration.as_ref(),
            ));
        }
        if removed_count == 0 {
            printer.info("No old generations to remove.");
        } else {
            printer.success(&format!("Removed {removed_count} old generation(s)."));
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

/// Prunes ordinary package-profile generations while preserving the current
/// generation even when it falls outside the latest `keep` window.
fn prune_package_generations(
    scope: ProfileScope,
    keep: u32,
) -> Result<PackageGenerationPruneResult> {
    let readonly = Profile::open_readonly(scope);
    let all = readonly.list_generations()?;
    let current = readonly
        .current_generation()?
        .map(|generation| generation.number);
    let before = all
        .iter()
        .map(|generation| generation.number)
        .collect::<Vec<_>>();
    let cutoff = all.len().saturating_sub(keep as usize);
    let should_prune = all[..cutoff]
        .iter()
        .any(|generation| Some(generation.number) != current);
    if !should_prune {
        return Ok(PackageGenerationPruneResult {
            current,
            before: before.clone(),
            after: before,
            removed: Vec::new(),
        });
    }

    let profile = Profile::open(scope)?;
    let removed = profile.prune_generations(keep)?;
    let after = profile
        .list_generations()?
        .iter()
        .map(|generation| generation.number)
        .collect();
    Ok(PackageGenerationPruneResult {
        current,
        before,
        after,
        removed: removed.iter().map(|generation| generation.number).collect(),
    })
}

/// Completes an interrupted prune or starts and durably commits a new one.
///
/// The state record is published before any `gen-N/` directory is removed.
/// Thus every crash point either leaves the old rollback set intact, or leaves
/// a conservative orphan directory whose `cfg/` and `cfgsrc/` roots are
/// released when this journal is replayed. The active generation is always
/// retained independently of the latest-generation window.
fn prune_config_generations_with<R, D>(
    profile: &Path,
    run_etc: &Path,
    state: crate::types::ConfigGenerationState,
    keep: u32,
    mut reconcile: R,
    mut remove_generation: D,
) -> Result<ConfigGenerationPruneResult>
where
    R: FnMut(&crate::types::ConfigGenerationState) -> Result<()>,
    D: FnMut(&Path) -> Result<()>,
{
    let journal_path = profile.join(CONFIG_PRUNE_JOURNAL);
    let journal = if journal_path.is_file() {
        serde_json::from_slice::<ConfigPruneJournal>(&std::fs::read(&journal_path)?)
            .with_context(|| format!("parsing config prune journal {}", journal_path.display()))?
    } else {
        let mut generations = state.generations.clone();
        generations.sort_by_key(|generation| generation.number);
        if state.current != 0
            && !generations
                .iter()
                .any(|generation| generation.number == state.current)
        {
            bail!(
                "configuration state names missing current generation {}",
                state.current
            );
        }
        let before = generations
            .iter()
            .map(|generation| generation.number)
            .collect::<Vec<_>>();
        let cutoff = generations.len().saturating_sub(keep as usize);
        let removed = generations[..cutoff]
            .iter()
            .filter(|generation| generation.number != state.current)
            .map(|generation| generation.number)
            .collect::<Vec<_>>();
        if removed.is_empty() {
            return Ok(ConfigGenerationPruneResult {
                current: state.current,
                before: before.clone(),
                after: before,
                removed,
                runtime_upper_warning: None,
            });
        }
        let mut state_after = state;
        state_after
            .generations
            .retain(|generation| !removed.contains(&generation.number));
        let journal = ConfigPruneJournal {
            schema: CONFIG_PRUNE_SCHEMA.to_string(),
            before,
            removed,
            state_after,
        };
        write_atomic_durable(&journal_path, &serde_json::to_vec_pretty(&journal)?)?;
        journal
    };

    if journal.schema != CONFIG_PRUNE_SCHEMA {
        bail!(
            "unsupported config prune journal schema {:?}",
            journal.schema
        );
    }
    let before = journal
        .before
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let removed = journal
        .removed
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let retained = journal
        .state_after
        .generations
        .iter()
        .map(|generation| generation.number)
        .collect::<std::collections::BTreeSet<_>>();
    if before.len() != journal.before.len()
        || removed.len() != journal.removed.len()
        || retained.len() != journal.state_after.generations.len()
        || !removed.is_subset(&before)
        || !retained.is_subset(&before)
        || !removed.is_disjoint(&retained)
        || before.len() != removed.len() + retained.len()
    {
        bail!("config prune journal has inconsistent generation sets");
    }
    if journal.state_after.current != 0
        && !journal
            .state_after
            .generations
            .iter()
            .any(|generation| generation.number == journal.state_after.current)
    {
        bail!("config prune journal would remove the current generation");
    }
    crate::sysroot::save_generation_state_pub(profile, &journal.state_after)?;
    for generation in &journal.removed {
        let path = profile.join(format!("gen-{generation}"));
        if path.symlink_metadata().is_ok() {
            remove_generation(&path)?;
            sync_directory(profile)?;
        }
    }
    reconcile(&journal.state_after)?;
    remove_file_durable(&journal_path)?;
    // Runtime uppers are ephemeral caches and disappear on reboot. Their
    // cleanup must never block activation recovery after the durable roots and
    // state are consistent, so retain the successful prune and report a
    // warning to an interactive cleaner instead.
    let runtime_upper_warning =
        prune_runtime_uppers(ProfileScope::System, &journal.removed, run_etc)
            .err()
            .map(|error| format!("could not reclaim runtime /etc upper(s): {error:#}"));

    let after = journal
        .state_after
        .generations
        .iter()
        .map(|generation| generation.number)
        .collect();
    Ok(ConfigGenerationPruneResult {
        current: journal.state_after.current,
        before: journal.before,
        after,
        removed: journal.removed,
        runtime_upper_warning,
    })
}

fn reconcile_config_baselib_roots(
    image_profile: &Path,
    state: &crate::types::ConfigGenerationState,
) -> Result<()> {
    let image_state = image_profile.join("state.json");
    if !image_state.is_file() {
        return Ok(());
    }
    let images = crate::sysroot::load_image_generation_state_pub(image_profile)?;
    crate::store::reconcile_baselib_gc_roots(image_profile, &images, state)
}

/// Finishes an interrupted configuration prune before activation reads state.
///
/// Callers must already hold the global switch lock. This hook prevents a new
/// activation from appending to state while a stale prune journal still names
/// an older `state_after` snapshot that recovery could otherwise republish.
///
/// # Errors
///
/// Returns an error when the journal is malformed, its generation sets are
/// inconsistent, durable state or directory cleanup fails, or required
/// retained base-library roots cannot be reconciled.
pub(crate) fn recover_config_prune_pub(profile: &Path) -> Result<()> {
    recover_config_prune_at(profile, Path::new(RUN_ETC_DIR))
}

fn recover_config_prune_at(profile: &Path, run_etc: &Path) -> Result<()> {
    if !profile.join(CONFIG_PRUNE_JOURNAL).is_file() {
        return Ok(());
    }
    let image_profile = profile
        .parent()
        .context("system profile has no profiles parent")?
        .join("image");
    let state = crate::sysroot::load_generation_state_pub(profile)?;
    prune_config_generations_with(
        profile,
        run_etc,
        state,
        0,
        |state| reconcile_config_baselib_roots(&image_profile, state),
        remove_config_generation_dir,
    )?;
    Ok(())
}

fn remove_config_generation_dir(path: &Path) -> Result<()> {
    std::fs::remove_dir_all(path)
        .with_context(|| format!("removing configuration generation {}", path.display()))
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
/// cannot be spawned or exits with a non-zero status. Garbage collection also
/// fails closed when a system switch owns the global switch lock.
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
/// cannot be spawned or exits with a non-zero status. Garbage collection also
/// fails closed when a system switch owns the global switch lock.
pub async fn run_gc_after_mutation(scope: ProfileScope, printer: &Printer) -> Result<()> {
    run_gc_impl(scope, printer, false).await
}

async fn run_gc_impl(scope: ProfileScope, printer: &Printer, emit_json: bool) -> Result<()> {
    let switch_lock = crate::config_eval::activation::ActivateConfigParams::default().switch_lock;
    with_global_gc_lock(&switch_lock, || run_gc_locked(scope, printer, emit_json)).await
}

/// Prunes stale overlays and runs the collector while the caller owns the
/// global switch lock.
async fn run_gc_locked(scope: ProfileScope, printer: &Printer, emit_json: bool) -> Result<()> {
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

/// Runs one global store-GC operation while owning the system-switch lock.
///
/// Lock acquisition is deliberately non-blocking: callers fail closed instead
/// of waiting behind an activation that may itself depend on their parent
/// operation. The guard remains live across the asynchronous child process so
/// activation cannot publish or replace GC roots until collection completes.
async fn with_global_gc_lock<T, F, Fut>(switch_lock: &Path, run_gc: F) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let _switch_guard = crate::config_eval::activation::acquire_switch_lock_pub(switch_lock)
        .context("serializing global garbage collection with system activation")?;
    run_gc().await
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
    package: &PackageGenerationPruneResult,
    configuration: Option<&ConfigGenerationPruneResult>,
) -> serde_json::Value {
    serde_json::json!({
        "action": "clean",
        "mode": "generations",
        "status": status,
        "keep": keep,
        // Retain the original package-profile fields for stable porcelain.
        "current_generation": package.current,
        "generations_before": package.before,
        "generations_after": package.after,
        "generations_before_count": package.before.len(),
        "generations_after_count": package.after.len(),
        "removed_generations": package.removed,
        "removed": package.removed.len(),
        // `--system` additionally reports the independent RFC-0011 config
        // axis, whose generation numbers need not align with package gens.
        "configuration": configuration.map(|result| serde_json::json!({
            "current_generation": result.current,
            "generations_before": result.before,
            "generations_after": result.after,
            "generations_before_count": result.before.len(),
            "generations_after_count": result.after.len(),
            "removed_generations": result.removed,
            "removed": result.removed.len(),
        })),
    })
}

fn write_atomic_durable(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("{} has no UTF-8 file name", path.display()))?;
    let temporary = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("opening {}", temporary.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| format!("publishing {}", path.display()))?;
    sync_directory(parent)
}

fn remove_file_durable(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    match std::fs::remove_file(path) {
        Ok(()) => sync_directory(parent),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    let directory = File::open(path)
        .with_context(|| format!("opening directory {} for sync", path.display()))?;
    directory
        .sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
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
    use crate::types::{ConfigGeneration, ConfigGenerationState};
    use std::cell::Cell;
    use tempfile::TempDir;

    fn config_generation(number: u32) -> ConfigGeneration {
        ConfigGeneration {
            number,
            image_gen_parent: if number < 4 { 1 } else { 2 },
            module_abi_pinned: if number < 4 { 1 } else { 2 },
            manifest_hash: format!("sha256:manifest-{number}"),
            config_module_closure: format!("/nix/store/module-{number}"),
            config_module_paths: vec![format!("/nix/store/module-{number}")],
            config_module_packages: vec!["fixture".into()],
            host_nix_ref: format!("/nix/store/host-{number}"),
            host_nix_commit: None,
            facts_hash: format!("sha256:facts-{number}"),
            facts_ref: format!("/nix/store/facts-{number}"),
            base_lib_ref: format!("/nix/store/base-{}", if number < 4 { 1 } else { 2 }),
            evaluator_ref: format!("/nix/store/evaluator-{}", if number < 4 { 1 } else { 2 }),
            created_at: format!("2026-08-{number:02}T00:00:00Z"),
        }
    }

    fn config_state(current: u32) -> ConfigGenerationState {
        ConfigGenerationState {
            current,
            next: 6,
            generations: (1..=5).map(config_generation).collect(),
        }
    }

    fn write_config_profile(profile: &Path, state: &ConfigGenerationState) {
        std::fs::create_dir_all(profile).unwrap();
        crate::sysroot::save_generation_state_pub(profile, state).unwrap();
        for generation in &state.generations {
            let directory = profile.join(format!("gen-{}", generation.number));
            std::fs::create_dir_all(directory.join("cfg")).unwrap();
            std::fs::create_dir_all(directory.join("cfgsrc")).unwrap();
        }
        std::os::unix::fs::symlink(format!("gen-{}", state.current), profile.join("current"))
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn global_gc_fails_closed_during_switch_without_running() {
        let temporary = TempDir::new().unwrap();
        let switch_lock = temporary.path().join("switch.lock");
        let switch_guard =
            crate::config_eval::activation::acquire_switch_lock_pub(&switch_lock).unwrap();
        let ran = Cell::new(false);

        let error = with_global_gc_lock(&switch_lock, || async {
            ran.set(true);
            Ok(())
        })
        .await
        .unwrap_err();

        assert!(
            !ran.get(),
            "GC must not start without owning the switch lock"
        );
        assert!(
            format!("{error:#}").contains("another system switch is active"),
            "unexpected contention error: {error:#}"
        );
        drop(switch_guard);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn global_gc_holds_switch_lock_until_successful_completion() {
        let temporary = TempDir::new().unwrap();
        let switch_lock = temporary.path().join("switch.lock");
        let observed_contention = Cell::new(false);

        let result = with_global_gc_lock(&switch_lock, || async {
            observed_contention.set(
                crate::config_eval::activation::acquire_switch_lock_pub(&switch_lock).is_err(),
            );
            Ok(17_u8)
        })
        .await
        .unwrap();

        assert_eq!(result, 17);
        assert!(
            observed_contention.get(),
            "the switch lock must remain held for the whole GC operation"
        );
        let guard = crate::config_eval::activation::acquire_switch_lock_pub(&switch_lock).unwrap();
        drop(guard);
    }

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
    fn config_prune_keeps_latest_window_and_current_outside_it() {
        let tmp = TempDir::new().unwrap();
        let profile = tmp.path().join("profiles/system");
        let run_etc = tmp.path().join("run/etc");
        let state = config_state(2);
        write_config_profile(&profile, &state);
        std::fs::create_dir_all(run_etc.join("upper-1/dir")).unwrap();
        std::fs::create_dir_all(run_etc.join("upper-3/dir")).unwrap();

        let mut reconciled = Vec::new();
        let result = prune_config_generations_with(
            &profile,
            &run_etc,
            state,
            2,
            |retained| {
                reconciled = retained
                    .generations
                    .iter()
                    .map(|generation| generation.number)
                    .collect();
                Ok(())
            },
            remove_config_generation_dir,
        )
        .unwrap();

        assert_eq!(result.before, vec![1, 2, 3, 4, 5]);
        assert_eq!(result.after, vec![2, 4, 5]);
        assert_eq!(result.removed, vec![1, 3]);
        assert_eq!(reconciled, vec![2, 4, 5]);
        assert!(profile.join("gen-2/cfgsrc").is_dir());
        assert!(profile.join("gen-4/cfg").is_dir());
        assert!(profile.join("gen-5/cfgsrc").is_dir());
        assert!(!profile.join("gen-1").exists());
        assert!(!profile.join("gen-3").exists());
        assert!(!run_etc.join("upper-1").exists());
        assert!(!run_etc.join("upper-3").exists());
        assert_eq!(
            std::fs::read_link(profile.join("current")).unwrap(),
            PathBuf::from("gen-2")
        );
        assert!(!profile.join(CONFIG_PRUNE_JOURNAL).exists());
    }

    #[test]
    fn config_prune_recovers_after_directory_removal_failure() {
        let tmp = TempDir::new().unwrap();
        let profile = tmp.path().join("profiles/system");
        let run_etc = tmp.path().join("run/etc");
        let state = config_state(5);
        write_config_profile(&profile, &state);
        let mut removals = 0usize;

        let error = prune_config_generations_with(
            &profile,
            &run_etc,
            state,
            2,
            |_| Ok(()),
            |path| {
                removals += 1;
                if removals == 2 {
                    bail!("injected removal failure");
                }
                remove_config_generation_dir(path)
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("injected removal failure"));
        assert!(profile.join(CONFIG_PRUNE_JOURNAL).is_file());
        // State publication precedes deletion, so the failed generation is no
        // longer advertised as a rollback target even while its roots remain.
        let published = crate::sysroot::load_generation_state_pub(&profile).unwrap();
        assert_eq!(
            published
                .generations
                .iter()
                .map(|generation| generation.number)
                .collect::<Vec<_>>(),
            vec![4, 5]
        );
        assert!(profile.join("gen-2/cfgsrc").is_dir());

        // The activation-side loader owns the same switch lock in production
        // and must finish the journal before admitting a new state mutation.
        recover_config_prune_at(&profile, &run_etc).unwrap();
        let recovered = crate::sysroot::load_generation_state_pub(&profile).unwrap();
        assert_eq!(
            recovered
                .generations
                .iter()
                .map(|generation| generation.number)
                .collect::<Vec<_>>(),
            vec![4, 5]
        );
        for generation in 1..=3 {
            assert!(!profile.join(format!("gen-{generation}")).exists());
        }
        assert!(!profile.join(CONFIG_PRUNE_JOURNAL).exists());
    }

    #[test]
    fn config_prune_recovers_after_baselib_reconciliation_failure() {
        let tmp = TempDir::new().unwrap();
        let profile = tmp.path().join("profiles/system");
        let run_etc = tmp.path().join("run/etc");
        let state = config_state(5);
        write_config_profile(&profile, &state);

        let error = prune_config_generations_with(
            &profile,
            &run_etc,
            state,
            3,
            |_| bail!("injected base-library reconciliation failure"),
            remove_config_generation_dir,
        )
        .unwrap_err();
        assert!(error.to_string().contains("base-library reconciliation"));
        assert!(profile.join(CONFIG_PRUNE_JOURNAL).is_file());

        let published = crate::sysroot::load_generation_state_pub(&profile).unwrap();
        let recovered = prune_config_generations_with(
            &profile,
            &run_etc,
            published,
            3,
            |_| Ok(()),
            remove_config_generation_dir,
        )
        .unwrap();
        assert_eq!(recovered.removed, vec![1, 2]);
        assert_eq!(recovered.after, vec![3, 4, 5]);
        assert!(!profile.join(CONFIG_PRUNE_JOURNAL).exists());
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
