# Phase 5: Core Commands

## Goal

Implement the primary user-facing commands: install, remove, update (wired in
Phase 2), upgrade, rollback, hold, clean, and gc. After this phase, the core
`apm` workflow is fully functional end-to-end.

## Prerequisites

- Phase 2 complete (registry sync — `apm update` already works)
- Phase 3 complete (store operations)
- Phase 4 complete (profile management)

## Design References

- [cli.md](../cli.md) — Command specs, install steps 1-13, remove steps
- [store.md](../store.md) — Install/remove flows, autoremove, rollback
- [examples.md](../examples.md) — Expected output format for all commands
- [convergence.md](../convergence.md) — Autoremove logic

---

## Chunk 5A: Install Pipeline

### Files to Create

**`src/package/resolve.rs`** (~150 lines)

Registry-scoped closure resolution.

```rust
/// Resolve a package and its full closure from a registry.
///
/// All deps resolve from the SAME registry as the parent package.
///
/// 1. Look up package name in the highest-priority registry (or --registry)
/// 2. Walk `references` transitively within that registry
/// 3. Return the complete closure as an ordered list
pub fn resolve_closure(
    registries: &RegistrySet,
    name: &str,
    registry_filter: Option<&str>,
) -> Result<ResolvedClosure>;

pub struct ResolvedClosure {
    pub registry_name: String,
    pub root: PackageMeta,
    pub closure: Vec<PackageMeta>,    // all transitive deps (including root)
    pub closure_size: u64,            // total download size
}

/// Resolve multiple packages, merging their closures.
/// Deduplicates by store path hash.
pub fn resolve_multiple(
    registries: &RegistrySet,
    names: &[String],
    registry_filter: Option<&str>,
) -> Result<Vec<ResolvedClosure>>;
```

**`src/package/install.rs`** (~350 lines)

Full install pipeline matching cli.md steps 1-13.

```rust
/// Run `apm install <packages>`.
pub async fn run(
    config: &ApmConfig,
    packages: &[String],
    registry_filter: Option<&str>,
    dry_run: bool,
    yes: bool,
    printer: &Printer,
) -> Result<()> {
    // Step 1: Load registries from cache
    let registries = load_registries(config)?;

    // Step 2: Resolve each package and its closure
    let closures = resolve_multiple(&registries, packages, registry_filter)?;

    // Step 3: Compute full closure (all transitive deps, deduplicated)
    let all_paths = collect_closure_paths(&closures);

    // Step 4: Diff against local store — identify missing paths
    let nix_store = NixStore::open(db_path)?;
    let missing = filter_missing(&nix_store, &all_paths);

    // Step 5: Display transaction summary
    print_install_summary(&closures, &missing, printer)?;

    // Step 6: Prompt for confirmation (unless -y)
    if !yes && !dry_run {
        confirm(printer)?;
    }
    if dry_run { return Ok(()); }

    // Step 7: Download missing NARs from mirrors
    let downloads = download_nars(client, &download_requests, cache_dir, parallel, printer).await?;

    // Step 8: Verify download hashes
    for dl in &downloads {
        verify_download_hash(&dl.local_path, &dl.download_hash)?;
    }

    // Step 9: Verify NAR hashes (decompress + hash)
    for dl in &downloads {
        verify_nar_hash(&dl.local_path, &dl.nar_hash)?;
    }

    // Step 10: Import NARs into Nix store
    for dl in &downloads {
        import_nar(&dl.local_path, &dl.store_path).await?;
    }

    // Step 11: Verify store paths
    // (import_nar already checks, but explicit for clarity)

    // Step 12: Open profile + create new generation
    let profile = Profile::open(config.scope)?;
    let prev_gen = profile.current_generation()?;
    let new_gen = profile.new_generation()?;

    // Copy roots from previous generation
    if let Some(prev) = &prev_gen {
        copy_roots(prev, &new_gen)?;
    }

    // Add new GC roots
    create_gc_roots(&new_gen.path, &all_metas)?;

    // Step 13: Write per-path metadata
    for (meta, explicit) in &install_metas {
        write_meta(&profile, &hash, &InstalledMeta { ... })?;
    }

    // Step 14: Build FHS merge tree
    let merge_result = build_fhs_tree(&new_gen, &all_packages, printer)?;

    // Step 15: Atomic switch
    profile.switch_to(&new_gen)?;

    // Step 16: Report
    print_install_complete(packages.len(), printer);
}

/// Display the install transaction summary.
fn print_install_summary(
    closures: &[ResolvedClosure],
    missing: &[String],
    printer: &Printer,
) -> Result<()>;

/// Prompt for Y/n confirmation.
fn confirm(printer: &Printer) -> Result<()>;

/// Copy all roots (usr/ and src/) from one generation to another.
fn copy_roots(from: &Generation, to: &Generation) -> Result<()>;
```

### Tests

- `resolve_closure` returns curl + all transitive deps from same registry.
- `resolve_closure` with `--registry` picks from specified registry.
- Closure deduplication: shared deps appear once.
- Missing path detection skips already-present store paths.
- Install summary shows NEW packages, already-present packages, download size.
- Dry run prints summary and exits without modifying anything.
- New generation inherits roots from previous generation.
- `confirm()` returns `UserCancelled` on "n".
- Full install flow with mock HTTP server (end-to-end).

### Acceptance Criteria

- `apm install curl` resolves, downloads, verifies, imports, and installs.
- All deps marked `apm.explicit = false`; explicitly named packages marked `true`.
- New generation has correct GC roots, FHS tree, and metadata.
- `current` symlink points to new generation after install.
- Output matches examples.md install format.
- Exit code 0 on success, 100 on user cancel.

---

## Chunk 5B: Remove & Autoremove

### Files to Create

**`src/package/remove.rs`** (~250 lines)

Package removal and orphan cleanup.

```rust
/// Run `apm remove <packages>`.
pub async fn run(
    config: &ApmConfig,
    packages: &[String],
    auto_remove: bool,
    dry_run: bool,
    yes: bool,
    printer: &Printer,
) -> Result<()> {
    let profile = Profile::open(config.scope)?;

    // 1. Verify all named packages are installed
    let to_remove = find_installed(&profile, packages)?;

    // 2. Check reverse dependencies (warn if other packages depend on these)
    let rdeps = find_reverse_deps(&profile, &to_remove)?;
    if !rdeps.is_empty() {
        print_rdep_warning(&rdeps, printer);
    }

    // 3. Find orphans (if --autoremove)
    let orphans = if auto_remove {
        find_orphans(&profile)?
    } else {
        let potential_orphans = find_potential_orphans(&profile, &to_remove)?;
        if !potential_orphans.is_empty() {
            printer.info(&format!(
                "{} packages are now orphaned. Use 'apm autoremove' to remove them.",
                potential_orphans.len()
            ));
        }
        vec![]
    };

    // 4. Display removal summary
    print_remove_summary(&to_remove, &orphans, printer);

    // 5. Confirm
    if !yes && !dry_run { confirm(printer)?; }
    if dry_run { return Ok(()); }

    // 6. Create new generation without removed packages
    let new_gen = profile.new_generation()?;
    copy_roots_except(&profile.current_generation()?, &new_gen, &remove_hashes)?;

    // 7. Delete metadata for removed packages
    for hash in &remove_hashes {
        delete_meta(&profile, hash)?;
    }

    // 8. Rebuild FHS tree
    let all_packages = remaining_packages(&profile, &new_gen)?;
    build_fhs_tree(&new_gen, &all_packages, printer)?;

    // 9. Switch to new generation
    profile.switch_to(&new_gen)?;

    print_remove_complete(to_remove.len(), orphans.len(), printer);
}

/// Run `apm autoremove`.
pub async fn autoremove(
    config: &ApmConfig,
    dry_run: bool,
    yes: bool,
    printer: &Printer,
) -> Result<()>;

/// Find orphaned packages: explicit=false and not in any explicit package's closure.
///
/// Walks the Nix store reference graph (via `nix-store -qR`) for each
/// explicit package to build the set of reachable paths. Any auto-installed
/// package not in this set is an orphan.
fn find_orphans(profile: &Profile) -> Result<Vec<InstalledMeta>>;

/// Copy all roots from one generation to another, EXCEPT the given hashes.
fn copy_roots_except(
    from: &Generation,
    to: &Generation,
    exclude: &HashSet<String>,
) -> Result<()>;
```

### Tests

- Remove a single package creates a new generation without it.
- Remove warns about reverse dependencies.
- Autoremove finds and removes orphaned auto-installed packages.
- Cannot remove a package that isn't installed → `PackageNotFound`.
- Dry run shows summary without changes.
- FHS tree is rebuilt after removal (no dangling symlinks).
- Metadata is deleted for removed packages.

### Acceptance Criteria

- `apm remove curl` creates new generation without curl, keeps deps.
- `apm autoremove` removes unreachable auto-installed packages.
- `apm remove --autoremove curl` combines both.
- Output matches examples.md remove format.

---

## Chunk 5C: Upgrade

### Files to Create

**`src/package/upgrade.rs`** (~200 lines)

Package upgrade by diffing installed vs registry.

```rust
/// Run `apm upgrade [packages]`.
pub async fn run(
    config: &ApmConfig,
    packages: &[String],        // empty = upgrade all
    exclude: &[String],
    dry_run: bool,
    yes: bool,
    printer: &Printer,
) -> Result<()> {
    let profile = Profile::open(config.scope)?;
    let registries = load_registries(config)?;

    // 1. Find upgradable packages
    let upgradable = find_upgradable(&profile, &registries, packages)?;

    // 2. Filter out held and excluded packages
    let (to_upgrade, held_back) = filter_held_and_excluded(
        &profile, &upgradable, exclude,
    )?;

    if to_upgrade.is_empty() {
        printer.info("All packages are up to date.");
        return Ok(());
    }

    // 3. Display upgrade summary (including held-back)
    print_upgrade_summary(&to_upgrade, &held_back, printer);

    // 4. Confirm
    if !yes && !dry_run { confirm(printer)?; }
    if dry_run { return Ok(()); }

    // 5. Resolve new closures for upgraded packages
    // 6. Download, verify, import new NARs
    // 7. Create new generation with updated roots
    // 8. Update metadata
    // 9. Rebuild FHS tree, switch

    print_upgrade_complete(to_upgrade.len(), printer);
}

/// Compare installed packages against registry to find upgradable ones.
///
/// A package is upgradable if the registry has a different store_path hash
/// for the same package name (indicating a new version or rebuild).
fn find_upgradable(
    profile: &Profile,
    registries: &RegistrySet,
    filter: &[String],
) -> Result<Vec<UpgradeCandidate>>;

pub struct UpgradeCandidate {
    pub name: String,
    pub old_version: String,
    pub new_version: String,
    pub old_hash: String,
    pub new_meta: PackageMeta,
    pub registry: String,
}
```

### Tests

- Detects when registry has newer version than installed.
- Held packages are listed as "held back" but not upgraded.
- `--exclude` skips named packages.
- Empty upgrade set prints "all up to date".
- Specific packages: `apm upgrade curl` only upgrades curl.
- New closure is resolved from same registry as original install.

### Acceptance Criteria

- `apm upgrade` upgrades all installed packages to registry versions.
- `apm upgrade curl` upgrades only curl.
- Held packages are reported but skipped.
- Output matches examples.md upgrade format.
- New generation has updated roots and metadata.

---

## Chunk 5D: Rollback, Hold, Clean, GC

### Files to Create

**`src/package/rollback.rs`** (~100 lines)

```rust
/// Run `apm rollback [--generation=N]`.
pub async fn run(
    config: &ApmConfig,
    generation: Option<u32>,
    dry_run: bool,
    printer: &Printer,
) -> Result<()> {
    let profile = Profile::open(config.scope)?;
    let current = profile.current_generation()?.ok_or(/* no gen */)?;
    let target = match generation {
        Some(n) => profile.list_generations()?.into_iter().find(|g| g.number == n),
        None => profile.list_generations()?.into_iter()
            .filter(|g| g.number < current.number)
            .last(),
    }.ok_or(/* target not found */)?;

    // Show diff between current and target generations
    let diff = compute_generation_diff(&current, &target, &profile)?;
    print_rollback_diff(&diff, printer);

    if dry_run { return Ok(()); }

    // Switch to target generation
    profile.switch_to(&target)?;

    // Rebuild meta/ from target generation's roots
    let registries = load_registries(config)?;
    rebuild_meta(&profile, &target, &registries)?;

    printer.success("Profile switched.");
}
```

**`src/package/hold.rs`** (~80 lines)

```rust
/// Run `apm hold <package>`.
pub async fn run_hold(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()>;

/// Run `apm unhold <package>`.
pub async fn run_unhold(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()>;

/// Run `apm held` — list held packages.
pub async fn run_held(config: &ApmConfig, printer: &Printer) -> Result<()>;
```

**`src/package/clean.rs`** (~100 lines)

```rust
/// Run `apm clean [--generations] [--keep=N]`.
pub async fn run(
    config: &ApmConfig,
    generations: bool,
    keep: u32,
    printer: &Printer,
) -> Result<()> {
    if generations {
        // Remove old profile generations (keep latest N)
        let profile = Profile::open(config.scope)?;
        let removed = profile.prune_generations(keep)?;
        printer.info(&format!("Removed {} old generations.", removed.len()));
    } else {
        // Remove cached NAR downloads
        let cache_dir = config.cache_path();
        let freed = clear_nar_cache(&cache_dir)?;
        printer.info(&format!("Cleared NAR cache, freed {}.", format_size(freed)));
    }
}

/// Run `apm gc` — delegate to `aos gc --collect`.
pub async fn run_gc(printer: &Printer) -> Result<()>;
```

### Tests

- Rollback switches `current` to previous generation.
- Rollback with `--generation=N` targets specific generation.
- Rollback rebuilds meta/ from target generation.
- Rollback diff shows added/removed packages.
- Hold sets `apm.held = true` in metadata.
- Unhold sets `apm.held = false`.
- `apm held` lists only held packages.
- Clean removes NAR cache files.
- Clean `--generations` prunes old generations.
- GC delegates to `aos gc --collect`.

### Acceptance Criteria

- `apm rollback` is instantaneous (no downloads, no store mutations).
- Hold/unhold modify metadata atomically.
- Clean frees disk space from caches and old generations.
- All commands respect `--system` scope.

---

## Integration Notes

After Phase 5 is complete:
- Full install/remove/upgrade/rollback lifecycle works end-to-end
- `apm update` (from Phase 2) + `apm install/remove/upgrade` form the core workflow
- Hold/clean/gc provide maintenance operations
- All commands create proper generations, GC roots, metadata, and FHS trees
