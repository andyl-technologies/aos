# Phase 4: Profile Management

## Goal

Implement the generation-based profile system with FHS symlink merging and
per-path metadata. After this phase, APM can create new profile generations,
build merged symlink trees (bin/, lib/, sbin/, share/, etc.), atomically switch
the `current` symlink, and track installed package metadata.

## Prerequisites

- Phase 3 complete (store import, GC roots)

## Design References

- [store.md](../store.md) — Profile structure, generation lifecycle
- [convergence.md](../convergence.md) — Profile directory layout
- [integration.md](../integration.md) — FHS merge, PATH ordering, man pages
- [cli.md](../cli.md) — Rollback behavior

---

## Chunk 4A: Generation Lifecycle

### Files to Create

**`src/package/profile/mod.rs`** (~250 lines)

Profile and generation management.

```rust
pub mod merge;
pub mod meta;

/// A profile (system or per-user).
pub struct Profile {
    pub path: PathBuf,            // /var/lib/profiles/system/ or per-user/$USER/
    pub scope: ProfileScope,
}

/// A single generation within a profile.
pub struct Generation {
    pub number: u32,
    pub path: PathBuf,            // profile_path/gen-N/
}

/// Profile state (from state.json).
pub struct ProfileState {
    pub current_generation: u32,
    pub next_generation: u32,
}

impl Profile {
    /// Open or initialize a profile directory.
    ///
    /// Creates the directory structure if it doesn't exist:
    ///   profile_path/
    ///   ├── state.json
    ///   └── meta/
    ///
    /// For user profiles, the Nix daemon creates the directory with
    /// correct ownership. For system profiles, requires root.
    pub fn open(scope: ProfileScope) -> Result<Self>;

    /// Get the current generation (follows `current` symlink).
    pub fn current_generation(&self) -> Result<Option<Generation>>;

    /// List all generations, sorted by number.
    pub fn list_generations(&self) -> Result<Vec<Generation>>;

    /// Load state.json.
    pub fn state(&self) -> Result<ProfileState>;

    /// Create a new generation directory.
    ///
    /// 1. Increment next_generation counter
    /// 2. Create gen-N/ directory
    /// 3. Return the new Generation
    pub fn new_generation(&self) -> Result<Generation>;

    /// Atomically switch `current` symlink to point at a generation.
    ///
    /// Uses temp symlink + rename for atomicity.
    pub fn switch_to(&self, gen: &Generation) -> Result<()>;

    /// Get the `current` path (profile_path/current/).
    pub fn current_path(&self) -> PathBuf;

    /// Remove old generations, keeping the latest N.
    pub fn prune_generations(&self, keep: u32) -> Result<Vec<Generation>>;

    /// Save state.json atomically.
    fn save_state(&self, state: &ProfileState) -> Result<()>;
}

impl Generation {
    /// Check if this generation has a usr/ directory with roots.
    pub fn has_roots(&self) -> bool;

    /// List all usr/{hash} roots in this generation.
    pub fn roots(&self) -> Result<Vec<(String, PathBuf)>>; // (hash, target)

    /// List all src/{hash} roots in this generation.
    pub fn source_roots(&self) -> Result<Vec<(String, PathBuf)>>;
}
```

### Tests

- `Profile::open` creates directory structure on first use.
- `new_generation` increments counter and creates `gen-N/`.
- `switch_to` creates atomic `current` symlink.
- `current_generation` follows `current` symlink correctly.
- `list_generations` returns sorted list.
- `prune_generations(3)` keeps latest 3, returns removed ones.
- State round-trips through save/load.
- Concurrent `switch_to` calls don't corrupt state (atomic rename).

### Acceptance Criteria

- Generation directories follow `gen-N/` naming.
- `current` is always a valid symlink (atomic switch).
- `state.json` tracks generation counter.
- Profile initialization is idempotent.

---

## Chunk 4B: FHS Merge Engine

### Files to Create

**`src/package/profile/merge.rs`** (~300 lines)

Build a merged FHS symlink tree from GC roots in a generation.

```rust
/// FHS directories to merge from store paths.
const MERGE_DIRS: &[&str] = &[
    "bin", "sbin", "lib", "lib64", "include", "share", "etc",
    "share/man/man1", "share/man/man2", "share/man/man3",
    "share/man/man4", "share/man/man5", "share/man/man6",
    "share/man/man7", "share/man/man8",
];

/// Build the merged FHS tree for a generation.
///
/// For each store path rooted in gen-N/usr/:
///   1. Scan the store path for files under each MERGE_DIR
///   2. Create symlinks in gen-N/{dir}/{filename} -> store_path/{dir}/{filename}
///
/// File conflicts (same filename from multiple packages): last-installed
/// wins. A warning is printed for conflicts.
///
/// Returns the list of created symlinks and any conflicts encountered.
pub fn build_fhs_tree(
    gen: &Generation,
    packages: &[&PackageMeta],
    printer: &Printer,
) -> Result<MergeResult>;

pub struct MergeResult {
    pub symlinks_created: usize,
    pub conflicts: Vec<FileConflict>,
}

pub struct FileConflict {
    pub path: String,           // e.g., "bin/python3"
    pub winner: String,         // package that won
    pub loser: String,          // package that was shadowed
}

/// Scan a store path for files under FHS directories.
///
/// Returns a map of relative_path -> absolute_store_path for each file.
fn scan_store_path(store_path: &Path) -> Result<HashMap<String, PathBuf>>;

/// Create a single FHS symlink atomically.
fn create_fhs_symlink(gen_dir: &Path, rel_path: &str, target: &Path) -> Result<()>;

/// Remove the FHS tree (all merged symlink directories) from a generation.
/// Used when rebuilding after remove/upgrade.
pub fn clear_fhs_tree(gen: &Generation) -> Result<()>;
```

### Tests

- `scan_store_path` finds `bin/curl`, `lib/libcurl.so`, `share/man/man1/curl.1`.
- `build_fhs_tree` creates correct symlinks for a single package.
- `build_fhs_tree` with two packages merges their files.
- File conflicts log a warning and last-installed wins.
- `clear_fhs_tree` removes all FHS directories but preserves `usr/` and `src/`.
- Man page symlinks land in `share/man/manN/` subdirectories.
- Empty FHS directories are not created (only dirs with actual content).

### Acceptance Criteria

- All MERGE_DIRS are scanned and symlinked.
- Symlinks point directly into store paths (not through intermediate dirs).
- Conflicts are handled with last-installed-wins + warning.
- Man pages are correctly merged by section.
- The merged tree is suitable for adding to PATH/MANPATH.

---

## Chunk 4C: Per-Path Metadata Management

### Files to Create

**`src/package/profile/meta.rs`** (~200 lines)

Read/write per-path metadata JSON in the profile's `meta/` directory.

```rust
/// Write metadata for a store path.
///
/// Creates meta/{hash}.json with the full InstalledMeta struct.
/// Atomic write (temp + rename).
pub fn write_meta(
    profile: &Profile,
    hash: &str,
    meta: &InstalledMeta,
) -> Result<()>;

/// Read metadata for a store path.
pub fn read_meta(
    profile: &Profile,
    hash: &str,
) -> Result<Option<InstalledMeta>>;

/// Delete metadata for a store path.
pub fn delete_meta(profile: &Profile, hash: &str) -> Result<()>;

/// List all metadata entries in the profile.
pub fn list_meta(profile: &Profile) -> Result<Vec<InstalledMeta>>;

/// Find all metadata entries from a specific registry.
pub fn meta_by_registry(
    profile: &Profile,
    registry_name: &str,
) -> Result<Vec<InstalledMeta>>;

/// Find all metadata entries where apm.explicit = false (auto-installed).
pub fn auto_installed(profile: &Profile) -> Result<Vec<InstalledMeta>>;

/// Find all metadata entries where apm.held = true.
pub fn held_packages(profile: &Profile) -> Result<Vec<InstalledMeta>>;

/// Set the held flag on a package's metadata.
pub fn set_held(profile: &Profile, hash: &str, held: bool) -> Result<()>;

/// Rebuild meta/ from a generation's usr/ roots and registry data.
///
/// Used by `apm rollback` — when switching to a previous generation,
/// meta/ is rebuilt from that generation's roots cross-referenced with
/// the registry to recover package names, versions, and registry origin.
pub fn rebuild_meta(
    profile: &Profile,
    gen: &Generation,
    registries: &RegistrySet,
) -> Result<()>;
```

### Tests

- Write and read back an `InstalledMeta` round-trip.
- `list_meta` returns all entries.
- `meta_by_registry("aos-core")` filters correctly.
- `auto_installed` returns only `explicit = false` entries.
- `held_packages` returns only `held = true` entries.
- `set_held` modifies the JSON file in place.
- `rebuild_meta` reconstructs meta/ from generation roots + registry data.
- `delete_meta` removes the JSON file.
- Atomic writes don't leave partial files on crash.

### Acceptance Criteria

- Metadata JSON format matches convergence.md schema (including `apm` section).
- All operations are atomic (temp + rename).
- `rebuild_meta` enables correct rollback behavior.
- Metadata queries are efficient for the expected scale (~100-1000 packages).

---

## Integration Notes

After Phase 4 is complete:
- Profile generations can be created, switched, listed, and pruned
- FHS merge builds a correct symlink tree from store paths
- Per-path metadata tracks installed package provenance
- Rollback can reconstruct metadata from generation roots
- Combined with Phases 2-3, the full pipeline is ready:
  registry → download → verify → import → GC roots → merge → switch
