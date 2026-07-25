//! Profile and generation management — apm's installed-state model.
//!
//! A *profile* (one per package-install scope: system packages or per-user) is
//! a directory of immutable, numbered *generations*. Every mutating command
//! (install, remove, upgrade) creates a fresh `gen-N/` rather than editing in
//! place; the `current` symlink names the active generation and is repointed
//! atomically, which is what makes installs transactional and rollback a pure
//! pointer switch.
//!
//! Each generation holds:
//!
//! - `usr/<hash> -> <store path>` — GC-root symlinks for installed package
//!   outputs (these keep the paths alive across `nix-store --gc`);
//! - `src/<hash> -> <drv path>` — GC roots for source derivations;
//! - `meta/<hash>.json` — a snapshot of the per-package metadata at the time
//!   the generation was created;
//! - a merged FHS tree built by [`merge`].
//!
//! `state.json` at the profile root persists the current-generation and
//! next-generation counters. Submodules: [`meta`] for per-package metadata,
//! [`merge`] for the merged `bin/`, `lib/`, ... symlink tree.

pub mod merge;
pub mod meta;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::types::ProfileScope;

// ---------------------------------------------------------------------------
// Profile — a system or per-user profile directory
// ---------------------------------------------------------------------------

/// A profile (system-package or per-user) that manages installed packages.
///
/// Directory layout:
/// ```text
/// profile_path/
/// ├── state.json        # persisted counter state
/// ├── meta/             # per-path metadata (Phase 4C)
/// ├── current -> gen-N  # symlink to the active generation
/// ├── gen-1/
/// │   ├── usr/{hash} -> /var/lib/store/{hash}-{name}-{version}
/// │   ├── src/{hash} -> /var/lib/store/{hash}-{name}-{version}.drv
/// │   └── meta/{hash}.json
/// ├── gen-2/
/// │   └── ...
/// └── ...
/// ```
pub struct Profile {
    /// Root directory of the profile.
    pub path: PathBuf,
    /// Whether this is the system profile or a per-user profile.
    pub scope: ProfileScope,
}

/// A single generation within a profile.
pub struct Generation {
    /// The generation number (`gen-N`).
    pub number: u32,
    /// Absolute path of the `gen-N/` directory.
    pub path: PathBuf,
}

/// Profile state persisted in state.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileState {
    /// Number of the active generation (0 = none activated yet).
    pub current_generation: u32,
    /// Number the next created generation will receive.
    pub next_generation: u32,
}

impl Default for ProfileState {
    fn default() -> Self {
        Self {
            current_generation: 0,
            next_generation: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Profile methods
// ---------------------------------------------------------------------------

impl Profile {
    /// Open or initialize a profile directory.
    ///
    /// Creates the directory structure if it doesn't exist:
    ///   - `profile_path/`
    ///   - `profile_path/meta/`
    ///   - `profile_path/state.json` (with default counters)
    ///
    /// # Errors
    ///
    /// Returns an error if the directories or the initial `state.json`
    /// cannot be created (typically a permission failure).
    pub fn open(scope: ProfileScope) -> Result<Self> {
        Self::open_at(scope.package_profile_path(), scope)
    }

    /// Reference an existing profile for read-only inspection without touching
    /// the filesystem.
    ///
    /// Unlike [`Profile::open`], this never creates the profile directory or
    /// writes `state.json`. It is meant for callers that only read
    /// installed-package metadata and must not require write access to the
    /// profile root — for example an unprivileged `apr` registry operation
    /// checking whether any packages came from a registry, which must not fail
    /// trying to create a system profile under `/var/lib/profiles`. The
    /// metadata and generation listing helpers already treat a missing profile
    /// as empty, so reads against a non-existent profile simply yield no
    /// results.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aos_package::profile::Profile;
    /// use aos_package::types::ProfileScope;
    ///
    /// let profile = Profile::open_readonly(ProfileScope::User);
    /// // Listing metadata is safe even if the profile was never initialized.
    /// let installed = aos_package::profile::meta::list_meta(&profile)?;
    /// assert!(installed.is_empty() || !installed.is_empty());
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn open_readonly(scope: ProfileScope) -> Self {
        Self {
            path: scope.package_profile_path(),
            scope,
        }
    }

    /// Open a profile at a specific path (useful for testing).
    ///
    /// # Errors
    ///
    /// Returns an error if the directories or the initial `state.json`
    /// cannot be created.
    pub fn open_at(path: PathBuf, scope: ProfileScope) -> Result<Self> {
        // Create profile directory and meta/ subdirectory.
        std::fs::create_dir_all(path.join("meta"))
            .with_context(|| format!("creating profile directory {}", path.display()))?;

        // Initialize state.json if it doesn't exist.
        let state_path = path.join("state.json");
        if !state_path.exists() {
            let state = ProfileState::default();
            let json = serde_json::to_string_pretty(&state)
                .context("serializing default profile state")?;
            atomic_write(&state_path, json.as_bytes()).context("writing initial state.json")?;
        }

        Ok(Self { path, scope })
    }

    /// Get the current generation (follows `current` symlink).
    ///
    /// Returns `None` if no generation has been activated yet (i.e. the
    /// `current` symlink does not exist).
    ///
    /// # Errors
    ///
    /// Returns an error if the symlink cannot be read or its target does
    /// not match the `gen-N` naming pattern.
    pub fn current_generation(&self) -> Result<Option<Generation>> {
        let current = self.current_path();
        if !current.symlink_metadata().is_ok() {
            return Ok(None);
        }

        let target = std::fs::read_link(&current)
            .with_context(|| format!("reading current symlink {}", current.display()))?;

        // The symlink target is a relative name like "gen-3".
        let gen_name = target
            .file_name()
            .unwrap_or(target.as_os_str())
            .to_string_lossy();

        let number = parse_gen_number(&gen_name)?;
        let gen_path = self.path.join(&*gen_name);

        Ok(Some(Generation {
            number,
            path: gen_path,
        }))
    }

    /// List all generations, sorted by number ascending.
    ///
    /// A missing profile directory yields an empty list.
    ///
    /// # Errors
    ///
    /// Returns an error if the profile directory exists but cannot be read.
    pub fn list_generations(&self) -> Result<Vec<Generation>> {
        let mut gens = Vec::new();

        let entries = match std::fs::read_dir(&self.path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("reading profile directory {}", self.path.display()));
            }
        };

        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Ok(number) = parse_gen_number(&name_str) {
                gens.push(Generation {
                    number,
                    path: entry.path(),
                });
            }
        }

        gens.sort_by_key(|g| g.number);
        Ok(gens)
    }

    /// Load state.json.
    ///
    /// # Errors
    ///
    /// Returns an error if `state.json` cannot be read or parsed.
    pub fn state(&self) -> Result<ProfileState> {
        let state_path = self.path.join("state.json");
        let data = std::fs::read_to_string(&state_path)
            .with_context(|| format!("reading {}", state_path.display()))?;
        let state: ProfileState = serde_json::from_str(&data)
            .with_context(|| format!("parsing {}", state_path.display()))?;
        Ok(state)
    }

    /// Create a new generation directory.
    ///
    /// 1. Load state, use `next_generation` as the new generation number
    /// 2. Create `gen-N/` directory
    /// 3. Increment `next_generation` and save state
    /// 4. Return the new `Generation`
    ///
    /// # Errors
    ///
    /// Returns an error if `state.json` cannot be read/written or the
    /// generation directory cannot be created.
    pub fn new_generation(&self) -> Result<Generation> {
        let mut state = self.state()?;
        let gen_number = state.next_generation;
        let gen_name = format!("gen-{gen_number}");
        let gen_path = self.path.join(&gen_name);

        std::fs::create_dir_all(&gen_path)
            .with_context(|| format!("creating generation directory {}", gen_path.display()))?;

        state.next_generation += 1;
        self.save_state(&state)?;

        Ok(Generation {
            number: gen_number,
            path: gen_path,
        })
    }

    /// Atomically switch `current` symlink to point at a generation.
    ///
    /// Uses temp symlink + rename for atomicity.  Also updates
    /// `current_generation` in state.json.
    ///
    /// # Errors
    ///
    /// Returns an error if the symlink cannot be created or renamed into
    /// place, or if `state.json` cannot be updated.
    pub fn switch_to(&self, generation: &Generation) -> Result<()> {
        use std::os::unix::fs::symlink;

        let current = self.current_path();
        let target_name = format!("gen-{}", generation.number);

        // Create a temp symlink next to `current`.
        let tmp_path = self
            .path
            .join(format!(".current.tmp.{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp_path);

        symlink(&target_name, &tmp_path)
            .with_context(|| format!("creating temp symlink {}", tmp_path.display()))?;

        std::fs::rename(&tmp_path, &current)
            .with_context(|| format!("renaming {} -> {}", tmp_path.display(), current.display()))?;

        // Update state to reflect the new current generation.
        let mut state = self.state()?;
        state.current_generation = generation.number;
        self.save_state(&state)?;

        Ok(())
    }

    /// Get the `current` symlink path.
    pub fn current_path(&self) -> PathBuf {
        self.path.join("current")
    }

    /// Remove old generations, keeping the latest `keep` generations.
    ///
    /// Never removes the current generation, even if it falls outside the
    /// latest `keep` window.  Returns the list of removed generations.
    ///
    /// # Errors
    ///
    /// Returns an error if the generations cannot be listed or a generation
    /// directory cannot be deleted.
    pub fn prune_generations(&self, keep: u32) -> Result<Vec<Generation>> {
        let all = self.list_generations()?;
        let current = self.current_generation()?;
        let current_number = current.map(|g| g.number);

        if all.len() <= keep as usize {
            return Ok(Vec::new());
        }

        // Keep the last `keep` generations (by number, already sorted ascending).
        let cutoff = all.len() - keep as usize;
        let mut removed = Vec::new();

        for g in &all[..cutoff] {
            // Never remove the current generation.
            if Some(g.number) == current_number {
                continue;
            }
            std::fs::remove_dir_all(&g.path).with_context(|| {
                format!("removing generation {} at {}", g.number, g.path.display())
            })?;
            removed.push(Generation {
                number: g.number,
                path: g.path.clone(),
            });
        }

        Ok(removed)
    }

    /// Save state.json atomically (write to temp file, then rename).
    fn save_state(&self, state: &ProfileState) -> Result<()> {
        let state_path = self.path.join("state.json");
        let json = serde_json::to_string_pretty(state).context("serializing profile state")?;
        atomic_write(&state_path, json.as_bytes()).context("saving state.json")
    }
}

// ---------------------------------------------------------------------------
// Generation methods
// ---------------------------------------------------------------------------

impl Generation {
    /// Check if this generation has a `usr/` directory with at least one root.
    pub fn has_roots(&self) -> bool {
        let usr_dir = self.path.join("usr");
        match std::fs::read_dir(&usr_dir) {
            Ok(mut entries) => entries.next().is_some(),
            Err(_) => false,
        }
    }

    /// List all `usr/{hash}` roots in this generation.
    ///
    /// Returns `Vec<(hash, symlink_target_path)>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `usr/` directory or one of its symlinks
    /// cannot be read (a missing directory yields an empty list).
    pub fn roots(&self) -> Result<Vec<(String, PathBuf)>> {
        read_root_dir(&self.path.join("usr"))
    }

    /// List all `src/{hash}` roots in this generation.
    ///
    /// Returns `Vec<(hash, symlink_target_path)>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `src/` directory or one of its symlinks
    /// cannot be read (a missing directory yields an empty list).
    pub fn source_roots(&self) -> Result<Vec<(String, PathBuf)>> {
        read_root_dir(&self.path.join("src"))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a generation number from a directory name like `gen-3`.
fn parse_gen_number(name: &str) -> Result<u32> {
    let num_str = name
        .strip_prefix("gen-")
        .with_context(|| format!("directory name '{name}' does not match gen-N pattern"))?;
    num_str
        .parse::<u32>()
        .with_context(|| format!("invalid generation number in '{name}'"))
}

/// Read a root directory (`usr/` or `src/`) and return `(name, target)` pairs.
///
/// Each entry is expected to be a symlink whose name is a store hash and
/// whose target is the store path.
fn read_root_dir(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut results = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(results),
        Err(e) => {
            return Err(e).with_context(|| format!("reading root directory {}", dir.display()));
        }
    };

    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let target = std::fs::read_link(entry.path())
            .with_context(|| format!("reading symlink {}", entry.path().display()))?;
        results.push((name, target));
    }

    Ok(results)
}

/// Write data to a file atomically via a temp file and rename.
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().context("path has no parent directory")?;
    let file_name = path
        .file_name()
        .context("path has no file name")?
        .to_string_lossy();
    let tmp_name = format!(".{file_name}.tmp.{}", std::process::id());
    let tmp_path = parent.join(&tmp_name);

    std::fs::write(&tmp_path, data)
        .with_context(|| format!("writing temp file {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} -> {}", tmp_path.display(), path.display()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_profile(tmp: &TempDir) -> Profile {
        Profile::open_at(tmp.path().to_path_buf(), ProfileScope::User).unwrap()
    }

    // 1. open_at creates directory structure (meta/, state.json)
    #[test]
    fn open_creates_directory_structure() {
        let tmp = TempDir::new().unwrap();
        let _profile = test_profile(&tmp);

        assert!(tmp.path().join("meta").is_dir());
        assert!(tmp.path().join("state.json").is_file());
    }

    // 2. open_at is idempotent (calling twice doesn't error)
    #[test]
    fn open_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let _p1 = test_profile(&tmp);
        let _p2 = test_profile(&tmp);

        assert!(tmp.path().join("state.json").is_file());
    }

    // 3. new_generation increments counter and creates gen-N/
    #[test]
    fn new_generation_creates_directory() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let g1 = profile.new_generation().unwrap();
        assert_eq!(g1.number, 1);
        assert!(g1.path.is_dir());
        assert_eq!(g1.path, tmp.path().join("gen-1"));

        let state = profile.state().unwrap();
        assert_eq!(state.next_generation, 2);
    }

    // 4. new_generation called twice creates gen-1/ and gen-2/
    #[test]
    fn new_generation_increments() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let gen1 = profile.new_generation().unwrap();
        let gen2 = profile.new_generation().unwrap();

        assert_eq!(gen1.number, 1);
        assert_eq!(gen2.number, 2);
        assert!(tmp.path().join("gen-1").is_dir());
        assert!(tmp.path().join("gen-2").is_dir());

        let state = profile.state().unwrap();
        assert_eq!(state.next_generation, 3);
    }

    // 5. switch_to creates current symlink pointing to gen-N
    #[test]
    fn switch_to_creates_current_symlink() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let g1 = profile.new_generation().unwrap();
        profile.switch_to(&g1).unwrap();

        let current = tmp.path().join("current");
        assert!(current.symlink_metadata().unwrap().file_type().is_symlink());

        let target = std::fs::read_link(&current).unwrap();
        assert_eq!(target.to_string_lossy(), "gen-1");
    }

    // 6. current_generation returns None before any switch
    #[test]
    fn current_generation_none_initially() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        assert!(profile.current_generation().unwrap().is_none());
    }

    // 7. current_generation returns correct gen after switch
    #[test]
    fn current_generation_after_switch() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let gen1 = profile.new_generation().unwrap();
        let gen2 = profile.new_generation().unwrap();

        profile.switch_to(&gen1).unwrap();
        let current = profile.current_generation().unwrap().unwrap();
        assert_eq!(current.number, 1);

        profile.switch_to(&gen2).unwrap();
        let current = profile.current_generation().unwrap().unwrap();
        assert_eq!(current.number, 2);
    }

    // 8. list_generations returns sorted list
    #[test]
    fn list_generations_sorted() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let _g1 = profile.new_generation().unwrap();
        let _g2 = profile.new_generation().unwrap();
        let _g3 = profile.new_generation().unwrap();

        let gens = profile.list_generations().unwrap();
        assert_eq!(gens.len(), 3);
        assert_eq!(gens[0].number, 1);
        assert_eq!(gens[1].number, 2);
        assert_eq!(gens[2].number, 3);
    }

    // 9. prune_generations keeps latest N and current
    #[test]
    fn prune_keeps_latest_and_current() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let g1 = profile.new_generation().unwrap();
        let _g2 = profile.new_generation().unwrap();
        let _g3 = profile.new_generation().unwrap();
        let _g4 = profile.new_generation().unwrap();

        // Switch to g1 (oldest) so it's the current one.
        profile.switch_to(&g1).unwrap();

        // Keep latest 2 (g3 and g4). g1 is current, so it should be kept too.
        let removed = profile.prune_generations(2).unwrap();

        // Only g2 should be removed (g1 is current, g3 and g4 are latest 2).
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].number, 2);

        // Verify g2 is actually gone.
        assert!(!tmp.path().join("gen-2").exists());
        // g1, g3, g4 should still exist.
        assert!(tmp.path().join("gen-1").exists());
        assert!(tmp.path().join("gen-3").exists());
        assert!(tmp.path().join("gen-4").exists());
    }

    // 10. state round-trips through save/load
    #[test]
    fn state_round_trip() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let state = profile.state().unwrap();
        assert_eq!(state.current_generation, 0);
        assert_eq!(state.next_generation, 1);

        // Mutate through new_generation + switch.
        let g1 = profile.new_generation().unwrap();
        profile.switch_to(&g1).unwrap();

        let state = profile.state().unwrap();
        assert_eq!(state.current_generation, 1);
        assert_eq!(state.next_generation, 2);
    }

    // 11. Generation::has_roots returns false for empty gen
    #[test]
    fn has_roots_empty_generation() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);
        let g1 = profile.new_generation().unwrap();

        assert!(!g1.has_roots());
    }

    // 12. Generation::roots lists usr/ entries
    #[test]
    fn roots_lists_usr_entries() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);
        let g1 = profile.new_generation().unwrap();

        // Create usr/ with a symlink.
        let usr_dir = g1.path.join("usr");
        std::fs::create_dir_all(&usr_dir).unwrap();
        symlink("/var/lib/store/abc123-curl-8.5.0", usr_dir.join("abc123")).unwrap();
        symlink("/var/lib/store/def456-zlib-1.3.1", usr_dir.join("def456")).unwrap();

        let roots = g1.roots().unwrap();
        assert_eq!(roots.len(), 2);

        // Sort for deterministic comparison.
        let mut hashes: Vec<&str> = roots.iter().map(|(h, _)| h.as_str()).collect();
        hashes.sort();
        assert_eq!(hashes, vec!["abc123", "def456"]);
    }

    // 13. Generation::source_roots lists src/ entries
    #[test]
    fn source_roots_lists_src_entries() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);
        let g1 = profile.new_generation().unwrap();

        // Create src/ with a symlink.
        let src_dir = g1.path.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        symlink(
            "/var/lib/store/xyz789-curl-8.5.0.drv",
            src_dir.join("xyz789"),
        )
        .unwrap();

        let roots = g1.source_roots().unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].0, "xyz789");
        assert_eq!(
            roots[0].1.to_string_lossy(),
            "/var/lib/store/xyz789-curl-8.5.0.drv"
        );
    }
}
