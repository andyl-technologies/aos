//! Views: named, GC-rooted slices of the Nix store.
//!
//! A *view* scopes what a client can see and how long it is retained. Each
//! view owns two on-disk trees under the AOS root:
//!
//! ```text
//! gcroots/{view}/{ns}/{hash}        -> symlink to the store path
//! meta/{view}/{ns}/{hash}.json      -> push/access metadata
//! ```
//!
//! where `{ns}` is one of three namespaces:
//!
//! - `bin/` — build outputs (subject to the view's `ttl`),
//! - `src/` — fixed-output source inputs mirrored alongside builds
//!   (subject to `source_ttl`),
//! - `tmp/` — short-lived roots protecting freshly uploaded paths until
//!   their build creates proper `bin/` roots.
//!
//! A path is "visible" in a view exactly when a GC root symlink for its
//! store hash exists ([`ViewManager::check_visibility`]) — the cache
//! handlers use this check for authorization, so possessing a path in the
//! shared store does not leak it across views. The symlinks double as Nix
//! GC roots, so anything visible in a view also survives `nix-store --gc`.

#![allow(
    clippy::disallowed_types,
    reason = "Named host view configuration retains its existing lookup-map API outside Crucible replay state."
)]

use std::collections::HashMap;
use std::fs;
use std::os::unix;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use aos_nix::{StoreHash, aos_nix_env};

use crate::config::ViewConfig;

/// Manages views and their GC root directories.
///
/// Holds the AOS root path and the per-view configuration map; all methods
/// operate on the `gcroots/` and `meta/` trees underneath the root.
pub struct ViewManager {
    root: PathBuf,
    views: HashMap<String, ViewConfig>,
}

impl ViewManager {
    /// Creates a manager for the given AOS root and view configurations.
    ///
    /// Does not touch the filesystem; call
    /// [`init_directories`](Self::init_directories) to create the on-disk
    /// tree.
    ///
    /// # Errors
    ///
    /// Returns an error if a view name is not a safe single path component or
    /// if the configuration defines the same view more than once.
    pub fn new(root: PathBuf, views: Vec<ViewConfig>) -> Result<Self> {
        let mut map = HashMap::with_capacity(views.len());
        for view in views {
            validate_view_name(&view.name)?;
            let name = view.name.clone();
            ensure!(
                map.insert(name.clone(), view).is_none(),
                "duplicate view {name:?}"
            );
        }

        Ok(Self { root, views: map })
    }

    /// Creates the directory tree for all configured views: the
    /// `gcroots/{view}/{ns}` and `meta/{view}/{ns}` directories for every
    /// namespace, plus the shared `views/` state directory.
    ///
    /// # Errors
    ///
    /// Returns an error if any directory cannot be created.
    pub fn init_directories(&self) -> Result<()> {
        for name in self.views.keys() {
            for ns in &["bin", "src", "tmp"] {
                let gcroot_dir = self.root.join("gcroots").join(name).join(ns);
                fs::create_dir_all(&gcroot_dir)
                    .with_context(|| format!("creating {}", gcroot_dir.display()))?;

                let meta_dir = self.root.join("meta").join(name).join(ns);
                fs::create_dir_all(&meta_dir)
                    .with_context(|| format!("creating {}", meta_dir.display()))?;
            }
        }

        // Also create the views state directory.
        let views_dir = self.root.join("views");
        fs::create_dir_all(&views_dir)
            .with_context(|| format!("creating {}", views_dir.display()))?;

        Ok(())
    }

    /// Checks if a store hash is visible in a view by looking for its GC
    /// root symlink.
    ///
    /// Returns the symlink's target (the full store path) if a root exists
    /// in `bin/` or `src/` (checked in that order), `None` otherwise. This
    /// is the gatekeeper used by the narinfo and NAR handlers: a path that
    /// exists in the shared store but has no root in the requested view is
    /// reported as not found.
    ///
    /// # Errors
    ///
    /// Returns an error if an existing root cannot be read, does not point to
    /// a direct entry in this server's store, or names a different store hash.
    pub fn check_visibility(&self, view: &str, hash: &StoreHash) -> Result<Option<String>> {
        for ns in &["bin", "src"] {
            let link = self
                .root
                .join("gcroots")
                .join(view)
                .join(ns)
                .join(hash.as_str());
            if link.is_symlink() {
                let target = fs::read_link(&link)
                    .with_context(|| format!("reading symlink {}", link.display()))?;
                let target = if target.is_absolute() {
                    target
                } else {
                    link.parent()
                        .context("GC root has no parent directory")?
                        .join(target)
                };
                let target = self.canonical_store_target(hash, &target)?;

                return Ok(Some(target.to_string_lossy().into_owned()));
            }
        }
        Ok(None)
    }

    /// Looks up a view's configuration by name.
    pub fn get_view(&self, name: &str) -> Option<&ViewConfig> {
        self.views.get(name)
    }

    /// Returns the AOS root path this manager operates under.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Creates an atomic GC root symlink:
    /// `gcroots/{view}/{ns}/{hash} -> store_path`.
    ///
    /// Uses a temp symlink + rename so concurrent readers never observe a
    /// half-created root; an existing root for the same hash is replaced.
    ///
    /// # Errors
    ///
    /// Returns an error if `store_path` is not the matching direct entry in
    /// this server's store, or if the symlink cannot be created or renamed
    /// into place (e.g. the namespace directory does not exist).
    pub fn create_gc_root(
        &self,
        view: &str,
        ns: &str,
        hash: &StoreHash,
        store_path: &str,
    ) -> Result<()> {
        let link_dir = self.root.join("gcroots").join(view).join(ns);
        let link = link_dir.join(hash.as_str());
        let tmp = link_dir.join(format!(".{hash}.tmp"));
        let store_path = self.canonical_store_target(hash, Path::new(store_path))?;

        // Remove stale temp symlink if it exists.
        let _ = fs::remove_file(&tmp);

        unix::fs::symlink(&store_path, &tmp)
            .with_context(|| format!("creating symlink {}", tmp.display()))?;
        fs::rename(&tmp, &link)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), link.display()))?;

        tracing::debug!(view = %view, ns = %ns, hash = %hash, store_path = %store_path.display(), "GC root created");
        Ok(())
    }

    /// Writes metadata JSON atomically to `meta/{view}/{ns}/{hash}.json`
    /// (temp file + rename).
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata cannot be serialized, written, or
    /// renamed into place.
    pub fn write_metadata(
        &self,
        view: &str,
        ns: &str,
        hash: &StoreHash,
        meta: &serde_json::Value,
    ) -> Result<()> {
        let meta_dir = self.root.join("meta").join(view).join(ns);
        let path = meta_dir.join(format!("{hash}.json"));
        let tmp = meta_dir.join(format!(".{hash}.json.tmp"));

        let data = serde_json::to_string_pretty(meta).context("serializing metadata")?;
        fs::write(&tmp, &data).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, &path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;

        Ok(())
    }

    /// Resolves a root target while preserving a store object that is itself
    /// a symlink.
    fn canonical_store_target(&self, hash: &StoreHash, target: &Path) -> Result<PathBuf> {
        let store_dir = fs::canonicalize(self.root.join("store"))
            .with_context(|| format!("resolving store directory under {}", self.root.display()))?;
        let target_parent = target
            .parent()
            .context("store target has no parent directory")?;
        let target_parent = fs::canonicalize(target_parent).with_context(|| {
            format!("resolving store target parent {}", target_parent.display())
        })?;

        ensure!(
            target_parent == store_dir,
            "GC root target is outside the store"
        );

        let target_name = target
            .file_name()
            .and_then(|name| name.to_str())
            .context("store target has no valid UTF-8 name")?;
        let target_hash = StoreHash::from_store_path(target_name)
            .context("GC root target has an invalid store path name")?;
        ensure!(
            &target_hash == hash,
            "GC root target hash does not match its name"
        );
        let target = store_dir.join(target_name);
        fs::symlink_metadata(&target)
            .with_context(|| format!("reading store target {}", target.display()))?;

        Ok(target)
    }

    /// Creates GC roots for the source inputs of a derivation.
    ///
    /// Queries the derivation's reference closure with `nix-store -qR` and
    /// roots every non-`.drv` path in the `src/` namespace, writing
    /// metadata that records the originating derivation (`source_of`) and,
    /// when `source_ttl` is set, an `expires_at` timestamp for TTL expiry.
    /// Called after successful builds on views with `source_mirror`
    /// enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if `nix-store -qR` cannot be run or exits non-zero,
    /// or if creating a root or writing metadata fails.
    #[allow(
        clippy::disallowed_methods,
        reason = "Host source-mirror roots record actual retention timestamps."
    )]
    pub fn create_source_roots(
        &self,
        view: &str,
        drv_path: &str,
        source_ttl: Option<std::time::Duration>,
    ) -> Result<()> {
        // Query the derivation's own references (not build outputs).
        let output = std::process::Command::new("nix-store")
            .envs(aos_nix_env())
            .args(["-qR", drv_path])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .with_context(|| format!("querying references of {drv_path}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nix-store -qR failed for {drv_path}: {stderr}");
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock error")?
            .as_secs() as i64;

        let expires_at = source_ttl.map(|d| now + d.as_secs() as i64);

        let paths: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|l| !l.is_empty())
            .filter(|l| !l.ends_with(".drv")) // Skip .drv files, keep sources
            .map(String::from)
            .collect();

        tracing::debug!(view = %view, drv = %drv_path, count = paths.len(), "creating source roots");

        for path in &paths {
            let hash = StoreHash::from_store_path(path)
                .with_context(|| format!("extracting hash from {path}"))?;

            self.create_gc_root(view, "src", &hash, path)?;

            let mut meta = serde_json::json!({
                "store_path": path,
                "pushed_at": now,
                "access_count": 0,
                "source_of": [drv_path],
            });

            if let Some(exp) = expires_at {
                meta["expires_at"] = serde_json::json!(exp);
            }

            self.write_metadata(view, "src", &hash, &meta)?;
        }

        Ok(())
    }

    /// Creates a temporary GC root for a freshly-imported store path.
    ///
    /// These roots live in the `tmp/` namespace and prevent GC from reclaiming
    /// uploaded paths before their build starts. Call
    /// [`remove_tmp_roots`](Self::remove_tmp_roots) after the build creates
    /// proper `bin/` roots.
    ///
    /// # Errors
    ///
    /// Returns an error if the root or its metadata cannot be written, or
    /// if the system clock is before the Unix epoch.
    #[allow(
        clippy::disallowed_methods,
        reason = "Temporary host upload roots expire relative to their actual creation time."
    )]
    pub fn create_tmp_root(&self, view: &str, hash: &StoreHash, store_path: &str) -> Result<()> {
        self.create_gc_root(view, "tmp", hash, store_path)?;

        let now = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock error")?
            .as_secs() as i64;

        let meta = serde_json::json!({
            "store_path": store_path,
            "pushed_at": now,
            "temporary": true,
        });
        self.write_metadata(view, "tmp", hash, &meta)?;
        Ok(())
    }

    /// Removes all temporary GC roots for a view.
    ///
    /// Called after a build completes and proper `bin/` roots have been
    /// created. Individual file removals are best-effort; a missing `tmp/`
    /// directory is a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error if the `tmp/` GC root directory cannot be listed.
    pub fn remove_tmp_roots(&self, view: &str) -> Result<()> {
        let gcroot_dir = self.root.join("gcroots").join(view).join("tmp");
        let meta_dir = self.root.join("meta").join(view).join("tmp");

        if !gcroot_dir.exists() {
            return Ok(());
        }

        let entries = fs::read_dir(&gcroot_dir)
            .with_context(|| format!("reading {}", gcroot_dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            let _ = fs::remove_file(entry.path());
            let _ = fs::remove_file(meta_dir.join(format!("{}.json", name.to_string_lossy())));
        }

        Ok(())
    }

    /// Counts the total number of GC-rooted paths across all namespaces
    /// (`bin`, `src`, `tmp`) in a view.
    ///
    /// Used to enforce the per-view `max_paths` upload quota. Hidden
    /// (dot-prefixed) temp files are excluded.
    ///
    /// # Errors
    ///
    /// Returns an error if a namespace directory exists but cannot be
    /// listed.
    pub fn count_roots(&self, view: &str) -> Result<u64> {
        let mut count = 0u64;
        for ns in &["bin", "src", "tmp"] {
            let gcroot_dir = self.root.join("gcroots").join(view).join(ns);
            if !gcroot_dir.exists() {
                continue;
            }
            for entry in fs::read_dir(&gcroot_dir)
                .with_context(|| format!("reading {}", gcroot_dir.display()))?
            {
                let entry = entry?;
                if !entry.file_name().to_string_lossy().starts_with('.') {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Creates GC roots (with fresh metadata) for all paths in a closure
    /// within the given view/namespace.
    ///
    /// Called after a successful build to root the full runtime closure of
    /// the outputs in `bin/`, making every member visible in the view.
    ///
    /// # Errors
    ///
    /// Returns an error if a hash cannot be extracted from a path, or if
    /// creating a root or writing its metadata fails.
    #[allow(
        clippy::disallowed_methods,
        reason = "Host closure retention records the actual creation time of each view root."
    )]
    pub fn create_roots_for_closure(&self, view: &str, ns: &str, paths: &[String]) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock error")?
            .as_secs() as i64;

        for path in paths {
            let hash = StoreHash::from_store_path(path)
                .with_context(|| format!("extracting hash from {path}"))?;

            self.create_gc_root(view, ns, &hash, path)?;

            let meta = serde_json::json!({
                "store_path": path,
                "pushed_at": now,
                "access_count": 0,
            });
            self.write_metadata(view, ns, &hash, &meta)?;
        }

        Ok(())
    }
}

/// Validates a view name before it is used as an on-disk path component.
///
/// # Errors
///
/// Returns an error for empty names, traversal sequences, separators, or null
/// bytes.
pub fn validate_view_name(name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "view name must not be empty");
    ensure!(
        name != "."
            && !name.contains("..")
            && !name.contains('/')
            && !name.contains('\\')
            && !name.contains('\0'),
        "view name must be a single path component"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;

    const STORE_HASH: &str = "0123456789abcdfghijklmnpqrsvwxyz";

    fn manager(root: &Path) -> ViewManager {
        ViewManager::new(root.to_path_buf(), ServerConfig::default().views).unwrap()
    }

    #[test]
    fn configured_view_names_are_safe_and_unique() {
        let root = PathBuf::from("/unused");
        for name in ["", ".", "..", "../other", "other/view", "other\\view"] {
            let mut config = ServerConfig::default();
            config.views[0].name = name.to_string();
            assert!(ViewManager::new(root.clone(), config.views).is_err());
        }

        let mut config = ServerConfig::default();
        config.views.push(config.views[0].clone());
        assert!(ViewManager::new(root, config.views).is_err());
    }

    #[test]
    fn visibility_accepts_only_matching_direct_store_targets() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = directory.path().join("store");
        let roots = directory.path().join("gcroots/default/bin");
        fs::create_dir_all(&store)?;
        fs::create_dir_all(&roots)?;

        let hash: StoreHash = STORE_HASH.parse()?;
        let valid_target = store.join(format!("{hash}-demo"));
        fs::write(&valid_target, b"payload")?;
        unix::fs::symlink(&valid_target, roots.join(hash.as_str()))?;

        assert_eq!(
            manager(directory.path()).check_visibility("default", &hash)?,
            Some(valid_target.to_string_lossy().into_owned())
        );

        let outside_target = directory.path().join(format!("{hash}-outside"));
        fs::write(&outside_target, b"outside")?;
        fs::remove_file(roots.join(hash.as_str()))?;
        unix::fs::symlink(&outside_target, roots.join(hash.as_str()))?;

        let error = manager(directory.path())
            .check_visibility("default", &hash)
            .unwrap_err();
        assert!(error.to_string().contains("outside the store"), "{error:#}");

        Ok(())
    }

    #[test]
    fn gc_root_creation_rejects_mismatched_store_targets() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = directory.path().join("store");
        let roots = directory.path().join("gcroots/default/bin");
        fs::create_dir_all(&store)?;
        fs::create_dir_all(&roots)?;

        let expected: StoreHash = STORE_HASH.parse()?;
        let other: StoreHash = "00000000000000000000000000000000".parse()?;
        let target = store.join(format!("{other}-demo"));
        fs::write(&target, b"payload")?;

        let error = manager(directory.path())
            .create_gc_root("default", "bin", &expected, target.to_str().unwrap())
            .unwrap_err();
        assert!(error.to_string().contains("does not match"), "{error:#}");
        assert!(!roots.join(expected.as_str()).exists());

        Ok(())
    }

    #[test]
    fn visibility_preserves_store_entries_that_are_symlinks() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = directory.path().join("store");
        let roots = directory.path().join("gcroots/default/bin");
        fs::create_dir_all(&store)?;
        fs::create_dir_all(&roots)?;

        let hash: StoreHash = STORE_HASH.parse()?;
        let target = store.join(format!("{hash}-link"));
        unix::fs::symlink("missing-target", &target)?;
        unix::fs::symlink(&target, roots.join(hash.as_str()))?;

        assert_eq!(
            manager(directory.path()).check_visibility("default", &hash)?,
            Some(target.to_string_lossy().into_owned())
        );

        Ok(())
    }
}
