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

use std::collections::HashMap;
use std::fs;
use std::os::unix;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use aos_core::nix::aos_nix_env;

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
    pub fn new(root: PathBuf, views: Vec<ViewConfig>) -> Self {
        let map = views.into_iter().map(|v| (v.name.clone(), v)).collect();
        Self { root, views: map }
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
    /// Returns an error if an existing symlink cannot be read.
    pub fn check_visibility(&self, view: &str, hash: &str) -> Result<Option<String>> {
        for ns in &["bin", "src"] {
            let link = self.root.join("gcroots").join(view).join(ns).join(hash);
            if link.is_symlink() {
                let target = fs::read_link(&link)
                    .with_context(|| format!("reading symlink {}", link.display()))?;
                return Ok(Some(target.to_string_lossy().to_string()));
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
    /// Returns an error if the symlink cannot be created or renamed into
    /// place (e.g. the namespace directory does not exist).
    pub fn create_gc_root(&self, view: &str, ns: &str, hash: &str, store_path: &str) -> Result<()> {
        let link_dir = self.root.join("gcroots").join(view).join(ns);
        let link = link_dir.join(hash);
        let tmp = link_dir.join(format!(".{hash}.tmp"));

        // Remove stale temp symlink if it exists.
        let _ = fs::remove_file(&tmp);

        unix::fs::symlink(store_path, &tmp)
            .with_context(|| format!("creating symlink {}", tmp.display()))?;
        fs::rename(&tmp, &link)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), link.display()))?;

        tracing::debug!(view = %view, ns = %ns, hash = %hash, store_path = %store_path, "GC root created");
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
        hash: &str,
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

    /// Extracts the hash portion from a store path
    /// (e.g. `/var/lib/aos/store/abc123-foo` -> `abc123`).
    ///
    /// Returns `None` only for pathological inputs with no basename.
    pub fn store_path_hash(store_path: &str) -> Option<&str> {
        let basename = store_path.rsplit('/').next()?;
        basename.split('-').next()
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
            let hash = Self::store_path_hash(path)
                .with_context(|| format!("extracting hash from {path}"))?;

            self.create_gc_root(view, "src", hash, path)?;

            let mut meta = serde_json::json!({
                "store_path": path,
                "pushed_at": now,
                "access_count": 0,
                "source_of": [drv_path],
            });

            if let Some(exp) = expires_at {
                meta["expires_at"] = serde_json::json!(exp);
            }

            self.write_metadata(view, "src", hash, &meta)?;
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
    pub fn create_tmp_root(&self, view: &str, hash: &str, store_path: &str) -> Result<()> {
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
    pub fn create_roots_for_closure(&self, view: &str, ns: &str, paths: &[String]) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock error")?
            .as_secs() as i64;

        for path in paths {
            let hash = Self::store_path_hash(path)
                .with_context(|| format!("extracting hash from {path}"))?;

            self.create_gc_root(view, ns, hash, path)?;

            let meta = serde_json::json!({
                "store_path": path,
                "pushed_at": now,
                "access_count": 0,
            });
            self.write_metadata(view, ns, hash, &meta)?;
        }

        Ok(())
    }
}
