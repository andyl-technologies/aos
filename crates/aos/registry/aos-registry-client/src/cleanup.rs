//! Cleanup of writable registry overlays whose seed definitions were removed.

use crate::types::ProfileScope;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

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
pub fn prune_orphaned_overlays(scope: ProfileScope) -> Result<Vec<String>> {
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
}
