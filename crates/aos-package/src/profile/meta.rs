//! Per-package metadata storage (`meta/<hash>.json`).
//!
//! Every installed store path has an [`InstalledMeta`] JSON file in the
//! profile's `meta/` directory, keyed by store-path hash. The `apm` section
//! records what apm knows about the package: name, version, source
//! registry, whether it was explicitly installed or pulled in as a
//! dependency, the hold flag, and source-derivation provenance.
//!
//! The profile-level `meta/` always describes the *current* generation.
//! Two recovery paths keep rollback exact:
//!
//! - [`snapshot_profile_meta_to_generation`] copies the entries for a
//!   generation's roots into `gen-N/meta/` when the generation is created.
//! - [`rebuild_meta`] (used by rollback) repopulates the profile `meta/`
//!   from a generation's roots, preferring the generation snapshot, then
//!   registry data by hash, then a minimal entry — so packages whose
//!   registry entries have since been retired still restore correctly.
//!
//! All writes are atomic (temp file + rename); unparseable entries are
//! skipped with a warning rather than failing whole-profile listings.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, bail};

use super::{Generation, Profile, atomic_write};
use crate::registry::{RegistrySet, store_path_hash};
use crate::types::{ApmMeta, InstalledMeta};

// ---------------------------------------------------------------------------
// Write / read / delete individual metadata entries
// ---------------------------------------------------------------------------

/// Write metadata for a store path hash.
///
/// Creates `meta/{hash}.json` with the full `InstalledMeta` struct.
/// Uses atomic write (temp file + rename) to avoid partial reads.
///
/// # Errors
///
/// Returns an error if the `meta/` directory cannot be created or the file
/// cannot be serialized or written.
pub fn write_meta(profile: &Profile, hash: &str, meta: &InstalledMeta) -> Result<()> {
    let meta_dir = profile.path.join("meta");
    std::fs::create_dir_all(&meta_dir)
        .with_context(|| format!("creating meta directory {}", meta_dir.display()))?;

    let json = serde_json::to_string_pretty(meta)
        .with_context(|| format!("serializing metadata for {hash}"))?;

    let dest = meta_dir.join(format!("{hash}.json"));
    atomic_write(&dest, json.as_bytes()).with_context(|| format!("writing metadata for {hash}"))
}

/// Read metadata for a store path hash.
///
/// Returns `None` if `meta/{hash}.json` does not exist.
///
/// # Errors
///
/// Returns an error if an existing file cannot be read or parsed.
pub fn read_meta(profile: &Profile, hash: &str) -> Result<Option<InstalledMeta>> {
    let path = profile.path.join("meta").join(format!("{hash}.json"));
    if !path.exists() {
        return Ok(None);
    }

    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("reading metadata file {}", path.display()))?;
    let meta: InstalledMeta = serde_json::from_str(&data)
        .with_context(|| format!("parsing metadata file {}", path.display()))?;
    Ok(Some(meta))
}

/// Delete metadata for a store path hash.
///
/// Removes `meta/{hash}.json`. No error if it doesn't exist.
///
/// # Errors
///
/// Returns an error if an existing file cannot be removed.
pub fn delete_meta(profile: &Profile, hash: &str) -> Result<()> {
    let path = profile.path.join("meta").join(format!("{hash}.json"));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("deleting metadata file {}", path.display())),
    }
}

/// Snapshot the current profile metadata into a generation-local `meta/` dir.
///
/// Rollback normally rebuilds profile metadata from registry metadata, but a
/// package can remain installed after its registry entry is retired. Keeping a
/// per-generation copy lets rollback restore the exact installed package state
/// even when the registry no longer advertises that store path.
///
/// Only entries matching the generation's `usr/` roots are snapshotted; any
/// stale `gen-N/meta/*.json` files are cleared first.
///
/// # Errors
///
/// Returns an error if the generation's roots cannot be read or the
/// snapshot files cannot be written.
pub fn snapshot_profile_meta_to_generation(
    profile: &Profile,
    generation: &Generation,
) -> Result<()> {
    let roots: HashSet<String> = generation
        .roots()?
        .into_iter()
        .map(|(hash, _)| hash)
        .collect();
    let meta_dir = generation.path.join("meta");
    std::fs::create_dir_all(&meta_dir)
        .with_context(|| format!("creating generation meta directory {}", meta_dir.display()))?;

    if meta_dir.is_dir() {
        for entry in std::fs::read_dir(&meta_dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().ends_with(".json") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    for meta in list_meta(profile)? {
        let hash = store_path_hash(&meta.store_path);
        if roots.contains(hash) {
            write_generation_meta(generation, hash, &meta)?;
        }
    }

    Ok(())
}

/// Write one snapshot entry to `gen-N/meta/<hash>.json` atomically.
fn write_generation_meta(generation: &Generation, hash: &str, meta: &InstalledMeta) -> Result<()> {
    let meta_dir = generation.path.join("meta");
    std::fs::create_dir_all(&meta_dir)
        .with_context(|| format!("creating generation meta directory {}", meta_dir.display()))?;
    let json = serde_json::to_string_pretty(meta)
        .with_context(|| format!("serializing generation metadata for {hash}"))?;
    let dest = meta_dir.join(format!("{hash}.json"));
    atomic_write(&dest, json.as_bytes())
        .with_context(|| format!("writing generation metadata for {hash}"))
}

/// Read one snapshot entry from `gen-N/meta/<hash>.json`, if present.
pub(crate) fn read_generation_meta(
    generation: &Generation,
    hash: &str,
) -> Result<Option<InstalledMeta>> {
    let path = generation.path.join("meta").join(format!("{hash}.json"));
    if !path.exists() {
        return Ok(None);
    }

    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("reading generation metadata file {}", path.display()))?;
    let meta: InstalledMeta = serde_json::from_str(&data)
        .with_context(|| format!("parsing generation metadata file {}", path.display()))?;
    Ok(Some(meta))
}

// ---------------------------------------------------------------------------
// Listing and filtering
// ---------------------------------------------------------------------------

/// List all metadata entries in the profile.
///
/// Reads all `meta/*.json` files. Files that fail to parse are skipped
/// with a warning printed to stderr. A missing `meta/` directory yields an
/// empty list.
///
/// # Errors
///
/// Returns an error if the `meta/` directory exists but cannot be read.
pub fn list_meta(profile: &Profile) -> Result<Vec<InstalledMeta>> {
    let meta_dir = profile.path.join("meta");
    let entries = match std::fs::read_dir(&meta_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("reading meta directory {}", meta_dir.display()));
        }
    };

    let mut results = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.ends_with(".json") {
            continue;
        }

        let path = entry.path();
        match read_and_parse(&path) {
            Ok(meta) => results.push(meta),
            Err(e) => {
                eprintln!("warning: skipping {}: {e}", path.display());
            }
        }
    }

    Ok(results)
}

/// Find all metadata entries from a specific registry.
///
/// # Errors
///
/// Returns an error if the metadata directory cannot be listed.
pub fn meta_by_registry(profile: &Profile, registry_name: &str) -> Result<Vec<InstalledMeta>> {
    let all = list_meta(profile)?;
    Ok(all
        .into_iter()
        .filter(|m| {
            m.apm
                .as_ref()
                .map(|a| a.registry == registry_name)
                .unwrap_or(false)
        })
        .collect())
}

/// Find installed packages whose source registry is no longer configured.
///
/// A package becomes *orphaned* when the registry it was installed from is
/// removed (for example via `apr remove`): the package stays installed, but it
/// can no longer be upgraded, re-verified, or re-resolved against its source.
/// This returns every installed entry whose [`ApmMeta::registry`] is absent
/// from `configured_registries` — the set of registry names still present in
/// the configuration (enabled *or* disabled; a disabled registry is not gone,
/// so its packages are not orphaned).
///
/// Entries without an `apm` section (e.g. raw cache paths) are never orphans.
///
/// [`ApmMeta::registry`]: crate::types::ApmMeta::registry
///
/// # Errors
///
/// Returns an error if the profile's `meta/` directory exists but cannot be
/// read. A missing profile yields an empty list rather than an error.
pub fn orphaned_by_registry(
    profile: &Profile,
    configured_registries: &HashSet<&str>,
) -> Result<Vec<InstalledMeta>> {
    let all = list_meta(profile)?;
    Ok(all
        .into_iter()
        .filter(|m| {
            m.apm
                .as_ref()
                .map(|a| !configured_registries.contains(a.registry.as_str()))
                .unwrap_or(false)
        })
        .collect())
}

/// Find all metadata entries where `apm.explicit = false` (auto-installed deps).
///
/// # Errors
///
/// Returns an error if the metadata directory cannot be listed.
pub fn auto_installed(profile: &Profile) -> Result<Vec<InstalledMeta>> {
    let all = list_meta(profile)?;
    Ok(all
        .into_iter()
        .filter(|m| m.apm.as_ref().map(|a| !a.explicit).unwrap_or(false))
        .collect())
}

/// Find all metadata entries where `apm.held = true`.
///
/// # Errors
///
/// Returns an error if the metadata directory cannot be listed.
pub fn held_packages(profile: &Profile) -> Result<Vec<InstalledMeta>> {
    let all = list_meta(profile)?;
    Ok(all
        .into_iter()
        .filter(|m| m.apm.as_ref().map(|a| a.held).unwrap_or(false))
        .collect())
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

/// Set the held flag on a package's metadata.
///
/// Reads the existing meta, modifies the `held` field, and writes back
/// atomically.
///
/// # Errors
///
/// Returns an error if no metadata exists for `hash`, the entry has no
/// `apm` section, or the profile or current generation metadata cannot be
/// read or written.
pub fn set_held(profile: &Profile, hash: &str, held: bool) -> Result<()> {
    let mut meta =
        read_meta(profile, hash)?.with_context(|| format!("no metadata for hash {hash}"))?;

    if let Some(ref mut apm) = meta.apm {
        apm.held = held;
    } else {
        bail!("metadata for {hash} has no apm section");
    }

    write_meta(profile, hash, &meta)?;

    if let Some(generation) = profile.current_generation()? {
        if let Some(mut generation_meta) = read_generation_meta(&generation, hash)? {
            if let Some(ref mut apm) = generation_meta.apm {
                apm.held = held;
                write_generation_meta(&generation, hash, &generation_meta)?;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Rebuild meta/ from a generation + registries
// ---------------------------------------------------------------------------

/// Rebuild `meta/` from a generation's `usr/` roots and registry data.
///
/// Used by `apm rollback` -- when switching to a previous generation,
/// `meta/` is rebuilt from that generation's roots cross-referenced with
/// the registries to recover package names, versions, and registry origin.
///
/// For each root hash in the generation, the entry comes from (in order of
/// preference): the generation's own `meta/` snapshot, the registry data
/// found via `Registry::get_by_hash`, or a minimal entry carrying just the
/// store path.
///
/// # Errors
///
/// Returns an error if the existing metadata or generation roots cannot be
/// read, or a rebuilt entry cannot be written.
pub fn rebuild_meta(
    profile: &Profile,
    generation: &Generation,
    registries: &RegistrySet,
) -> Result<()> {
    // Clear existing meta/*.json files.
    let meta_dir = profile.path.join("meta");
    if meta_dir.is_dir() {
        for entry in std::fs::read_dir(&meta_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().ends_with(".json") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let roots = generation.roots()?;

    for (hash, target) in &roots {
        // Try to find this hash in any registry.
        let mut found = None;
        for reg in registries.registries() {
            if let Some(pkg) = reg.get_by_hash(hash) {
                found = Some((reg, pkg));
                break;
            }
        }

        let meta = if let Some(meta) = read_generation_meta(generation, hash)? {
            meta
        } else if let Some((reg, pkg)) = found {
            InstalledMeta {
                store_path: pkg.store_path.clone(),
                pushed_at: now,
                pushed_by: "apm".into(),
                expires_at: None,
                is_root: true,
                last_accessed: now,
                access_count: 0,
                apm: Some(ApmMeta {
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    explicit: true,
                    registry: reg.config.name.clone(),
                    installed_at: "rebuilt".into(),
                    held: false,
                    source_drv: pkg.source_drv.clone(),
                    source_nar_hash: pkg.source_nar_hash.clone(),
                    expose: pkg.expose.clone(),
                    expose_artifact: pkg.expose_artifact.clone(),
                    config_module: pkg.config_module.clone(),
                    documentation: pkg.documentation.clone(),
                    permissions: pkg.permissions.clone(),
                    bpf_lsm: pkg.bpf_lsm.clone(),
                    attestation: pkg.attestation.clone(),
                }),
            }
        } else {
            // Minimal entry — store path from symlink target.
            InstalledMeta {
                store_path: target.to_string_lossy().into_owned(),
                pushed_at: now,
                pushed_by: "apm".into(),
                expires_at: None,
                is_root: true,
                last_accessed: now,
                access_count: 0,
                apm: None,
            }
        };

        write_meta(profile, hash, &meta)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Read and parse a single JSON metadata file.
fn read_and_parse(path: &Path) -> Result<InstalledMeta> {
    let data =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let meta: InstalledMeta =
        serde_json::from_str(&data).with_context(|| format!("parsing {}", path.display()))?;
    Ok(meta)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    use crate::types::ProfileScope;

    fn test_profile(tmp: &TempDir) -> Profile {
        Profile::open_at(tmp.path().to_path_buf(), ProfileScope::User).unwrap()
    }

    fn sample_meta(name: &str, registry: &str, explicit: bool, held: bool) -> InstalledMeta {
        InstalledMeta {
            store_path: format!("/var/lib/store/abc123-{name}-1.0"),
            pushed_at: 1707800000,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1707800000,
            access_count: 0,
            apm: Some(ApmMeta {
                name: name.into(),
                version: "1.0".into(),
                explicit,
                registry: registry.into(),
                installed_at: "2026-02-16T00:00:00Z".into(),
                held,
                source_drv: String::new(),
                source_nar_hash: String::new(),
                expose: None,
                expose_artifact: None,
                config_module: None,
                documentation: None,
                permissions: Default::default(),
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        }
    }

    fn add_usr_root(generation: &Generation, hash: &str, target: &str) {
        use std::os::unix::fs::symlink;

        let usr = generation.path.join("usr");
        std::fs::create_dir_all(&usr).unwrap();
        symlink(target, usr.join(hash)).unwrap();
    }

    // 1. write_meta + read_meta round-trip
    #[test]
    fn write_read_round_trip() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);
        let meta = sample_meta("curl", "aos-core", true, false);

        write_meta(&profile, "abc123", &meta).unwrap();

        let loaded = read_meta(&profile, "abc123").unwrap().unwrap();
        assert_eq!(loaded.store_path, meta.store_path);
        let apm = loaded.apm.unwrap();
        assert_eq!(apm.name, "curl");
        assert_eq!(apm.version, "1.0");
        assert!(apm.explicit);
        assert!(!apm.held);
        assert_eq!(apm.registry, "aos-core");
    }

    // 2. read_meta returns None for missing hash
    #[test]
    fn read_meta_missing_returns_none() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let result = read_meta(&profile, "nonexistent").unwrap();
        assert!(result.is_none());
    }

    // 3. delete_meta removes the file
    #[test]
    fn delete_meta_removes_file() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);
        let meta = sample_meta("curl", "aos-core", true, false);

        write_meta(&profile, "abc123", &meta).unwrap();
        assert!(read_meta(&profile, "abc123").unwrap().is_some());

        delete_meta(&profile, "abc123").unwrap();
        assert!(read_meta(&profile, "abc123").unwrap().is_none());
    }

    // 4. delete_meta is idempotent (no error on missing)
    #[test]
    fn delete_meta_idempotent() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        // Deleting a non-existent hash should not error.
        delete_meta(&profile, "nonexistent").unwrap();
        delete_meta(&profile, "nonexistent").unwrap();
    }

    #[test]
    fn rebuild_meta_restores_generation_snapshot_without_registry() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);
        let generation = profile.new_generation().unwrap();
        let meta = sample_meta("retired-tool", "retired-reg", true, true);
        add_usr_root(&generation, "abc123", &meta.store_path);

        write_meta(&profile, "abc123", &meta).unwrap();
        snapshot_profile_meta_to_generation(&profile, &generation).unwrap();
        delete_meta(&profile, "abc123").unwrap();

        let registries = RegistrySet::new(vec![]);
        rebuild_meta(&profile, &generation, &registries).unwrap();

        let restored = read_meta(&profile, "abc123").unwrap().unwrap();
        assert_eq!(restored.store_path, meta.store_path);
        let restored_apm = restored.apm.unwrap();
        assert_eq!(restored_apm.name, "retired-tool");
        assert_eq!(restored_apm.registry, "retired-reg");
        assert!(restored_apm.explicit);
        assert!(restored_apm.held);
    }

    // 5. list_meta returns all entries
    #[test]
    fn list_meta_returns_all() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        write_meta(
            &profile,
            "aaa111",
            &sample_meta("curl", "core", true, false),
        )
        .unwrap();
        write_meta(
            &profile,
            "bbb222",
            &sample_meta("zlib", "core", false, false),
        )
        .unwrap();
        write_meta(&profile, "ccc333", &sample_meta("jq", "extra", true, true)).unwrap();

        let all = list_meta(&profile).unwrap();
        assert_eq!(all.len(), 3);
    }

    // 6. meta_by_registry filters correctly
    #[test]
    fn meta_by_registry_filters() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        write_meta(
            &profile,
            "aaa111",
            &sample_meta("curl", "core", true, false),
        )
        .unwrap();
        write_meta(
            &profile,
            "bbb222",
            &sample_meta("zlib", "core", false, false),
        )
        .unwrap();
        write_meta(&profile, "ccc333", &sample_meta("jq", "extra", true, true)).unwrap();

        let core_pkgs = meta_by_registry(&profile, "core").unwrap();
        assert_eq!(core_pkgs.len(), 2);

        let extra_pkgs = meta_by_registry(&profile, "extra").unwrap();
        assert_eq!(extra_pkgs.len(), 1);
        assert_eq!(extra_pkgs[0].apm.as_ref().unwrap().name, "jq");

        let none_pkgs = meta_by_registry(&profile, "nonexistent").unwrap();
        assert!(none_pkgs.is_empty());
    }

    // 6b. orphaned_by_registry returns packages from unconfigured registries
    #[test]
    fn orphaned_by_registry_filters() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        write_meta(
            &profile,
            "aaa111",
            &sample_meta("curl", "core", true, false),
        )
        .unwrap();
        write_meta(
            &profile,
            "bbb222",
            &sample_meta("zlib", "core", false, false),
        )
        .unwrap();
        write_meta(&profile, "ccc333", &sample_meta("jq", "extra", true, true)).unwrap();

        // Only "core" is still configured; "extra" was removed.
        let configured: HashSet<&str> = ["core"].into_iter().collect();
        let orphans = orphaned_by_registry(&profile, &configured).unwrap();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].apm.as_ref().unwrap().name, "jq");
        assert_eq!(orphans[0].apm.as_ref().unwrap().registry, "extra");

        // With every registry configured, nothing is orphaned.
        let all_configured: HashSet<&str> = ["core", "extra"].into_iter().collect();
        assert!(
            orphaned_by_registry(&profile, &all_configured)
                .unwrap()
                .is_empty()
        );

        // With no registries configured, every apm package is orphaned.
        let none: HashSet<&str> = HashSet::new();
        assert_eq!(orphaned_by_registry(&profile, &none).unwrap().len(), 3);
    }

    // 6c. orphaned_by_registry treats a missing profile as empty (no error)
    #[test]
    fn orphaned_by_registry_missing_profile_is_empty() {
        let tmp = TempDir::new().unwrap();
        // Reference a profile path that was never initialized — no meta/ dir.
        let profile = Profile {
            path: tmp.path().join("never-created"),
            scope: ProfileScope::User,
        };

        let configured: HashSet<&str> = ["core"].into_iter().collect();
        assert!(
            orphaned_by_registry(&profile, &configured)
                .unwrap()
                .is_empty()
        );
    }

    // 7. auto_installed returns only explicit=false entries
    #[test]
    fn auto_installed_filters() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        write_meta(
            &profile,
            "aaa111",
            &sample_meta("curl", "core", true, false),
        )
        .unwrap();
        write_meta(
            &profile,
            "bbb222",
            &sample_meta("zlib", "core", false, false),
        )
        .unwrap();
        write_meta(&profile, "ccc333", &sample_meta("jq", "extra", true, true)).unwrap();

        let auto = auto_installed(&profile).unwrap();
        assert_eq!(auto.len(), 1);
        assert_eq!(auto[0].apm.as_ref().unwrap().name, "zlib");
    }

    // 8. held_packages returns only held=true entries
    #[test]
    fn held_packages_filters() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        write_meta(
            &profile,
            "aaa111",
            &sample_meta("curl", "core", true, false),
        )
        .unwrap();
        write_meta(
            &profile,
            "bbb222",
            &sample_meta("zlib", "core", false, false),
        )
        .unwrap();
        write_meta(&profile, "ccc333", &sample_meta("jq", "extra", true, true)).unwrap();

        let held = held_packages(&profile).unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].apm.as_ref().unwrap().name, "jq");
    }

    // 9. set_held modifies and persists the flag
    #[test]
    fn set_held_modifies_flag() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        write_meta(
            &profile,
            "aaa111",
            &sample_meta("curl", "core", true, false),
        )
        .unwrap();

        // Initially not held.
        let meta = read_meta(&profile, "aaa111").unwrap().unwrap();
        assert!(!meta.apm.as_ref().unwrap().held);

        // Set held = true.
        set_held(&profile, "aaa111", true).unwrap();
        let meta = read_meta(&profile, "aaa111").unwrap().unwrap();
        assert!(meta.apm.as_ref().unwrap().held);

        // Set held = false again.
        set_held(&profile, "aaa111", false).unwrap();
        let meta = read_meta(&profile, "aaa111").unwrap().unwrap();
        assert!(!meta.apm.as_ref().unwrap().held);
    }

    #[test]
    fn set_held_updates_current_generation_snapshot() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);
        let generation = profile.new_generation().unwrap();
        let meta = sample_meta("curl", "core", true, false);

        add_usr_root(&generation, "abc123", &meta.store_path);
        write_meta(&profile, "abc123", &meta).unwrap();
        snapshot_profile_meta_to_generation(&profile, &generation).unwrap();
        profile.switch_to(&generation).unwrap();

        set_held(&profile, "abc123", true).unwrap();
        let generation_meta = read_generation_meta(&generation, "abc123")
            .unwrap()
            .unwrap();
        assert!(generation_meta.apm.as_ref().unwrap().held);

        set_held(&profile, "abc123", false).unwrap();
        let generation_meta = read_generation_meta(&generation, "abc123")
            .unwrap()
            .unwrap();
        assert!(!generation_meta.apm.as_ref().unwrap().held);
    }

    // 10. set_held on missing hash returns error
    #[test]
    fn set_held_missing_hash_errors() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let result = set_held(&profile, "nonexistent", true);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no metadata for hash")
        );
    }
}
