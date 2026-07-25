//! `apm hold`, `apm unhold`, and `apm held` — upgrade holds.
//!
//! A *hold* pins an installed package at its current version: `apm upgrade`
//! skips held packages until they are released with `apm unhold`. The hold
//! flag lives in the package's profile metadata (the `held` field of
//! [`crate::types::ApmMeta`]), so it survives generation switches and is
//! visible to `apm list`/`apm held`.

use anyhow::Result;

use super::config::ApmConfig;
use super::profile::Profile;
use super::profile::meta;
use super::registry::store_path_hash;
use super::types::InstalledMeta;
use aos_core::output::{OutputMode, Printer};

/// Run `apm hold <package>` -- prevent a package from being upgraded.
///
/// # Errors
///
/// Returns an error if `package` is not installed in the profile, or if the
/// profile cannot be opened for writing (e.g. another apm process holds the
/// lock) or its metadata cannot be updated.
pub async fn run_hold(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()> {
    let profile = Profile::open_readonly(config.scope);
    let (hash, installed) = find_installed_by_name(&profile, package)?;

    let profile = Profile::open(config.scope)?;
    meta::set_held(&profile, &hash, true)?;

    if printer.mode() == OutputMode::Json {
        printer.json(&hold_result_json("hold", "held", &installed, true));
        return Ok(());
    }

    printer.success(&format!("{package} set on hold."));
    Ok(())
}

/// Run `apm unhold <package>` -- release the upgrade hold.
///
/// # Errors
///
/// Returns an error if `package` is not installed in the profile, or if the
/// profile cannot be opened for writing or its metadata cannot be updated.
pub async fn run_unhold(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()> {
    let profile = Profile::open_readonly(config.scope);
    let (hash, installed) = find_installed_by_name(&profile, package)?;

    let profile = Profile::open(config.scope)?;
    meta::set_held(&profile, &hash, false)?;

    if printer.mode() == OutputMode::Json {
        printer.json(&hold_result_json("unhold", "unheld", &installed, false));
        return Ok(());
    }

    printer.success(&format!("{package} released from hold."));
    Ok(())
}

/// Run `apm held` -- list all held packages.
///
/// # Errors
///
/// Returns an error if the profile's metadata entries cannot be read.
pub async fn run_held(config: &ApmConfig, printer: &Printer) -> Result<()> {
    let profile = Profile::open_readonly(config.scope);

    let held = meta::held_packages(&profile)?;

    if printer.mode() == OutputMode::Json {
        let json: Vec<serde_json::Value> = held
            .iter()
            .filter_map(|m| {
                let apm = m.apm.as_ref()?;
                Some(serde_json::json!({
                    "name": apm.name,
                    "version": apm.version,
                    "registry": apm.registry,
                    "store_path": m.store_path,
                }))
            })
            .collect();
        printer.json(&serde_json::json!(json));
        return Ok(());
    }

    if held.is_empty() {
        printer.info("No packages are held.");
        return Ok(());
    }

    printer.header("Held packages:");
    for m in &held {
        if let Some(ref apm) = m.apm {
            printer.plain(&format!(
                "  {} {} ({})",
                apm.name, apm.version, apm.registry
            ));
        }
    }

    Ok(())
}

/// Find installed metadata for a package by its APM name.
///
/// Iterates all metadata entries in the profile and returns the hash
/// component of the matching package's store path.
fn find_installed_by_name(profile: &Profile, name: &str) -> Result<(String, InstalledMeta)> {
    let all = meta::list_meta(profile)?;
    select_installed_by_name(all, name)
}

/// Select the installed entry a name-based hold operation should mutate.
///
/// A package name can appear more than once when an explicit root from one
/// registry shadows an automatic same-name dependency from another registry.
/// Prefer explicit roots, because `apm hold <name>` is a user-directed
/// operation on the package they installed. If only automatic entries exist,
/// preserve the historical behavior and use the first match.
fn select_installed_by_name(
    installed: Vec<InstalledMeta>,
    name: &str,
) -> Result<(String, InstalledMeta)> {
    let mut fallback = None;

    for m in installed {
        let Some(apm) = m.apm.as_ref() else {
            continue;
        };
        if apm.name != name {
            continue;
        }

        let hash = store_path_hash(&m.store_path).to_string();
        if apm.explicit {
            return Ok((hash, m));
        }
        if fallback.is_none() {
            fallback = Some((hash, m));
        }
    }

    fallback.ok_or_else(|| anyhow::anyhow!("package not found: {name}"))
}

/// Build the JSON document for a hold/unhold result, degrading gracefully
/// when the entry carries no APM metadata.
fn hold_result_json(
    action: &str,
    status: &str,
    installed: &InstalledMeta,
    held: bool,
) -> serde_json::Value {
    match installed.apm.as_ref() {
        Some(apm) => serde_json::json!({
            "action": action,
            "status": status,
            "package": apm.name,
            "name": apm.name,
            "version": apm.version,
            "registry": apm.registry,
            "store_path": installed.store_path,
            "held": held,
        }),
        None => serde_json::json!({
            "action": action,
            "status": status,
            "store_path": installed.store_path,
            "held": held,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    use crate::types::{ApmMeta, InstalledMeta, ProfileScope};
    use tempfile::TempDir;

    fn test_profile(tmp: &TempDir) -> Profile {
        Profile::open_at(tmp.path().to_path_buf(), ProfileScope::User).unwrap()
    }

    fn sample_meta(name: &str, store_path: &str, held: bool) -> InstalledMeta {
        sample_meta_with_flags(name, store_path, "aos-core", true, held)
    }

    fn sample_meta_with_flags(
        name: &str,
        store_path: &str,
        registry: &str,
        explicit: bool,
        held: bool,
    ) -> InstalledMeta {
        InstalledMeta {
            store_path: store_path.into(),
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
                permissions: Default::default(),
                bpf_lsm: None,
                attestation: Default::default(),
            }),
        }
    }

    #[test]
    fn hold_sets_held_true() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let m = sample_meta("curl", "/var/lib/store/abc123-curl-8.5.0", false);
        meta::write_meta(&profile, "abc123", &m).unwrap();

        // Verify initially not held.
        let loaded = meta::read_meta(&profile, "abc123").unwrap().unwrap();
        assert!(!loaded.apm.as_ref().unwrap().held);

        // Use find_installed_by_name + set_held (same logic as run_hold).
        let (hash, _) = find_installed_by_name(&profile, "curl").unwrap();
        meta::set_held(&profile, &hash, true).unwrap();

        let loaded = meta::read_meta(&profile, "abc123").unwrap().unwrap();
        assert!(loaded.apm.as_ref().unwrap().held);
    }

    #[test]
    fn hold_selection_prefers_explicit_duplicate_name() {
        let installed = vec![
            sample_meta_with_flags(
                "priority-tool",
                "/var/lib/store/bbb222-priority-tool-9.0.0",
                "low-priority",
                false,
                false,
            ),
            sample_meta_with_flags(
                "priority-tool",
                "/var/lib/store/ccc333-priority-tool-2.0.0",
                "high-priority",
                true,
                false,
            ),
        ];

        let (hash, selected) = select_installed_by_name(installed, "priority-tool").unwrap();

        assert_eq!(hash, "ccc333");
        let apm = selected.apm.as_ref().unwrap();
        assert_eq!(apm.registry, "high-priority");
        assert!(apm.explicit);
    }

    #[test]
    fn hold_selection_keeps_implicit_only_behavior() {
        let installed = vec![sample_meta_with_flags(
            "priority-tool",
            "/var/lib/store/bbb222-priority-tool-9.0.0",
            "low-priority",
            false,
            false,
        )];

        let (hash, selected) = select_installed_by_name(installed, "priority-tool").unwrap();

        assert_eq!(hash, "bbb222");
        let apm = selected.apm.as_ref().unwrap();
        assert_eq!(apm.registry, "low-priority");
        assert!(!apm.explicit);
    }

    #[test]
    fn unhold_sets_held_false() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let m = sample_meta("curl", "/var/lib/store/abc123-curl-8.5.0", true);
        meta::write_meta(&profile, "abc123", &m).unwrap();

        // Verify initially held.
        let loaded = meta::read_meta(&profile, "abc123").unwrap().unwrap();
        assert!(loaded.apm.as_ref().unwrap().held);

        // Unhold.
        let (hash, _) = find_installed_by_name(&profile, "curl").unwrap();
        meta::set_held(&profile, &hash, false).unwrap();

        let loaded = meta::read_meta(&profile, "abc123").unwrap().unwrap();
        assert!(!loaded.apm.as_ref().unwrap().held);
    }

    #[test]
    fn hold_nonexistent_package_errors() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let result = find_installed_by_name(&profile, "nonexistent");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("package not found")
        );
    }

    #[test]
    fn held_lists_only_held_packages() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        meta::write_meta(
            &profile,
            "aaa111",
            &sample_meta("curl", "/var/lib/store/aaa111-curl-8.5.0", true),
        )
        .unwrap();
        meta::write_meta(
            &profile,
            "bbb222",
            &sample_meta("zlib", "/var/lib/store/bbb222-zlib-1.3.1", false),
        )
        .unwrap();
        meta::write_meta(
            &profile,
            "ccc333",
            &sample_meta("jq", "/var/lib/store/ccc333-jq-1.7", true),
        )
        .unwrap();

        let held = meta::held_packages(&profile).unwrap();
        assert_eq!(held.len(), 2);

        let names: Vec<&str> = held
            .iter()
            .map(|m| m.apm.as_ref().unwrap().name.as_str())
            .collect();
        assert!(names.contains(&"curl"));
        assert!(names.contains(&"jq"));
        assert!(!names.contains(&"zlib"));
    }
}
