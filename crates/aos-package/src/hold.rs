use anyhow::{bail, Result};

use super::config::ApmConfig;
use super::profile::meta;
use super::profile::Profile;
use super::registry::store_path_hash;
use aos_core::output::Printer;

/// Run `apm hold <package>` -- prevent a package from being upgraded.
pub async fn run_hold(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()> {
    let profile = Profile::open(config.scope)?;

    let hash = find_hash_by_name(&profile, package)?;
    meta::set_held(&profile, &hash, true)?;

    printer.success(&format!("{package} set on hold."));
    Ok(())
}

/// Run `apm unhold <package>` -- release the upgrade hold.
pub async fn run_unhold(config: &ApmConfig, package: &str, printer: &Printer) -> Result<()> {
    let profile = Profile::open(config.scope)?;

    let hash = find_hash_by_name(&profile, package)?;
    meta::set_held(&profile, &hash, false)?;

    printer.success(&format!("{package} released from hold."));
    Ok(())
}

/// Run `apm held` -- list all held packages.
pub async fn run_held(config: &ApmConfig, printer: &Printer) -> Result<()> {
    let profile = Profile::open(config.scope)?;

    let held = meta::held_packages(&profile)?;

    if held.is_empty() {
        printer.info("No packages are held.");
        return Ok(());
    }

    printer.header("Held packages:");
    for m in &held {
        if let Some(ref apm) = m.apm {
            printer.plain(&format!("  {} {} ({})", apm.name, apm.version, apm.registry));
        }
    }

    Ok(())
}

/// Find the store-path hash for a package by its APM name.
///
/// Iterates all metadata entries in the profile and returns the hash
/// component of the matching package's store path.
fn find_hash_by_name(profile: &Profile, name: &str) -> Result<String> {
    let all = meta::list_meta(profile)?;
    for m in &all {
        if let Some(ref apm) = m.apm {
            if apm.name == name {
                return Ok(store_path_hash(&m.store_path).to_string());
            }
        }
    }
    bail!("package not found: {name}");
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
                explicit: true,
                registry: "aos-core".into(),
                installed_at: "2026-02-16T00:00:00Z".into(),
                held,
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

        // Use find_hash_by_name + set_held (same logic as run_hold).
        let hash = find_hash_by_name(&profile, "curl").unwrap();
        meta::set_held(&profile, &hash, true).unwrap();

        let loaded = meta::read_meta(&profile, "abc123").unwrap().unwrap();
        assert!(loaded.apm.as_ref().unwrap().held);
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
        let hash = find_hash_by_name(&profile, "curl").unwrap();
        meta::set_held(&profile, &hash, false).unwrap();

        let loaded = meta::read_meta(&profile, "abc123").unwrap().unwrap();
        assert!(!loaded.apm.as_ref().unwrap().held);
    }

    #[test]
    fn hold_nonexistent_package_errors() {
        let tmp = TempDir::new().unwrap();
        let profile = test_profile(&tmp);

        let result = find_hash_by_name(&profile, "nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("package not found"));
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
