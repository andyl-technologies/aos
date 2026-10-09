//! Declarative desired-package reconciliation for install-at-boot.
//!
//! `desired.toml` is written by the signed host-configuration path or another host-authoritative
//! provisioner. The reconciler treats its package list as the set of explicit
//! APM package roots that should exist in the selected profile: missing names
//! are installed, and explicit installed names absent from the file are
//! removed.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::config::ApmConfig;
use crate::install;
use crate::profile::Profile;
use crate::profile::meta::list_meta;
use crate::remove;
use crate::sysroot_lock::IgnoreSysrootLock;
use crate::types::validate_package_name;
use aos_core::output::{OutputMode, Printer};

/// The default host-authored desired package set.
pub const DEFAULT_DESIRED_PATH: &str = "/etc/aos/packages.d/desired.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredToml {
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    desired: Option<DesiredSection>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredSection {
    #[serde(default)]
    packages: Vec<String>,
}

/// Reconcile explicit APM roots against a desired-package file.
///
/// # Errors
///
/// Returns an error if the desired file cannot be read or parsed, a package
/// name is invalid, registry update/install/remove fails, or the user declines
/// a confirmation prompt.
pub async fn reconcile_from_file(
    config: &ApmConfig,
    path: &Path,
    dry_run: bool,
    yes: bool,
    printer: &Printer,
) -> Result<()> {
    let desired_file = DesiredFile::from_path(path)?;
    let desired = desired_file.packages;
    let profile = Profile::open_readonly(config.scope);
    let installed_before_meta = list_meta(&profile)?;
    let installed_before = explicit_installed_packages_from_meta(&installed_before_meta);

    let additions = desired
        .difference(&installed_before)
        .cloned()
        .collect::<Vec<_>>();

    if !dry_run
        && !additions.is_empty()
        && let Err(err) = crate::update::run(config, None, printer).await
    {
        printer.warning(&format!(
            "registry update failed before desired package reconciliation; continuing with cached metadata: {err:#}"
        ));
    }

    if !additions.is_empty() {
        install::run(
            config,
            &additions,
            None,
            false,
            false,
            false,
            false,
            dry_run,
            yes,
            &IgnoreSysrootLock::Enforce,
            printer,
        )
        .await
        .context("installing desired packages")?;
    }

    let installed_after_add = if dry_run {
        installed_before
    } else {
        explicit_installed_packages(config)?
    };
    let removals = installed_after_add
        .difference(&desired)
        .cloned()
        .collect::<Vec<_>>();

    if !removals.is_empty() {
        remove::run(config, &removals, true, dry_run, yes, printer)
            .await
            .context("removing packages absent from desired package set")?;
    }

    if printer.mode() == OutputMode::Json {
        printer.json(&serde_json::json!({
            "action": "reconcile-desired",
            "status": if additions.is_empty() && removals.is_empty() {
                "current"
            } else if dry_run {
                "planned"
            } else {
                "reconciled"
            },
            "desired": desired,
            "install": additions,
            "remove": removals,
            "dry_run": dry_run,
        }));
    } else if additions.is_empty() && removals.is_empty() {
        printer.info("Desired package set is already current.");
    }

    Ok(())
}

#[derive(Debug)]
struct DesiredFile {
    packages: BTreeSet<String>,
}

impl DesiredFile {
    fn from_path(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading desired package file {}", path.display()))?;
        Self::from_str(&content).with_context(|| format!("parsing {}", path.display()))
    }

    fn from_str(content: &str) -> Result<Self> {
        let parsed: DesiredToml =
            toml::from_str(content).context("invalid desired package TOML")?;
        let top_level_present = !parsed.packages.is_empty();
        let names = match parsed.desired {
            Some(desired) if !desired.packages.is_empty() => {
                if top_level_present {
                    bail!("desired package file must not mix top-level keys with [desired]");
                }
                desired.packages
            }
            _ => parsed.packages,
        };

        let mut set = BTreeSet::new();
        for name in names {
            validate_package_name(&name)
                .with_context(|| format!("invalid desired package name '{name}'"))?;
            set.insert(name);
        }
        Ok(Self { packages: set })
    }
}

#[cfg(test)]
fn desired_packages_from_str(content: &str) -> Result<BTreeSet<String>> {
    Ok(DesiredFile::from_str(content)?.packages)
}
fn explicit_installed_packages(config: &ApmConfig) -> Result<BTreeSet<String>> {
    let profile = Profile::open_readonly(config.scope);
    let installed = list_meta(&profile)?;
    Ok(explicit_installed_packages_from_meta(&installed))
}

fn explicit_installed_packages_from_meta(
    installed: &[crate::types::InstalledMeta],
) -> BTreeSet<String> {
    installed
        .iter()
        .filter_map(|meta| {
            let apm = meta.apm.as_ref()?;
            apm.explicit.then(|| apm.name.clone())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desired_packages_parse_top_level_list() {
        let packages = desired_packages_from_str(
            r#"
packages = ["web", "worker", "web"]
"#,
        )
        .unwrap();
        assert_eq!(
            packages.into_iter().collect::<Vec<_>>(),
            vec!["web".to_string(), "worker".to_string()]
        );
    }

    #[test]
    fn desired_packages_parse_nested_section() {
        let packages = desired_packages_from_str(
            r#"
[desired]
packages = ["k3s-worker"]
"#,
        )
        .unwrap();
        assert_eq!(
            packages.into_iter().collect::<Vec<_>>(),
            vec!["k3s-worker".to_string()]
        );
    }

    #[test]
    fn desired_file_rejects_legacy_credentials() {
        let err = DesiredFile::from_str(
            r#"
packages = ["web"]

[credentials.web.join-token]
system-credential = "bootstrap-token"
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("invalid desired package TOML"));
    }

    #[test]
    fn desired_file_rejects_mixed_top_level_and_nested_forms() {
        let err = DesiredFile::from_str(
            r#"
packages = ["web"]

[desired]
packages = ["worker"]
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("must not mix"));
    }

    #[test]
    fn desired_packages_reject_path_like_names() {
        let err = desired_packages_from_str(r#"packages = ["../bad"]"#).unwrap_err();
        assert!(err.to_string().contains("invalid desired package name"));
    }
}
