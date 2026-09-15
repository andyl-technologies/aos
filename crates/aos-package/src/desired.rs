//! Declarative desired-package reconciliation for install-at-boot.
//!
//! `desired.toml` is written by the signed host-configuration path or another host-authoritative
//! provisioner. The reconciler treats its package list as the set of explicit
//! APM package roots that should exist in the selected profile: missing names
//! are installed, and explicit installed names absent from the file are
//! removed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::config::ApmConfig;
use crate::install;
use crate::profile::Profile;
use crate::profile::meta::list_meta;
use crate::remove;
use crate::resolve;
use crate::sysroot_lock::IgnoreSysrootLock;
use crate::types::validate_package_name;
use aos_core::output::{OutputMode, Printer};

/// The default host-authored desired package set.
pub const DEFAULT_DESIRED_PATH: &str = "/etc/aos/packages.d/desired.toml";

#[derive(Debug, Default, Deserialize)]
struct DesiredToml {
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    config: DesiredPackageConfig,
    #[serde(default)]
    credentials: DesiredPackageCredentials,
    #[serde(default)]
    desired: Option<DesiredSection>,
}

#[derive(Debug, Default, Deserialize)]
struct DesiredSection {
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    config: DesiredPackageConfig,
    #[serde(default)]
    credentials: DesiredPackageCredentials,
}

/// Desired config values keyed by package, artifact, and field name.
pub(crate) type DesiredPackageConfig =
    BTreeMap<String, BTreeMap<String, BTreeMap<String, toml::Value>>>;
/// Desired credential values keyed by package and credential name.
pub(crate) type DesiredPackageCredentials =
    BTreeMap<String, BTreeMap<String, DesiredCredentialValue>>;

/// Loads only the credential resolver inputs from a desired-package file.
///
/// # Errors
///
/// Returns an error when the file cannot be read or its TOML contract is
/// malformed.
pub(crate) fn load_desired_credentials(path: &Path) -> Result<DesiredPackageCredentials> {
    Ok(DesiredFile::from_path(path)?.credentials)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub(crate) enum DesiredCredentialValue {
    Plaintext(String),
    Source(DesiredCredentialSource),
}

impl From<String> for DesiredCredentialValue {
    fn from(value: String) -> Self {
        Self::Plaintext(value)
    }
}

impl From<&str> for DesiredCredentialValue {
    fn from(value: &str) -> Self {
        Self::Plaintext(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct DesiredCredentialSource {
    pub(crate) system_credential: String,
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

    let resolved_additions = if additions.is_empty() {
        Vec::new()
    } else {
        let registries = install::load_registries(config)
            .context("loading registries for desired package preflight")?;
        resolve::resolve_multiple(&registries, &additions, None)
            .context("resolving desired additions for package preflight")?
    };
    let resolved_addition_roots = resolved_additions
        .iter()
        .map(|closure| closure.root.clone())
        .collect::<Vec<_>>();
    crate::config_artifact::preflight_desired_config(
        config,
        &desired_file.config,
        &desired,
        &installed_before_meta,
        &resolved_addition_roots,
    )
    .context("preflighting desired package config")?;
    crate::credential_artifact::preflight_desired_credentials(
        config,
        &desired_file.credentials,
        &desired,
        &installed_before_meta,
        &resolved_addition_roots,
    )
    .context("preflighting desired package credentials")?;

    if !additions.is_empty() {
        install::run_deferred_expose_reconcile(
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
        remove::run_deferred_expose_reconcile(config, &removals, true, dry_run, yes, printer)
            .await
            .context("removing packages absent from desired package set")?;
    }

    let config_reconciliation = if dry_run {
        crate::config_artifact::ConfigReconciliation::default()
    } else {
        crate::config_artifact::reconcile_desired_config(config, &desired_file.config, printer)
            .await
            .context("reconciling desired package config")?
    };
    let credential_reconciliation = if dry_run {
        crate::credential_artifact::CredentialReconciliation::default()
    } else {
        crate::credential_artifact::reconcile_desired_credentials(
            config,
            &desired_file.credentials,
            printer,
        )
        .await
        .context("reconciling desired package credentials")?
    };
    let changed_config = config_reconciliation.changed();
    let changed_credentials = credential_reconciliation.changed();

    let profile_changed = !additions.is_empty() || !removals.is_empty();
    if (profile_changed || changed_config || changed_credentials) && !dry_run {
        crate::exposed_units::reconcile_system_profile(config, printer)
            .await
            .context("reconciling exposed package units")?;
        config_reconciliation
            .apply()
            .context("applying desired package config service changes")?;
        credential_reconciliation
            .apply()
            .context("applying desired package credential service changes")?;
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
            "config_changed": changed_config,
            "credentials_changed": changed_credentials,
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
    config: DesiredPackageConfig,
    credentials: DesiredPackageCredentials,
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
        let top_level_present = !parsed.packages.is_empty()
            || !parsed.config.is_empty()
            || !parsed.credentials.is_empty();
        let (names, config, credentials) = match parsed.desired {
            Some(desired)
                if !desired.packages.is_empty()
                    || !desired.config.is_empty()
                    || !desired.credentials.is_empty() =>
            {
                if top_level_present {
                    bail!("desired package file must not mix top-level keys with [desired]");
                }
                (desired.packages, desired.config, desired.credentials)
            }
            _ => (parsed.packages, parsed.config, parsed.credentials),
        };

        let mut set = BTreeSet::new();
        for name in names {
            validate_package_name(&name)
                .with_context(|| format!("invalid desired package name '{name}'"))?;
            set.insert(name);
        }
        for name in config.keys() {
            validate_package_name(name)
                .with_context(|| format!("invalid desired config package name '{name}'"))?;
        }
        for (package, package_credentials) in &credentials {
            validate_package_name(package)
                .with_context(|| format!("invalid desired credential package name '{package}'"))?;
            for name in package_credentials.keys() {
                crate::types::validate_credential_name(name).with_context(|| {
                    format!("invalid desired credential name '{package}.{name}'")
                })?;
            }
            for (name, value) in package_credentials {
                if let DesiredCredentialValue::Source(source) = value {
                    crate::types::validate_credential_name(&source.system_credential)
                        .with_context(|| {
                            format!(
                                "invalid desired system credential name '{}.{}'",
                                package, name
                            )
                        })?;
                }
            }
        }

        Ok(Self {
            packages: set,
            config,
            credentials,
        })
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
    fn desired_file_parse_nested_config() {
        let desired = DesiredFile::from_str(
            r#"
[desired]
packages = ["web"]

[desired.config.web.env]
TOKEN = "abc"
"#,
        )
        .unwrap();

        assert!(desired.packages.contains("web"));
        assert_eq!(desired.config["web"]["env"]["TOKEN"].as_str(), Some("abc"));
    }

    #[test]
    fn desired_file_parse_nested_credentials() {
        let desired = DesiredFile::from_str(
            r#"
[desired]
packages = ["web"]

[desired.credentials.web]
join-token = "secret"
"#,
        )
        .unwrap();

        assert!(desired.packages.contains("web"));
        assert_eq!(
            desired.credentials["web"]["join-token"],
            DesiredCredentialValue::Plaintext("secret".to_string())
        );
    }

    #[test]
    fn desired_file_parse_system_credential_reference() {
        let desired = DesiredFile::from_str(
            r#"
[desired]
packages = ["web"]

[desired.credentials.web]
join-token = { system-credential = "bootstrap-token" }
"#,
        )
        .unwrap();

        let DesiredCredentialValue::Source(source) = &desired.credentials["web"]["join-token"]
        else {
            panic!("expected system credential source");
        };
        assert_eq!(source.system_credential, "bootstrap-token");
    }

    #[test]
    fn desired_file_parse_system_credential_reference_table() {
        let desired = DesiredFile::from_str(
            r#"
packages = ["web"]

[credentials.web.join-token]
system-credential = "bootstrap-token"
"#,
        )
        .unwrap();

        let DesiredCredentialValue::Source(source) = &desired.credentials["web"]["join-token"]
        else {
            panic!("expected system credential source");
        };
        assert_eq!(source.system_credential, "bootstrap-token");
    }

    #[test]
    fn desired_file_rejects_system_credential_unknown_fields() {
        let err = DesiredFile::from_str(
            r#"
packages = ["web"]

[credentials.web.join-token]
system-credential = "bootstrap-token"
plaintext = "secret"
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

[desired.credentials.worker]
join-token = "secret"
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

    #[test]
    fn desired_credentials_reject_invalid_names() {
        let err = DesiredFile::from_str(
            r#"
packages = ["web"]

[credentials.web]
"bad/name" = "secret"
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("invalid desired credential name"));
    }

    #[test]
    fn desired_credentials_reject_invalid_system_credential_names() {
        let err = DesiredFile::from_str(
            r#"
packages = ["web"]

[credentials.web]
join-token = { system-credential = "bad/name" }
"#,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid desired system credential name")
        );
    }
}
