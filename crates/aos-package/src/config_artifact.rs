//! Desired-package config artifact materialization.
//!
//! `apm install --system --from desired.toml` accepts package-scoped config
//! values keyed by package and artifact name. This module validates those
//! values against the signed RFC-0001 `expose.config` metadata persisted in the
//! package profile, writes the materialized files under `/etc/aos/packages`,
//! and applies the declared reload/restart policy for changed artifacts.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use aos_core::output::Printer;

use crate::config::ApmConfig;
use crate::desired::DesiredPackageConfig;
use crate::profile::Profile;
use crate::profile::meta::list_meta;
use crate::types::{
    ConfigArtifactFormat, ConfigArtifactMeta, ConfigReloadPolicy, InstalledMeta, ProfileScope,
    validate_config_field_name,
};

/// Materialize desired package config artifacts.
///
/// Returns `true` when one or more materialized files changed.
///
/// # Errors
///
/// Returns an error when desired config references an unknown package or
/// artifact, omits a required field, includes undeclared fields, cannot be
/// serialized, or cannot be written.
pub(crate) async fn reconcile_desired_config(
    config: &ApmConfig,
    desired: &DesiredPackageConfig,
    printer: &Printer,
) -> Result<bool> {
    if config.scope != ProfileScope::System {
        return Ok(false);
    }

    let profile = Profile::open_readonly(ProfileScope::System);
    let installed = list_meta(&profile)?;
    let root = aos_root_path();
    let mut changed = false;
    let mut handled_packages = BTreeSet::new();
    let mut reload_units = BTreeSet::new();
    let mut restart_units = BTreeSet::new();

    for entry in installed.iter().filter(|entry| {
        entry
            .apm
            .as_ref()
            .is_some_and(|apm| apm.explicit && apm.expose.is_some())
    }) {
        let Some(apm) = entry.apm.as_ref() else {
            continue;
        };
        let Some(expose) = apm.expose.as_ref() else {
            continue;
        };
        if expose.config.is_empty() {
            continue;
        }
        handled_packages.insert(apm.name.clone());
        let desired_package = desired.get(&apm.name);
        changed |= materialize_package_config(
            &root,
            &apm.name,
            entry,
            desired_package,
            &mut reload_units,
            &mut restart_units,
        )?;
    }

    for package in desired.keys() {
        if !handled_packages.contains(package) {
            bail!("desired config references package '{package}' without signed config metadata");
        }
    }

    if changed {
        apply_config_reconciliation(&root, reload_units, restart_units)?;
        printer.info("Reconciled desired package config artifacts.");
    }

    Ok(changed)
}

fn materialize_package_config(
    root: &Path,
    package: &str,
    installed: &InstalledMeta,
    desired_package: Option<&BTreeMap<String, BTreeMap<String, toml::Value>>>,
    reload_units: &mut BTreeSet<String>,
    restart_units: &mut BTreeSet<String>,
) -> Result<bool> {
    let apm = installed
        .apm
        .as_ref()
        .context("installed package missing apm metadata")?;
    let expose = apm
        .expose
        .as_ref()
        .context("installed package missing expose metadata")?;
    let desired_package = desired_package.cloned().unwrap_or_default();
    let mut known_artifacts = BTreeSet::new();
    let mut changed = false;

    for artifact in &expose.config.artifacts {
        known_artifacts.insert(artifact.name.clone());
        let values = desired_package
            .get(&artifact.name)
            .cloned()
            .unwrap_or_default();
        validate_artifact_values(package, artifact, &values)?;
        let bytes = render_artifact(artifact, &values)?;
        if write_artifact(root, &artifact.path, &bytes)? {
            changed = true;
            match artifact.reload {
                ConfigReloadPolicy::Reload => reload_units.extend(artifact.units.iter().cloned()),
                ConfigReloadPolicy::Restart => {
                    restart_units.extend(artifact.units.iter().cloned());
                }
                ConfigReloadPolicy::None => {}
            }
        }
    }

    for artifact in desired_package.keys() {
        if !known_artifacts.contains(artifact) {
            bail!(
                "desired config for package '{package}' references unknown artifact '{artifact}'"
            );
        }
    }

    Ok(changed)
}

fn validate_artifact_values(
    package: &str,
    artifact: &ConfigArtifactMeta,
    values: &BTreeMap<String, toml::Value>,
) -> Result<()> {
    let required = artifact.required.iter().collect::<BTreeSet<_>>();
    let optional = artifact.optional.iter().collect::<BTreeSet<_>>();
    for field in &artifact.required {
        if !values.contains_key(field) {
            bail!(
                "desired config for package '{package}' artifact '{}' is missing required field '{field}'",
                artifact.name
            );
        }
    }
    for field in values.keys() {
        validate_config_field_name(field)?;
        if !required.contains(field) && !optional.contains(field) {
            bail!(
                "desired config for package '{package}' artifact '{}' contains undeclared field '{field}'",
                artifact.name
            );
        }
    }
    Ok(())
}

fn render_artifact(
    artifact: &ConfigArtifactMeta,
    values: &BTreeMap<String, toml::Value>,
) -> Result<Vec<u8>> {
    let text = match artifact.format {
        ConfigArtifactFormat::Env => render_env(values)?,
        ConfigArtifactFormat::Json => {
            serde_json::to_string_pretty(values).context("serializing config artifact as JSON")?
                + "\n"
        }
        ConfigArtifactFormat::Toml => {
            toml::to_string(values).context("serializing config artifact as TOML")?
        }
    };
    Ok(text.into_bytes())
}

fn render_env(values: &BTreeMap<String, toml::Value>) -> Result<String> {
    let mut out = String::new();
    for (key, value) in values {
        out.push_str(key);
        out.push('=');
        out.push_str(&env_value(value).with_context(|| format!("rendering env field '{key}'"))?);
        out.push('\n');
    }
    Ok(out)
}

fn env_value(value: &toml::Value) -> Result<String> {
    match value {
        toml::Value::String(value) => Ok(shell_quote(value)),
        toml::Value::Integer(value) => Ok(value.to_string()),
        toml::Value::Float(value) => Ok(value.to_string()),
        toml::Value::Boolean(value) => Ok(if *value { "true" } else { "false" }.into()),
        _ => bail!("env artifacts only support string, integer, float, or boolean fields"),
    }
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '/' | ':' | '@'))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn write_artifact(root: &Path, path: &str, bytes: &[u8]) -> Result<bool> {
    let persistent = persistent_path(root, path)?;
    let live = live_path(root, path)?;
    let changed = std::fs::read(&persistent)
        .map(|old| old != bytes)
        .unwrap_or(true);
    for target in [persistent, live] {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(&target, bytes).with_context(|| format!("writing {}", target.display()))?;
    }
    Ok(changed)
}

fn persistent_path(root: &Path, path: &str) -> Result<PathBuf> {
    let rel = Path::new(path)
        .strip_prefix("/etc")
        .with_context(|| format!("config artifact path must be under /etc: {path}"))?;
    Ok(root.join("var/etc").join(rel))
}

fn live_path(root: &Path, path: &str) -> Result<PathBuf> {
    let rel = Path::new(path)
        .strip_prefix("/")
        .with_context(|| format!("config artifact path must be absolute: {path}"))?;
    Ok(root.join(rel))
}

fn apply_config_reconciliation(
    root: &Path,
    reload_units: BTreeSet<String>,
    restart_units: BTreeSet<String>,
) -> Result<()> {
    if root != Path::new("/") {
        return Ok(());
    }

    for unit in reload_units.difference(&restart_units) {
        run_systemctl(
            &["reload-or-restart", unit],
            "reload changed package config",
        )?;
    }
    for unit in restart_units {
        run_systemctl(&["restart", &unit], "restart changed package config")?;
    }
    Ok(())
}

fn run_systemctl(args: &[&str], action: &str) -> Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("running systemctl to {action}"))?;
    if !status.success() {
        bail!("systemctl failed to {action}: {status}");
    }
    Ok(())
}

fn aos_root_path() -> PathBuf {
    match std::env::var("AOS_ROOT") {
        Ok(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                path
            } else {
                PathBuf::from("/").join(path)
            }
        }
        _ => PathBuf::from("/"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ApmMeta, ExposeConfigMeta, ExposeMeta};
    use tempfile::TempDir;

    fn installed_with_config() -> InstalledMeta {
        InstalledMeta {
            store_path: "/nix/store/pkghash111-web".into(),
            pushed_at: 1,
            pushed_by: "apm".into(),
            expires_at: None,
            is_root: true,
            last_accessed: 1,
            access_count: 0,
            apm: Some(ApmMeta {
                name: "web".into(),
                version: "1.0".into(),
                explicit: true,
                registry: "test".into(),
                installed_at: "2026-06-16T00:00:00Z".into(),
                held: false,
                source_drv: String::new(),
                source_nar_hash: String::new(),
                expose: Some(ExposeMeta {
                    target: "aos-pkg-web.target".into(),
                    units: vec!["web.service".into()],
                    images: Vec::new(),
                    requires: Vec::new(),
                    config: ExposeConfigMeta {
                        artifacts: vec![ConfigArtifactMeta {
                            name: "env".into(),
                            path: "/etc/aos/packages/web/config.env".into(),
                            format: ConfigArtifactFormat::Env,
                            required: vec!["TOKEN".into()],
                            optional: vec!["URL".into()],
                            units: vec!["web.service".into()],
                            reload: ConfigReloadPolicy::Reload,
                        }],
                        credentials: Vec::new(),
                    },
                    provides: Vec::new(),
                    uses: Vec::new(),
                }),
                expose_artifact: None,
                permissions: Default::default(),
            }),
        }
    }

    #[test]
    fn materialize_package_config_writes_persistent_and_live_artifacts() {
        let tmp = TempDir::new().unwrap();
        let installed = installed_with_config();
        let mut package = BTreeMap::new();
        let mut artifact = BTreeMap::new();
        artifact.insert("TOKEN".into(), toml::Value::String("abc 123".into()));
        package.insert("env".into(), artifact);

        let mut reload = BTreeSet::new();
        let mut restart = BTreeSet::new();
        let changed = materialize_package_config(
            tmp.path(),
            "web",
            &installed,
            Some(&package),
            &mut reload,
            &mut restart,
        )
        .unwrap();

        assert!(changed);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("var/etc/aos/packages/web/config.env"))
                .unwrap(),
            "TOKEN='abc 123'\n"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("etc/aos/packages/web/config.env")).unwrap(),
            "TOKEN='abc 123'\n"
        );
        assert!(reload.contains("web.service"));
        assert!(restart.is_empty());
    }

    #[test]
    fn materialize_package_config_rejects_missing_required_fields() {
        let tmp = TempDir::new().unwrap();
        let installed = installed_with_config();
        let package = BTreeMap::new();
        let mut reload = BTreeSet::new();
        let mut restart = BTreeSet::new();

        let err = materialize_package_config(
            tmp.path(),
            "web",
            &installed,
            Some(&package),
            &mut reload,
            &mut restart,
        )
        .unwrap_err();

        assert!(err.to_string().contains("missing required field"));
    }
}
