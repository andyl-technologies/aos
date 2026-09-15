//! Fleet-managed BPF-LSM policy selection.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::types::{validate_package_name, validate_registry_name};

/// Default host policy path on an AOS system.
pub const DEFAULT_POLICY_PATH: &str = "/etc/aos/policy.toml";

pub(crate) fn policy_root() -> PathBuf {
    std::env::var("AOS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/"))
}

/// Parsed host selection for fleet-managed BPF-LSM policy artifacts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPolicy {
    /// Fleet-managed BPF-LSM policy packages selected for this host.
    #[serde(default, rename = "ebpf-lsm")]
    pub ebpf_lsm: EbpfLsmPolicySet,
}

impl HostPolicy {
    /// Parses and validates host BPF-LSM policy selection.
    ///
    /// # Errors
    ///
    /// Returns an error when the TOML or an artifact reference is invalid.
    pub fn parse_str(content: &str) -> Result<Self> {
        let policy: Self = toml::from_str(content).context("invalid AOS policy TOML")?;
        policy.ebpf_lsm.validate()?;
        Ok(policy)
    }

    /// Loads host BPF-LSM policy selection from an explicit path.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or parsed.
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse_str(&content).with_context(|| format!("parsing {}", path.display()))
    }
}

/// Fleet-managed BPF-LSM policy references selected by host policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EbpfLsmPolicySet {
    /// Signed policy packages to load on this host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<EbpfLsmPolicyRef>,
}

impl EbpfLsmPolicySet {
    fn validate(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for policy in &self.policies {
            policy.validate()?;
            if !seen.insert(&policy.name) {
                bail!("duplicate ebpf-lsm policy '{}'", policy.name);
            }
        }
        Ok(())
    }
}

/// A signed registry package and artifact paths for one fleet BPF-LSM policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EbpfLsmPolicyRef {
    /// Stable policy name used for bpffs link pins.
    pub name: String,
    /// Registry that supplied the installed policy package.
    pub registry: String,
    /// Installed package carrying the BPF-LSM policy artifact.
    pub package: String,
    /// Exact package version selected by fleet policy.
    pub version: String,
    /// Relative JSON policy path inside the installed package root.
    pub policy: String,
    /// Relative BPF object path inside the installed package root.
    pub object: String,
    /// BPF program names expected in the object and policy JSON.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub programs: Vec<String>,
}

impl EbpfLsmPolicyRef {
    fn validate(&self) -> Result<()> {
        validate_safe_label("ebpf-lsm policy name", &self.name)?;
        validate_registry_name(&self.registry)?;
        validate_package_name(&self.package)?;
        validate_version(&self.version)?;
        validate_relative_artifact_path("ebpf-lsm policy", &self.policy, ".json")?;
        validate_relative_artifact_path("ebpf-lsm object", &self.object, ".bpf.o")?;
        if self.programs.is_empty() {
            bail!(
                "ebpf-lsm policy '{}' must name at least one program",
                self.name
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for program in &self.programs {
            validate_bpf_program_name(program)?;
            if !seen.insert(program) {
                bail!(
                    "ebpf-lsm policy '{}' contains duplicate program '{}'",
                    self.name,
                    program
                );
            }
        }
        Ok(())
    }
}

fn validate_version(version: &str) -> Result<()> {
    if version.is_empty()
        || version
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '/' | '\\'))
    {
        bail!("invalid ebpf-lsm package version '{version}'");
    }
    Ok(())
}

fn validate_relative_artifact_path(kind: &str, path: &str, suffix: &str) -> Result<()> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') || !path.ends_with(suffix) {
        bail!("{kind} path '{path}' must be a relative *{suffix} path");
    }
    for component in Path::new(path).components() {
        match component {
            std::path::Component::Normal(part) if !part.is_empty() => {}
            _ => bail!("{kind} path '{path}' must not contain '.', '..', or prefixes"),
        }
    }
    Ok(())
}

fn validate_safe_label(kind: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        bail!("invalid {kind} '{value}'");
    }
    Ok(())
}

fn validate_bpf_program_name(program: &str) -> Result<()> {
    let mut chars = program.chars();
    let Some(first) = chars.next() else {
        bail!("BPF program name must not be empty");
    };
    if !(first == '_' || first.is_ascii_alphabetic())
        || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        bail!("invalid BPF program name '{program}'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ebpf_lsm_policy_selection() {
        let policy = HostPolicy::parse_str(
            r#"
[[ebpf-lsm.policies]]
name = "aos-lsm-task-audit"
registry = "aos"
package = "aos-ebpf-lsm-policy"
version = "0"
policy = "share/aos/ebpf-lsm/aos-task-audit.json"
object = "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o"
programs = ["aos_lsm_file_mprotect"]
"#,
        )
        .unwrap();

        assert_eq!(policy.ebpf_lsm.policies.len(), 1);
        assert_eq!(
            policy.ebpf_lsm.policies[0].object,
            "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o"
        );
    }

    #[test]
    fn rejects_unsafe_ebpf_lsm_policy_references() {
        let err = HostPolicy::parse_str(
            r#"
[[ebpf-lsm.policies]]
name = "bad"
registry = "aos"
package = "aos-ebpf-lsm-policy"
version = "0"
policy = "../policy.json"
object = "lib/bpf/aos-ebpf-lsm-task-audit.bpf.o"
programs = ["aos_lsm_file_mprotect"]
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must not contain"));
    }
}
