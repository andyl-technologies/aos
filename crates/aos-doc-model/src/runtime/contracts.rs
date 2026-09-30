//! Source-generated ability versions and module dependency requirements.
//!
//! These declarations describe interfaces independently of package versions.
//! Reading them neither selects a compatible provider nor authenticates a release.
//!
//! ```json
//! {"abilityContracts":{"service":{"version":"1.2.3","owner":"service-interface"}},
//!  "moduleRequirements":[{"owner":"web-server","package":"service-interface",
//!    "abilities":{"service":"^1.2"},"packageVersion":"^7"}]}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{ModuleReference, invalid};
use crate::Result;

/// Identifies the declared version and owning package of one stable ability name.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AbilityContract {
    /// Records the ability interface's semantic version, independently of its package.
    pub version: String,
    /// Names the package declaring this interface version.
    pub owner: String,
}

/// Describes a ranged module dependency declared by one requesting owner.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModuleRequirement {
    /// Names the module owner requesting the dependency.
    pub owner: String,
    /// Names the dependency package supplying the required interfaces.
    pub package: String,
    /// Preserves required semantic version ranges under stable ability names.
    pub abilities: BTreeMap<String, String>,
    /// Optionally constrains the dependency's package version independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_version: Option<String>,
}

pub(super) fn validate(reference: &ModuleReference) -> Result<()> {
    if reference.ability_contracts.len() > 1024 || reference.module_requirements.len() > 16_384 {
        return Err(invalid(
            "native resolution declarations exceed their bounds",
        ));
    }
    for (name, contract) in &reference.ability_contracts {
        require_ability_name(name)?;
        require_name(&contract.owner, "ability owner")?;
        if contract.version.len() > 128 {
            return Err(invalid("ability version exceeds its bound"));
        }
        let version = semver::Version::parse(&contract.version)
            .map_err(|error| invalid(format!("invalid ability version for {name}: {error}")))?;
        if version.to_string() != contract.version {
            return Err(invalid("ability version must be strict SemVer"));
        }
    }
    let mut dependencies = BTreeSet::new();
    for requirement in &reference.module_requirements {
        if !dependencies.insert((&requirement.owner, &requirement.package)) {
            return Err(invalid("duplicate owner/module dependency declaration"));
        }
        require_name(&requirement.owner, "requesting owner")?;
        require_name(&requirement.package, "dependency package")?;
        if (requirement.abilities.is_empty() && requirement.package_version.is_none())
            || requirement.abilities.len() > 1024
        {
            return Err(invalid(
                "ranged module dependency must request bounded ability or package versions",
            ));
        }
        for (name, range) in &requirement.abilities {
            require_ability_name(name)?;
            validate_range(range)?;
        }
        if let Some(range) = &requirement.package_version {
            validate_range(range)?;
        }
    }
    Ok(())
}

fn require_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 {
        return Err(invalid(format!("{label} must be nonempty and bounded")));
    }
    Ok(())
}

fn validate_range(range: &str) -> Result<()> {
    if range.is_empty() || range.len() > 4096 {
        return Err(invalid("module version range must be nonempty and bounded"));
    }
    let requirement = semver::VersionReq::parse(range)
        .map_err(|error| invalid(format!("invalid module version range: {error}")))?;
    if requirement.comparators.len() > 32 {
        return Err(invalid("module version range exceeds its comparator bound"));
    }
    Ok(())
}

fn require_ability_name(name: &str) -> Result<()> {
    require_name(name, "ability name")?;
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(invalid("invalid stable ability name"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeDocument;
    use serde_json::json;

    fn reference() -> serde_json::Value {
        json!({"schema":"aos.module.documentation","scope":["host","main"],
            "system":"x86_64-linux","packages":[],"options":[],"abilities":{},
            "abilityContracts":{"service":{"version":"1.2.3","owner":"interfaces"}},
            "moduleRequirements":[{"owner":"web-server","package":"interfaces",
                "abilities":{"service":"^1.2"},"packageVersion":">=7.0, <8.0"}]})
    }

    fn decode(value: &serde_json::Value) -> crate::Result<RuntimeDocument> {
        RuntimeDocument::from_json(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn native_metadata_preserves_independent_version_and_requirement_strings() {
        let value = reference();
        let document = decode(&value).unwrap();
        let reference = document.reference().unwrap();
        assert_eq!(reference.ability_contracts["service"].version, "1.2.3");
        assert_eq!(
            reference.module_requirements[0].package_version.as_deref(),
            Some(">=7.0, <8.0")
        );
        assert_eq!(document.value(), &value);
        let schema: serde_json::Value =
            serde_json::from_slice(&super::super::module_documentation_json_schema().unwrap())
                .unwrap();
        assert!(schema["properties"]["abilityContracts"].is_object());
        assert!(schema["properties"]["moduleRequirements"].is_object());
    }

    #[test]
    fn absent_and_empty_metadata_keep_unversioned_native_references_valid() {
        let mut value = reference();
        value.as_object_mut().unwrap().remove("abilityContracts");
        value.as_object_mut().unwrap().remove("moduleRequirements");
        let document = decode(&value).unwrap();
        assert!(document.reference().unwrap().ability_contracts.is_empty());
        assert!(document.reference().unwrap().module_requirements.is_empty());

        value["abilityContracts"] = json!({});
        value["moduleRequirements"] = json!([]);
        assert!(decode(&value).is_ok());
    }

    #[test]
    fn malformed_versions_requirements_and_requesting_owners_are_rejected() {
        for version in ["1.2", "01.2.3", "not-a-version"] {
            let mut value = reference();
            value["abilityContracts"]["service"]["version"] = json!(version);
            assert!(decode(&value).is_err());
        }
        for field in ["owner", "package"] {
            let mut value = reference();
            value["moduleRequirements"][0][field] = json!("");
            assert!(decode(&value).is_err());
        }
        for range in ["", "not-a-range", "^1 || ^2"] {
            let mut value = reference();
            value["moduleRequirements"][0]["abilities"]["service"] = json!(range);
            assert!(decode(&value).is_err());
        }
        let mut value = reference();
        value["moduleRequirements"][0]
            .as_object_mut()
            .unwrap()
            .remove("owner");
        assert!(decode(&value).is_err());
    }
    #[test]
    fn semantic_version_fields_obey_shared_text_and_comparator_bounds() {
        let mut value = reference();
        value["abilityContracts"]["service"]["version"] =
            json!(format!("1.2.3+{}", "a".repeat(122)));
        assert!(decode(&value).is_ok());
        value["abilityContracts"]["service"]["version"] =
            json!(format!("1.2.3+{}", "a".repeat(123)));
        assert!(decode(&value).is_err());

        let mut value = reference();
        value["moduleRequirements"][0]["abilities"]["service"] =
            json!(vec![">=1.0.0"; 32].join(", "));
        assert!(decode(&value).is_ok());
        value["moduleRequirements"][0]["abilities"]["service"] =
            json!(vec![">=1.0.0"; 33].join(", "));
        assert!(decode(&value).is_err());
        value["moduleRequirements"][0]["abilities"]["service"] = json!(" ".repeat(4097));
        assert!(decode(&value).is_err());
    }

    #[test]
    fn package_only_module_requirement_is_valid_and_unconstrained_dependency_is_not() {
        let mut value = reference();
        value["moduleRequirements"][0]["abilities"] = json!({});
        assert!(decode(&value).is_ok());
        value["moduleRequirements"][0]
            .as_object_mut()
            .unwrap()
            .remove("packageVersion");
        assert!(decode(&value).is_err());
    }
}
