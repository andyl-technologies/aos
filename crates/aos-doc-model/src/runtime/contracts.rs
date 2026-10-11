//! Source-generated package and OS compatibility requirements.
//!
//! Ability interfaces use their owning package version, or the OS release version
//! for base-provided interfaces. Reading these declarations does not select a
//! compatible provider or authenticate a release.
//!
//! ```json
//! {"moduleRequirements":[{"owner":"web-server","package":"service-interface",
//!    "packageVersion":"^7"}],
//!  "osRequirements":[{"owner":"web-server","osVersion":"^1"}],
//!  "osRelease":{"name":"aos","version":"1.0.0"}}
//! ```

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{ModuleReference, invalid};
use crate::Result;

/// Describes a package version requirement declared by one requesting owner.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModuleRequirement {
    /// Names the module owner requesting the dependency.
    pub owner: String,
    /// Names the dependency package supplying the required interfaces.
    pub package: String,
    /// Constrains the dependency package version with a semantic version range.
    pub package_version: String,
}

/// Describes an OS version requirement for base-provided interfaces.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OsRequirement {
    /// Names the module owner requesting the base interfaces.
    pub owner: String,
    /// Constrains the OS release version with a semantic version range.
    pub os_version: String,
}

/// Identifies the OS release supplying base interfaces in an evaluated scope.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OsRelease {
    /// Names the operating system release family.
    pub name: String,
    /// Records the OS release's semantic version.
    pub version: String,
}

pub(super) fn validate(reference: &ModuleReference) -> Result<()> {
    if reference.module_requirements.len() > 16_384 || reference.os_requirements.len() > 16_384 {
        return Err(invalid(
            "native resolution declarations exceed their bounds",
        ));
    }

    for package in &reference.packages {
        if let Some(range) = &package.version_requirement {
            if !matches!(range.as_bytes().first(), Some(b'^' | b'~' | b'='))
                || range.get(1..) != Some(package.version.as_str())
                || package.version.len() > 128
            {
                return Err(invalid(
                    "generated package version requirement must prefix its exact version with ^, ~, or =",
                ));
            }
            validate_range(range)?;
            let version = semver::Version::parse(&package.version).map_err(|error| {
                invalid(format!(
                    "invalid package version for compatibility requirement: {error}"
                ))
            })?;
            let requirement = semver::VersionReq::parse(range).map_err(invalid)?;
            if !requirement.matches(&version) {
                return Err(invalid(
                    "package compatibility requirement must include its selected version",
                ));
            }
        }
    }

    if let Some(release) = &reference.os_release {
        require_name(&release.name, "OS release name")?;
        if release.version.len() > 128 {
            return Err(invalid("OS release version exceeds its bound"));
        }
        let version = semver::Version::parse(&release.version)
            .map_err(|error| invalid(format!("invalid OS release version: {error}")))?;
        if version.to_string() != release.version {
            return Err(invalid("OS release version must be strict SemVer"));
        }
    }

    let mut dependencies = BTreeSet::new();
    for requirement in &reference.module_requirements {
        if !dependencies.insert((&requirement.owner, &requirement.package)) {
            return Err(invalid("duplicate owner/module dependency declaration"));
        }
        require_name(&requirement.owner, "requesting owner")?;
        require_name(&requirement.package, "dependency package")?;
        validate_range(&requirement.package_version)?;
    }

    let mut requesters = BTreeSet::new();
    for requirement in &reference.os_requirements {
        if !requesters.insert(&requirement.owner) {
            return Err(invalid("duplicate owner/OS requirement declaration"));
        }
        require_name(&requirement.owner, "requesting owner")?;
        validate_range(&requirement.os_version)?;
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
        return Err(invalid("version range must be nonempty and bounded"));
    }
    let requirement = semver::VersionReq::parse(range)
        .map_err(|error| invalid(format!("invalid version range: {error}")))?;
    if requirement.comparators.len() > 32 {
        return Err(invalid("version range exceeds its comparator bound"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::runtime::RuntimeDocument;
    use serde_json::json;

    fn reference() -> serde_json::Value {
        json!({"schema":"aos.module.documentation","scope":["host","main"],
            "system":"x86_64-linux","packages":[],"options":[],"abilities":{},
            "moduleRequirements":[{"owner":"web-server","package":"interfaces",
                "packageVersion":">=7.0, <8.0"}],
            "osRequirements":[{"owner":"web-server","osVersion":"^1"}],
            "osRelease":{"name":"aos","version":"1.0.0"}})
    }

    fn decode(value: &serde_json::Value) -> crate::Result<RuntimeDocument> {
        RuntimeDocument::from_json(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn metadata_preserves_package_and_os_requirement_strings() {
        let value = reference();
        let document = decode(&value).unwrap();
        let reference = document.reference().unwrap();
        assert_eq!(
            reference.module_requirements[0].package_version,
            ">=7.0, <8.0"
        );
        assert_eq!(reference.os_requirements[0].os_version, "^1");
        assert_eq!(reference.os_release.as_ref().unwrap().version, "1.0.0");
        assert_eq!(document.value(), &value);
        let schema: serde_json::Value =
            serde_json::from_slice(&super::super::module_documentation_json_schema().unwrap())
                .unwrap();
        assert!(schema["properties"]["moduleRequirements"].is_object());
        assert!(schema["properties"]["osRequirements"].is_object());
        assert!(schema["properties"].get("abilityContracts").is_none());
    }

    #[test]
    fn absent_optional_metadata_keeps_native_references_valid() {
        let mut value = reference();
        for field in ["moduleRequirements", "osRequirements", "osRelease"] {
            value.as_object_mut().unwrap().remove(field);
        }
        let document = decode(&value).unwrap();
        let reference = document.reference().unwrap();
        assert!(reference.module_requirements.is_empty());
        assert!(reference.os_requirements.is_empty());
        assert!(reference.os_release.is_none());
    }

    #[test]
    fn removed_ability_versions_and_missing_package_ranges_are_rejected() {
        let mut value = reference();
        value["abilityContracts"] = json!({});
        assert!(decode(&value).is_err());
        let mut value = reference();
        value["moduleRequirements"][0]["abilities"] = json!({"service":"^1"});
        assert!(decode(&value).is_err());
        let mut value = reference();
        value["moduleRequirements"][0]
            .as_object_mut()
            .unwrap()
            .remove("packageVersion");
        assert!(decode(&value).is_err());
    }

    #[test]
    fn invalid_ranges_owners_and_os_versions_are_rejected() {
        for version in ["1.2", "01.2.3", "not-a-version"] {
            let mut value = reference();
            value["osRelease"]["version"] = json!(version);
            assert!(decode(&value).is_err());
        }
        for field in ["owner", "package"] {
            let mut value = reference();
            value["moduleRequirements"][0][field] = json!("");
            assert!(decode(&value).is_err());
        }
        for range in ["", "not-a-range", "^1 || ^2"] {
            let mut value = reference();
            value["moduleRequirements"][0]["packageVersion"] = json!(range);
            assert!(decode(&value).is_err());
            let mut value = reference();
            value["osRequirements"][0]["osVersion"] = json!(range);
            assert!(decode(&value).is_err());
        }
    }

    #[test]
    fn ranges_obey_shared_text_and_comparator_bounds() {
        let mut value = reference();
        value["moduleRequirements"][0]["packageVersion"] = json!(vec![">=1.0.0"; 32].join(", "));
        assert!(decode(&value).is_ok());
        value["moduleRequirements"][0]["packageVersion"] = json!(vec![">=1.0.0"; 33].join(", "));
        assert!(decode(&value).is_err());
        value["moduleRequirements"][0]["packageVersion"] = json!(" ".repeat(4097));
        assert!(decode(&value).is_err());
    }

    #[test]
    fn duplicate_package_and_os_requirements_are_rejected() {
        for field in ["moduleRequirements", "osRequirements"] {
            let mut value = reference();
            let duplicate = value[field][0].clone();
            value[field].as_array_mut().unwrap().push(duplicate);
            assert!(decode(&value).is_err());
        }
    }
    #[test]
    fn input_default_paths_are_preserved_and_bounded() {
        let mut value = reference();
        value["abilities"] = json!({"echo":{"run":{
            "input":{},"result":{},
            "inputType":{"kind":"submodule","fields":{"message":{"kind":"string"}},"open":false},
            "resultType":{"kind":"submodule","fields":{},"open":false},
            "inputDefaults":[["message"]], "handlerAvailable":false, "configuredEffects":[],
            "sources":{"input":[],"result":[],"handler":[],"effects":[]}
        }}});
        let document = decode(&value).unwrap();
        assert_eq!(
            document.reference().unwrap().abilities["echo"]["run"].input_defaults,
            vec![vec!["message".to_owned()]]
        );
        for paths in [
            json!([[]]),
            json!([[""]]),
            json!([["message"], ["message"]]),
            json!([["a".repeat(257)]]),
        ] {
            value["abilities"]["echo"]["run"]["inputDefaults"] = paths;
            assert!(decode(&value).is_err());
        }
    }
    #[test]
    fn generated_package_version_requirements_preserve_normalized_recipe_policy() {
        for prefix in ["^", "~", "="] {
            let mut value = reference();
            let requirement = format!("{prefix}7.4.2");
            value["packages"] =
                json!([{"name":"interfaces","version":"7.4.2","versionRequirement":requirement}]);
            let document = decode(&value).unwrap();
            assert_eq!(
                document.reference().unwrap().packages[0]
                    .version_requirement
                    .as_deref(),
                Some(requirement.as_str())
            );
            assert_eq!(document.value(), &value);
            assert!(
                document
                    .render_plain()
                    .contains(&format!("Compatibility requirement: {requirement}"))
            );
            assert!(document.render_html().contains(&format!(
                "Compatibility requirement: <code>{requirement}</code>"
            )));
        }
    }

    #[test]
    fn generated_package_policy_rejects_arbitrary_ranges_and_mismatched_versions() {
        for requirement in [">=7.4.2", "^7", "~7.4.1", "*", "7.4.2", "=not-semver"] {
            let mut value = reference();
            value["packages"] =
                json!([{"name":"interfaces","version":"7.4.2","versionRequirement":requirement}]);
            assert!(decode(&value).is_err(), "accepted {requirement}");
        }
        let mut value = reference();
        value["packages"] = json!([{"name":"interfaces","version":"git-snapshot"}]);
        assert!(decode(&value).is_ok());
    }
}
