//! Compares native declarations and dependency requirements independently of prose.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{RuntimeDocument, invalid};
use crate::Result;

/// Lists exact paths added, removed, or changed in a native reference.
///
/// Option paths retain their segments. Operation paths contain ability and
/// operation names, avoiding ambiguity when either name contains a dot.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceChanges {
    /// Lists newly declared paths.
    pub added: Vec<Vec<String>>,
    /// Lists paths no longer declared.
    pub removed: Vec<Vec<String>>,
    /// Lists paths whose typed semantics changed.
    pub changed: Vec<Vec<String>>,
}

impl ReferenceChanges {
    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// Describes declaration changes between two exact package references.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeComparison {
    /// Identifies this native comparison format.
    pub schema: String,
    /// Names the package shared by both references.
    pub package: String,
    /// Records the earlier package version.
    pub from_version: String,
    /// Records the later package version.
    pub to_version: String,
    /// Records their shared target platform.
    pub platform: String,
    /// Compares option types and mutability/extension policy.
    pub options: ReferenceChanges,
    /// Compares operation input/results, handler selection, and configured instances.
    pub operations: ReferenceChanges,
    /// Compares OS version requirements by requesting owner.
    pub os_requirements: ReferenceChanges,
    /// Compares dependency requirements by exact requesting-owner and package pairs.
    pub module_requirements: ReferenceChanges,
    /// Reports whether any compared declaration semantics changed.
    pub semantic_changed: bool,
}

impl RuntimeDocument {
    /// Compares native package declarations, excluding prose and source locations.
    ///
    /// The comparison covers option types, read-only and extension policy,
    /// operation input/result types, handler availability, and configured instance
    /// names, package requirements, and OS version requirements. It does not compare
    /// executable contents or observed runtime state.
    ///
    /// # Errors
    /// Returns an error unless both references describe the same package and
    /// platform with unambiguous package versions.
    pub fn compare(&self, other: &Self) -> Result<NativeComparison> {
        let earlier = self
            .reference()
            .ok_or_else(|| invalid("comparison requires native references"))?;
        let later = other
            .reference()
            .ok_or_else(|| invalid("comparison requires native references"))?;
        if earlier.scope.len() != 2
            || earlier.scope[0] != "package"
            || earlier.scope != later.scope
            || earlier.system != later.system
        {
            return Err(invalid(
                "comparison requires the same package scope and target",
            ));
        }
        let package = &earlier.scope[1];
        let version = |reference: &super::ModuleReference| {
            reference
                .packages
                .iter()
                .find(|identity| identity.name == *package)
                .map(|identity| identity.version.clone())
                .ok_or_else(|| invalid("comparison reference omits its package identity"))
        };
        let from_version = version(earlier)?;
        let to_version = version(later)?;
        self.verify_package_identity(package, &from_version, &earlier.system)?;
        other.verify_package_identity(package, &to_version, &earlier.system)?;

        let options = |reference: &super::ModuleReference| {
            reference.options.iter().map(|option| (option.path.clone(), json!({
                "type": option.option_type, "readOnly": option.read_only, "extensible": option.extensible
            }))).collect()
        };
        let operations = |reference: &super::ModuleReference| {
            reference
                .abilities
                .iter()
                .flat_map(|(ability, operations)| {
                    operations.iter().map(move |(name, operation)| {
                        let mut instances = operation.configured_effects.clone();
                        instances.sort();
                        let mut input_defaults = operation.input_defaults.clone();
                        input_defaults.sort();
                        (
                            vec![ability.clone(), name.clone()],
                            json!({
                                "input":operation.input_type,"inputDefaults":input_defaults,"result":operation.result_type,
                                "handled":operation.handler_available,"instances":instances
                            }),
                        )
                    })
                })
                .collect()
        };
        let options = changes(options(earlier), options(later));
        let operations = changes(operations(earlier), operations(later));
        let requirements = |reference: &super::ModuleReference| {
            reference
                .module_requirements
                .iter()
                .map(|requirement| {
                    let path = vec![requirement.owner.clone(), requirement.package.clone()];
                    let constraints = json!({
                        "packageVersion": requirement.package_version
                    });
                    (path, constraints)
                })
                .collect()
        };
        let os_requirements = |reference: &super::ModuleReference| {
            reference
                .os_requirements
                .iter()
                .map(|requirement| {
                    (
                        vec![requirement.owner.clone()],
                        json!({"osVersion":requirement.os_version}),
                    )
                })
                .collect()
        };
        let os_requirements = changes(os_requirements(earlier), os_requirements(later));
        let module_requirements = changes(requirements(earlier), requirements(later));
        let semantic_changed = !options.is_empty()
            || !operations.is_empty()
            || !os_requirements.is_empty()
            || !module_requirements.is_empty();
        Ok(NativeComparison {
            schema: "aos.module.documentation.comparison".into(),
            package: package.clone(),
            from_version,
            to_version,
            platform: earlier.system.clone(),
            options,
            operations,
            os_requirements,
            module_requirements,
            semantic_changed,
        })
    }
}

fn changes(
    earlier: BTreeMap<Vec<String>, Value>,
    later: BTreeMap<Vec<String>, Value>,
) -> ReferenceChanges {
    ReferenceChanges {
        added: later
            .keys()
            .filter(|path| !earlier.contains_key(*path))
            .cloned()
            .collect(),
        removed: earlier
            .keys()
            .filter(|path| !later.contains_key(*path))
            .cloned()
            .collect(),
        changed: earlier
            .iter()
            .filter(|(path, value)| later.get(*path).is_some_and(|next| next != *value))
            .map(|(path, _)| path.clone())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(version: &str, description: &str, read_only: bool) -> RuntimeDocument {
        RuntimeDocument::from_json(&serde_json::to_vec(&json!({
            "schema":"aos.module.documentation","scope":["package","example"],
            "system":"x86_64-linux","packages":[{"name":"example","version":version}],
            "options":[{"path":["example","value"],"owner":"example","description":description,
                "type":{"kind":"string"},"readOnly":read_only,"extensible":false,"visibility":"public"}],
            "abilities":{}
        })).unwrap()).unwrap()
    }

    #[test]
    fn compares_contract_changes_without_treating_prose_as_semantics() {
        let before = reference("1", "Old prose", false);
        let prose = reference("2", "New prose", false);
        let changed = reference("2", "New prose", true);

        assert!(!before.compare(&prose).unwrap().semantic_changed);
        let comparison = before.compare(&changed).unwrap();
        assert!(comparison.semantic_changed);
        assert_eq!(comparison.options.changed, vec![vec!["example", "value"]]);
        assert_eq!(comparison.from_version, "1");
        assert_eq!(comparison.to_version, "2");
    }
    #[test]
    fn package_and_os_range_changes_report_semantic_changes() {
        let mut value = reference("1", "Description", false).value().clone();
        value["moduleRequirements"] = json!([{"owner":"example","package":"interface",
            "packageVersion":"^7"}]);
        value["osRequirements"] = json!([{"owner":"example","osVersion":"^1"}]);
        let decode = |value: &Value| {
            RuntimeDocument::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
        };
        let before = decode(&value);
        value["osRequirements"][0]["osVersion"] = json!("^2");
        let comparison = before.compare(&decode(&value)).unwrap();
        assert!(comparison.semantic_changed);
        assert_eq!(comparison.os_requirements.changed, vec![vec!["example"]]);
        assert!(comparison.options.is_empty());
        assert!(comparison.operations.is_empty());

        value["osRequirements"][0]["osVersion"] = json!("^1");
        value["moduleRequirements"][0]["packageVersion"] = json!("^8");
        let comparison = before.compare(&decode(&value)).unwrap();
        assert!(comparison.semantic_changed);
        assert_eq!(
            comparison.module_requirements.changed,
            vec![vec!["example", "interface"]]
        );
        assert!(comparison.os_requirements.is_empty());
    }
}
