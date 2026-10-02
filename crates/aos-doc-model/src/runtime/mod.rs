//! Native module documentation and deferred transaction inspection.
//!
//! Both the CLI and Hub read the same evaluator-generated documents. References
//! describe declarations and configured uses; transaction graphs describe a
//! selected execution path. Neither is an observation of live state.
//!
//! ```json
//! {"schema":"aos.module.documentation","scope":["package","example"],"system":"x86_64-linux","packages":[],"options":[],"abilities":{}}
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_plan::module_graph::{CheckedModuleGraph, GRAPH_LIMITS, check_retirement};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{DocumentationError, OptionType, Result};

mod comparison;
pub mod compatibility;
mod contracts;
pub mod deployment;
mod render;

pub use comparison::{NativeComparison, ReferenceChanges};
pub use contracts::{ModuleRequirement, OsRelease, OsRequirement};

/// Serializes the complete portable option type as a stable signature.
///
/// # Errors
/// Returns an error if the option type cannot be serialized.
pub fn type_signature(option: &OptionType) -> Result<String> {
    Ok(serde_json::to_string(option)?)
}

/// Identifies the native fixed-point documentation format.
pub const MODULE_DOCUMENTATION_SCHEMA: &str = "aos.module.documentation";

/// Generates the native reference schema from its decoding types.
///
/// # Errors
///
/// Returns an error if the generated schema cannot be serialized.
pub fn module_documentation_json_schema() -> Result<Vec<u8>> {
    let mut schema = serde_json::to_value(schemars::schema_for!(ModuleReference))?;
    schema["properties"]["schema"]["const"] = Value::String(MODULE_DOCUMENTATION_SCHEMA.into());
    Ok(serde_json::to_vec_pretty(&schema)?)
}

/// Bounds imported documentation and transaction JSON.
pub const MAX_RUNTIME_DOCUMENT_BYTES: usize = GRAPH_LIMITS.max_bytes;

/// Identifies a package participating in the evaluated module closure.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackageIdentity {
    /// Names the package.
    pub name: String,
    /// Records its selected version.
    pub version: String,
    /// Captures the compatibility requirement generated from the package version recipe.
    ///
    /// Non-SemVer packages omit this field and retain exact source dependencies.
    #[serde(
        rename = "versionRequirement",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub version_requirement: Option<String>,
}

/// Describes an option projected from the native module fixed point.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeOption {
    /// Preserves the exact option path segments.
    pub path: Vec<String>,
    /// Names the declaring package or environment owner.
    pub owner: String,
    /// Contains the declaration prose.
    pub description: String,
    #[serde(rename = "type")]
    /// Contains the portable structured option type.
    pub option_type: OptionType,
    /// Selects its reference visibility.
    pub visibility: crate::Visibility,
    /// Indicates that external definitions are rejected.
    pub read_only: bool,
    /// Indicates whether other modules may extend this option.
    pub extensible: bool,
    /// Reports an authored default without exposing or evaluating its value.
    #[serde(default)]
    pub has_default: bool,
}

/// Describes one declared operation input or result.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationField {
    /// Contains the declaration prose.
    pub description: String,
    #[serde(rename = "type")]
    /// Preserves its portable structured type.
    pub option_type: OptionType,
}

/// Identifies one module definition contributing to an operation.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DefinitionSource {
    /// Locates the retained source file.
    pub file: String,
    /// Names the package or environment owner.
    pub owner: String,
    /// Records the module definition priority.
    pub priority: i64,
    /// Preserves the evaluator provenance label.
    pub provenance: String,
}

/// Groups operation definition provenance by its role.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationSources {
    /// Locates input declarations.
    pub input: Vec<DefinitionSource>,
    /// Locates result declarations.
    pub result: Vec<DefinitionSource>,
    /// Locates handler selection definitions.
    pub handler: Vec<DefinitionSource>,
    /// Locates configured effect definitions.
    pub effects: Vec<DefinitionSource>,
}

/// Describes one merged ability operation without executing it.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationReference {
    /// Lists documented input fields.
    pub input: BTreeMap<String, OperationField>,
    /// Lists documented result fields.
    pub result: BTreeMap<String, OperationField>,
    /// Preserves the complete input schema.
    pub input_type: OptionType,
    /// Lists input declaration paths with defaults, without evaluating their values.
    #[serde(
        rename = "inputDefaults",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub input_defaults: Vec<Vec<String>>,
    /// Preserves the complete result schema.
    pub result_type: OptionType,
    /// Reports whether this fixed point selected a handler.
    pub handler_available: bool,
    /// Lists configured instance names, which may include disabled instances.
    pub configured_effects: Vec<String>,
    /// Links declarations, implementations, and configured uses to their owners.
    pub sources: OperationSources,
}

/// Carries generated package and operation reference data for one scope.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleReference {
    /// Identifies the native documentation format.
    pub schema: String,
    /// Identifies the evaluated installation or package scope.
    pub scope: Vec<String>,
    /// Names the target platform.
    pub system: String,
    /// Lists the selected payload identities, including dependencies.
    pub packages: Vec<PackageIdentity>,
    /// Contains declarations projected from the module evaluator.
    pub options: Vec<NativeOption>,
    /// Groups operation references by ability and operation names.
    pub abilities: BTreeMap<String, BTreeMap<String, OperationReference>>,
    /// Records ranged module dependencies projected from the same source declarations.
    #[serde(
        rename = "moduleRequirements",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub module_requirements: Vec<ModuleRequirement>,
    /// Records OS requirements for base-provided interfaces.
    #[serde(
        rename = "osRequirements",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub os_requirements: Vec<OsRequirement>,
    /// Identifies the OS release supplying base interfaces when known.
    #[serde(rename = "osRelease", default, skip_serializing_if = "Option::is_none")]
    pub os_release: Option<OsRelease>,
}

#[derive(Clone, Debug)]
enum Source {
    ModuleReference(ModuleReference),
    Transaction {
        scope: Vec<String>,
        system: String,
        graph: CheckedModuleGraph,
        retire: BTreeSet<String>,
    },
}

/// Holds bounded native reference data or a structurally checked execution graph.
///
/// Importing a document does not authenticate its publisher, evaluate Nix,
/// inspect a machine, or execute a handler.
#[derive(Clone, Debug)]
pub struct RuntimeDocument {
    original: Value,
    source: Source,
}

impl RuntimeDocument {
    /// Returns the checked desired effect graph for a package transaction.
    ///
    /// Module references declare contracts and therefore have no execution graph.
    #[must_use]
    pub fn transaction_graph(&self) -> Option<&CheckedModuleGraph> {
        match &self.source {
            Source::Transaction { graph, .. } => Some(graph),
            Source::ModuleReference(_) => None,
        }
    }

    /// Returns explicit retirement decisions from a checked native transaction.
    ///
    /// Module references contain declarations and therefore have no retirement list.
    #[must_use]
    pub fn transaction_retirement(&self) -> Option<&BTreeSet<String>> {
        match &self.source {
            Source::Transaction { retire, .. } => Some(retire),
            Source::ModuleReference(_) => None,
        }
    }

    /// Decodes an evaluator-generated reference or package transaction.
    ///
    /// # Errors
    /// Returns an error for unknown formats, exceeded bounds, malformed module
    /// declarations, or an invalid effect graph.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let original: Value = GRAPH_LIMITS
            .decode(bytes, "runtime documentation")
            .map_err(invalid)?;
        let source = match original.get("schema").and_then(Value::as_str) {
            Some(MODULE_DOCUMENTATION_SCHEMA) => {
                Source::ModuleReference(serde_json::from_value(original.clone()).map_err(invalid)?)
            }
            Some("aos.package.transaction") => {
                let scope = serde_json::from_value(
                    original
                        .get("scope")
                        .cloned()
                        .ok_or_else(|| invalid("missing scope"))?,
                )
                .map_err(invalid)?;
                let system = original
                    .get("system")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("missing target system"))?
                    .to_owned();
                let graph = original
                    .get("graph")
                    .ok_or_else(|| invalid("missing effect graph"))?;
                let graph =
                    CheckedModuleGraph::decode(&serde_json::to_vec(graph).map_err(invalid)?)
                        .map_err(invalid)?;
                let retirement: Vec<String> = serde_json::from_value(
                    original
                        .get("retire")
                        .cloned()
                        .ok_or_else(|| invalid("missing explicit retirement list"))?,
                )
                .map_err(invalid)?;
                let retire = check_retirement(&graph, &retirement).map_err(invalid)?;
                Source::Transaction {
                    scope,
                    system,
                    graph,
                    retire,
                }
            }
            _ => {
                return Err(invalid(
                    "expected aos.module.documentation or aos.package.transaction",
                ));
            }
        };
        let (scope, system) = match &source {
            Source::ModuleReference(reference) => (&reference.scope, &reference.system),
            Source::Transaction { scope, system, .. } => (scope, system),
        };
        if scope.is_empty() || scope.iter().any(String::is_empty) || system.is_empty() {
            return Err(invalid("scope and target system must be explicit"));
        }
        if let Source::ModuleReference(reference) = &source {
            contracts::validate(reference)?;
            for option in &reference.options {
                crate::validate_option_type(&option.option_type)?;
            }
            for operation in reference.abilities.values().flat_map(BTreeMap::values) {
                if operation.input_defaults.len() > 16_384 {
                    return Err(invalid("operation input default paths exceed their bound"));
                }
                let mut default_paths = BTreeSet::new();
                for path in &operation.input_defaults {
                    if path.is_empty()
                        || path.len() > 64
                        || path
                            .iter()
                            .any(|segment| segment.is_empty() || segment.len() > 256)
                    {
                        return Err(invalid(
                            "operation input default path must be nonempty and bounded",
                        ));
                    }
                    if !default_paths.insert(path) {
                        return Err(invalid("duplicate operation input default path"));
                    }
                }
                crate::validate_option_type(&operation.input_type)?;
                crate::validate_option_type(&operation.result_type)?;
                for field in operation.input.values().chain(operation.result.values()) {
                    crate::validate_option_type(&field.option_type)?;
                }
            }
        }
        if let Source::Transaction { graph, .. } = &source {
            if graph
                .graph()
                .nodes
                .values()
                .any(|effect| !effect.identity.starts_with(scope))
            {
                return Err(invalid("effect identity differs from the document scope"));
            }
        }
        Ok(Self { original, source })
    }

    /// Borrows native declarations, or returns `None` for a transaction document.
    pub fn reference(&self) -> Option<&ModuleReference> {
        match &self.source {
            Source::ModuleReference(reference) => Some(reference),
            Source::Transaction { .. } => None,
        }
    }

    /// Borrows native option declarations; transaction documents have no reference options.
    pub fn options(&self) -> &[NativeOption] {
        self.reference()
            .map_or(&[], |reference| reference.options.as_slice())
    }

    /// Verifies that a reference belongs to the exact published package and target.
    ///
    /// Dependencies may also appear in the module closure. Publication authenticity
    /// and the original document byte digest must be checked by the caller.
    ///
    /// # Errors
    /// Returns an error for a transaction document, a non-package scope, or a
    /// mismatched package name, version, or target platform.
    pub fn verify_package_identity(&self, name: &str, version: &str, system: &str) -> Result<()> {
        let reference = self
            .reference()
            .ok_or_else(|| invalid("expected package module documentation"))?;
        if reference.scope != ["package", name]
            || reference.system != system
            || !reference
                .packages
                .iter()
                .any(|package| package.name == name && package.version == version)
            || reference
                .packages
                .iter()
                .any(|package| package.name == name && package.version != version)
        {
            return Err(invalid(
                "module documentation differs from the selected package release",
            ));
        }
        Ok(())
    }

    /// Derives deterministic search rows from package, option, and operation declarations.
    ///
    /// Transaction documents have no static reference rows. Hidden options are omitted.
    pub fn search_documents(&self) -> Vec<crate::SearchDocument> {
        let Some(reference) = self.reference() else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        for package in &reference.packages {
            rows.push(crate::search_row(
                "package",
                &package.name,
                &package.name,
                &package.version,
                [(&package.name, 100), (&package.version, 20)],
            ));
        }
        for option in reference
            .options
            .iter()
            .filter(|option| option.visibility != crate::Visibility::Hidden)
        {
            let path = option.path.join(".");
            let kind = render::type_label(&option.option_type);
            rows.push(crate::search_row(
                "option",
                &path,
                &path,
                &option.description,
                [
                    (path.as_str(), 100),
                    (kind.as_str(), 40),
                    (option.description.as_str(), 20),
                ],
            ));
        }
        for (ability, operations) in &reference.abilities {
            for (name, operation) in operations {
                let title = format!("{ability}.{name}");
                let key = format!("{}:{ability}{name}", ability.len());
                let description = operation
                    .input
                    .iter()
                    .chain(&operation.result)
                    .map(|(field, value)| format!("{field}: {}", value.description))
                    .collect::<Vec<_>>()
                    .join("; ");
                rows.push(crate::search_row(
                    "operation",
                    &key,
                    &title,
                    &description,
                    [(title.as_str(), 100), (description.as_str(), 20)],
                ));
            }
        }
        rows
    }

    /// Returns the exact parsed source, without replacing it with a presentation model.
    pub fn value(&self) -> &Value {
        &self.original
    }

    /// Renders declarations, package relationships, or an ordered execution path.
    pub fn render_plain(&self) -> String {
        render::plain(&self.source)
    }

    /// Renders the same document with linked package owners and operation details.
    pub fn render_html(&self) -> String {
        render::html(&self.source)
    }
}

fn invalid(error: impl std::fmt::Display) -> DocumentationError {
    DocumentationError::Invalid(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_reference_preserves_package_identity_and_escapes_markup() {
        let bytes = br#"{"schema":"aos.module.documentation","scope":["package","<example>"],"system":"x86_64-linux","packages":[{"name":"<example>","version":"1"}],"options":[],"abilities":{}}"#;
        let document = RuntimeDocument::from_json(bytes).unwrap();
        assert!(document.render_plain().contains("<example>"));
        assert!(document.render_html().contains("&lt;example&gt;"));
        assert!(!document.render_html().contains("<example>"));
        assert_eq!(document.value()["packages"][0]["version"], "1");
        document
            .verify_package_identity("<example>", "1", "x86_64-linux")
            .unwrap();
        assert!(
            document
                .verify_package_identity("<example>", "2", "x86_64-linux")
                .is_err()
        );
        assert!(
            document
                .verify_package_identity("<example>", "1", "aarch64-linux")
                .is_err()
        );
        assert_eq!(document.search_documents()[0].key, "<example>");
    }

    #[test]
    fn rejects_missing_scope_and_obsolete_formats() {
        assert!(
            RuntimeDocument::from_json(br#"{"schema":"aos.package-ability-reference/v1"}"#)
                .is_err()
        );
        assert!(RuntimeDocument::from_json(br#"{"schema":"aos.package.transaction","scope":[],"system":"x86_64-linux","retire":[],"graph":{"schema":"aos.activation.graph","nodes":{},"order":[]}}"#).is_err());
    }

    #[test]
    fn operation_reference_links_each_definition_owner() {
        let source = |owner: &str| {
            serde_json::json!({
                "owner":owner, "file":"module.nix", "priority":100, "provenance":"package"
            })
        };
        let field = serde_json::json!({"description":"A <message>","type":{"kind":"string"}});
        let document = serde_json::json!({
            "schema":MODULE_DOCUMENTATION_SCHEMA,
            "scope":["host","main"],"system":"x86_64-linux",
            "packages":[{"name":"consumer","version":"1"}],"options":[],
            "abilities":{"echo":{"run":{
                "input":{"message":field},"result":{"message":field},
                "inputType":{"kind":"submodule","fields":{"message":{"kind":"string"}},"open":false},
                "resultType":{"kind":"submodule","fields":{"message":{"kind":"string"}},"open":false},
                "handlerAvailable":true,"configuredEffects":["main"],
                "sources":{"input":[source("interface")],"result":[source("interface")],
                    "handler":[source("backend")],"effects":[source("consumer")]}
            }}}
        });

        let reference =
            RuntimeDocument::from_json(&serde_json::to_vec(&document).unwrap()).unwrap();
        let html = reference.render_html();
        for owner in ["interface", "backend", "consumer"] {
            let anchor = crate::documentation_anchor("runtime-owner", owner);
            assert!(html.matches(&format!("-{anchor}\"")).count() >= 2);
        }
        assert!(html.contains("Configured instances: main"));
        assert!(html.contains("A &lt;message&gt;"));
        assert!(reference.render_plain().contains("Input message: str"));
    }
    #[test]
    fn transaction_retirement_is_required_checked_and_rendered_as_desired_intent() {
        let mut transaction = serde_json::json!({
            "schema":"aos.package.transaction", "scope":["host","main"],
            "system":"x86_64-linux", "retire":["<retained-effect>"],
            "graph":{"schema":"aos.activation.graph","nodes":{},"order":[]}
        });
        let document =
            RuntimeDocument::from_json(&serde_json::to_vec(&transaction).unwrap()).unwrap();
        assert_eq!(
            document.transaction_retirement().unwrap(),
            &BTreeSet::from(["<retained-effect>".to_string()])
        );
        assert!(document.render_plain().contains("<retained-effect>"));
        assert!(document.render_html().contains("&lt;retained-effect&gt;"));

        transaction["retire"] = serde_json::json!(["duplicate", "duplicate"]);
        assert!(RuntimeDocument::from_json(&serde_json::to_vec(&transaction).unwrap()).is_err());
        transaction.as_object_mut().unwrap().remove("retire");
        assert!(RuntimeDocument::from_json(&serde_json::to_vec(&transaction).unwrap()).is_err());
    }
}
