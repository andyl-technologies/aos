//! Shared package-contract readers and schema fixtures for native-adapter audits.
//!
//! The matrix and package projections are decoded once through the production
//! contract parser. Synthetic values pass the published value schema before a
//! checked plan can use them.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use aos_ability_model::{
    AbilityValue, InterfaceDocument, InterfaceKey, ProviderAssignment, StringSyntax,
    ValueExpression, ValueSchema,
};
use aos_ability_validate::test_support::PlanFixture;
use serde::Deserialize;
use serde_json::{Map, Value, json};

#[derive(Deserialize)]
pub(super) struct MatrixSpec {
    pub(super) schema: String,
    pub(super) surface: Surface,
    pub(super) applicability: Applicability,
    pub(super) cells: Vec<Value>,
}

#[derive(Deserialize)]
pub(super) struct Surface {
    pub(super) schema: String,
    pub(super) matrix_schema: String,
    pub(super) adapters: Vec<Adapter>,
    pub(super) scenarios: Vec<Value>,
}

#[derive(Deserialize)]
pub(super) struct Adapter {
    pub(super) adapter: String,
    pub(super) interface_name: String,
    pub(super) interface_abi: u32,
    pub(super) interface_descriptor: String,
    pub(super) scope: String,
    pub(super) methods: Vec<MatrixMethod>,
}

#[derive(Deserialize)]
pub(super) struct MatrixMethod {
    pub(super) method: String,
    pub(super) required_target_access: String,
}

#[derive(Deserialize)]
pub(super) struct Applicability {
    pub(super) schema: String,
    pub(super) applicable_cell_ids: Vec<String>,
    pub(super) inapplicable_cells: Vec<Value>,
}

pub(super) fn minimal_value(schema: &ValueSchema, fixture: &PlanFixture) -> Result<Value> {
    Ok(match schema {
        ValueSchema::Boolean => Value::Bool(false),
        ValueSchema::Integer { minimum, .. } => json!(minimum),
        ValueSchema::String { max_length, syntax } => {
            let candidate = match syntax {
                Some(StringSyntax::LocalKeyV1) => "x",
                Some(StringSyntax::QualifiedNameV1) => "x.y",
                Some(StringSyntax::ExecutionPathV1) => "/x",
                Some(StringSyntax::RelativePathV1) => "x",
                None => "",
            };
            ensure!(
                candidate.len() as u64 <= *max_length,
                "string schema has no simple inhabitant"
            );
            Value::String(candidate.to_string())
        }
        ValueSchema::StringEnum { values } => {
            Value::String(values.first().context("string enum is empty")?.clone())
        }
        ValueSchema::List { .. } => Value::Array(Vec::new()),
        ValueSchema::Map { .. } => Value::Object(Map::new()),
        ValueSchema::Record {
            fields,
            optional_fields,
        } => {
            let optional: BTreeSet<_> = optional_fields.iter().collect();
            let mut record = Map::new();
            for (key, value) in fields {
                if !optional.contains(key) {
                    record.insert(key.as_str().to_string(), minimal_value(value, fixture)?);
                }
            }
            Value::Object(record)
        }
        ValueSchema::DocumentRecord {
            fields,
            optional_fields,
            ..
        } => {
            let optional: BTreeSet<_> = optional_fields.iter().collect();
            let mut record = Map::new();
            for (key, value) in fields {
                if !optional.contains(key) {
                    record.insert(key.clone(), minimal_value(value, fixture)?);
                }
            }
            Value::Object(record)
        }
        ValueSchema::TaggedUnion { tag, variants } => {
            let (variant, schema) = variants.iter().next().context("tagged union is empty")?;
            let Value::Object(mut record) = minimal_value(schema, fixture)? else {
                bail!("tagged union variant is not a record");
            };
            record.insert(
                tag.as_str().to_string(),
                Value::String(variant.as_str().to_string()),
            );
            Value::Object(record)
        }
        ValueSchema::DisjointUnion { variants } => {
            let variant = variants.first().context("disjoint union is empty")?;
            minimal_value(variant, fixture)?
        }
        ValueSchema::Optional { .. } => Value::Null,
        ValueSchema::Refined { value, .. } => {
            let candidate = minimal_value(value, fixture)?;
            if schema_accepts_literal(schema, &candidate)? {
                candidate
            } else if candidate.is_string() {
                // Search a bounded, deterministic set of simple strings. The
                // published schema remains the oracle for every candidate.
                let mut matching = None;
                for character in ['0', '1', 'a', 'x'] {
                    for length in 1..=128 {
                        let candidate = Value::String(character.to_string().repeat(length));
                        if schema_accepts_literal(schema, &candidate)? {
                            matching = Some(candidate);
                            break;
                        }
                    }
                    if matching.is_some() {
                        break;
                    }
                }
                matching.context("refined string schema has no simple inhabitant")?
            } else {
                bail!("refined schema has no simple inhabitant")
            }
        }
        ValueSchema::ArtifactReference => serde_json::to_value(&fixture.effect_plan.artifacts[0])?,
        ValueSchema::ResourceReference => {
            serde_json::to_value(&fixture.effect_plan.operations[0].target)?
        }
        ValueSchema::ProviderAssignment => serde_json::to_value(
            fixture.binding_inputs.environment.providers[0]
                .incarnation
                .as_ref()
                .map(|incarnation| ProviderAssignment {
                    provider: fixture.binding_inputs.environment.providers[0]
                        .provider
                        .clone(),
                    interface: fixture.binding_inputs.environment.providers[0]
                        .interface
                        .clone(),
                    implementation: fixture.binding_inputs.environment.providers[0]
                        .implementation
                        .clone(),
                    incarnation: incarnation.clone(),
                })
                .context("fixture provider lacks an incarnation")?,
        )?,
        ValueSchema::OperationResultReference => {
            bail!("operation result schema requires a producer")
        }
        ValueSchema::TransactionBlobReference => {
            bail!("transaction blob reference schema requires a producer")
        }
    })
}

pub(super) fn schema_accepts_literal(schema: &ValueSchema, candidate: &Value) -> Result<bool> {
    let value = AbilityValue::new(candidate.clone())?;
    Ok(aos_ability_validate::validate_value(schema, &ValueExpression::Literal { value }).is_ok())
}

pub(super) fn validate_spec(spec: &MatrixSpec) -> Result<()> {
    ensure!(
        spec.schema == "aos.qualification.native-adapter-matrix-spec/v1",
        "unsupported matrix schema"
    );
    ensure!(
        spec.surface.schema == "aos.qualification.native-adapter-surface/v1",
        "unsupported surface schema"
    );
    ensure!(
        spec.surface.matrix_schema == "aos.qualification.native-adapter-matrix/v1",
        "unsupported matrix result schema"
    );
    ensure!(
        spec.applicability.schema == "aos.qualification.native-adapter-matrix-applicability/v1",
        "unsupported matrix applicability schema"
    );
    ensure!(
        !spec.surface.scenarios.is_empty(),
        "matrix scenarios are absent"
    );
    ensure!(
        spec.surface
            .adapters
            .iter()
            .all(|adapter| !adapter.scope.is_empty()),
        "matrix adapter scope is absent"
    );
    let all_ids: BTreeSet<_> = spec
        .cells
        .iter()
        .map(|cell| {
            cell.get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .context("matrix cell lacks an id")
        })
        .collect::<Result<_>>()?;
    let applicable: BTreeSet<_> = spec
        .applicability
        .applicable_cell_ids
        .iter()
        .cloned()
        .collect();
    let inapplicable: BTreeSet<_> = spec
        .applicability
        .inapplicable_cells
        .iter()
        .map(|entry| {
            entry
                .get("cell_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .context("inapplicable matrix entry lacks a cell id")
        })
        .collect::<Result<_>>()?;
    ensure!(
        all_ids.len() == spec.cells.len(),
        "matrix repeats a cell id"
    );
    ensure!(
        applicable.len() == spec.applicability.applicable_cell_ids.len(),
        "matrix repeats an applicable cell id"
    );
    ensure!(
        inapplicable.len() == spec.applicability.inapplicable_cells.len(),
        "matrix repeats an inapplicable cell id"
    );
    ensure!(
        applicable.is_disjoint(&inapplicable)
            && all_ids == applicable.union(&inapplicable).cloned().collect(),
        "matrix applicability does not partition its cells"
    );
    Ok(())
}

pub(super) fn load_interfaces(
    roots: &[PathBuf],
) -> Result<BTreeMap<InterfaceKey, InterfaceDocument>> {
    let mut interfaces = BTreeMap::new();
    for root in roots {
        let bytes = fs::read(root)
            .with_context(|| format!("failed to read package contract {}", root.display()))?;
        let projection = aos_ability_validate::decode_package_projection(&bytes)
            .with_context(|| format!("invalid package contract {}", root.display()))?;
        for entry in projection.interface_documents {
            let document = entry.document;
            let key = document.interface_key()?;
            ensure!(
                entry.descriptor == key.descriptor,
                "interface descriptor differs from its package projection"
            );
            if let Some(previous) = interfaces.insert(key, document.clone()) {
                ensure!(
                    previous == document,
                    "package contracts contain conflicting interface descriptors"
                );
            }
        }
    }
    Ok(interfaces)
}

pub(super) fn select_interface_catalog(
    interface: &InterfaceDocument,
    interfaces: &BTreeMap<InterfaceKey, InterfaceDocument>,
) -> Result<Vec<InterfaceDocument>> {
    let mut selected = vec![interface.clone()];
    for method in interface.interface.methods.values() {
        if method.target_resource == interface.interface.name {
            continue;
        }

        let mut matches = interfaces
            .values()
            .filter(|candidate| candidate.interface.name == method.target_resource);
        let target = matches
            .next()
            .with_context(|| format!("missing target interface {}", method.target_resource))?;
        ensure!(
            matches.next().is_none(),
            "ambiguous target interface {}",
            method.target_resource
        );
        if !selected.contains(target) {
            selected.push(target.clone());
        }
    }

    Ok(selected)
}
