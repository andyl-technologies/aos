//! Pure materialization of expressions with no runtime result dependencies.

use anyhow::{Context, Result, bail, ensure};
use aos_ability_model::{AbilityValue, ValueExpression};
use serde_json::{Map, Value};

use crate::validate_value;

/// Resolves an expression whose dependencies are fixed before stage entry.
///
/// Artifact and resource references are retained as typed canonical values.
/// Runtime, aggregate, and request outputs have no static value and fail
/// instead of being inferred from an image artifact.
///
/// # Errors
///
/// Returns an error for deferred outputs, invalid execution paths, a value
/// that violates its canonical JSON schema or bound, or an invalid value.
pub fn resolve_static_expression(expression: &ValueExpression) -> Result<AbilityValue> {
    AbilityValue::new(resolve(expression)?).context("static expression is not a canonical value")
}

fn resolve(expression: &ValueExpression) -> Result<Value> {
    match expression {
        ValueExpression::Literal { value } => Ok(value.as_json().clone()),
        ValueExpression::List { items } => items
            .iter()
            .map(resolve)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        ValueExpression::Object { fields } => fields
            .iter()
            .map(|(name, value)| Ok((name.clone(), resolve(value)?)))
            .collect::<Result<Map<_, _>>>()
            .map(Value::Object),
        ValueExpression::ArtifactReference { reference } => Ok(serde_json::to_value(reference)?),
        ValueExpression::ResourceReference { reference } => Ok(serde_json::to_value(reference)?),
        ValueExpression::PathWithin {
            base,
            relative_path,
        } => {
            let base = resolve(base)?;
            let base = base
                .as_str()
                .context("static execution path base is not text")?;
            ensure!(
                valid_execution_path(base),
                "invalid static execution path base"
            );
            let path = if base == "/" {
                format!("/{relative_path}")
            } else {
                format!("{base}/{relative_path}")
            };
            ensure!(valid_execution_path(&path), "invalid static execution path");
            Ok(Value::String(path))
        }
        ValueExpression::CanonicalJson {
            source_schema,
            value,
            max_bytes,
        } => {
            let value = resolve(value)?;
            validate_value(
                source_schema,
                &ValueExpression::Literal {
                    value: AbilityValue::new(value.clone())?,
                },
            )
            .context("static canonical JSON source differs from its declared schema")?;
            let encoded = aos_contract::canonical::canonical_json(&value)?;
            ensure!(
                encoded.len() as u64 <= *max_bytes,
                "static canonical JSON exceeds its declared byte bound"
            );
            Ok(Value::String(String::from_utf8(encoded)?))
        }
        ValueExpression::AggregateOutput { .. }
        | ValueExpression::OperationResult { .. }
        | ValueExpression::RequestOutput { .. } => {
            bail!("static expression depends on a runtime result")
        }
    }
}

fn valid_execution_path(path: &str) -> bool {
    path.len() <= 4_096
        && path.starts_with('/')
        && !path.contains('\0')
        && (path == "/"
            || path[1..]
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != ".."))
}

#[cfg(test)]
mod tests {
    use aos_ability_model::{AbilityValue, ValueExpression};

    use super::resolve_static_expression;

    #[test]
    fn static_object_resolves_nested_paths_without_runtime_state() {
        let expression = ValueExpression::Object {
            fields: [(
                "executable".to_string(),
                ValueExpression::PathWithin {
                    base: Box::new(ValueExpression::Literal {
                        value: AbilityValue::new(serde_json::json!("/nix/store/example"))
                            .expect("base"),
                    }),
                    relative_path: serde_json::from_value(serde_json::json!("bin/example"))
                        .expect("relative path"),
                },
            )]
            .into(),
        };

        let resolved = resolve_static_expression(&expression).expect("static expression");
        assert_eq!(
            resolved.as_json(),
            &serde_json::json!({"executable":"/nix/store/example/bin/example"})
        );
    }
}
