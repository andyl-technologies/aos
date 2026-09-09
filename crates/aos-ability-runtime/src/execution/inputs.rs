//! Resolution of checked symbolic operation inputs from durable results.

use aos_ability_model::{
    AbilityValue, LocalKey, MergeNode, OperationResultReference, ScopedOperationKey,
    ValueExpression,
};
use thiserror::Error;

use crate::execution::{ExecutionTransaction, OperationState, TransactionError};

/// Reports why a checked operation input cannot be materialized for admission.
#[derive(Debug, Error)]
pub enum InputResolutionError {
    /// The requested operation is absent from the checked plan.
    #[error("operation is absent from the checked effect plan")]
    OperationMissing,
    /// A symbolic producer has not durably completed with the named output.
    #[error("referenced operation or merge output is not durably available")]
    ResultUnavailable,
    /// A typed artifact or resource reference could not be encoded.
    #[error("typed input reference could not be encoded: {0}")]
    Encoding(#[source] serde_json::Error),
    /// Resolving repeated references would exceed a checked plan input bound.
    #[error("resolved input exceeds the checked {0} limit")]
    Limit(&'static str),
    /// The fully resolved input exceeded the bounded ability-value contract.
    #[error("resolved input is outside the bounded ability-value contract: {0}")]
    Value(#[from] aos_ability_model::ValueError),
    /// The materialized value violates the checked method or nested authority.
    #[error("resolved input violates the checked method contract: {0}")]
    Checked(#[source] anyhow::Error),
}

impl ExecutionTransaction<'_> {
    /// Resolves one checked operation's complete typed input from durable values.
    ///
    /// Literals and exact artifact/resource references retain their closed
    /// representation. Operation and merge references resolve only from
    /// completion records already accepted by checked replay.
    ///
    /// # Errors
    ///
    /// Returns an error when the operation is absent, a referenced producer has
    /// not completed, a typed reference cannot be encoded, or the materialized
    /// value exceeds the version-1 value bounds.
    pub fn resolve_operation_inputs(
        &self,
        operation: &ScopedOperationKey,
    ) -> Result<AbilityValue, InputResolutionError> {
        let operation = self
            .plan()
            .operation(operation)
            .ok_or(InputResolutionError::OperationMissing)?;
        let limits = self.plan().document().limits;
        preflight_expression(self, &operation.inputs, 1, limits)?;
        let value = resolve_expression(self, &operation.inputs)?;
        let value = AbilityValue::new(value).map_err(InputResolutionError::Value)?;
        self.plan()
            .validate_operation_inputs(operation, &value)
            .map_err(|source| InputResolutionError::Checked(anyhow::Error::new(source)))?;
        Ok(value)
    }

    pub(crate) fn preflight_merge_outputs(
        &self,
        merge: &MergeNode,
        alternative: &LocalKey,
    ) -> Result<(), InputResolutionError> {
        let limits = self.plan().document().limits;
        let mut footprint = named_values_footprint(merge.outputs.len(), limits)?;

        for (port, merged_output) in &merge.outputs {
            let reference = merged_output
                .alternatives
                .get(alternative)
                .ok_or(InputResolutionError::ResultUnavailable)?;
            let value = transaction_result(self, reference)?;
            add_named_value(&mut footprint, port, value, limits)?;
        }
        Ok(())
    }

    fn resolved_result(
        &self,
        reference: &OperationResultReference,
    ) -> Result<&serde_json::Value, InputResolutionError> {
        use aos_ability_model::ResultProducerKey;

        match &reference.producer {
            ResultProducerKey::Operation { key } => {
                let history = self
                    .history(key)
                    .map_err(|_source: TransactionError| InputResolutionError::ResultUnavailable)?;
                let OperationState::Completed { outputs, .. } = history.state() else {
                    return Err(InputResolutionError::ResultUnavailable);
                };
                outputs
                    .get(&reference.output)
                    .map(AbilityValue::as_json)
                    .ok_or(InputResolutionError::ResultUnavailable)
            }
            ResultProducerKey::Merge { key } => self
                .merged_output(key, &reference.output)
                .map(AbilityValue::as_json)
                .ok_or(InputResolutionError::ResultUnavailable),
        }
    }
}

fn transaction_result<'transaction>(
    transaction: &'transaction ExecutionTransaction<'_>,
    reference: &OperationResultReference,
) -> Result<&'transaction serde_json::Value, InputResolutionError> {
    transaction.resolved_result(reference)
}

fn named_values_footprint(
    length: usize,
    limits: aos_ability_model::LimitProfile,
) -> Result<Footprint, InputResolutionError> {
    let footprint = Footprint {
        bytes: collection_punctuation(length),
        items: length as u64,
        depth: 1,
    };
    check_footprint(footprint, limits)?;
    Ok(footprint)
}

fn add_named_value(
    footprint: &mut Footprint,
    name: &LocalKey,
    value: &serde_json::Value,
    limits: aos_ability_model::LimitProfile,
) -> Result<(), InputResolutionError> {
    if name.as_str().len() as u64 > limits.max_string_bytes {
        return Err(InputResolutionError::Limit("string byte"));
    }
    add_bytes(
        footprint,
        encoded_string_size(name.as_str()).saturating_add(1),
        limits,
    )?;
    add_footprint(footprint, json_footprint(value, 2, limits)?)?;
    check_footprint(*footprint, limits)
}

#[derive(Clone, Copy, Debug, Default)]
struct Footprint {
    bytes: u64,
    items: u64,
    depth: u32,
}

fn preflight_expression(
    transaction: &ExecutionTransaction<'_>,
    expression: &ValueExpression,
    depth: u32,
    limits: aos_ability_model::LimitProfile,
) -> Result<(), InputResolutionError> {
    let footprint = expression_footprint(transaction, expression, depth, limits)?;
    if footprint.bytes > limits.max_document_bytes {
        return Err(InputResolutionError::Limit("encoded byte"));
    }
    if footprint.items > limits.max_collection_items {
        return Err(InputResolutionError::Limit("collection item"));
    }
    if footprint.depth > limits.max_structural_depth {
        return Err(InputResolutionError::Limit("structural depth"));
    }
    Ok(())
}

fn expression_footprint(
    transaction: &ExecutionTransaction<'_>,
    expression: &ValueExpression,
    depth: u32,
    limits: aos_ability_model::LimitProfile,
) -> Result<Footprint, InputResolutionError> {
    match expression {
        ValueExpression::Literal { value } => json_footprint(value.as_json(), depth, limits),
        ValueExpression::ArtifactReference { reference } => {
            let value = serde_json::to_value(reference).map_err(InputResolutionError::Encoding)?;
            json_footprint(&value, depth, limits)
        }
        ValueExpression::ResourceReference { reference } => {
            let value = serde_json::to_value(reference).map_err(InputResolutionError::Encoding)?;
            json_footprint(&value, depth, limits)
        }
        ValueExpression::OperationResult { reference } => {
            let value = transaction.resolved_result(reference)?;
            json_footprint(value, depth, limits)
        }
        ValueExpression::List { items } => {
            let mut footprint = Footprint {
                bytes: 2_u64.saturating_add(items.len().saturating_sub(1) as u64),
                items: items.len() as u64,
                depth,
            };
            for item in items {
                add_footprint(
                    &mut footprint,
                    expression_footprint(transaction, item, depth.saturating_add(1), limits)?,
                )?;
                check_footprint(footprint, limits)?;
            }
            Ok(footprint)
        }
        ValueExpression::Object { fields } => {
            let mut footprint = Footprint {
                bytes: 2_u64.saturating_add(fields.len().saturating_sub(1) as u64),
                items: fields.len() as u64,
                depth,
            };
            for (name, value) in fields {
                if name.len() as u64 > limits.max_string_bytes {
                    return Err(InputResolutionError::Limit("string byte"));
                }
                let encoded_name =
                    serde_json::to_vec(name).map_err(InputResolutionError::Encoding)?;
                footprint.bytes = footprint
                    .bytes
                    .checked_add(encoded_name.len() as u64)
                    .and_then(|bytes| bytes.checked_add(1))
                    .ok_or(InputResolutionError::Limit("encoded byte"))?;
                add_footprint(
                    &mut footprint,
                    expression_footprint(transaction, value, depth.saturating_add(1), limits)?,
                )?;
                check_footprint(footprint, limits)?;
            }
            Ok(footprint)
        }
    }
}

fn json_footprint(
    value: &serde_json::Value,
    starting_depth: u32,
    limits: aos_ability_model::LimitProfile,
) -> Result<Footprint, InputResolutionError> {
    let mut footprint = Footprint {
        depth: starting_depth,
        ..Footprint::default()
    };
    let mut stack = vec![(value, starting_depth)];
    while let Some((value, depth)) = stack.pop() {
        footprint.depth = footprint.depth.max(depth);
        if depth > limits.max_structural_depth {
            return Err(InputResolutionError::Limit("structural depth"));
        }
        match value {
            serde_json::Value::Null => add_bytes(&mut footprint, 4, limits)?,
            serde_json::Value::Bool(true) => add_bytes(&mut footprint, 4, limits)?,
            serde_json::Value::Bool(false) => add_bytes(&mut footprint, 5, limits)?,
            serde_json::Value::Number(number) => {
                add_bytes(&mut footprint, number.to_string().len() as u64, limits)?;
            }
            serde_json::Value::String(value) => {
                if value.len() as u64 > limits.max_string_bytes {
                    return Err(InputResolutionError::Limit("string byte"));
                }
                add_bytes(&mut footprint, encoded_string_size(value), limits)?;
            }
            serde_json::Value::Array(items) => {
                add_items(&mut footprint, items.len() as u64, limits)?;
                add_bytes(&mut footprint, collection_punctuation(items.len()), limits)?;
                stack.extend(items.iter().map(|item| (item, depth.saturating_add(1))));
            }
            serde_json::Value::Object(fields) => {
                add_items(&mut footprint, fields.len() as u64, limits)?;
                add_bytes(&mut footprint, collection_punctuation(fields.len()), limits)?;
                for (name, value) in fields {
                    if name.len() as u64 > limits.max_string_bytes {
                        return Err(InputResolutionError::Limit("string byte"));
                    }
                    add_bytes(
                        &mut footprint,
                        encoded_string_size(name).saturating_add(1),
                        limits,
                    )?;
                    stack.push((value, depth.saturating_add(1)));
                }
            }
        }
    }
    check_footprint(footprint, limits)?;
    Ok(footprint)
}

fn add_bytes(
    footprint: &mut Footprint,
    additional: u64,
    limits: aos_ability_model::LimitProfile,
) -> Result<(), InputResolutionError> {
    footprint.bytes = footprint
        .bytes
        .checked_add(additional)
        .ok_or(InputResolutionError::Limit("encoded byte"))?;
    check_footprint(*footprint, limits)
}

fn add_items(
    footprint: &mut Footprint,
    additional: u64,
    limits: aos_ability_model::LimitProfile,
) -> Result<(), InputResolutionError> {
    footprint.items = footprint
        .items
        .checked_add(additional)
        .ok_or(InputResolutionError::Limit("collection item"))?;
    check_footprint(*footprint, limits)
}

fn collection_punctuation(length: usize) -> u64 {
    if length == 0 {
        2
    } else {
        (length as u64).saturating_add(1)
    }
}

fn encoded_string_size(value: &str) -> u64 {
    value
        .chars()
        .map(|character| match character {
            '\u{0008}' | '\t' | '\n' | '\u{000c}' | '\r' | '"' | '\\' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => character.len_utf8() as u64,
        })
        .fold(2, u64::saturating_add)
}

fn add_footprint(total: &mut Footprint, child: Footprint) -> Result<(), InputResolutionError> {
    total.bytes = total
        .bytes
        .checked_add(child.bytes)
        .ok_or(InputResolutionError::Limit("encoded byte"))?;
    total.items = total
        .items
        .checked_add(child.items)
        .ok_or(InputResolutionError::Limit("collection item"))?;
    total.depth = total.depth.max(child.depth);
    Ok(())
}

fn check_footprint(
    footprint: Footprint,
    limits: aos_ability_model::LimitProfile,
) -> Result<(), InputResolutionError> {
    if footprint.bytes > limits.max_document_bytes {
        Err(InputResolutionError::Limit("encoded byte"))
    } else if footprint.items > limits.max_collection_items {
        Err(InputResolutionError::Limit("collection item"))
    } else if footprint.depth > limits.max_structural_depth {
        Err(InputResolutionError::Limit("structural depth"))
    } else {
        Ok(())
    }
}

fn resolve_expression(
    transaction: &ExecutionTransaction<'_>,
    expression: &ValueExpression,
) -> Result<serde_json::Value, InputResolutionError> {
    match expression {
        ValueExpression::Literal { value } => Ok(value.as_json().clone()),
        ValueExpression::List { items } => items
            .iter()
            .map(|item| resolve_expression(transaction, item))
            .collect::<Result<Vec<_>, _>>()
            .map(serde_json::Value::Array),
        ValueExpression::Object { fields } => fields
            .iter()
            .map(|(name, value)| {
                resolve_expression(transaction, value).map(|value| (name.clone(), value))
            })
            .collect::<Result<serde_json::Map<_, _>, _>>()
            .map(serde_json::Value::Object),
        ValueExpression::ArtifactReference { reference } => {
            serde_json::to_value(reference).map_err(InputResolutionError::Encoding)
        }
        ValueExpression::ResourceReference { reference } => {
            serde_json::to_value(reference).map_err(InputResolutionError::Encoding)
        }
        ValueExpression::OperationResult { reference } => {
            transaction.resolved_result(reference).cloned()
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn repeated_borrowed_values_fit_the_exact_aggregate_boundary() {
        let limits = limits_with_bytes(46);
        let value = serde_json::json!("abcdefgh");
        let mut footprint = named_values_footprint(3, limits).expect("map header fits");

        for name in ["a", "b", "c"] {
            add_named_value(
                &mut footprint,
                &LocalKey::new(name).expect("valid key"),
                &value,
                limits,
            )
            .expect("exact aggregate boundary must fit");
        }

        assert_eq!(footprint.bytes, 46);
    }

    #[test]
    fn repeated_borrowed_values_fail_before_aggregate_cloning() {
        let limits = limits_with_bytes(45);
        let value = serde_json::json!("abcdefgh");
        let mut footprint = named_values_footprint(3, limits).expect("map header fits");
        let keys = ["a", "b", "c"];

        for name in &keys[..2] {
            add_named_value(
                &mut footprint,
                &LocalKey::new(*name).expect("valid key"),
                &value,
                limits,
            )
            .expect("partial aggregate fits");
        }
        let error = add_named_value(
            &mut footprint,
            &LocalKey::new(keys[2]).expect("valid key"),
            &value,
            limits,
        )
        .expect_err("final repeated value must exceed the lowered bound");

        assert!(matches!(error, InputResolutionError::Limit("encoded byte")));
    }

    fn limits_with_bytes(max_document_bytes: u64) -> aos_ability_model::LimitProfile {
        aos_ability_model::LimitProfile {
            max_document_bytes,
            max_structural_depth: 8,
            max_graph_nodes: 8,
            max_graph_edges: 8,
            max_resolver_rounds: 8,
            max_candidates_per_alias: 8,
            max_collection_items: 8,
            max_string_bytes: 32,
            max_provider_search_visits: 8,
        }
    }
}
