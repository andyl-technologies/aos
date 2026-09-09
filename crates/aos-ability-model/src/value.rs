//! Typed symbolic references and canonical values carried by contracts.
//!
//! Expressions carry an explicit `source` tag, and result producers carry a
//! separate `kind` tag:
//!
//! ```json
//! {"source":"operation-result","reference":{"producer":{"kind":"merge","key":{"key":"selected","scope":[]}},"output":"endpoint"}}
//! ```

use std::collections::BTreeMap;

use aos_contract::Sha256Digest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

use crate::identity::{
    AggregateId, IncarnationId, InstanceId, InterfaceKey, LocalKey, ResourceId, ScopedOperationKey,
};
use crate::interface::ProviderImplementationReference;
use crate::limits::ABILITY_LIMITS_V1;

/// Reports why a value cannot enter a canonical ability contract.
#[derive(Debug, Error)]
pub enum ValueError {
    /// The value exceeded a version-1 structural or size bound.
    #[error("value exceeds the version-1 {limit} limit")]
    Limit {
        /// Names the exceeded limit.
        limit: &'static str,
    },
    /// The value violated the canonical JSON dialect.
    #[error("value is outside the AOS canonical JSON dialect")]
    Canonical {
        /// Retains the canonical encoder's error chain.
        #[source]
        source: anyhow::Error,
    },
}

/// Holds one value already checked against the canonical JSON dialect.
///
/// Schema validation remains a separate operation because the expected schema
/// belongs to an interface method or result port, not to the value itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbilityValue(Value);

impl AbilityValue {
    /// Constructs a value after checking canonical-dialect restrictions.
    ///
    /// # Errors
    ///
    /// Returns an error for floating-point or out-of-range numbers and for
    /// non-ASCII object member names. It also rejects values exceeding the
    /// version-1 depth, collection, string, or encoded-byte bounds.
    pub fn new(value: Value) -> Result<Self, ValueError> {
        let encoded_size = validate_value_limits(&value, &ABILITY_LIMITS_V1)?;
        if encoded_size > ABILITY_LIMITS_V1.max_document_bytes {
            return Err(ValueError::Limit {
                limit: "encoded byte",
            });
        }

        let bytes = aos_contract::canonical::canonical_json(&value)
            .map_err(|source| ValueError::Canonical { source })?;
        debug_assert_eq!(bytes.len() as u64, encoded_size);
        Ok(Self(value))
    }

    /// Returns the underlying JSON value for schema-directed inspection.
    #[must_use]
    pub fn as_json(&self) -> &Value {
        &self.0
    }

    /// Returns the exact canonical encoded size after rechecking value bounds.
    ///
    /// # Errors
    ///
    /// Returns an error if an in-memory value exceeds the version-1 structural,
    /// collection, string, or encoded-byte limits.
    pub fn encoded_size(&self) -> Result<u64, ValueError> {
        validate_value_limits(&self.0, &ABILITY_LIMITS_V1)
    }

    /// Consumes the wrapper and returns the underlying JSON value.
    #[must_use]
    pub fn into_json(self) -> Value {
        self.0
    }
}

impl TryFrom<Value> for AbilityValue {
    type Error = ValueError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl Serialize for AbilityValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AbilityValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Identifies an exact immutable artifact and its authenticated closure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    /// Identifies the artifact's exact bytes or canonical semantic content.
    pub content: Sha256Digest,
    /// Preserves the exact Nix store path selected by the authenticated release.
    pub store_path: String,
    /// Preserves the artifact's NAR identity.
    pub nar_hash: Sha256Digest,
    /// Identifies the authenticated transitive closure association.
    pub closure: Sha256Digest,
}

/// Defines how long a referenced resource is expected to remain usable.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceLifetime {
    /// Exists only during one operation attempt.
    Attempt,
    /// Exists for the durable transaction.
    Transaction,
    /// Exists while its owning instance remains selected.
    Instance,
    /// Persists until a separately authorized deletion.
    Persistent,
}

/// Names a logical resource and the exact operation projection granted to it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceReference {
    /// Identifies the interface that issued the reference.
    pub interface: InterfaceKey,
    /// Identifies the logical provider-owned resource.
    pub resource: ResourceId,
    /// Names permitted operations in canonical key order.
    pub operations: Vec<LocalKey>,
    /// States the expected lifetime of this reference.
    pub lifetime: ResourceLifetime,
}

/// Records one live assignment of an exact provider implementation.
///
/// The record becomes trusted evidence only after a checked readiness producer
/// returns it and fresh runtime policy accepts its exact subject and incarnation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAssignment {
    /// Identifies the assigned provider instance.
    pub provider: InstanceId,
    /// Identifies the exact public interface supplied by the assignment.
    pub interface: InterfaceKey,
    /// Pins the exact executable implementation assigned to the provider.
    pub implementation: ProviderImplementationReference,
    /// Identifies the fresh provider-assigned live generation.
    pub incarnation: IncarnationId,
}

/// Names one typed result port produced inside the current effect plan.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationResultReference {
    /// Names the producing operation or conditional merge.
    pub producer: ResultProducerKey,
    /// Names the producer's output port.
    pub output: LocalKey,
}

/// Names a plan node that can produce a typed result.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ResultProducerKey {
    /// Names an invoked provider operation.
    Operation {
        /// Carries the operation's scoped key.
        key: ScopedOperationKey,
    },
    /// Names a conditional merge output.
    Merge {
        /// Carries the merge node's scoped key.
        key: ScopedOperationKey,
    },
}

impl ResultProducerKey {
    /// Returns the underlying scoped node key.
    #[must_use]
    pub const fn key(&self) -> &ScopedOperationKey {
        match self {
            Self::Operation { key } | Self::Merge { key } => key,
        }
    }
}

/// Associates a closed record field name with a canonical value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedValue {
    /// Names the record field or method parameter.
    pub name: LocalKey,
    /// Supplies its canonical value.
    pub value: AbilityValue,
}

/// Refers to one provider-qualified aggregate output from pure composition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateOutputReference {
    /// Identifies the exact provider aggregate producing the value.
    pub aggregate: AggregateId,
    /// Identifies the exact public interface declaring the output.
    pub interface: InterfaceKey,
    /// Names the interface-local output port.
    pub port: LocalKey,
}

/// Describes a literal or symbolic value without shape-based interpretation.
///
/// Composite expressions are needed only when a symbolic reference occurs
/// below the root. A complete literal list or object may remain one `literal`
/// expression.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "source", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ValueExpression {
    /// Supplies a canonical value containing no symbolic references.
    Literal {
        /// Carries the complete literal value.
        value: AbilityValue,
    },
    /// Builds an ordered list from independently typed expressions.
    List {
        /// Supplies the list elements in declared order.
        items: Vec<ValueExpression>,
    },
    /// Builds a record or map from independently typed field expressions.
    Object {
        /// Supplies fields in canonical member-name order.
        fields: BTreeMap<String, ValueExpression>,
    },
    /// Supplies an exact immutable artifact reference.
    ArtifactReference {
        /// Identifies the retained artifact and closure.
        reference: ArtifactReference,
    },
    /// Supplies a scoped logical resource reference.
    ResourceReference {
        /// Identifies the resource and operation projection.
        reference: ResourceReference,
    },
    /// Supplies a typed output from a selected lower provider aggregate.
    AggregateOutput {
        /// Identifies the provider aggregate and exact interface-local port.
        reference: AggregateOutputReference,
    },
    /// Supplies a future value from another operation's typed output port.
    OperationResult {
        /// Identifies the producer and output port.
        reference: OperationResultReference,
    },
}

impl ValueExpression {
    /// Reports whether recursive expression nesting and collection growth stay bounded.
    #[must_use]
    pub fn is_within_limits(&self, max_depth: u32, max_items: u64) -> bool {
        let mut item_count = 0_u64;
        let mut stack = vec![(self, 1_u32)];

        while let Some((expression, depth)) = stack.pop() {
            if depth > max_depth {
                return false;
            }

            let child_depth = depth.saturating_add(1);
            match expression {
                Self::List { items } => {
                    item_count = item_count.saturating_add(items.len() as u64);
                    if item_count > max_items {
                        return false;
                    }
                    stack.extend(items.iter().map(|item| (item, child_depth)));
                }
                Self::Object { fields } => {
                    item_count = item_count.saturating_add(fields.len() as u64);
                    if item_count > max_items {
                        return false;
                    }
                    stack.extend(fields.values().map(|field| (field, child_depth)));
                }
                Self::Literal { .. }
                | Self::ArtifactReference { .. }
                | Self::ResourceReference { .. }
                | Self::AggregateOutput { .. }
                | Self::OperationResult { .. } => {}
            }
        }

        true
    }
}

/// Supplies named method inputs as explicit literal or symbolic expressions.
pub type InputMap = BTreeMap<LocalKey, ValueExpression>;

fn validate_value_limits(
    root: &Value,
    limits: &crate::limits::LimitProfile,
) -> Result<u64, ValueError> {
    let mut item_count = 0_u64;
    let mut encoded_size = 0_u64;
    let mut stack = vec![(root, 1_u32)];

    while let Some((value, depth)) = stack.pop() {
        if depth > limits.max_structural_depth {
            return Err(ValueError::Limit { limit: "depth" });
        }

        match value {
            Value::Null => add_encoded_size(&mut encoded_size, 4, limits)?,
            Value::Bool(true) => add_encoded_size(&mut encoded_size, 4, limits)?,
            Value::Bool(false) => add_encoded_size(&mut encoded_size, 5, limits)?,
            Value::Number(number) => {
                add_encoded_size(&mut encoded_size, number.to_string().len() as u64, limits)?;
            }
            Value::String(text) => {
                validate_string_length(text, limits)?;
                add_encoded_size(&mut encoded_size, encoded_string_size(text), limits)?;
            }
            Value::Array(values) => {
                add_collection_items(&mut item_count, values.len() as u64, limits)?;
                add_encoded_size(
                    &mut encoded_size,
                    collection_punctuation(values.len()),
                    limits,
                )?;
                for child in values {
                    stack.push((child, depth.saturating_add(1)));
                }
            }
            Value::Object(object) => {
                add_collection_items(&mut item_count, object.len() as u64, limits)?;
                add_encoded_size(
                    &mut encoded_size,
                    collection_punctuation(object.len()),
                    limits,
                )?;
                for (name, child) in object {
                    validate_string_length(name, limits)?;
                    add_encoded_size(
                        &mut encoded_size,
                        encoded_string_size(name).saturating_add(1),
                        limits,
                    )?;
                    stack.push((child, depth.saturating_add(1)));
                }
            }
        }
    }

    Ok(encoded_size)
}

fn add_collection_items(
    item_count: &mut u64,
    additional: u64,
    limits: &crate::limits::LimitProfile,
) -> Result<(), ValueError> {
    *item_count = item_count
        .checked_add(additional)
        .ok_or(ValueError::Limit {
            limit: "collection item",
        })?;
    if *item_count > limits.max_collection_items {
        return Err(ValueError::Limit {
            limit: "collection item",
        });
    }
    Ok(())
}

fn add_encoded_size(
    encoded_size: &mut u64,
    additional: u64,
    limits: &crate::limits::LimitProfile,
) -> Result<(), ValueError> {
    *encoded_size = encoded_size
        .checked_add(additional)
        .ok_or(ValueError::Limit {
            limit: "encoded byte",
        })?;
    if *encoded_size > limits.max_document_bytes {
        return Err(ValueError::Limit {
            limit: "encoded byte",
        });
    }
    Ok(())
}

fn collection_punctuation(length: usize) -> u64 {
    if length == 0 {
        2
    } else {
        (length as u64).saturating_add(1)
    }
}

fn encoded_string_size(value: &str) -> u64 {
    let contents = value.chars().fold(0_u64, |size, character| {
        let escaped = match character {
            '\u{0008}' | '\t' | '\n' | '\u{000c}' | '\r' | '"' | '\\' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => character.len_utf8() as u64,
        };
        size.saturating_add(escaped)
    });
    contents.saturating_add(2)
}

fn validate_string_length(
    value: &str,
    limits: &crate::limits::LimitProfile,
) -> Result<(), ValueError> {
    if value.len() as u64 > limits.max_string_bytes {
        return Err(ValueError::Limit {
            limit: "string byte",
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn value_limits_reject_collection_growth_before_traversal() {
        let limits = crate::limits::LimitProfile {
            max_collection_items: 2,
            ..ABILITY_LIMITS_V1
        };
        let value = Value::Array(vec![Value::Null, Value::Null, Value::Null]);

        assert!(matches!(
            validate_value_limits(&value, &limits),
            Err(ValueError::Limit {
                limit: "collection item"
            })
        ));
    }

    #[test]
    fn value_limits_precompute_encoded_size() {
        let limits = crate::limits::LimitProfile {
            max_document_bytes: 5,
            ..ABILITY_LIMITS_V1
        };
        let value = Value::String("1234".to_string());

        assert!(matches!(
            validate_value_limits(&value, &limits),
            Err(ValueError::Limit {
                limit: "encoded byte"
            })
        ));
    }

    #[test]
    fn structural_preflight_bounds_wide_expressions_before_stack_growth() {
        let expression = ValueExpression::List {
            items: vec![
                ValueExpression::Literal {
                    value: AbilityValue::new(Value::Null).expect("valid test value"),
                };
                3
            ],
        };

        assert!(!expression.is_within_limits(64, 2));
    }
}
