//! Closed portable schemas for values crossing ability boundaries.
//!
//! The vocabulary deliberately excludes executable predicates and remote
//! schema references. String constraints use named syntax profiles so Nix,
//! native Rust, and web consumers can implement identical semantics.
//!
//! Variants carry an explicit `kind` tag:
//!
//! ```json
//! {"kind":"optional","value":{"kind":"boolean"}}
//! ```

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::identity::LocalKey;

/// Identifies one top-level JSON representation admitted by a schema.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum JsonValueKind {
    /// JSON array.
    Array,
    /// JSON Boolean.
    Boolean,
    /// JSON number.
    Number,
    /// JSON object.
    Object,
    /// JSON string.
    String,
}

impl JsonValueKind {
    /// Returns the top-level kind of a non-null JSON value.
    #[must_use]
    pub const fn of_json(value: &serde_json::Value) -> Option<Self> {
        match value {
            serde_json::Value::Null => None,
            serde_json::Value::Bool(_) => Some(Self::Boolean),
            serde_json::Value::Number(_) => Some(Self::Number),
            serde_json::Value::String(_) => Some(Self::String),
            serde_json::Value::Array(_) => Some(Self::Array),
            serde_json::Value::Object(_) => Some(Self::Object),
        }
    }
}

/// Names a closed, cross-consumer string grammar.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StringSyntax {
    /// Uses the version-1 local-key grammar `[A-Za-z0-9._-]+`.
    LocalKeyV1,
    /// Uses at least two dot-separated `[A-Za-z0-9_-]+` segments.
    QualifiedNameV1,
    /// Uses a normalized absolute path with no empty, `.` or `..` components.
    ExecutionPathV1,
}

/// Constrains strings used as values or map keys.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StringConstraint {
    /// Sets the maximum UTF-8 byte length.
    pub max_length: u64,
    /// Selects an optional closed syntax profile.
    pub syntax: Option<StringSyntax>,
}

/// Defines one closed portable value schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ValueSchema {
    /// Accepts a JSON Boolean.
    Boolean,
    /// Accepts a bounded signed integer.
    Integer {
        /// Inclusive minimum accepted value.
        minimum: i64,
        /// Inclusive maximum accepted value.
        maximum: i64,
    },
    /// Accepts a bounded string under an optional syntax profile.
    String {
        /// Maximum UTF-8 byte length.
        max_length: u64,
        /// Optional closed syntax profile.
        syntax: Option<StringSyntax>,
    },
    /// Accepts exactly one member of a sorted closed string set.
    StringEnum {
        /// Allowed values in canonical byte order.
        values: Vec<String>,
    },
    /// Accepts an ordered bounded list.
    List {
        /// Schema applied to each list element.
        element: Box<ValueSchema>,
        /// Maximum number of elements.
        max_items: u64,
        /// Requires every element's canonical JSON encoding to be distinct.
        #[serde(default, skip_serializing_if = "is_false")]
        unique: bool,
        /// Requires strict ascending order by canonical JSON encoding.
        #[serde(default, skip_serializing_if = "is_false")]
        canonical_order: bool,
    },
    /// Accepts a bounded map with constrained string keys.
    Map {
        /// Constraint applied to every member name.
        key: StringConstraint,
        /// Schema applied to every member value.
        value: Box<ValueSchema>,
        /// Maximum number of entries.
        max_entries: u64,
    },
    /// Accepts a closed record with named optional fields.
    Record {
        /// Defines every permitted field in canonical key order.
        fields: BTreeMap<LocalKey, ValueSchema>,
        /// Names fields that may be absent, in canonical key order.
        optional_fields: Vec<LocalKey>,
    },
    /// Accepts a closed object whose application-owned keys retain their spelling.
    DocumentRecord {
        /// Maximum UTF-8 byte length of every declared field name.
        key_max_length: u64,
        /// Defines every permitted document field in canonical key order.
        fields: BTreeMap<String, ValueSchema>,
        /// Names fields that may be absent, in canonical key order.
        optional_fields: Vec<String>,
    },
    /// Accepts one closed record variant selected by a string tag field.
    TaggedUnion {
        /// Names the discriminating record field.
        tag: LocalKey,
        /// Maps each allowed tag value to its complete record schema.
        variants: BTreeMap<LocalKey, ValueSchema>,
    },
    /// Accepts one raw JSON value from variants with distinct top-level kinds.
    DisjointUnion {
        /// Schemas ordered by their top-level JSON kind.
        variants: Vec<ValueSchema>,
    },
    /// Accepts explicit null or a value satisfying the nested schema.
    Optional {
        /// Schema for the present value.
        value: Box<ValueSchema>,
    },
    /// Accepts an immutable [`crate::ArtifactReference`].
    ArtifactReference,
    /// Accepts a scoped [`crate::ResourceReference`].
    ResourceReference,
    /// Accepts the closed shape of a [`crate::ProviderAssignment`] record.
    ProviderAssignment,
    /// Accepts a runtime-generated [`crate::TransactionBlobReference`].
    TransactionBlobReference,
    /// Accepts a typed [`crate::OperationResultReference`].
    OperationResultReference,
}

const fn is_false(value: &bool) -> bool {
    !*value
}

impl ValueSchema {
    /// Reports whether recursive schema nesting and collection growth stay bounded.
    #[must_use]
    pub fn is_within_limits(&self, max_depth: u32, max_items: u64) -> bool {
        let mut item_count = 0_u64;
        let mut stack = vec![(self, 1_u32)];

        while let Some((schema, depth)) = stack.pop() {
            if depth > max_depth {
                return false;
            }

            let child_depth = depth.saturating_add(1);
            match schema {
                Self::List { element, .. }
                | Self::Map { value: element, .. }
                | Self::Optional { value: element } => stack.push((element, child_depth)),
                Self::Record {
                    fields,
                    optional_fields,
                } => {
                    item_count = item_count
                        .saturating_add(fields.len() as u64)
                        .saturating_add(optional_fields.len() as u64);
                    if item_count > max_items {
                        return false;
                    }
                    stack.extend(fields.values().map(|field| (field, child_depth)));
                }
                Self::DocumentRecord {
                    fields,
                    optional_fields,
                    ..
                } => {
                    item_count = item_count
                        .saturating_add(fields.len() as u64)
                        .saturating_add(optional_fields.len() as u64);
                    if item_count > max_items {
                        return false;
                    }
                    stack.extend(fields.values().map(|field| (field, child_depth)));
                }
                Self::TaggedUnion { variants, .. } => {
                    item_count = item_count.saturating_add(variants.len() as u64);
                    if item_count > max_items {
                        return false;
                    }
                    stack.extend(variants.values().map(|variant| (variant, child_depth)));
                }
                Self::DisjointUnion { variants } => {
                    item_count = item_count.saturating_add(variants.len() as u64);
                    if item_count > max_items {
                        return false;
                    }
                    stack.extend(variants.iter().map(|variant| (variant, child_depth)));
                }
                Self::Boolean
                | Self::Integer { .. }
                | Self::String { .. }
                | Self::ArtifactReference
                | Self::ResourceReference
                | Self::ProviderAssignment
                | Self::TransactionBlobReference
                | Self::OperationResultReference => {}
                Self::StringEnum { values } => {
                    item_count = item_count.saturating_add(values.len() as u64);
                    if item_count > max_items {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Returns the single top-level JSON kind admitted by this schema.
    ///
    /// Optional and disjoint-union schemas return `None` because they can admit
    /// more than one top-level representation.
    #[must_use]
    pub const fn top_level_json_kind(&self) -> Option<JsonValueKind> {
        match self {
            Self::Boolean => Some(JsonValueKind::Boolean),
            Self::Integer { .. } => Some(JsonValueKind::Number),
            Self::String { .. } | Self::StringEnum { .. } => Some(JsonValueKind::String),
            Self::List { .. } => Some(JsonValueKind::Array),
            Self::Map { .. }
            | Self::Record { .. }
            | Self::DocumentRecord { .. }
            | Self::TaggedUnion { .. }
            | Self::ArtifactReference
            | Self::ResourceReference
            | Self::ProviderAssignment
            | Self::TransactionBlobReference
            | Self::OperationResultReference => Some(JsonValueKind::Object),
            Self::DisjointUnion { .. } | Self::Optional { .. } => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn structural_preflight_bounds_wide_schemas_before_stack_growth() {
        let fields = ["a", "b", "c"]
            .into_iter()
            .map(|name| {
                (
                    LocalKey::new(name).expect("valid test key"),
                    ValueSchema::Boolean,
                )
            })
            .collect();
        let schema = ValueSchema::Record {
            fields,
            optional_fields: Vec::new(),
        };

        assert!(!schema.is_within_limits(64, 2));
    }

    #[test]
    fn unconstrained_lists_keep_the_existing_wire_shape() {
        let schema = ValueSchema::List {
            element: Box::new(ValueSchema::Boolean),
            max_items: 4,
            unique: false,
            canonical_order: false,
        };

        assert_eq!(
            serde_json::to_value(schema).expect("list schema serializes"),
            serde_json::json!({
                "kind": "list",
                "element": {"kind": "boolean"},
                "max_items": 4,
            })
        );
    }

    #[test]
    fn constrained_lists_round_trip_without_a_parallel_schema_version() {
        let encoded = serde_json::json!({
            "kind": "list",
            "element": {"kind": "string", "max_length": 8, "syntax": null},
            "max_items": 4,
            "unique": true,
            "canonical_order": true,
        });
        let schema: ValueSchema =
            serde_json::from_value(encoded.clone()).expect("constrained list schema decodes");

        assert_eq!(
            serde_json::to_value(schema).expect("constrained list schema serializes"),
            encoded
        );
    }

    #[test]
    fn disjoint_union_round_trips_raw_variants() {
        let encoded = serde_json::json!({
            "kind": "disjoint-union",
            "variants": [
                {"kind": "boolean"},
                {"kind": "integer", "minimum": 0, "maximum": 8},
                {"kind": "string", "max_length": 8, "syntax": null},
            ],
        });
        let schema: ValueSchema =
            serde_json::from_value(encoded.clone()).expect("disjoint union schema decodes");

        assert_eq!(
            serde_json::to_value(schema).expect("disjoint union schema serializes"),
            encoded
        );
    }
}
