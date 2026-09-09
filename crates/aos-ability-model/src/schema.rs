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

use serde::{Deserialize, Serialize};

use crate::identity::LocalKey;

/// Names a closed, cross-consumer string grammar.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StringSyntax {
    /// Uses the version-1 local-key grammar `[A-Za-z0-9._-]+`.
    LocalKeyV1,
    /// Uses at least two dot-separated `[A-Za-z0-9_-]+` segments.
    QualifiedNameV1,
}

/// Constrains strings used as values or map keys.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    /// Accepts one closed record variant selected by a string tag field.
    TaggedUnion {
        /// Names the discriminating record field.
        tag: LocalKey,
        /// Maps each allowed tag value to its complete record schema.
        variants: BTreeMap<LocalKey, ValueSchema>,
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
    /// Accepts a typed [`crate::OperationResultReference`].
    OperationResultReference,
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
                Self::TaggedUnion { variants, .. } => {
                    item_count = item_count.saturating_add(variants.len() as u64);
                    if item_count > max_items {
                        return false;
                    }
                    stack.extend(variants.values().map(|variant| (variant, child_depth)));
                }
                Self::Boolean
                | Self::Integer { .. }
                | Self::String { .. }
                | Self::ArtifactReference
                | Self::ResourceReference
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
}
