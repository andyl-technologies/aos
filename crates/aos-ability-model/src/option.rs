//! Authenticated module option declarations and their portable type algebra.
//!
//! This module is the single wire and documentation authority for option types,
//! safe defaults and examples, visibility, and declaration source provenance.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::document::{DocumentError, PackageDocument, VersionedDocument};
use crate::identity::{LocalKey, RelativePath};
use crate::limits::LimitProfile;
use crate::schema::{
    JsonValueKind, StringConstraint, ValueConstraint, ValueSchema, string_matches,
};
use crate::value::{AbilityValue, ArtifactReference};

/// Records one package-owned module option from the authenticated evaluator.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageOptionDeclaration {
    /// Carries the exact option path segments.
    pub path: Vec<String>,
    /// Preserves the module engine's stable type signature.
    pub type_signature: String,
    /// Preserves the closed structured type declaration.
    pub structured_type: OptionType,
    /// Preserves the declaration's public prose.
    pub description: String,
    /// Preserves a safe literal or documented computed default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<DocumentedValue>,
    /// Preserves a safe literal or documented example.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<DocumentedValue>,
    /// Selects the option's documentation visibility.
    pub visibility: OptionVisibility,
    /// Records whether the module engine rejects external definitions.
    pub read_only: bool,
    /// Records whether another authenticated package may contribute below the option.
    pub contributable: bool,
    /// Carries an optional deprecation notice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<String>,
    /// Names the replacement option path when the declaration is deprecated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<Vec<String>>,
    /// Locates the declaration within the authenticated package module artifact.
    pub source: OptionSource,
}

/// Selects the visibility of one authenticated package option declaration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OptionVisibility {
    /// Exposes the option to package users.
    Public,
    /// Retains the option for authenticated tooling.
    Internal,
    /// Hides implementation plumbing from ordinary documentation.
    Hidden,
}

/// Describes one option using the closed portable module type algebra.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum OptionType {
    /// Boolean value.
    Bool,
    /// Signed integer value.
    Integer {
        /// Inclusive lower bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<i64>,
        /// Inclusive upper bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max: Option<i64>,
    },
    /// Unsigned integer value.
    Unsigned {
        /// Inclusive lower bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<u64>,
        /// Inclusive upper bound.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max: Option<u64>,
    },
    /// String with optional validation constraints.
    String {
        /// Stable pattern description.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pattern: Option<String>,
        /// Maximum string length when bounded.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_length: Option<u64>,
    },
    /// TCP or UDP port number.
    Port,
    /// Filesystem path.
    Path,
    /// Duration value.
    Duration,
    /// CIDR network prefix.
    Cidr,
    /// Opaque secret or credential reference.
    OpaqueReference,
    /// Enumerated string values.
    Enum {
        /// Exact values and their optional structured prose.
        values: Vec<OptionEnumValue>,
    },
    /// Ordered list.
    List {
        /// Element type.
        element: Box<OptionType>,
        /// Maximum element count for a portable bounded list.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_items: Option<u64>,
        /// Whether duplicates are forbidden.
        #[serde(default)]
        unique: bool,
        /// Whether values use canonical order.
        #[serde(default)]
        canonical_order: bool,
    },
    /// Unordered semantic set.
    Set {
        /// Element type.
        element: Box<OptionType>,
    },
    /// Attribute map with dynamic keys.
    AttrsOf {
        /// Value type.
        value: Box<OptionType>,
        /// Dynamic segment placeholder.
        placeholder: String,
    },
    /// Bounded portable map with checked dynamic keys.
    Map {
        /// Constraint applied to every member name.
        key: StringConstraint,
        /// Value type.
        value: Box<OptionType>,
        /// Maximum number of entries.
        max_entries: u64,
    },
    /// Fixed-field record.
    Submodule {
        /// Canonically keyed fields.
        fields: BTreeMap<String, OptionType>,
        /// Whether additional fields are admitted.
        #[serde(default)]
        open: bool,
    },
    /// Closed portable record with local-key field names.
    Record {
        /// Defines every permitted field.
        #[schemars(with = "BTreeMap<String, OptionType>")]
        fields: BTreeMap<LocalKey, OptionType>,
        /// Names fields that may be absent.
        #[schemars(with = "Vec<String>")]
        optional_fields: Vec<LocalKey>,
    },
    /// Closed portable object retaining application-owned field spelling.
    DocumentRecord {
        /// Maximum UTF-8 byte length of declared field names.
        key_max_length: u64,
        /// Defines every permitted field.
        fields: BTreeMap<String, OptionType>,
        /// Names fields that may be absent.
        optional_fields: Vec<String>,
    },
    /// Closed record union selected by one local-key tag field.
    TaggedUnion {
        /// Names the discriminating record field.
        #[schemars(with = "String")]
        tag: LocalKey,
        /// Maps tag values to their complete record variants.
        #[schemars(with = "BTreeMap<String, OptionType>")]
        variants: BTreeMap<LocalKey, OptionType>,
    },
    /// Portable union whose variants have distinct top-level JSON kinds.
    DisjointUnion {
        /// Variants in top-level JSON-kind order.
        variants: Vec<OptionType>,
    },
    /// Nullable value.
    Nullable {
        /// Non-null value type.
        value: Box<OptionType>,
    },
    /// Portable nullable value projected directly from an ability schema.
    Optional {
        /// Non-null value type.
        value: Box<OptionType>,
    },
    /// Portable option value with closed data constraints.
    Refined {
        /// Base option type checked before the refinements.
        value: Box<OptionType>,
        /// Predicates shared with the canonical ability schema.
        constraints: Vec<ValueConstraint>,
    },
    /// Bounded union.
    OneOf {
        /// Alternative types.
        alternatives: Vec<OptionType>,
    },
    /// Stable fallback for a module type without a rich variant.
    Opaque {
        /// Stable type signature.
        signature: String,
    },
    /// Immutable artifact reference.
    ArtifactReference,
    /// Scoped resource reference.
    ResourceReference,
    /// Checked provider assignment.
    ProviderAssignment,
    /// Typed operation-result reference.
    OperationResultReference,
}

/// Describes one value in a package option enumeration.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OptionEnumValue {
    /// Carries the exact enumerated value.
    pub value: String,
}

/// Preserves one bounded literal or explanatory computed option value.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DocumentedValue {
    /// Carries a canonical JSON-compatible literal.
    Literal {
        /// Carries the exact literal value.
        #[schemars(with = "serde_json::Value")]
        value: AbilityValue,
    },
    /// Carries stable explanatory text for a computed value.
    Text {
        /// Describes the computed value without evaluating it.
        text: String,
    },
}

impl OptionType {
    /// Reports whether the recursive type and its strings fit the versioned limits.
    #[must_use]
    pub fn is_within_limits(&self, limits: &LimitProfile) -> bool {
        let mut items = 0_u64;
        let mut stack = vec![(self, 1_u32)];

        while let Some((option_type, depth)) = stack.pop() {
            if depth > limits.max_structural_depth {
                return false;
            }
            items = items.saturating_add(1);
            if items > limits.max_collection_items {
                return false;
            }

            let valid_string = |value: &str| {
                !value.is_empty()
                    && value.len() as u64 <= limits.max_string_bytes
                    && !value.chars().any(char::is_control)
            };
            let child_depth = depth.saturating_add(1);
            match option_type {
                Self::Integer { min, max } => {
                    if min
                        .zip(*max)
                        .is_some_and(|(minimum, maximum)| minimum > maximum)
                    {
                        return false;
                    }
                }
                Self::Unsigned { min, max } => {
                    if min
                        .zip(*max)
                        .is_some_and(|(minimum, maximum)| minimum > maximum)
                    {
                        return false;
                    }
                }
                Self::String {
                    pattern,
                    max_length,
                } => {
                    if pattern.as_deref().is_some_and(|value| !valid_string(value))
                        || max_length.is_some_and(|length| length > limits.max_string_bytes)
                    {
                        return false;
                    }
                }
                Self::Enum { values } => {
                    items = items.saturating_add(values.len() as u64);
                    if items > limits.max_collection_items
                        || values.is_empty()
                        || values.iter().any(|entry| !valid_string(&entry.value))
                        || values.windows(2).any(|pair| pair[0].value >= pair[1].value)
                    {
                        return false;
                    }
                }
                Self::List {
                    element, max_items, ..
                } => {
                    if max_items.is_some_and(|maximum| maximum > limits.max_collection_items) {
                        return false;
                    }
                    stack.push((element, child_depth));
                }
                Self::Set { element }
                | Self::Nullable { value: element }
                | Self::Optional { value: element } => stack.push((element, child_depth)),
                Self::Refined { value, constraints } => {
                    items = items.saturating_add(constraints.len() as u64);
                    if constraints.is_empty()
                        || items > limits.max_collection_items
                        || constraints.iter().any(|constraint| {
                            !constraint.is_within_limits(
                                limits.max_string_bytes,
                                limits.max_collection_items,
                            )
                        })
                    {
                        return false;
                    }
                    stack.push((value, child_depth));
                }
                Self::AttrsOf { value, placeholder } => {
                    if !valid_string(placeholder) {
                        return false;
                    }
                    stack.push((value, child_depth));
                }
                Self::Map {
                    key,
                    value,
                    max_entries,
                } => {
                    if key.max_length == 0
                        || key.max_length > limits.max_string_bytes
                        || *max_entries == 0
                        || *max_entries > limits.max_collection_items
                    {
                        return false;
                    }
                    stack.push((value, child_depth));
                }
                Self::Submodule { fields, .. } => {
                    items = items.saturating_add(fields.len() as u64);
                    if items > limits.max_collection_items
                        || fields.keys().any(|name| !valid_string(name))
                    {
                        return false;
                    }
                    stack.extend(fields.values().map(|field| (field, child_depth)));
                }
                Self::Record {
                    fields,
                    optional_fields,
                } => {
                    items = items
                        .saturating_add(fields.len() as u64)
                        .saturating_add(optional_fields.len() as u64);
                    if items > limits.max_collection_items
                        || optional_fields.windows(2).any(|pair| pair[0] >= pair[1])
                        || optional_fields
                            .iter()
                            .any(|name| !fields.contains_key(name))
                    {
                        return false;
                    }
                    stack.extend(fields.values().map(|field| (field, child_depth)));
                }
                Self::DocumentRecord {
                    key_max_length,
                    fields,
                    optional_fields,
                } => {
                    items = items
                        .saturating_add(fields.len() as u64)
                        .saturating_add(optional_fields.len() as u64);
                    if *key_max_length == 0
                        || *key_max_length > limits.max_string_bytes
                        || items > limits.max_collection_items
                        || fields.keys().any(|name| {
                            name.is_empty()
                                || name.len() as u64 > *key_max_length
                                || name.chars().any(char::is_control)
                        })
                        || optional_fields.windows(2).any(|pair| pair[0] >= pair[1])
                        || optional_fields
                            .iter()
                            .any(|name| !fields.contains_key(name))
                    {
                        return false;
                    }
                    stack.extend(fields.values().map(|field| (field, child_depth)));
                }
                Self::TaggedUnion { variants, .. } => {
                    items = items.saturating_add(variants.len() as u64);
                    if variants.is_empty() || items > limits.max_collection_items {
                        return false;
                    }
                    stack.extend(variants.values().map(|variant| (variant, child_depth)));
                }
                Self::DisjointUnion { variants } => {
                    items = items.saturating_add(variants.len() as u64);
                    let kinds = variants
                        .iter()
                        .filter_map(OptionType::top_level_json_kind)
                        .collect::<Vec<_>>();
                    if variants.is_empty()
                        || variants.len() as u64 > limits.max_collection_items
                        || kinds.len() != variants.len()
                        || kinds.windows(2).any(|pair| pair[0] >= pair[1])
                        || items > limits.max_collection_items
                    {
                        return false;
                    }
                    stack.extend(variants.iter().map(|variant| (variant, child_depth)));
                }
                Self::OneOf { alternatives } => {
                    items = items.saturating_add(alternatives.len() as u64);
                    let unique = alternatives
                        .iter()
                        .filter_map(|alternative| aos_contract::canonical::to_vec(alternative).ok())
                        .collect::<BTreeSet<_>>();
                    if alternatives.is_empty()
                        || alternatives.len() as u64 > limits.max_collection_items
                        || unique.len() != alternatives.len()
                        || items > limits.max_collection_items
                    {
                        return false;
                    }
                    stack.extend(
                        alternatives
                            .iter()
                            .map(|alternative| (alternative, child_depth)),
                    );
                }
                Self::Opaque { signature } => {
                    if !valid_string(signature) {
                        return false;
                    }
                }
                Self::Bool
                | Self::Port
                | Self::Path
                | Self::Duration
                | Self::Cidr
                | Self::OpaqueReference
                | Self::ArtifactReference
                | Self::ResourceReference
                | Self::ProviderAssignment
                | Self::OperationResultReference => {}
            }
        }

        true
    }

    /// Reports whether a canonical literal matches this portable option type.
    #[must_use]
    pub fn admits(&self, value: &AbilityValue) -> bool {
        self.admits_json(value.as_json())
    }

    fn admits_json(&self, value: &serde_json::Value) -> bool {
        match self {
            Self::Bool => value.is_boolean(),
            Self::Integer { min, max } => value.as_i64().is_some_and(|candidate| {
                min.is_none_or(|minimum| candidate >= minimum)
                    && max.is_none_or(|maximum| candidate <= maximum)
            }),
            Self::Unsigned { min, max } => value.as_u64().is_some_and(|candidate| {
                min.is_none_or(|minimum| candidate >= minimum)
                    && max.is_none_or(|maximum| candidate <= maximum)
            }),
            Self::String { max_length, .. } => value.as_str().is_some_and(|candidate| {
                max_length.is_none_or(|maximum| candidate.len() as u64 <= maximum)
            }),
            Self::Port => value
                .as_u64()
                .is_some_and(|candidate| (1..=65_535).contains(&candidate)),
            Self::Path | Self::Duration | Self::Cidr | Self::OpaqueReference => value.is_string(),
            Self::Enum { values } => value
                .as_str()
                .is_some_and(|candidate| values.iter().any(|entry| entry.value == candidate)),
            Self::List {
                element,
                max_items,
                unique,
                canonical_order,
            } => value.as_array().is_some_and(|values| {
                max_items.is_none_or(|maximum| values.len() as u64 <= maximum)
                    && values.iter().all(|value| element.admits_json(value))
                    && (!*unique
                        || values.iter().enumerate().all(|(index, value)| {
                            !values[index.saturating_add(1)..].contains(value)
                        }))
                    && (!*canonical_order
                        || values.windows(2).all(|pair| {
                            match (
                                aos_contract::canonical::to_vec(&pair[0]),
                                aos_contract::canonical::to_vec(&pair[1]),
                            ) {
                                (Ok(left), Ok(right)) => left < right,
                                _ => false,
                            }
                        }))
            }),
            Self::Set { element } => value.as_array().is_some_and(|values| {
                values.iter().all(|value| element.admits_json(value))
                    && values
                        .iter()
                        .enumerate()
                        .all(|(index, value)| !values[index.saturating_add(1)..].contains(value))
                    && values.windows(2).all(|pair| {
                        match (
                            aos_contract::canonical::to_vec(&pair[0]),
                            aos_contract::canonical::to_vec(&pair[1]),
                        ) {
                            (Ok(left), Ok(right)) => left < right,
                            _ => false,
                        }
                    })
            }),
            Self::AttrsOf { value: nested, .. } => value
                .as_object()
                .is_some_and(|values| values.values().all(|value| nested.admits_json(value))),
            Self::Map {
                key,
                value: nested,
                max_entries,
            } => value.as_object().is_some_and(|values| {
                values.len() as u64 <= *max_entries
                    && values.keys().all(|name| key_accepts(key, name))
                    && values.values().all(|value| nested.admits_json(value))
            }),
            Self::Submodule { fields, open } => value.as_object().is_some_and(|values| {
                (*open || values.keys().all(|name| fields.contains_key(name)))
                    && values.iter().all(|(name, value)| {
                        fields
                            .get(name)
                            .is_none_or(|field| field.admits_json(value))
                    })
            }),
            Self::Record {
                fields,
                optional_fields,
            } => value.as_object().is_some_and(|values| {
                values.keys().all(|name| {
                    LocalKey::new(name)
                        .ok()
                        .is_some_and(|name| fields.contains_key(&name))
                }) && fields.iter().all(|(name, field)| {
                    values
                        .get(name.as_str())
                        .is_some_and(|value| field.admits_json(value))
                        || optional_fields.contains(name)
                })
            }),
            Self::DocumentRecord {
                key_max_length,
                fields,
                optional_fields,
            } => value.as_object().is_some_and(|values| {
                values
                    .keys()
                    .all(|name| name.len() as u64 <= *key_max_length && fields.contains_key(name))
                    && fields.iter().all(|(name, field)| {
                        values
                            .get(name)
                            .is_some_and(|value| field.admits_json(value))
                            || optional_fields.contains(name)
                    })
            }),
            Self::TaggedUnion { tag, variants } => value.as_object().is_some_and(|values| {
                values
                    .get(tag.as_str())
                    .and_then(serde_json::Value::as_str)
                    .and_then(|variant| LocalKey::new(variant).ok())
                    .and_then(|variant| variants.get(&variant))
                    .is_some_and(|variant| variant.admits_json(value))
            }),
            Self::DisjointUnion { variants } => {
                variants
                    .iter()
                    .filter(|variant| variant.admits_json(value))
                    .count()
                    == 1
            }
            Self::Nullable { value: nested } | Self::Optional { value: nested } => {
                value.is_null() || nested.admits_json(value)
            }
            Self::Refined {
                value: nested,
                constraints,
            } => {
                nested.admits_json(value)
                    && constraints
                        .iter()
                        .all(|constraint| constraint.admits(value))
            }
            Self::OneOf { alternatives } => alternatives
                .iter()
                .any(|alternative| alternative.admits_json(value)),
            Self::Opaque { .. } => true,
            Self::ArtifactReference => {
                serde_json::from_value::<ArtifactReference>(value.clone()).is_ok()
            }
            Self::ResourceReference => {
                serde_json::from_value::<crate::ResourceReference>(value.clone()).is_ok()
            }
            Self::ProviderAssignment => {
                serde_json::from_value::<crate::ProviderAssignment>(value.clone()).is_ok()
            }
            Self::OperationResultReference => {
                serde_json::from_value::<crate::OperationResultReference>(value.clone()).is_ok()
            }
        }
    }

    fn top_level_json_kind(&self) -> Option<JsonValueKind> {
        match self {
            Self::Bool => Some(JsonValueKind::Boolean),
            Self::Integer { .. } | Self::Unsigned { .. } | Self::Port => {
                Some(JsonValueKind::Number)
            }
            Self::String { .. }
            | Self::Path
            | Self::Duration
            | Self::Cidr
            | Self::OpaqueReference
            | Self::Enum { .. } => Some(JsonValueKind::String),
            Self::List { .. } | Self::Set { .. } => Some(JsonValueKind::Array),
            Self::AttrsOf { .. }
            | Self::Map { .. }
            | Self::Submodule { .. }
            | Self::Record { .. }
            | Self::DocumentRecord { .. }
            | Self::TaggedUnion { .. }
            | Self::ArtifactReference
            | Self::ResourceReference
            | Self::ProviderAssignment
            | Self::OperationResultReference => Some(JsonValueKind::Object),
            Self::Nullable { .. }
            | Self::Optional { .. }
            | Self::OneOf { .. }
            | Self::DisjointUnion { .. }
            | Self::Opaque { .. } => None,
            Self::Refined { value, .. } => value.top_level_json_kind(),
        }
    }

    /// Returns whether this type contains a field without a portable rich type.
    #[must_use]
    pub fn contains_opaque(&self) -> bool {
        let mut stack = vec![self];

        while let Some(option_type) = stack.pop() {
            match option_type {
                Self::Opaque { .. } | Self::Submodule { open: true, .. } => return true,
                Self::List { element, .. }
                | Self::Set { element }
                | Self::Nullable { value: element }
                | Self::Optional { value: element }
                | Self::Refined { value: element, .. } => stack.push(element),
                Self::AttrsOf { value, .. } | Self::Map { value, .. } => stack.push(value),
                Self::Submodule {
                    fields,
                    open: false,
                }
                | Self::DocumentRecord { fields, .. } => stack.extend(fields.values()),
                Self::Record { fields, .. }
                | Self::TaggedUnion {
                    variants: fields, ..
                } => stack.extend(fields.values()),
                Self::OneOf { alternatives }
                | Self::DisjointUnion {
                    variants: alternatives,
                } => stack.extend(alternatives),
                Self::Bool
                | Self::Integer { .. }
                | Self::Unsigned { .. }
                | Self::String { .. }
                | Self::Port
                | Self::Path
                | Self::Duration
                | Self::Cidr
                | Self::OpaqueReference
                | Self::Enum { .. }
                | Self::ArtifactReference
                | Self::ResourceReference
                | Self::ProviderAssignment
                | Self::OperationResultReference => {}
            }
        }

        false
    }
}

fn refinements_are_compatible(option_type: &OptionType) -> bool {
    match option_type {
        OptionType::Refined { value, constraints } => {
            option_type_as_value_schema(value).is_some_and(|schema| {
                constraints
                    .iter()
                    .all(|constraint| constraint.is_compatible_with(&schema))
            }) && refinements_are_compatible(value)
        }
        OptionType::List { element, .. }
        | OptionType::Set { element }
        | OptionType::Nullable { value: element }
        | OptionType::Optional { value: element } => refinements_are_compatible(element),
        OptionType::AttrsOf { value, .. } | OptionType::Map { value, .. } => {
            refinements_are_compatible(value)
        }
        OptionType::Submodule { fields, .. } | OptionType::DocumentRecord { fields, .. } => {
            fields.values().all(refinements_are_compatible)
        }
        OptionType::Record { fields, .. }
        | OptionType::TaggedUnion {
            variants: fields, ..
        } => fields.values().all(refinements_are_compatible),
        OptionType::OneOf { alternatives }
        | OptionType::DisjointUnion {
            variants: alternatives,
        } => alternatives.iter().all(refinements_are_compatible),
        OptionType::Bool
        | OptionType::Integer { .. }
        | OptionType::Unsigned { .. }
        | OptionType::String { .. }
        | OptionType::Port
        | OptionType::Path
        | OptionType::Duration
        | OptionType::Cidr
        | OptionType::OpaqueReference
        | OptionType::Enum { .. }
        | OptionType::Opaque { .. }
        | OptionType::ArtifactReference
        | OptionType::ResourceReference
        | OptionType::ProviderAssignment
        | OptionType::OperationResultReference => true,
    }
}

fn option_type_as_value_schema(option_type: &OptionType) -> Option<ValueSchema> {
    const MAX_EXACT_INTEGER: i64 = 9_007_199_254_740_991;
    const MAX_STRING_LENGTH: u64 = 1_048_576;
    const MAX_COLLECTION_ITEMS: u64 = 2_000_000;

    Some(match option_type {
        OptionType::Bool => ValueSchema::Boolean,
        OptionType::Integer { min, max } => ValueSchema::Integer {
            minimum: min.unwrap_or(-MAX_EXACT_INTEGER),
            maximum: max.unwrap_or(MAX_EXACT_INTEGER),
        },
        OptionType::Unsigned { min, max } => ValueSchema::Integer {
            minimum: i64::try_from(min.unwrap_or(0)).ok()?,
            maximum: i64::try_from(max.unwrap_or(MAX_EXACT_INTEGER as u64)).ok()?,
        },
        OptionType::String { max_length, .. } => ValueSchema::String {
            max_length: max_length.unwrap_or(MAX_STRING_LENGTH),
            syntax: None,
        },
        OptionType::Path
        | OptionType::Duration
        | OptionType::Cidr
        | OptionType::OpaqueReference => ValueSchema::String {
            max_length: MAX_STRING_LENGTH,
            syntax: None,
        },
        OptionType::Port => ValueSchema::Integer {
            minimum: 0,
            maximum: 65_535,
        },
        OptionType::Enum { values } => ValueSchema::StringEnum {
            values: values.iter().map(|entry| entry.value.clone()).collect(),
        },
        OptionType::List {
            element,
            max_items,
            unique,
            canonical_order,
        } => ValueSchema::List {
            element: Box::new(option_type_as_value_schema(element)?),
            max_items: max_items.unwrap_or(MAX_COLLECTION_ITEMS),
            unique: *unique,
            canonical_order: *canonical_order,
        },
        OptionType::Set { element } => ValueSchema::List {
            element: Box::new(option_type_as_value_schema(element)?),
            max_items: MAX_COLLECTION_ITEMS,
            unique: true,
            canonical_order: false,
        },
        OptionType::Map {
            key,
            value,
            max_entries,
        } => ValueSchema::Map {
            key: key.clone(),
            value: Box::new(option_type_as_value_schema(value)?),
            max_entries: *max_entries,
        },
        OptionType::Record {
            fields,
            optional_fields,
        } => ValueSchema::Record {
            fields: fields
                .iter()
                .map(|(name, field)| Some((name.clone(), option_type_as_value_schema(field)?)))
                .collect::<Option<_>>()?,
            optional_fields: optional_fields.clone(),
        },
        OptionType::DocumentRecord {
            key_max_length,
            fields,
            optional_fields,
        } => ValueSchema::DocumentRecord {
            key_max_length: *key_max_length,
            fields: fields
                .iter()
                .map(|(name, field)| Some((name.clone(), option_type_as_value_schema(field)?)))
                .collect::<Option<_>>()?,
            optional_fields: optional_fields.clone(),
        },
        OptionType::TaggedUnion { tag, variants } => ValueSchema::TaggedUnion {
            tag: tag.clone(),
            variants: variants
                .iter()
                .map(|(name, variant)| Some((name.clone(), option_type_as_value_schema(variant)?)))
                .collect::<Option<_>>()?,
        },
        OptionType::DisjointUnion { variants } => ValueSchema::DisjointUnion {
            variants: variants
                .iter()
                .map(option_type_as_value_schema)
                .collect::<Option<_>>()?,
        },
        OptionType::Optional { value } | OptionType::Nullable { value } => ValueSchema::Optional {
            value: Box::new(option_type_as_value_schema(value)?),
        },
        OptionType::Refined { value, constraints } => ValueSchema::Refined {
            value: Box::new(option_type_as_value_schema(value)?),
            constraints: constraints.clone(),
        },
        OptionType::ArtifactReference => ValueSchema::ArtifactReference,
        OptionType::ResourceReference => ValueSchema::ResourceReference,
        OptionType::ProviderAssignment => ValueSchema::ProviderAssignment,
        OptionType::OperationResultReference => ValueSchema::OperationResultReference,
        OptionType::AttrsOf { .. }
        | OptionType::Submodule { .. }
        | OptionType::OneOf { .. }
        | OptionType::Opaque { .. } => return None,
    })
}

fn key_accepts(constraint: &StringConstraint, value: &str) -> bool {
    string_matches(constraint.max_length, constraint.syntax, value)
}

/// Locates one option declaration below the authenticated package module root.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OptionSource {
    /// Names the normalized source file below the package module artifact.
    #[schemars(with = "String")]
    pub path: RelativePath,
}

/// Validates the canonical package-owned option declaration surface.
///
/// # Errors
///
/// Returns an error when paths are repeated or unordered or any declaration
/// value exceeds the versioned bounds.
pub fn validate_package_option_declarations(
    declarations: &[PackageOptionDeclaration],
    limits: &LimitProfile,
) -> Result<(), DocumentError> {
    let bounded_prose = |value: &str| {
        !value.trim().is_empty()
            && value.len() as u64 <= limits.max_string_bytes
            && !value
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    };

    if declarations.len() as u64 > limits.max_collection_items {
        return Err(DocumentError::Limit {
            label: PackageDocument::SCHEMA.to_string(),
            limit: "collection item",
        });
    }
    for pair in declarations.windows(2) {
        if pair[0].path >= pair[1].path {
            return Err(DocumentError::Decode {
                label: PackageDocument::SCHEMA.to_string(),
                source: anyhow::anyhow!(
                    "package option declarations must be strictly ordered by path"
                ),
            });
        }
    }
    for declaration in declarations {
        let path_is_valid = !declaration.path.is_empty()
            && declaration.path.iter().all(|segment| {
                !segment.is_empty()
                    && segment.len() as u64 <= limits.max_string_bytes
                    && !segment.chars().any(char::is_control)
            });
        let strings_are_valid = !declaration.type_signature.is_empty()
            && declaration.type_signature.len() as u64 <= limits.max_string_bytes
            && !declaration.type_signature.chars().any(char::is_control)
            && bounded_prose(&declaration.description)
            && declaration.deprecated.as_deref().is_none_or(bounded_prose);
        let structured_type_is_valid = declaration.structured_type.is_within_limits(limits)
            && refinements_are_compatible(&declaration.structured_type);
        let replacement_is_valid = declaration.replacement.as_ref().is_none_or(|path| {
            !path.is_empty()
                && path.iter().all(|segment| {
                    !segment.is_empty()
                        && segment.len() as u64 <= limits.max_string_bytes
                        && !segment.chars().any(char::is_control)
                })
        });
        let documented_value_is_valid = |value: &DocumentedValue| match value {
            DocumentedValue::Literal { value } => declaration.structured_type.admits(value),
            DocumentedValue::Text { text } => bounded_prose(text),
        };
        if !path_is_valid
            || !strings_are_valid
            || !structured_type_is_valid
            || !replacement_is_valid
            || declaration
                .default
                .as_ref()
                .is_some_and(|value| !documented_value_is_valid(value))
            || declaration
                .example
                .as_ref()
                .is_some_and(|value| !documented_value_is_valid(value))
            || (declaration.visibility == OptionVisibility::Public
                && declaration.structured_type.contains_opaque())
            || (declaration.replacement.is_some() && declaration.deprecated.is_none())
        {
            return Err(DocumentError::Decode {
                label: PackageDocument::SCHEMA.to_string(),
                source: anyhow::anyhow!(
                    "package option declaration '{}' is invalid",
                    declaration.path.join(".")
                ),
            });
        }
    }

    Ok(())
}
