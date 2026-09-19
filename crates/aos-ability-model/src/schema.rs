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

/// Names one field path within a refined value.
pub type ValuePath = Vec<LocalKey>;

/// Names a portable character class that a refined string may exclude.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum ExcludedCharacterClass {
    /// Excludes ASCII control characters.
    AsciiControl,
    /// Excludes the ASCII space character.
    AsciiSpace,
    /// Excludes ASCII whitespace characters.
    AsciiWhitespace,
    /// Excludes carriage returns and line feeds.
    LineBreak,
}

/// Defines a closed, portable predicate applied after a value's base schema.
///
/// Each variant is data rather than executable code, so every schema consumer
/// can enforce and describe the same constraint.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ValueConstraint {
    /// Requires the root string to match the complete regular expression.
    StringPattern {
        /// Portable regular expression matched against the entire string.
        pattern: String,
    },
    /// Requires the root string, list, or map to contain at least this many items.
    MinimumSize {
        /// Inclusive minimum byte length or collection cardinality.
        minimum: u64,
    },
    /// Restricts the root integer to a sorted set of accepted values.
    IntegerSet {
        /// Accepted integers in canonical ascending order.
        values: Vec<i64>,
    },
    /// Requires every root map key to match the complete regular expression.
    MapKeysPattern {
        /// Portable regular expression matched against every map key.
        pattern: String,
    },
    /// Requires the root string to omit the named portable character classes.
    StringExcludes {
        /// Character classes that may not occur, in canonical order.
        classes: Vec<ExcludedCharacterClass>,
    },
    /// Allows at most one named root-record field to contain a non-null value.
    AtMostOneNonNull {
        /// Root-record fields participating in the constraint.
        #[schemars(with = "Vec<String>")]
        fields: Vec<LocalKey>,
    },
    /// Requires the list at a record path to contain distinct canonical values.
    UniqueAt {
        /// Path to the nested list.
        #[schemars(with = "Vec<String>")]
        path: ValuePath,
    },
    /// Requires the two lists at record paths to contain no common value.
    DisjointAt {
        /// Path to the first nested list.
        #[schemars(with = "Vec<String>")]
        left: ValuePath,
        /// Path to the second nested list.
        #[schemars(with = "Vec<String>")]
        right: ValuePath,
    },
    /// Requires one list to be a subset of another unless a field equals a value.
    SubsetUnless {
        /// Path to the list whose members must be allowed.
        #[schemars(with = "Vec<String>")]
        subset: ValuePath,
        /// Path to the list containing the allowed members.
        #[schemars(with = "Vec<String>")]
        superset: ValuePath,
        /// Path to the discriminator that can bypass the subset requirement.
        #[schemars(with = "Vec<String>")]
        unless_path: ValuePath,
        /// Exact JSON value that bypasses the subset requirement.
        unless_equals: serde_json::Value,
    },
    /// Requires a canonical rooted structured-document node list.
    StructuredDocument {
        /// Root-record field containing the document format name.
        #[schemars(with = "String")]
        format_field: LocalKey,
        /// Root-record field containing the flattened document nodes.
        #[schemars(with = "String")]
        document_field: LocalKey,
    },
}

impl ValueConstraint {
    /// Reports whether a canonical JSON value satisfies this constraint.
    #[must_use]
    pub fn admits(&self, value: &serde_json::Value) -> bool {
        use serde_json::Value;

        match self {
            Self::StringPattern { pattern } => value
                .as_str()
                .is_some_and(|text| complete_pattern_matches(pattern, text)),
            Self::MinimumSize { minimum } => match value {
                Value::String(text) => text.len() as u64 >= *minimum,
                Value::Array(items) => items.len() as u64 >= *minimum,
                Value::Object(fields) => fields.len() as u64 >= *minimum,
                _ => false,
            },
            Self::IntegerSet { values } => value
                .as_i64()
                .is_some_and(|integer| values.binary_search(&integer).is_ok()),
            Self::MapKeysPattern { pattern } => value.as_object().is_some_and(|fields| {
                fields
                    .keys()
                    .all(|name| complete_pattern_matches(pattern, name))
            }),
            Self::StringExcludes { classes } => value.as_str().is_some_and(|text| {
                text.chars().all(|character| {
                    classes.iter().all(|class| match class {
                        ExcludedCharacterClass::AsciiControl => !character.is_ascii_control(),
                        ExcludedCharacterClass::AsciiSpace => character != ' ',
                        ExcludedCharacterClass::AsciiWhitespace => !character.is_ascii_whitespace(),
                        ExcludedCharacterClass::LineBreak => character != '\n' && character != '\r',
                    })
                })
            }),
            Self::AtMostOneNonNull { fields } => value.as_object().is_some_and(|record| {
                fields
                    .iter()
                    .filter(|field| {
                        record
                            .get(field.as_str())
                            .is_some_and(|value| !value.is_null())
                    })
                    .count()
                    <= 1
            }),
            Self::UniqueAt { path } => value_at_path(value, path).is_some_and(unique_array),
            Self::DisjointAt { left, right } => {
                match (value_at_path(value, left), value_at_path(value, right)) {
                    (Some(Value::Array(left)), Some(Value::Array(right))) => {
                        left.iter().all(|item| !right.contains(item))
                    }
                    _ => false,
                }
            }
            Self::SubsetUnless {
                subset,
                superset,
                unless_path,
                unless_equals,
            } => {
                value_at_path(value, unless_path) == Some(unless_equals)
                    || match (value_at_path(value, subset), value_at_path(value, superset)) {
                        (Some(Value::Array(subset)), Some(Value::Array(superset))) => {
                            subset.iter().all(|item| superset.contains(item))
                        }
                        _ => false,
                    }
            }
            Self::StructuredDocument {
                format_field,
                document_field,
            } => {
                validate_structured_document(value, format_field.as_str(), document_field.as_str())
            }
        }
    }

    /// Returns the stable schema discriminator for diagnostics and documentation.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::StringPattern { .. } => "string-pattern",
            Self::MinimumSize { .. } => "minimum-size",
            Self::IntegerSet { .. } => "integer-set",
            Self::MapKeysPattern { .. } => "map-keys-pattern",
            Self::StringExcludes { .. } => "string-excludes",
            Self::AtMostOneNonNull { .. } => "at-most-one-non-null",
            Self::UniqueAt { .. } => "unique-at",
            Self::DisjointAt { .. } => "disjoint-at",
            Self::SubsetUnless { .. } => "subset-unless",
            Self::StructuredDocument { .. } => "structured-document",
        }
    }

    /// Reports whether this constraint can refine the supplied base schema.
    ///
    /// Compatibility includes referenced-field existence and type checks, so
    /// an invalid declaration is rejected before any value is evaluated.
    #[must_use]
    pub fn is_compatible_with(&self, base_schema: &ValueSchema) -> bool {
        let base_schema = refined_base(base_schema);
        match self {
            Self::StringPattern { .. } | Self::StringExcludes { .. } => {
                is_string_schema(base_schema)
            }
            Self::MinimumSize { minimum } => {
                maximum_cardinality(base_schema).is_some_and(|maximum| *minimum <= maximum)
            }
            Self::IntegerSet { values } => match base_schema {
                ValueSchema::Integer { minimum, maximum } => values
                    .iter()
                    .all(|value| value >= minimum && value <= maximum),
                _ => false,
            },
            Self::MapKeysPattern { .. } => matches!(base_schema, ValueSchema::Map { .. }),
            Self::AtMostOneNonNull { fields } => match base_schema {
                ValueSchema::Record {
                    fields: declared, ..
                } => fields.iter().all(|field| declared.contains_key(field)),
                ValueSchema::DocumentRecord {
                    fields: declared, ..
                } => fields
                    .iter()
                    .all(|field| declared.contains_key(field.as_str())),
                _ => false,
            },
            Self::UniqueAt { path } => schemas_at_path(base_schema, path).is_some_and(|schemas| {
                schemas
                    .iter()
                    .all(|schema| matches!(refined_base(schema), ValueSchema::List { .. }))
            }),
            Self::DisjointAt { left, right } => compatible_list_paths(base_schema, left, right),
            Self::SubsetUnless {
                subset,
                superset,
                unless_path,
                unless_equals,
            } => {
                compatible_list_paths(base_schema, subset, superset)
                    && path_admits_literal(base_schema, unless_path, unless_equals)
            }
            Self::StructuredDocument {
                format_field,
                document_field,
            } => {
                matches!(
                    base_schema,
                    ValueSchema::Record { .. } | ValueSchema::DocumentRecord { .. }
                ) && schemas_at_path(base_schema, std::slice::from_ref(format_field)).is_some_and(
                    |schemas| {
                        schemas
                            .iter()
                            .all(|schema| is_string_schema(refined_base(schema)))
                    },
                ) && schemas_at_path(base_schema, std::slice::from_ref(document_field)).is_some_and(
                    |schemas| {
                        schemas
                            .iter()
                            .all(|schema| matches!(refined_base(schema), ValueSchema::List { .. }))
                    },
                )
            }
        }
    }

    /// Reports whether constraint data fits the shared schema limits.
    #[must_use]
    pub fn is_within_limits(&self, max_string_bytes: u64, max_items: u64) -> bool {
        let strings_and_items = match self {
            Self::StringPattern { pattern } | Self::MapKeysPattern { pattern } => {
                return pattern.len() as u64 <= max_string_bytes;
            }
            Self::StringExcludes { classes } => {
                return classes.len() as u64 <= max_items;
            }
            Self::MinimumSize { minimum } => return *minimum <= max_items,
            Self::IntegerSet { values } => {
                return values.len() as u64 <= max_items;
            }
            Self::AtMostOneNonNull { fields } => fields.len(),
            Self::UniqueAt { path } => path.len(),
            Self::DisjointAt { left, right } => left.len().saturating_add(right.len()),
            Self::SubsetUnless {
                subset,
                superset,
                unless_path,
                unless_equals,
            } => {
                let Ok(encoded) = aos_contract::canonical::to_vec(unless_equals) else {
                    return false;
                };
                if encoded.len() as u64 > max_string_bytes {
                    return false;
                }
                subset
                    .len()
                    .saturating_add(superset.len())
                    .saturating_add(unless_path.len())
            }
            Self::StructuredDocument { .. } => 2,
        };
        strings_and_items > 0 && strings_and_items as u64 <= max_items
    }
}

fn refined_base(mut schema: &ValueSchema) -> &ValueSchema {
    while let ValueSchema::Refined { value, .. } = schema {
        schema = value;
    }
    schema
}

fn is_string_schema(schema: &ValueSchema) -> bool {
    matches!(
        schema,
        ValueSchema::String { .. } | ValueSchema::StringEnum { .. }
    )
}

fn maximum_cardinality(schema: &ValueSchema) -> Option<u64> {
    match refined_base(schema) {
        ValueSchema::String { max_length, .. } => Some(*max_length),
        ValueSchema::StringEnum { values } => values
            .iter()
            .map(|value| value.len() as u64)
            .max()
            .or(Some(0)),
        ValueSchema::List { max_items, .. } => Some(*max_items),
        ValueSchema::Map { max_entries, .. } => Some(*max_entries),
        ValueSchema::Record { fields, .. } => Some(fields.len() as u64),
        ValueSchema::DocumentRecord { fields, .. } => Some(fields.len() as u64),
        _ => None,
    }
}

fn schemas_at_path<'a>(schema: &'a ValueSchema, path: &[LocalKey]) -> Option<Vec<&'a ValueSchema>> {
    if path.is_empty() {
        return Some(vec![refined_base(schema)]);
    }
    let schema = refined_base(schema);
    let field = &path[0];
    let remaining = &path[1..];
    match schema {
        ValueSchema::Record { fields, .. } => schemas_at_path(fields.get(field)?, remaining),
        ValueSchema::DocumentRecord { fields, .. } => {
            schemas_at_path(fields.get(field.as_str())?, remaining)
        }
        ValueSchema::TaggedUnion { variants, .. } => variants
            .values()
            .map(|variant| schemas_at_path(variant, path))
            .collect::<Option<Vec<_>>>()
            .map(|paths| paths.into_iter().flatten().collect()),
        ValueSchema::DisjointUnion { variants } => variants
            .iter()
            .map(|variant| schemas_at_path(variant, path))
            .collect::<Option<Vec<_>>>()
            .map(|paths| paths.into_iter().flatten().collect()),
        _ => None,
    }
}

fn path_admits_literal(schema: &ValueSchema, path: &[LocalKey], value: &serde_json::Value) -> bool {
    let schema = refined_base(schema);
    if path.is_empty() {
        return schema_admits_json(schema, value);
    }

    let field = &path[0];
    let remaining = &path[1..];
    match schema {
        ValueSchema::Record { fields, .. } => fields
            .get(field)
            .is_some_and(|field| path_admits_literal(field, remaining, value)),
        ValueSchema::DocumentRecord { fields, .. } => fields
            .get(field.as_str())
            .is_some_and(|field| path_admits_literal(field, remaining, value)),
        ValueSchema::TaggedUnion { tag, variants } if path == std::slice::from_ref(tag) => {
            // The tag is one logical closed enumeration even though each variant
            // serializes its singleton discriminator schema independently.
            variants
                .values()
                .any(|variant| path_admits_literal(variant, path, value))
        }
        ValueSchema::TaggedUnion { variants, .. } => variants
            .values()
            .all(|variant| path_admits_literal(variant, path, value)),
        ValueSchema::DisjointUnion { variants } => variants
            .iter()
            .all(|variant| path_admits_literal(variant, path, value)),
        _ => false,
    }
}

fn compatible_list_paths(base_schema: &ValueSchema, left: &[LocalKey], right: &[LocalKey]) -> bool {
    let elements = |path| {
        schemas_at_path(base_schema, path).and_then(|schemas| {
            schemas
                .into_iter()
                .map(|schema| match refined_base(schema) {
                    ValueSchema::List { element, .. } => Some(element.as_ref()),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
        })
    };
    match (elements(left), elements(right)) {
        (Some(left), Some(right)) => {
            left.iter().all(|schema| right.contains(schema))
                && right.iter().all(|schema| left.contains(schema))
        }
        _ => false,
    }
}

fn schema_admits_json(schema: &ValueSchema, value: &serde_json::Value) -> bool {
    match refined_base(schema) {
        ValueSchema::Boolean => value.is_boolean(),
        ValueSchema::Integer { minimum, maximum } => value
            .as_i64()
            .is_some_and(|integer| integer >= *minimum && integer <= *maximum),
        ValueSchema::String { max_length, syntax } => value
            .as_str()
            .is_some_and(|text| string_matches(*max_length, *syntax, text)),
        ValueSchema::StringEnum { values } => value.as_str().is_some_and(|text| {
            values
                .binary_search_by(|candidate| candidate.as_str().cmp(text))
                .is_ok()
        }),
        ValueSchema::Optional { value: nested } => {
            value.is_null() || schema_admits_json(nested, value)
        }
        ValueSchema::DisjointUnion { variants } => {
            variants
                .iter()
                .filter(|variant| schema_admits_json(variant, value))
                .count()
                == 1
        }
        _ => false,
    }
}

fn complete_pattern_matches(pattern: &str, value: &str) -> bool {
    regex::Regex::new(&format!(r"\A(?:{pattern})\z"))
        .is_ok_and(|expression| expression.is_match(value))
}

pub(crate) fn string_matches(max_length: u64, syntax: Option<StringSyntax>, value: &str) -> bool {
    if value.len() as u64 > max_length {
        return false;
    }
    match syntax {
        None => !value.chars().any(char::is_control),
        Some(StringSyntax::LocalKeyV1) => LocalKey::new(value).is_ok(),
        Some(StringSyntax::QualifiedNameV1) => {
            let segments = value.split('.').collect::<Vec<_>>();
            segments.len() >= 2
                && segments.iter().all(|segment| {
                    !segment.is_empty()
                        && segment.chars().all(|character| {
                            character.is_ascii_alphanumeric()
                                || character == '_'
                                || character == '-'
                        })
                })
        }
        Some(StringSyntax::ExecutionPathV1) => {
            value.starts_with('/')
                && (value == "/"
                    || value
                        .split('/')
                        .skip(1)
                        .all(|segment| !segment.is_empty() && segment != "." && segment != ".."))
        }
        Some(StringSyntax::RelativePathV1) => {
            !value.is_empty()
                && !value.starts_with('/')
                && value
                    .split('/')
                    .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        }
    }
}

/// Reports whether a regular expression belongs to the closed cross-engine subset.
///
/// The subset is printable ASCII, excludes engine-specific groups, character-set
/// operators and anchors, and permits escapes only for a literal dot or backslash.
#[must_use]
pub fn portable_pattern_is_valid(pattern: &str, max_length: u64) -> bool {
    if pattern.is_empty()
        || pattern.len() as u64 > max_length
        || !pattern
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        || pattern.contains("(?")
        || pattern.contains("&&")
        || pattern.contains("~~")
        || pattern.contains("[.")
        || pattern.contains("[=")
    {
        return false;
    }

    let mut escaped = false;
    let mut in_character_class = false;
    for byte in pattern.bytes() {
        if escaped {
            if !matches!(byte, b'.' | b'\\') {
                return false;
            }
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'[' && !in_character_class {
            in_character_class = true;
        } else if byte == b']' && in_character_class {
            in_character_class = false;
        } else if !in_character_class && matches!(byte, b'^' | b'$') {
            return false;
        }
    }
    if escaped || in_character_class {
        return false;
    }

    regex::Regex::new(&format!(r"\A(?:{pattern})\z")).is_ok()
}

fn value_at_path<'a>(
    value: &'a serde_json::Value,
    path: &[LocalKey],
) -> Option<&'a serde_json::Value> {
    path.iter().try_fold(value, |current, component| {
        current.as_object()?.get(component.as_str())
    })
}

fn unique_array(value: &serde_json::Value) -> bool {
    let Some(items) = value.as_array() else {
        return false;
    };
    let encoded = items
        .iter()
        .map(aos_contract::canonical::to_vec)
        .collect::<Result<Vec<_>, _>>();
    encoded.is_ok_and(|items| {
        items
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == items.len()
    })
}

fn validate_structured_document(
    value: &serde_json::Value,
    format_field: &str,
    document_field: &str,
) -> bool {
    use serde_json::Value;

    let Some(source) = value.as_object() else {
        return false;
    };
    let Some(format) = source.get(format_field).and_then(Value::as_str) else {
        return false;
    };
    let Some(nodes) = source.get(document_field).and_then(Value::as_array) else {
        return false;
    };
    if nodes.is_empty() {
        return false;
    }

    let mut nodes_by_path = BTreeMap::new();
    for node in nodes {
        let Some(path) = node.get("path").and_then(Value::as_array) else {
            return false;
        };
        let Ok(encoded) = aos_contract::canonical::to_vec(&Value::Array(path.clone())) else {
            return false;
        };
        if nodes_by_path.insert(encoded, node).is_some() {
            return false;
        }
    }

    let Ok(root_key) = aos_contract::canonical::to_vec(&serde_json::json!([])) else {
        return false;
    };
    let Some(root) = nodes_by_path.get(&root_key) else {
        return false;
    };

    for node in nodes {
        let Some(path) = node.get("path").and_then(Value::as_array) else {
            return false;
        };
        if path.is_empty() {
            continue;
        }
        let Ok(parent_key) =
            aos_contract::canonical::to_vec(&Value::Array(path[..path.len() - 1].to_vec()))
        else {
            return false;
        };
        let Some(parent) = nodes_by_path.get(&parent_key) else {
            return false;
        };
        let Some(segment_kind) = path
            .last()
            .and_then(|segment| segment.get("kind"))
            .and_then(Value::as_str)
        else {
            return false;
        };
        let Some(parent_kind) = parent.get("kind").and_then(Value::as_str) else {
            return false;
        };
        if !matches!(
            (segment_kind, parent_kind),
            ("key", "object") | ("index", "array")
        ) {
            return false;
        }
    }

    for node in nodes
        .iter()
        .filter(|node| node.get("kind").and_then(Value::as_str) == Some("array"))
    {
        let Some(parent_path) = node.get("path").and_then(Value::as_array) else {
            return false;
        };
        let mut indices = Vec::new();
        for child in nodes {
            let Some(child_path) = child.get("path").and_then(Value::as_array) else {
                return false;
            };
            if child_path.len() == parent_path.len() + 1
                && child_path[..parent_path.len()] == *parent_path
            {
                let Some(index) = child_path
                    .last()
                    .and_then(|segment| segment.get("value"))
                    .and_then(Value::as_u64)
                else {
                    return false;
                };
                indices.push(index);
            }
        }
        indices.sort_unstable();
        if indices.iter().copied().ne(0..indices.len() as u64) {
            return false;
        }
    }

    format != "toml"
        || (root.get("kind").and_then(Value::as_str) == Some("object")
            && nodes
                .iter()
                .all(|node| node.get("kind").and_then(Value::as_str) != Some("null")))
}

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
    /// Uses a normalized relative path with no empty, `.` or `..` components.
    RelativePathV1,
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
    /// Applies portable predicates to a nested schema.
    Refined {
        /// Base schema validated before the refinements.
        value: Box<ValueSchema>,
        /// Non-empty ordered constraints applied to the validated value.
        constraints: Vec<ValueConstraint>,
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
    /// Returns one exact string discriminator declared for a closed record field.
    ///
    /// This derives a wire discriminator from the canonical schema instead of
    /// requiring consumers to repeat the package-owned literal.
    #[must_use]
    pub fn singleton_string_field(&self, field: &str) -> Option<&str> {
        self.singleton_string_path(&[field])
    }

    /// Returns one exact string discriminator at a required closed-record path.
    ///
    /// Each segment must name a required field. This permits provider protocols
    /// to derive nested evidence discriminators without copying schema literals.
    #[must_use]
    pub fn singleton_string_path(&self, path: &[&str]) -> Option<&str> {
        if let Self::Refined { value, .. } = self {
            return value.singleton_string_path(path);
        }
        let (field, rest) = path.split_first()?;
        let schema = self.required_field(field)?;
        if !rest.is_empty() {
            return schema.singleton_string_path(rest);
        }
        let Self::StringEnum { values } = schema else {
            return None;
        };
        let [value] = values.as_slice() else {
            return None;
        };
        Some(value)
    }

    fn required_field(&self, field: &str) -> Option<&Self> {
        match self {
            Self::Record {
                fields,
                optional_fields,
            } => {
                let (key, schema) = fields.iter().find(|(name, _)| name.as_str() == field)?;
                (!optional_fields.contains(key)).then_some(schema)
            }
            Self::DocumentRecord {
                fields,
                optional_fields,
                ..
            } => (!optional_fields.iter().any(|name| name == field))
                .then(|| fields.get(field))
                .flatten(),
            Self::Refined { value, .. } => value.required_field(field),
            _ => None,
        }
    }

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
                Self::Refined { value, constraints } => {
                    item_count = item_count.saturating_add(constraints.len() as u64);
                    if constraints.is_empty()
                        || item_count > max_items
                        || constraints
                            .iter()
                            .any(|constraint| !constraint.is_within_limits(1_048_576, max_items))
                    {
                        return false;
                    }
                    stack.push((value, child_depth));
                }
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
            Self::Refined { value, .. } => value.top_level_json_kind(),
            Self::DisjointUnion { .. } | Self::Optional { .. } => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn singleton_string_field_uses_the_canonical_record_schema() {
        let schema = ValueSchema::DocumentRecord {
            key_max_length: 64,
            fields: [(
                "schema".into(),
                ValueSchema::StringEnum {
                    values: vec!["aos.test.observation/v1".into()],
                },
            )]
            .into(),
            optional_fields: Vec::new(),
        };

        assert_eq!(
            schema.singleton_string_field("schema"),
            Some("aos.test.observation/v1")
        );
        assert_eq!(schema.singleton_string_field("missing"), None);
    }

    #[test]
    fn singleton_string_field_rejects_an_open_or_ambiguous_discriminator() {
        let schema = ValueSchema::Record {
            fields: [(
                LocalKey::new("schema").expect("schema key is valid"),
                ValueSchema::StringEnum {
                    values: vec!["aos.test.v1".into(), "aos.test.v2".into()],
                },
            )]
            .into(),
            optional_fields: Vec::new(),
        };

        assert_eq!(schema.singleton_string_field("schema"), None);
        assert_eq!(ValueSchema::Boolean.singleton_string_field("schema"), None);
    }

    #[test]
    fn singleton_string_path_walks_only_required_closed_fields() {
        let discriminator = ValueSchema::StringEnum {
            values: vec!["aos.test.observation/v1".into()],
        };
        let schema = ValueSchema::Record {
            fields: [(
                LocalKey::new("observation").expect("observation key is valid"),
                ValueSchema::DocumentRecord {
                    key_max_length: 64,
                    fields: [("schema".into(), discriminator)].into(),
                    optional_fields: Vec::new(),
                },
            )]
            .into(),
            optional_fields: Vec::new(),
        };

        assert_eq!(
            schema.singleton_string_path(&["observation", "schema"]),
            Some("aos.test.observation/v1")
        );

        let optional = ValueSchema::Record {
            fields: [(
                LocalKey::new("observation").expect("observation key is valid"),
                schema,
            )]
            .into(),
            optional_fields: vec![LocalKey::new("observation").expect("observation key is valid")],
        };
        assert_eq!(
            optional.singleton_string_path(&["observation", "observation", "schema"]),
            None
        );
    }

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
    fn refined_schema_round_trips_portable_constraints() {
        let encoded = serde_json::json!({
            "kind": "refined",
            "value": {"kind": "string", "max_length": 32, "syntax": null},
            "constraints": [
                {"kind": "minimum-size", "minimum": 1},
                {"kind": "string-pattern", "pattern": "[a-z]+"},
            ],
        });
        let schema: ValueSchema =
            serde_json::from_value(encoded.clone()).expect("refined schema decodes");

        assert_eq!(schema.top_level_json_kind(), Some(JsonValueKind::String));
        assert_eq!(
            serde_json::to_value(schema).expect("refined schema serializes"),
            encoded
        );
    }

    #[test]
    fn portable_patterns_reject_engine_specific_constructs() {
        assert!(portable_pattern_is_valid("[0-9a-f]{8}-[0-9a-f]{4}", 128));
        assert!(portable_pattern_is_valid(
            "/dev/disk/by-id/[A-Za-z0-9._:+-]+",
            128
        ));
        assert!(!portable_pattern_is_valid("([a])\\1", 128));
        assert!(!portable_pattern_is_valid("(?=prefix).*", 128));
    }

    #[test]
    fn excluded_character_classes_are_data_driven() {
        let constraint = ValueConstraint::StringExcludes {
            classes: vec![
                ExcludedCharacterClass::AsciiSpace,
                ExcludedCharacterClass::LineBreak,
            ],
        };

        assert!(constraint.admits(&serde_json::json!("single-line")));
        assert!(!constraint.admits(&serde_json::json!("two words")));
        assert!(!constraint.admits(&serde_json::json!("two\nlines")));
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
