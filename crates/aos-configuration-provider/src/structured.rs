//! Typed structured configuration reconstruction and deterministic encoding.
//!
//! The configuration provider receives a checked flat document tree after deferred scalar
//! results have been resolved. It reconstructs that tree without accepting
//! sparse arrays or implicit parents, then emits one deterministic JSON, TOML,
//! or YAML document. YAML uses the JSON subset of YAML 1.2, keeping one
//! canonical serializer for both formats.

use std::collections::{BTreeMap, BTreeSet};

use aos_ability_model::ABILITY_LIMITS_V1;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

/// Reports why a checked structured document cannot be reconstructed or encoded.
#[derive(Debug, Error)]
pub enum StructuredDocumentError {
    /// The flat node graph violates its closed tree contract.
    #[error("invalid structured configuration tree: {0}")]
    InvalidTree(String),
    /// The requested output format cannot represent the checked value.
    #[error("cannot encode structured configuration as {format}: {message}")]
    Encoding {
        /// Names the requested deterministic format.
        format: &'static str,
        /// Describes the representation failure.
        message: String,
    },
}

/// Selects the deterministic configuration serialization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructuredFormat {
    /// Emits canonical compact JSON.
    Json,
    /// Emits deterministic TOML using lexically ordered keys and tables.
    Toml,
    /// Emits canonical JSON syntax, a valid YAML 1.2 document.
    Yaml,
}

/// Identifies one object member or array element in the document tree.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DocumentPathSegment {
    /// Selects one zero-based array element.
    Index {
        /// Carries the exact element index.
        value: u16,
    },
    /// Selects one object member.
    Key {
        /// Carries the exact member name.
        value: String,
    },
}

/// Holds one explicitly typed node in a flat structured document.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DocumentNode {
    /// Declares an array container.
    Array { path: Vec<DocumentPathSegment> },
    /// Declares a Boolean scalar.
    Boolean {
        path: Vec<DocumentPathSegment>,
        value: bool,
    },
    /// Declares an exactly represented JSON-safe integer scalar.
    Integer {
        path: Vec<DocumentPathSegment>,
        value: i64,
    },
    /// Declares a checked execution-path scalar after deferred-result resolution.
    ExecutionPath {
        path: Vec<DocumentPathSegment>,
        value: String,
    },
    /// Declares a null scalar.
    Null { path: Vec<DocumentPathSegment> },
    /// Declares an object container.
    Object { path: Vec<DocumentPathSegment> },
    /// Declares a string scalar after deferred-result resolution.
    String {
        path: Vec<DocumentPathSegment>,
        value: String,
    },
}

impl DocumentNode {
    fn path(&self) -> &[DocumentPathSegment] {
        match self {
            Self::Array { path }
            | Self::Boolean { path, .. }
            | Self::ExecutionPath { path, .. }
            | Self::Integer { path, .. }
            | Self::Null { path }
            | Self::Object { path }
            | Self::String { path, .. } => path,
        }
    }
}

/// Reconstructs and deterministically serializes a checked document tree.
///
/// # Errors
///
/// Returns an error for duplicate or missing nodes, implicit parents, mismatched
/// path segment/container kinds, sparse arrays, unsupported TOML nulls or
/// roots, and serialization failures.
pub fn encode_structured_document(
    format: StructuredFormat,
    nodes: Vec<DocumentNode>,
) -> Result<Vec<u8>, StructuredDocumentError> {
    let value = reconstruct(nodes)?;

    match format {
        StructuredFormat::Json | StructuredFormat::Yaml => {
            let encoded = aos_contract::canonical::to_vec(&value).map_err(|error| {
                StructuredDocumentError::Encoding {
                    format: match format {
                        StructuredFormat::Json => "JSON",
                        StructuredFormat::Yaml => "YAML",
                        StructuredFormat::Toml => unreachable!(),
                    },
                    message: error.to_string(),
                }
            })?;
            ensure_encoded_size(encoded, "JSON/YAML")
        }
        StructuredFormat::Toml => {
            if !value.is_object() {
                return Err(invalid("TOML requires an object root"));
            }
            if contains_null(&value) {
                return Err(invalid("TOML cannot represent null nodes"));
            }
            let encoded = toml::to_string(&value)
                .map(String::into_bytes)
                .map_err(|error| StructuredDocumentError::Encoding {
                    format: "TOML",
                    message: error.to_string(),
                })?;
            ensure_encoded_size(encoded, "TOML")
        }
    }
}

fn reconstruct(nodes: Vec<DocumentNode>) -> Result<Value, StructuredDocumentError> {
    if nodes.is_empty()
        || u64::try_from(nodes.len()).unwrap_or(u64::MAX) > ABILITY_LIMITS_V1.max_collection_items
    {
        return Err(invalid("node count is outside the bounded profile"));
    }

    let mut by_path = BTreeMap::new();
    for node in nodes {
        if u32::try_from(node.path().len()).unwrap_or(u32::MAX)
            > ABILITY_LIMITS_V1.max_structural_depth
        {
            return Err(invalid("a node path exceeds the bounded depth"));
        }
        validate_node_strings(&node)?;
        let path = node.path().to_vec();
        if by_path.insert(path, node).is_some() {
            return Err(invalid("two nodes claim the same path"));
        }
    }

    let mut visited = BTreeSet::new();
    let root = build_node(&[], &by_path, &mut visited)?;
    if visited.len() != by_path.len() {
        return Err(invalid("the document contains an unreachable node"));
    }
    Ok(root)
}

fn validate_node_strings(node: &DocumentNode) -> Result<(), StructuredDocumentError> {
    for segment in node.path() {
        if let DocumentPathSegment::Key { value } = segment
            && u64::try_from(value.len()).unwrap_or(u64::MAX) > ABILITY_LIMITS_V1.max_string_bytes
        {
            return Err(invalid("an object key exceeds the canonical ability bound"));
        }
    }
    if let DocumentNode::String { value, .. } | DocumentNode::ExecutionPath { value, .. } = node
        && u64::try_from(value.len()).unwrap_or(u64::MAX) > ABILITY_LIMITS_V1.max_string_bytes
    {
        return Err(invalid(
            "a scalar string exceeds the canonical ability bound",
        ));
    }
    Ok(())
}

fn build_node(
    path: &[DocumentPathSegment],
    nodes: &BTreeMap<Vec<DocumentPathSegment>, DocumentNode>,
    visited: &mut BTreeSet<Vec<DocumentPathSegment>>,
) -> Result<Value, StructuredDocumentError> {
    let node = nodes
        .get(path)
        .ok_or_else(|| invalid("the document root or a child node is missing"))?;
    visited.insert(path.to_vec());

    match node {
        DocumentNode::Null { .. } => Ok(Value::Null),
        DocumentNode::Boolean { value, .. } => Ok(Value::Bool(*value)),
        DocumentNode::Integer { value, .. } => Ok(Value::from(*value)),
        DocumentNode::ExecutionPath { value, .. } => Ok(Value::String(value.clone())),
        DocumentNode::String { value, .. } => Ok(Value::String(value.clone())),
        DocumentNode::Object { .. } => build_object(path, nodes, visited),
        DocumentNode::Array { .. } => build_array(path, nodes, visited),
    }
}

fn direct_children<'a>(
    path: &'a [DocumentPathSegment],
    nodes: &'a BTreeMap<Vec<DocumentPathSegment>, DocumentNode>,
) -> impl Iterator<Item = (&'a DocumentPathSegment, &'a Vec<DocumentPathSegment>)> {
    nodes.keys().filter_map(move |candidate| {
        (candidate.len() == path.len() + 1 && candidate.starts_with(path))
            .then(|| (&candidate[path.len()], candidate))
    })
}

fn build_object(
    path: &[DocumentPathSegment],
    nodes: &BTreeMap<Vec<DocumentPathSegment>, DocumentNode>,
    visited: &mut BTreeSet<Vec<DocumentPathSegment>>,
) -> Result<Value, StructuredDocumentError> {
    let mut object = Map::new();
    for (segment, child_path) in direct_children(path, nodes) {
        let DocumentPathSegment::Key { value: key } = segment else {
            return Err(invalid("an object child uses an array index"));
        };
        object.insert(key.clone(), build_node(child_path, nodes, visited)?);
    }
    Ok(Value::Object(object))
}

fn build_array(
    path: &[DocumentPathSegment],
    nodes: &BTreeMap<Vec<DocumentPathSegment>, DocumentNode>,
    visited: &mut BTreeSet<Vec<DocumentPathSegment>>,
) -> Result<Value, StructuredDocumentError> {
    let children = direct_children(path, nodes).collect::<Vec<_>>();
    let mut values = Vec::with_capacity(children.len());
    for (expected, (segment, child_path)) in children.into_iter().enumerate() {
        let DocumentPathSegment::Index { value: index } = segment else {
            return Err(invalid("an array child uses an object key"));
        };
        if usize::from(*index) != expected {
            return Err(invalid("array indices must be contiguous from zero"));
        }
        values.push(build_node(child_path, nodes, visited)?);
    }
    Ok(Value::Array(values))
}

fn contains_null(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(values) => values.iter().any(contains_null),
        Value::Object(values) => values.values().any(contains_null),
        Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn ensure_encoded_size(
    encoded: Vec<u8>,
    format: &'static str,
) -> Result<Vec<u8>, StructuredDocumentError> {
    if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > ABILITY_LIMITS_V1.max_document_bytes {
        return Err(StructuredDocumentError::Encoding {
            format,
            message: "encoded document exceeds the canonical ability byte bound".to_string(),
        });
    }
    Ok(encoded)
}

fn invalid(message: impl Into<String>) -> StructuredDocumentError {
    StructuredDocumentError::InvalidTree(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: &str) -> DocumentPathSegment {
        DocumentPathSegment::Key {
            value: value.to_string(),
        }
    }

    fn index(value: u16) -> DocumentPathSegment {
        DocumentPathSegment::Index { value }
    }

    fn fixture() -> Vec<DocumentNode> {
        vec![
            DocumentNode::Object { path: vec![] },
            DocumentNode::ExecutionPath {
                path: vec![key("runtime")],
                value: "/run/example".to_string(),
            },
            DocumentNode::Array {
                path: vec![key("ports")],
            },
            DocumentNode::Integer {
                path: vec![key("ports"), index(0)],
                value: 8080,
            },
            DocumentNode::Integer {
                path: vec![key("ports"), index(1)],
                value: 8443,
            },
        ]
    }

    #[test]
    fn json_and_yaml_use_the_same_canonical_yaml_subset() {
        let json = encode_structured_document(StructuredFormat::Json, fixture())
            .expect("JSON document encodes");
        let yaml = encode_structured_document(StructuredFormat::Yaml, fixture())
            .expect("YAML document encodes");

        assert_eq!(json, br#"{"ports":[8080,8443],"runtime":"/run/example"}"#);
        assert_eq!(yaml, json);
    }

    #[test]
    fn execution_path_node_decodes_and_serializes_as_a_string() {
        let node: DocumentNode = serde_json::from_value(serde_json::json!({
            "kind": "execution-path",
            "path": [],
            "value": "/run/aos/configurations/example.json"
        }))
        .expect("execution-path node decodes");
        let encoded = encode_structured_document(StructuredFormat::Json, vec![node])
            .expect("execution path document encodes");

        assert_eq!(encoded, br#""/run/aos/configurations/example.json""#);
    }

    #[test]
    fn toml_is_deterministic_and_round_trips() {
        let encoded = encode_structured_document(StructuredFormat::Toml, fixture())
            .expect("TOML document encodes");
        let text = String::from_utf8(encoded).expect("TOML is UTF-8");
        let decoded: toml::Value = toml::from_str(&text).expect("TOML parses");

        assert_eq!(decoded["runtime"].as_str(), Some("/run/example"));
        assert_eq!(decoded["ports"][1].as_integer(), Some(8443));
        assert_eq!(
            text,
            String::from_utf8(
                encode_structured_document(StructuredFormat::Toml, fixture())
                    .expect("repeated TOML encoding succeeds")
            )
            .expect("TOML is UTF-8")
        );
    }

    #[test]
    fn sparse_arrays_and_unreachable_nodes_fail_closed() {
        let sparse = vec![
            DocumentNode::Array { path: vec![] },
            DocumentNode::String {
                path: vec![index(1)],
                value: "late".to_string(),
            },
        ];
        assert!(
            encode_structured_document(StructuredFormat::Json, sparse)
                .expect_err("sparse array is rejected")
                .to_string()
                .contains("contiguous")
        );

        let orphan = vec![
            DocumentNode::Object { path: vec![] },
            DocumentNode::String {
                path: vec![key("missing"), key("child")],
                value: "orphan".to_string(),
            },
        ];
        assert!(
            encode_structured_document(StructuredFormat::Json, orphan)
                .expect_err("implicit parent is rejected")
                .to_string()
                .contains("unreachable")
        );
    }

    #[test]
    fn toml_rejects_null_and_non_object_roots() {
        let null = vec![DocumentNode::Null { path: vec![] }];
        assert!(
            encode_structured_document(StructuredFormat::Toml, null)
                .expect_err("TOML null is rejected")
                .to_string()
                .contains("object root")
        );

        let object_with_null = vec![
            DocumentNode::Object { path: vec![] },
            DocumentNode::Null {
                path: vec![key("missing")],
            },
        ];
        assert!(
            encode_structured_document(StructuredFormat::Toml, object_with_null)
                .expect_err("nested TOML null is rejected")
                .to_string()
                .contains("null")
        );
    }

    #[test]
    fn direct_calls_reject_object_keys_above_the_wire_ceiling() {
        let overlong_key = "k"
            .repeat(usize::try_from(ABILITY_LIMITS_V1.max_string_bytes).expect("limit fits") + 1);
        let invalid_key = vec![
            DocumentNode::Object { path: vec![] },
            DocumentNode::String {
                path: vec![key(&overlong_key)],
                value: "value".to_string(),
            },
        ];
        assert!(
            encode_structured_document(StructuredFormat::Json, invalid_key)
                .expect_err("overlong key is rejected")
                .to_string()
                .contains("object key")
        );
    }

    #[test]
    fn direct_calls_reject_overlong_scalar_strings() {
        let overlong_string = "v"
            .repeat(usize::try_from(ABILITY_LIMITS_V1.max_string_bytes).expect("limit fits") + 1);
        assert!(
            encode_structured_document(
                StructuredFormat::Json,
                vec![DocumentNode::String {
                    path: vec![],
                    value: overlong_string,
                }],
            )
            .expect_err("overlong scalar string is rejected")
            .to_string()
            .contains("scalar string")
        );
    }

    #[test]
    fn direct_calls_reject_oversized_encoded_documents() {
        let scalar_bytes =
            usize::try_from(ABILITY_LIMITS_V1.max_string_bytes).expect("string bound fits");
        let escaped_scalar = "\0".repeat(scalar_bytes);
        let mut oversized = vec![DocumentNode::Object { path: vec![] }];
        for member in 0..6 {
            oversized.push(DocumentNode::String {
                path: vec![key(&format!("member-{member}"))],
                value: escaped_scalar.clone(),
            });
        }

        assert!(
            encode_structured_document(StructuredFormat::Json, oversized)
                .expect_err("oversized encoding is rejected")
                .to_string()
                .contains("byte bound")
        );
    }
}
