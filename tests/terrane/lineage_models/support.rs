//! Assembles CBOR primitives and reads exact bounded, named format witnesses.
//!
//! ```text
//! primitive = uint / bytes / text / array / map / bool / null / raw-wire
//! ```

use std::collections::BTreeMap;

/// Identifies an independently constructed ordinary format family.
#[derive(Clone, Copy, Debug)]
pub(super) enum Family {
    /// A control selector and represented physical owner.
    Pin,
    /// One complete root-policy occurrence.
    Root,
    /// An ordered list of consumed occurrences.
    View,
    /// Complete nested used-input fields.
    Used,
    /// Whole source/Commit evidence and represented relationships.
    Checked,
}

/// Represents only the primitive values needed by the independent tables.
#[derive(Clone, Debug)]
pub(super) enum Value {
    /// An unsigned integer.
    UInt(u64),
    /// Exact byte-string contents.
    Bytes(Vec<u8>),
    /// Exact UTF-8 text.
    Text(String),
    /// An ordered array.
    Array(Vec<Value>),
    /// A map whose keys are canonically ordered during primitive assembly.
    Map(Vec<(Value, Value)>),
    /// A simple boolean.
    Bool(bool),
    /// Explicit null.
    Null,
    /// Independently malformed bytes, or an already assembled nested value.
    Raw(Vec<u8>),
}

/// Returns a shortest unsigned CBOR header.
///
/// # Panics
/// Panics only if the exhaustive width table unexpectedly lacks a uint64 case.
pub(super) fn head(major: u8, argument: u64) -> Vec<u8> {
    if argument < 24 {
        return vec![
            (major << 5) | u8::try_from(argument).unwrap_or_else(|_| panic!("small head")),
        ];
    }
    for (width, additional) in [(1, 24), (2, 25), (4, 26), (8, 27)] {
        if width == 8 || argument < 1 << (width * 8) {
            let mut bytes = vec![(major << 5) | additional];
            bytes.extend_from_slice(&argument.to_be_bytes()[8 - width..]);
            return bytes;
        }
    }
    panic!("uint64 width table")
}

/// Encodes primitives without invoking an owning Terrane encoder.
///
/// # Panics
/// Panics only if a platform-sized collection length cannot fit uint64.
pub(super) fn encode(value: &Value) -> Vec<u8> {
    let length = |length| u64::try_from(length).unwrap_or_else(|_| panic!("length"));
    match value {
        Value::UInt(value) => head(0, *value),
        Value::Bytes(bytes) => [head(2, length(bytes.len())), bytes.clone()].concat(),
        Value::Text(text) => [head(3, length(text.len())), text.as_bytes().to_vec()].concat(),
        Value::Array(values) => {
            let mut bytes = head(4, length(values.len()));
            for item in values {
                bytes.extend_from_slice(&encode(item));
            }
            bytes
        }
        Value::Map(values) => {
            let mut values: Vec<_> = values
                .iter()
                .map(|(key, value)| (encode(key), encode(value)))
                .collect();
            values.sort_by(|left, right| (left.0.len(), &left.0).cmp(&(right.0.len(), &right.0)));
            let mut bytes = head(5, length(values.len()));
            for (key, value) in values {
                bytes.extend_from_slice(&key);
                bytes.extend_from_slice(&value);
            }
            bytes
        }
        Value::Bool(value) => vec![if *value { 0xf5 } else { 0xf4 }],
        Value::Null => vec![0xf6],
        Value::Raw(bytes) => bytes.clone(),
    }
}

/// Constructs a numeric-key field map.
pub(super) fn map(fields: Vec<(u64, Value)>) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(key, value)| (Value::UInt(key), value))
            .collect(),
    )
}

/// Constructs an exact UTF-8 text value.
pub(super) fn text(value: &str) -> Value {
    Value::Text(value.into())
}

/// Constructs an exact byte-string value.
pub(super) fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

/// Constructs a 32-byte opaque digest claim.
pub(super) fn digest(value: u8) -> Value {
    bytes(&[value; 32])
}

/// Constructs a text-key property map independently of property encoders.
pub(super) fn properties(fields: Vec<(&str, Value)>) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(key, value)| (text(key), value))
            .collect(),
    )
}

/// Replaces one numeric map field or array element in an independent table.
///
/// # Panics
/// Panics for an empty path or a missing/wrong-shaped fixture intermediate.
pub(super) fn set(value: &mut Value, path: &[u64], replacement: Value) {
    if let Value::Map(fields) = value {
        let (_, child) = fields
            .iter_mut()
            .find(|(key, _)| matches!(key, Value::UInt(key) if *key == path[0]))
            .unwrap_or_else(|| panic!("fixture key {}", path[0]));
        if path.len() == 1 {
            *child = replacement;
        } else {
            set(child, &path[1..], replacement);
        }
    } else if let Value::Array(fields) = value {
        let child = &mut fields[usize::try_from(path[0]).unwrap_or_else(|_| panic!("index"))];
        if path.len() == 1 {
            *child = replacement;
        } else {
            set(child, &path[1..], replacement);
        }
    } else {
        panic!("fixture intermediate");
    }
}

/// Copies a table and replaces one independently specified field.
///
/// # Panics
/// Panics under the invalid fixture paths documented by [`set`].
pub(super) fn changed(value: &Value, path: &[u64], replacement: Value) -> Value {
    let mut value = value.clone();
    set(&mut value, path, replacement);
    value
}

/// Preserves the exact independently published fields needed by comparisons.
pub(super) struct ReferenceRow {
    /// Exact wire bytes, including negative malformed bytes.
    pub(super) wire: Vec<u8>,
    /// Registered Commit ID only on complete positive checked-source models.
    pub(super) commit_id: Option<[u8; 32]>,
}

/// Parses exact even-width hexadecimal fixture bytes.
///
/// # Panics
/// Panics for odd-width text, invalid UTF-8 or invalid hexadecimal digits.
fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap_or_else(|_| panic!("hex UTF-8"));
            u8::from_str_radix(pair, 16).unwrap_or_else(|_| panic!("hex digit"))
        })
        .collect()
}

/// Reads a unique bounded section with unique names and complete wire fields.
///
/// # Panics
/// Panics for missing/duplicate sections, names, wire fields or malformed hex.
pub(super) fn reference() -> BTreeMap<String, ReferenceRow> {
    const HEADING: &str = "## Consumed-lineage record field witnesses";
    let document = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../tests/terrane/lineage-reference.md"
    ));
    assert_eq!(document.lines().filter(|line| *line == HEADING).count(), 1);
    let section = document
        .split_once(HEADING)
        .unwrap_or_else(|| panic!("section"))
        .1;
    let section = section
        .split("\n## ")
        .next()
        .unwrap_or_else(|| panic!("body"));
    let mut rows = BTreeMap::new();
    for block in section.split("\n### ").skip(1) {
        let (name, body) = block.split_once('\n').unwrap_or_else(|| panic!("name"));
        let wires: Vec<_> = body
            .lines()
            .filter_map(|line| line.strip_prefix("wire = "))
            .collect();
        assert_eq!(wires.len(), 1, "{name}");
        let ids: Vec<_> = body
            .lines()
            .filter_map(|line| line.strip_prefix("commit-id = "))
            .collect();
        assert!(ids.len() <= 1);
        let commit_id = ids
            .first()
            .map(|value| hex(value).try_into().unwrap_or_else(|_| panic!("ID width")));
        assert!(
            rows.insert(
                name.into(),
                ReferenceRow {
                    wire: hex(wires[0]),
                    commit_id
                }
            )
            .is_none()
        );
    }
    rows
}
