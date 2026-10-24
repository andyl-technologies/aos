//! Independent CBOR primitives and bounded reference-section readers.
//!
//! Only primitive values are encoded here; owning record encoders are never
//! used to construct a negative input or a reference preimage.
//!
//! ```text
//! a1 01 02 = {1: 2}
//! ```

use std::collections::BTreeMap;

/// A small primitive value tree for independently assembled fixture fields.
#[derive(Clone, Debug)]
pub(crate) enum Value {
    /// An unsigned integer encoded in its shortest representation.
    UInt(u64),
    /// An opaque byte string.
    Bytes(Vec<u8>),
    /// A UTF-8 text string.
    Text(String),
    /// An ordered array of primitive values.
    Array(Vec<Value>),
    /// A map whose encoded keys are sorted canonically during encoding.
    Map(Vec<(Value, Value)>),
    /// A primitive boolean value.
    Bool(bool),
    /// An explicit null, distinct from an absent map key.
    Null,
}

/// Constructs an unsigned primitive value.
pub(crate) fn n(value: u64) -> Value {
    Value::UInt(value)
}

/// Copies opaque bytes into a primitive byte string.
pub(crate) fn b(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

/// Copies UTF-8 text into a primitive text string.
pub(crate) fn t(value: &str) -> Value {
    Value::Text(value.into())
}

/// Constructs an ordered primitive array.
pub(crate) fn a(values: Vec<Value>) -> Value {
    Value::Array(values)
}

/// Constructs a primitive map with numbered schema keys.
pub(crate) fn m(fields: Vec<(u64, Value)>) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(key, value)| (n(key), value))
            .collect(),
    )
}

/// Constructs a primitive map with UTF-8 text keys.
pub(crate) fn texts(fields: Vec<(&str, Value)>) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(key, value)| (t(key), value))
            .collect(),
    )
}

/// Constructs fixed-width opaque fixture bytes.
pub(crate) fn repeated(byte: u8, width: usize) -> Value {
    b(&vec![byte; width])
}

/// Writes a shortest definite CBOR argument without a record codec.
fn head(output: &mut Vec<u8>, major: u8, value: u64) {
    if value < 24 {
        output.push((major << 5) | value as u8);
        return;
    }
    for (width, additional) in [(1, 24), (2, 25), (4, 26), (8, 27)] {
        if width == 8 || value < (1u64 << (8 * width)) {
            output.push((major << 5) | additional);
            output.extend_from_slice(&value.to_be_bytes()[8 - width..]);
            return;
        }
    }
}

/// Encodes a primitive value using shortest definite CBOR and canonical map ordering.
pub(crate) fn encode(value: &Value) -> Vec<u8> {
    let mut output = Vec::new();
    match value {
        Value::UInt(value) => head(&mut output, 0, *value),
        Value::Bytes(bytes) => {
            head(&mut output, 2, bytes.len() as u64);
            output.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            head(&mut output, 3, text.len() as u64);
            output.extend_from_slice(text.as_bytes());
        }
        Value::Array(values) => {
            head(&mut output, 4, values.len() as u64);
            for value in values {
                output.extend_from_slice(&encode(value));
            }
        }
        Value::Map(fields) => {
            let mut fields: Vec<_> = fields
                .iter()
                .map(|(key, value)| (encode(key), encode(value)))
                .collect();
            fields.sort_by(|left, right| (left.0.len(), &left.0).cmp(&(right.0.len(), &right.0)));
            head(&mut output, 5, fields.len() as u64);
            for (key, value) in fields {
                output.extend_from_slice(&key);
                output.extend_from_slice(&value);
            }
        }
        Value::Bool(value) => output.push(if *value { 0xf5 } else { 0xf4 }),
        Value::Null => output.push(0xf6),
    }
    output
}

/// Replaces a numbered map field in an independent primitive model.
///
/// # Panics
/// Panics for an empty path, a path traversing a non-map value, or a missing
/// intermediate field. A missing final field is inserted into its parent map.
pub(crate) fn set(value: &mut Value, path: &[u64], replacement: Value) {
    let Value::Map(fields) = value else {
        panic!("fixture path must traverse a numbered map");
    };
    let key = path[0];
    if let Some((_, field)) = fields
        .iter_mut()
        .find(|(candidate, _)| matches!(candidate, Value::UInt(k) if *k == key))
    {
        if path.len() == 1 {
            *field = replacement;
        } else {
            set(field, &path[1..], replacement);
        }
    } else {
        assert_eq!(path.len(), 1, "missing intermediate fixture field");
        fields.push((n(key), replacement));
    }
}

/// Removes a numbered map field from an independent primitive model.
///
/// # Panics
/// Panics if the supplied fixture is not a map.
pub(crate) fn remove(value: &mut Value, key: u64) {
    let Value::Map(fields) = value else {
        panic!("fixture must be a map");
    };
    fields.retain(|(candidate, _)| !matches!(candidate, Value::UInt(k) if *k == key));
}

/// Decodes a hexadecimal fixture field.
///
/// # Panics
/// Panics for malformed reference hexadecimal.
pub(crate) fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text =
                std::str::from_utf8(pair).unwrap_or_else(|error| panic!("hex UTF-8: {error}"));
            u8::from_str_radix(text, 16).unwrap_or_else(|error| panic!("hex digit: {error}"))
        })
        .collect()
}

/// Returns every named field block inside the unique bounded reference section.
///
/// # Panics
/// Panics for missing, repeated or malformed witness names and fields.
pub(crate) fn reference() -> BTreeMap<String, BTreeMap<String, String>> {
    let document = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../tests/terrane/refs-reference.md"
    ));
    let heading = "## Modern commit and ref record field witnesses";
    assert_eq!(document.lines().filter(|line| *line == heading).count(), 1);
    let section = document
        .split_once(heading)
        .unwrap_or_else(|| panic!("missing section"))
        .1;
    let section = section
        .split("\n## ")
        .next()
        .unwrap_or_else(|| panic!("missing section body"));
    let mut witnesses = BTreeMap::new();
    for block in section.split("\n### ").skip(1) {
        let (name, body) = block
            .split_once('\n')
            .unwrap_or_else(|| panic!("missing witness body"));
        let mut fields = BTreeMap::new();
        for line in body.lines().filter(|line| line.contains(" = ")) {
            let (key, value) = line
                .split_once(" = ")
                .unwrap_or_else(|| panic!("missing field separator"));
            assert!(
                fields.insert(key.into(), value.into()).is_none(),
                "duplicate {name} field {key}"
            );
        }
        assert!(
            witnesses.insert(name.into(), fields).is_none(),
            "duplicate witness {name}"
        );
    }
    witnesses
}

/// Reads one required witness field.
///
/// # Panics
/// Panics when the reference omits the named witness or field.
pub(crate) fn field<'a>(
    reference: &'a BTreeMap<String, BTreeMap<String, String>>,
    name: &str,
    key: &str,
) -> &'a str {
    reference
        .get(name)
        .and_then(|fields| fields.get(key))
        .unwrap_or_else(|| panic!("missing {name}.{key}"))
}
