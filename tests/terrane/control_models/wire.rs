//! Owns the independent primitive CBOR oracle and exact reference comparison.
//!
//! ```text
//! Value = null | uint | bstr | tstr | [Value] | {uint: Value}
//! ```

use std::fmt::Debug;

/// Represents complete primitive fields without calling any owning codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Value {
    /// Explicit CBOR null.
    Null,
    /// Unsigned integer.
    Uint(u64),
    /// Exact byte string.
    Bytes(Vec<u8>),
    /// Exact UTF-8 text.
    Text(String),
    /// Ordered array.
    Array(Vec<Value>),
    /// Canonically sorted unsigned-key map.
    Map(Vec<(u64, Value)>),
}

impl Value {
    /// Encodes primitive fields independently in shortest CBOR form.
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        self.write(&mut output);
        output
    }

    fn write(&self, output: &mut Vec<u8>) {
        match self {
            Self::Null => output.push(0xf6),
            Self::Uint(value) => head(output, 0, *value),
            Self::Bytes(bytes) => {
                head(output, 2, bytes.len() as u64);
                output.extend(bytes);
            }
            Self::Text(text) => {
                head(output, 3, text.len() as u64);
                output.extend(text.as_bytes());
            }
            Self::Array(values) => {
                head(output, 4, values.len() as u64);
                for value in values {
                    value.write(output);
                }
            }
            Self::Map(fields) => {
                head(output, 5, fields.len() as u64);
                for (key, value) in fields {
                    head(output, 0, *key);
                    value.write(output);
                }
            }
        }
    }

    /// Replaces a primitive map field for malformed-input construction.
    ///
    /// # Panics
    /// Panics if the fixture is not a map or lacks the named field.
    pub(super) fn replace(&mut self, key: u64, value: Value) {
        let Self::Map(fields) = self else {
            panic!("fixture is not a map");
        };
        fields
            .iter_mut()
            .find(|field| field.0 == key)
            .unwrap_or_else(|| panic!("primitive fixture lacks key {key}"))
            .1 = value;
    }

    /// Returns a mutable primitive array for malformed-input construction.
    ///
    /// # Panics
    /// Panics if the fixture is not an array.
    pub(super) fn array_mut(&mut self) -> &mut Vec<Value> {
        let Self::Array(values) = self else {
            panic!("fixture is not an array");
        };
        values
    }

    /// Returns a mutable map field for nested malformed-input construction.
    ///
    /// # Panics
    /// Panics if the fixture is not a map or lacks the field.
    pub(super) fn field_mut(&mut self, key: u64) -> &mut Value {
        let Self::Map(fields) = self else {
            panic!("fixture is not a map");
        };
        &mut fields
            .iter_mut()
            .find(|field| field.0 == key)
            .unwrap_or_else(|| panic!("primitive fixture lacks key {key}"))
            .1
    }
}

fn head(output: &mut Vec<u8>, major: u8, argument: u64) {
    if argument < 24 {
        output.push(major << 5 | argument as u8);
    } else {
        let bytes = argument.to_be_bytes();
        let (width, additional) = if argument <= u8::MAX.into() {
            (1, 24)
        } else if argument <= u16::MAX.into() {
            (2, 25)
        } else if argument <= u32::MAX.into() {
            (4, 26)
        } else {
            (8, 27)
        };
        output.push(major << 5 | additional);
        output.extend(&bytes[8 - width..]);
    }
}

/// Constructs a primitive unsigned integer.
pub(super) fn u(value: u64) -> Value {
    Value::Uint(value)
}

/// Constructs exact primitive bytes.
pub(super) fn bytes(value: impl Into<Vec<u8>>) -> Value {
    Value::Bytes(value.into())
}

/// Constructs a repeated opaque byte field.
pub(super) fn b(byte: u8, count: usize) -> Value {
    bytes(vec![byte; count])
}

/// Constructs primitive exact text.
pub(super) fn s(value: impl Into<String>) -> Value {
    Value::Text(value.into())
}

/// Constructs an ordered primitive array.
pub(super) fn a(values: Vec<Value>) -> Value {
    Value::Array(values)
}

/// Constructs a primitive map sorted by unsigned keys.
pub(super) fn m(mut fields: Vec<(u64, Value)>) -> Value {
    fields.sort_by_key(|field| field.0);
    Value::Map(fields)
}

/// Hashes primitive bytes solely for represented field relationships.
pub(super) fn raw(value: &Value) -> [u8; 32] {
    *blake3::hash(&value.encode()).as_bytes()
}

/// Reads a unique complete hexadecimal witness from the prepared/published input.
///
/// # Panics
/// Panics for absent, duplicate, malformed or interrupted fixture sections.
pub(super) fn reference(name: &str) -> Vec<u8> {
    let source = include_str!("../../../../../../tests/terrane/control-reference.md");
    let marker = format!("### {name}\n");
    assert_eq!(source.matches(&marker).count(), 1, "{name}");
    let body = source
        .split_once(&marker)
        .unwrap_or_else(|| panic!("missing witness {name}"))
        .1;
    let body = body
        .split("\n### ")
        .next()
        .unwrap_or_else(|| panic!("missing witness body {name}"));
    let hex = body
        .split_once("```hex\n")
        .unwrap_or_else(|| panic!("missing hexadecimal input {name}"))
        .1
        .split("```")
        .next()
        .unwrap_or_else(|| panic!("missing hexadecimal terminator {name}"));
    let hex: String = hex.lines().collect();
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&hex[offset..offset + 2], 16)
                .unwrap_or_else(|error| panic!("invalid hexadecimal input {name}: {error}"))
        })
        .collect()
}

/// Compares independently constructed typed fields and primitive/reference wires.
///
/// # Panics
/// Panics for any wire/field mismatch, rejected positive or accepted malformed
/// prefix, trailing byte or nonminimal container head.
pub(super) fn check<T: Eq + Debug, E: Debug>(
    name: &str,
    model: T,
    primitive: Value,
    encoded: Result<Vec<u8>, E>,
    decode: impl Fn(&[u8]) -> Result<T, E>,
) {
    let wire = primitive.encode();
    assert_eq!(reference(name), wire, "{name}: independent primitive input");
    assert_eq!(
        encoded.unwrap_or_else(|error| panic!("{name}: owning encoding rejected: {error:?}")),
        wire,
        "{name}: owning encoding"
    );
    assert_eq!(
        decode(&wire).unwrap_or_else(|error| panic!("{name}: owning decoding rejected: {error:?}")),
        model,
        "{name}: complete typed fields"
    );
    for end in 0..wire.len() {
        assert!(decode(&wire[..end]).is_err(), "{name}: truncated at {end}");
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(decode(&trailing).is_err(), "{name}: trailing byte");
    if wire[0] & 31 < 24 {
        let mut nonminimal = vec![wire[0] & 0xe0 | 24, wire[0] & 31];
        nonminimal.extend(&wire[1..]);
        assert!(decode(&nonminimal).is_err(), "{name}: nonminimal head");
    }
}

/// Requires exact primitive malformed bytes and an owning decoder error.
///
/// # Panics
/// Panics if reference bytes differ or the owning decoder accepts the wire.
pub(super) fn reject<T, E>(name: &str, wire: Vec<u8>, decode: impl Fn(&[u8]) -> Result<T, E>) {
    assert_eq!(
        reference(&format!("control-negative-{name}")),
        wire,
        "{name}"
    );
    assert!(
        decode(&wire).is_err(),
        "{name}: malformed primitive input accepted"
    );
}
