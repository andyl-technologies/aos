//! Independently assembles canonical CBOR and reads named published witnesses.
//!
//! No owning recipe codec constructs these comparison or rejection bytes.
//! ```text
//! recipe = {1: operation, 2: ordered-roots, 3: arguments}
//! ```

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Represents primitive field data, including explicitly malformed raw bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Value {
    /// An unsigned integer.
    UInt(u64),
    /// An opaque byte string.
    Bytes(Vec<u8>),
    /// A UTF-8 text string.
    Text(String),
    /// A boolean.
    Bool(bool),
    /// The null simple value.
    Null,
    /// An ordered array.
    Array(Vec<Self>),
    /// A canonical map whose keys are sorted during primitive assembly.
    Map(Vec<(Self, Self)>),
    /// Preassembled CBOR used to bypass structural validation in negative inputs.
    Raw(Vec<u8>),
}

/// Emits the shortest unsigned CBOR argument header.
pub(super) fn head(major: u8, argument: u64) -> Vec<u8> {
    let mut output = Vec::new();
    if argument < 24 {
        output.push((major << 5) | argument as u8);
        return output;
    }
    let (width, additional) = if argument <= u8::MAX.into() {
        (1, 24)
    } else if argument <= u16::MAX.into() {
        (2, 25)
    } else if argument <= u32::MAX.into() {
        (4, 26)
    } else {
        (8, 27)
    };
    output.push((major << 5) | additional);
    output.extend_from_slice(&argument.to_be_bytes()[8 - width..]);
    output
}

/// Assembles one value without calling Terrane CBOR or owning format encoders.
pub(super) fn encode(value: &Value) -> Vec<u8> {
    match value {
        Value::UInt(value) => head(0, *value),
        Value::Bytes(bytes) => [head(2, bytes.len() as u64), bytes.clone()].concat(),
        Value::Text(text) => [head(3, text.len() as u64), text.as_bytes().to_vec()].concat(),
        Value::Bool(value) => vec![if *value { 0xf5 } else { 0xf4 }],
        Value::Null => vec![0xf6],
        Value::Array(values) => {
            let mut output = head(4, values.len() as u64);
            for value in values {
                output.extend(encode(value));
            }
            output
        }
        Value::Map(fields) => {
            let mut fields: Vec<_> = fields
                .iter()
                .map(|(key, value)| (encode(key), encode(value)))
                .collect();
            fields.sort_by(|(left, _), (right, _)| (left.len(), left).cmp(&(right.len(), right)));
            let mut output = head(5, fields.len() as u64);
            for (key, value) in fields {
                output.extend(key);
                output.extend(value);
            }
            output
        }
        Value::Raw(bytes) => bytes.clone(),
    }
}

/// Constructs a text field.
pub(super) fn text(value: &str) -> Value {
    Value::Text(String::from(value))
}

/// Constructs a fixed-width opaque digest field.
pub(super) fn digest(value: u8) -> Value {
    Value::Bytes(vec![value; 32])
}

/// Constructs the complete enclosing operation map from independent fields.
pub(super) fn recipe(operation: &str, roots: Vec<Value>, arguments: Value) -> Value {
    Value::Map(vec![
        (Value::UInt(1), text(operation)),
        (Value::UInt(2), Value::Array(roots)),
        (Value::UInt(3), arguments),
    ])
}

/// Requires a successful pure fixture result without suppressing workspace lints.
///
/// # Panics
/// Panics with the fixture reason and error when the result is unsuccessful.
pub(super) fn required<T, E: core::fmt::Debug>(result: Result<T, E>, reason: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{reason}: {error:?}"),
    }
}

/// Requires a field that the independent fixture declares present.
///
/// # Panics
/// Panics with the fixture reason when the optional field is absent.
pub(super) fn present<T>(value: Option<T>, reason: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{reason}"),
    }
}

/// Reads exact named hex data from the temporary published reference.
///
/// # Panics
/// Panics if the reviewed reference is missing, ambiguous, or contains invalid hex.
pub(super) fn published(name: &str, field: &str) -> Vec<u8> {
    const REFERENCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../tests/terrane/recipe-context-reference.md"
    ));
    let marker = alloc::format!("### {name}\n");
    assert_eq!(
        REFERENCE.matches(&marker).count(),
        1,
        "unique fixture {name}"
    );
    let section = present(REFERENCE.split_once(&marker), "named fixture").1;
    let section = present(section.split("\n### ").next(), "bounded fixture");
    let prefix = alloc::format!("{field} = ");
    let lines: Vec<_> = section
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect();
    assert_eq!(lines.len(), 1, "unique {field} field for {name}");
    let value = lines[0];
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = required(core::str::from_utf8(pair), "ASCII hex");
            required(u8::from_str_radix(pair, 16), "lowercase fixture hex")
        })
        .collect()
}

/// Compares the full independently built recipe wire and registered memo digest.
///
/// # Panics
/// Panics if a fixture or independently reconstructed memo identity differs.
pub(super) fn positive(name: &str, fields: &Value, recipe: &crate::algebra::Recipe<'_>) -> Vec<u8> {
    let wire = encode(fields);
    assert_eq!(wire, published(name, "wire"), "independent wire {name}");
    assert_eq!(recipe.encode(), wire, "owning encode {name}");
    let mut preimage = b"terrane-memo-v1\0".to_vec();
    preimage.extend_from_slice(&wire);
    let identity = blake3::hash(&preimage);
    assert_eq!(identity.as_bytes().as_slice(), published(name, "memo"));
    assert_eq!(
        required(recipe.identity(), "registered memo domain"),
        *identity.as_bytes()
    );
    wire
}

/// Requires structural rejection of independently constructed complete recipe bytes.
///
/// # Panics
/// Panics if the published bytes differ or the owning decoder accepts the input.
pub(super) fn negative(name: &str, wire: Vec<u8>) {
    assert_eq!(wire, published(name, "wire"), "independent negative {name}");
    assert!(
        crate::algebra::Recipe::decode(&wire).is_err(),
        "structural refusal {name}"
    );
}
