//! Supplies independent primitive CBOR and reference bytes to private consumers.
//!
//! Canonical field values below carry no verified identity or authority.
//!
//! ```text
//! primitive = uint / text / bytes / array / map / null / bool
//! ```

#![allow(
    dead_code,
    reason = "four private consumers use different fixture subsets"
)]

use crate::cbor::Decoder;
use alloc::{format, string::String, vec, vec::Vec};

/// Represents a bounded ordinary fixture field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Value {
    /// An unsigned integer.
    UInt(u64),
    /// A UTF-8 string.
    Text(String),
    /// An exact byte string.
    Bytes(Vec<u8>),
    /// An ordered sequence.
    Array(Vec<Value>),
    /// A map with canonically sorted primitive keys.
    Map(Vec<(Value, Value)>),
    /// Explicit absence.
    Null,
    /// A boolean simple value.
    Bool(bool),
}

use Value::{Array, Bool, Bytes, Map, Null, Text, UInt};

fn head(output: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => output.push(prefix | value as u8),
        24..=255 => output.extend([prefix | 24, value as u8]),
        256..=65535 => {
            output.push(prefix | 25);
            output.extend((value as u16).to_be_bytes());
        }
        65536..=4294967295 => {
            output.push(prefix | 26);
            output.extend((value as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend(value.to_be_bytes());
        }
    }
}

impl Value {
    /// Encodes bounded primitive fields without an owning record encoder.
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        self.write(&mut output);
        output
    }

    fn write(&self, output: &mut Vec<u8>) {
        match self {
            UInt(value) => head(output, 0, *value),
            Text(value) => {
                head(output, 3, value.len() as u64);
                output.extend(value.as_bytes());
            }
            Bytes(value) => {
                head(output, 2, value.len() as u64);
                output.extend(value);
            }
            Array(values) => {
                head(output, 4, values.len() as u64);
                for value in values {
                    value.write(output);
                }
            }
            Map(fields) => {
                head(output, 5, fields.len() as u64);
                for (key, value) in fields {
                    key.write(output);
                    value.write(output);
                }
            }
            Null => output.push(0xf6),
            Bool(value) => output.push(if *value { 0xf5 } else { 0xf4 }),
        }
    }
}

/// Constructs a byte field.
pub(super) fn bytes(value: impl AsRef<[u8]>) -> Value {
    Bytes(value.as_ref().to_vec())
}

/// Constructs a text field.
pub(super) fn text(value: impl Into<String>) -> Value {
    Text(value.into())
}

/// Constructs a 32-byte opaque digest-shaped field.
pub(super) fn digest(byte: u8) -> Value {
    bytes([byte; 32])
}

/// Orders a primitive map by canonical encoded keys.
pub(super) fn map(mut fields: Vec<(Value, Value)>) -> Value {
    fields.sort_by_cached_key(|(key, _)| {
        let encoded = key.encode();
        (encoded.len(), encoded)
    });
    Map(fields)
}

/// Constructs an unsigned-key map.
pub(super) fn uint_map(fields: Vec<(u64, Value)>) -> Value {
    map(fields
        .into_iter()
        .map(|(key, value)| (UInt(key), value))
        .collect())
}

/// Reads one complete bounded primitive model for field assertions.
///
/// # Panics
/// Panics on malformed fixture bytes.
pub(super) fn fields(encoded: &[u8]) -> Value {
    fn read(decoder: &mut Decoder<'_>, bound: usize) -> Value {
        match decoder.peek_major().unwrap() {
            0 => UInt(decoder.uint().unwrap()),
            2 => bytes(decoder.bytes(bound).unwrap()),
            3 => text(decoder.text(bound).unwrap()),
            4 => {
                let count = decoder.array(bound).unwrap();
                Array((0..count).map(|_| read(decoder, bound)).collect())
            }
            5 => {
                let count = decoder.map(bound).unwrap();
                Map((0..count)
                    .map(|_| (read(decoder, bound), read(decoder, bound)))
                    .collect())
            }
            7 => match decoder.simple().unwrap() {
                0xf4 => Bool(false),
                0xf5 => Bool(true),
                0xf6 => Null,
                _ => panic!("unsupported fixture simple value"),
            },
            _ => panic!("unsupported fixture major type"),
        }
    }
    let mut decoder = Decoder::new(encoded);
    let value = read(&mut decoder, encoded.len());
    decoder.finish().unwrap();
    value
}

/// Extracts the exact prepared reference input for a unique heading.
///
/// # Panics
/// Panics if a required fixture is absent, duplicated or malformed.
pub(super) fn reference(name: &str) -> Vec<u8> {
    const REFERENCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../tests/terrane/evidence-reference.md"
    ));
    let heading = format!("### {name}\n");
    assert_eq!(REFERENCE.matches(&heading).count(), 1, "{name}");
    let section = REFERENCE
        .split_once(&heading)
        .unwrap()
        .1
        .split("\n### ")
        .next()
        .unwrap();
    let hex = section
        .split_once("```hex\n")
        .unwrap()
        .1
        .split_once("```")
        .unwrap()
        .0;
    let digits: String = hex
        .chars()
        .filter(|value| !value.is_ascii_whitespace())
        .collect();
    assert!(
        digits.bytes().all(|value| value.is_ascii_hexdigit()),
        "{name}"
    );
    assert_eq!(digits.len() % 2, 0, "{name}");
    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

/// Compares primitive bytes with the independently generated reference.
///
/// # Panics
/// Panics on any wire disagreement.
pub(super) fn compare(name: &str, model: &Value) -> Vec<u8> {
    let expected = reference(name);
    assert_eq!(model.encode(), expected, "primitive bytes: {name}");
    assert_eq!(
        fields(&expected),
        *model,
        "complete primitive fields: {name}"
    );
    expected
}

/// Constructs every field of an ordinary location tuple.
pub(super) fn location(commit: u8, root: u8, path: &[u8]) -> Value {
    Array(vec![digest(commit), digest(root), bytes(path)])
}

/// Constructs all nine side-evidence fields independently.
pub(super) fn evidence(carrying: bool) -> Value {
    Array(vec![
        digest(5),
        digest(6),
        text("hash.sha256"),
        text("sha256"),
        text("v1"),
        bytes(digest(7).encode()),
        digest(8),
        location(if carrying { 9 } else { 8 }, 10, b"carrying/item"),
        Array(vec![text("public"), bytes(b"producer/full/item")]),
    ])
}

/// Constructs selected-row fields with distinct relative and full paths.
pub(super) fn row(index: u8, carrying: bool) -> Value {
    Array(vec![
        location(1, 2 + index, b"relative/item"),
        text("hash.sha256"),
        text("private:target"),
        bytes(b"view/full/item"),
        evidence(carrying),
    ])
}

/// Constructs exact context projection fields, preserving baseline presence.
pub(super) fn context(version: u64, baseline: Option<&str>, rows: Option<Vec<Value>>) -> Value {
    let selector = Array(vec![
        text("attr-by"),
        text("hash.sha256"),
        Array(vec![text("kind"), text("workload")]),
    ]);
    let mut values = vec![
        UInt(version),
        digest(1),
        text("private:target"),
        bytes(selector.encode()),
        baseline.map_or(Null, text),
        UInt(262_144),
    ];
    if version == 2 {
        values.push(bytes(
            Array(rows.unwrap_or_else(|| vec![row(0, false), row(1, true)])).encode(),
        ));
    }
    Array(values)
}

/// Constructs all eight statement slots for a supported content layout.
pub(super) fn statement(layout: usize) -> Value {
    let content = match layout {
        0 | 1 => Array(vec![
            UInt(1),
            UInt(if layout == 0 { 24 } else { 65536 }),
            Array(vec![UInt(layout as u64), digest(21)]),
        ]),
        2 => Array(vec![UInt(2)]),
        _ => Array(vec![UInt(3), bytes(b"raw/\xfftarget")]),
    };
    Array(vec![
        text("12".repeat(32)),
        text("private:source"),
        UInt(256),
        location(11, 12, b"source/full/item"),
        digest(13),
        Array(vec![
            text("refs/heads/_/target"),
            digest(14),
            bytes(b"target/full/item"),
            text("private:target"),
        ]),
        content,
        digest(15),
    ])
}

/// Constructs opaque canonical recipe fields whose signature-like data is retained.
pub(super) fn recipe(opaque_changed: bool) -> Value {
    uint_map(vec![
        (1, text("map")),
        (2, Array(vec![digest(7)])),
        (
            3,
            map(vec![
                (
                    text("opaque"),
                    Array(vec![
                        bytes([if opaque_changed { 0x8e } else { 0x8a }; 64]),
                        map(vec![(text("signature"), bytes([0x8b; 64]))]),
                    ]),
                ),
                (text("note"), text("kept")),
            ]),
        ),
    ])
}

/// Constructs syntax-only embedded token data with a retained signature slot.
pub(super) fn token() -> Value {
    Array(vec![uint_map(vec![
        (1, text("issuer-a")),
        (2, text("key-a")),
        (3, text("subject-a")),
        (4, UInt(2)),
        (5, Array(vec![text("baseline")])),
        (6, UInt(999)),
        (7, UInt(1)),
        (8, bytes([8; 16])),
        (9, Array(vec![Array(vec![text("refs/heads/_/*"), UInt(4)])])),
        (10, text("workload-a")),
        (11, digest(0x8d)),
        (12, bytes([0x8c; 64])),
    ])])
}

/// Constructs complete target metadata and precisely normalized certificate slots.
pub(super) fn target(variant: &str, normalized: bool) -> Value {
    let changed = variant == "signatures";
    let source = location(31, 32, b"origin/item");
    let proof = uint_map(vec![
        (1, text("12".repeat(32))),
        (2, text("private:source")),
        (3, UInt(256)),
        (
            4,
            bytes(
                [if normalized {
                    0
                } else if changed {
                    0x81
                } else {
                    0x80
                }; 64],
            ),
        ),
    ]);
    let other_proof = uint_map(vec![
        (1, text("34".repeat(32))),
        (2, text("group:source")),
        (3, UInt(65536)),
        (
            4,
            bytes(
                [if normalized {
                    0
                } else if changed {
                    0x83
                } else {
                    0x82
                }; 64],
            ),
        ),
    ]);
    let locality = uint_map(vec![(1, text("r")), (2, text("z")), (3, text("h"))]);
    let provenance = uint_map(vec![
        (1, text("issuer-a")),
        (2, bytes([8; 16])),
        (3, text("subject-a")),
        (4, UInt(2)),
        (5, text("workload-a")),
        (6, text("process-a")),
        (7, UInt(24)),
        (8, UInt(2)),
        (9, UInt(4)),
        (10, token()),
    ]);
    let profile = uint_map(vec![
        (1, UInt(1)),
        (2, text("cdc-1m")),
        (3, recipe(variant == "opaque")),
        (4, Bool(false)),
        (5, uint_map(vec![(1, text("owner-a")), (2, UInt(999))])),
        (
            6,
            map(vec![
                (text("baseline"), text("baseline")),
                (text("trust"), Array(vec![text("preset"), text("strict")])),
            ]),
        ),
        (
            7,
            Array(vec![
                Array(vec![
                    digest(2),
                    bytes(b"a"),
                    UInt(0),
                    map(vec![
                        (text("magic"), UInt(0)),
                        (text("hash.sha256"), source.clone()),
                    ]),
                    source.clone(),
                    proof,
                ]),
                Array(vec![digest(2), bytes(b"b"), source.clone()]),
                Array(vec![
                    digest(3),
                    bytes(b"c"),
                    UInt(0),
                    Null,
                    source,
                    other_proof,
                ]),
            ]),
        ),
        (
            8,
            uint_map(vec![
                (1, text("refs/heads/_/target")),
                (2, text("api")),
                (3, locality.clone()),
                (
                    4,
                    Array(vec![
                        Array(vec![bytes(b"/"), text("private:target")]),
                        Array(vec![bytes(b"/nested"), text("group:target")]),
                    ]),
                ),
            ]),
        ),
    ]);
    let mut values = vec![
        (1, digest(1)),
        (2, Array(vec![digest(4), digest(5)])),
        (3, provenance),
        (4, UInt(256)),
        (5, text("retained metadata")),
        (6, profile),
        (7, Array(vec![Array(vec![bytes([6; 16]), locality])])),
    ];
    if !normalized {
        values.push((8, bytes([if changed { 0x91 } else { 0x90 }; 64])));
    }
    uint_map(values)
}
