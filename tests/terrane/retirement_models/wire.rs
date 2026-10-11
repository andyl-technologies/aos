//! Constructs retirement wire fields using only primitive CBOR and BLAKE3.
//!
//! No owning record encoder supplies bytes to this independent oracle.
//!
//! ```text
//! value = uint / bytes / text / array / ordered-map / null / bool
//! ```

/// Represents the bounded fixture's primitive CBOR values.
#[derive(Clone)]
pub(super) enum Value {
    /// An unsigned integer.
    UInt(u64),
    /// An exact byte string.
    Bytes(Vec<u8>),
    /// A UTF-8 text string.
    Text(String),
    /// An ordered sequence of values.
    Array(Vec<Value>),
    /// A map with strictly increasing unsigned keys.
    Map(Vec<(u64, Value)>),
    /// An explicit absent value.
    Null,
    /// A simple boolean value.
    Bool(bool),
}

use Value::{Array, Bool, Map, Null, UInt};

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
    /// Encodes primitive deterministic CBOR without a Terrane codec.
    ///
    /// # Panics
    /// Panics if a map's keys are not strictly increasing.
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        self.write(&mut output);
        output
    }

    fn write(&self, output: &mut Vec<u8>) {
        match self {
            UInt(value) => head(output, 0, *value),
            Self::Bytes(value) => {
                head(output, 2, value.len() as u64);
                output.extend(value);
            }
            Self::Text(value) => {
                head(output, 3, value.len() as u64);
                output.extend(value.as_bytes());
            }
            Array(values) => {
                head(output, 4, values.len() as u64);
                for value in values {
                    value.write(output);
                }
            }
            Map(fields) => {
                assert!(fields.windows(2).all(|pair| pair[0].0 < pair[1].0));
                head(output, 5, fields.len() as u64);
                for (key, value) in fields {
                    UInt(*key).write(output);
                    value.write(output);
                }
            }
            Null => output.push(0xf6),
            Bool(value) => output.push(if *value { 0xf5 } else { 0xf4 }),
        }
    }

    /// Removes a required field to build a negative wire directly.
    ///
    /// # Panics
    /// Panics if the value is not a map or the key is absent.
    pub(super) fn remove(&mut self, key: u64) {
        let Map(fields) = self else {
            panic!("fixture must be a map")
        };
        assert!(fields.iter().any(|field| field.0 == key));
        fields.retain(|field| field.0 != key);
    }

    /// Replaces or adds a primitive map field for a negative wire.
    ///
    /// # Panics
    /// Panics if the value is not a map.
    pub(super) fn set(&mut self, key: u64, value: Value) {
        let Map(fields) = self else {
            panic!("fixture must be a map")
        };
        fields.retain(|field| field.0 != key);
        fields.push((key, value));
        fields.sort_by_key(|field| field.0);
    }
}

/// Constructs a primitive byte string.
pub(super) fn bytes(value: impl AsRef<[u8]>) -> Value {
    Value::Bytes(value.as_ref().to_vec())
}

fn text(value: impl Into<String>) -> Value {
    Value::Text(value.into())
}

fn repeated(byte: u8) -> Value {
    bytes([byte; 32])
}

/// Returns a raw digest, without assigning an immutable-content identity.
///
/// # Panics
/// Panics if a map's keys are not strictly increasing.
pub(super) fn raw(value: &Value) -> [u8; 32] {
    *blake3::hash(&value.encode()).as_bytes()
}

/// Returns the fixed operation key's canonical fixture spelling.
pub(super) fn operation_key() -> String {
    format!("gc/3/delete/{}/{}", "12".repeat(16), "34".repeat(32))
}

fn trash_key() -> String {
    format!("trash/3/{}", "12".repeat(16))
}

/// Constructs the whole lease map independently.
pub(super) fn lease() -> Value {
    Map(vec![(1, text("A")), (2, UInt(2)), (3, UInt(100))])
}

/// Constructs the exact local or remote backend fields.
pub(super) fn backend(local: bool) -> Value {
    if local {
        Array(vec![
            UInt(0),
            bytes(b"/a"),
            UInt(1),
            UInt(2),
            UInt(3),
            UInt(4),
        ])
    } else {
        Array(vec![
            UInt(1),
            text("s3"),
            Array(vec![text("e"), text("b"), bytes([]), repeated(1)]),
            Array(vec![bytes(b"c"), repeated(2)]),
        ])
    }
}

fn exclusion() -> Value {
    Array(vec![bytes([0x12; 16]), UInt(3), UInt(2)])
}

/// Constructs the complete embedded Tombstone.
pub(super) fn tombstone() -> Value {
    Map(vec![
        (1, bytes([0x12; 16])),
        (2, UInt(3)),
        (3, UInt(4)),
        (4, UInt(0)),
        (5, UInt(2)),
    ])
}

/// Constructs a slot's represented fields.
pub(super) fn slot(revision: u64, byte: u8) -> Value {
    Array(vec![UInt(revision), repeated(byte)])
}

fn pointer(key: impl Into<String>, byte: u8) -> Value {
    Array(vec![text(key), repeated(byte)])
}

/// Constructs the empty detached-index witness in little-endian format.
pub(super) fn witness() -> Vec<u8> {
    let mut value = b"TRPK".to_vec();
    value.extend(1_u16.to_le_bytes());
    value.extend([0; 2]);
    value.extend([0x12; 16]);
    value.extend(b"TRIX");
    value.extend([0; 8]);
    value
}

/// Computes the registered detached-index digest using only the hash primitive.
pub(super) fn index_digest() -> [u8; 32] {
    let mut value = b"terrane-index-v1\0".to_vec();
    value.extend(witness());
    *blake3::hash(&value).as_bytes()
}

/// Constructs either complete authorization alternative from primitive fields.
pub(super) fn authorization(copied: bool, local: bool, lineage: bool) -> Value {
    let tombstone = tombstone().encode();
    let trash = Array(vec![
        text(trash_key()),
        bytes(blake3::hash(&tombstone).as_bytes()),
        UInt(tombstone.len() as u64),
    ]);
    let artifacts = if copied {
        let barrier = if local {
            Array(vec![
                text(trash_key()),
                repeated(5),
                Array(vec![UInt(2), bytes(&tombstone)]),
                bytes([6]),
            ])
        } else {
            trash
        };
        Array(vec![Null, Null, barrier])
    } else {
        let key = format!("objects/pack/12/{}", "12".repeat(16));
        Array(vec![
            Array(vec![text(format!("{key}.pack")), repeated(7), UInt(52)]),
            Array(vec![
                text(format!("{key}.idx")),
                bytes(index_digest()),
                UInt(36),
            ]),
            trash,
        ])
    };
    let mut fields = vec![
        (0, UInt(2)),
        (1, repeated(0x34)),
        (2, backend(local)),
        (3, exclusion()),
        (4, lease()),
        (5, UInt(2)),
        (6, artifacts),
    ];
    if !copied {
        fields.push((7, bytes(witness())));
    }
    fields.extend([
        (8, bytes(tombstone)),
        (9, UInt(2_000_000_000)),
        (10, pointer("gc/3/fence/2", 8)),
        (11, UInt(1)),
        (12, UInt(1_000_000_000)),
        (13, UInt(1)),
    ]);
    if copied {
        fields.extend([(14, UInt(1)), (15, slot(0, 9)), (16, slot(1, 10))]);
        if lineage {
            fields.push((17, pointer("gc/3/fence/2", 21)));
        }
    }
    Map(fields)
}

/// Constructs all ten copied preparation plan fields independently.
pub(super) fn plan(local: bool) -> Value {
    Map(vec![
        (0, UInt(2)),
        (1, repeated(0x34)),
        (2, backend(local)),
        (3, exclusion()),
        (4, lease()),
        (5, slot(0, 9)),
        (6, pointer("gc/3/fence/0", 11)),
        (7, bytes(tombstone().encode())),
        (8, UInt(1)),
        (9, UInt(2)),
    ])
}

/// Constructs a represented selection without selecting authority.
pub(super) fn selection(permanent: bool, digest: [u8; 32]) -> Value {
    if permanent {
        Array(vec![UInt(1), text(operation_key()), bytes(digest)])
    } else {
        Array(vec![UInt(0)])
    }
}

/// Constructs an embedded publication state without its owning encoder.
pub(super) fn state(
    revision: u64,
    local: bool,
    owners: Vec<Value>,
    guard: Option<u8>,
    loss: u64,
) -> Value {
    Map(vec![
        (0, UInt(1)),
        (1, UInt(revision)),
        (2, UInt(loss)),
        (3, Array(vec![])),
        (4, backend(local)),
        (5, Array(vec![])),
        (6, guard.map_or(Null, repeated)),
        (7, Array(owners)),
    ])
}

/// Constructs an entire pass including state, observations and coverage.
pub(super) fn progress(local: bool, completed: bool, copied: bool) -> Value {
    let digest = raw(&authorization(copied, local, false));
    let owners = vec![Array(vec![bytes([0x12; 16]), selection(true, digest)])];
    let mut observations = vec![Array(vec![UInt(0), Array(vec![UInt(0)]), UInt(1)])];
    if !local {
        observations.extend([
            Array(vec![
                UInt(0),
                Array(vec![UInt(1), UInt(0), bytes(b"version")]),
                UInt(1),
            ]),
            Array(vec![
                UInt(0),
                Array(vec![UInt(1), UInt(1), bytes(b"marker")]),
                UInt(2),
            ]),
        ]);
    }
    observations.extend([
        Array(vec![UInt(1), Array(vec![UInt(0)]), UInt(2)]),
        Array(vec![UInt(2), UInt(3), Array(vec![UInt(0)]), UInt(3)]),
    ]);
    let mut fields = vec![
        (0, UInt(2)),
        (1, bytes(digest)),
        (2, slot(3, 12)),
        (3, UInt(if copied { 2 } else { 1 })),
        (4, Array(vec![UInt(0), UInt(0)])),
        (5, slot(4, 13)),
        (6, bytes(state(4, local, owners, None, 1).encode())),
        (7, lease()),
        (8, backend(local)),
        (9, UInt(u64::from(completed))),
        (10, Array(observations)),
        (
            11,
            Array(
                (0..3)
                    .map(|kind| Array(vec![UInt(kind), UInt(u64::from(completed))]))
                    .collect(),
            ),
        ),
        (12, repeated(14)),
    ];
    if local {
        fields.push((13, pointer("gc/3/fence/4", 15)));
    }
    Map(fields)
}

/// Constructs the complete capabilities embedded in each fence.
pub(super) fn capabilities() -> Value {
    Map(vec![
        (1, UInt(2)),
        (2, Bool(true)),
        (3, Bool(true)),
        (4, Bool(true)),
        (5, Bool(false)),
        (6, UInt(1)),
        (7, UInt(4)),
        (
            8,
            Map(vec![
                (1, text("terrane-v1")),
                (2, text("blake3")),
                (3, text("cdc-1m")),
                (4, repeated(0)),
            ]),
        ),
        (9, UInt(1)),
        (10, Array(vec![])),
        (11, UInt(1)),
    ])
}

/// Constructs every manifest field, including explicit empty inventories.
pub(super) fn manifest(copied: bool) -> Value {
    Map(vec![
        (1, UInt(1)),
        (2, Array(vec![])),
        (3, UInt(4)),
        (4, UInt(3)),
        (5, Array(vec![])),
        (6, Array(vec![exclusion()])),
        (
            7,
            Array(if copied {
                vec![bytes([0x12; 16])]
            } else {
                vec![]
            }),
        ),
    ])
}

/// Constructs current/copy fence fields without authority or I/O.
pub(super) fn fence(copied: bool, local: bool) -> Value {
    let owners = if copied {
        vec![Array(vec![bytes([0x12; 16]), selection(false, [0; 32])])]
    } else {
        vec![]
    };
    let mut fields = vec![
        (0, UInt(if copied { 2 } else { 1 })),
        (1, bytes(capabilities().encode())),
        (2, bytes(manifest(copied).encode())),
        (3, Array(vec![])),
        (4, repeated(17)),
        (5, bytes(state(2, local, owners, Some(17), 0).encode())),
        (6, pointer("gc/3/roots", 18)),
        (7, pointer("gc/3/state", 19)),
        (8, backend(local)),
        (9, Array(vec![])),
    ];
    if copied {
        fields.extend([
            (10, slot(0, 9)),
            (
                11,
                pointer(format!("publication/snapshots/2:{}", "00".repeat(32)), 20),
            ),
        ]);
    }
    Map(fields)
}

/// Constructs an operation, computing its pointer digest independently.
pub(super) fn operation(phase: u64, copied: bool, local: bool) -> Value {
    let revision = if phase == 0 {
        0
    } else if copied {
        2
    } else {
        1
    };
    let (owner, pass) = if phase == 1 {
        let key = format!("gc/3/reconcile/{}/{revision}", "0e".repeat(32));
        (
            slot(3, 12),
            Array(vec![text(key), bytes(raw(&progress(local, false, copied)))]),
        )
    } else {
        (Null, Null)
    };
    Array(vec![
        UInt(2),
        UInt(revision),
        UInt(phase),
        authorization(copied, local, false),
        owner,
        pass,
    ])
}
