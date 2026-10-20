//! Compares complete unverified local reconciliation models with primitive CBOR.
//!
//! Digests and fence labels here are ordinary field data, without factories,
//! physical observations, current-authority checks or deletion operations.
//!
//! ```text
//! {0: 1, 1: authorization32, 2: ["gc/5/fence/7", fence32],
//!  3: [pack16, original_cycle, original_epoch], 4: index32}
//! ```

use std::collections::BTreeMap;

use terrane_format::cbor::Error as CborError;
use terrane_format::gc::publication::PublicationError;
use terrane_format::gc::publication::reconciliation::LocalGcReconciliation;

const MAX_UINT: u64 = u64::MAX;
const HEADING: &str = "## Local reconciliation record field witnesses";

/// Encodes primitive field tables independently of the owning record encoder.
#[derive(Clone)]
enum Value {
    UInt(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Self>),
    Map(Vec<(u64, Self)>),
    Bool(bool),
    Null,
    Raw(Vec<u8>),
}

/// Assembles the shortest primitive header without an owning format codec.
///
/// # Panics
/// Panics if the fixed width table ceases to cover every uint64 value.
fn head(major: u8, value: u64) -> Vec<u8> {
    if value < 24 {
        return vec![(major << 5) | value as u8];
    }
    for (width, additional) in [(1, 24), (2, 25), (4, 26), (8, 27)] {
        if width == 8 || value < (1 << (8 * width)) {
            let mut bytes = vec![(major << 5) | additional];
            bytes.extend_from_slice(&value.to_be_bytes()[8 - width..]);
            return bytes;
        }
    }
    unreachable!("every uint64 uses at most eight bytes")
}

fn encode(value: &Value) -> Vec<u8> {
    match value {
        Value::UInt(value) => head(0, *value),
        Value::Bytes(value) => [head(2, value.len() as u64), value.clone()].concat(),
        Value::Text(value) => [head(3, value.len() as u64), value.as_bytes().to_vec()].concat(),
        Value::Array(values) => {
            let mut bytes = head(4, values.len() as u64);
            for value in values {
                bytes.extend_from_slice(&encode(value));
            }
            bytes
        }
        Value::Map(values) => {
            let mut fields: Vec<_> = values
                .iter()
                .map(|(key, value)| (head(0, *key), encode(value)))
                .collect();
            fields.sort_by(|left, right| left.0.cmp(&right.0));
            let mut bytes = head(5, fields.len() as u64);
            for (key, value) in fields {
                bytes.extend_from_slice(&key);
                bytes.extend_from_slice(&value);
            }
            bytes
        }
        Value::Bool(value) => vec![if *value { 0xf5 } else { 0xf4 }],
        Value::Null => vec![0xf6],
        Value::Raw(value) => value.clone(),
    }
}

fn text(value: &str) -> Value {
    Value::Text(value.to_string())
}

fn fields(cycle: u64, epoch: u64, key: &str, byte: u8) -> Value {
    Value::Map(vec![
        (0, Value::UInt(1)),
        (1, Value::Bytes(vec![byte; 32])),
        (
            2,
            Value::Array(vec![
                text(key),
                Value::Bytes(vec![byte.wrapping_add(1); 32]),
            ]),
        ),
        (
            3,
            Value::Array(vec![
                Value::Bytes(vec![byte.wrapping_add(2); 16]),
                Value::UInt(cycle),
                Value::UInt(epoch),
            ]),
        ),
        (4, Value::Bytes(vec![byte.wrapping_add(3); 32])),
    ])
}

fn model(cycle: u64, epoch: u64, key: &str, byte: u8) -> LocalGcReconciliation {
    LocalGcReconciliation {
        authorization: [byte; 32],
        fence_key: key.to_string(),
        fence_digest: [byte.wrapping_add(1); 32],
        pack: [byte.wrapping_add(2); 16],
        cycle,
        epoch,
        index: [byte.wrapping_add(3); 32],
    }
}

/// Replaces a fixture map field or array element.
///
/// # Panics
/// Panics when a path is empty, missing, or traverses a scalar fixture value.
fn set(value: &mut Value, path: &[u64], replacement: Value) {
    let field = match value {
        Value::Map(fields) => {
            &mut fields
                .iter_mut()
                .find(|(key, _)| *key == path[0])
                .unwrap_or_else(|| panic!("missing fixture key"))
                .1
        }
        Value::Array(fields) => &mut fields[path[0] as usize],
        _ => panic!("fixture path traverses a scalar"),
    };
    if path.len() == 1 {
        *field = replacement;
    } else {
        set(field, &path[1..], replacement);
    }
}

/// Changes one independent fixture field.
///
/// # Panics
/// Panics for an invalid fixture path, as documented by `set`.
fn changed(model: &Value, path: &[u64], replacement: Value) -> Value {
    let mut value = model.clone();
    set(&mut value, path, replacement);
    value
}

fn positive_models() -> Vec<(String, Value, LocalGcReconciliation)> {
    let mut values = vec![
        (
            "local-reconciliation-current-and-original".into(),
            fields(3, 4, "gc/5/fence/7", 1),
            model(3, 4, "gc/5/fence/7", 1),
        ),
        (
            "local-reconciliation-zero-counters".into(),
            fields(0, 0, "gc/0/fence/0", 0),
            model(0, 0, "gc/0/fence/0", 0),
        ),
        (
            "local-reconciliation-max-counters".into(),
            fields(
                MAX_UINT,
                MAX_UINT,
                &format!("gc/{MAX_UINT}/fence/{MAX_UINT}"),
                252,
            ),
            model(
                MAX_UINT,
                MAX_UINT,
                &format!("gc/{MAX_UINT}/fence/{MAX_UINT}"),
                252,
            ),
        ),
    ];
    for counter in [23, 24, 255, 256, 65535, 65536, (1 << 32) - 1, 1 << 32] {
        values.push((
            format!("local-reconciliation-counter-{counter}"),
            fields(counter, counter, "gc/5/fence/7", 1),
            model(counter, counter, "gc/5/fence/7", 1),
        ));
    }
    let mut varied_fields = fields(9, 2, "gc/12/fence/24", 1);
    set(&mut varied_fields, &[1], Value::Bytes((0..32).collect()));
    set(
        &mut varied_fields,
        &[2, 1],
        Value::Bytes((0..32).rev().collect()),
    );
    set(&mut varied_fields, &[3, 0], Value::Bytes((0..16).collect()));
    set(&mut varied_fields, &[4], Value::Bytes((32..64).collect()));
    let mut varied_model = model(9, 2, "gc/12/fence/24", 1);
    varied_model.authorization = core::array::from_fn(|index| index as u8);
    varied_model.fence_digest = core::array::from_fn(|index| (31 - index) as u8);
    varied_model.pack = core::array::from_fn(|index| index as u8);
    varied_model.index = core::array::from_fn(|index| (32 + index) as u8);
    values.push((
        "local-reconciliation-distinct-byte-fields".into(),
        varied_fields,
        varied_model,
    ));
    values
}

fn negative_wires() -> Vec<(String, Vec<u8>)> {
    let model = fields(3, 4, "gc/5/fence/7", 1);
    let mut wires = Vec::new();
    let mut add = |name: String, value: Value| {
        wires.push((format!("bad-local-reconciliation-{name}"), encode(&value)));
    };
    for key in 0..5 {
        let Value::Map(mut values) = model.clone() else {
            unreachable!()
        };
        values.retain(|(current, _)| *current != key);
        add(format!("missing-key-{key}"), Value::Map(values));
        add(
            format!("null-key-{key}"),
            changed(&model, &[key], Value::Null),
        );
    }
    let Value::Map(mut values) = model.clone() else {
        unreachable!()
    };
    values.push((5, Value::UInt(0)));
    add("unknown-key".into(), Value::Map(values));
    for (name, version) in [
        ("0", Value::UInt(0)),
        ("2", Value::UInt(2)),
        ("18446744073709551615", Value::UInt(MAX_UINT)),
        ("True", Value::Bool(true)),
    ] {
        add(format!("version-{name}"), changed(&model, &[0], version));
    }
    for (label, path, width) in [
        ("authorization", vec![1], 32),
        ("fence-digest", vec![2, 1], 32),
        ("pack", vec![3, 0], 16),
        ("index", vec![4], 32),
    ] {
        for length in [0, width - 1, width + 1] {
            add(
                format!("{label}-width-{length}"),
                changed(&model, &path, Value::Bytes(vec![0; length])),
            );
        }
        add(
            format!("{label}-text"),
            changed(&model, &path, text("opaque")),
        );
    }
    for (key, count) in [(2, 2), (3, 3)] {
        for length in 0..count + 2 {
            if length != count {
                add(
                    format!("tuple-{key}-count-{length}"),
                    changed(&model, &[key], Value::Array(vec![Value::UInt(0); length])),
                );
            }
        }
    }
    for (label, path) in [("cycle", vec![3, 1]), ("epoch", vec![3, 2])] {
        for (name, value) in [
            ("null", Value::Null),
            ("bool", Value::Bool(false)),
            ("text", text("1")),
        ] {
            add(format!("{label}-{name}"), changed(&model, &path, value));
        }
        for (name, raw) in [("negative", vec![0x20]), ("nonminimal", vec![0x18, 0])] {
            add(
                format!("{label}-{name}"),
                changed(&model, &path, Value::Raw(raw)),
            );
        }
    }
    for (name, key) in [
        ("empty", "".into()),
        ("wrong-prefix", "other/5/fence/7".into()),
        ("wrong-kind", "gc/5/reconcile/7".into()),
        ("cycle-leading-zero", "gc/05/fence/7".into()),
        ("revision-leading-zero", "gc/5/fence/07".into()),
        ("cycle-negative", "gc/-5/fence/7".into()),
        ("revision-plus", "gc/5/fence/+7".into()),
        ("extra-component", "gc/5/fence/7/more".into()),
        (
            "overflow",
            format!("gc/{}/fence/7", u128::from(MAX_UINT) + 1),
        ),
        ("unicode", "gc/５/fence/7".into()),
        ("nul", "gc/5/fence/7\0".into()),
    ] {
        add(
            format!("fence-key-{name}"),
            changed(&model, &[2, 0], text(&key)),
        );
    }
    add(
        "fence-key-bytes".into(),
        changed(&model, &[2, 0], Value::Bytes(b"gc/5/fence/7".to_vec())),
    );
    add(
        "fence-key-invalid-utf8".into(),
        changed(&model, &[2, 0], Value::Raw(vec![0x61, 0xff])),
    );

    let wire = encode(&model);
    for (name, raw) in [
        ("trailing", [wire.clone(), vec![0]].concat()),
        ("truncated", wire[..wire.len() - 1].to_vec()),
        (
            "nonminimal-map",
            [vec![0xb8, 5], wire[1..].to_vec()].concat(),
        ),
        (
            "indefinite-map",
            [vec![0xbf], wire[1..].to_vec(), vec![0xff]].concat(),
        ),
        ("tag", [vec![0xc0], wire.clone()].concat()),
    ] {
        add(name.into(), Value::Raw(raw));
    }
    let Value::Map(values) = model else {
        unreachable!()
    };
    let mut reversed = head(5, 5);
    for (key, value) in values.iter().rev() {
        reversed.extend_from_slice(&head(0, *key));
        reversed.extend_from_slice(&encode(value));
    }
    add("key-order".into(), Value::Raw(reversed));
    let mut duplicate = head(5, 5);
    for (key, value) in values {
        duplicate.extend_from_slice(&head(0, if key == 1 { 0 } else { key }));
        duplicate.extend_from_slice(&encode(&value));
    }
    add("duplicate-key".into(), Value::Raw(duplicate));
    wires
}

fn limit_wires() -> Vec<(String, Vec<u8>, CborError)> {
    let model = fields(3, 4, "gc/5/fence/7", 1);
    let mut wires = vec![(
        "limit-local-reconciliation-map-count".into(),
        head(5, MAX_UINT),
        CborError::Limit,
    )];
    for (name, path, major) in [
        ("authorization", vec![1], 2),
        ("fence-tuple", vec![2], 4),
        ("fence-key", vec![2, 0], 3),
        ("fence-digest", vec![2, 1], 2),
        ("exclusion-tuple", vec![3], 4),
        ("pack", vec![3, 0], 2),
        ("index", vec![4], 2),
    ] {
        wires.push((
            format!("limit-local-reconciliation-{name}"),
            encode(&changed(&model, &path, Value::Raw(head(major, MAX_UINT)))),
            CborError::Limit,
        ));
    }
    for (label, path, width) in [("authorization", vec![1], 32), ("pack", vec![3, 0], 16)] {
        wires.push((
            format!("limit-local-reconciliation-{label}-short-body"),
            encode(&changed(&model, &path, Value::Raw(head(2, width + 1)))),
            CborError::Limit,
        ));
    }
    let long_key = changed(&model, &[2, 0], text(&"x".repeat(4097)));
    wires.push((
        "limit-local-reconciliation-late-trailing".into(),
        [encode(&long_key), vec![0]].concat(),
        CborError::TrailingData,
    ));
    wires
}

/// Parses the unique bounded reference section into complete named wire fields.
///
/// # Panics
/// Panics for missing/duplicate sections, names or fields, or malformed hex.
fn reference() -> BTreeMap<String, Vec<u8>> {
    let document = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../tests/terrane/reconciliation-reference.md"
    ));
    assert_eq!(document.lines().filter(|line| *line == HEADING).count(), 1);
    let section = document
        .split_once(HEADING)
        .unwrap_or_else(|| panic!("missing section"))
        .1;
    let section = section
        .split("\n## ")
        .next()
        .unwrap_or_else(|| panic!("missing body"));
    let mut models = BTreeMap::new();
    for block in section.split("\n### ").skip(1) {
        let (name, fields) = block
            .split_once('\n')
            .unwrap_or_else(|| panic!("missing fields"));
        let wires: Vec<_> = fields
            .lines()
            .filter_map(|line| line.strip_prefix("wire = "))
            .collect();
        assert_eq!(wires.len(), 1);
        let wire = wires[0];
        assert_eq!(wire.len() % 2, 0);
        let bytes = wire
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let pair =
                    std::str::from_utf8(pair).unwrap_or_else(|error| panic!("hex UTF-8: {error}"));
                u8::from_str_radix(pair, 16).unwrap_or_else(|error| panic!("hex digit: {error}"))
            })
            .collect();
        assert!(models.insert(name.to_string(), bytes).is_none());
    }
    models
}

#[test]
fn reference_local_reconciliation_preserves_complete_fields() {
    let reference = reference();
    let models = positive_models();
    assert_eq!(models.len(), 12);
    assert_eq!(
        reference
            .keys()
            .filter(|name| name.starts_with("local-"))
            .count(),
        models.len()
    );

    for (name, fields, model) in models {
        let wire = encode(&fields);
        assert_eq!(reference[&name], wire, "{name}");
        let actual =
            LocalGcReconciliation::decode(&wire).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(actual, model, "{name}");
        assert_eq!(
            model
                .encode()
                .unwrap_or_else(|error| panic!("{name}: {error}")),
            wire,
            "{name}"
        );
    }
}

#[test]
fn reference_local_reconciliation_rejects_independent_malformed_wires() {
    let reference = reference();
    let wires = negative_wires();
    assert_eq!(wires.len(), 68);
    assert_eq!(
        reference
            .keys()
            .filter(|name| name.starts_with("bad-"))
            .count(),
        wires.len()
    );

    for (name, wire) in wires {
        assert_eq!(reference[&name], wire, "{name}");
        assert!(
            LocalGcReconciliation::decode(&wire).is_err(),
            "accepted {name}"
        );
    }
    for key in ["", "gc/01/fence/2", "gc/1/fence/+2", "other/1/fence/2"] {
        let invalid = model(3, 4, key, 1);
        assert_eq!(invalid.encode(), Err(PublicationError::Schema));
    }
}

#[test]
fn reference_local_reconciliation_applies_limits_before_retaining_fields() {
    let reference = reference();
    let wires = limit_wires();
    assert_eq!(wires.len(), 11);
    assert_eq!(
        reference
            .keys()
            .filter(|name| name.starts_with("limit-"))
            .count(),
        wires.len()
    );

    for (name, wire, error) in wires {
        assert_eq!(reference[&name], wire, "{name}");
        assert_eq!(
            LocalGcReconciliation::decode(&wire),
            Err(PublicationError::Cbor(error)),
            "{name}"
        );
    }
}
