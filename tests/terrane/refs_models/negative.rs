//! Reconstructs structural failures through independent primitive CBOR.
//!
//! Each complete negative starts from a handwritten field table. No owning
//! encoder supplies malformed input or a supposedly trusted token assertion.

use super::{
    fields,
    support::{Value, a, b, encode, m, n, remove, repeated, set, t, texts},
};

/// Carries one independently assembled input requiring structural decoder rejection.
pub(crate) struct Negative {
    /// Unique witness name used to locate its reference block.
    pub(crate) name: String,
    /// Owning decoder family: commit, ref or log.
    pub(crate) family: &'static str,
    /// Complete malformed wire reconstructed with independent primitives.
    pub(crate) wire: Vec<u8>,
}

fn add(values: &mut Vec<Negative>, name: &str, family: &'static str, fields: Value) {
    values.push(Negative {
        name: name.into(),
        family,
        wire: encode(&fields),
    });
}

fn changed(
    values: &mut Vec<Negative>,
    name: &str,
    family: &'static str,
    mut fields: Value,
    path: &[u64],
    replacement: Value,
) {
    set(&mut fields, path, replacement);
    add(values, name, family, fields);
}

/// Constructs all negative wires from primitive fields rather than owning record encoders.
///
/// # Panics
/// Panics if a handwritten table no longer supports its required field paths.
pub(crate) fn models() -> Vec<Negative> {
    let mut values = Vec::new();
    for key in 1..=6 {
        let mut fields = fields::commit(2, 1);
        remove(&mut fields, key);
        add(
            &mut values,
            &format!("bad-commit-missing-{key}"),
            "commit",
            fields,
        );
    }
    for (name, path, replacement) in [
        ("tree-width", vec![1], repeated(1, 31)),
        ("parent-width", vec![2], a(vec![repeated(1, 33)])),
        ("parents-limit", vec![2], a(vec![repeated(1, 32); 257])),
        ("principal", vec![3, 4], n(0)),
        ("source", vec![3, 9], n(7)),
        ("token-id-width", vec![3, 2], repeated(2, 15)),
        ("workload-type", vec![3, 5], Value::Null),
        ("tree-format", vec![6, 1], n(2)),
        ("profile-empty", vec![6, 2], t("")),
        (
            "recipe-operation",
            vec![6, 3],
            m(vec![(1, t("unknown")), (2, a(vec![]))]),
        ),
        ("conflicted-type", vec![6, 4], n(0)),
        ("lease-missing", vec![6, 5], m(vec![(1, t("job"))])),
        (
            "property-null",
            vec![6, 6],
            texts(vec![("retain", Value::Null)]),
        ),
        (
            "property-key",
            vec![6, 6],
            texts(vec![("", Value::Bool(true))]),
        ),
        ("packs-empty", vec![7], a(vec![])),
        (
            "pack-width",
            vec![7],
            a(vec![a(vec![repeated(1, 15), m(vec![])])]),
        ),
        ("signature-width", vec![8], repeated(1, 63)),
        ("unknown", vec![9], n(0)),
    ] {
        changed(
            &mut values,
            &format!("bad-commit-{name}"),
            "commit",
            fields::commit(2, 1),
            &path,
            replacement,
        );
    }
    for (name, key, replacement) in [
        ("ref", 1, t("refs/unknown/_/main")),
        ("surface", 2, t("unknown")),
        ("empty", 4, a(vec![])),
        ("relative", 4, a(vec![a(vec![b(b"relative"), t("public")])])),
        ("duplicate", 4, a(vec![a(vec![b(b"/"), t("public")]); 2])),
        (
            "order",
            4,
            a(vec![
                a(vec![b(b"/z"), t("public")]),
                a(vec![b(b"/aa"), t("private:fixture")]),
                a(vec![b(b"/"), t("public")]),
            ]),
        ),
    ] {
        let mut context = fields::context();
        set(&mut context, &[key], replacement);
        changed(
            &mut values,
            &format!("bad-context-{name}"),
            "commit",
            fields::commit(2, 1),
            &[6, 8],
            context,
        );
    }
    let mut reversed = fields::receipts();
    if let Value::Array(rows) = &mut reversed {
        rows.reverse();
    }
    for (name, rows) in [
        (
            "empty-path",
            a(vec![a(vec![repeated(1, 32), b(b""), n(0)])]),
        ),
        ("origin", a(vec![a(vec![repeated(1, 32), b(b"a"), n(1)])])),
        (
            "four-null",
            a(vec![a(vec![repeated(1, 32), b(b"a"), n(0), Value::Null])]),
        ),
        (
            "source-reintro",
            a(vec![a(vec![
                repeated(1, 32),
                b(b"a"),
                fields::source(),
                Value::Null,
                fields::source(),
            ])]),
        ),
        (
            "duplicate",
            a(vec![a(vec![repeated(1, 32), b(b"a"), n(0)]); 2]),
        ),
        ("order", reversed),
        (
            "attribute-empty",
            a(vec![a(vec![
                repeated(1, 32),
                b(b"a"),
                n(0),
                texts(vec![("", n(0))]),
            ])]),
        ),
    ] {
        changed(
            &mut values,
            &format!("bad-receipt-{name}"),
            "commit",
            fields::commit(2, 1),
            &[6, 7],
            rows,
        );
    }
    let mut proof = fields::proof();
    set(&mut proof, &[1], t(&"AB".repeat(32)));
    let receipt = a(vec![
        repeated(1, 32),
        b(b"h"),
        n(0),
        texts(vec![("z", fields::source())]),
        fields::source(),
        proof,
    ]);
    changed(
        &mut values,
        "bad-proof-key",
        "commit",
        fields::commit(2, 1),
        &[6, 7],
        a(vec![receipt]),
    );

    let mut excessive_blocks = vec![fields::authority(false)];
    excessive_blocks.extend(vec![
        m(vec![(5, repeated(10, 32)), (6, repeated(11, 64))]);
        16
    ]);
    for (name, token) in [
        ("empty", a(vec![])),
        ("missing", a(vec![m(vec![])])),
        ("limit", a(excessive_blocks)),
    ] {
        changed(
            &mut values,
            &format!("bad-token-{name}"),
            "commit",
            fields::commit(2, 1),
            &[3, 10],
            token,
        );
    }
    for (key, replacement) in [
        (4, n(4)),
        (8, repeated(2, 17)),
        (9, a(vec![])),
        (11, repeated(8, 31)),
        (12, repeated(9, 65)),
        (13, n(0)),
    ] {
        let mut authority = fields::authority(false);
        set(&mut authority, &[key], replacement);
        changed(
            &mut values,
            &format!("bad-token-authority-{key}"),
            "commit",
            fields::commit(2, 1),
            &[3, 10],
            a(vec![authority]),
        );
    }
    for (key, replacement) in [
        (4, a(vec![a(vec![t("unknown"), n(0)])])),
        (3, a(vec![])),
        (5, repeated(10, 31)),
        (7, n(0)),
    ] {
        let mut attenuation = fields::attenuation();
        set(&mut attenuation, &[key], replacement);
        changed(
            &mut values,
            &format!("bad-token-attenuation-{key}"),
            "commit",
            fields::commit(2, 1),
            &[3, 10],
            a(vec![fields::authority(true), attenuation]),
        );
    }
    for (name, path, replacement) in [
        ("seq-zero", vec![2], n(0)),
        ("commit-width", vec![1], repeated(1, 31)),
        ("candidate-width", vec![6], repeated(15, 31)),
        ("unknown", vec![7], n(0)),
        ("locality-key", vec![4], m(vec![(4, t("host"))])),
        ("policy-bool", vec![5], m(vec![(1, Value::Null)])),
        ("policy-empty-merges", vec![5], m(vec![(2, a(vec![]))])),
        ("policy-merge", vec![5], m(vec![(2, a(vec![t("unknown")]))])),
        ("policy-retain", vec![5], m(vec![(3, t("unknown"))])),
        ("policy-ttl", vec![5], m(vec![(3, a(vec![t("ttl")]))])),
        ("policy-unknown", vec![5], m(vec![(6, n(0))])),
    ] {
        changed(
            &mut values,
            &format!("bad-ref-{name}"),
            "ref",
            fields::record(1, false),
            &path,
            replacement,
        );
    }
    for (name, key, replacement) in [
        ("tag", 1, t("refs/heads/_/main")),
        ("commit", 2, repeated(1, 31)),
        ("attestation", 3, m(vec![(1, Value::Bool(true))])),
        ("signature", 5, repeated(14, 63)),
    ] {
        let mut annotation = fields::envelope();
        set(&mut annotation, &[key], replacement);
        changed(
            &mut values,
            &format!("bad-envelope-{name}"),
            "ref",
            fields::record(1, false),
            &[5],
            m(vec![(5, annotation)]),
        );
    }
    let mut fault = |name: &str, mode: &str, path: &[u64], replacement| {
        changed(
            &mut values,
            &format!("bad-log-{name}"),
            "log",
            fields::log("commit", mode),
            path,
            replacement,
        );
    };
    fault("reason", "legacy", &[4], t("unknown"));
    fault(
        "selected-no-expectation",
        "legacy",
        &[1],
        fields::record(2, true),
    );
    fault("previous-mismatch", "expected", &[2], repeated(99, 32));
    fault("fresh-sequence", "fresh", &[1], fields::record(2, true));
    fault(
        "retained-with-expectation",
        "expected",
        &[7],
        fields::record(1, true),
    );
    fault("retained-legacy", "legacy", &[7], fields::record(1, false));
    fault("epoch-regression", "expected", &[1, 3], n(6));
    fault("home-changed", "expected", &[1, 4], m(vec![]));
    fault("unknown", "legacy", &[8], n(0));

    for (family, fields) in [
        ("commit", fields::commit(2, 1)),
        ("ref", fields::record(1, false)),
        ("log", fields::log("commit", "legacy")),
    ] {
        let wire = encode(&fields);
        if let Value::Map(pairs) = &fields {
            let mut reversed_wire = vec![wire[0]];
            for (key, value) in pairs.iter().rev() {
                reversed_wire.extend_from_slice(&encode(key));
                reversed_wire.extend_from_slice(&encode(value));
            }
            let mut duplicate_wire = vec![wire[0]];
            for (index, (key, value)) in pairs.iter().enumerate() {
                duplicate_wire.extend_from_slice(&encode(if index == 1 {
                    &pairs[0].0
                } else {
                    key
                }));
                duplicate_wire.extend_from_slice(&encode(value));
            }
            values.push(Negative {
                name: format!("bad-{family}-key-order"),
                family,
                wire: reversed_wire,
            });
            values.push(Negative {
                name: format!("bad-{family}-duplicate-key"),
                family,
                wire: duplicate_wire,
            });
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        let mut indefinite = vec![0xbf];
        indefinite.extend_from_slice(&wire[1..]);
        indefinite.push(0xff);
        let mut nonminimal = vec![wire[0], 0x18, 1];
        nonminimal.extend_from_slice(&wire[2..]);
        for (suffix, bytes) in [
            ("truncated", wire[..wire.len() - 1].to_vec()),
            ("trailing", trailing),
            ("indefinite", indefinite),
            ("nonminimal", nonminimal),
            (
                "claimed-count",
                vec![0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ] {
            values.push(Negative {
                name: format!("bad-{family}-{suffix}"),
                family,
                wire: bytes,
            });
        }
    }
    values
}
