//! Checks whole-Commit recipe schemas against independent primitive CBOR tables.
//!
//! These witnesses contain ordinary, unauthenticated data. Decoding a recipe,
//! disclosure label, or trust configuration does not authorize materialization.
//!
//! ```text
//! commit.profile-pair.recipe = {
//!   1: "graft", 2: [parent, target],
//!   3: {"at": h'746172676574', "entry": bstr({1: 4, 6: target}),
//!       "replace": false}
//! }
//! ```

#![allow(
    clippy::expect_used,
    reason = "malformed or changed independent fixture data must fail the test"
)]

use super::{Commit, CommitSource, PrincipalKind, ProfilePair, Provenance};
use crate::cbor;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

/// A primitive CBOR value independent of every owning record encoder.
#[derive(Clone)]
enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Self>),
    Map(Vec<(Self, Self)>),
    Bool(bool),
    Null,
    /// Supplies deliberately malformed bytes without an owning codec.
    Raw(Vec<u8>),
}

impl Value {
    fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        match self {
            Self::Uint(value) => cbor::write_uint(&mut output, *value),
            Self::Bytes(value) => cbor::write_bytes(&mut output, value),
            Self::Text(value) => cbor::write_text(&mut output, value),
            Self::Array(values) => {
                cbor::write_array(&mut output, values.len());
                for value in values {
                    output.extend_from_slice(&value.encode());
                }
            }
            Self::Map(values) => {
                let mut entries: Vec<_> = values
                    .iter()
                    .map(|(key, value)| (key.encode(), value.encode()))
                    .collect();
                entries.sort_by(|left, right| left.0.cmp(&right.0));

                cbor::write_map(&mut output, entries.len());
                for (key, value) in entries {
                    output.extend_from_slice(&key);
                    output.extend_from_slice(&value);
                }
            }
            Self::Bool(value) => output.push(if *value { 0xf5 } else { 0xf4 }),
            Self::Null => output.push(0xf6),
            Self::Raw(value) => output.extend_from_slice(value),
        }
        output
    }
}

fn text(value: &str) -> Value {
    Value::Text(value.to_string())
}

fn digest(value: u8) -> Value {
    Value::Bytes(vec![value; 32])
}

fn array(values: &[Value]) -> Value {
    Value::Array(values.to_vec())
}

fn map(values: &[(u64, Value)]) -> Value {
    Value::Map(
        values
            .iter()
            .map(|(key, value)| (Value::Uint(*key), value.clone()))
            .collect(),
    )
}

fn arguments(values: &[(&str, Value)]) -> Value {
    Value::Map(
        values
            .iter()
            .map(|(key, value)| (text(key), value.clone()))
            .collect(),
    )
}

fn recipe(operation: &str, roots: &[Value], fields: Option<Value>) -> Value {
    let mut values = vec![(1, text(operation)), (2, array(roots))];
    if let Some(fields) = fields {
        values.push((3, fields));
    }
    map(&values)
}

fn tree_entry(target: u8) -> Value {
    // TREE entries have no file mode; the root is the second graft operand.
    Value::Bytes(map(&[(1, Value::Uint(4)), (6, digest(target))]).encode())
}

fn graft_fields() -> Vec<(&'static str, Value)> {
    vec![
        ("at", Value::Bytes(b"target".to_vec())),
        ("entry", tree_entry(2)),
        ("replace", Value::Bool(false)),
    ]
}

fn domains() -> Value {
    array(&[
        array(&[digest(1), text("private:parent")]),
        array(&[digest(2), text("tenant:target")]),
    ])
}

fn policies(names: &[&str]) -> Value {
    Value::Array(names.iter().map(|name| text(name)).collect())
}

fn trust() -> Value {
    let selector = array(&[text("preset"), text("any")]);
    let context = |root: u8, domain: &str| {
        Value::Bytes(
            array(&[
                Value::Uint(1),
                digest(root),
                text(domain),
                Value::Bytes(selector.encode()),
                Value::Null,
                Value::Uint(0),
            ])
            .encode(),
        )
    };
    let configuration = array(&[
        array(&[context(2, "private:ours"), context(3, "tenant:theirs")]),
        Value::Null,
    ]);
    map(&[
        (1, selector),
        (2, text("terrane-verified-path/v1")),
        (3, configuration),
        (4, array(&[])),
    ])
}

fn model(recipe: Vec<u8>) -> Commit {
    Commit {
        tree: [1; 32],
        parents: vec![[2; 32], [3; 32]],
        provenance: Provenance {
            issuer: "fixture issuer".into(),
            token_id: [4; 16],
            subject: "fixture principal".into(),
            kind: PrincipalKind::Workload,
            workload_identity: None,
            process: "fixture process".into(),
            observed_at: 24,
            writer_epoch: 7,
            source: CommitSource::Derived,
            embedded_token: None,
        },
        timestamp: 24,
        message: "recipe field witness".into(),
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "cdc-1m".into(),
            recipe: Some(recipe),
            conflicted: None,
            lease: None,
            required_properties: None,
            entry_receipts: None,
            commit_context: None,
        },
        packs: None,
        signature: Some([5; 64]),
    }
}

fn commit_wire(recipe: Value, signed: bool) -> Vec<u8> {
    let provenance = map(&[
        (1, text("fixture issuer")),
        (2, Value::Bytes(vec![4; 16])),
        (3, text("fixture principal")),
        (4, Value::Uint(2)),
        (6, text("fixture process")),
        (7, Value::Uint(24)),
        (8, Value::Uint(7)),
        (9, Value::Uint(5)),
    ]);
    let mut fields = vec![
        (1, digest(1)),
        (2, array(&[digest(2), digest(3)])),
        (3, provenance),
        (4, Value::Uint(24)),
        (5, text("recipe field witness")),
        (
            6,
            map(&[(1, Value::Uint(1)), (2, text("cdc-1m")), (3, recipe)]),
        ),
    ];
    if signed {
        fields.push((8, Value::Bytes(vec![5; 64])));
    }
    map(&fields).encode()
}

fn positive_recipes() -> Vec<(String, Value)> {
    let roots = [digest(1), digest(2), digest(3)];
    let mut fixtures = vec![
        ("overlay-empty".into(), recipe("overlay", &[], None)),
        ("overlay-ordered".into(), recipe("overlay", &roots, None)),
        (
            "overlay-reversed".into(),
            recipe("overlay", &[digest(3), digest(2), digest(1)], None),
        ),
        (
            "overlay-domains".into(),
            recipe(
                "overlay",
                &roots,
                Some(arguments(&[("domains", domains())])),
            ),
        ),
    ];
    for replace in [false, true] {
        for with_domains in [false, true] {
            let mut fields = graft_fields();
            fields[2].1 = Value::Bool(replace);
            if with_domains {
                fields.push(("domains", domains()));
            }
            fixtures.push((
                format!("graft-replace-{replace}-domains-{with_domains}"),
                recipe("graft", &roots[..2], Some(arguments(&fields))),
            ));
        }
    }
    for (name, ordered, uses_trust) in [
        ("empty", vec![], false),
        (
            "ordinary",
            vec!["prefer-ours", "prefer-theirs", "keep-conflict", "error"],
            false,
        ),
        (
            "reversed",
            vec!["error", "keep-conflict", "prefer-theirs", "prefer-ours"],
            false,
        ),
        ("trusted", vec!["prefer-trusted", "keep-conflict"], true),
        ("newer", vec!["prefer-newer", "prefer-ours"], true),
        (
            "trusted-newer",
            vec!["prefer-trusted", "prefer-newer", "error"],
            true,
        ),
    ] {
        for with_domains in [false, true] {
            let mut fields = vec![("policy", policies(&ordered))];
            if uses_trust {
                fields.push(("trust", trust()));
            }
            if with_domains {
                fields.push(("domains", domains()));
            }
            fixtures.push((
                format!("merge-{name}-domains-{with_domains}"),
                recipe("merge", &roots, Some(arguments(&fields))),
            ));
        }
    }

    // Generic operation schemas retain canonical argument syntax, including
    // future argument data. No corresponding operation is executed here.
    for operation in [
        "split",
        "flatten",
        "filter",
        "map",
        "union",
        "difference",
        "intersection",
        "index",
        "realize",
    ] {
        fixtures.push((
            format!("{operation}-absent"),
            recipe(operation, &roots, None),
        ));
        fixtures.push((
            format!("{operation}-arguments"),
            recipe(
                operation,
                &roots,
                Some(arguments(&[
                    (
                        "future",
                        array(&[Value::Null, Value::Bool(true), digest(4)]),
                    ),
                    ("configuration", map(&[(1, text("inert"))])),
                ])),
            ),
        ));
    }
    fixtures
}

#[test]
fn commit_recipe_codec_preserves_registered_and_other_encodings() {
    let fixtures = positive_recipes();
    assert_eq!(fixtures.len(), 38);

    for (name, recipe) in fixtures {
        let expected = model(recipe.encode());
        let wire = commit_wire(recipe.clone(), true);
        let preimage = commit_wire(recipe, false);

        assert_eq!(expected.encode().expect("positive encode"), wire, "{name}");
        assert_eq!(
            Commit::decode(&wire).expect("positive decode"),
            expected,
            "{name}"
        );
        assert_eq!(
            expected.signature_preimage().expect("positive preimage"),
            preimage,
            "{name}"
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"terrane-commit-v1\0");
        hasher.update(&wire);
        let identity = *hasher.finalize().as_bytes();
        assert_eq!(
            expected.identity().expect("model identity"),
            identity,
            "{name}"
        );

        let mut unsigned = expected;
        unsigned.signature = None;
        assert_eq!(
            unsigned.encode().expect("unsigned encode"),
            preimage,
            "{name}"
        );
        assert_eq!(
            Commit::decode(&preimage).expect("unsigned decode"),
            unsigned,
            "{name}"
        );
    }
}

/// Reconstructs rejected inputs without using the rejecting format encoders.
///
/// # Panics
/// Panics if a table's ordinary arguments cease to be primitive map values.
fn negative_recipes() -> Vec<(String, Value)> {
    let roots = [digest(1), digest(2), digest(3)];
    let mut fixtures = Vec::new();
    for (operation, operands, ordinary) in [
        ("graft", &roots[..2], arguments(&graft_fields())),
        (
            "overlay",
            roots.as_slice(),
            arguments(&[("domains", domains())]),
        ),
        (
            "merge",
            roots.as_slice(),
            arguments(&[("policy", policies(&["keep-conflict"]))]),
        ),
    ] {
        for (name, malformed) in [
            ("null", Value::Null),
            ("boolean", Value::Bool(false)),
            ("array", array(&[])),
        ] {
            fixtures.push((
                format!("{operation}-nonmap-{name}"),
                recipe(operation, operands, Some(malformed)),
            ));
        }
        let Value::Map(mut fields) = ordinary.clone() else {
            unreachable!()
        };
        fields.push((text("unknown"), Value::Null));
        fixtures.push((
            format!("{operation}-unknown-argument"),
            recipe(operation, operands, Some(Value::Map(fields))),
        ));
        fixtures.push((
            format!("{operation}-empty-arguments"),
            recipe(operation, operands, Some(arguments(&[]))),
        ));

        for (name, bad_domains) in [
            ("null", Value::Null),
            (
                "unknown-kind",
                array(&[array(&[digest(1), text("unknown:owner")])]),
            ),
            (
                "empty-owner",
                array(&[array(&[digest(1), text("private:")])]),
            ),
            (
                "nontext-label",
                array(&[array(&[digest(1), Value::Uint(1)])]),
            ),
            (
                "short-root",
                array(&[array(&[Value::Bytes(vec![1; 31]), text("public")])]),
            ),
            (
                "extra-pair-field",
                array(&[array(&[digest(1), text("public"), Value::Null])]),
            ),
            (
                "duplicate-root",
                array(&[
                    array(&[digest(1), text("public")]),
                    array(&[digest(1), text("public")]),
                ]),
            ),
            (
                "unordered-roots",
                array(&[
                    array(&[digest(2), text("public")]),
                    array(&[digest(1), text("public")]),
                ]),
            ),
        ] {
            let Value::Map(mut fields) = ordinary.clone() else {
                unreachable!()
            };
            fields.retain(|(key, _)| !matches!(key, Value::Text(name) if name == "domains"));
            fields.push((text("domains"), bad_domains));
            fixtures.push((
                format!("{operation}-malformed-domains-{name}"),
                recipe(operation, operands, Some(Value::Map(fields))),
            ));
        }
    }

    for operation in ["graft", "merge"] {
        let operands = if operation == "graft" {
            &roots[..2]
        } else {
            roots.as_slice()
        };
        fixtures.push((
            format!("{operation}-missing-arguments"),
            recipe(operation, operands, None),
        ));
        for count in 0..=4 {
            if count == if operation == "graft" { 2 } else { 3 } {
                continue;
            }
            let operands = vec![digest(1); count];
            let fields = if operation == "graft" {
                arguments(&graft_fields())
            } else {
                arguments(&[("policy", policies(&[]))])
            };
            fixtures.push((
                format!("{operation}-operand-count-{count}"),
                recipe(operation, &operands, Some(fields)),
            ));
        }
    }

    for missing in ["at", "entry", "replace"] {
        let mut fields = graft_fields();
        fields.retain(|(key, _)| *key != missing);
        fixtures.push((
            format!("graft-missing-{missing}"),
            recipe("graft", &roots[..2], Some(arguments(&fields))),
        ));
    }
    for (name, field, value) in [
        ("text-path", "at", text("target")),
        ("empty-path", "at", Value::Bytes(vec![])),
        ("absolute-path", "at", Value::Bytes(b"/absolute".to_vec())),
        ("parent-path", "at", Value::Bytes(b"a/../b".to_vec())),
        ("null-entry", "entry", Value::Null),
        ("different-target", "entry", tree_entry(3)),
        (
            "tree-with-mode",
            "entry",
            Value::Bytes(
                map(&[(1, Value::Uint(4)), (2, Value::Uint(420)), (6, digest(2))]).encode(),
            ),
        ),
        (
            "file-instead-of-tree",
            "entry",
            Value::Bytes(
                map(&[
                    (1, Value::Uint(1)),
                    (2, Value::Uint(420)),
                    (3, Value::Uint(6)),
                    (4, array(&[Value::Uint(0), digest(2)])),
                ])
                .encode(),
            ),
        ),
        (
            "truncated-entry",
            "entry",
            Value::Bytes(vec![0xa2, 0x01, 0x04]),
        ),
        ("integer-replacement", "replace", Value::Uint(0)),
        ("null-replacement", "replace", Value::Null),
    ] {
        let mut fields = graft_fields();
        for (key, current) in &mut fields {
            if *key == field {
                *current = value.clone();
            }
        }
        fixtures.push((
            format!("graft-invalid-{name}"),
            recipe("graft", &roots[..2], Some(arguments(&fields))),
        ));
    }

    for (name, invalid) in [
        ("null", Value::Null),
        ("text", text("prefer-ours")),
        ("nontext-name", array(&[Value::Uint(1)])),
        ("unknown-name", policies(&["unknown"])),
    ] {
        fixtures.push((
            format!("merge-invalid-policy-{name}"),
            recipe("merge", &roots, Some(arguments(&[("policy", invalid)]))),
        ));
    }
    for policy in ["prefer-trusted", "prefer-newer"] {
        fixtures.push((
            format!("merge-{policy}-missing-trust"),
            recipe(
                "merge",
                &roots,
                Some(arguments(&[("policy", policies(&[policy]))])),
            ),
        ));
        for (name, invalid) in [
            ("null", Value::Null),
            ("empty-map", map(&[])),
            (
                "empty-version",
                map(&[
                    (1, array(&[text("preset"), text("any")])),
                    (2, text("")),
                    (3, Value::Null),
                    (4, array(&[])),
                ]),
            ),
        ] {
            fixtures.push((
                format!("merge-{policy}-malformed-trust-{name}"),
                recipe(
                    "merge",
                    &roots,
                    Some(arguments(&[
                        ("policy", policies(&[policy])),
                        ("trust", invalid),
                    ])),
                ),
            ));
        }
    }
    fixtures.push((
        "merge-unneeded-trust".into(),
        recipe(
            "merge",
            &roots,
            Some(arguments(&[
                ("policy", policies(&["prefer-ours"])),
                ("trust", trust()),
            ])),
        ),
    ));
    fixtures.push((
        "merge-missing-policy".into(),
        recipe("merge", &roots, Some(arguments(&[("trust", trust())]))),
    ));

    for (name, malformed) in [
        (
            "proved-graft-missing-inputs-and-arguments",
            recipe("graft", &[], None),
        ),
        (
            "proved-merge-empty-inputs-and-arguments",
            recipe("merge", &[], Some(arguments(&[]))),
        ),
        (
            "unknown-operation",
            recipe("future-operation", &roots, None),
        ),
        (
            "generic-nontext-key",
            recipe("map", &roots, Some(map(&[(1, Value::Null)]))),
        ),
        (
            "short-operand",
            recipe("overlay", &[Value::Bytes(vec![1; 31])], None),
        ),
        (
            "long-operand",
            recipe("overlay", &[Value::Bytes(vec![1; 33])], None),
        ),
        (
            "huge-missing-operands",
            Value::Raw(vec![
                0xa2, 1, 0x67, b'o', b'v', b'e', b'r', b'l', b'a', b'y', 2, 0x9b, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff,
            ]),
        ),
        (
            "nonminimal-recipe-count",
            Value::Raw(vec![
                0xb8, 2, 1, 0x67, b'o', b'v', b'e', b'r', b'l', b'a', b'y', 2, 0x80,
            ]),
        ),
        (
            "truncated-arguments",
            Value::Raw(vec![
                0xa3, 1, 0x65, b'g', b'r', b'a', b'f', b't', 2, 0x80, 3, 0xa1,
            ]),
        ),
    ] {
        fixtures.push((name.into(), malformed));
    }
    fixtures
}

#[test]
fn commit_recipe_codec_rejects_invalid_registered_arguments() {
    let fixtures = negative_recipes();
    assert_eq!(fixtures.len(), 86);

    for (name, recipe) in fixtures {
        // The wire never passes through Commit::encode or Recipe::encode.
        let wire = commit_wire(recipe.clone(), true);
        assert!(
            Commit::decode(&wire).is_err(),
            "accepted independently assembled {name}"
        );

        let unsigned_wire = commit_wire(recipe.clone(), false);
        assert!(
            Commit::decode(&unsigned_wire).is_err(),
            "accepted independently assembled unsigned {name}"
        );

        let invalid = model(recipe.encode());
        assert!(invalid.encode().is_err(), "encoded {name}");
        assert!(
            invalid.signature_preimage().is_err(),
            "preimage accepted {name}"
        );
        assert!(invalid.identity().is_err(), "identity accepted {name}");
    }
}
