//! Complete inert numbered field tables for nested commit and ref models.
//!
//! These primitive tables are separate from the public Rust model construction.
//! All embedded claims and signatures remain unverified ordinary bytes.

use super::support::{Value, a, b, m, n, repeated, t, texts};

/// Lists every registered recipe operation represented by the fixtures.
pub(crate) const OPERATIONS: [&str; 12] = [
    "graft",
    "split",
    "flatten",
    "overlay",
    "merge",
    "filter",
    "map",
    "union",
    "difference",
    "intersection",
    "index",
    "realize",
];
/// Lists the closed reflog reason vocabulary in fixture order.
pub(crate) const REASONS: [&str; 6] = [
    "commit",
    "merge",
    "fold",
    "rollback",
    "job-checkpoint",
    "migrate",
];
/// Lists every registered ref merge policy in fixture order.
pub(crate) const POLICIES: [&str; 6] = [
    "prefer-ours",
    "prefer-theirs",
    "prefer-trusted",
    "prefer-newer",
    "keep-conflict",
    "error",
];

/// Constructs all three optional locality fields as inert labels.
pub(crate) fn locality() -> Value {
    m(vec![(1, t("region")), (2, t("zone")), (3, t("host"))])
}

/// Constructs an opaque source entry reference without resolving it.
pub(crate) fn source() -> Value {
    a(vec![repeated(3, 32), repeated(4, 32), b(b"source\xff")])
}

/// Constructs every disclosure-certificate field without checking its signature.
pub(crate) fn proof() -> Value {
    m(vec![
        (1, t(&"ab".repeat(32))),
        (2, t("private:source")),
        (3, n(42)),
        (4, repeated(7, 64)),
    ])
}

/// Constructs all receipt shapes with distinct absent and empty attribute maps.
pub(crate) fn receipts() -> Value {
    let root = || repeated(1, 32);
    a(vec![
        a(vec![root(), b(b"a"), n(0)]),
        a(vec![root(), b(b"b"), source()]),
        a(vec![root(), b(b"c"), n(0), texts(vec![])]),
        a(vec![
            root(),
            b(b"d"),
            source(),
            texts(vec![("z", n(0)), ("aa", source())]),
        ]),
        a(vec![root(), b(b"e"), n(0), Value::Null, source()]),
        a(vec![root(), b(b"f"), n(0), texts(vec![]), source()]),
        a(vec![root(), b(b"g"), n(0), Value::Null, source(), proof()]),
        a(vec![
            root(),
            b(b"h"),
            n(0),
            texts(vec![("z", source())]),
            source(),
            proof(),
        ]),
    ])
}

/// Constructs sorted scope assertions without establishing their truth.
pub(crate) fn context() -> Value {
    m(vec![
        (1, t("refs/heads/_/main")),
        (2, t("sdk")),
        (3, locality()),
        (
            4,
            a(vec![
                a(vec![b(b"/"), t("public")]),
                a(vec![b(b"/aa"), t("private:fixture")]),
                a(vec![b(b"/z"), t("public")]),
            ]),
        ),
    ])
}

/// Constructs the required token block fields and optional claims when requested.
pub(crate) fn authority(full: bool) -> Value {
    let mut fields = vec![
        (1, t("issuer")),
        (2, t("key")),
        (3, t("subject")),
        (4, n(2)),
        (
            5,
            a(if full {
                vec![t("builders"), t("readers")]
            } else {
                vec![]
            }),
        ),
        (6, n(99)),
        (8, repeated(2, 16)),
        (9, a(vec![a(vec![t("refs/heads/_/main"), n(5)])])),
        (11, repeated(8, 32)),
        (12, repeated(9, 64)),
    ];
    if full {
        fields.extend([(7, n(1)), (10, t("workload"))]);
    }
    m(fields)
}

/// Constructs every attenuation field and registered caveat alternative.
pub(crate) fn attenuation() -> Value {
    m(vec![
        (1, n(90)),
        (2, n(2)),
        (3, a(vec![a(vec![t("refs/heads/_/main"), n(1)])])),
        (
            4,
            a(vec![
                a(vec![t("before"), n(90)]),
                a(vec![t("after"), n(2)]),
                a(vec![t("ref"), t("refs/heads/_/main")]),
                a(vec![t("root"), t("/aa")]),
                a(vec![t("verb"), n(1)]),
                a(vec![t("domain"), t("public")]),
                a(vec![t("surface"), t("sdk")]),
                a(vec![t("locality"), locality()]),
                a(vec![t("epoch"), t("refs/heads/_/main"), n(7)]),
            ]),
        ),
        (5, repeated(10, 32)),
        (6, repeated(11, 64)),
    ])
}

/// Constructs an opaque canonical public token chain without verification.
pub(crate) fn token(full: bool) -> Value {
    a(if full {
        vec![authority(true), attenuation()]
    } else {
        vec![authority(false)]
    })
}

/// Constructs operation-specific recipe fields, including the complete graft tree entry.
pub(crate) fn recipe(operation: &str) -> Value {
    let mut fields = vec![
        (1, t(operation)),
        (2, a(vec![repeated(1, 32), repeated(2, 32)])),
    ];
    if operation == "graft" {
        let entry = m(vec![(1, n(4)), (6, repeated(2, 32))]);
        fields.push((
            3,
            texts(vec![
                ("at", b(b"target")),
                ("entry", b(&super::support::encode(&entry))),
                ("replace", Value::Bool(false)),
            ]),
        ));
    } else if operation == "merge" {
        fields[1].1 = a(vec![repeated(1, 32), repeated(2, 32), repeated(3, 32)]);
        fields.push((
            3,
            texts(vec![("policy", a(vec![t("prefer-ours"), t("error")]))]),
        ));
    }
    m(fields)
}

/// Constructs the required commit fields with absent optional map keys.
pub(crate) fn commit(kind: u64, production: u64) -> Value {
    m(vec![
        (1, repeated(1, 32)),
        (2, a(vec![])),
        (
            3,
            m(vec![
                (1, t("issuer")),
                (2, repeated(2, 16)),
                (3, t("subject")),
                (4, n(kind)),
                (6, t("fixture process")),
                (7, n(24)),
                (8, n(7)),
                (9, n(production)),
            ]),
        ),
        (4, n(24)),
        (5, t("")),
        (6, m(vec![(1, n(1)), (2, t("cdc-1m"))])),
    ])
}

/// Constructs complete inert tag annotation and nested attestation fields.
pub(crate) fn envelope() -> Value {
    m(vec![
        (1, t("refs/tags/_/snapshot")),
        (2, repeated(1, 32)),
        (
            3,
            texts(vec![
                (
                    "a",
                    a(vec![n(0), Value::Bool(true), Value::Null, repeated(13, 3)]),
                ),
                ("zz", texts(vec![("x", t("value"))])),
            ]),
        ),
        (4, t(&"cd".repeat(32))),
        (5, repeated(14, 64)),
    ])
}

/// Constructs a mutable ref value with an optional opaque candidate selector.
pub(crate) fn record(seq: u8, selected: bool) -> Value {
    let mut fields = vec![
        (1, repeated(seq, 32)),
        (2, n(u64::from(seq))),
        (3, n(7)),
        (4, locality()),
    ];
    if selected {
        fields.push((6, repeated(15, 32)));
    }
    m(fields)
}

/// Constructs legacy, selected and retained-predecessor reflog field alternatives.
pub(crate) fn log(reason: &str, mode: &str) -> Value {
    let mut fields = vec![
        (1, record(2, mode != "legacy")),
        (2, repeated(1, 32)),
        (3, t("subject")),
        (4, t(reason)),
        (5, n(24)),
    ];
    match mode {
        "fresh" => {
            fields[0].1 = record(1, true);
            fields[1].1 = Value::Null;
            fields.push((6, Value::Null));
        }
        "expected" => fields.push((6, record(1, true))),
        "retained" => fields.extend([(6, Value::Null), (7, record(1, true))]),
        _ => {}
    }
    m(fields)
}
