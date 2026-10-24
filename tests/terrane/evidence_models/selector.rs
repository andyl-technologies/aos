//! Compares selector wires with independently constructed complete AST arenas.
//!
//! Preset properties normalize to AST bytes. Parsing establishes syntax only;
//! these fixtures never evaluate provenance or construct a verified history.
//!
//! ```text
//! ["all", [["issuer", "issuer-a"], ["not", ["group", "blocked"]]]]
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "complete bounded fixture assertions"
)]

#[allow(
    clippy::duplicate_mod,
    reason = "isolated private consumer modules share the primitive fixture oracle"
)]
#[path = "support.rs"]
mod support;

use super::*;
use Value::{Array, UInt};
use alloc::{format, vec};
use support::{Value, bytes, compare, reference, text};

fn atom(name: &str, argument: &str) -> Value {
    Array(vec![text(name), text(argument)])
}

fn check(name: &str, primitive: Value, nodes: Vec<Node>, root: usize) {
    let published = compare(name, &primitive);
    let expected = Selector {
        nodes,
        root,
        bytes: primitive.encode(),
    };
    let actual = Selector::decode(&published).unwrap();

    assert_eq!(actual, expected, "complete AST/arena/root/bytes: {name}");
    assert_eq!(
        expected.encode(),
        published,
        "cached canonical bytes: {name}"
    );
    assert_eq!(actual.encode(), published);
    for cut in 0..published.len() {
        assert!(
            Selector::decode(&published[..cut]).is_err(),
            "truncated {name}: {cut}"
        );
    }
    let mut trailing = published;
    trailing.push(0);
    assert!(Selector::decode(&trailing).is_err(), "trailing {name}");
}

#[test]
fn reference_selector_models_preserve_complete_ast() {
    for (name, primitive, node) in [
        (
            "selector-issuer",
            atom("issuer", "issuer-a"),
            Node::Issuer("issuer-a".into()),
        ),
        (
            "selector-subject",
            atom("subject", "user:*"),
            Node::Subject(SubjectPattern::new("user:*".into())),
        ),
        (
            "selector-group",
            atom("group", "baseline"),
            Node::Group("baseline".into()),
        ),
        (
            "selector-signed-by-key",
            atom("signed-by-key", &"12".repeat(32)),
            Node::SignedByKey([0x12; 32]),
        ),
    ] {
        check(name, primitive, vec![node], 0);
    }
    for (label, kind) in [
        ("human", PrincipalKind::Human),
        ("workload", PrincipalKind::Workload),
        ("service", PrincipalKind::Service),
    ] {
        check(
            &format!("selector-kind-{label}"),
            atom("kind", label),
            vec![Node::Kind(kind)],
            0,
        );
    }
    for (label, source) in [
        ("built", CommitSource::Built),
        ("uploaded", CommitSource::Uploaded),
        ("imported", CommitSource::Imported),
        ("merged", CommitSource::Merged),
        ("derived", CommitSource::Derived),
        ("migrated", CommitSource::Migrated),
    ] {
        check(
            &format!("selector-source-{label}"),
            atom("source", label),
            vec![Node::Source(source)],
            0,
        );
    }
    for (label, preset) in [
        ("any", Preset::Any),
        ("signed-baseline", Preset::SignedBaseline),
        ("strict", Preset::Strict),
        ("attested", Preset::Attested),
    ] {
        check(
            &format!("selector-preset-{label}"),
            atom("preset", label),
            vec![Node::Preset(preset)],
            0,
        );
        let property = compare(&format!("selector-property-{label}"), &text(label));
        let expected = Selector {
            nodes: vec![Node::Preset(preset)],
            root: 0,
            bytes: atom("preset", label).encode(),
        };
        assert_eq!(Selector::from_property(&property).unwrap(), expected);
        assert_eq!(Selector::preset(preset), expected);
        assert_eq!(
            Selector::from_property(expected.encode()).unwrap(),
            expected
        );
    }

    check(
        "selector-accepted-by",
        Array(vec![text("accepted-by"), atom("group", "baseline")]),
        vec![Node::Group("baseline".into()), Node::AcceptedBy(0)],
        1,
    );
    check(
        "selector-attr-by",
        Array(vec![
            text("attr-by"),
            text("hash.sha256"),
            atom("kind", "workload"),
        ]),
        vec![
            Node::Kind(PrincipalKind::Workload),
            Node::AttributeBy("hash.sha256".into(), 0),
        ],
        1,
    );
    check(
        "selector-not",
        Array(vec![text("not"), atom("source", "imported")]),
        vec![Node::Source(CommitSource::Imported), Node::Not(0)],
        1,
    );
    check(
        "selector-all-nested",
        Array(vec![
            text("all"),
            Array(vec![
                atom("issuer", "issuer-a"),
                Array(vec![
                    text("any"),
                    Array(vec![atom("kind", "human"), atom("subject", "user:*")]),
                ]),
                Array(vec![text("not"), atom("group", "blocked")]),
            ]),
        ]),
        vec![
            Node::Issuer("issuer-a".into()),
            Node::Kind(PrincipalKind::Human),
            Node::Subject(SubjectPattern::new("user:*".into())),
            Node::Any(vec![1, 2]),
            Node::Group("blocked".into()),
            Node::Not(4),
            Node::All(vec![0, 3, 5]),
        ],
        6,
    );
    check(
        "selector-any-nested",
        Array(vec![
            text("any"),
            Array(vec![
                atom("preset", "any"),
                Array(vec![text("accepted-by"), atom("group", "baseline")]),
            ]),
        ]),
        vec![
            Node::Preset(Preset::Any),
            Node::Group("baseline".into()),
            Node::AcceptedBy(1),
            Node::Any(vec![0, 2]),
        ],
        3,
    );

    let invalid = [
        ("unknown-atom", atom("other", "value")),
        ("unregistered-attestation", atom("attested", "claim")),
        ("unknown-kind", atom("kind", "other")),
        ("unknown-source", atom("source", "other")),
        ("uppercase-key", atom("signed-by-key", &"AB".repeat(32))),
        ("short-key", atom("signed-by-key", "12")),
        ("unknown-preset", atom("preset", "other")),
        ("empty-all", Array(vec![text("all"), Array(vec![])])),
        ("empty-any", Array(vec![text("any"), Array(vec![])])),
        (
            "unknown-attribute",
            Array(vec![text("attr-by"), text("other"), atom("preset", "any")]),
        ),
        (
            "wrong-arity",
            Array(vec![text("issuer"), text("a"), text("b")]),
        ),
        ("wrong-argument", Array(vec![text("issuer"), UInt(1)])),
    ];
    for (label, model) in invalid {
        let name = format!("selector-negative-{label}");
        let published = compare(&name, &model);
        assert!(Selector::decode(&published).is_err(), "{name}");
    }
    let canonical = atom("preset", "any").encode();
    let mut nonminimal = vec![0x98, 2];
    nonminimal.extend(&canonical[1..]);
    let mut trailing = canonical.clone();
    trailing.push(0);
    let mut huge = vec![0x9b];
    huge.extend([0xff; 8]);
    for (label, primitive) in [
        ("nonminimal", nonminimal),
        ("trailing", trailing),
        ("truncated", canonical[..canonical.len() - 1].to_vec()),
        ("huge-count", huge),
    ] {
        let name = format!("selector-negative-{label}");
        assert_eq!(primitive, reference(&name));
        assert_eq!(Selector::decode(&primitive), Err(SelectorError), "{name}");
    }
    // Invalid property representations are primitive inputs, never presets
    // created by a trusted context or evidence holder.
    assert!(Selector::from_property(&bytes([0]).encode()).is_err());
}
