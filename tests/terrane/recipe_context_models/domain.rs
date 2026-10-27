//! Compares complete unauthenticated domain models inside enclosing recipes.
//!
//! Private field access belongs only to this test child of the owning module.
//! ```text
//! domains = [[root-digest32, domain-label], ...] ; root-sorted and unique
//! ```

#[path = "domain_primitives.rs"]
mod primitives;

use super::OperationDomains;
use crate::algebra::Recipe;
use alloc::collections::BTreeMap;
use alloc::vec;
use primitives::{Value, digest, encode, negative, positive, present, recipe, required, text};

fn rows(values: &[(u8, &str)]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|(root, label)| Value::Array(vec![digest(*root), text(label)]))
            .collect(),
    )
}

fn overlay(domains: Value) -> Value {
    recipe(
        "overlay",
        vec![digest(1), digest(2), digest(3)],
        Value::Map(vec![(text("domains"), domains)]),
    )
}

fn model(values: &[(u8, &str)]) -> OperationDomains {
    let labels: BTreeMap<_, _> = values
        .iter()
        .map(|(root, label)| ([*root; 32], encode(&text(label))))
        .collect();
    OperationDomains {
        labels,
        authenticated: false,
    }
}

fn compare(actual: &OperationDomains, expected: &OperationDomains) {
    assert_eq!(actual.labels, expected.labels);
    assert!(!actual.authenticated);
    assert!(!expected.authenticated);
    assert_eq!(actual, expected);
}

#[test]
fn reference_recipe_domains_preserve_nonempty_fields() {
    let roots = [[1; 32], [2; 32], [3; 32]];
    for (index, label) in [
        "public",
        "tenant:tenant-a",
        "group:editors",
        "private:owner",
    ]
    .into_iter()
    .enumerate()
    {
        let fields = [(1, label)];
        let expected = model(&fields);
        let recipe = Recipe::OverlayWithDomains {
            roots: &roots,
            domains: &expected,
        };
        let name = alloc::format!("recipe-domain-{index}");
        let wire = positive(&name, &overlay(rows(&fields)), &recipe);
        let owned = required(Recipe::decode(&wire), "complete overlay");
        let Recipe::OverlayWithDomains {
            roots: decoded_roots,
            domains,
        } = owned.as_recipe()
        else {
            panic!("domain-bearing overlay")
        };
        assert_eq!(decoded_roots, roots);
        compare(domains, &expected);
        assert_eq!(owned.as_recipe().encode(), wire);
    }

    let fields = [(1, "public"), (2, "private:owner"), (3, "group:editors")];
    let expected = model(&fields);
    let recipe = Recipe::OverlayWithDomains {
        roots: &roots,
        domains: &expected,
    };
    let wire = positive("recipe-domain-multiple", &overlay(rows(&fields)), &recipe);
    let owned = required(Recipe::decode(&wire), "multiple domain pairs");
    let Recipe::OverlayWithDomains {
        roots: actual,
        domains,
    } = owned.as_recipe()
    else {
        panic!("overlay")
    };
    assert_eq!(actual, roots);
    compare(domains, &expected);

    let graft_fields = &fields[..2];
    let expected = model(graft_fields);
    let entry = encode(&Value::Map(vec![
        (Value::UInt(1), Value::UInt(4)),
        (Value::UInt(6), digest(2)),
    ]));
    let fields = recipe_fields_graft(rows(graft_fields), &entry);
    let recipe = Recipe::Graft {
        parent: roots[0],
        target: roots[1],
        at: b"mount/child",
        entry: &entry,
        replace: true,
        domains: Some(&expected),
    };
    let wire = positive("recipe-domain-graft", &fields, &recipe);
    let owned = required(Recipe::decode(&wire), "complete graft");
    let Recipe::Graft {
        parent,
        target,
        at,
        entry: actual_entry,
        replace,
        domains,
    } = owned.as_recipe()
    else {
        panic!("graft")
    };
    assert_eq!((parent, target), (roots[0], roots[1]));
    assert_eq!(at, b"mount/child");
    assert_eq!(actual_entry, entry);
    assert!(replace);
    compare(present(domains, "present labels"), &expected);
    assert_eq!(owned.as_recipe().encode(), wire);
}

fn recipe_fields_graft(domains: Value, entry: &[u8]) -> Value {
    recipe(
        "graft",
        vec![digest(1), digest(2)],
        Value::Map(vec![
            (text("at"), Value::Bytes(b"mount/child".to_vec())),
            (text("entry"), Value::Bytes(entry.to_vec())),
            (text("replace"), Value::Bool(true)),
            (text("domains"), domains),
        ]),
    )
}

#[test]
fn reference_recipe_domain_negatives_require_structural_rejection() {
    let pair = |root: Value, label: Value| Value::Array(vec![root, label]);
    let mut cases = vec![
        (
            "short-digest",
            vec![pair(Value::Bytes(vec![b'x'; 31]), text("public"))],
        ),
        (
            "long-digest",
            vec![pair(Value::Bytes(vec![b'x'; 33]), text("public"))],
        ),
        ("digest-type", vec![pair(Value::UInt(1), text("public"))]),
        (
            "label-type",
            vec![pair(digest(1), Value::Bytes(b"public".to_vec()))],
        ),
        ("short-pair", vec![Value::Array(vec![digest(1)])]),
        (
            "long-pair",
            vec![Value::Array(vec![digest(1), text("public"), Value::Null])],
        ),
        ("duplicate", vec![pair(digest(1), text("public")); 2]),
        (
            "reversed",
            vec![
                pair(digest(2), text("public")),
                pair(digest(1), text("public")),
            ],
        ),
    ];
    for (name, label) in [
        ("grammar-8", "unknown"),
        ("grammar-9", "tenant:"),
        ("grammar-10", "group:"),
        ("grammar-11", "private:"),
        ("grammar-12", "public:owner"),
        ("grammar-13", ""),
    ] {
        cases.push((name, vec![pair(digest(1), text(label))]));
    }
    for (name, rows) in cases {
        negative(
            &alloc::format!("recipe-domain-negative-{name}"),
            encode(&overlay(Value::Array(rows))),
        );
    }
    let wire = encode(&overlay(rows(&[(1, "public")])));
    negative(
        "recipe-domain-negative-trailing",
        [wire.clone(), vec![0]].concat(),
    );
    negative(
        "recipe-domain-negative-truncated",
        wire[..wire.len() - 1].to_vec(),
    );
    negative(
        "recipe-domain-negative-nonminimal",
        [vec![0xb8, 3], wire[1..].to_vec()].concat(),
    );
    negative(
        "recipe-domain-negative-huge-count",
        encode(&overlay(Value::Raw(primitives::head(4, u64::MAX)))),
    );
    negative(
        "recipe-domain-negative-invalid-utf8",
        encode(&overlay(Value::Array(vec![pair(
            digest(1),
            Value::Raw(vec![0x61, 0xff]),
        )]))),
    );
}
