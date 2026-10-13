//! Compares complete outer trust evidence without constructing policy authority.
//!
//! Context and fold configuration bytes remain canonical ordinary data.
//! ```text
//! trust = {1: selector, 2: version, 3: configuration, 4: accepted, ?5: timestamps}
//! ```

#[path = "primitives.rs"]
mod primitives;

use super::TrustContext;
use crate::algebra::{MergePolicy, Recipe};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use primitives::{Value, digest, encode, negative, positive, recipe, required, text};

fn selector(tag: &str, argument: Value) -> Value {
    Value::Array(vec![text(tag), argument])
}

fn any() -> Value {
    selector("preset", text("any"))
}

fn configuration() -> Value {
    Value::Map(vec![
        (
            Value::UInt(1),
            Value::Array(vec![
                Value::Bool(false),
                Value::Bool(true),
                Value::Null,
                Value::UInt(24),
                Value::Bytes(b"context".to_vec()),
            ]),
        ),
        (Value::UInt(2), text("configuration")),
    ])
}

fn context(view: u8, domain: &str, selector: Value, baseline: Value, minimum: u64) -> Value {
    Value::Bytes(encode(&Value::Array(vec![
        Value::UInt(1),
        digest(view),
        text(domain),
        Value::Bytes(encode(&selector)),
        baseline,
        Value::UInt(minimum),
    ])))
}

fn verified_configuration(preprocessing: Value) -> Value {
    Value::Array(vec![
        Value::Array(vec![
            context(
                6,
                "private:ours",
                selector("preset", text("strict")),
                text("baseline-a"),
                4096,
            ),
            context(7, "group:incoming", any(), Value::Null, 8192),
        ]),
        preprocessing,
    ])
}

fn fold(domain: bool) -> Value {
    let mut fields = vec![
        digest(1),
        digest(3),
        digest(8),
        Value::Array(vec![
            Value::Bytes(b"a".to_vec()),
            Value::Bytes(b"a/child".to_vec()),
            Value::Bytes(b"z".to_vec()),
        ]),
    ];
    if domain {
        fields.push(text("private:incoming"));
    }
    Value::Array(fields)
}

fn complex_selector() -> Value {
    selector(
        "all",
        Value::Array(vec![
            selector("issuer", text("issuer-a")),
            selector("subject", text("subject-*")),
            selector("kind", text("workload")),
            selector("group", text("editors")),
            selector("source", text("source-a")),
            selector("signed-by-key", text(&"ab".repeat(32))),
            selector("attested", text("claim-a")),
            selector("accepted-by", selector("preset", text("signed-baseline"))),
            selector("not", selector("preset", text("attested"))),
            Value::Array(vec![
                text("attr-by"),
                text("hash.sha256"),
                selector("kind", text("human")),
            ]),
            selector(
                "any",
                Value::Array(vec![selector("kind", text("service")), any()]),
            ),
        ]),
    )
}

fn fields(
    selector: Value,
    version: &str,
    configuration: Value,
    accepted: Vec<Value>,
    timestamps: Option<Vec<Value>>,
) -> Value {
    let mut fields = vec![
        (Value::UInt(1), selector),
        (Value::UInt(2), text(version)),
        (Value::UInt(3), configuration),
        (Value::UInt(4), Value::Array(accepted)),
    ];
    if let Some(timestamps) = timestamps {
        fields.push((Value::UInt(5), Value::Array(timestamps)));
    }
    Value::Map(fields)
}

fn merge(trust: Value) -> Value {
    recipe(
        "merge",
        vec![digest(1), digest(2), digest(3)],
        Value::Map(vec![
            (text("trust"), trust),
            (
                text("policy"),
                Value::Array(vec![
                    text("prefer-trusted"),
                    text("prefer-newer"),
                    text("keep-conflict"),
                ]),
            ),
        ]),
    )
}

fn model(
    selector: &Value,
    version: &str,
    configuration: &Value,
    accepted: Vec<[u8; 32]>,
    timestamps: Vec<([u8; 32], u64)>,
) -> TrustContext {
    TrustContext {
        selector: encode(selector),
        evaluator_version: String::from(version),
        configuration: encode(configuration),
        accepted,
        any: *selector == any(),
        timestamps,
        evaluators: Vec::new(),
        authenticated: false,
        filter: None,
    }
}

fn compare(actual: &TrustContext, expected: &TrustContext) {
    assert_eq!(actual.selector(), expected.selector);
    assert_eq!(actual.selector, expected.selector);
    assert_eq!(actual.evaluator_version, expected.evaluator_version);
    assert_eq!(actual.configuration, expected.configuration);
    assert_eq!(actual.accepted, expected.accepted);
    assert_eq!(actual.any, expected.any);
    assert_eq!(actual.timestamps, expected.timestamps);
    assert!(actual.evaluators.is_empty());
    assert!(expected.evaluators.is_empty());
    assert!(!actual.authenticated);
    assert!(!expected.authenticated);
    assert!(actual.filter.is_none());
    assert!(expected.filter.is_none());
    assert_eq!(actual, expected);
}

#[test]
fn reference_recipe_trust_preserves_outer_evidence_fields() {
    let accepted = vec![[4; 32], [5; 32]];
    let timestamps = vec![([4; 32], 0), ([5; 32], u64::MAX)];
    let cases = vec![
        (
            "inert",
            any(),
            "terrane-preset-any/v1",
            Value::Null,
            Vec::new(),
            Vec::new(),
        ),
        (
            "accepted",
            selector("preset", text("strict")),
            "ordinary-evidence/v2",
            configuration(),
            accepted.clone(),
            Vec::new(),
        ),
        (
            "timestamps",
            selector("preset", text("strict")),
            "ordinary-evidence/v2",
            configuration(),
            accepted.clone(),
            timestamps,
        ),
        (
            "selector",
            complex_selector(),
            "ordinary-evidence/v2",
            configuration(),
            accepted,
            Vec::new(),
        ),
        (
            "verified-null",
            any(),
            "terrane-verified-path/v1",
            verified_configuration(Value::Null),
            Vec::new(),
            Vec::new(),
        ),
        (
            "verified-fold",
            any(),
            "terrane-verified-path/v1",
            verified_configuration(fold(false)),
            Vec::new(),
            Vec::new(),
        ),
        (
            "verified-fold-domain",
            any(),
            "terrane-verified-path/v1",
            verified_configuration(fold(true)),
            Vec::new(),
            Vec::new(),
        ),
    ];
    let policies = [
        MergePolicy::PreferTrusted,
        MergePolicy::PreferNewer,
        MergePolicy::KeepConflict,
    ];
    for (suffix, selector, version, configuration, accepted, timestamps) in cases {
        let accepted_fields = accepted
            .iter()
            .map(|identity| Value::Bytes(identity.to_vec()))
            .collect();
        let time_fields = if timestamps.is_empty() {
            None
        } else {
            Some(
                timestamps
                    .iter()
                    .map(|(identity, timestamp)| {
                        Value::Array(vec![
                            Value::Bytes(identity.to_vec()),
                            Value::UInt(*timestamp),
                        ])
                    })
                    .collect(),
            )
        };
        let fields = fields(
            selector.clone(),
            version,
            configuration.clone(),
            accepted_fields,
            time_fields,
        );
        let expected = model(&selector, version, &configuration, accepted, timestamps);
        let recipe = Recipe::Merge {
            base: [1; 32],
            ours: [2; 32],
            theirs: [3; 32],
            policies: &policies,
            trust: &expected,
            domains: None,
        };
        let name = alloc::format!("recipe-trust-{suffix}");
        let wire = positive(&name, &merge(fields), &recipe);
        let owned = required(Recipe::decode(&wire), "complete ordinary trust recipe");
        let Recipe::Merge {
            base,
            ours,
            theirs,
            policies: actual_policies,
            trust,
            domains,
        } = owned.as_recipe()
        else {
            panic!("merge")
        };
        assert_eq!((base, ours, theirs), ([1; 32], [2; 32], [3; 32]));
        assert_eq!(actual_policies, policies);
        assert!(domains.is_none());
        compare(trust, &expected);
        assert_eq!(owned.as_recipe().encode(), wire);
        assert_eq!(
            required(owned.as_recipe().identity(), "memo identity"),
            required(recipe.identity(), "memo identity")
        );
    }
}

// Changing a primitive map bypasses the owning TrustContext encoder.
fn changed(trust: &Value, key: u64, replacement: Option<Value>) -> Value {
    let Value::Map(original) = trust else {
        panic!("primitive trust map")
    };
    let mut fields = original.clone();
    fields.retain(|(field, _)| *field != Value::UInt(key));
    if let Some(replacement) = replacement {
        fields.push((Value::UInt(key), replacement));
    }
    Value::Map(fields)
}

#[test]
fn reference_recipe_trust_negatives_require_structural_rejection() {
    let trust = fields(
        selector("preset", text("strict")),
        "ordinary-evidence/v2",
        Value::Null,
        vec![digest(4)],
        None,
    );
    for key in [1, 2, 3, 4] {
        negative(
            &alloc::format!("recipe-trust-negative-missing-{key}"),
            encode(&merge(changed(&trust, key, None))),
        );
    }
    let pair = |identity: Value, timestamp: Value| Value::Array(vec![identity, timestamp]);
    let cases = vec![
        ("unknown", 6, Value::Null),
        ("version-empty", 2, text("")),
        ("version-type", 2, Value::UInt(1)),
        (
            "accepted-short",
            4,
            Value::Array(vec![Value::Bytes(vec![b'x'; 31])]),
        ),
        (
            "accepted-long",
            4,
            Value::Array(vec![Value::Bytes(vec![b'x'; 33])]),
        ),
        ("accepted-type", 4, Value::Array(vec![Value::UInt(1)])),
        (
            "accepted-duplicate",
            4,
            Value::Array(vec![digest(1), digest(1)]),
        ),
        (
            "accepted-reversed",
            4,
            Value::Array(vec![digest(2), digest(1)]),
        ),
        ("timestamps-empty", 5, Value::Array(Vec::new())),
        ("timestamps-null", 5, Value::Null),
        (
            "timestamp-short",
            5,
            Value::Array(vec![pair(Value::Bytes(vec![b'x'; 31]), Value::UInt(1))]),
        ),
        (
            "timestamp-pair-short",
            5,
            Value::Array(vec![Value::Array(vec![digest(1)])]),
        ),
        (
            "timestamp-pair-long",
            5,
            Value::Array(vec![Value::Array(vec![
                digest(1),
                Value::UInt(1),
                Value::UInt(2),
            ])]),
        ),
        (
            "timestamp-value",
            5,
            Value::Array(vec![pair(digest(1), text("1"))]),
        ),
        (
            "timestamp-duplicate",
            5,
            Value::Array(vec![
                pair(digest(1), Value::UInt(1)),
                pair(digest(1), Value::UInt(2)),
            ]),
        ),
        (
            "timestamp-reversed",
            5,
            Value::Array(vec![
                pair(digest(2), Value::UInt(1)),
                pair(digest(1), Value::UInt(2)),
            ]),
        ),
        ("selector-unknown", 1, selector("unknown", text("x"))),
        ("selector-kind", 1, selector("kind", text("unknown"))),
        ("selector-preset", 1, selector("preset", text("unknown"))),
        (
            "selector-attr",
            1,
            Value::Array(vec![text("attr-by"), text("unknown"), any()]),
        ),
        (
            "selector-empty-all",
            1,
            selector("all", Value::Array(Vec::new())),
        ),
        (
            "selector-empty-any",
            1,
            selector("any", Value::Array(Vec::new())),
        ),
        ("selector-short", 1, Value::Array(vec![text("issuer")])),
        (
            "selector-long",
            1,
            Value::Array(vec![text("issuer"), text("x"), text("y")]),
        ),
        ("selector-atom-type", 1, selector("issuer", Value::UInt(1))),
        (
            "selector-attribute-limit",
            1,
            Value::Array(vec![text("attr-by"), text(&"x".repeat(256)), any()]),
        ),
    ];
    for (name, key, value) in cases {
        negative(
            &alloc::format!("recipe-trust-negative-{name}"),
            encode(&merge(changed(&trust, key, Some(value)))),
        );
    }
    let wire = encode(&merge(trust.clone()));
    negative(
        "recipe-trust-negative-trailing",
        [wire.clone(), vec![0]].concat(),
    );
    negative(
        "recipe-trust-negative-truncated",
        wire[..wire.len() - 1].to_vec(),
    );
    negative(
        "recipe-trust-negative-nonminimal",
        [vec![0xb8, 3], wire[1..].to_vec()].concat(),
    );
    for (name, raw) in [
        ("configuration-tag", vec![0xc0, 0]),
        ("configuration-float", vec![0xf9, 0, 0]),
        ("configuration-unsorted", vec![0xa2, 2, 0, 1, 0]),
        ("configuration-duplicate", vec![0xa2, 1, 0, 1, 0]),
        ("configuration-huge", primitives::head(4, u64::MAX)),
        ("configuration-nonminimal", vec![0x18, 0]),
        ("configuration-key-type", vec![0xa1, 0x80, 0]),
    ] {
        negative(
            &alloc::format!("recipe-trust-negative-{name}"),
            encode(&merge(changed(&trust, 3, Some(Value::Raw(raw))))),
        );
    }
    for (name, key, raw) in [
        ("accepted-huge", 4, primitives::head(4, u64::MAX)),
        ("timestamps-huge", 5, primitives::head(4, u64::MAX)),
        ("version-invalid-utf8", 2, vec![0x61, 0xff]),
    ] {
        negative(
            &alloc::format!("recipe-trust-negative-{name}"),
            encode(&merge(changed(&trust, key, Some(Value::Raw(raw))))),
        );
    }
}
