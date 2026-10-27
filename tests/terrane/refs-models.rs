//! Compares independent complete field witnesses with the owning ref codecs.
//!
//! Fixtures are inert format models. Their fixed signatures and token claims
//! do not authenticate any principal, establish policy or prove a ref advance.
//!
//! ```text
//! Commit preimage: canonical commit map with key 8 absent
//! Snapshot preimage: canonical annotation map with key 5 absent
//! ```

mod refs_models;

use refs_models::{
    commits, fields, negative, records,
    support::{Value, encode, field, hex, reference, remove},
};
use terrane_format::refs::{Commit, RefLogRecord, RefRecord};

#[test]
fn reference_modern_commit_models_preserve_optional_fields_and_preimage() {
    let reference = reference();
    let models = commits::models();
    assert_eq!(models.len(), 33);
    for (name, model, mut primitive) in models {
        let wire = hex(field(&reference, &name, "wire"));
        assert_eq!(encode(&primitive), wire, "independent fields: {name}");
        assert_eq!(
            model
                .encode()
                .unwrap_or_else(|error| panic!("{name}: {error}")),
            wire,
            "owning encoder: {name}"
        );
        let decoded = Commit::decode(&wire).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(decoded, model, "all decoded fields: {name}");
        if name == "commit-recipe-graft" {
            let recipe = model
                .profile_pair
                .recipe
                .as_deref()
                .unwrap_or_else(|| panic!("missing graft recipe"));
            let decoded_recipe = terrane_format::algebra::Recipe::decode(recipe)
                .unwrap_or_else(|error| panic!("graft schema: {error}"));
            let entry = encode(&refs_models::support::m(vec![
                (1, Value::UInt(4)),
                (6, Value::Bytes(vec![2; 32])),
            ]));
            assert_eq!(
                decoded_recipe.as_recipe(),
                terrane_format::algebra::Recipe::Graft {
                    parent: [1; 32],
                    target: [2; 32],
                    at: b"target",
                    entry: &entry,
                    replace: false,
                    domains: None,
                }
            );
        }

        if let (Some(actual), Some(expected)) = (
            &decoded.profile_pair.commit_context,
            &model.profile_pair.commit_context,
        ) {
            assert_eq!(actual.reference(), expected.reference());
            assert_eq!(actual.surface(), expected.surface());
            assert_eq!(actual.locality(), expected.locality());
            assert_eq!(actual.roots(), expected.roots());
        }
        remove(&mut primitive, 8);
        let preimage = hex(field(&reference, &name, "preimage"));
        assert_eq!(
            encode(&primitive),
            preimage,
            "independent unsigned map: {name}"
        );
        assert_eq!(
            model
                .signature_preimage()
                .unwrap_or_else(|error| panic!("{name}: {error}")),
            preimage
        );
        assert_eq!(
            model
                .identity()
                .unwrap_or_else(|error| panic!("{name}: {error}"))
                .as_slice(),
            hex(field(&reference, &name, "identity"))
        );
    }
    assert_eq!(
        reference
            .keys()
            .filter(|name| name.starts_with("commit-"))
            .count(),
        33
    );
}

#[test]
fn reference_ref_record_models_preserve_policy_envelope_fields_and_preimage() {
    let reference = reference();
    let models = records::refs();
    assert_eq!(models.len(), 8);
    for (name, model, primitive) in models {
        let wire = hex(field(&reference, &name, "wire"));
        assert_eq!(encode(&primitive), wire, "independent fields: {name}");
        assert_eq!(
            model
                .encode()
                .unwrap_or_else(|error| panic!("{name}: {error}")),
            wire
        );
        assert_eq!(
            RefRecord::decode(&wire).unwrap_or_else(|error| panic!("{name}: {error}")),
            model
        );
        if let Some(snapshot) = model
            .policy
            .as_ref()
            .and_then(|policy| policy.snapshot.as_ref())
        {
            let mut unsigned = fields::envelope();
            remove(&mut unsigned, 5);
            let preimage = hex(field(&reference, &name, "preimage"));
            assert_eq!(encode(&unsigned), preimage);
            assert_eq!(
                snapshot
                    .signature_preimage()
                    .unwrap_or_else(|error| panic!("{name}: {error}")),
                preimage
            );
        }
        assert!(!reference[&name].contains_key("identity"));
    }
    assert_eq!(
        reference
            .keys()
            .filter(|name| name.starts_with("ref-"))
            .count(),
        8
    );
}

#[test]
fn reference_reflog_models_preserve_reason_expected_and_predecessor_fields() {
    let reference = reference();
    let models = records::logs();
    assert_eq!(models.len(), 10);
    for (name, model, primitive) in models {
        let wire = hex(field(&reference, &name, "wire"));
        assert_eq!(encode(&primitive), wire, "independent fields: {name}");
        assert_eq!(
            model
                .encode()
                .unwrap_or_else(|error| panic!("{name}: {error}")),
            wire
        );
        assert_eq!(
            RefLogRecord::decode(&wire).unwrap_or_else(|error| panic!("{name}: {error}")),
            model
        );
        if let Some(expected) = &model.expected_previous {
            assert_eq!(
                model
                    .cas_expected_previous()
                    .unwrap_or_else(|error| panic!("{name}: {error}")),
                expected.as_ref()
            );
            assert_eq!(
                model
                    .selected_previous()
                    .unwrap_or_else(|error| panic!("{name}: {error}")),
                model.committed_previous.as_ref().or(expected.as_ref())
            );
        } else {
            assert!(model.cas_expected_previous().is_err());
            assert!(model.selected_previous().is_err());
        }
        assert!(!reference[&name].contains_key("identity"));
    }
    assert_eq!(
        reference
            .keys()
            .filter(|name| name.starts_with("log-"))
            .count(),
        10
    );
}

#[test]
fn reference_negative_ref_wires_require_structural_rejection() {
    let reference = reference();
    let models = negative::models();
    assert_eq!(models.len(), 96);
    for model in models {
        let wire = hex(field(&reference, &model.name, "wire"));
        assert_eq!(
            model.wire, wire,
            "independently reconstructed negative: {}",
            model.name
        );
        assert_eq!(field(&reference, &model.name, "family"), model.family);
        let rejected = match model.family {
            "commit" => Commit::decode(&wire).is_err(),
            "ref" => RefRecord::decode(&wire).is_err(),
            "log" => RefLogRecord::decode(&wire).is_err(),
            _ => panic!("unknown negative family"),
        };
        assert!(rejected, "structural input accepted: {}", model.name);
        assert!(!reference[&model.name].contains_key("identity"));
    }
    assert_eq!(
        reference
            .keys()
            .filter(|name| name.starts_with("bad-"))
            .count(),
        96
    );
    // Primitive canonicalization must sort encoded text keys by length first.
    let ordered = refs_models::support::texts(vec![("aa", Value::UInt(1)), ("z", Value::UInt(2))]);
    assert_eq!(encode(&ordered), hex("a2617a0262616101"));
}
