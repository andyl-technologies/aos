//! Compares complete unauthenticated recipe/configuration fields and memo keys.
//!
//! No evaluator, history admission, fold execution or operation authority is used.
//! ```text
//! configuration = [[ours-context-bytes, theirs-context-bytes], null-or-fold]
//! preimage = "terrane-memo-v1" || 0x00 || complete canonical recipe bytes
//! ```

// The three owning consumers share only independent primitive field models.
#[allow(clippy::duplicate_mod)]
#[path = "primitives.rs"]
mod primitives;

use super::TrustContext;
use crate::algebra::{MergePolicy, Recipe};
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use primitives::{Value, published, required};

fn ordinary_trust(configuration: &Value) -> TrustContext {
    TrustContext {
        selector: primitives::encode(&Value::Array(alloc::vec![
            primitives::text("preset"),
            primitives::text("any")
        ])),
        evaluator_version: "terrane-verified-path/v1".into(),
        configuration: primitives::encode(configuration),
        accepted: Vec::new(),
        any: true,
        timestamps: Vec::new(),
        evaluators: Vec::new(),
        authenticated: false,
        filter: None,
    }
}

fn compare_trust(actual: &TrustContext, expected: &TrustContext) {
    assert_eq!(actual.selector, expected.selector);
    assert_eq!(actual.evaluator_version, expected.evaluator_version);
    assert_eq!(actual.configuration, expected.configuration);
    assert_eq!(actual.accepted, expected.accepted);
    assert_eq!(actual.any, expected.any);
    assert_eq!(actual.timestamps, expected.timestamps);
    assert!(actual.evaluators.is_empty());
    assert!(!actual.authenticated);
    assert!(actual.filter.is_none());
}

#[test]
fn reference_recorded_context_recipes_bind_complete_configuration_and_keys() {
    let contexts = primitives::contexts();
    assert_eq!(contexts.len(), 21);
    assert_eq!(primitives::negatives().len(), 70);
    let models = primitives::recipes(&contexts);
    assert_eq!(models.len(), 22);
    let policies = [
        MergePolicy::PreferTrusted,
        MergePolicy::PreferNewer,
        MergePolicy::KeepConflict,
    ];
    let mut identities = BTreeSet::new();

    for model in models {
        let expected = primitives::encode(&model.value());
        assert_eq!(expected, published(&model.name, "wire"));
        let trust = ordinary_trust(&model.configuration);
        let recipe = Recipe::Merge {
            base: model.roots[0],
            ours: model.roots[1],
            theirs: model.roots[2],
            policies: &policies,
            trust: &trust,
            domains: None,
        };
        assert_eq!(recipe.encode(), expected, "complete encode {}", model.name);
        let decoded = required(Recipe::decode(&expected), "complete recipe decode");
        let Recipe::Merge {
            base,
            ours,
            theirs,
            policies: actual,
            trust: decoded_trust,
            domains,
        } = decoded.as_recipe()
        else {
            panic!("independent complete merge model");
        };
        assert_eq!([base, ours, theirs], model.roots);
        assert_eq!(actual, policies);
        assert!(domains.is_none());
        compare_trust(decoded_trust, &trust);
        assert_eq!(decoded.as_recipe().encode(), expected);

        let Value::Array(configuration) = &model.configuration else {
            panic!("configuration array")
        };
        let Value::Array(pair) = &configuration[0] else {
            panic!("ordered context pair")
        };
        assert_eq!(pair.len(), 2);
        for context in pair {
            let Value::Bytes(bytes) = context else {
                panic!("context byte string")
            };
            required(
                crate::provenance::validate_canonical_context(bytes),
                "registered context syntax",
            );
        }
        if model.name.starts_with("recorded-recipe-fold") {
            // Fold changes the operand, while the incoming context still names
            // its original signed-view root. No transform is executed here.
            assert_eq!(model.roots[2], [6; 32]);
            let Value::Bytes(incoming) = &pair[1] else {
                panic!("incoming bytes")
            };
            let mut original = primitives::base_context(3);
            original.view = [2; 32];
            original.domain = "group:incoming".into();
            primitives::present(original.recorded.as_mut(), "incoming recorded root").root =
                [4; 32];
            assert_eq!(*incoming, primitives::encode(&original.value()));
        }
        let mut preimage = b"terrane-memo-v1\0".to_vec();
        preimage.extend_from_slice(&expected);
        assert_eq!(preimage, published(&model.name, "preimage"));
        let identity = *blake3::hash(&preimage).as_bytes();
        assert_eq!(identity.as_slice(), published(&model.name, "memo"));
        assert_eq!(
            required(recipe.identity(), "registered recipe memo key"),
            identity
        );
        assert!(
            identities.insert(identity),
            "isolated field key {}",
            model.name
        );
    }
    assert_eq!(identities.len(), 22);
    assert_eq!(
        primitives::encode(&Value::Map(alloc::vec![
            (Value::UInt(24), Value::Null),
            (Value::Bytes(Vec::new()), Value::Bool(true)),
        ])),
        [0xa2, 0x18, 0x18, 0xf6, 0x40, 0xf5]
    );
}
