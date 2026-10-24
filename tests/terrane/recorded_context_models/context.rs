//! Reconstructs malformed borrowed tuples independently of rejecting encoders.
//!
//! Positive tuple evidence is ordinary data, not an authenticated association.
//! ```text
//! malformed = independently assembled CBOR fields or raw claimed lengths
//! ```

// Each private consumer imports the same independent primitive field tables.
#[allow(clippy::duplicate_mod)]
#[path = "primitives.rs"]
mod primitives;

use primitives::{published, required};

#[test]
fn reference_recorded_context_decoder_refuses_independent_malformed_wires() {
    let models = primitives::contexts();
    assert_eq!(models.len(), 21);
    assert_eq!(primitives::recipes(&models).len(), 22);
    for recipe in primitives::recipes(&models) {
        assert_eq!(
            primitives::encode(&recipe.value()),
            published(&recipe.name, "wire")
        );
    }
    for model in models {
        let wire = primitives::encode(&model.value());
        assert_eq!(wire, published(&model.name, "wire"));
        let decoded = required(super::decode(&wire), "ordinary positive context");
        assert_eq!(decoded.version, model.version);
        assert_eq!(decoded.view, model.view);
        assert_eq!(decoded.domain, model.domain);
        assert_eq!(decoded.selector, primitives::encode(&model.selector));
        assert_eq!(decoded.baseline, model.baseline.as_deref());
        assert_eq!(decoded.minimum, model.minimum);
        assert_eq!(
            decoded.selected,
            model.selected.as_ref().map(primitives::encode).as_deref()
        );
        match (decoded.recorded, model.recorded) {
            (Some(actual), Some(expected)) => {
                assert_eq!(actual.root, expected.root);
                assert_eq!(actual.revision, expected.revision);
                assert_eq!(actual.behavioral, expected.behavioral);
                assert_eq!(actual.later, expected.later);
            }
            (None, None) => {}
            _ => panic!("exact recorded-field presence"),
        }
    }
    let negatives = primitives::negatives();
    assert_eq!(negatives.len(), 70);
    for (name, wire) in negatives {
        assert_eq!(
            wire,
            published(&name, "wire"),
            "independent primitive {name}"
        );
        assert!(super::decode(&wire).is_err(), "structural rejection {name}");
        assert!(
            super::validate(&wire).is_err(),
            "public validator refusal {name}"
        );
    }
}
