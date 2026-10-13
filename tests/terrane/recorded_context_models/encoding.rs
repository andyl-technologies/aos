//! Compares complete ordinary encoding inputs, published wires and decoded fields.
//!
//! No serialized registration or view/root claim creates authority.
//! ```text
//! recorded context = [3, view, domain, selector, baseline, minimum, selected,
//!                     [original-root, revision, behavioral, later]]
//! ```

// The same independent field tables serve three private owning-codec consumers.
#[allow(clippy::duplicate_mod)]
#[path = "primitives.rs"]
mod primitives;

use super::{ContextFields, RecordedContextFields, encode, encode_recorded};
use alloc::vec::Vec;
use primitives::{Context, present, published, required};

fn compare_decoded(model: &Context, wire: &[u8]) {
    let selector = primitives::encode(&model.selector);
    let selected = model.selected.as_ref().map(primitives::encode);
    let recorded = model
        .recorded
        .as_ref()
        .map(|fields| super::super::context::RecordedFields {
            root: fields.root.as_slice(),
            revision: fields.revision,
            behavioral: fields.behavioral.iter().map(|name| name.as_str()).collect(),
            later: fields.later.iter().map(|name| name.as_str()).collect(),
        });
    let expected = super::super::context::DecodedContext {
        version: model.version,
        view: model.view.as_slice(),
        domain: &model.domain,
        selector: &selector,
        baseline: model.baseline.as_deref(),
        minimum: model.minimum,
        selected: selected.as_deref(),
        recorded,
    };
    let actual = required(
        super::super::context::decode(wire),
        "complete decoded context",
    );
    assert_eq!(actual, expected, "every decoded field {}", model.name);
}

#[test]
fn reference_recorded_context_encoder_preserves_complete_fields() {
    let models = primitives::contexts();
    assert_eq!(models.len(), 21);
    assert_eq!(primitives::recipes(&models).len(), 22);
    for recipe in primitives::recipes(&models) {
        assert_eq!(
            primitives::encode(&recipe.value()),
            published(&recipe.name, "wire")
        );
    }
    assert_eq!(primitives::negatives().len(), 70);
    assert_eq!(primitives::vocabulary(1).len(), 33);
    assert_eq!(primitives::vocabulary(2).len(), 34);
    assert_eq!(primitives::vocabulary(3).len(), 35);

    for model in models {
        let expected = primitives::encode(&model.value());
        assert_eq!(expected, published(&model.name, "wire"));
        let selector = primitives::encode(&model.selector);
        let selected = model
            .selected
            .as_ref()
            .map(primitives::encode)
            .unwrap_or_default();
        let context = ContextFields {
            view: &model.view,
            domain: &model.domain,
            selector: &selector,
            baseline: model.baseline.as_deref(),
            minimum: model.minimum,
            selected: &selected,
        };
        let actual = if model.version == 3 {
            let fields = present(model.recorded.as_ref(), "v3 recorded fields");
            let behavioral: Vec<_> = fields.behavioral.iter().map(|name| name.as_str()).collect();
            let later: Vec<_> = fields.later.iter().map(|name| name.as_str()).collect();
            required(
                encode_recorded(RecordedContextFields {
                    context,
                    root: &fields.root,
                    revision: fields.revision,
                    behavioral: &behavioral,
                    later: &later,
                }),
                "ordinary registered encoder",
            )
        } else {
            encode(context)
        };
        assert_eq!(actual, expected, "complete owning encode {}", model.name);
        compare_decoded(&model, &expected);
    }
}
