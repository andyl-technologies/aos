//! Checks explicit recorded encodings against independently assembled tuples.
#![allow(clippy::unwrap_used)]
// Private fixture modules share one immutable independent primitive model.
#[allow(clippy::duplicate_mod)]
#[path = "recorded_models.rs"]
mod models;
use super::*;
use alloc::vec;
use models::*;

#[test]
fn prov_recorded_context_encoder_preserves_explicit_fields_and_legacy_bytes() {
    let names = vocabulary(1);
    assert_encoder_refusal(4, &names, &[], &[]);
    assert_encoder_refusal(1, &vocabulary(2), &[], &[]);
    for later in [
        &["acl"][..],
        &["z", "a"][..],
        &["same", "same"][..],
        &[""][..],
    ] {
        assert_encoder_refusal(1, &names, later, &[]);
    }
    let long = "x".repeat(256);
    assert_encoder_refusal(1, &names, &[&long], &[]);
    let excessive: Vec<_> = (0..258)
        .map(|i| alloc::format!("{i:03}{}", "x".repeat(252)))
        .collect();
    let refs: Vec<_> = excessive.iter().map(|n| n.as_str()).collect();
    assert_encoder_refusal(1, &names, &refs, &[]);
    assert_encoder_refusal(1, &names, &[], &evidence(9, "private:test", "uid", "uid"));

    for revision in 1..=3 {
        let names = vocabulary(revision);
        for selected in [None, Some(evidence(1, "private:test", "uid", "uid"))] {
            let selector = array(&[text("preset"), text("any")]);
            let fields = ContextFields {
                view: &[1; 32],
                domain: "private:test",
                selector: &selector,
                baseline: Some(""),
                minimum: 262144,
                selected: selected.as_deref().unwrap_or(&[]),
            };
            let expected_legacy = {
                let mut fields = vec![
                    uint(if selected.is_some() { 2 } else { 1 }),
                    bytes(&[1; 32]),
                    text("private:test"),
                    bytes(&selector),
                    text(""),
                    uint(262144),
                ];
                if let Some(selected) = &selected {
                    fields.push(bytes(selected));
                }
                array(&fields)
            };
            assert_eq!(encode(fields), expected_legacy);
            let actual = encode_recorded(RecordedContextFields {
                context: ContextFields {
                    view: &[1; 32],
                    domain: "private:test",
                    selector: &selector,
                    baseline: Some(""),
                    minimum: 262144,
                    selected: selected.as_deref().unwrap_or(&[]),
                },
                root: &[2; 32],
                revision,
                behavioral: &names,
                later: &["future.value"],
            })
            .unwrap();
            let expected = context(revision, &names, &["future.value"], selected.as_deref());
            assert_eq!(actual, expected);
            let decoded = super::super::context::decode(&actual).unwrap();
            assert_eq!(decoded.version, 3);
            assert_eq!(decoded.view, &[1; 32]);
            assert_eq!(decoded.domain, "private:test");
            assert_eq!(decoded.selector, selector);
            assert_eq!(decoded.baseline, Some(""));
            assert_eq!(decoded.minimum, 262144);
            assert_eq!(decoded.selected, selected.as_deref());
            let recorded = decoded.recorded.unwrap();
            assert_eq!(recorded.root, &[2; 32]);
            assert_eq!(recorded.revision, revision);
            assert_eq!(recorded.behavioral, names);
            assert_eq!(recorded.later, vec!["future.value"]);
        }
    }
}

/// Exercises encoder refusals without constructing an evaluator.
///
/// # Panics
/// Panics when a malformed ordinary claim unexpectedly encodes successfully.
fn assert_encoder_refusal(revision: u64, names: &[&str], later: &[&str], selected: &[u8]) {
    let selector = array(&[text("preset"), text("any")]);
    assert!(
        encode_recorded(RecordedContextFields {
            context: ContextFields {
                view: &[1; 32],
                domain: "private:test",
                selector: &selector,
                baseline: Some(""),
                minimum: 262144,
                selected
            },
            root: &[2; 32],
            revision,
            behavioral: names,
            later
        })
        .is_err()
    );
}
