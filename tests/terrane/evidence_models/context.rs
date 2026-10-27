//! Checks both trust-context versions against complete ordinary field models.
//!
//! Baseline absence differs from a present empty baseline. The validator below
//! checks syntax only and never produces a trust evaluator or verified history.
//!
//! ```text
//! [1, view, domain, selector-bytes, baseline-or-null, minimum]
//! [2, view, domain, selector-bytes, baseline-or-null, minimum, selected-bytes]
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
use crate::provenance::validate_canonical_context;
use Value::{Array, Bool, UInt};
use alloc::{format, vec};
use support::{Value, bytes, compare, context, fields, row, text};

fn slots(value: &mut Value) -> &mut Vec<Value> {
    let Array(values) = value else {
        panic!("fixture must be an array")
    };
    values
}

#[test]
fn reference_context_models_preserve_versions_and_presence() {
    let selector = Array(vec![
        text("attr-by"),
        text("hash.sha256"),
        Array(vec![text("kind"), text("workload")]),
    ])
    .encode();
    let selected_rows = Array(vec![row(0, false), row(1, true)]);
    let selected = selected_rows.encode();
    assert_eq!(fields(&selected), selected_rows);

    for version in [1, 2] {
        for (baseline, label) in [
            (None, "absent"),
            (Some(""), "empty"),
            (Some("baseline"), "present"),
        ] {
            let name = format!("context-v{version}-{label}");
            let model = context(version, baseline, None);
            let published = compare(&name, &model);
            let encoded = encode(ContextFields {
                view: &[1; 32],
                domain: "private:target",
                selector: &selector,
                baseline,
                minimum: 262_144,
                selected: if version == 1 { &[] } else { &selected },
            });

            assert_eq!(encoded, published, "owning context projection: {name}");
            assert_eq!(fields(&encoded), model, "all context fields: {name}");
            assert_eq!(
                validate_canonical_context(&published),
                Ok(()),
                "syntax only: {name}"
            );
            for cut in 0..published.len() {
                assert!(
                    validate_canonical_context(&published[..cut]).is_err(),
                    "truncated {name}: {cut}"
                );
            }
            let mut trailing = published.clone();
            trailing.push(0);
            assert!(validate_canonical_context(&trailing).is_err());
            let mut nonminimal = vec![0x98, published[0] & 31];
            nonminimal.extend(&published[1..]);
            assert!(validate_canonical_context(&nonminimal).is_err());
        }
    }

    let mut negatives = vec![];
    for (label, index, value) in [
        ("version", 0, UInt(3)),
        ("short-view", 1, bytes(b"x")),
        (
            "selector",
            3,
            bytes(Array(vec![text("unknown"), text("x")]).encode()),
        ),
        ("baseline", 4, Bool(false)),
    ] {
        let mut model = context(1, None, None);
        slots(&mut model)[index] = value;
        negatives.push((label, model));
    }
    negatives.push(("empty-selected", context(2, None, Some(vec![]))));
    for label in [
        "wrong-view",
        "wrong-domain",
        "empty-full-path",
        "empty-carrying-path",
        "empty-producer-path",
        "short-record",
        "wrong-name",
        "noncanonical-value",
        "reversed-rows",
        "duplicate-rows",
        "short-tuple",
    ] {
        let mut rows = vec![row(0, false), row(1, true)];
        match label {
            "wrong-view" => slots(&mut slots(&mut rows[0])[0])[0] = bytes([99; 32]),
            "wrong-domain" => slots(&mut rows[0])[2] = text("public"),
            "empty-full-path" => slots(&mut rows[0])[3] = bytes([]),
            "empty-carrying-path" => {
                slots(&mut slots(&mut slots(&mut rows[0])[4])[7])[2] = bytes([])
            }
            "empty-producer-path" => {
                slots(&mut slots(&mut slots(&mut rows[0])[4])[8])[1] = bytes([])
            }
            "short-record" => slots(&mut slots(&mut rows[0])[4])[0] = bytes(b"x"),
            "wrong-name" => slots(&mut slots(&mut rows[0])[4])[2] = text("magic"),
            "noncanonical-value" => slots(&mut slots(&mut rows[0])[4])[5] = bytes([0x18, 1]),
            "reversed-rows" => rows.reverse(),
            "duplicate-rows" => rows[1] = rows[0].clone(),
            "short-tuple" => {
                slots(&mut slots(&mut rows[0])[4]).pop();
            }
            _ => panic!("unknown negative fixture"),
        }
        negatives.push((label, context(2, None, Some(rows))));
    }
    for (label, model) in negatives {
        let name = format!("context-negative-{label}");
        let published = compare(&name, &model);
        assert!(
            validate_canonical_context(&published).is_err(),
            "syntax rejection: {name}"
        );
    }

    // Declared lengths are bounded by supplied bytes before schema traversal.
    // This tests the syntax seam, without creating any evidence holder.
    let mut huge = vec![0x9b];
    huge.extend([0xff; 8]);
    assert!(validate_canonical_context(&huge).is_err());
}
