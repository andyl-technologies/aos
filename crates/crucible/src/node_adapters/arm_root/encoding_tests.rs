//! Exercises finite common-record geometry without constructing native authority.

// crucible-lint: allow panic-shortcut -- These data-only geometry fixtures panic when canonical bytes or finite credit invariants change.
#![allow(clippy::unwrap_used)]

use super::encoding::record;
use crucible_node_contract::canonical;
use serde_json::json;

#[test]
fn canonical_record_preserves_exact_unicode_and_number_geometry() {
    let value = json!({
        "unicode": "λ\n\"\\",
        "scalar": 1.0e30,
        "arrays": [null, false, true, {"z":0,"a":-17}],
    });
    let expected = canonical::canonical_json(&value).unwrap();
    let serialized = serde_json::to_vec(&value).unwrap();
    let credit = expected.len().max(serialized.len());

    assert_eq!(record(&value, credit).unwrap(), expected);
    assert!(record(&value, credit - 1).is_err());
}

#[test]
fn canonical_record_refuses_number_expansion_beyond_reserved_body() {
    let value = json!({"number": 1.0e20});
    let ordinary = serde_json::to_vec(&value).unwrap();
    let canonical = canonical::canonical_json(&value).unwrap();
    assert!(canonical.len() > ordinary.len());

    let failure = record(&value, ordinary.len()).unwrap_err();

    assert!(failure.reason.contains("reserved body budget"));
    assert_eq!(failure.effects, crate::node_contract::EffectKnowledge::None);
    assert_eq!(record(&value, canonical.len()).unwrap(), canonical);
}

#[test]
fn canonical_record_refuses_nested_container_before_final_body() {
    let mut value = json!(0);
    for _ in 0..65 {
        value = json!([value]);
    }

    assert!(record(&value, 4096).is_err());
}
