//! Exercises complete borrowed snapshot identity and pre-allocation credit.
//!
//! These data controls establish no runtime/native authority or original handle.

use super::*;
use serde::Serialize;
use std::cell::Cell;

fn snapshot() -> serde_json::Value {
    serde_json::json!([
        "crucible.original-quantized-completion.v1",
        {"window": "original", "budget": 17},
        {"activation": "original", "owners": ["source", "consumer"]},
        {"batch": "original", "payload": [0, 255]},
        {"ack": "original", "bodies": [[0, 1, 255]], "edges": [[0, 1]]},
        {"reached": 3, "output": [7, 8]},
        false
    ])
}

#[test]
fn complete_snapshot_retains_every_original_scope_field() -> Result<(), QualificationError> {
    let original = snapshot();
    let bytes = current_snapshot(&original, 4096)?;
    assert_eq!(bytes, current_snapshot(&original, bytes.len())?);

    for index in 1..7 {
        let mut changed = snapshot();
        changed[index] = serde_json::json!("foreign");
        assert_ne!(bytes, current_snapshot(&changed, 4096)?);
    }
    Ok(())
}

#[test]
fn native_body_and_direct_edge_changes_remain_distinct() -> Result<(), QualificationError> {
    let original = snapshot();
    let bytes = current_snapshot(&original, 4096)?;
    let mut body = snapshot();
    body[4]["bodies"][0][2] = serde_json::json!(254);
    let mut edges = snapshot();
    edges[4]["edges"][0][1] = serde_json::json!(2);

    assert_ne!(bytes, current_snapshot(&body, 4096)?);
    assert_ne!(bytes, current_snapshot(&edges, 4096)?);
    Ok(())
}

#[test]
fn exact_family_and_full_ack_disposition_remain_distinct() -> Result<(), QualificationError> {
    let original = snapshot();
    let bytes = current_snapshot(&original, 4096)?;
    let mut changed = snapshot();
    changed[0] = serde_json::json!("crucible.original-exact-completion.v1");
    assert_ne!(bytes, current_snapshot(&changed, 4096)?);

    changed = snapshot();
    changed[6] = serde_json::json!(true);
    assert_ne!(bytes, current_snapshot(&changed, 4096)?);
    Ok(())
}

struct BoundedOriginal<'a>(&'a Cell<usize>);

impl Serialize for BoundedOriginal<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.set(self.0.get() + 1);
        serializer.serialize_str("original full body exceeds tiny credit")
    }
}

#[test]
fn insufficient_credit_refuses_before_second_value_serialization() {
    let calls = Cell::new(0);
    assert!(current_snapshot(&BoundedOriginal(&calls), 1).is_err());
    assert_eq!(calls.get(), 1);
}
