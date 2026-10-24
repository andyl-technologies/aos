//! Checks actual canonical full references against the borrowed native comparator.

use super::*;
use crucible_node_format::{ContentRef, U64};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn compare(reference: &ContentRef) -> TestResult {
    let canonical = canonical::canonical_json(&serde_json::to_value(reference)?)?;
    authenticate_canonical_reference_bytes(&canonical, reference)
        .map_err(|failure| failure.reason)?;
    let ordinary = serde_json::to_vec(reference)?;
    assert_ne!(ordinary, canonical);
    assert!(authenticate_canonical_reference_bytes(&ordinary, reference).is_err());
    Ok(())
}

#[test]
fn canonical_full_reference_preserves_hash_order_and_quoted_length() -> TestResult {
    let mut reference = canonical::content_ref(b"actual original bytes", "application/json")?;
    compare(&reference)?;
    reference.length = U64::new(u64::MAX);
    compare(&reference)?;
    Ok(())
}

#[test]
fn canonical_full_reference_refuses_changed_missing_and_extra_fields() -> TestResult {
    let reference = canonical::content_ref(b"actual original bytes", "application/json")?;
    let original = serde_json::to_value(&reference)?;
    for (field, replacement) in [
        ("algorithm", "another"),
        ("digest", "another"),
        ("domain", "another"),
    ] {
        let mut changed = original.clone();
        changed["hash"][field] = serde_json::Value::String(replacement.to_owned());
        let bytes = canonical::canonical_json(&changed)?;
        assert!(authenticate_canonical_reference_bytes(&bytes, &reference).is_err());
    }
    let mut changed = original.clone();
    changed["length"] = serde_json::Value::String("00021".to_owned());
    assert!(
        authenticate_canonical_reference_bytes(&canonical::canonical_json(&changed)?, &reference)
            .is_err()
    );
    changed = original.clone();
    changed["media_type"] = serde_json::Value::String("application/changed".to_owned());
    assert!(
        authenticate_canonical_reference_bytes(&canonical::canonical_json(&changed)?, &reference)
            .is_err()
    );
    changed = original.clone();
    changed["hash"]["extra"] = serde_json::Value::Bool(true);
    assert!(
        authenticate_canonical_reference_bytes(&canonical::canonical_json(&changed)?, &reference)
            .is_err()
    );
    changed = original;
    let Some(fields) = changed.as_object_mut() else {
        return Err("reference is not an object".into());
    };
    fields.remove("length");
    assert!(
        authenticate_canonical_reference_bytes(&canonical::canonical_json(&changed)?, &reference)
            .is_err()
    );
    Ok(())
}
