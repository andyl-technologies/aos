//! Literal legacy wire and bounded condition-body inventory regressions.
//!
//! These data-only fixtures issue no native, source or preservation authority.

use crucible_node_contract::canonical;

use super::*;

const LEGACY: &str = concat!(
    "{\"schema_version\":1,\"source_activation\":{\"generation\":\"1\",",
    "\"activation_id\":\"original\",\"world_binding_hash\":{",
    "\"algorithm\":\"blake3-256\",\"domain\":\"model-only\",",
    "\"digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},",
    "\"owners\":[],\"boundary\":{\"time_ps\":\"0\",\"microstep\":\"0\",\"phase\":0}},",
    "\"capture_cut\":{\"time_ps\":\"100\",\"microstep\":\"0\",\"phase\":0},",
    "\"capture_ordinal\":\"7\",\"owners\":[],\"operations\":[],\"inputs\":[]}"
);

#[test]
fn condition_wire_keeps_literal_legacy_editions_one_through_four_exact()
-> Result<(), Box<dyn std::error::Error>> {
    for edition in 1..=4 {
        let literal = LEGACY.replacen(
            "\"schema_version\":1",
            &format!("\"schema_version\":{edition}"),
            1,
        );
        let decoded: RuntimeSnapshot = serde_json::from_str(&literal)?;
        assert_eq!(decoded.schema_version, edition);
        assert!(decoded.condition_stop.is_none());
        assert_eq!(serde_json::to_string(&decoded)?, literal);
    }
    Ok(())
}

#[test]
fn condition_wire_rejects_legacy_unknown_fields_and_duplicate_versions() {
    let injected = format!("{},\"condition_stop\":null}}", &LEGACY[..LEGACY.len() - 1]);
    assert!(serde_json::from_str::<RuntimeSnapshot>(&injected).is_err());

    let repeated = LEGACY.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    assert!(serde_json::from_str::<RuntimeSnapshot>(&repeated).is_err());

    let unsupported = LEGACY.replacen("\"schema_version\":1", "\"schema_version\":6", 1);
    assert!(serde_json::from_str::<RuntimeSnapshot>(&unsupported).is_err());
}

#[test]
fn condition_wire_retains_shared_actual_body_once_and_refuses_metadata_alias()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = vec![0x51; 65_537];
    let reference = canonical::content_ref(&bytes, "application/octet-stream")?;
    let body = InputPayload {
        reference: reference.clone(),
        bytes,
    };
    let mut pool = BodyPool::default();

    for _ in 0..16 {
        assert_eq!(pool.retain(&body)?, reference);
    }
    assert_eq!(pool.references.len(), 1);
    assert_eq!(pool.bytes, 65_537);

    let mut alias = body.clone();
    alias.reference.media_type = "application/json".to_owned();
    assert!(pool.retain(&alias).is_err());
    assert_eq!(pool.references.len(), 1);
    assert_eq!(pool.bytes, 65_537);
    Ok(())
}

#[test]
fn condition_wire_repeated_references_are_bounded_before_body_expansion()
-> Result<(), Box<dyn std::error::Error>> {
    let bytes = vec![0x5a; 1 << 20];
    let reference = canonical::content_ref(&bytes, "application/octet-stream")?;
    let body = InputPayload {
        reference: reference.clone(),
        bytes,
    };
    let bodies = BTreeMap::from([(reference.clone(), body)]);
    let mut expanded = ExpansionBudget::default();

    for _ in 0..64 {
        expanded.reference(&reference, &bodies)?;
    }
    assert_eq!(expanded.bytes, MAXIMUM_BYTES);
    assert!(matches!(
        expanded.reference(&reference, &bodies),
        Err(RuntimeError::ResourceLimit)
    ));
    assert_eq!(expanded.entries, 64);
    assert_eq!(expanded.bytes, MAXIMUM_BYTES);
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[&reference].bytes.len(), 1 << 20);
    Ok(())
}

#[test]
fn condition_wire_repeated_zero_length_associations_have_finite_entry_credit()
-> Result<(), Box<dyn std::error::Error>> {
    let reference = canonical::content_ref(&[], "application/octet-stream")?;
    let bodies = BTreeMap::from([(
        reference.clone(),
        InputPayload {
            reference: reference.clone(),
            bytes: Vec::new(),
        },
    )]);
    let mut expanded = ExpansionBudget::default();

    for _ in 0..MAXIMUM_OBJECTS {
        expanded.reference(&reference, &bodies)?;
    }
    assert!(matches!(
        expanded.reference(&reference, &bodies),
        Err(RuntimeError::ResourceLimit)
    ));
    assert_eq!(expanded.entries, MAXIMUM_OBJECTS);
    assert_eq!(expanded.bytes, 0);
    Ok(())
}

#[test]
fn condition_wire_expansion_credit_refuses_missing_bodies_and_overflow()
-> Result<(), Box<dyn std::error::Error>> {
    let reference = canonical::content_ref(&[1], "application/octet-stream")?;
    let mut expanded = ExpansionBudget::default();

    assert!(matches!(
        expanded.reference(&reference, &BTreeMap::new()),
        Err(RuntimeError::InvalidReceipt)
    ));
    assert!(matches!(
        expanded.charge(usize::MAX, 0),
        Err(RuntimeError::ResourceLimit)
    ));
    assert!(matches!(
        expanded.charge(1, usize::MAX),
        Err(RuntimeError::ResourceLimit)
    ));
    assert_eq!(expanded.entries, 0);
    assert_eq!(expanded.bytes, 0);
    Ok(())
}
