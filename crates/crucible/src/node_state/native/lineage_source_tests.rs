//! Tests closed coordinator selection without manufacturing native source seals.

use super::*;

fn coordinator() -> Result<OriginalLineageCoordinator, StateError> {
    Ok(OriginalLineageCoordinator {
        schema_version: 7,
        runtime: canonical::content_ref(
            b"bounded inert Runtime7 fixture",
            ORIGINAL_LINEAGE_RUNTIME_MEDIA,
        )
        .map_err(super::super::super::schema)?,
        scheduler: canonical::content_ref(b"bounded inert scheduler fixture", "application/json")
            .map_err(super::super::super::schema)?,
        world_repeatability: Repeatability::Nondeterministic,
    })
}

#[test]
fn coordinator7_preserves_original_nondeterminism_and_full_typed_roles() -> Result<(), StateError> {
    let original = coordinator()?;
    original.validate()?;
    let bytes = canonical::canonical_json(
        &serde_json::to_value(&original).map_err(super::super::super::schema)?,
    )
    .map_err(super::super::super::schema)?;
    let decoded: OriginalLineageCoordinator =
        serde_json::from_slice(&bytes).map_err(super::super::super::schema)?;
    assert_eq!(decoded, original);
    assert_eq!(decoded.world_repeatability, Repeatability::Nondeterministic);
    Ok(())
}

#[test]
fn coordinator7_refuses_legacy_media_and_qualified_origin() -> Result<(), StateError> {
    let original = coordinator()?;
    for changed in ["edition", "runtime", "scheduler", "repeatability"] {
        let mut counterexample = original.clone();
        match changed {
            "edition" => counterexample.schema_version = 1,
            "runtime" => counterexample.runtime.media_type = "application/json".into(),
            "scheduler" => {
                counterexample.scheduler.media_type = ORIGINAL_LINEAGE_RUNTIME_MEDIA.into()
            }
            _ => counterexample.world_repeatability = Repeatability::Qualified,
        }
        assert!(counterexample.validate().is_err(), "accepted {changed}");
    }
    Ok(())
}

#[test]
fn coordinator7_requires_both_reference_fields_and_closed_keys() -> Result<(), StateError> {
    let original = coordinator()?;
    let value = serde_json::to_value(&original).map_err(super::super::super::schema)?;
    for field in ["runtime", "scheduler", "world_repeatability"] {
        let mut incomplete = value.clone();
        if let Some(object) = incomplete.as_object_mut() {
            object.remove(field);
        }
        assert!(serde_json::from_value::<OriginalLineageCoordinator>(incomplete).is_err());
    }
    let mut unexpected = value;
    if let Some(object) = unexpected.as_object_mut() {
        object.insert("first_scope".into(), serde_json::Value::Null);
    }
    assert!(serde_json::from_value::<OriginalLineageCoordinator>(unexpected).is_err());
    Ok(())
}
