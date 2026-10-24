//! Preserves the independent original full-launch helper bodies for comparison.

use super::*;

/// Retains the saved original algorithm's digest and projected extent for tests.
pub(super) struct SavedProjection {
    planned: [u8; 32],
    maximum_encoded_bytes: usize,
}

impl SavedProjection {
    pub(super) fn parts_data(&self) -> ([u8; 32], usize) {
        (self.planned, self.maximum_encoded_bytes)
    }
}

pub(super) fn declaration(
    launch: &PacketNative5SourceLaunch,
) -> Result<PacketNativeImport18HelloDeclarationData, ProviderError> {
    if launch.schema_version != 5
        || launch.ack_emitter_selection.is_none()
        || launch.confirmation_selection.is_none()
        || launch.protocol_metadata_limits.is_none()
        || launch.selection.realization.bindings.len() != 1
    {
        return Err(refused());
    }
    declaration_for_selections_data(
        launch.complete_restore_selection,
        launch.capture_allocation_selection.is_some(),
        launch.fresh_restore_allocation_selection.is_some(),
    )
}

fn authenticate_plan_original(
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
) -> Result<(), ProviderError> {
    if *declaration != self::declaration(launch)? {
        return Err(refused());
    }
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let object = planned.as_object().ok_or_else(refused)?;
    if object.len() != FIELDS.len()
        || FIELDS.iter().any(|key| !object.contains_key(*key))
        || text(planned, "schema")? != PLANNED_SCHEMA
        || text(planned, "role")? != "controller"
        || text(planned, "session_id")? != binding.authority.session_id.as_str()
        || text(planned, "incarnation_id")? != binding.authority.incarnation_id.as_str()
        || !Id::is_valid_str(text(planned, "connection_id")?)
    {
        return Err(refused());
    }
    let limits = planned
        .get("limits")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    let actual = [
        launch.limits.frame_bytes,
        launch.limits.nesting,
        launch.limits.requests,
        launch.limits.journal_entries,
        launch.limits.blob_chunk_bytes,
    ];
    if limits.len() != LIMIT_FIELDS.len() {
        return Err(refused());
    }
    for (key, expected) in LIMIT_FIELDS.into_iter().zip(actual) {
        let encoded = limits
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(refused)?;
        if encoded.is_empty()
            || encoded.len() > 20
            || (encoded.len() > 1 && encoded.starts_with('0'))
            || !encoded.bytes().all(|byte| byte.is_ascii_digit())
            || encoded.parse::<u64>().ok() != Some(expected.get())
        {
            return Err(refused());
        }
    }
    let features = planned
        .get("features")
        .and_then(Value::as_array)
        .ok_or_else(refused)?;
    let keys = planned
        .get("envelope_extensions")
        .and_then(Value::as_array)
        .ok_or_else(refused)?;
    if features.len() != declaration.feature_count_data()
        || keys.len() != declaration.key_count_data()
        || planned
            .get("extensions")
            .and_then(Value::as_array)
            .is_none_or(|values| !values.is_empty())
    {
        return Err(refused());
    }
    sorted_strings(features)?;
    sorted_strings(keys)?;
    for feature in features {
        let name = feature.as_str().ok_or_else(refused)?;
        if !declaration
            .features_data()
            .iter()
            .flatten()
            .any(|expected| *expected == name)
        {
            return Err(refused());
        }
    }
    for key in keys {
        let name = key.as_str().ok_or_else(refused)?;
        if !declaration
            .keys_data()
            .iter()
            .flatten()
            .any(|(expected, _)| *expected == name)
        {
            return Err(refused());
        }
    }
    Ok(())
}

pub(super) fn prospective(
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
    maximum: usize,
) -> Result<SavedProjection, ProviderError> {
    authenticate_plan_original(launch, declaration, planned)?;
    let mut projection = Projection::new(maximum)?;
    projection.add_array_extent(10)?;
    projection.add_string(HISTORICAL_SCHEMA)?;
    for key in ["connection_id", "session_id", "incarnation_id"] {
        projection.add_value(planned.get(key).ok_or_else(refused)?)?;
    }
    projection.add_unescaped_ascii_extent(20)?;
    projection.add_value(&launch.limits)?;
    projection.add_value(planned.get("features").ok_or_else(refused)?)?;
    projection.add_value(planned.get("envelope_extensions").ok_or_else(refused)?)?;
    projection.add_array_extent(0)?;
    projection.add_string(BACKING_MARKER)?;
    let projected = projection.finish(maximum)?;
    Ok(SavedProjection {
        planned: planned_identity(planned)?,
        maximum_encoded_bytes: projected.maximum_encoded_bytes,
    })
}

pub(super) fn authenticate_saved(
    saved: &PacketNativeImport18ProspectiveHostRegistrationData,
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
) -> Result<(), ProviderError> {
    authenticate_plan_original(launch, declaration, planned)?;
    if saved.planned_identity_data() != planned_identity(planned)? {
        return Err(refused());
    }
    Ok(())
}

// Only known validated strings/arrays participate. Each length-delimited field
// is committed in its defining order; no canonical DOM/formatter is allocated.
fn planned_identity(planned: &Value) -> Result<[u8; 32], ProviderError> {
    let mut hash = blake3::Hasher::new_derive_key("native-import18.planned-registration/1");
    for key in [
        "schema",
        "role",
        "connection_id",
        "session_id",
        "incarnation_id",
    ] {
        include(&mut hash, text(planned, key)?.as_bytes())?;
    }
    for key in LIMIT_FIELDS {
        include(
            &mut hash,
            planned
                .get("limits")
                .and_then(|limits| limits.get(key))
                .and_then(Value::as_str)
                .ok_or_else(refused)?
                .as_bytes(),
        )?;
    }
    for key in ["features", "envelope_extensions", "extensions"] {
        let values = planned
            .get(key)
            .and_then(Value::as_array)
            .ok_or_else(refused)?;
        hash.update(
            &u64::try_from(values.len())
                .map_err(|_| refused())?
                .to_be_bytes(),
        );
        for value in values {
            include(&mut hash, value.as_str().ok_or_else(refused)?.as_bytes())?;
        }
    }
    Ok(*hash.finalize().as_bytes())
}

fn include(hash: &mut blake3::Hasher, value: &[u8]) -> Result<(), ProviderError> {
    hash.update(
        &u64::try_from(value.len())
            .map_err(|_| refused())?
            .to_be_bytes(),
    );
    hash.update(value);
    Ok(())
}
