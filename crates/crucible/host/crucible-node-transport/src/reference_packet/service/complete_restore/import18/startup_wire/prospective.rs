//! Projects real bootstrap operands before the Initial row exists.
//!
//! The complete fixed recipe grammar, future commitments and Initial decimals
//! use their defining maximum widths before any of those values exist. No row,
//! recipe, digest or permission is invented to break that encoding dependency.
//! Actual launch and Source
//! operands remain borrowed; custom serializer formatting is separately
//! admitted before these walks.

use super::*;
use crate::protocol_snapshot::raw_value_reparse::{
    self, JsonValueReparseConstructionData as Resets,
};
use crate::retained_metadata::{
    BootstrapBodyMetadataProfileData,
    serialization_storage::{
        OriginalSerializationStorageData as Shape,
        OriginalSerializationStorageProjection as Projection,
        original_json_value_storage_population_data, original_serialization_counter_scratch_data,
    },
};

/// Borrows the actual private operands without a future Source wrapper or row.
pub(in crate::reference_packet) struct PrivateOperands<'a> {
    pub(super) declaration: PacketNativeImport18SourceDeclarationView<'a>,
    pub(super) private_key: &'a Bytes,
    pub(super) birth_id: &'a Bytes,
    pub(super) expected_host_registration: &'a Value,
    pub(super) private_launch: &'a Id,
    pub(super) host_executable: &'a ContentRef,
}

/// Retains independently derived body ceilings and native parser demand as DATA.
pub(super) struct ProspectiveBodyConstructionData {
    pub(super) maximum_encoded_bytes: [usize; 3],
    pub(super) parser_rows: [[usize; 3]; 3],
}

/// Quotes real immutable operands without constructing an Initial result.
///
/// Callers admit custom launch/Host formatters and the fixed counter first.
/// The complete Initial producer must add the physical Bootstrap18, seven-bank
/// headers and simultaneous owners. These parser rows alone grant no admission.
///
/// # Errors
/// Refuses invalid key/birth lengths, unsupported actual serializer populations,
/// arithmetic overflow or complete parser demand above the restriction.
pub(super) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    private: &PrivateOperands<'_>,
    maximum: usize,
) -> Result<ProspectiveBodyConstructionData, ProviderError> {
    if private.private_key.as_slice().len() != 32 || private.birth_id.as_slice().len() != 32 {
        return Err(invalid());
    }
    let mut recipe_shape = Projection::new(maximum)?;
    native_import18_prebirth_recipe_projection_data(&mut recipe_shape)?;
    let recipe_shape = recipe_shape.finish(maximum)?;

    let mut selected = Projection::new(maximum)?;
    selected.add_object()?;
    for name in [
        "schema_version",
        "mechanism",
        "launch",
        "prebirth_recipe_identity",
        "initial_funding",
    ] {
        selected.add_field(name)?;
    }
    selected.add_value(&9u16)?;
    selected.add_value(&PacketNativeImport18Selection::SourceSignedImport18)?;
    selected.add_value(launch)?;
    native_import18_recipe_identity_projection_data(&mut selected)?;
    native_import18_initial_row_projection_data(&mut selected)?;
    let selected = selected.finish(maximum)?;

    let mut boot = Projection::new(maximum)?;
    boot.add_object()?;
    for name in [
        "schema",
        "private_key",
        "birth_id",
        "source_birth",
        "expected_host_registration",
        "private_launch",
        "host_executable",
    ] {
        boot.add_field(name)?;
    }
    boot.add_string(NATIVE_IMPORT18_PRIVATE_BOOT_SCHEMA)?;
    boot.add_value(private.private_key)?;
    boot.add_value(private.birth_id)?;
    source_binding(&mut boot, &private.declaration)?;
    boot.add_value(private.expected_host_registration)?;
    boot.add_value(private.private_launch)?;
    boot.add_value(private.host_executable)?;
    let boot = boot.finish(maximum)?;

    // The exhaustive fixed recipe grammar contains no Value/RawValue leaves.
    // Only the actual Launch and Host Value can introduce reserved keys. The
    // original Source remains an opaque Bytes leaf throughout this projection.
    let launch_resets = raw_value_reparse::quote_serialized_raw_bound_data(launch, 1, maximum)?;
    let boot_resets = raw_value_reparse::quote_serialized_raw_bound_data(
        private.expected_host_registration,
        1,
        maximum,
    )?;
    from_shapes(
        [recipe_shape, selected, boot],
        [Resets::default(), launch_resets, boot_resets],
        maximum,
    )
}

fn source_binding(
    out: &mut Projection,
    declaration: &PacketNativeImport18SourceDeclarationView<'_>,
) -> Result<(), ProviderError> {
    out.add_object()?;
    for name in [
        "schema",
        "declaration",
        "mechanism",
        "prebirth_recipe",
        "initial_funding",
    ] {
        out.add_field(name)?;
    }
    out.add_string(NATIVE_IMPORT18_SOURCE_BINDING_SCHEMA)?;
    native_import18_source_declaration_projection_data(out, declaration)?;
    out.add_value(&PacketNativeImport18Selection::SourceSignedImport18)?;
    native_import18_prebirth_recipe_projection_data(out)?;
    native_import18_initial_row_projection_data(out)
}

fn from_shapes(
    shapes: [Shape; 3],
    resets: [Resets; 3],
    maximum: usize,
) -> Result<ProspectiveBodyConstructionData, ProviderError> {
    let geometry = private_body_typed_geometry_data();
    let partials = private_body_typed_partials_data();
    let mut maximum_encoded_bytes = [0; 3];
    let mut parser_rows = [[0; 3]; 3];
    for index in 0..3 {
        let shape = &shapes[index];
        // Every map key and object root owns a capacity record. This covers
        // the native lexical counter's entries-plus-empty-roots population.
        // Encoded bytes independently bound decoded text and escaped spelling.
        let mut raw = original_json_value_storage_population_data(
            shape.serialized_value_nodes,
            shape.serialized_capacity_records,
            shape.maximum_encoded_bytes,
        )?;
        raw.declared_counter_scratch_bytes =
            crate::reference_packet::service::native_startup::raw_json_extent_counter_scratch_data(
            );
        let mut row = super::decoding::body_population(
            &raw,
            &resets[index],
            shape.maximum_encoded_bytes,
            geometry[index],
            partials[index],
            maximum,
        )?;
        let profile = BootstrapBodyMetadataProfileData::from_populations_data(
            raw.maximum_value_nodes,
            raw.maximum_object_members,
            &resets[index],
        )?;
        row[2] = row[2]
            .checked_add(profile.walk_scratch_data()?)
            .and_then(|n| n.checked_add(private_body_owner_counter_scratch_data()))
            .ok_or_else(exhausted)?;
        if row
            .into_iter()
            .try_fold(0usize, |total, n| total.checked_add(n))
            .is_none_or(|n| n > maximum)
        {
            return Err(exhausted());
        }
        maximum_encoded_bytes[index] = shape.maximum_encoded_bytes;
        parser_rows[index] = row;
    }
    Ok(ProspectiveBodyConstructionData {
        maximum_encoded_bytes,
        parser_rows,
    })
}

/// Names the actual borrowed projections, reset scans and returned DATA views.
pub(super) fn counter_scratch_data() -> usize {
    original_serialization_counter_scratch_data()
        + native_import18_recipe_projection_counter_scratch_data()
        + raw_value_reparse::serialized_scanner_counter_scratch_data()
        + raw_value_reparse::value_scanner_counter_scratch_data()
        + private_body_decode_counter_scratch_data()
        + private_body_owner_counter_scratch_data()
        + size_of::<Projection>() * 3
        + size_of::<[Shape; 3]>()
        + size_of::<[Resets; 3]>()
        + size_of::<PrivateOperands<'static>>()
        + size_of::<ProspectiveBodyConstructionData>()
        + size_of::<Result<ProspectiveBodyConstructionData, ProviderError>>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<[[usize; 3]; 3]>()
        + size_of::<[&str; 7]>()
        + size_of::<std::array::IntoIter<&str, 7>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<usize>() * 3
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("prospective original import18 body construction")
}

#[cfg(test)]
#[path = "prospective/tests.rs"]
mod tests;
