//! Projects real bootstrap operands before the Initial row exists.
//!
//! The three future Initial decimal strings use U64's actual maximum width,
//! independently of their future values. No row, recipe, digest or permission
//! is invented to break that encoding dependency. Actual immutable recipe and
//! Source operands remain borrowed; custom serializer formatting is separately
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
pub(super) struct PrivateOperands<'a> {
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
    recipe: &PacketNativeImport18PrebirthRecipeData,
    launch: &PacketNative5SourceLaunch,
    private: &PrivateOperands<'_>,
    maximum: usize,
) -> Result<ProspectiveBodyConstructionData, ProviderError> {
    quote(
        &recipe.borrowed_wire_data(),
        &recipe.identity_data(),
        launch,
        private,
        maximum,
    )
}

fn quote(
    recipe: &impl Serialize,
    recipe_identity: &[u8; 32],
    launch: &PacketNative5SourceLaunch,
    private: &PrivateOperands<'_>,
    maximum: usize,
) -> Result<ProspectiveBodyConstructionData, ProviderError> {
    if private.private_key.as_slice().len() != 32 || private.birth_id.as_slice().len() != 32 {
        return Err(invalid());
    }
    let mut recipe_shape = Projection::new(maximum)?;
    recipe_shape.add_value(recipe)?;
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
    selected.add_value(recipe_identity)?;
    initial_row(&mut selected)?;
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
    source_binding(&mut boot, recipe, &private.declaration)?;
    boot.add_value(private.expected_host_registration)?;
    boot.add_value(private.private_launch)?;
    boot.add_value(private.host_executable)?;
    let boot = boot.finish(maximum)?;

    // Closed wrapper/Initial fields cannot introduce a reserved key. The
    // original Source is an opaque Bytes string. Walk the actual typed recipe,
    // launch and Host Value independently, without constructing an outer DOM.
    let recipe_resets = raw_value_reparse::quote_serialized_raw_bound_data(recipe, 0, maximum)?;
    let launch_resets = raw_value_reparse::quote_serialized_raw_bound_data(launch, 1, maximum)?;
    let mut boot_resets = raw_value_reparse::quote_serialized_raw_bound_data(recipe, 2, maximum)?;
    boot_resets.include_data(
        raw_value_reparse::quote_serialized_raw_bound_data(
            private.expected_host_registration,
            1,
            maximum,
        )?,
        maximum,
    )?;
    from_shapes(
        [recipe_shape, selected, boot],
        [recipe_resets, launch_resets, boot_resets],
        maximum,
    )
}

fn initial_row(out: &mut Projection) -> Result<(), ProviderError> {
    out.add_object()?;
    for name in [
        "retained_requested_bytes",
        "maximum_simultaneous_transient_bytes",
        "declared_counter_scratch_bytes",
    ] {
        out.add_field(name)?;
        // Decimal U64 is a JSON string. Only its defining maximum width is
        // projected; no future number or serialized Initial is constructed.
        out.add_unescaped_ascii_extent(u64::MAX.ilog10() as usize + 1)?;
    }
    Ok(())
}

fn source_binding(
    out: &mut Projection,
    recipe: &impl Serialize,
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
    out.add_value(recipe)?;
    initial_row(out)
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
