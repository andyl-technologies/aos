//! Projects the exact declared negotiation and native registration before Birth.
//!
//! These shapes use the same private finite roster as the true native Hello
//! constructor. An empty typed selection is the actual new constructor's choice;
//! no future authority, lease, epoch, PID or granted row is synthesized.

use super::*;
use crate::handshake::Limits;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData as Shape,
    OriginalSerializationStorageProjection as Projection,
    original_serialization_counter_scratch_data,
};

/// Projects negotiated4 and native Registration9 from the same genuine launch.
///
/// The order is negotiated policy fields, native registration. The caller
/// independently binds the immutable launch and actual Host plan to its birth
/// occurrence; these shapes supply no permission. Native later checks its real
/// current operands and fits their independently recomputed materialization.
///
/// # Errors
/// Refuses another declaration, changed sole target, overflow or insufficient
/// restriction for either full projection.
pub(in crate::reference_packet) fn native_import18_hello_normalization_projection_data(
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
    maximum: usize,
) -> Result<[Shape; 2], ProviderError> {
    let mut negotiated = Projection::new(maximum)?;
    native_import18_hello_negotiated_projection_data(&mut negotiated, launch, declaration)?;
    let negotiated = negotiated.finish(maximum)?;

    let mut registration = Projection::new(maximum)?;
    super::registration::prospective_native_registration_projection_data(
        &mut registration,
        launch,
        declaration,
    )?;
    Ok([negotiated, registration.finish(maximum)?])
}

/// Adds the exact prospective negotiated4 fields to a larger policy projection.
///
/// # Errors
/// Refuses another actual launch declaration or checked projection overflow.
pub(in crate::reference_packet) fn native_import18_hello_negotiated_projection_data(
    out: &mut Projection,
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
) -> Result<(), ProviderError> {
    if *declaration != native_import18_hello_declaration_data(launch)? {
        return Err(refused());
    }
    out.add_object()?;
    for field in ["limits", "features", "extensions", "envelope_extensions"] {
        out.add_field(field)?;
    }
    out.add_value(&launch.limits)?;
    project_features_data(out, declaration)?;
    out.add_array_extent(0)?;
    project_keys_data(out, declaration)
}

/// Adds native Registration9 from the same independently bound target declaration.
///
/// # Errors
/// Refuses another declaration, changed sole target or projection overflow.
pub(in crate::reference_packet) fn native_import18_hello_registration_projection_data(
    out: &mut Projection,
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
) -> Result<(), ProviderError> {
    if *declaration != native_import18_hello_declaration_data(launch)? {
        return Err(refused());
    }
    super::registration::prospective_native_registration_projection_data(out, launch, declaration)
}

pub(super) fn project_features_data(
    out: &mut Projection,
    declaration: &PacketNativeImport18HelloDeclarationData,
) -> Result<(), ProviderError> {
    out.add_array_extent(declaration.feature_count)?;
    for feature in declaration.features.iter().flatten() {
        out.add_string(feature)?;
    }
    Ok(())
}

pub(super) fn project_keys_data(
    out: &mut Projection,
    declaration: &PacketNativeImport18HelloDeclarationData,
) -> Result<(), ProviderError> {
    out.add_array_extent(declaration.key_count)?;
    for (key, _) in declaration.keys.iter().flatten() {
        out.add_string(key)?;
    }
    Ok(())
}

/// Names actual finite-array walks and direct prospective serialization states.
pub(in crate::reference_packet) fn native_import18_hello_projection_counter_scratch_data() -> usize
{
    PacketNativeImport18HelloDeclarationData::declaration_counter_scratch_data()
        + original_serialization_counter_scratch_data()
        + size_of::<Projection>() * 2
        + size_of::<Result<Projection, ProviderError>>()
        + size_of::<[Shape; 2]>()
        + size_of::<Result<[Shape; 2], ProviderError>>()
        + size_of::<Result<Shape, ProviderError>>()
        + size_of::<&mut Projection>() * 3
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&PacketNativeImport18HelloDeclarationData>()
        + size_of::<[&str; 4]>()
        + size_of::<std::array::IntoIter<&'static str, 4>>()
        + size_of::<[&str; 9]>()
        + size_of::<std::array::IntoIter<&'static str, 9>>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<&'static str>>>>()
        + size_of::<
            std::iter::Flatten<std::slice::Iter<'static, Option<(&'static str, &'static str)>>>,
        >()
        + size_of::<std::slice::Iter<'static, Option<&'static str>>>()
        + size_of::<std::slice::Iter<'static, Option<(&'static str, &'static str)>>>()
        + size_of::<Option<&'static Option<&'static str>>>()
        + size_of::<Option<&'static Option<(&'static str, &'static str)>>>()
        + size_of::<Option<&'static str>>()
        + size_of::<Option<(&'static str, &'static str)>>()
        + size_of::<&&str>()
        + size_of::<&str>() * 3
        + size_of::<&crucible_node_contract::NodeBinding>()
        + size_of::<&[crucible_node_contract::NodeBinding]>()
        + size_of::<&Limits>()
        + size_of::<&Id>() * 2
        + size_of::<usize>()
        + size_of::<Result<(), ProviderError>>()
}
