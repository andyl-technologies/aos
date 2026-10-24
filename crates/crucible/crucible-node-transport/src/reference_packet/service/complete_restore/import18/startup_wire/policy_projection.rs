//! Projects the actual decoded SourceBinding18 without formatting its Bytes.
//!
//! The full announcement and initial row remain inert original DATA. This walk
//! neither copies their owner nor creates an opaque recipe or startup allowance.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageProjection as Projection,
    original_serialization_counter_scratch_data,
};

/// Adds every actual decoded Source binding field without constructing a DOM.
///
/// # Errors
/// Refuses checked projection overflow or an independently short restriction.
pub(in crate::reference_packet) fn native_import18_source_binding_wire_projection_data(
    out: &mut Projection,
    binding: &PacketNativeImport18SourceBindingWireData,
) -> Result<(), ProviderError> {
    let PacketNativeImport18SourceBindingWireData {
        schema: SourceSchema::Import18,
        declaration,
        mechanism,
        prebirth_recipe,
        initial_funding,
    } = binding;
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
    native_import18_source_declaration_projection_data(out, &declaration.borrowed_wire_data())?;
    out.add_value(mechanism)?;
    // RecipeWire24 owns only fixed arrays, enums and scalars. In particular it
    // contains no Bytes leaf whose formatter could allocate during projection.
    out.add_value(prebirth_recipe)?;
    out.add_value(initial_funding)
}

/// Quotes the actual decoded declaration's sequential base64 formatter bank.
///
/// # Errors
/// Refuses overflow in the original Source bank's encoded length.
pub(in crate::reference_packet) fn native_import18_source_binding_wire_formatter_requested_data(
    binding: &PacketNativeImport18SourceBindingWireData,
) -> Result<usize, ProviderError> {
    native_import18_source_declaration_formatter_requested_data(
        &binding.declaration.borrowed_wire_data(),
    )
}

/// Names direct wire/declaration projection controls beside dynamic serializer work.
pub(in crate::reference_packet) fn native_import18_source_binding_wire_projection_counter_scratch_data()
-> usize {
    original_serialization_counter_scratch_data()
        + native_import18_source_declaration_projection_counter_scratch_data()
        + native_import18_recipe_projection_counter_scratch_data()
        + size_of::<&PacketNativeImport18SourceBindingWireData>()
        + size_of::<PacketNativeImport18SourceDeclarationView<'static>>()
        + size_of::<&mut Projection>()
        + size_of::<[&str; 5]>()
        + size_of::<std::array::IntoIter<&'static str, 5>>()
        + size_of::<&PacketNativeImport18PrebirthRecipeWireData>()
        + size_of::<&PacketNativeStartupAllocationRow>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
}
