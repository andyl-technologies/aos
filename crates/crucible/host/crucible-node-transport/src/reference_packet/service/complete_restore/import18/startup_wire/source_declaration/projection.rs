//! Projects the actual declaration's raw-Source Bytes without invoking its codec.
//!
//! The raw bank remains borrowed from the genuine BodyPlan owner. This child
//! prices serializer DATA only and cannot prove that bank's origin or launch.

use super::*;
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData as Shape,
    OriginalSerializationStorageProjection as Projection,
    original_serialization_counter_scratch_data,
};
use std::mem::size_of;

/// Returns the exact temporary String length of the unchanged Bytes serializer.
///
/// # Errors
/// Refuses overflow in unpadded base64's defining encoded-length calculation.
pub(in crate::reference_packet) fn native_import18_source_declaration_formatter_requested_data(
    declaration: &PacketNativeImport18SourceDeclarationView<'_>,
) -> Result<usize, ProviderError> {
    base64::encoded_len(declaration.source_birth.as_slice().len(), false).ok_or_else(exhausted)
}

/// Adds the actual declaration's complete three fields without allocating.
///
/// The Bytes leaf is projected as its exact unpadded ASCII extent. The caller
/// separately admits that formatter's returned temporary and fixed controls.
///
/// # Errors
/// Refuses encoded-length overflow or the projection's independent restriction.
pub(in crate::reference_packet) fn native_import18_source_declaration_projection_data(
    out: &mut Projection,
    declaration: &PacketNativeImport18SourceDeclarationView<'_>,
) -> Result<(), ProviderError> {
    let PacketNativeImport18SourceDeclarationView {
        schema,
        source_birth: _,
        fresh_restore_allocation_selection,
    } = declaration;
    out.add_object()?;
    for field in [
        "schema",
        "source_birth",
        "fresh_restore_allocation_selection",
    ] {
        out.add_field(field)?;
    }
    out.add_string(schema)?;
    out.add_unescaped_ascii_extent(native_import18_source_declaration_formatter_requested_data(
        declaration,
    )?)?;
    out.add_value(fresh_restore_allocation_selection)
}

/// Returns the complete defining shape with its independent Bytes temporary.
///
/// # Errors
/// Refuses checked geometry overflow or the complete shape above the restriction.
pub(in crate::reference_packet) fn native_import18_source_declaration_serialization_data(
    declaration: &PacketNativeImport18SourceDeclarationView<'_>,
    maximum: usize,
) -> Result<Shape, ProviderError> {
    let mut out = Projection::new(maximum)?;
    native_import18_source_declaration_projection_data(&mut out, declaration)?;
    let mut shape = out.finish(maximum)?;
    shape.serializer_temporary_requested_bytes = shape.serializer_temporary_requested_bytes.max(
        native_import18_source_declaration_formatter_requested_data(declaration)?,
    );
    if shape.requested_total()? > maximum {
        return Err(exhausted());
    }
    Ok(shape)
}

/// Names direct quote states; actual Bytes execution has its defining codec S.
pub(in crate::reference_packet) fn native_import18_source_declaration_projection_counter_scratch_data()
-> usize {
    original_serialization_counter_scratch_data()
        + size_of::<Projection>()
        + size_of::<Result<Projection, ProviderError>>()
        + size_of::<&mut Projection>()
        + size_of::<Shape>()
        + size_of::<Result<Shape, ProviderError>>()
        + size_of::<&PacketNativeImport18SourceDeclarationView<'static>>()
        + size_of::<&Option<PacketNative5FreshRestoreAllocationSelection>>()
        + size_of::<[&str; 3]>()
        + size_of::<std::array::IntoIter<&'static str, 3>>()
        + size_of::<&str>()
        + size_of::<Option<usize>>()
        + size_of::<usize>() * 3
        + size_of::<bool>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native import18 declaration projection")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_raw_source_bytes_have_the_same_unpadded_extent_and_value_shape() {
        for length in [1, 2, 3, 4, 31, 32, 33, 4096] {
            let raw = Bytes::new(vec![255; length]);
            // This private serializer view is inert DATA, not a genuine Source.
            let view = PacketNativeImport18SourceDeclarationView {
                schema: NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA,
                source_birth: &raw,
                fresh_restore_allocation_selection: None,
            };
            let value = serde_json::to_value(view).unwrap();
            let actual_encoded = value["source_birth"].as_str().unwrap();
            let formatter =
                native_import18_source_declaration_formatter_requested_data(&view).unwrap();
            let shape =
                native_import18_source_declaration_serialization_data(&view, usize::MAX / 16)
                    .unwrap();
            let bytes = canonical::canonical_json(&value).unwrap();
            assert_eq!(formatter, actual_encoded.len());
            assert!(shape.serializer_temporary_requested_bytes >= formatter);
            assert!(shape.maximum_encoded_bytes >= bytes.len());
            assert!(native_import18_source_declaration_serialization_data(&view, 1).is_err());
        }
    }
}
