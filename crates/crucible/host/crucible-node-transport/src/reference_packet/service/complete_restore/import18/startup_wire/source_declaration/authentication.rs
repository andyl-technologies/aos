//! Prices the actual unchanged Source-bank parser and launch correspondence.
//!
//! The original Source bytes remain opaque until this separately admitted
//! native-side DATA check. It retains no model or Source purpose and never
//! treats a matching declaration as a genuine Birth or native admission.

use super::*;
use crate::retained_metadata::{
    observe_retained_native_launch, retained_native_launch_counter_scratch_data,
    serialization_storage::{
        OriginalSerializationStorageData as Shape,
        OriginalSerializationStorageProjection as Projection,
        original_json_value_storage_extent_counter_scratch_data,
        original_json_value_storage_extent_data, original_serialization_counter_scratch_data,
        original_serialization_formatter_temporary_storage_data,
        original_serialization_frame_counter_scratch_data,
    },
};

/// Quotes actual Source parsing, canonical equality and typed launch comparisons.
///
/// Callers admit `source_authentication_quote_construction_data` first, then the returned
/// complete row before invoking `authenticate_launch_data`. Original raw/typed
/// bootstrap owners remain independently charged. The returned R retains a
/// possible failed diagnostic, not a parsed Source model or admission.
///
/// # Errors
/// Refuses unsupported actual raw/launch populations, checked layout overflow or
/// a complete construction above the independent restriction.
pub(in crate::reference_packet) fn source_authentication_construction_data(
    declaration: &PacketNativeImport18SourceDeclarationWireData,
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    for_bank_length(
        declaration.source_birth_data().as_slice().len(),
        launch,
        maximum,
    )
}

/// Projects the identical check while leaving the genuine parent bank opaque.
///
/// # Errors
/// Refuses actual launch/length geometry overflow or insufficient restriction.
pub(in crate::reference_packet) fn source_authentication_projection_data(
    declaration: &PacketNativeImport18SourceDeclarationView<'_>,
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    for_bank_length(declaration.source_birth.len(), launch, maximum)
}

fn for_bank_length(
    length: usize,
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    // Both sides use the same lexical worst case from the actual bank length.
    // The parent never scans or parses its opaque worker response to quote the
    // native check. Real Value/Vec/tree/JCS layouts are applied independently.
    let raw = original_json_value_storage_extent_data(length)?;
    let facts = observe_retained_native_launch(launch)?;
    let formatter = original_serialization_formatter_temporary_storage_data(&facts)?;
    let mut fields = Projection::new(maximum)?;
    fields.add_value(launch)?;
    let fields = fields.finish(maximum)?;

    // Each equal() serializes one actual launch field, then releases its Value
    // before the next field. The complete launch forest conservatively covers
    // all those child backings and the separately canonicalized coordinator.
    // The original Source Value stays live throughout. Its canonical output
    // is dropped before those comparisons, so summing both windows is safe.
    let diagnostic = super::super::decoding::diagnostic_storage_data(
        length,
        super::super::private_body_typed_geometry_data()[2],
    )?;
    let transient = sum(&[
        raw.value_dom_requested_bytes,
        raw.canonical_work_requested_bytes,
        raw.canonical_output_requested_bytes,
        fields.dom_and_canonical_scratch_bytes,
        fields.canonical_output_requested_bytes,
        formatter,
        diagnostic,
        size_of::<Value>() * 2,
        size_of::<Result<Value, ContractError>>(),
        size_of::<Result<Value, serde_json::Error>>(),
        size_of::<Vec<u8>>(),
        size_of::<Result<Vec<u8>, ContractError>>(),
    ])?;
    let scratch = sum(&[
        source_authentication_counter_scratch_data(),
        canonical::json_parse_counter_scratch_bytes_data(),
        canonical::canonical_json_counter_scratch_bytes_data(),
        // Both the strict original and the serializable typed forest have the
        // same finite canonical profile. Count actual serializer and paired
        // Value/container equality views, independently of backing allocation.
        mul(65, original_serialization_frame_counter_scratch_data())?,
        mul(65, equality_frame_counter_scratch_data())?,
    ])?;
    let row = [diagnostic, transient, scratch];
    if sum(&row)? > maximum {
        return Err(exhausted());
    }
    Ok(row)
}

/// Quotes the actual formatter temporary before invoking any serializer.
///
/// The caller first admits this helper's fixed counter. Metadata inspection
/// allocates no formatter, DOM or Source parser and conveys no credit.
///
/// # Errors
/// Refuses actual launch metadata traversal or checked formatter overflow.
pub(in crate::reference_packet) fn source_authentication_quote_construction_data(
    launch: &PacketNative5SourceLaunch,
) -> Result<[usize; 3], ProviderError> {
    let facts = observe_retained_native_launch(launch)?;
    Ok([
        0,
        original_serialization_formatter_temporary_storage_data(&facts)?,
        source_authentication_counter_scratch_data(),
    ])
}

/// Names actual lexical, metadata, projection and correspondence quote controls.
pub(in crate::reference_packet) fn source_authentication_counter_scratch_data() -> usize {
    original_json_value_storage_extent_counter_scratch_data()
        + retained_native_launch_counter_scratch_data()
        + original_serialization_counter_scratch_data()
        + native_import18_source_declaration_counter_scratch_data()
        + size_of::<&PacketNativeImport18SourceDeclarationWireData>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<Projection>()
        + size_of::<Shape>()
        + size_of::<Result<Shape, ProviderError>>()
        + size_of::<
            crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
        >()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<Result<crate::retained_metadata::RetainedProtocolMetadataFacts, ProviderError>>(
        )
        + size_of::<[usize; 12]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<usize>() * 6
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

fn equality_frame_counter_scratch_data() -> usize {
    size_of::<&Value>() * 2
        + size_of::<(&String, &Value)>() * 2
        + size_of::<
            std::iter::Zip<std::slice::Iter<'static, Value>, std::slice::Iter<'static, Value>>,
        >()
        + size_of::<
            std::iter::Zip<
                std::collections::btree_map::Iter<'static, String, Value>,
                std::collections::btree_map::Iter<'static, String, Value>,
            >,
        >()
        + size_of::<Option<(&Value, &Value)>>()
        + size_of::<Option<((&String, &Value), (&String, &Value))>>()
        + size_of::<bool>()
        + size_of::<usize>() * 2
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, &n| {
        total.checked_add(n).ok_or_else(exhausted)
    })
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native import18 original Source correspondence")
}

#[cfg(test)]
#[path = "authentication/tests.rs"]
mod tests;
