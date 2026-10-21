//! Projects the actual initial Hello result and completed response body.
//!
//! Future challenge bytes are represented by their defining unpadded base64
//! extent. No nonce, result DTO, connection or response is fabricated. Every
//! identity, limit, feature and provider field comes from the original launch.

use crate::ProviderError;
use crate::bodies::ResponseShape;
use crate::handshake::{ExtensionSelectionV1, HelloResult};
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::{
    PacketNativeImport18HelloDeclarationData, native_import18_hello_declaration_data,
};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData as Shape,
    OriginalSerializationStorageProjection as Projection,
    original_serialization_counter_scratch_data,
};
use std::mem::size_of;

macro_rules! result_fields {
    ($($field:ident),+ $(,)?) => {
        const FIELDS: [&str; 0 $(+ { let _ = stringify!($field); 1 })+] = [
            $(stringify!($field),)+
        ];

        const _: fn(&HelloResult) = |value| {
            let HelloResult { $($field: _,)+ } = value;
        };
    };
}

result_fields!(
    version,
    session_id,
    incarnation_id,
    controller_nonce,
    provider_nonce,
    selected_features,
    limits,
    resume_token,
    provider_identity,
    resumed_operations,
);

const _: fn(&ExtensionSelectionV1) = |value| {
    let ExtensionSelectionV1 {
        format: _,
        selected: _,
    } = value;
};

const _: fn(&ResponseShape) = |value| match value {
    ResponseShape::Completed {
        operation_state: _,
        result: _,
        extensions: _,
    }
    | ResponseShape::Accepted {
        operation_state: _,
        result: _,
        extensions: _,
    } => (),
    ResponseShape::Error {
        operation_state: _,
        error: _,
        extensions: _,
    } => (),
};

/// Projects the real initial empty installed-selection extension.
///
/// # Errors
/// Refuses unsupported geometry, overflow or the independent restriction.
pub(super) fn selection_data(maximum: usize) -> Result<Shape, ProviderError> {
    let mut out = Projection::new(maximum)?;
    out.add_object()?;
    out.add_field("format")?;
    out.add_string("1")?;
    out.add_field("selected")?;
    out.add_array_extent(0)?;
    finish_data(out, maximum)
}

/// Projects the complete future result before either challenge is available.
///
/// # Errors
/// Refuses a foreign declaration, missing sole binding, checked geometry
/// overflow or the independently selected complete-shape restriction.
pub(super) fn result_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<Shape, ProviderError> {
    let mut out = Projection::new(maximum)?;
    add_result_data(&mut out, launch)?;
    finish_data(out, maximum)
}

/// Projects the actual Completed response body around the same future result.
///
/// Result Value ownership and this enclosing body Value remain separate
/// retained populations when the real ResponseShape is serialized.
///
/// # Errors
/// Refuses a foreign declaration, invalid geometry, overflow or the independent
/// complete-shape restriction.
pub(super) fn completed_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<Shape, ProviderError> {
    let mut out = Projection::new(maximum)?;
    out.add_object()?;
    out.add_field("status")?;
    out.add_string("completed")?;
    out.add_field("operation_state")?;
    out.add_string("completed")?;
    out.add_field("result")?;
    add_result_data(&mut out, launch)?;
    out.add_field("extensions")?;
    out.add_object()?;
    finish_data(out, maximum)
}

fn add_result_data(
    out: &mut Projection,
    launch: &PacketNative5SourceLaunch,
) -> Result<(), ProviderError> {
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    let declaration = native_import18_hello_declaration_data(launch)?;
    out.add_object()?;
    for field in FIELDS {
        out.add_field(field)?;
    }
    out.add_string("CNP/1")?;
    out.add_value(&binding.authority.session_id)?;
    out.add_value(&binding.authority.incarnation_id)?;
    let challenge_bytes = challenge_formatter_data()?;
    out.add_unescaped_ascii_extent(challenge_bytes)?;
    out.add_unescaped_ascii_extent(challenge_bytes)?;
    out.add_array_extent(declaration.feature_count_data())?;
    for feature in declaration.features_data().iter().flatten() {
        out.add_string(feature)?;
    }
    out.add_value(&launch.limits)?;
    out.add_value(&Option::<bool>::None)?;
    out.add_value(&launch.selection.provider)?;
    out.add_array_extent(0)
}

fn finish_data(out: Projection, maximum: usize) -> Result<Shape, ProviderError> {
    let mut shape = out.finish(maximum)?;
    // A Bytes serializer drops its actual temporary String after that field's
    // visit. The two nonces therefore reuse one formatter bank.
    shape.serializer_temporary_requested_bytes = shape
        .serializer_temporary_requested_bytes
        .max(challenge_formatter_data()?);
    if shape.requested_total()? > maximum {
        return Err(refused());
    }
    Ok(shape)
}

/// Returns the defining actual formatter extent for a checked 32-byte challenge.
///
/// # Errors
/// Refuses overflow in the unchanged unpadded base64 length calculation.
pub(super) fn challenge_formatter_data() -> Result<usize, ProviderError> {
    base64::encoded_len(32, false).ok_or_else(refused)
}

/// Names actual projection, defining rosters and returned layout controls.
pub(super) fn counter_scratch_data() -> usize {
    original_serialization_counter_scratch_data()
        + super::serialize_controls::provider_data()
        + PacketNativeImport18HelloDeclarationData::declaration_counter_scratch_data()
        + size_of::<Projection>()
        + size_of::<Result<Projection, ProviderError>>()
        + size_of::<&mut Projection>()
        + size_of::<Shape>()
        + size_of::<Result<Shape, ProviderError>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<PacketNativeImport18HelloDeclarationData>()
        + size_of::<[&str; FIELDS.len()]>()
        + size_of::<std::array::IntoIter<&'static str, { FIELDS.len() }>>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<&'static str>>>>()
        + size_of::<Option<bool>>()
        + size_of::<&str>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>() * 2
        + size_of::<usize>() * 4
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 Hello response projection")
}
