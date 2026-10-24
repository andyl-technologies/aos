//! Quotes the complete five-role bootstrap normalization schedule before Birth.
//!
//! Actual Source/launch/Host operands are borrowed. Future scalar widths come
//! from the defining Recipe24/Initial3 projections. Complete schema references
//! come from the actual compiled factories, never invented references or rows.
//! Every result remains construction DATA without Source or native authority.

use super::prospective::PrivateOperands;
use super::*;
use crate::reference_packet::service::ack_emitter::native_boot::{
    original_import18_bootstrap_normalizations_construction_data,
    original_import18_bootstrap_normalizations_counter_scratch_data,
};
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    NativeImport18BootstrapProspectiveOperands,
    native_import18_bootstrap_prospective_operands_counter_scratch_data,
    native_import18_bootstrap_prospective_operands_data,
};
use crate::reference_packet::service::complete_restore::import18::hello::{
    PacketNativeImport18HelloDeclarationData, native_import18_hello_declaration_data,
};
use crate::retained_metadata::serialization_storage::{
    OriginalSerializationStorageData as Shape, OriginalSerializationStorageProjection as Projection,
};

/// Prices the actual factory overlap and all quote controls before that work.
///
/// Each factory's temporary bound includes its returned full reference strings.
/// Three such windows conservatively cover two retained references alongside
/// the third factory, and all three references during the projection walk.
///
/// # Errors
/// Refuses checked accumulation overflow or unsupported compiled definitions.
pub(super) fn prewalk_data() -> Result<[usize; 3], ProviderError> {
    let (factory, scratch) = native_import18_selection_construction_storage_data(usize::MAX)?;
    let scratch = [
        native_import18_selection_prewalk_data(),
        native_import18_bootstrap_prospective_operands_counter_scratch_data(),
        PacketNativeImport18HelloDeclarationData::declaration_counter_scratch_data(),
        size_of::<[SchemaRef; 3]>(),
        size_of::<Result<SchemaRef, ProviderError>>(),
        size_of::<[Shape; 5]>(),
        size_of::<[Shape; 4]>(),
        size_of::<Projection>(),
        size_of::<Result<Shape, ProviderError>>(),
        size_of::<[usize; 3]>() * 2,
        size_of::<Result<[usize; 3], ProviderError>>(),
        size_of::<PacketNativeImport18HelloDeclarationData>(),
        size_of::<Result<PacketNativeImport18HelloDeclarationData, ProviderError>>(),
        size_of::<PrivateOperands<'static>>(),
        size_of::<&ContentRef>(),
        size_of::<Option<&ContentRef>>(),
        size_of::<usize>() * 3,
    ]
    .into_iter()
    .try_fold(scratch, add)?;
    Ok([
        0,
        factory.checked_mul(3).ok_or_else(exhausted)?,
        add(
            scratch,
            original_import18_bootstrap_normalizations_counter_scratch_data()?,
        )?,
    ])
}

/// Combines actual prospective preimages with the same native schedule formula.
///
/// The caller has admitted `prewalk_data` and custom Host/launch formatters.
/// No Source bank, private key or future recipe is serialized by this quote.
///
/// # Errors
/// Refuses ambiguous executable roles, invalid operands, arithmetic overflow or
/// the complete component exceeding the independent restriction.
pub(super) fn construction_data<H: Serialize>(
    launch: &PacketNative5SourceLaunch,
    private: &PrivateOperands<'_, H>,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let [import, stage, record] = [
        native_import18_schema_data()?,
        native_import18_stage_schema_data()?,
        native_import18_restored_record_schema_data()?,
    ];
    let hello = native_import18_hello_declaration_data(launch)?;
    let mut executables = launch
        .selection
        .provider
        .implementation
        .artifacts
        .iter()
        .filter(|artifact| artifact.role.as_str() == "executable");
    let executable = &executables.next().ok_or_else(exhausted)?.content;
    if executables.next().is_some() {
        return Err(exhausted());
    }
    let operands = NativeImport18BootstrapProspectiveOperands {
        launch,
        hello: &hello,
        declaration: &private.declaration,
        private_launch: private.private_launch,
        host_executable: private.host_executable,
        native_executable: executable,
        expected_host_registration: private.expected_host_registration,
        import: &import,
        stage: &stage,
        record: &record,
    };
    let [mut birth, kernel, mut policy, registration] =
        native_import18_bootstrap_prospective_operands_data(&operands, usize::MAX)?;
    // Native normalizes the typed declaration and recipe directly. The earlier
    // String-view quote must also reserve those real allocating Bytes formatters.
    let source_formatter =
        native_import18_source_declaration_formatter_requested_data(&private.declaration)?;
    birth.serializer_temporary_requested_bytes = birth
        .serializer_temporary_requested_bytes
        .max(source_formatter)
        .max(43);
    policy.serializer_temporary_requested_bytes = policy
        .serializer_temporary_requested_bytes
        .max(source_formatter)
        .max(43);
    let mut host = Projection::new(usize::MAX)?;
    host.add_value(private.expected_host_registration)?;
    let mut row = original_import18_bootstrap_normalizations_construction_data(
        &[
            birth,
            kernel,
            policy,
            registration,
            host.finish(usize::MAX)?,
        ],
        usize::MAX,
    )?;
    let prewalk = prewalk_data()?;
    row[1] = row[1].max(prewalk[1]);
    // The prospective walk and the future native constructor never execute
    // together. Keep their complete counter windows as sequential maxima.
    row[2] = row[2].max(prewalk[2]);
    if row
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .is_none_or(|peak| peak > maximum)
    {
        return Err(exhausted());
    }
    Ok(row)
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 five bootstrap normalizations")
}
