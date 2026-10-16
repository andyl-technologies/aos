//! Counts the selected native's actual baseline constructor owners before birth.
//!
//! Every retained copy has a named constructor association. Fixed banks use
//! their actual reservation layouts, while immutable raw inputs are scanned
//! before any DOM/typed decode. The caller admits the fixed counter window
//! first. This producer grants no permission to launch, parse, Admit or Prepare.

use super::super::{PacketConnectedSourceProgram, PacketNative5SourceLaunch};
use crate::retained_metadata::{
    MetadataObserver, requested_metadata_backing_storage_data,
    serialization_storage::{
        original_json_value_storage_extent_counter_scratch_data,
        original_json_value_storage_extent_data,
    },
};
use crate::{ProviderError, protocol_snapshot::ProtocolSnapshotReservation};
use std::mem::{align_of, size_of};

mod admit;
mod coordinator_decode;
mod decoded;
mod hello;
mod initial;
mod private_bootstrap;
mod schemas;
mod source_binding;

// Names only explicit compiled live locals/results/row arrays. Recursive
// compiler/serde frames, allocator rounding and kernel resources are separate.
type InitialCounterLocals = (
    initial::InitialLifecycleStorage,
    schemas::InitialSchemaStorage,
    private_bootstrap::PrivateBootstrapStorage,
    crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
    admit::AdmitStorage,
    hello::HelloStorage,
    [usize; 6],
    [usize; 5],
    [usize; 21],
    [usize; 12],
    [usize; 3],
);

const PRIVATE_LAUNCH_BYTES: usize = 1024 * 1024;
const PRIVATE_BOOT_BYTES: usize = 512 * 1024;
const NATIVE_HELLO_BYTES: usize = 65_536;

/// Borrows the actual retained original inputs used by native baseline birth.
///
/// Core's genuine source/installed-plan scope supplies these independent owners.
/// Equivalent caller labels and a decoded DTO cannot authenticate that origin.
/// The native side obtains the same inputs from its original private channel.
pub struct PacketNativeBirthStartupInputs<'a> {
    /// Borrows the original typed launch retained before its canonical encoding.
    pub launch: &'a PacketNative5SourceLaunch,
    /// Borrows the same immutable Source-born private launch identity.
    pub private_launch: &'a crucible_node_contract::Id,
    /// Borrows the canonical bytes retained from that same construction.
    pub encoded_launch: &'a [u8],
    /// Borrows this same Source's original canonical private birth binding.
    pub source_birth: &'a [u8],
    /// Borrows its independently retained planned host registration.
    pub host_registration: &'a [u8],
}

/// Describes all prospective native birth owners independently of publication.
///
/// These requested components are conservative data. Only the actual installed
/// ResourceLimits action can issue the Source member and native private scope.
/// A successful quote says nothing about kernel/allocator residency or stack.
pub struct PacketNativeBirthStartupStorageData {
    retained_requested_bytes: usize,
    maximum_simultaneous_transient_bytes: usize,
    declared_counter_scratch_bytes: usize,
    private_bootstrap: private_bootstrap::PrivateBootstrapStorage,
}

impl PacketNativeBirthStartupStorageData {
    /// Returns the independently counted private pre-parser/raw-bank owners.
    pub const fn private_bootstrap_retained_requested_bytes(&self) -> usize {
        self.private_bootstrap.retained
    }

    /// Returns its complete simultaneous private decoding/construction phase.
    pub const fn private_bootstrap_maximum_simultaneous_transient_bytes(&self) -> usize {
        self.private_bootstrap.transient
    }

    /// Returns the closed boot body bound enforced before raw frame allocation.
    pub const fn maximum_private_boot_body_bytes(&self) -> usize {
        self.private_bootstrap.maximum_boot_bytes
    }

    /// Returns all new native baseline owners retained through completed Admit.
    pub const fn retained_requested_bytes(&self) -> usize {
        self.retained_requested_bytes
    }

    /// Returns the complete simultaneous baseline construction phase.
    pub const fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.maximum_simultaneous_transient_bytes
    }

    /// Returns the fixed compiled counter and observer window required first.
    pub const fn declared_counter_scratch_bytes(&self) -> usize {
        self.declared_counter_scratch_bytes
    }
}

/// Quotes the fixed layouts required before entering the baseline data producer.
///
/// Recursive compiler/serializer frames and allocator/kernel costs remain
/// separate. The producer invokes only closed compiled serialization projections
/// and metadata walks, with no parser, erased callback or I/O. Known Bytes
/// formatting temporaries are separately included in this declared window.
pub fn original_native_birth_startup_counter_scratch_data() -> usize {
    size_of::<crate::reference_packet::service::ack_emitter::OriginalNativeBirthReadScope<'static>>()
        + super::data_equality::counter_scratch_data()
        + coordinator_decode::counter_scratch_data()
        + decoded::counter_scratch_data()
        + launch_validation_counter_scratch_data()
        // Private second-frame projection retains its independent raw extent
        // beside the original max-raw result and nested helper views.
        + size_of::<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData>()
        + 3 * size_of::<decoded::DecodedStorage>()
        + size_of::<[usize; 12]>()
        + crate::handshake::Handshake::original_native_hello_reuse_counter_scratch_data()
        + crate::protocol_snapshot::owned11::correspondence::envelope_counter_scratch_data()
        + size_of::<PacketNativeBirthStartupStorageData>()
        + size_of::<PacketNativeBirthStartupInputs<'_>>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + original_json_value_storage_extent_counter_scratch_data()
        + super::super::complete_restore::transfer::selected_issuer_decode_counter_scratch_data()
        + size_of::<InitialCounterLocals>()
        + crate::connection::original_packet_prefix_startup_counter_scratch_data()
        + crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::requested_serialization_scratch_bytes()
        // The closed once-Admit outer projector holds association, kernel and
        // policy counters together; this precedes any native constructor.
        + 3 * size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection>()
        + 5 * size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData>()
        + size_of::<[u8; 20]>()
        + size_of::<[u8; 64]>()
        // The known launch/program serializers can format a Bytes leaf before
        // reaching the event sink. Its base64 spelling is a substring of this
        // same authenticated canonical launch, bounded by the launch grammar.
        + PRIVATE_LAUNCH_BYTES
}

/// Counts the same immutable selected constructor inputs without making owners.
///
/// The caller admits the fixed scratch before this call and retains all inputs.
/// Independently selected banks are summed; no largest-scalar surrogate or
/// publication allowance substitutes for baseline storage. Native construction
/// must check the actual capacities under its same admitted private scope.
///
/// # Errors
/// Refuses absent or unsupported inputs, malformed bounded raw trees, invalid
/// constructor bounds, overflow or any component above `maximum_requested_bytes`.
pub fn original_native_birth_startup_storage_data(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum_requested_bytes: usize,
) -> Result<PacketNativeBirthStartupStorageData, ProviderError> {
    if input.encoded_launch.is_empty()
        || input.encoded_launch.len() > PRIVATE_LAUNCH_BYTES
        || input.source_birth.is_empty()
        || input.source_birth.len() > 384 * 1024
        || input.host_registration.is_empty()
        || input.host_registration.len() > 16 * 1024
        || !matches!(
            input.launch.capture_profile,
            super::super::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        )
    {
        return Err(refused());
    }
    let maximum = maximum_requested_bytes;
    let launch = input.launch;
    let metadata = launch.protocol_metadata_limits.ok_or_else(refused)?;
    let history = extent(launch.storage.frame_bank_bytes.get())?;
    let frames = extent(launch.storage.frames_per_direction.get())?;
    let before = extent(
        launch
            .capture_profile
            .native_before_bytes(&launch.storage)
            .get(),
    )?;
    let after = extent(
        launch
            .capture_profile
            .native_after_bytes(&launch.storage)
            .get(),
    )?;
    let before_bank =
        ProtocolSnapshotReservation::original_owned11_reservation_requested_storage_data(
            before,
            history,
            frames,
            extent(metadata.native_before_rows.get())?,
        )?;
    let after_bank =
        ProtocolSnapshotReservation::original_owned11_reservation_requested_storage_data(
            after,
            history,
            frames,
            extent(metadata.native_after_rows.get())?,
        )?;
    let literal = literal_bank(history, frames)?;
    let native_hello = literal_bank((NATIVE_HELLO_BYTES + 4) * 2, 1)?;
    let model_banks = match &launch.program {
        PacketConnectedSourceProgram::Producer { .. } =>
            crate::reference_packet::PacketProgram::original_initial_reservation_requested_bytes()?,
        PacketConnectedSourceProgram::Reactive { .. } =>
            crate::reference_packet::connected::PacketConnectedProgram::original_initial_reservation_requested_bytes()?,
    };
    let fixed_banks = sum(
        &[before_bank, after_bank, literal, native_hello, model_banks],
        maximum,
    )?;

    // Each raw walk uses actual occurrences and compiled DTO/map layouts. It
    // allocates no fake Envelope, boot, model, coordinator or permission object.
    let launch_decode = decode(
        input.encoded_launch,
        size_of::<PacketNative5SourceLaunch>(),
        maximum,
    )?;
    let coordinator_decode = original_native_coordinator_decode_storage_data(
        launch.initial_coordinator.bytes.as_slice(),
        maximum,
    )?;
    let source_shape = private_bootstrap::project(input, maximum)?;
    // The same nine immutable base Values and the closed Binding14 additions
    // determine this tree. Its encoded length is not a license to replace that
    // known structure with the worst possible arbitrary JSON of equal length.
    let source_decode = source_shape.source_requested_bytes;
    let source_backing = source_shape.source_value_backing_bytes;
    let launch_backing = decoded::quote(
        input.encoded_launch,
        size_of::<PacketNative5SourceLaunch>(),
        native_element_slot(),
        maximum,
    )?
    .typed_backing;
    let coordinator_backing =
        coordinator_decode::backing(launch.initial_coordinator.bytes.as_slice(), maximum)?;
    let registration_backing = decoded::quote(
        input.host_registration,
        size_of::<serde_json::Value>(),
        size_of::<serde_json::Value>(),
        maximum,
    )?
    .value_backing;
    let registration_decode = decode_value(input.host_registration, maximum)?;

    let selection = metadata_backing(&launch.selection)?;
    let provider = metadata_backing(&launch.selection.provider)?;
    let realization = metadata_backing(&launch.selection.realization)?;
    let coordinator_bytes = launch.initial_coordinator.bytes.as_slice().len();
    let model_definition = match &launch.program {
        PacketConnectedSourceProgram::Producer { program } => metadata_backing(program)?,
        PacketConnectedSourceProgram::Reactive { program } => metadata_backing(program)?,
    };

    // These independent retained owners correspond to the exact constructor
    // assignments, rather than a numeric multiplier over an arbitrary maximum.
    let retained_copies = sum(
        &[
            launch_backing, // Actual typed launch moved into native service; private owns its separate Value.
            input.encoded_launch.len(), // Bootstrap.launch_bytes.
            input.encoded_launch.len(), // NativeAckBoot.launch_body.
            source_backing, // Bootstrap.boot_value.source_birth.
            source_backing, // NativeAckBoot.data.source_birth.
            source_backing, // NativeAckBoot.normalized source binding.
            source_shape.maximum_source_bytes, // NativeAckBoot.source_body after finalization.
            registration_backing, // Bootstrap.boot_value registration.
            registration_backing, // NativeAckBoot.data registration.
            registration_backing, // NativeAckBoot.normalized registration.
            input.host_registration.len(), // NativeAckBoot.host_body.
            selection,      // Native5Policy.selection.
            selection,      // PacketControl.selection.
            coordinator_bytes, // Native5Policy installed coordinator bytes.
            coordinator_backing, // Native5Policy decoded common coordinator.
            coordinator_backing, // PacketControl complete coordinator.
            model_definition, // Producer events or reactive definition.
            provider,       // Handshake.TrustedInstallation.
            provider,       // Actual retained native Hello response identity.
            realization,    // Actual retained Realize terminal.
        ],
        maximum,
    )?;

    let private = source_shape;
    let lifecycle = initial::project(launch, maximum)?;
    let definitions = schemas::project(launch, maximum)?;
    let shared_headers =
        super::super::server::complete::birth::original_native_birth_shared_layout_bytes()?;
    let phase_headers =
        super::super::server::complete::birth::original_native_birth_phase_layout_bytes()?;
    let context_banks = sum(
        &super::super::ack_emitter::ORIGINAL_ACK_CONTEXT_BANK_BYTES,
        maximum,
    )?;
    let retained = sum(
        &[
            fixed_banks,
            retained_copies,
            lifecycle.retained,
            definitions.retained_reference_children,
            shared_headers,
            phase_headers,
            context_banks,
        ],
        maximum,
    )?;
    let admit = admit::project(input, &private, maximum)?;
    let hello = hello::project(input, maximum)?;
    let retained = sum(
        &[
            retained,
            admit.retained,
            hello.retained,
            // Native boot retains the exact typed allocation schema alongside its
            // primitive rows. Key/birth arrays and scope digests are inline.
            super::PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA.len(),
        ],
        maximum,
    )?;
    // CompleteBirth::prepare returns before D/R/Admit dispatch. Its local
    // Hello/decoded comparison banks are dropped; all service and failed-partial
    // fields are in retained above. Coordinator validation is likewise a
    // returning construction call. No max is taken over persistent owners.
    // The explicit Hello scope has ended before either retained coordinator
    // is constructed. Earlier private Source/host decoding likewise returns
    // before CompleteBirth starts. Their actual permanent owners are above.
    let birth_work = launch_decode
        .max(coordinator_decode)
        .max(source_decode)
        .max(registration_decode)
        .max(hello.transient);
    let lifecycle_work = sum(
        &[
            lifecycle.transient,
            definitions.transient,
            model_definition,
            model_definition,
        ],
        maximum,
    )?;
    let maximum_simultaneous_transient_bytes =
        birth_work.max(lifecycle_work).max(admit.transient).max(
            super::super::ack_emitter::original_prepare_executable_measurement_counter_scratch_data(
            ),
        );
    let scratch = original_native_birth_startup_counter_scratch_data();
    if lifecycle.scratch > scratch || admit.scratch > scratch || hello.scratch > scratch {
        return Err(refused());
    }
    sum(
        &[retained, maximum_simultaneous_transient_bytes, scratch],
        maximum,
    )?;
    Ok(PacketNativeBirthStartupStorageData {
        retained_requested_bytes: retained,
        maximum_simultaneous_transient_bytes,
        declared_counter_scratch_bytes: scratch,
        private_bootstrap: private,
    })
}

/// Lists actual independently allocated native Vec element classes. Scalar
/// fields and nested structs are inline in their root/element, not heap DTOs
/// per string/key token; unknown Value children retain their full DOM row.
fn native_element_slot() -> usize {
    coordinator_decode::typed_slot()
        .max(size_of::<crate::reference_packet::PacketEvent>())
        .max(size_of::<
            crate::reference_packet::connected::PacketInputConnection,
        >())
        .max(size_of::<u8>())
}


/// Prices the actual launch validator shared by private bootstrap and Admit.
/// The generic syntax/DTO decode scalar does not cover these calls: validate
/// creates ingress schemas, decodes coordinator, projects model configuration,
/// and may construct a temporary complete Native5Policy. Returning subcalls
/// are conservatively summed; no existing permission or validation is skipped.
fn launch_validation_work(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<usize, ProviderError> {
    let launch = input.launch;
    let mut configuration = crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection::new(maximum)?;
    match &launch.program {
        PacketConnectedSourceProgram::Producer { program } => configuration.add_value(program)?,
        PacketConnectedSourceProgram::Reactive { program } => configuration.add_value(program)?,
    }
    let configuration = configuration.finish(maximum)?;
    let definitions = schemas::project(launch, maximum)?;
    // Native5Policy can retain its own decoded coordinator during subsequent
    // returning validation. Its selection/raw coordinator copy are separate
    // children beside the temporary decoder/validator work.
    sum(&[
        decode(input.encoded_launch, size_of::<PacketNative5SourceLaunch>(), maximum)?,
        original_native_coordinator_decode_storage_data(launch.initial_coordinator.bytes.as_slice(), maximum)?,
        coordinator_decode::backing(launch.initial_coordinator.bytes.as_slice(), maximum)?,
        metadata_backing(&launch.selection)?,
        launch.initial_coordinator.bytes.as_slice().len(),
        size_of::<crate::reference_packet::service::Native5Policy>(),
        configuration.requested_total()?,
        definitions.transient,
        definitions.retained_reference_children,
    ], maximum)
}

fn launch_validation_counter_scratch_data() -> usize {
    size_of::<MetadataObserver<'static>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection>()
        + size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData>()
        + size_of::<schemas::InitialSchemaStorage>()
        + size_of::<[usize; 10]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
}

fn decode(bytes: &[u8], typed: usize, maximum: usize) -> Result<usize, ProviderError> {
    super::super::complete_restore::transfer::selected_issuer_decode_storage_data(
        bytes, typed, maximum,
    )
}

/// Counts the selected complete coordinator and its actual validation phases.
pub(crate) fn original_native_coordinator_decode_storage_data(
    bytes: &[u8],
    maximum: usize,
) -> Result<usize, ProviderError> {
    coordinator_decode::quote(bytes, maximum)
}

pub(crate) fn original_native_coordinator_decode_counter_scratch_data() -> usize {
    coordinator_decode::counter_scratch_data()
}

// Only actual Value-only fields use this helper. Typed launch/coordinator and
// authority constructors retain their independently named complete quotes.
fn decode_value(bytes: &[u8], maximum: usize) -> Result<usize, ProviderError> {
    super::super::complete_restore::transfer::selected_value_decode_storage_data(bytes, maximum)
}

fn literal_bank(bytes: usize, frames: usize) -> Result<usize, ProviderError> {
    use crate::transport::original_frames::{
        MAX_ORIGINAL_FRAME_BYTES, MAX_ORIGINAL_FRAMES_PER_DIRECTION, original_frame_slot_layout,
    };
    if !(4..=MAX_ORIGINAL_FRAME_BYTES).contains(&bytes)
        || frames == 0
        || frames > MAX_ORIGINAL_FRAMES_PER_DIRECTION
    {
        return Err(refused());
    }
    bytes
        .checked_add(
            frames
                .checked_mul(2)
                .and_then(|n| n.checked_mul(original_frame_slot_layout()))
                .ok_or_else(refused)?,
        )
        .ok_or_else(refused)
}

fn metadata_backing<T: crate::retained_metadata::ObserveMetadata + ?Sized>(
    value: &T,
) -> Result<usize, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(value)?;
    requested_metadata_backing_storage_data(&observer.finish())
}

fn extent(value: u64) -> Result<usize, ProviderError> {
    usize::try_from(value).map_err(|_| refused())
}

fn sum(values: &[usize], maximum: usize) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |total, bytes| {
        total
            .checked_add(*bytes)
            .filter(|total| *total <= maximum)
            .ok_or_else(refused)
    })
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("native baseline requested storage")
}

/// Quotes the closed outer boot fields used by the Source's actual wire owner.
///
/// The two independent Source/registration trees are counted by their actual
/// raw occurrence scans at the caller. This helper supplies the outer object,
/// actual identifier/reference children and fixed encoded private-key fields.
///
/// # Errors
/// Refuses incomplete inputs, projection overflow or the requested ceiling.
pub fn original_native_private_boot_fields_storage_data(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum: usize,
) -> Result<usize, ProviderError> {
    private_bootstrap::boot_fields(input, maximum)?.requested_total()
}

#[cfg(test)]
#[path = "storage/schema_parity_tests.rs"]
mod schema_parity_tests;

pub(crate) use initial::{
    OriginalHostInitialLifecycleShapes, original_host_initial_lifecycle_shapes_data,
};

pub(crate) fn original_host_initial_codec_schema_storage_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<(usize, usize), ProviderError> {
    let data = schemas::project(launch, maximum)?;
    Ok((data.transient, data.retained_reference_children))
}
