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
use crucible_source_birth_data::profile::reference_packet::service::native_startup::hello_shapes::HelloFixedLayoutData;
use std::mem::{align_of, size_of};

mod admit;
mod coordinator_decode;
mod decoded;
mod fixed_layout;
mod hello;
mod initial;
mod launch_decode;
mod launch_validation;
mod private_bootstrap;
use private_bootstrap::PrivateBootstrapStorageExt;
mod retained_overlap;
pub use retained_overlap::PacketNativeBirthRetainedOverlapData;
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
    pub private_launch: &'a crucible_node_format::Id,
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
    retained_overlap: PacketNativeBirthRetainedOverlapData,
}

impl PacketNativeBirthStartupStorageData {
    /// Authenticates non-wire common-owner facts against these exact inputs.
    ///
    /// # Errors
    /// Refuses another creator, typed launch/private identity or complete raw
    /// original. This DATA grants no rights and never discounts another Source.
    pub fn authenticated_retained_overlap_data(
        &self,
        input: &PacketNativeBirthStartupInputs<'_>,
    ) -> Result<PacketNativeBirthRetainedOverlapData, ProviderError> {
        self.retained_overlap.authenticate_inputs_data(input)?;
        Ok(self.retained_overlap)
    }

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
        + crate::reference_packet::control::PacketControl::original_native_birth_selection_counter_scratch_data()
        + super::data_equality::counter_scratch_data()
        + invocation_ingress_counter_scratch_data()
        + retained_overlap::counter_scratch_data()
        + schemas::counter_scratch_data()
        + admit::adapter_counter_scratch_data()
        + coordinator_decode::counter_scratch_data()
        + decoded::counter_scratch_data()
        + fixed_layout::counter_scratch_data()
        + initial::original_initial_literal_shape_counter_scratch_data()
        + private_bootstrap::literal_shape_counter_scratch_data()
        + super::private_backing::ADAPTER_COUNTER_SCRATCH_DATA
        + crucible_source_birth_data::profile::reference_packet::service::native_startup::hello_shapes::additional_counter_scratch_data()
        + launch_validation_counter_scratch_data()
        + super::super::Native5Policy::CONSTRUCTION_ADAPTER_SCRATCH_DATA
        // Exact lower restore-input aggregate initializer and owned callee input.
        + 2 * size_of::<crucible_source_birth_data::profile::reference_packet::service::native5_policy::Native5CompleteRestorePolicyInput>()
        + launch_validation::counter_scratch_data()
        + launch_decode::counter_scratch_data()
        + super::pre_dom::counter_scratch_data()
        // Complete return views coexist with the named payload/observer rows:
        // edition transpose, actual Hello phase, and exhaustive launch facts.
        // Canonical private bank growth: checked full/spare scalar views.
        + size_of::<[usize; 3]>()
        + size_of::<Result<usize, ProviderError>>()
        // Selected phase cap and occurrence-based partial native DTO view.
        + 2 * size_of::<bool>()
        + size_of::<[usize; 6]>()
        + size_of::<[usize; 2]>()
        + size_of::<[usize; 4]>()
        + size_of::<[usize; 4]>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<Option<bool>, ProviderError>>()
        + size_of::<Result<hello::HelloStorage, ProviderError>>()
        // Private second-frame projection retains its independent raw extent
        // beside the original max-raw result and nested helper views.
        + size_of::<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData>()
        + 3 * size_of::<decoded::DecodedStorage>()
        + size_of::<[usize; 12]>()
        + crate::handshake::Handshake::original_native_hello_reuse_counter_scratch_data()
        + crate::protocol_snapshot::owned11::correspondence::envelope_counter_scratch_data()
        + size_of::<PacketNativeBirthStartupStorageData>()
        + size_of::<PacketNativeBirthStartupInputs<'_>>()
        // The defining launch observer includes its complete borrowed field
        // views beside the observer and returned facts. Both Core and native
        // admit this same fixed window before the exhaustive launch walk.
        + crate::retained_metadata::retained_native_launch_counter_scratch_data()
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
        + super::super::ack_emitter::original_native_restoration_activation_counter_scratch_data()
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
    birth_storage_with_source(
        input,
        maximum_requested_bytes,
        private_bootstrap::project,
        false,
    )
}

/// Quotes original14 construction under the actual pre-DOM frame gates.
///
/// This separate DATA producer is selected by the authenticated host action and
/// the current original14 native claim. It bounds accepted input layout before
/// Value allocation; it does not promise every frame at the byte cap will fit.
/// The broad public producer and Invocation15 keep their original raw floors.
///
/// # Errors
/// Refuses unsupported inputs, overflow or any complete component above the
/// supplied ceiling. No returned component authorizes allocation or parsing.
pub fn original_native_preflight_birth_startup_storage_data(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum_requested_bytes: usize,
) -> Result<PacketNativeBirthStartupStorageData, ProviderError> {
    birth_storage_with_source(
        input,
        maximum_requested_bytes,
        private_bootstrap::project_preflight,
        true,
    )
}

/// Quotes only reachable restoration ingress under a complete invocation target.
///
/// Original execution cannot allocate the fresh activation/upload/first-Observe
/// attempt owners: their actual native preallocation gates reject that purpose.
/// Fresh targets retain every independently selected ingress row. This DATA does
/// not authenticate a Source, ticket, bootstrap or request and issues no rights.
/// The caller credits `original_native_birth_startup_counter_scratch_data` first.
///
/// # Errors
/// Refuses a foreign full target, row overflow or any complete selected ingress
/// conjunction above the supplied requested-storage ceiling.
pub fn original_native_invocation_ingress_storage_data(
    launch: &PacketNative5SourceLaunch,
    purpose: &super::PacketNativeInvocationPurposeData,
    maximum_requested_bytes: usize,
) -> Result<Option<super::PacketNativeStartupAllocationRow>, ProviderError> {
    purpose.authenticate_target_data(launch)?;
    if purpose.is_original_execution_data() {
        return Ok(None);
    }
    let activation = launch
        .selection
        .provider
        .extensions_supported
        .iter()
        .any(|feature| {
            feature.as_str()
                == super::super::complete_restore::activation::PACKET_RESTORATION_ACTIVATION_FEATURE
        });
    let observation = launch.selection.provider.extensions_supported.iter().any(|feature| {
        feature.as_str() == super::super::complete_restore::restoration_observe::PACKET_RESTORATION_OBSERVE_FEATURE
    });
    if !activation && !observation {
        return Ok(None);
    }
    let frame = extent(launch.limits.frame_bytes.get())?;
    let activation = if activation {
        Some(
            super::super::ack_emitter::original_native_restoration_activation_ingress_row_data(
                frame,
            )?,
        )
    } else {
        None
    };
    let observation = if observation {
        Some(
            super::super::ack_emitter::original_native_restoration_observation_ingress_row_data(
                frame,
            )?,
        )
    } else {
        None
    };
    let row = match (activation, observation) {
        (Some(activation), Some(observation)) => super::PacketNativeStartupAllocationRow {
            retained_requested_bytes: crucible_node_format::U64::new(
                activation
                    .retained_requested_bytes
                    .get()
                    .checked_add(observation.retained_requested_bytes.get())
                    .ok_or_else(refused)?,
            ),
            maximum_simultaneous_transient_bytes: crucible_node_format::U64::new(
                activation
                    .maximum_simultaneous_transient_bytes
                    .get()
                    .max(observation.maximum_simultaneous_transient_bytes.get()),
            ),
            declared_counter_scratch_bytes: crucible_node_format::U64::new(
                activation
                    .declared_counter_scratch_bytes
                    .get()
                    .max(observation.declared_counter_scratch_bytes.get()),
            ),
        },
        (Some(row), None) | (None, Some(row)) => row,
        (None, None) => return Ok(None),
    };
    if extent(row.requested_peak_data()?)? > maximum_requested_bytes {
        return Err(refused());
    }
    Ok(Some(row))
}

// Only authenticated invocation15/16 claims use the Source15 census. The same
// target/purpose producer is prepaid by Core before issuing either member.
pub(crate) fn original_native_invocation_baseline_storage_data(
    input: &PacketNativeBirthStartupInputs<'_>,
    purpose: &super::PacketNativeInvocationPurposeData,
    maximum_requested_bytes: usize,
) -> Result<PacketNativeBirthStartupStorageData, ProviderError> {
    purpose.authenticate_target_data(input.launch)?;
    let mut row = birth_storage_with_source(
        input,
        maximum_requested_bytes,
        private_bootstrap::project_invocation,
        false,
    )?;
    if let Some(ingress) = original_native_invocation_ingress_storage_data(
        input.launch,
        purpose,
        maximum_requested_bytes,
    )? {
        row.retained_requested_bytes = sum(
            &[
                row.retained_requested_bytes,
                extent(ingress.retained_requested_bytes.get())?,
            ],
            maximum_requested_bytes,
        )?;
        // Neither independent ingress owner belongs to the original three-owner
        // intersection. Preserve its full-row seal without enlarging the overlap.
        row.retained_overlap = row
            .retained_overlap
            .with_additional_retained_requested_bytes_data(
                0,
                extent(ingress.retained_requested_bytes.get())?,
            )?;
        row.maximum_simultaneous_transient_bytes = row
            .maximum_simultaneous_transient_bytes
            .max(extent(ingress.maximum_simultaneous_transient_bytes.get())?);
        row.declared_counter_scratch_bytes = row
            .declared_counter_scratch_bytes
            .max(extent(ingress.declared_counter_scratch_bytes.get())?);
        sum(
            &[
                row.retained_requested_bytes,
                row.maximum_simultaneous_transient_bytes,
                row.declared_counter_scratch_bytes,
            ],
            maximum_requested_bytes,
        )?;
    }
    Ok(row)
}

fn invocation_ingress_counter_scratch_data() -> usize {
    // Full purpose correspondence is borrowed and allocation-free. The two
    // optional ingress rows coexist through the exhaustive selection match.
    super::original_native_invocation_counter_scratch_data()
        + size_of::<&super::PacketNativeInvocationPurposeData>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Option<super::PacketNativeStartupAllocationRow>>() * 2
        + size_of::<(
            Option<super::PacketNativeStartupAllocationRow>,
            Option<super::PacketNativeStartupAllocationRow>,
        )>()
        + size_of::<super::PacketNativeStartupAllocationRow>() * 3
        + size_of::<Result<super::PacketNativeStartupAllocationRow, ProviderError>>()
        + size_of::<Result<Option<super::PacketNativeStartupAllocationRow>, ProviderError>>()
        + size_of::<Option<u64>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<std::slice::Iter<'static, crucible_node_format::Id>>()
        + size_of::<&crucible_node_format::Id>()
        + size_of::<&str>()
        + size_of::<[bool; 2]>()
        + size_of::<[usize; 3]>()
}

fn birth_storage_with_source(
    input: &PacketNativeBirthStartupInputs<'_>,
    maximum_requested_bytes: usize,
    source_project: fn(
        &PacketNativeBirthStartupInputs<'_>,
        usize,
    ) -> Result<private_bootstrap::PrivateBootstrapStorage, ProviderError>,
    preflight: bool,
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
    let native_hello =
        crate::native_hello::OriginalNativeHelloJournal::reservation_requested_storage_data(
            NATIVE_HELLO_BYTES,
        )?;
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
    let launch_decode = launch_decode::quote(input.encoded_launch, maximum)?;
    let coordinator_decode = original_native_coordinator_decode_storage_data(
        launch.initial_coordinator.bytes.as_slice(),
        maximum,
    )?;
    let source_shape = source_project(input, maximum)?;
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
    let fixed_layout = fixed_layout::project(maximum)?;
    let retained = sum(
        &[
            fixed_banks,
            retained_copies,
            lifecycle.retained,
            definitions.retained_reference_children,
            fixed_layout.shared_headers_bytes,
            fixed_layout.phase_headers_bytes,
            fixed_layout.context_bank_bytes,
        ],
        maximum,
    )?;
    let admit = admit::project(input, &private, maximum)?;
    // Selected Hello work is checked against the SAME native row before any
    // request Value. Compute its unchanged retained/scratch projection without
    // making the broad arbitrary-byte transient a hidden selected requirement.
    // This arithmetic ceiling grants no allocation; final rows still use maximum.
    let hello = hello::project(input, if preflight { usize::MAX } else { maximum })?;
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
        .max(if preflight {
            NATIVE_HELLO_BYTES
        } else {
            hello.transient
        });
    let lifecycle_work = sum(
        &[
            lifecycle.transient,
            definitions.transient,
            model_definition,
            model_definition,
        ],
        maximum,
    )?;
    // CompleteBirth::prepare calls the generic measurement path. Charge its
    // entire bank here. Selected Prepare/restore use their separately counted
    // bank; the current-controller check remains in the private-bootstrap phase.
    let maximum_simultaneous_transient_bytes = birth_work
        .max(lifecycle_work)
        .max(admit.transient)
        .max(
        super::super::ack_emitter::original_conformance_executable_measurement_counter_scratch_data(
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
    // Both standalone rows stay complete. Only their proven intersection is
    // carried separately to the host's joint census; no wire row is rewritten.
    let shared_private = private.shared_retained_owner_data(input, maximum)?;
    let retained_overlap = PacketNativeBirthRetainedOverlapData::new(
        input,
        shared_private,
        [
            input.encoded_launch.len(),
            source_backing,
            registration_backing,
        ],
        private.retained,
        retained,
        maximum,
    )?;
    Ok(PacketNativeBirthStartupStorageData {
        retained_requested_bytes: retained,
        maximum_simultaneous_transient_bytes,
        declared_counter_scratch_bytes: scratch,
        private_bootstrap: private,
        retained_overlap,
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
    sum(
        &[
            launch_decode::quote(input.encoded_launch, maximum)?,
            original_native_coordinator_decode_storage_data(
                launch.initial_coordinator.bytes.as_slice(),
                maximum,
            )?,
            coordinator_decode::backing(launch.initial_coordinator.bytes.as_slice(), maximum)?,
            metadata_backing(&launch.selection)?,
            launch.initial_coordinator.bytes.as_slice().len(),
            size_of::<crucible_source_birth_data::profile::reference_packet::service::native5_policy::Native5PolicyData>(),
            configuration.requested_total()?,
            definitions.transient,
            definitions.retained_reference_children,
        ],
        maximum,
    )
}

fn launch_validation_counter_scratch_data() -> usize {
    PacketNative5SourceLaunch::VALIDATION_INPUT_COUNTER_SCRATCH_DATA
        + size_of::<MetadataObserver<'static>>()
        + size_of::<crate::retained_metadata::RetainedProtocolMetadataFacts>()
        + size_of::<
            crate::retained_metadata::serialization_storage::OriginalSerializationStorageProjection,
        >()
        + size_of::<crate::retained_metadata::serialization_storage::OriginalSerializationStorageData>(
        )
        + size_of::<schemas::InitialSchemaStorage>()
        + size_of::<[usize; 10]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
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

/// Counts the actual permanent complete-coordinator DTO, excluding decode work.
///
/// The unchanged complete decoder/validator has a separate prospective row.
/// Unknown shapes retain the defining conservative backing fallback.
///
/// # Errors
/// Refuses encoded extent, unsupported raw structure, checked layout overflow
/// or a defining component above the supplied construction ceiling.
pub(crate) fn original_native_coordinator_backing_storage_data(
    bytes: &[u8],
    maximum: usize,
) -> Result<usize, ProviderError> {
    if bytes.len()
        > crate::reference_packet::coordinator::PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES
    {
        return Err(refused());
    }
    coordinator_decode::backing(bytes, maximum)
}

/// Counts the defining backing scanner and its independent nested views.
pub(crate) fn original_native_coordinator_backing_counter_scratch_data() -> usize {
    coordinator_decode::counter_scratch_data()
        + decoded::counter_scratch_data()
        + size_of::<Result<decoded::DecodedStorage, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + crate::retained_metadata::serialization_storage::original_serialization_tree_node_counter_scratch_data()
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
    original_initial_literal_shape_counter_scratch_data,
};

pub(crate) fn original_host_initial_codec_schema_storage_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<(usize, usize), ProviderError> {
    let data = schemas::project(launch, maximum)?;
    Ok((data.transient, data.retained_reference_children))
}

// The original boot supplies its actual launch/registration and native row.
// Only the transient phase is restricted here; all independent retained roots
// remain in the original native quote and actual owner walk.
pub(super) fn hello_frame_work_data(
    launch: &PacketNative5SourceLaunch,
    registration: &[u8],
    raw: crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
    maximum: usize,
) -> Result<usize, ProviderError> {
    hello::project_with_raw(launch, registration, raw, maximum).map(|shape| shape.transient)
}

/// Counts the actual typed launch carried across the second raw frame.
///
/// This readonly capacity walk follows the original canonical digest guard.
///
/// # Errors
/// Refuses an unsupported metadata owner, borrowed child, or checked overflow.
pub(in crate::reference_packet::service) fn original_private_launch_backing_data(
    launch: &PacketNative5SourceLaunch,
) -> Result<usize, ProviderError> {
    let facts = crate::retained_metadata::observe_retained_native_launch(launch)?;
    sum(
        &[
            size_of::<PacketNative5SourceLaunch>(),
            requested_metadata_backing_storage_data(&facts)?,
        ],
        usize::MAX,
    )
}

// Both private frames are admitted against actual raw occurrences. The first
// may construct a partial native launch; the second BootData owns Value trees.
// Keep the compiled native Vec roster for both, including malformed partials.
pub(super) fn private_frame_work_data(
    raw: crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
    carry: usize,
) -> Result<usize, ProviderError> {
    let slots = raw.maximum_value_nodes.checked_mul(4).ok_or_else(refused)?;
    let typed = sum(
        &[
            raw.value_dom_requested_bytes,
            slots
                .checked_mul(native_element_slot())
                .ok_or_else(refused)?,
            raw.maximum_decoded_string_bytes
                .checked_mul(8)
                .ok_or_else(refused)?,
            size_of::<PacketNative5SourceLaunch>()
                .max(super::super::ack_emitter::original_native_ack_boot_layout()),
        ],
        usize::MAX,
    )?;
    sum(
        &[
            raw.canonical_pass_requested_bytes()?,
            raw.canonical_pass_requested_bytes()?,
            typed,
            carry,
        ],
        usize::MAX,
    )
}

pub use launch_validation::PacketNative5LaunchValidationStorage;

pub use coordinator_decode::PacketNative5CoordinatorConstructionStorage;

/// Measures genuine compiled Hello headers and its two original fixed getters.
///
/// This is an explicit operational export query, separate from the legacy
/// Hello arithmetic's unchanged end-only calls. Numeric facts authenticate no
/// Source/Job/native owner and require same-code/original input remeasurement.
pub fn original_native_hello_fixed_layout_data() -> HelloFixedLayoutData {
    HelloFixedLayoutData {
        headers: hello::HEADER_LAYOUT,
        hello_selection_counter_scratch_bytes:
            super::super::server::complete::hello_selection::counter_scratch_data(),
        hello_reuse_counter_scratch_bytes:
            crate::handshake::Handshake::original_native_hello_reuse_counter_scratch_data(),
    }
}

/// Names the actual new fixed header family required by the export getter.
///
/// The original Source/Job holder must admit this separate operational query
/// window before exporting layout facts; it creates no construction authority.
pub const fn original_native_hello_fixed_layout_counter_scratch_data() -> usize {
    crucible_source_birth_data::profile::reference_packet::service::native_startup::hello_shapes::fixed_layout_export_counter_scratch_data()
}
