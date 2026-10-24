//! Names the actual complete Control decoder's nested derived field partials.
//!
//! Every roster is tied to its real DTO with an exhaustive field pattern. The
//! generated Option/Result slots recurse through the actual field type DAG;
//! no input, serializer, parser, historical-reader counter or native authority
//! is constructed. Arbitrary Value traversal is the separately admitted shared
//! JSON adapter row. These controls do not price heap backing.

use super::*;
use crate::bodies::*;
use crate::envelope::Nullable;
use crate::handshake::Limits;
use crate::reference_packet::{
    control::{PacketControlSelection, PacketNative5StorageSelection},
    coordinator::{
        PacketConnectedCoordinatorInstallation, PacketConnectedHostSelection,
        PacketCoordinatorInstallation, PacketNative5CoordinatorInstallation,
        PacketWorldCoordinatorInstallation,
    },
    service::{
        PacketNative5AckEmitterSelection, PacketNative5CaptureProfile,
        PacketNative5ConfirmationSelection, PacketNative5ProtocolMetadataBankFacts,
        PacketNative5ProtocolMetadataBirthFacts, PacketNative5ProtocolMetadataLimits,
        PacketNative5StorageLimits,
        capture_allocation::PacketNative5CaptureAllocationSelection,
        complete_restore::{
            PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
        },
    },
};
use crucible_node_format::*;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::mem::size_of;

type Error = serde_json::Error;

mod diagnostics;

/// Declares the actual owned DTO's ordinary serde partial layouts.
pub(in crate::reference_packet) trait DecoderPartial:
    Sized + 'static
{
    /// Returns ordinary partial field/result controls through this real DAG.
    fn partial_counter_data() -> usize;

    /// Bounds per-node generated field count and key bytes without an instance.
    const EMITTED_FIELDS: (usize, usize) = (0, 0);

    /// Names actual typed slot/alignment and map K+V/alignment maxima.
    const TYPED_LAYOUT: (usize, usize, usize, usize) = slot_layout_data::<Self>();

    /// Names actual heap element/map layouts, excluding inline-only root headers.
    const HEAP_LAYOUT: (usize, usize, usize, usize) = (0, 1, 0, 1);

    /// Counts simultaneously buffered tagged-enum levels in this actual DAG.
    const BUFFERED_TAG_LEVELS: usize = 0;

    /// Bounds the complete actual type/field/variant diagnostic-name roster.
    const DIAGNOSTIC_NAMES_BYTES: usize = 0;
}

/// Names one real derived field's partial slot and nested type controls.
pub(in crate::reference_packet) fn field_data<S, T: DecoderPartial>(_: fn(&S) -> &T) -> usize {
    size_of::<Option<T>>() + size_of::<Result<Option<T>, Error>>() + T::partial_counter_data()
}

/// Resolves a real field's associated geometry without evaluating its witness.
pub(in crate::reference_packet) const fn field_emitted_data<S, T: DecoderPartial>(
    _: fn(&S) -> &T,
) -> (usize, usize) {
    T::EMITTED_FIELDS
}

/// Combines per-node maxima without treating distinct nodes as one object.
pub(in crate::reference_packet) const fn maximum_fields_data(
    a: (usize, usize),
    b: (usize, usize),
) -> (usize, usize) {
    (
        if a.0 > b.0 { a.0 } else { b.0 },
        if a.1 > b.1 { a.1 } else { b.1 },
    )
}

/// Resolves a field type's actual heap layout without constructing that field.
pub(in crate::reference_packet) const fn field_typed_layout_data<S, T: DecoderPartial>(
    _: fn(&S) -> &T,
) -> (usize, usize, usize, usize) {
    T::TYPED_LAYOUT
}

/// Resolves only allocating descendants of a real field's type.
pub(in crate::reference_packet) const fn field_heap_layout_data<S, T: DecoderPartial>(
    _: fn(&S) -> &T,
) -> (usize, usize, usize, usize) {
    T::HEAP_LAYOUT
}

/// Resolves the actual child type's buffered-tag depth.
pub(in crate::reference_packet) const fn field_tag_levels_data<S, T: DecoderPartial>(
    _: fn(&S) -> &T,
) -> usize {
    T::BUFFERED_TAG_LEVELS
}

/// Combines actual child tagged-enum depths during constant evaluation.
const fn maximum_tag_levels_data(left: usize, right: usize) -> usize {
    if left > right { left } else { right }
}

/// Names one actual typed value's slot; no map is implied by that value.
pub(in crate::reference_packet) const fn slot_layout_data<T>() -> (usize, usize, usize, usize) {
    (size_of::<T>(), std::mem::align_of::<T>(), 0, 1)
}

/// Names the actual key/value arrays used by a concrete map instantiation.
const fn map_layout_data<K, V>() -> (usize, usize, usize, usize) {
    let alignment = if std::mem::align_of::<K>() > std::mem::align_of::<V>() {
        std::mem::align_of::<K>()
    } else {
        std::mem::align_of::<V>()
    };
    (0, 1, size_of::<K>() + size_of::<V>(), alignment)
}

/// Combines independent actual slot and map component maxima.
pub(in crate::reference_packet) const fn maximum_typed_layout_data(
    left: (usize, usize, usize, usize),
    right: (usize, usize, usize, usize),
) -> (usize, usize, usize, usize) {
    (
        if left.0 > right.0 { left.0 } else { right.0 },
        if left.1 > right.1 { left.1 } else { right.1 },
        if left.2 > right.2 { left.2 } else { right.2 },
        if left.3 > right.3 { left.3 } else { right.3 },
    )
}

/// Resolves the actual child type's static diagnostic-name roster.
pub(in crate::reference_packet) const fn field_diagnostic_name_bytes_data<S, T: DecoderPartial>(
    _: fn(&S) -> &T,
) -> usize {
    T::DIAGNOSTIC_NAMES_BYTES
}

/// Names fixed formatting literals reached by this decoder's typed visitors.
pub(in crate::reference_packet) const fn diagnostic_format_text_bytes_data() -> usize {
    diagnostics::format_literal_bytes_data()
}

/// Names the concrete custom Version field decoder's fixed states.
pub(in crate::reference_packet) fn version_field_counter_scratch_data() -> usize {
    diagnostics::version_field_counter_scratch_data()
}

/// Bounds a pinned ErrorImpl allocation independently of its Error pointer.
pub(in crate::reference_packet) const fn diagnostic_error_impl_allocation_upper_bytes_data() -> usize
{
    diagnostics::error_impl_allocation_upper_bytes_data()
}

/// Names the actual private model-kind unit enum's diagnostic roster.
pub(in crate::reference_packet) const fn model_kind_diagnostic_name_bytes_data() -> usize {
    diagnostics::model_kind_name_bytes_data()
}

macro_rules! decoder_struct {
    ($name:ident { $($field:ident),+ $(,)? }) => {
        impl $crate::reference_packet::continuation_models::serde_partials::DecoderPartial for $name {
            const EMITTED_FIELDS: (usize, usize) = {
                let mut fields = 0usize;
                let mut bytes = 0usize;
                let mut nested = (0usize, 0usize);

                $(
                    fields += 1;
                    bytes += stringify!($field).len();
                    nested = $crate::reference_packet::continuation_models::serde_partials::maximum_fields_data(
                        nested,
                        $crate::reference_packet::continuation_models::serde_partials::field_emitted_data(
                            |value: &Self| &value.$field
                        ),
                    );
                )+

                $crate::reference_packet::continuation_models::serde_partials::maximum_fields_data(
                    (fields, bytes),
                    nested
                )
            };

            const TYPED_LAYOUT: (usize, usize, usize, usize) = {
                let mut layout = $crate::reference_packet::continuation_models::serde_partials::slot_layout_data::<Self>();

                $(
                    layout = $crate::reference_packet::continuation_models::serde_partials::maximum_typed_layout_data(
                        layout,
                        $crate::reference_packet::continuation_models::serde_partials::field_typed_layout_data(
                            |value: &Self| &value.$field,
                        ),
                    );
                )+

                layout
            };

            const HEAP_LAYOUT: (usize, usize, usize, usize) = {
                let mut layout = (0, 1, 0, 1);

                $(
                    layout = $crate::reference_packet::continuation_models::serde_partials::maximum_typed_layout_data(
                        layout,
                        $crate::reference_packet::continuation_models::serde_partials::field_heap_layout_data(
                            |value: &Self| &value.$field,
                        ),
                    );
                )+

                layout
            };

            const BUFFERED_TAG_LEVELS: usize = {
                let mut levels = 0usize;

                $(
                    let child = $crate::reference_packet::continuation_models::serde_partials::field_tag_levels_data(
                        |value: &Self| &value.$field,
                    );
                    levels = if child > levels { child } else { levels };
                )+

                levels
            };

            const DIAGNOSTIC_NAMES_BYTES: usize = {
                let mut own = stringify!($name).len();
                let mut nested = 0usize;

                $(
                    // Backticks plus the OneOf list separator are distinct
                    // actual formatting bytes for every complete field name.
                    own += stringify!($field).len() + "``".len() + ", ".len();
                    let child = $crate::reference_packet::continuation_models::serde_partials::field_diagnostic_name_bytes_data(
                        |value: &Self| &value.$field,
                    );
                    nested = if child > nested { child } else { nested };
                )+

                if own > nested { own } else { nested }
            };

            fn partial_counter_data() -> usize {
                // The private derive field selector has one unit variant per
                // real field. A usize tag upper-bounds its local and Option;
                // Error pointer + fulltag/alignment bounds its returned Result.
                std::mem::size_of::<Self>()
                    + std::mem::size_of::<Result<Self, serde_json::Error>>()
                    + $crate::reference_packet::continuation_models::serde_partials::field_selector_data()
                    $(
                        + $crate::reference_packet::continuation_models::serde_partials::field_data(
                            |value: &Self| &value.$field
                        )
                    )+
            }
        }

        const _: fn(&$name) = |value| {
            let $name { $($field: _,)+ } = value;
        };
    };
}
pub(in crate::reference_packet) use decoder_struct;

/// Bounds the actual finite derive field selector and its returned states.
pub(in crate::reference_packet) fn field_selector_data() -> usize {
    // serde derive's field enum is finite and fieldless. Unit enum/tag +Option
    // may each require a usize; returned Result also contains Error and a tag,
    // with field and tail padding. No unrelated deserializer stands in for it.
    let alignment = std::mem::align_of::<usize>().max(std::mem::align_of::<Error>());
    3 * size_of::<usize>() + size_of::<Error>() + 2 * (alignment - 1)
}

macro_rules! scalar {
    ($($type:ty),+ $(,)?) => {
        $(
            impl DecoderPartial for $type {
                const DIAGNOSTIC_NAMES_BYTES: usize =
                    diagnostics::scalar_name_bytes_data::<Self>();

                fn partial_counter_data() -> usize {
                    size_of::<Self>() + size_of::<Result<Self, Error>>()
                }
            }
        )+
    };
}

scalar!(
    bool,
    u8,
    u16,
    u32,
    u64,
    usize,
    i64,
    Phase,
    Direction,
    OperatingMode,
    SchedulingRole,
    BoundaryPolicy,
    BeginKind,
    OperationState,
    EffectCertainty,
    Repeatability,
    CaptureScope,
    Continuation,
    PacketNative5ConfirmationSelection,
    PacketNative5AckEmitterSelection,
    PacketNative5CompleteRestoreSelection,
    PacketNative5RestoreInputEmitterSelection,
    PacketNative5CaptureAllocationSelection
);

impl DecoderPartial for String {
    const HEAP_LAYOUT: (usize, usize, usize, usize) = slot_layout_data::<u8>();

    fn partial_counter_data() -> usize {
        size_of::<Self>() + size_of::<Result<Self, Error>>()
    }
}

impl DecoderPartial for Id {
    const HEAP_LAYOUT: (usize, usize, usize, usize) = String::HEAP_LAYOUT;

    fn partial_counter_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, Error>>()
            + String::partial_counter_data()
            + size_of::<Result<Self, ContractError>>()
            + size_of::<Result<Self, crucible_node_format::IdFromOwnedError>>()
            + crucible_node_format::IdFromOwnedError::construction_transient_bytes_data()
            + crucible_node_format::IdFromOwnedError::construction_counter_scratch_bytes_data()
            + size_of::<std::str::Bytes<'static>>()
    }
}

impl DecoderPartial for U64 {
    const HEAP_LAYOUT: (usize, usize, usize, usize) = String::HEAP_LAYOUT;

    fn partial_counter_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, Error>>()
            + String::partial_counter_data()
            + size_of::<Result<Self, ContractError>>()
            + size_of::<Result<u64, std::num::ParseIntError>>()
            + size_of::<std::str::Bytes<'static>>()
            + size_of::<&str>()
    }
}

impl<T: DecoderPartial> DecoderPartial for Option<T> {
    const EMITTED_FIELDS: (usize, usize) = T::EMITTED_FIELDS;
    const HEAP_LAYOUT: (usize, usize, usize, usize) = T::HEAP_LAYOUT;

    const TYPED_LAYOUT: (usize, usize, usize, usize) =
        maximum_typed_layout_data(slot_layout_data::<Self>(), T::TYPED_LAYOUT);
    const BUFFERED_TAG_LEVELS: usize = T::BUFFERED_TAG_LEVELS;

    const DIAGNOSTIC_NAMES_BYTES: usize = T::DIAGNOSTIC_NAMES_BYTES;

    fn partial_counter_data() -> usize {
        size_of::<Self>() + size_of::<Result<Self, Error>>() + T::partial_counter_data()
    }
}

impl<T: DecoderPartial> DecoderPartial for Nullable<T> {
    const EMITTED_FIELDS: (usize, usize) = T::EMITTED_FIELDS;
    const HEAP_LAYOUT: (usize, usize, usize, usize) =
        maximum_typed_layout_data(Value::HEAP_LAYOUT, T::HEAP_LAYOUT);

    const TYPED_LAYOUT: (usize, usize, usize, usize) =
        maximum_typed_layout_data(slot_layout_data::<Self>(), T::TYPED_LAYOUT);
    const BUFFERED_TAG_LEVELS: usize = T::BUFFERED_TAG_LEVELS;

    const DIAGNOSTIC_NAMES_BYTES: usize = T::DIAGNOSTIC_NAMES_BYTES;

    fn partial_counter_data() -> usize {
        // Actual Nullable first obtains Value, then from_value<T>. Recurse only
        // through this T; Nullable<Id> does not acquire a recursive container.
        size_of::<Self>()
            + size_of::<Result<Self, Error>>()
            + size_of::<Value>()
            + size_of::<Result<Value, Error>>()
            + size_of::<Result<T, Error>>()
            + T::partial_counter_data()
    }
}

impl<T: DecoderPartial> DecoderPartial for Vec<T> {
    const EMITTED_FIELDS: (usize, usize) = T::EMITTED_FIELDS;
    const HEAP_LAYOUT: (usize, usize, usize, usize) =
        maximum_typed_layout_data(slot_layout_data::<T>(), T::HEAP_LAYOUT);

    const TYPED_LAYOUT: (usize, usize, usize, usize) =
        maximum_typed_layout_data(slot_layout_data::<Self>(), T::TYPED_LAYOUT);
    const BUFFERED_TAG_LEVELS: usize = T::BUFFERED_TAG_LEVELS;

    const DIAGNOSTIC_NAMES_BYTES: usize = T::DIAGNOSTIC_NAMES_BYTES;

    fn partial_counter_data() -> usize {
        size_of::<Self>()
            + size_of::<Option<usize>>()
            + size_of::<Result<Self, Error>>()
            + size_of::<Option<T>>()
            + size_of::<Result<Option<T>, Error>>()
            + T::partial_counter_data()
    }
}

impl<K: DecoderPartial, V: DecoderPartial> DecoderPartial for BTreeMap<K, V> {
    const EMITTED_FIELDS: (usize, usize) =
        maximum_fields_data(K::EMITTED_FIELDS, V::EMITTED_FIELDS);
    const HEAP_LAYOUT: (usize, usize, usize, usize) = maximum_typed_layout_data(
        map_layout_data::<K, V>(),
        maximum_typed_layout_data(K::HEAP_LAYOUT, V::HEAP_LAYOUT),
    );

    const TYPED_LAYOUT: (usize, usize, usize, usize) = maximum_typed_layout_data(
        maximum_typed_layout_data(slot_layout_data::<Self>(), map_layout_data::<K, V>()),
        maximum_typed_layout_data(K::TYPED_LAYOUT, V::TYPED_LAYOUT),
    );
    const BUFFERED_TAG_LEVELS: usize = if K::BUFFERED_TAG_LEVELS > V::BUFFERED_TAG_LEVELS {
        K::BUFFERED_TAG_LEVELS
    } else {
        V::BUFFERED_TAG_LEVELS
    };

    const DIAGNOSTIC_NAMES_BYTES: usize = if K::DIAGNOSTIC_NAMES_BYTES > V::DIAGNOSTIC_NAMES_BYTES {
        K::DIAGNOSTIC_NAMES_BYTES
    } else {
        V::DIAGNOSTIC_NAMES_BYTES
    };

    fn partial_counter_data() -> usize {
        size_of::<Self>()
            + size_of::<Option<(K, V)>>()
            + size_of::<Result<Option<(K, V)>, Error>>()
            + size_of::<Result<Self, Error>>()
            + K::partial_counter_data()
            + V::partial_counter_data()
    }
}

impl<A: DecoderPartial, B: DecoderPartial> DecoderPartial for (A, B) {
    const EMITTED_FIELDS: (usize, usize) =
        maximum_fields_data(A::EMITTED_FIELDS, B::EMITTED_FIELDS);
    const HEAP_LAYOUT: (usize, usize, usize, usize) =
        maximum_typed_layout_data(A::HEAP_LAYOUT, B::HEAP_LAYOUT);

    const TYPED_LAYOUT: (usize, usize, usize, usize) = maximum_typed_layout_data(
        slot_layout_data::<Self>(),
        maximum_typed_layout_data(A::TYPED_LAYOUT, B::TYPED_LAYOUT),
    );
    const BUFFERED_TAG_LEVELS: usize = if A::BUFFERED_TAG_LEVELS > B::BUFFERED_TAG_LEVELS {
        A::BUFFERED_TAG_LEVELS
    } else {
        B::BUFFERED_TAG_LEVELS
    };

    const DIAGNOSTIC_NAMES_BYTES: usize = if A::DIAGNOSTIC_NAMES_BYTES > B::DIAGNOSTIC_NAMES_BYTES {
        A::DIAGNOSTIC_NAMES_BYTES
    } else {
        B::DIAGNOSTIC_NAMES_BYTES
    };

    fn partial_counter_data() -> usize {
        size_of::<Self>()
            + size_of::<Option<A>>()
            + size_of::<Option<B>>()
            + size_of::<Result<Self, Error>>()
            + A::partial_counter_data()
            + B::partial_counter_data()
    }
}

impl DecoderPartial for Value {
    const HEAP_LAYOUT: (usize, usize, usize, usize) = maximum_typed_layout_data(
        slot_layout_data::<Self>(),
        map_layout_data::<String, Value>(),
    );
    // Dynamic JSON traversal is independently bounded by actual raw/expanded
    // facts; it does not introduce another schema-specific tagged DTO level.
    const TYPED_LAYOUT: (usize, usize, usize, usize) = maximum_typed_layout_data(
        slot_layout_data::<Self>(),
        map_layout_data::<String, Value>(),
    );

    fn partial_counter_data() -> usize {
        size_of::<Self>() + size_of::<Result<Self, Error>>()
    }
}

impl DecoderPartial for serde_json::Map<String, Value> {
    const HEAP_LAYOUT: (usize, usize, usize, usize) = Value::HEAP_LAYOUT;
    const TYPED_LAYOUT: (usize, usize, usize, usize) = maximum_typed_layout_data(
        slot_layout_data::<Self>(),
        map_layout_data::<String, Value>(),
    );

    fn partial_counter_data() -> usize {
        size_of::<Self>() + size_of::<Result<Self, Error>>()
    }
}

decoder_struct!(ArtifactIdentity {
    id,
    role,
    content,
    extensions,
});

decoder_struct!(BindingCompatibility {
    schema_version,
    node_id,
    descriptor_hash,
    implementation,
    profile_ref,
    configuration_ref,
    operating_contract,
    execution_owner,
    capture_owner,
    capabilities_ref,
    guarantees_ref,
    qualification_refs,
    extensions,
});

decoder_struct!(ContentRef {
    hash,
    length,
    media_type,
});

decoder_struct!(ExtensionSelection {
    declaration,
    identifier,
    semantic_version,
    schema_digest,
});

decoder_struct!(FacetSelection {
    id,
    version,
    configuration_ref,
    guarantees_ref,
    extensions,
});

decoder_struct!(HashRef {
    algorithm,
    domain,
    digest,
});

decoder_struct!(ImplementationIdentity {
    schema_version,
    implementation_id,
    artifacts,
    model_definitions,
    formats,
    extensions,
});

decoder_struct!(LaneDescriptor {
    id,
    direction,
    payload_schema,
    maximum_payload_bytes,
    maximum_pending_events,
    extensions,
});

decoder_struct!(LiveAuthority {
    schema_version,
    session_id,
    incarnation_id,
    realization_id,
    activation_id,
    world_generation,
    owner_generation,
    input_epoch,
    host_receipt,
    extensions,
});

decoder_struct!(NodeBinding {
    compatibility,
    authority,
    extensions,
});

decoder_struct!(NodeBindingRef {
    node_id,
    binding_hash,
    extensions,
});

decoder_struct!(NodeDescriptor {
    schema_version,
    id,
    roles,
    model_ref,
    configuration_ref,
    initialization_ref,
    ports,
    extensions,
});

decoder_struct!(NodeManifest {
    schema_version,
    profile_id,
    roles,
    configuration_schema,
    allowed_combinations_ref,
    port_templates_ref,
    state_formats,
    operation_facets,
    extensions,
});

decoder_struct!(OperatingContract {
    schema_version,
    mode,
    scheduling_role,
    ordering_profile,
    policy_ref,
    resolution_ps,
    phase_ps,
    facets,
    extensions,
});

decoder_struct!(OwnerBinding {
    schema_version,
    owner,
    owner_roles,
    node_bindings,
    ownership_ref,
    extensions,
});

decoder_struct!(OwnerRef {
    id,
    participant_ids,
    state_domain_ids,
});

decoder_struct!(PacketConnectedHostSelection {
    descriptor,
    binding,
    owner,
    prepared_token,
    initial_node,
});

decoder_struct!(PacketControlSelection {
    provider,
    realization,
    realize,
    prepared_token,
    admission,
    transaction,
    gate,
    world,
    admission_receipt,
});

decoder_struct!(PacketNative5CoordinatorInstallation {
    schema,
    participants,
    host,
    template,
});

decoder_struct!(PortDescriptor {
    id,
    lanes,
    interface_id,
    features,
    configuration_ref,
    extensions,
});

decoder_struct!(ProviderManifest {
    schema_version,
    provider_id,
    implementation,
    protocol_versions,
    supported_profiles,
    extensions_supported,
    qualification_refs,
    extensions,
});

decoder_struct!(RealizationManifest {
    schema_version,
    realization_id,
    provider_manifest,
    descriptors,
    bindings,
    owners,
    owner_bindings,
    extensions,
});

decoder_struct!(RealizeRequest {
    realization_id,
    configuration,
    requested_node_ids,
    resource_limits,
    extensions,
});

decoder_struct!(ResourceLimits {
    cpu_budget_ns,
    memory_bytes,
    writable_bytes,
    processes,
    descriptors,
    pending_events,
    content_bytes,
    maximum_operations,
    extensions,
});

decoder_struct!(SchemaRef {
    id,
    version,
    definition,
    extensions,
});

decoder_struct!(SemanticVersion {
    major,
    minor,
    patch,
    prerelease,
    build,
});

// Coordinator validation derives these typed children from its retained template.
decoder_struct!(WorldBinding {
    schema_version,
    scenario_ref,
    node_bindings,
    connections,
    ownership_ref,
    coordinator_contract_ref,
    ordering_profile,
    initialization_ref,
    extensions,
});

decoder_struct!(ConnectionDescriptor {
    schema_version,
    id,
    producer,
    consumer,
    interface_id,
    features,
    payload_schema,
    minimum_latency_ps,
    policy_ref,
    capture_owner_id,
    extensions,
});

decoder_struct!(Endpoint {
    node_id,
    port_id,
    lane_id,
});

decoder_struct!(GuaranteeProfile {
    schema_version,
    repeatability,
    capture_scope,
    continuation,
    durable_restart,
    isolated_fork,
    conditional_replay,
    limitations_ref,
    extensions,
});

decoder_struct!(PacketCoordinatorInstallation { schema, template });

decoder_struct!(PacketWorldCoordinatorInstallation {
    schema,
    participants,
    template,
});

decoder_struct!(PacketConnectedCoordinatorInstallation {
    schema,
    participants,
    host,
    template,
});

decoder_struct!(PacketNative5StorageSelection { storage, limits });

decoder_struct!(PacketNative5StorageLimits {
    snapshot_bytes,
    control_snapshot_bytes,
    protocol_snapshot_bytes,
    frame_bank_bytes,
    frames_per_direction,
    hello_bytes,
    settlement_bytes,
});

decoder_struct!(Limits {
    frame_bytes,
    nesting,
    requests,
    journal_entries,
    blob_chunk_bytes,
});

decoder_struct!(PacketNative5ProtocolMetadataLimits {
    native_before_rows,
    native_after_rows,
});

decoder_struct!(PacketNative5ProtocolMetadataBankFacts {
    selected_rows,
    record_capacity,
    record_bytes,
    alias_row_capacity,
    alias_lookup_capacity,
    alias_row_bytes,
    alias_lookup_bytes,
});

decoder_struct!(PacketNative5ProtocolMetadataBirthFacts { before, after });

decoder_struct!(ActivateRequest {
    admission_id,
    activation_id,
    world_generation,
    prepared_token,
    world_binding_hash,
    gate_id,
    extensions,
});

decoder_struct!(BeginRequest {
    kind,
    binding_hash,
    owner_generation,
    activation_id,
    world_generation,
    arguments,
    extensions,
});

decoder_struct!(WorldActivateRequest {
    transaction_id,
    activation_id,
    world_generation,
    prepared_token,
    world_binding_hash,
    gate_id,
    activation_manifest,
    extensions,
});

decoder_struct!(ErrorRecord {
    code,
    message,
    effect,
    retryable,
    details,
});

decoder_struct!(ExactRunArguments {
    grant_id,
    participant_ids,
    realization_id,
    activation_id,
    world_generation,
    owner_generation,
    input_epoch,
    mode,
    ordering_profile,
    start,
    limit,
    boundary_policy,
    input_authorization,
    input_watermark,
});

decoder_struct!(QuantumBeginArguments {
    grant_id,
    participant_ids,
    realization_id,
    activation_id,
    world_generation,
    owner_generation,
    input_epoch,
    mode,
    ordering_profile,
    quantum_index,
    from_ps,
    until_ps,
    input_batch,
    input_watermark,
    policy_hash,
    wall_budget_ns,
});

decoder_struct!(PauseArguments {
    participant_ids,
    reason,
});

decoder_struct!(CaptureArguments {
    capture_id,
    participant_ids,
    cut_id,
    cut,
    event_ordinal,
    ordering_profile,
    preservation_contract,
});

decoder_struct!(PrepareRestoreArguments {
    transaction_id,
    capture_manifest,
    expected_world_binding_hash,
    expected_owner_binding_hash,
    destination_owner_ids,
});

decoder_struct!(ShutdownArguments {
    participant_ids,
    reason,
});

decoder_struct!(Position {
    time_ps,
    microstep,
    phase,
});

impl DecoderPartial for PacketNative5CaptureProfile {
    const HEAP_LAYOUT: (usize, usize, usize, usize) = U64::HEAP_LAYOUT;
    const EMITTED_FIELDS: (usize, usize) = (
        4,
        "encoding".len()
            + "native_before_protocol_bytes".len()
            + "native_after_protocol_bytes".len()
            + "host_protocol_bytes".len(),
    );

    const TYPED_LAYOUT: (usize, usize, usize, usize) =
        maximum_typed_layout_data(slot_layout_data::<Self>(), U64::TYPED_LAYOUT);
    const BUFFERED_TAG_LEVELS: usize = 1 + U64::BUFFERED_TAG_LEVELS;

    const DIAGNOSTIC_NAMES_BYTES: usize = "PacketNative5CaptureProfile".len()
        + "original_arrays6".len()
        + "compact_bytes7".len()
        + "owned_protocol11".len()
        + "encoding".len()
        + "native_before_protocol_bytes".len()
        + "native_after_protocol_bytes".len()
        + "host_protocol_bytes".len()
        + 7 * ("``".len() + ", ".len());

    fn partial_counter_data() -> usize {
        // Two data variants have the same three U64 fields. Their field slots
        // coexist only within the selected variant; tag Content is separate.
        size_of::<Self>()
            + size_of::<Result<Self, Error>>()
            + field_selector_data()
            + 3 * (size_of::<Option<U64>>()
                + size_of::<Result<Option<U64>, Error>>()
                + U64::partial_counter_data())
    }
}

const _: fn(&PacketNative5CaptureProfile) = |value| match value {
    PacketNative5CaptureProfile::OriginalArrays6 => {}
    PacketNative5CaptureProfile::CompactBytes7 {
        native_before_protocol_bytes: _,
        native_after_protocol_bytes: _,
        host_protocol_bytes: _,
    }
    | PacketNative5CaptureProfile::OwnedProtocol11 {
        native_before_protocol_bytes: _,
        native_after_protocol_bytes: _,
        host_protocol_bytes: _,
    } => {}
};

impl DecoderPartial for ResponseShape {
    const HEAP_LAYOUT: (usize, usize, usize, usize) = maximum_typed_layout_data(
        Map::<String, Value>::HEAP_LAYOUT,
        maximum_typed_layout_data(ErrorRecord::HEAP_LAYOUT, Extensions::HEAP_LAYOUT),
    );
    const EMITTED_FIELDS: (usize, usize) = maximum_fields_data(
        (
            4,
            "status".len() + "operation_state".len() + "result".len() + "extensions".len(),
        ),
        ErrorRecord::EMITTED_FIELDS,
    );

    const TYPED_LAYOUT: (usize, usize, usize, usize) = maximum_typed_layout_data(
        slot_layout_data::<Self>(),
        maximum_typed_layout_data(
            OperationState::TYPED_LAYOUT,
            maximum_typed_layout_data(
                Map::<String, Value>::TYPED_LAYOUT,
                maximum_typed_layout_data(ErrorRecord::TYPED_LAYOUT, Extensions::TYPED_LAYOUT),
            ),
        ),
    );
    // The actual internally tagged branches currently contain no other tagged
    // DTO. Propagate their real child facts so a field-type change is visible;
    // arbitrary Value trees remain the independent dynamic JSON row.
    const BUFFERED_TAG_LEVELS: usize = 1 + maximum_tag_levels_data(
        maximum_tag_levels_data(
            OperationState::BUFFERED_TAG_LEVELS,
            Map::<String, Value>::BUFFERED_TAG_LEVELS,
        ),
        maximum_tag_levels_data(
            ErrorRecord::BUFFERED_TAG_LEVELS,
            Extensions::BUFFERED_TAG_LEVELS,
        ),
    );

    const DIAGNOSTIC_NAMES_BYTES: usize = {
        let own = "ResponseShape".len()
            + "accepted".len()
            + "completed".len()
            + "error".len()
            + "status".len()
            + "operation_state".len()
            + "result".len()
            + "error".len()
            + "extensions".len()
            + 8 * ("``".len() + ", ".len());
        if own > ErrorRecord::DIAGNOSTIC_NAMES_BYTES {
            own
        } else {
            ErrorRecord::DIAGNOSTIC_NAMES_BYTES
        }
    };

    fn partial_counter_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, Error>>()
            + field_selector_data()
            + size_of::<Option<OperationState>>()
            + OperationState::partial_counter_data()
            + size_of::<Option<Map<String, Value>>>()
            + Map::<String, Value>::partial_counter_data()
            + size_of::<Option<ErrorRecord>>()
            + ErrorRecord::partial_counter_data()
            + size_of::<Option<Extensions>>()
            + Extensions::partial_counter_data()
    }
}

const _: fn(&ResponseShape) = |value| match value {
    ResponseShape::Accepted {
        operation_state: _,
        result: _,
        extensions: _,
    }
    | ResponseShape::Completed {
        operation_state: _,
        result: _,
        extensions: _,
    } => {}
    ResponseShape::Error {
        operation_state: _,
        error: _,
        extensions: _,
    } => {}
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_layouts_distinguish_inline_roots_from_real_container_elements() {
        assert_eq!(Option::<ContentRef>::HEAP_LAYOUT.0, size_of::<u8>());
        assert!(Option::<ContentRef>::TYPED_LAYOUT.0 >= size_of::<ContentRef>());
        assert_eq!(Vec::<ContentRef>::HEAP_LAYOUT.0, size_of::<ContentRef>());

        let tree = BTreeMap::<Id, ContentRef>::HEAP_LAYOUT;
        assert_eq!(tree.0, size_of::<u8>());
        assert_eq!(tree.2, size_of::<Id>() + size_of::<ContentRef>());
        assert_eq!(Vec::<BTreeMap<Id, ContentRef>>::HEAP_LAYOUT.2, tree.2);
    }

    fn actual_emitted_fields<T: DecoderPartial + serde::Serialize>(value: &T) {
        let encoded = serde_json::to_value(value).unwrap();
        let object = encoded.as_object().unwrap();
        let (fields, keys) = T::EMITTED_FIELDS;
        assert!(object.len() <= fields);
        assert!(object.keys().map(String::len).sum::<usize>() <= keys);
    }

    #[test]
    fn real_nullable_version_and_closed_ref_emissions_fit_defining_rosters() {
        let version: SemanticVersion = serde_json::from_value(serde_json::json!({
            "major":"1","minor":"2","patch":"3", "prerelease":null,"build":null
        }))
        .unwrap();
        actual_emitted_fields(&version);

        let reference = ContentRef {
            hash: HashRef {
                algorithm: "blake3".into(),
                domain: "test-data".into(),
                digest: "00".repeat(32),
            },
            length: U64::new(0),
            media_type: "application/json".into(),
        };
        actual_emitted_fields(&reference);
    }

    #[test]
    fn real_nullable_begin_and_tagged_profile_emit_without_native_authority() {
        let begin = BeginRequest {
            kind: BeginKind::Capture,
            binding_hash: HashRef {
                algorithm: "blake3".into(),
                domain: "cnp.owner-binding.v1".into(),
                digest: "00".repeat(32),
            },
            owner_generation: U64::new(1),
            activation_id: Nullable(None),
            world_generation: U64::new(1),
            arguments: Map::new(),
            extensions: Extensions::new(),
        };
        // This is only ordinary Serialize DATA; empty arguments are deliberately
        // no valid Capture action or private Source/native authority.
        actual_emitted_fields(&begin);
        let profile = PacketNative5CaptureProfile::OwnedProtocol11 {
            native_before_protocol_bytes: U64::new(1),
            native_after_protocol_bytes: U64::new(2),
            host_protocol_bytes: U64::new(3),
        };
        actual_emitted_fields(&profile);
    }
}
