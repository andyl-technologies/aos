//! Declares the existing complete Control decoder's fixed requested controls.
//!
//! Input/DOM/canonical/schema/typed backing and errors require a separate
//! admitted constructor row. This is no native permission and makes no change
//! to the old decoder, its field grammar or its validation order.

use super::*;
use crate::reference_packet::continuation_models::serde_partials::{
    DecoderPartial, decoder_struct,
};
use crate::reference_packet::continuation_models::{
    model_decoder_counter_scratch_data, owned_json_decoder_counter_scratch_data,
};
use std::mem::size_of;

decoder_struct!(ControlRecord {
    schema,
    captured_process,
    administrative_cut,
    local_cursor,
    model,
    control
});
decoder_struct!(ControlState {
    selection,
    originals,
    begins,
    begin_requests,
    content,
    content_bytes,
    realized,
    admitted,
    staged,
    active,
    fenced,
    native_effect_attempted,
    immediate,
    current_operation,
    terminals,
    common_coordinator,
    world_coordinator,
    connected_coordinator,
    complete_coordinator,
    complete_storage,
    complete_capture_profile,
    complete_confirmation_selection,
    complete_ack_emitter_selection,
    complete_protocol_metadata_limits,
    complete_protocol_metadata_birth_facts,
    complete_restore_selection,
    complete_restore_input_emitter_selection,
    complete_capture_allocation_selection
});
decoder_struct!(OriginalRecord {
    request,
    identity,
    response_body,
    evidence
});

impl PacketDecodedCaptureFutureControlData {
    /// Returns maximum emitted field count and total key bytes per actual DTO node.
    ///
    /// These compile-time facts follow exhaustive real field/tag rosters,
    /// including defaults omitted by input before later roundtrip refusal.
    /// Dynamic Value keys remain the caller's actual/expanded input facts.
    /// No serializer, DTO instance, native owner or constructor grant is made.
    pub fn decoder_emitted_field_geometry_data() -> (usize, usize) {
        const GEOMETRY: ((usize, usize, usize, usize), (usize, usize), usize) =
            complete_decoder_geometry_data();
        GEOMETRY.1
    }

    /// Returns complete actual typed slot and map key/value layout maxima.
    ///
    /// The tuple contains typed slot bytes, typed alignment, map K+V bytes and
    /// map alignment. It follows the actual Control/model and validation-created
    /// DTO field graph, including child vectors and concrete map instantiations.
    /// Content buffers and backing populations remain independently admitted;
    /// these layout facts create no constructor credit or native permission.
    pub fn decoder_typed_layout_geometry_data() -> (usize, usize, usize, usize) {
        const GEOMETRY: ((usize, usize, usize, usize), (usize, usize), usize) =
            complete_decoder_geometry_data();
        GEOMETRY.0
    }

    /// Returns simultaneous buffered tagged-enum levels in the actual DTO graph.
    ///
    /// The internally tagged CaptureProfile and ResponseShape each introduce
    /// one level and have no tagged DTO descendants. Dynamic Value traversal
    /// and RawValue reset parsers are separate actual JSON facts and rows.
    pub fn decoder_buffered_content_levels_data() -> usize {
        const GEOMETRY: ((usize, usize, usize, usize), (usize, usize), usize) =
            complete_decoder_geometry_data();
        GEOMETRY.2
    }

    /// Names one downstream expanded Value/Content/serializer/JCS activation.
    ///
    /// The actual Source independently multiplies this defining layout by its
    /// actual expanded/default-node bounds for each real later phase. It must
    /// retain/admit that variable S before decoding; the baseline64 counter is
    /// not a grant or a bound for the later expanded tree.
    pub fn decoder_expanded_value_frame_counter_scratch_data() -> usize {
        crate::protocol_snapshot::serde_decode_layout::owned_value_frame_counter_scratch_data()
            + crate::protocol_snapshot::serde_decode_layout::content_frame_counter_scratch_data()
            + crate::reference_packet::continuation_models::canonical_value_writer_frame_data()
    }

    /// Names fixed controls of the unchanged complete Control/model decoder.
    ///
    /// The actual Source admits this S before invoking the existing decoder.
    /// It covers ordinary retained/returned headers and concrete owned JSON
    /// visitor states under the unchanged baseline64 profile. Reserved RawValue
    /// parsing and actual expanded downstream nodes remain separate admitted
    /// rows, including their variable S from the defining frame getter. Heap
    /// backing, callback/outer-owner controls, generic compiler frames and
    /// physical stack residency remain separate; none receives allocation
    /// credit from this declaration.
    pub fn decoder_counter_scratch_data() -> usize {
        owned_json_decoder_counter_scratch_data()
            + model_decoder_counter_scratch_data()
            + ControlRecord::partial_counter_data()
            + WorldBinding::partial_counter_data()
            + GuaranteeProfile::partial_counter_data()
            + Vec::<Id>::partial_counter_data()
            + ResponseShape::partial_counter_data()
            + ExactRunArguments::partial_counter_data()
            + QuantumBeginArguments::partial_counter_data()
            + PauseArguments::partial_counter_data()
            + CaptureArguments::partial_counter_data()
            + PrepareRestoreArguments::partial_counter_data()
            + ShutdownArguments::partial_counter_data()
            + 65 * crate::protocol_snapshot::serde_decode_layout::content_frame_counter_scratch_data(
            )
            + size_of::<ControlRecord>()
            + size_of::<ControlState>()
            + size_of::<OriginalRecord>()
            + size_of::<PacketDecodedControlSnapshot>()
            + size_of::<Result<PacketDecodedControlSnapshot, ProviderError>>()
            + size_of::<&[u8]>()
            + size_of::<&ContentRef>()
            + size_of::<&ControlState>()
            + size_of::<&ControlRecord>()
            + size_of::<Value>() * 3
            + size_of::<Vec<u8>>() * 2
            + size_of::<ContentRef>() * 2
            + size_of::<HashRef>()
            + size_of::<Position>()
            + size_of::<String>()
            + size_of::<crate::bodies::ResponseShape>()
            + size_of::<Result<crate::bodies::ResponseShape, ProviderError>>()
            + size_of::<BeginRequest>()
            + size_of::<Option<&Value>>()
            + size_of::<Option<&str>>()
            + size_of::<Result<Value, ContractError>>()
            + size_of::<Result<ControlRecord, serde_json::Error>>()
            + size_of::<Result<ContentRef, ContractError>>()
            + size_of::<Result<Vec<u8>, ContractError>>()
            + validation_views_data()
            + selected_bank_validation_views_data()
            + contract_sorted_validation_views_data()
            + crate::reference_packet::continuation_models::serde_partials::version_field_counter_scratch_data()
    }
}

fn validation_views_data() -> usize {
    use std::collections::BTreeSet;
    size_of::<std::slice::Windows<'static, OriginalRecord>>()
        + size_of::<std::slice::Windows<'static, (ContentRef, Vec<u8>)>>()
        + size_of::<std::slice::Iter<'static, OriginalRecord>>()
        + size_of::<std::slice::Iter<'static, (ContentRef, Vec<u8>)>>()
        + size_of::<std::collections::btree_map::Iter<'static, Id, BeginRequest>>()
        + size_of::<std::collections::btree_map::Iter<'static, Id, Id>>()
        + size_of::<std::collections::btree_map::Iter<'static, Id, Map<String, Value>>>()
        + size_of::<std::slice::Iter<'static, SchemaRef>>()
        + size_of::<std::vec::IntoIter<SchemaRef>>()
        + size_of::<std::array::IntoIter<SchemaRef, 2>>()
        + size_of::<std::array::IntoIter<SchemaRef, 3>>()
        + size_of::<[SchemaRef; 2]>()
        + size_of::<[SchemaRef; 3]>()
        + size_of::<SchemaRef>()
        + size_of::<Result<SchemaRef, ProviderError>>()
        + size_of::<Vec<SchemaRef>>()
        + size_of::<BTreeSet<&Id>>()
        + size_of::<BTreeSet<Id>>()
        + size_of::<Option<(&ActivateRequest, &ContentRef)>>()
        + size_of::<Option<&WorldActivateRequest>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<usize>()
        + crate::reference_packet::coordinator::packet_native5_coordinator_installation_counter_scratch_data()
        + crate::reference_packet::coordinator::PacketConnectedCoordinatorInstallation::borrowed_validation_counter_scratch_data()
        + crate::connection::original_serialized_credit_counter_scratch_data()
}

fn selected_bank_validation_views_data() -> usize {
    // protocol_metadata.rs::validate_rows owns these exact three bank tuples,
    // their consuming iterator, both alias layout results and checked u64 cast.
    size_of::<[(U64, U64, usize); 3]>()
        + size_of::<std::array::IntoIter<(U64, U64, usize), 3>>()
        + size_of::<(U64, U64, usize)>()
        + size_of::<(usize, usize)>()
        + 2 * size_of::<usize>() // the two received alias layout values
        + size_of::<u64>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<Option<u64>>()
        // Protocol metadata selection tests its two actual U64 row limits.
        + size_of::<[U64; 2]>()
        + size_of::<std::slice::Iter<'static, U64>>()
        // Limits::validate consumes its actual five receiving-limit pairs.
        + size_of::<[(U64, u64); 5]>()
        + size_of::<std::array::IntoIter<(U64, u64), 5>>()
        + size_of::<(U64, u64)>()
        // native5 storage validate owns snapshot/chunk/prefix arithmetic.
        + 3 * size_of::<u64>()
        + size_of::<Option<u64>>()
        + size_of::<Result<(), ProviderError>>()
}

fn contract_sorted_validation_views_data() -> usize {
    // These are the actual schema field types passed to validate_sorted and
    // iterated for child validation by this Control/World's selected DTOs.
    sorted_views::<Id>()
        + sorted_views::<ArtifactIdentity>()
        + sorted_views::<ContentRef>()
        + sorted_views::<SchemaRef>()
        + sorted_views::<NodeBindingRef>()
        + sorted_views::<ConnectionDescriptor>()
        + sorted_views::<LaneDescriptor>()
        + sorted_views::<PortDescriptor>()
        + sorted_views::<NodeManifest>()
        + sorted_views::<NodeDescriptor>()
        + sorted_views::<NodeBinding>()
        + sorted_views::<OwnerRef>()
        + sorted_views::<OwnerBinding>()
        + sorted_views::<FacetSelection>()
        // validate_sorted compares two freshly returned keys. Actual callbacks
        // return Id, String, (domain,digest) or (schema/facet Id,Version).
        + 2 * size_of::<Id>()
        + 2 * size_of::<String>()
        + 2 * size_of::<(String, String)>()
        + 2 * size_of::<(Id, Version)>()
}

fn sorted_views<T: 'static>() -> usize {
    size_of::<&[T]>()
        + size_of::<std::slice::Windows<'static, T>>()
        + size_of::<Option<&[T]>>()
        + size_of::<std::slice::Iter<'static, T>>()
        + size_of::<&T>()
        + size_of::<&str>()
        + size_of::<Result<(), ContractError>>()
}

// These are the actual from_value roots reached by the unchanged complete
// decoder and its validator. Const evaluation constructs no DTO or heap bank.
const fn complete_decoder_geometry_data() -> ((usize, usize, usize, usize), (usize, usize), usize) {
    use crate::reference_packet::continuation_models::serde_partials::{
        maximum_fields_data, maximum_typed_layout_data,
    };

    let model = crate::reference_packet::continuation_models::model_decoder_geometry_data();
    let mut geometry = model;

    macro_rules! include_root {
        ($type:ty) => {
            geometry.0 = maximum_typed_layout_data(geometry.0, <$type>::TYPED_LAYOUT);
            geometry.1 = maximum_fields_data(geometry.1, <$type>::EMITTED_FIELDS);
            geometry.2 = if <$type>::BUFFERED_TAG_LEVELS > geometry.2 {
                <$type>::BUFFERED_TAG_LEVELS
            } else {
                geometry.2
            };
        };
    }

    include_root!(ControlRecord);
    include_root!(ResponseShape);
    include_root!(WorldBinding);
    include_root!(GuaranteeProfile);
    include_root!(Vec<Id>);
    include_root!(ExactRunArguments);
    include_root!(QuantumBeginArguments);
    include_root!(PauseArguments);
    include_root!(CaptureArguments);
    include_root!(PrepareRestoreArguments);
    include_root!(ShutdownArguments);

    geometry
}

impl PacketDecodedCaptureFutureControlData {
    /// Bounds one pinned serde_json ErrorImpl allocation behind its Error pointer.
    ///
    /// The bound follows the actual ErrorCode tag and Message/Io payloads plus
    /// ErrorImpl's code/line/column fields and their alignment. Each retained
    /// inner or outer Error owns a separate Box request. Message strings,
    /// enclosing errors and their growth remain separately admitted.
    pub fn decoder_error_impl_allocation_upper_bytes_data() -> usize {
        const BYTES: usize = crate::reference_packet::continuation_models::serde_partials::diagnostic_error_impl_allocation_upper_bytes_data();
        BYTES
    }

    /// Bounds the actual typed decoder's fixed diagnostic names and literals.
    ///
    /// This combines complete field/type/variant name rosters with pinned serde
    /// visitor formatting and custom Id/U64/version/Phase decode literals.
    /// It is only a text component: unknown raw/expanded input and escaping,
    /// scalar/location displays, parser syntax diagnostics, String/Box/ErrorImpl
    /// growth and outer Contract/Provider wrapping require independent rows.
    /// No input is decoded or rejected and no constructor credit is granted.
    pub fn decoder_diagnostic_static_text_bytes_data() -> usize {
        const NAMES: usize = complete_decoder_diagnostic_name_bytes_data();
        const FORMAT: usize = crate::reference_packet::continuation_models::serde_partials::diagnostic_format_text_bytes_data();
        NAMES + FORMAT
    }
}

const fn complete_decoder_diagnostic_name_bytes_data() -> usize {
    let mut names =
        crate::reference_packet::continuation_models::model_decoder_diagnostic_name_bytes_data();

    macro_rules! include_root {
        ($type:ty) => {
            if <$type>::DIAGNOSTIC_NAMES_BYTES > names {
                names = <$type>::DIAGNOSTIC_NAMES_BYTES;
            }
        };
    }

    include_root!(ControlRecord);
    include_root!(ResponseShape);
    include_root!(WorldBinding);
    include_root!(GuaranteeProfile);
    include_root!(Vec<Id>);
    include_root!(ExactRunArguments);
    include_root!(QuantumBeginArguments);
    include_root!(PauseArguments);
    include_root!(CaptureArguments);
    include_root!(PrepareRestoreArguments);
    include_root!(ShutdownArguments);

    names
}
