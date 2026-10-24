//! Counts one original packet prefix and its actual frame preparation work.
//!
//! The components describe requested layouts. They do not authenticate a
//! connection, select a native request family, observe retained capacities or
//! issue allocation/transport credit. Transport retains all live reconciliation.

use crate::ProviderError;
use crate::profile::envelope::Method;
use crate::profile::serialization_storage::OriginalSerializationStorageData;
use crucible_node_format::{ContentRef, Id, U64};
use std::mem::{align_of, size_of};

/// Names each independent original prefix obligation without authorizing it.
#[derive(Debug, Eq, PartialEq)]
pub struct OriginalPacketPrefixStorageData {
    /// Separates actual native-baseline persistent banks from legacy work.
    /// Ordinary/public prefix quotes keep their existing summed components.
    pub native_retained_backing_bytes: Option<usize>,
    /// Counts all planned response and proof frames.
    pub frames: usize,
    /// Counts proof requests that may require acknowledgements.
    pub requests: usize,
    /// Counts the projected evidence payload bytes.
    pub evidence_payload_bytes: usize,
    /// Counts the complete projected outgoing framed bytes.
    pub outgoing_framed_bytes: usize,
    /// Counts the complete projected incoming framed bytes.
    pub incoming_framed_bytes: usize,
    /// Bounds the unchanged native prefix wire-credit charge, not heap storage.
    pub new_transport_credit_bytes: usize,
    /// Counts independent original-plan requested storage.
    pub original_plan_requested_bytes: usize,
    /// Counts acknowledgement-index requested storage.
    pub acknowledgement_index_requested_bytes: usize,
    /// Counts independent retained canonical banks.
    pub canonical_requested_bytes: usize,
    /// Counts record and frame-slot requested storage.
    pub record_slots_requested_bytes: usize,
    /// Counts independently retained outgoing guard storage.
    pub outgoing_guard_requested_bytes: usize,
    /// Counts the prospective response iterator storage.
    pub response_iterator_requested_bytes: usize,
    /// Counts closed successful acknowledgement cache storage.
    pub successful_ack_cache_requested_bytes: usize,
    /// Counts one complete terminating open acknowledgement.
    pub one_open_ack_requested_bytes: usize,
    /// Counts independently retained containment storage.
    pub containment_requested_bytes: usize,
    /// Counts the complete construction work sum.
    pub construction_transient_requested_bytes: usize,
    /// Counts the complete preparation work sum.
    pub preparation_transient_requested_bytes: usize,
    /// Counts the defining fixed quote/header controls.
    pub declared_quote_scratch_bytes: usize,
    /// Is a subextent of the existing literal allocation, not a new bank request.
    pub original_literal_required_bytes: usize,
    /// Is a subextent of the existing descriptor bank, not a new allocation.
    pub original_slots_required: usize,
}

impl OriginalPacketPrefixStorageData {
    /// Sums the original twelve requested-storage components.
    ///
    /// # Errors
    /// Refuses checked requested-storage overflow.
    pub fn requested_bytes(&self) -> Result<usize, ProviderError> {
        sum(&[
            self.original_plan_requested_bytes,
            self.acknowledgement_index_requested_bytes,
            self.canonical_requested_bytes,
            self.record_slots_requested_bytes,
            self.outgoing_guard_requested_bytes,
            self.response_iterator_requested_bytes,
            self.successful_ack_cache_requested_bytes,
            self.one_open_ack_requested_bytes,
            self.containment_requested_bytes,
            self.construction_transient_requested_bytes,
            self.preparation_transient_requested_bytes,
            self.declared_quote_scratch_bytes,
        ])
    }
}

/// Charges the actual original frame and validation arithmetic in place.
///
/// The upper owner supplies its genuine compiled request/response header width
/// and ACK layout. A refusal preserves all preceding component updates in
/// `data`; the caller must retain that failed prefix. No allocation occurs.
///
/// # Errors
/// Refuses an oversized encoded frame, checked arithmetic/layout overflow or
/// the unchanged ACK storage refusals, in the original evaluation order.
pub fn charge_frame(
    data: &mut OriginalPacketPrefixStorageData,
    projected: OriginalSerializationStorageData,
    request: bool,
    maximum_frame: usize,
    maximum_body_header_bytes: usize,
    acknowledgement_layout: &super::report_ack::AckFixedLayoutData,
) -> Result<(), ProviderError> {
    if projected.maximum_encoded_bytes > maximum_frame.min(65_536) {
        return Err(credit());
    }
    if let Some(retained) = data.native_retained_backing_bytes.as_mut() {
        // Plan, outgoing guard and containment own three independent DOMs.
        // The canonical frame bank is another persistent allocation.
        *retained = sum(&[
            *retained,
            mul(3, projected.retained_value_backing_bytes)?,
            projected.canonical_output_requested_bytes,
            if request {
                add(128, growth(128)?)?
            } else {
                128
            },
        ])?;
    }
    let deep_copy = projected.dom_and_canonical_scratch_bytes;
    data.original_plan_requested_bytes = add(data.original_plan_requested_bytes, deep_copy)?;
    data.outgoing_guard_requested_bytes =
        add(data.outgoing_guard_requested_bytes, add(deep_copy, 128)?)?;
    data.containment_requested_bytes = add(data.containment_requested_bytes, deep_copy)?;
    data.canonical_requested_bytes = add(
        data.canonical_requested_bytes,
        projected.canonical_output_requested_bytes,
    )?;
    let framed = add(projected.maximum_encoded_bytes, 4)?;
    data.outgoing_framed_bytes = add(data.outgoing_framed_bytes, framed)?;
    data.original_literal_required_bytes = add(data.original_literal_required_bytes, framed)?;
    // All retained canonical banks plus every sequential validation construction
    // are conservatively simultaneous here. This sums source-pinned passes,
    // rather than inferring a typed heap allowance from transport wire bytes.
    let typed_slots = mul(
        4,
        add(
            projected.sequence_elements,
            mul(4, projected.sequence_containers)?,
        )?,
    )?;
    let typed_element = size_of::<crucible_node_format::ObservationBatch>()
        .max(size_of::<crucible_node_format::Event>())
        .max(size_of::<ContentRef>())
        .max(size_of::<Id>());
    let typed_validation = sum(&[
        mul(typed_slots, typed_element)?,
        crate::profile::requested_storage::tree_storage_data(
            projected.sequence_containers,
            projected.sequence_elements,
            size_of::<(&Id, U64)>(),
            align_of::<(&Id, U64)>(),
        )?,
        mul(2 * 128, projected.sequence_elements)?,
        maximum_body_header_bytes,
        super::report_ack::serde_error_storage(projected.maximum_encoded_bytes)?,
    ])?;
    data.preparation_transient_requested_bytes = add(
        data.preparation_transient_requested_bytes,
        add(mul(projected.requested_total()?, 4)?, typed_validation)?,
    )?;
    if request {
        if let Some(retained) = data.native_retained_backing_bytes.as_mut() {
            *retained = add(
                *retained,
                super::report_ack::successful_ack_storage(acknowledgement_layout)?,
            )?;
        }
        data.successful_ack_cache_requested_bytes = add(
            data.successful_ack_cache_requested_bytes,
            super::report_ack::successful_ack_storage(acknowledgement_layout)?,
        )?;
        data.original_plan_requested_bytes = add(data.original_plan_requested_bytes, growth(128)?)?;
    }
    Ok(())
}

/// Applies the original checked prefix requested-storage arithmetic.
///
/// # Errors
/// Refuses checked prefix arithmetic overflow.
pub fn growth(bytes: usize) -> Result<usize, ProviderError> {
    add(mul(bytes, 4)?, 256)
}
/// Applies the original checked prefix requested-storage arithmetic.
///
/// # Errors
/// Refuses checked prefix arithmetic overflow.
pub fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(credit)
}
/// Applies the original checked prefix requested-storage arithmetic.
///
/// # Errors
/// Refuses checked prefix arithmetic overflow.
pub fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(credit)
}
/// Applies the original checked prefix requested-storage arithmetic.
///
/// # Errors
/// Refuses checked prefix arithmetic overflow.
pub fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |sum, value| add(sum, *value))
}
/// Constructs the original prefix requested-storage refusal.
pub fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("original packet prefix requested storage")
}

/// Projects actual content-reference and Blob frame shapes without owned payloads.
pub mod frames;

/// Replays the original Observe preparation work without native authority.
pub mod preparation;

use frames::{ContentExtent, OriginalContinuationContentExtent};

/// Names an inert closed shape class, never an authenticated request family.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum PrefixClass {
    /// Names an ordinary Observe proof shape.
    Observe,
    /// Names the existing restored Input17 shape.
    RestoredInput17,
    /// Names the existing restored Observe17 shape.
    RestoredObserve17,
    /// Names the existing Capture upload method shape.
    CaptureUpload17(Method),
}

impl PrefixClass {
    /// Names the request method represented by this inert shape class.
    pub const fn method_data(self) -> Method {
        match self {
            Self::Observe | Self::RestoredObserve17 => Method::Observe,
            Self::RestoredInput17 => Method::Input,
            Self::CaptureUpload17(method) => method,
        }
    }

    /// Tests whether this DATA names the distinct upload shape class.
    pub const fn is_capture17_upload_data(self) -> bool {
        matches!(self, Self::CaptureUpload17(_))
    }
}

/// Borrows the original producer reports and finite content roster.
pub struct OriginalPacketPrefixProjectionInput<'a> {
    /// Carries the original terminal frame serializer report.
    pub terminal: &'a OriginalSerializationStorageData,
    /// Carries the independently retained incoming frame serializer report.
    pub original: &'a OriginalSerializationStorageData,
    /// Carries the actual finite prospective content roster.
    pub objects: &'a [OriginalContinuationContentExtent<'a>],
    /// Retains the independently supplied complete requested-storage ceiling.
    pub maximum_requested_bytes: usize,
}

/// Carries prospective components without allocation or transport rights.
pub struct OriginalPacketPrefixProjectionStorageData<const OBJECTS: usize = 3> {
    /// Carries the complete original prefix component report.
    pub exchange: OriginalPacketPrefixStorageData,
    /// Counts the independent producer-owned source input storage.
    pub source_owner_requested_bytes: usize,
    /// Is present only for the closed native initial lifecycle grammar.
    pub native_source_backing_bytes: Option<usize>,
    /// Counts the defining fixed projection/header controls.
    pub declared_counter_scratch_bytes: usize,
    /// Carries the original terminal frame serializer report.
    pub terminal: OriginalSerializationStorageData,
    /// Carries the independently retained incoming frame serializer report.
    pub original: OriginalSerializationStorageData,
    /// Carries the actual finite prospective content roster.
    pub objects: [Option<ContentExtent>; OBJECTS],
    /// Names an inert shape class; it grants no dispatch or native scope.
    pub class: PrefixClass,
    /// Retains the independently supplied complete requested-storage ceiling.
    pub maximum_requested_bytes: usize,
}

impl<const OBJECTS: usize> OriginalPacketPrefixProjectionStorageData<OBJECTS> {
    /// Sums the same independently named original requested components.
    ///
    /// # Errors
    /// Refuses the original checked requested-storage overflow.
    pub fn requested_bytes(&self) -> Result<usize, ProviderError> {
        sum(&[
            self.exchange.requested_bytes()?,
            self.source_owner_requested_bytes,
            self.declared_counter_scratch_bytes,
        ])
    }
}

/// Shares the actual original startup frame loop with the upper constructors.
pub mod startup;

/// Counts the original containment algorithm from genuine compiled header inputs.
///
/// # Errors
/// Preserves the original checked tree-layout and storage arithmetic refusals.
pub fn startup_containment(
    extensions: usize,
    original: &OriginalSerializationStorageData,
    envelope_bytes: usize,
    envelope_alignment: usize,
    incident_bytes: usize,
) -> Result<usize, ProviderError> {
    // Fresh13 maps its Query and PrepareBinding keys to one selected feature.
    // The closed installed mapping has at most two keys per advertised feature;
    // charge both Id-bounded names even when that feature is not selected.
    // The independent confirmation key retains its own additional entry.
    let mapped_keys = mul(2, extensions)?;
    let tree = crate::profile::requested_storage::tree_storage_data(
        4,
        add(mapped_keys, 1)?,
        size_of::<Id>() + envelope_bytes,
        align_of::<Id>().max(envelope_alignment),
    )?;
    sum(&[
        original.dom_and_canonical_scratch_bytes,
        // Guard and authority retain independently cloned session/incarnation
        // IDs plus connection ID; the incoming map independently clones its key.
        mul(6, 128)?,
        mul(mapped_keys, 128)?,
        tree,
        mul(10, envelope_bytes)?,
        incident_bytes,
    ])
}

/// Converts the original negotiated numeric ceiling without widening it.
///
/// # Errors
/// Refuses an unrepresentable platform extent.
pub fn allowance(value: u64) -> Result<usize, ProviderError> {
    usize::try_from(value)
        .map_err(|_| ProviderError::ResourceExhausted("unrepresentable connection allowance"))
}

/// Constructs the original closed prefix correlation refusal.
pub fn refused() -> ProviderError {
    ProviderError::Correlation("original packet prefix storage data")
}

/// Partitions original Observe lifetime DATA without transport authority.
pub mod lifetime;
