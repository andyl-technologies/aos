//! Borrows every fixed cached validation fact without turning it into credit.
//!
//! These rows describe historical work and correspondence. Their serialization
//! creates no allocation receipt, Source identity, decoder plan or native right.

use super::*;
use crucible_node_transport::{
    client::{compact_cursor::CompactContentLimits, compact_metadata8::CompactMetadata8Limits},
    protocol_snapshot::owned11::{
        json_value::HistoricalJsonLimits, outer::OwnedProtocol11AllocationDemand,
    },
    reference_packet::service::complete_restore::transfer::PacketCompleteRestoreOwnerValidationStorage,
};
use serde::{Serialize, Serializer, ser::SerializeStruct};

pub(crate) struct RestorationDataHistory<'a>(&'a CompleteOriginalNativeRestorationData);
struct NativeDemand<'a>(&'a NativeOwnedProtocol11AllocationDemand);
struct RecordedDemand<'a>(&'a OwnedProtocol11AllocationDemand);
struct DecodeLimits<'a>(&'a OwnedProtocol11DataLimits);
struct JsonLimits<'a>(&'a HistoricalJsonLimits);
struct ContentLimits<'a>(&'a CompactMetadata8Limits);
struct CompactLimits<'a>(&'a CompactContentLimits);
struct SelectedOwner<'a>(&'a PacketCompleteRestoreOwnerValidationStorage);
struct ArchivedValidation<'a>(&'a CompleteOriginalArchivedValidationConstructionData);

impl CompleteOriginalNativeRestorationData {
    pub(crate) fn borrowed_settled_history_data(&self) -> RestorationDataHistory<'_> {
        RestorationDataHistory(self)
    }
}

impl Serialize for RestorationDataHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let CompleteOriginalNativeRestorationData {
            native,
            limits,
            input_lengths,
            reference_identities,
            source_cold_requested_bytes,
            mapping_reference_clone_bytes,
            selected_owner,
            archived_validation,
        } = self.0;
        let mut value =
            serializer.serialize_struct("CompleteOriginalNativeRestorationDataHistory", 8)?;
        value.serialize_field("native", &NativeDemand(native))?;
        value.serialize_field("limits", &DecodeLimits(limits))?;
        value.serialize_field("input_lengths", input_lengths)?;
        value.serialize_field("reference_identities", reference_identities)?;
        value.serialize_field("source_cold_requested_bytes", source_cold_requested_bytes)?;
        value.serialize_field(
            "mapping_reference_clone_bytes",
            mapping_reference_clone_bytes,
        )?;
        value.serialize_field(
            "selected_owner",
            &selected_owner.as_ref().map(SelectedOwner),
        )?;
        value.serialize_field(
            "archived_validation",
            &archived_validation.as_ref().map(ArchivedValidation),
        )?;
        value.end()
    }
}

impl Serialize for NativeDemand<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let NativeOwnedProtocol11AllocationDemand {
            recorded,
            native_group_lookup_bytes,
            historical_payload_layout_bytes,
            semantic_validation_stack_bytes,
        } = self.0;
        let mut value =
            serializer.serialize_struct("NativeOwnedProtocol11AllocationDemandHistory", 4)?;
        value.serialize_field("recorded", &RecordedDemand(recorded))?;
        value.serialize_field("native_group_lookup_bytes", native_group_lookup_bytes)?;
        value.serialize_field(
            "historical_payload_layout_bytes",
            historical_payload_layout_bytes,
        )?;
        value.serialize_field(
            "semantic_validation_stack_bytes",
            semantic_validation_stack_bytes,
        )?;
        value.end()
    }
}

impl Serialize for DecodeLimits<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let OwnedProtocol11DataLimits {
            json,
            content,
            maximum_metadata_rows,
            maximum_literal_backing_bytes,
        } = self.0;
        let mut value = serializer.serialize_struct("OwnedProtocol11DataLimitsHistory", 4)?;
        value.serialize_field("json", &JsonLimits(json))?;
        value.serialize_field("content", &ContentLimits(content))?;
        value.serialize_field("maximum_metadata_rows", maximum_metadata_rows)?;
        value.serialize_field(
            "maximum_literal_backing_bytes",
            maximum_literal_backing_bytes,
        )?;
        value.end()
    }
}

impl Serialize for ContentLimits<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let CompactMetadata8Limits {
            content,
            maximum_metadata_capacity_bytes,
        } = self.0;
        let mut value = serializer.serialize_struct("CompactMetadata8LimitsHistory", 2)?;
        value.serialize_field("content", &CompactLimits(content))?;
        value.serialize_field(
            "maximum_metadata_capacity_bytes",
            maximum_metadata_capacity_bytes,
        )?;
        value.end()
    }
}

macro_rules! scalar_fields {
    ($wrapper:ident, $ty:path, $($field:ident),+ $(,)?) => {
        impl Serialize for $wrapper<'_> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let $ty { $($field,)+ } = self.0;
                let mut value = serializer.serialize_struct(stringify!($wrapper), [$(stringify!($field)),+].len())?;
                $(value.serialize_field(stringify!($field), $field)?;)+
                value.end()
            }
        }
    };
}

scalar_fields!(
    RecordedDemand,
    OwnedProtocol11AllocationDemand,
    recorded_string_bytes,
    recorded_vector_bytes,
    literal_backing_bytes,
    tree_entries,
    tree_entry_layout_bytes,
    tree_containers,
    maximum_tree_key_value_bytes,
    maximum_tree_entry_alignment,
    shared_backing_views,
    maximum_shared_value_alignment,
    boxed_value_bytes,
    shared_view_bytes,
    alias_groups,
    alias_rows,
    alias_summary_entries,
    alias_summary_layout_bytes,
    selected_group_lookup_bytes,
    content_group_lookup_bytes,
    selected_slice_staging_bytes
);
scalar_fields!(
    JsonLimits,
    HistoricalJsonLimits,
    maximum_input_bytes,
    maximum_nodes,
    maximum_depth,
    maximum_owned_backing_bytes,
    maximum_tree_entries
);
scalar_fields!(
    CompactLimits,
    CompactContentLimits,
    max_input_bytes,
    max_rows,
    max_groups,
    max_first_group_capacity_bytes
);
scalar_fields!(
    SelectedOwner,
    PacketCompleteRestoreOwnerValidationStorage,
    snapshot_bytes,
    journal_bytes,
    control_bytes,
    model_vector_backing_bytes,
    anchor_bytes,
    capture_comparison_bytes,
    declared_scanner_bytes,
    total_bytes
);
scalar_fields!(
    ArchivedValidation,
    CompleteOriginalArchivedValidationConstructionData,
    phases,
    semantic_decode,
    fixed_scratch,
    requested
);

impl CompleteOriginalNativeRestorationData {
    /// Names direct historical views; output and serializer work stay separate.
    pub(crate) fn settled_history_counter_scratch_data() -> usize {
        let terms = [
            std::mem::size_of::<RestorationDataHistory<'static>>(),
            std::mem::size_of::<Option<RestorationDataHistory<'static>>>(),
            std::mem::size_of::<NativeDemand<'static>>(),
            std::mem::size_of::<RecordedDemand<'static>>(),
            std::mem::size_of::<DecodeLimits<'static>>(),
            std::mem::size_of::<JsonLimits<'static>>(),
            std::mem::size_of::<ContentLimits<'static>>(),
            std::mem::size_of::<CompactLimits<'static>>(),
            std::mem::size_of::<SelectedOwner<'static>>(),
            std::mem::size_of::<Option<SelectedOwner<'static>>>(),
            std::mem::size_of::<Option<&PacketCompleteRestoreOwnerValidationStorage>>(),
            std::mem::size_of::<ArchivedValidation<'static>>(),
            std::mem::size_of::<Option<ArchivedValidation<'static>>>(),
            std::mem::size_of::<Option<&CompleteOriginalArchivedValidationConstructionData>>(),
            std::mem::size_of::<(
                &NativeOwnedProtocol11AllocationDemand,
                &OwnedProtocol11DataLimits,
                &[usize; 5],
                &[[u8; 32]; 5],
                &usize,
                &usize,
                &Option<PacketCompleteRestoreOwnerValidationStorage>,
                &Option<CompleteOriginalArchivedValidationConstructionData>,
            )>(),
            std::mem::size_of::<(&OwnedProtocol11AllocationDemand, &usize, &usize, &usize)>(),
            std::mem::size_of::<(
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
            )>(),
            std::mem::size_of::<(
                &HistoricalJsonLimits,
                &CompactMetadata8Limits,
                &usize,
                &usize,
            )>(),
            std::mem::size_of::<(&CompactContentLimits, &usize)>(),
            std::mem::size_of::<(&usize, &usize, &usize, &usize, &usize)>(),
            std::mem::size_of::<(&usize, &usize, &usize, &usize)>(),
            std::mem::size_of::<(
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
                &usize,
            )>(),
            std::mem::size_of::<(&[usize; 3], &usize, &usize, &usize)>(),
        ];
        let array_bytes = std::mem::size_of_val(&terms);
        let mut iterator = terms.into_iter();
        let iterator_bytes = std::mem::size_of_val(&iterator);
        array_bytes
            .checked_add(iterator_bytes)
            .and_then(|initial| iterator.try_fold(initial, usize::checked_add))
            .unwrap_or(usize::MAX)
    }
}
