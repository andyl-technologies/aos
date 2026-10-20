//! Factors genuine input/reconstruction and held-proof requested storage as DATA.
//!
//! The installed Source action supplies its cached actual native demand and
//! decoder limits. No Connection, Prepare, model, receipt, bytes bank or native
//! permit is created. Commit decoding, model adoption, actual fresh owners and
//! all host owners remain separate mandatory whole-restoration terms.

use super::*;
use crate::client::DeadlineStream;
use crate::protocol_snapshot::owned11::outer::OwnedProtocol11DataLimits;
use crate::reference_packet::service::{
    PacketNative5SourceLaunch,
    complete_restore::transfer::{
        PacketCompleteRestoreInputAllocation, PacketCompleteRestoreOwnerValidationStorage,
    },
};
use crucible_node_format::U64;

/// Reports the factored native input suffix without granting reconstruction.
///
/// This is numeric DATA. The Source's actual ticket authenticates the cached
/// native demand/limits and exact six role extents before an installed window
/// can conjoin this row with its other required host/native phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalNativeRestoreInputConstructionData {
    raw_input_bytes: usize,
    historical_backing_bytes: usize,
    reconstruction_lookup_bytes: usize,
    requested_geometry_bytes: usize,
    declared_scratch_and_owner_bytes: usize,
    custody_layout_bytes: usize,
    held_proof_bytes: usize,
    native_reconstruction_bytes: usize,
    requested_input_suffix_bytes: usize,
    input_allocation_fields: [U64; 14],
}

impl OriginalNativeRestoreInputConstructionData {
    /// Reproduces the exact finite allocation fields used by this native quote.
    ///
    /// This fixed owning DTO allocates no bank and grants no permission. The
    /// installed window retains it for Source-derived request construction;
    /// its Source claim, full reference association and keyed proof remain
    /// independent requirements before any Prepare or reconstruction effect.
    pub fn original_input_allocation_data(&self) -> PacketCompleteRestoreInputAllocation {
        PacketCompleteRestoreInputAllocation {
            maximum_known_requested_bytes: self.input_allocation_fields[0],
            maximum_input_bytes: self.input_allocation_fields[1],
            maximum_nodes: self.input_allocation_fields[2],
            maximum_depth: self.input_allocation_fields[3],
            maximum_owned_backing_bytes: self.input_allocation_fields[4],
            maximum_tree_entries: self.input_allocation_fields[5],
            maximum_metadata_rows: self.input_allocation_fields[6],
            maximum_literal_backing_bytes: self.input_allocation_fields[7],
            maximum_content_transfers: self.input_allocation_fields[8],
            maximum_content_objects: self.input_allocation_fields[9],
            maximum_content_groups: self.input_allocation_fields[10],
            maximum_content_bytes: self.input_allocation_fields[11],
            maximum_content_metadata_bytes: self.input_allocation_fields[12],
            maximum_model_bytes: self.input_allocation_fields[13],
        }
    }

    /// Returns all six independent raw Vec requests in their original role order.
    pub fn raw_input_bytes(&self) -> usize {
        self.raw_input_bytes
    }

    /// Returns the complete input/reconstruction/proof conjunction as DATA.
    ///
    /// The complete installed action must additionally fund Commit/model work,
    /// fresh native/query/Prepare owners, all host owners and callback phases.
    pub fn requested_input_suffix_bytes(&self) -> usize {
        self.requested_input_suffix_bytes
    }

    /// Returns separately named recorded backing and native reconstruction terms.
    pub fn reconstruction_terms_data(&self) -> [usize; 7] {
        [
            self.historical_backing_bytes,
            self.reconstruction_lookup_bytes,
            self.requested_geometry_bytes,
            self.declared_scratch_and_owner_bytes,
            self.custody_layout_bytes,
            self.held_proof_bytes,
            self.native_reconstruction_bytes,
        ]
    }
}

/// Names explicit row, held-proof and metadata views before this data walk.
///
/// Recursive/compiler frames and allocator physical overhead remain separate.
pub fn original_native_restore_input_construction_counter_scratch_data() -> usize {
    crate::reference_packet::service::ack_emitter::VerifiedCompleteRestorePrepare::original_selected_native_counter_scratch_data()
        + crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping::original_selected_construction_counter_scratch_data()
        + size_of::<OriginalNativeRestoreInputConstructionData>()
        + size_of::<PacketCompleteRestoreInputAllocation>()
        + size_of::<[U64; 14]>()
        + size_of::<InputGeometry>() + size_of::<MetadataObserver>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<[usize; 6]>()
        // Actual input_geometry signed-field, lookup/backing/owner arrays.
        + size_of::<[u64; 10]>() + size_of::<std::array::IntoIter<u64, 10>>()
        + size_of::<[usize; 5]>() + size_of::<[usize; 8]>()
        + size_of::<[usize; 9]>()
        // Actual held_proof_geometry container/vector/scratch/total arrays.
        + size_of::<[usize; 3]>() + size_of::<[usize; 6]>()
        + 2 * size_of::<[usize; 7]>()
        // Actual cached reconstruction sum and complete input-suffix sum.
        + size_of::<[usize; 14]>() + size_of::<[usize; 8]>() + size_of::<[usize; 4]>()
        + size_of::<[&str; 23]>() + size_of::<std::array::IntoIter<&str, 23>>()
        + crate::reference_packet::service::complete_restore::maximum_complete_restore_held_evidence_counter_scratch_data()
}

/// Quotes actual selected decoder and input geometry before native Prepare.
///
/// The actual called custody quote and this function use the SAME input and
/// held-proof formulas. Actual native prior frame-bank roots are conservatively
/// bounded here by the separately MAC-authenticated current native owner and
/// direct Query/Prepare retained-growth rows;
/// that row is not input, model, Commit or allocation permission. The Source must
/// authenticate it against its original completed query before trusting the sum.
///
/// Decoder limits preserve independently bounded spare capacities, tree/alias
/// populations and content banks; encoded lengths never replace those fields.
/// A missing selected owner/model row must refuse before calling this function.
/// The selected live consumer still rechecks its actual demand before effects.
///
/// # Errors
/// Refuses another selected launch, unavailable/zero independent bounds,
/// unsupported native grammar populations, integer overflow or input demand
/// beyond the independently supplied installed ceiling. No limits are raised.
pub fn original_native_restore_input_construction_storage_data(
    launch: &PacketNative5SourceLaunch,
    native: &outer::NativeOwnedProtocol11AllocationDemand,
    limits: OwnedProtocol11DataLimits,
    model: &PacketCompleteRestoreOwnerValidationStorage,
    input_lengths: [usize; 6],
    authenticated_fresh_report: &crate::reference_packet::service::fresh_restore_allocation::PacketNativeFreshRestoreAllocationReport,
    maximum_requested_bytes: usize,
) -> Result<OriginalNativeRestoreInputConstructionData, ProviderError> {
    if launch.complete_restore_selection
        != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        || launch.fresh_restore_allocation_selection.is_none()
        || model.total_bytes == 0
        || input_lengths.iter().any(|length| *length == 0)
        || maximum_requested_bytes == 0
    {
        return Err(refused());
    }
    authenticated_fresh_report.validate_data()?;
    let fresh = &authenticated_fresh_report.data.storage;
    // This is the complete directly authenticated pre-input retained frontier,
    // including real Query/Prepare growth. It is a conservative DATA boundary
    // for the held quote's prior frame roots, never an input/model permission.
    let native_before_inputs = sum(&[
        selected(fresh.current_retained_bytes.get())?,
        selected(fresh.query_retained_growth_bytes.get())?,
        selected(fresh.prepare_retained_growth_bytes.get())?,
        selected(fresh.declared_counter_scratch_bytes.get())?,
    ])?;
    let bound = |value: usize| -> Result<U64, ProviderError> {
        let value = u64::try_from(value).map_err(|_| credit())?;
        selected(value)?;
        Ok(U64::new(value))
    };
    let allocation = PacketCompleteRestoreInputAllocation {
        // This numerical ceiling is an internal checked DATA bound. No signed
        // request or allocation token is emitted from this helper.
        maximum_known_requested_bytes: bound(maximum_requested_bytes.min(MAXIMUM_SELECTION_BYTES))?,
        maximum_input_bytes: bound(limits.json.maximum_input_bytes)?,
        maximum_nodes: bound(limits.json.maximum_nodes)?,
        maximum_depth: bound(limits.json.maximum_depth)?,
        maximum_owned_backing_bytes: bound(limits.json.maximum_owned_backing_bytes)?,
        maximum_tree_entries: bound(limits.json.maximum_tree_entries)?,
        maximum_metadata_rows: bound(limits.maximum_metadata_rows)?,
        maximum_literal_backing_bytes: bound(limits.maximum_literal_backing_bytes)?,
        maximum_content_transfers: bound(limits.content.content.max_rows)?,
        maximum_content_objects: bound(limits.content.content.max_rows)?,
        maximum_content_groups: bound(limits.content.content.max_groups)?,
        maximum_content_bytes: bound(limits.content.content.max_first_group_capacity_bytes)?,
        maximum_content_metadata_bytes: bound(limits.content.maximum_metadata_capacity_bytes)?,
        maximum_model_bytes: bound(model.total_bytes)?,
    };
    // Policy metadata only obtains tree widths/alignment from the same actual
    // selection. The connected coordinator also owns a JSON template and host
    // selection; tree_layout independently includes its String/Value map width.
    // Participant/host selections repeat the same closed descriptor/binding
    // families. Remaining policy fields add no different tree key/value layout.
    let mut observer = MetadataObserver::new();
    observer.observe(&launch.selection)?;
    let facts = observer.finish();
    let maximum_frame = selected(launch.limits.frame_bytes.get())?;
    let chunk = selected(launch.limits.blob_chunk_bytes.get())?.min(4096);
    let header = size_of::<Connection<DeadlineStream>>();
    let geometry = input_geometry(&allocation, input_lengths, facts, maximum_frame, header)?;
    let (held_frames, held_proof_bytes) = super::super::restore_proof_quote::held_proof_geometry(
        maximum_frame, chunk, native_before_inputs, header,
        crate::reference_packet::service::complete_restore::maximum_complete_restore_held_evidence_bytes()?,
    )?;
    if held_frames > selected(launch.limits.requests.get())? {
        return Err(credit());
    }

    let recorded = &native.recorded;
    let native_reconstruction_bytes = sum(&[
        recorded.recorded_string_bytes,
        recorded.recorded_vector_bytes,
        recorded.literal_backing_bytes,
        recorded.boxed_value_bytes,
        recorded.shared_view_bytes,
        recorded.alias_summary_layout_bytes,
        recorded.selected_group_lookup_bytes,
        recorded.content_group_lookup_bytes,
        recorded.selected_slice_staging_bytes,
        tree_storage(
            recorded.tree_containers,
            recorded.tree_entries,
            recorded.maximum_tree_key_value_bytes,
            recorded.maximum_tree_entry_alignment.max(1),
        )?,
        shared_header_storage(
            recorded.shared_backing_views,
            recorded.maximum_shared_value_alignment.max(1),
        )?,
        native.native_group_lookup_bytes,
        native.historical_payload_layout_bytes,
        native.semantic_validation_stack_bytes,
    ])?;
    let total = sum(&[
        geometry.raw_input_bytes,
        geometry.historical_backing_bytes,
        geometry.reconstruction_lookup_bytes,
        geometry.requested_geometry_bytes,
        geometry.declared_scratch_and_owner_bytes,
        geometry.custody_layout_bytes,
        held_proof_bytes,
        native_reconstruction_bytes,
    ])?;
    if total > maximum_requested_bytes {
        return Err(credit());
    }
    Ok(OriginalNativeRestoreInputConstructionData {
        raw_input_bytes: geometry.raw_input_bytes,
        historical_backing_bytes: geometry.historical_backing_bytes,
        reconstruction_lookup_bytes: geometry.reconstruction_lookup_bytes,
        requested_geometry_bytes: geometry.requested_geometry_bytes,
        declared_scratch_and_owner_bytes: geometry.declared_scratch_and_owner_bytes,
        custody_layout_bytes: geometry.custody_layout_bytes,
        held_proof_bytes,
        native_reconstruction_bytes,
        requested_input_suffix_bytes: total,
        input_allocation_fields: [
            allocation.maximum_known_requested_bytes,
            allocation.maximum_input_bytes,
            allocation.maximum_nodes,
            allocation.maximum_depth,
            allocation.maximum_owned_backing_bytes,
            allocation.maximum_tree_entries,
            allocation.maximum_metadata_rows,
            allocation.maximum_literal_backing_bytes,
            allocation.maximum_content_transfers,
            allocation.maximum_content_objects,
            allocation.maximum_content_groups,
            allocation.maximum_content_bytes,
            allocation.maximum_content_metadata_bytes,
            allocation.maximum_model_bytes,
        ],
    })
}
