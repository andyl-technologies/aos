//! Quotes source-selected restoration inputs before allocating their custody.
//!
//! A quote describes conservative simultaneous requested storage for the exact
//! retained prepare request. It grants no receive or installation right. The
//! native fresh-key issuer authenticates that request and conjoins its own
//! retained attempt/model/Control demand before the SDK allocates any bank.

use super::*;
use crate::protocol_snapshot::owned11::{aliases::HistoricalAliasSummary, native::outer};
use crate::reference_packet::service::complete_restore::{
    PacketNative5CompleteRestoreSelection, transfer::PacketCompleteRestorePrepareRequest,
};
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use crucible_node_contract::{ContentRef, ExtensionSelection};
use serde::Serialize;
use std::mem::{align_of, size_of};

#[path = "restore_input_quote/prospective.rs"]
mod prospective;
pub use prospective::{
    OriginalNativeRestoreInputConstructionData,
    original_native_restore_input_construction_counter_scratch_data,
    original_native_restore_input_construction_storage_data,
};

const MAXIMUM_SELECTION_BYTES: usize = 512 * 1024 * 1024;

/// Reports bounded requested storage, without issuing an input-bank lease.
///
/// Fields are deliberately private: only an actual selected Connection creates
/// this source-bound quote. The genuine proof token checks the complete request
/// again before the custody installer consumes this report.
pub(crate) struct NativeRestoreInputAllocationQuote {
    actor: Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    codec: Rc<Native5CodecOwner>,
    request_digest: blake3::Hash,
    input_lengths: [usize; 6],
    maximum_metadata_rows: usize,
    maximum_nodes: usize,
    /// Includes all six simultaneous raw input Vec requests, without dedup.
    raw_input_bytes: usize,
    /// Includes recorded backing, independent literal/content budgets and maps.
    historical_backing_bytes: usize,
    /// Includes summaries, both content lookups, native/selected lookups/staging.
    reconstruction_lookup_bytes: usize,
    /// Includes pinned conservative tree nodes and Rc/Arc headers per view.
    requested_geometry_bytes: usize,
    /// Includes declared parser arrays, semantic bitset and final owner layouts.
    declared_scratch_and_owner_bytes: usize,
    /// Includes the selected custody's six chunk ledgers and their inline owner.
    custody_layout_bytes: usize,
    /// Separately named complete proof/staging/canonical/ACK requested bound.
    held_proof: super::restore_proof_quote::OriginalRestoreHeldProofAllocationQuote,
    sdk_requested_bytes: usize,
}

impl NativeRestoreInputAllocationQuote {
    pub(super) fn actor_current(&self) -> Result<(), ProviderError> {
        self.actor.ensure_current()
    }

    pub(crate) fn authenticate_original_request(
        &self,
        request: &PacketCompleteRestorePrepareRequest,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        if request_digest(request)? != self.request_digest
            || input_lengths(request)? != self.input_lengths
            || selected(request.allocation.maximum_metadata_rows.get())?
                != self.maximum_metadata_rows
            || selected(request.allocation.maximum_nodes.get())? != self.maximum_nodes
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Conjoins actual retained native owners and the separately signed model cap.
    ///
    /// The model cap still requires a post-upload actual typed-demand check. It
    /// is charged here in full, rather than estimated from its encoded length.
    pub(crate) fn conjoin_native_allocation_data(
        &self,
        request: &PacketCompleteRestorePrepareRequest,
        native_fixed_requested_bytes: usize,
        signed_model_control_budget_bytes: usize,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_request(request)?;
        if signed_model_control_budget_bytes
            != selected(request.allocation.maximum_model_bytes.get())?
        {
            return Err(refused());
        }
        let terms = self.requested_terms();
        let actual_sdk = add(sum(&terms[..6])?, self.held_proof.requested_bytes())?;
        if actual_sdk != terms[6] {
            return Err(refused());
        }
        let total = add(
            add(actual_sdk, native_fixed_requested_bytes)?,
            signed_model_control_budget_bytes,
        )?;
        if total > selected(request.allocation.maximum_known_requested_bytes.get())? {
            return Err(credit());
        }
        Ok(())
    }

    pub(super) fn authenticate_connection<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        if !Rc::ptr_eq(&self.actor, &connection.protocol_owner)
            || connection
                .native5_codec
                .as_ref()
                .is_none_or(|codec| !Rc::ptr_eq(codec, &self.codec))
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn retain_held_proof_quote<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<super::restore_proof_quote::OriginalRestoreHeldProofAllocationQuote, ProviderError>
    {
        self.authenticate_connection(connection)?;
        self.held_proof.retain_original(connection)
    }

    pub(super) const fn input_lengths(&self) -> [usize; 6] {
        self.input_lengths
    }

    pub(super) const fn maximum_nodes(&self) -> usize {
        self.maximum_nodes
    }

    pub(super) const fn maximum_metadata_rows(&self) -> usize {
        self.maximum_metadata_rows
    }

    /// Checks actual admitted decoder demand before constructing any final owner.
    pub(super) fn authenticate_native_plan(
        &self,
        request: &PacketCompleteRestorePrepareRequest,
        demand: &outer::NativeOwnedProtocol11AllocationDemand,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_request(request)?;
        let a = &request.allocation;
        let actual = &demand.recorded;
        let (_, maximum_payload, _, _) = outer::original_restore_decoder_layouts();
        if add(actual.recorded_string_bytes, actual.recorded_vector_bytes)?
            > selected(a.maximum_owned_backing_bytes.get())?
            || actual.literal_backing_bytes > selected(a.maximum_literal_backing_bytes.get())?
            || actual.tree_entries > selected(a.maximum_tree_entries.get())?
            || actual.alias_rows > self.maximum_metadata_rows
            || actual.alias_groups > self.maximum_metadata_rows
            || add(actual.boxed_value_bytes, actual.shared_view_bytes)?
                > multiply(self.maximum_metadata_rows, maximum_payload)?
            || demand.historical_payload_layout_bytes
                > multiply(self.maximum_metadata_rows, maximum_payload)?
        {
            return Err(credit());
        }
        let lookup = sum(&[
            actual.alias_summary_layout_bytes,
            actual.selected_group_lookup_bytes,
            actual.content_group_lookup_bytes,
            actual.selected_slice_staging_bytes,
            demand.native_group_lookup_bytes,
        ])?;
        let geometry = add(
            tree_storage(
                actual.tree_containers,
                actual.tree_entries,
                actual.maximum_tree_key_value_bytes,
                actual.maximum_tree_entry_alignment,
            )?,
            shared_header_storage(
                actual.shared_backing_views,
                actual.maximum_shared_value_alignment,
            )?,
        )?;
        if lookup > self.reconstruction_lookup_bytes
            || geometry > self.requested_geometry_bytes
            || demand.semantic_validation_stack_bytes > self.declared_scratch_and_owner_bytes
        {
            return Err(credit());
        }
        Ok(())
    }

    /// Reports named terms for exact source-side receipts and boundary controls.
    pub(crate) const fn requested_terms(&self) -> [usize; 7] {
        [
            self.raw_input_bytes,
            self.historical_backing_bytes,
            self.reconstruction_lookup_bytes,
            self.requested_geometry_bytes,
            self.declared_scratch_and_owner_bytes,
            self.custody_layout_bytes,
            self.sdk_requested_bytes,
        ]
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn quote_original_complete_restore_input_custody(
        &self,
        request: &PacketCompleteRestorePrepareRequest,
    ) -> Result<NativeRestoreInputAllocationQuote, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider
            || self.original_native5_complete_restore_selection()?
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return Err(refused());
        }
        let codec = self.native5_codec.as_ref().ok_or_else(refused)?;
        let Native5CodecOwner::NativePacket(policy) = codec.as_ref() else {
            return Err(refused());
        };
        let mut observer = MetadataObserver::new();
        policy.observe_retained_metadata(&mut observer)?;
        let facts = observer.finish();
        let allocation = &request.allocation;
        let input_lengths = input_lengths(request)?;
        let InputGeometry {
            raw_input_bytes,
            historical_backing_bytes,
            reconstruction_lookup_bytes,
            requested_geometry_bytes,
            declared_scratch_and_owner_bytes,
            custody_layout_bytes,
        } = input_geometry(
            allocation,
            input_lengths,
            facts,
            selected(self.authority.limits().frame_bytes.get())?,
            size_of::<Self>(),
        )?;
        let held_proof = self.quote_original_restore_held_proof_allocation()?;
        let sdk_requested_bytes = sum(&[
            raw_input_bytes,
            historical_backing_bytes,
            reconstruction_lookup_bytes,
            requested_geometry_bytes,
            declared_scratch_and_owner_bytes,
            custody_layout_bytes,
            held_proof.requested_bytes(),
        ])?;
        if sdk_requested_bytes > selected(allocation.maximum_known_requested_bytes.get())? {
            return Err(credit());
        }
        let rows = selected(allocation.maximum_metadata_rows.get())?;
        let nodes = selected(allocation.maximum_nodes.get())?;
        Ok(NativeRestoreInputAllocationQuote {
            actor: Rc::clone(&self.protocol_owner),
            codec: Rc::clone(codec),
            request_digest: request_digest(request)?,
            input_lengths,
            maximum_metadata_rows: rows,
            maximum_nodes: nodes,
            raw_input_bytes,
            historical_backing_bytes,
            reconstruction_lookup_bytes,
            requested_geometry_bytes,
            declared_scratch_and_owner_bytes,
            custody_layout_bytes,
            held_proof,
            sdk_requested_bytes,
        })
    }
}

pub(super) fn input_references(request: &PacketCompleteRestorePrepareRequest) -> [&ContentRef; 6] {
    [
        &request.native_protocol,
        &request.native_control,
        &request.native_anchor,
        &request.restoration.owner_state,
        &request.restoration.journal,
        &request.restoration.mapping,
    ]
}

fn input_lengths(
    request: &PacketCompleteRestorePrepareRequest,
) -> Result<[usize; 6], ProviderError> {
    let mut lengths = [0; 6];
    for (length, reference) in lengths.iter_mut().zip(input_references(request)) {
        *length = selected(reference.length.get())?;
    }
    Ok(lengths)
}

fn tree_layout(facts: RetainedProtocolMetadataFacts) -> (usize, usize) {
    use crate::protocol_snapshot::owned11::native::blob::{
        HistoricalNativeBlobPin, HistoricalNativeBlobRecord,
    };
    let layouts = [
        (
            size_of::<String>() + size_of::<serde_json::Value>(),
            align_of::<String>().max(align_of::<serde_json::Value>()),
        ),
        (
            size_of::<Id>() + size_of::<Envelope>(),
            align_of::<Id>().max(align_of::<Envelope>()),
        ),
        (
            size_of::<crate::blob::TransferKey>() + size_of::<HistoricalNativeBlobRecord>(),
            align_of::<crate::blob::TransferKey>().max(align_of::<HistoricalNativeBlobRecord>()),
        ),
        (
            size_of::<u64>() + size_of::<HistoricalNativeBlobPin>(),
            align_of::<u64>().max(align_of::<HistoricalNativeBlobPin>()),
        ),
        (2 * size_of::<usize>(), align_of::<usize>()),
        (
            facts.maximum_tree_key_value_bytes,
            facts.maximum_tree_entry_alignment,
        ),
    ];
    layouts
        .into_iter()
        .fold((0, 1), |(bytes, alignment), actual| {
            (bytes.max(actual.0), alignment.max(actual.1))
        })
}

// Existing restore callers use the same checked SDK metadata layout producer.
pub(super) fn tree_storage(
    containers: usize,
    entries: usize,
    value: usize,
    alignment: usize,
) -> Result<usize, ProviderError> {
    crate::retained_metadata::requested_storage::tree_storage_data(
        containers, entries, value, alignment,
    )
}

pub(super) fn shared_header_storage(
    views: usize,
    alignment: usize,
) -> Result<usize, ProviderError> {
    crate::retained_metadata::requested_storage::shared_header_storage_data(views, alignment)
}

fn request_digest(
    request: &PacketCompleteRestorePrepareRequest,
) -> Result<blake3::Hash, ProviderError> {
    struct Sink(blake3::Hasher);
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink(blake3::Hasher::new_derive_key(
        "source-private.complete-restore-quote-correspondence/12",
    ));
    request
        .serialize(&mut serde_json::Serializer::new(&mut sink))
        .map_err(|_| refused())?;
    Ok(sink.0.finalize())
}

fn selected(value: u64) -> Result<usize, ProviderError> {
    let value = usize::try_from(value).map_err(|_| credit())?;
    if value == 0 || value > MAXIMUM_SELECTION_BYTES {
        return Err(credit());
    }
    Ok(value)
}
fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(credit)
}
fn multiply(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(credit)
}
fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0, |total, value| add(total, *value))
}
fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("complete restore input allocation")
}
fn refused() -> ProviderError {
    ProviderError::Correlation("complete restore input quote changed")
}

pub(super) fn authenticate_decoder_limits(
    request: &PacketCompleteRestorePrepareRequest,
    limits: crate::protocol_snapshot::owned11::outer::OwnedProtocol11DataLimits,
) -> Result<(), ProviderError> {
    let a = &request.allocation;
    for (actual, bound) in [
        (limits.json.maximum_input_bytes, a.maximum_input_bytes.get()),
        (limits.json.maximum_nodes, a.maximum_nodes.get()),
        (limits.json.maximum_depth, a.maximum_depth.get()),
        (
            limits.json.maximum_owned_backing_bytes,
            a.maximum_owned_backing_bytes.get(),
        ),
        (
            limits.json.maximum_tree_entries,
            a.maximum_tree_entries.get(),
        ),
        (limits.maximum_metadata_rows, a.maximum_metadata_rows.get()),
        (
            limits.maximum_literal_backing_bytes,
            a.maximum_literal_backing_bytes.get(),
        ),
        (
            limits.content.content.max_input_bytes,
            a.maximum_input_bytes.get(),
        ),
        (
            limits.content.content.max_groups,
            a.maximum_content_groups.get(),
        ),
        (
            limits.content.content.max_first_group_capacity_bytes,
            a.maximum_content_bytes.get(),
        ),
        (
            limits.content.maximum_metadata_capacity_bytes,
            a.maximum_content_metadata_bytes.get(),
        ),
    ] {
        if actual == 0 || actual > selected(bound)? {
            return Err(credit());
        }
    }
    let rows = add(
        selected(a.maximum_content_transfers.get())?,
        selected(a.maximum_content_objects.get())?,
    )?;
    if limits.content.content.max_rows == 0 || limits.content.content.max_rows > rows {
        return Err(credit());
    }
    Ok(())
}

fn original_restore_response_requested_bound(maximum_frame: usize) -> Result<usize, ProviderError> {
    if maximum_frame > 65_536 {
        return Err(credit());
    }
    // The actual constructor checks the common body at 4096 encoded bytes
    // before copying it. Every JSON node needs at least one encoded byte.
    // Three concurrent Value/decoded representations conservatively cover its
    // validation/encoding path; the full wire limit also bounds scope copies.
    const BODY_BYTES: usize = 4096;
    let tree = tree_storage(
        BODY_BYTES,
        BODY_BYTES,
        size_of::<String>() + size_of::<serde_json::Value>(),
        align_of::<String>().max(align_of::<serde_json::Value>()),
    )?;
    let transient = sum(&[
        BODY_BYTES,
        multiply(BODY_BYTES, size_of::<serde_json::Value>())?,
        tree,
        maximum_frame,
    ])?;
    sum(&[
        multiply(3, transient)?,
        maximum_frame,
        super::restore_response::original_restore_response_owner_layout(),
    ])
}

/// Borrows the same allocation geometry used by the actual custody constructor.
struct InputGeometry {
    raw_input_bytes: usize,
    historical_backing_bytes: usize,
    reconstruction_lookup_bytes: usize,
    requested_geometry_bytes: usize,
    declared_scratch_and_owner_bytes: usize,
    custody_layout_bytes: usize,
}

fn input_geometry(
    allocation: &crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreInputAllocation,
    input_lengths: [usize; 6],
    facts: RetainedProtocolMetadataFacts,
    maximum_frame: usize,
    connection_header_bytes: usize,
) -> Result<InputGeometry, ProviderError> {
    let raw_input_bytes = input_lengths
        .iter()
        .try_fold(0usize, |n, length| add(n, *length))?;
    if input_lengths[0] > selected(allocation.maximum_input_bytes.get())? {
        return Err(credit());
    }
    let rows = selected(allocation.maximum_metadata_rows.get())?;
    let nodes = selected(allocation.maximum_nodes.get())?;
    let depth = selected(allocation.maximum_depth.get())?;
    if rows > 131_072 || depth > 64 {
        return Err(credit());
    }
    // Validate every signed field even if an empty category needs no bank.
    for value in [
        allocation.maximum_known_requested_bytes.get(),
        allocation.maximum_owned_backing_bytes.get(),
        allocation.maximum_tree_entries.get(),
        allocation.maximum_literal_backing_bytes.get(),
        allocation.maximum_content_transfers.get(),
        allocation.maximum_content_objects.get(),
        allocation.maximum_content_groups.get(),
        allocation.maximum_content_bytes.get(),
        allocation.maximum_content_metadata_bytes.get(),
        allocation.maximum_model_bytes.get(),
    ] {
        selected(value)?;
    }
    let (native_entry, historical_payload, payload_alignment, final_owner) =
        outer::original_restore_decoder_layouts();
    let summary = multiply(rows, size_of::<HistoricalAliasSummary>())?;
    let native_groups = multiply(rows, native_entry)?;
    let selected_groups = multiply(
        rows,
        size_of::<Option<std::sync::Arc<[ExtensionSelection]>>>(),
    )?;
    let selected_staging = multiply(rows, 2 * size_of::<ExtensionSelection>())?;
    let content_rows = add(
        selected(allocation.maximum_content_transfers.get())?,
        selected(allocation.maximum_content_objects.get())?,
    )?;
    let content_group_count = selected(allocation.maximum_content_groups.get())?;
    if content_rows > 8192 || content_group_count > 8192 {
        return Err(credit());
    }
    let content_groups = multiply(content_rows, 2 * size_of::<Option<Rc<Vec<u8>>>>())?;
    let reconstruction_lookup_bytes = sum(&[
        summary,
        native_groups,
        selected_groups,
        selected_staging,
        content_groups,
    ])?;
    // Literal/content bounds may overlap recorded Vec rows. Charging both
    // is conservative; an archive cannot claim dedup credit from labels.
    let historical_backing_bytes = sum(&[
        selected(allocation.maximum_owned_backing_bytes.get())?,
        selected(allocation.maximum_literal_backing_bytes.get())?,
        selected(allocation.maximum_content_bytes.get())?,
        selected(allocation.maximum_content_metadata_bytes.get())?,
        multiply(rows, historical_payload)?,
        // Native mapping preparation retains its own canonical Vec and a
        // host projection within it while the original input is retained.
        input_lengths[5],
        input_lengths[0],
        512, // Sealed native full ContentRef backing, distinct from its source DTO.
    ])?;
    let (tree_value, tree_alignment) = tree_layout(facts);
    let trees = tree_storage(
        rows,
        selected(allocation.maximum_tree_entries.get())?,
        tree_value,
        tree_alignment,
    )?;
    let headers = shared_header_storage(
        add(rows, content_group_count)?,
        payload_alignment.max(facts.maximum_shared_value_alignment),
    )?;
    let requested_geometry_bytes = add(trees, headers)?;
    let declared_scratch_and_owner_bytes = sum(&[
        crate::protocol_snapshot::owned11::json_value::original_reconstruction_stack_bytes(),
        // Native blob correspondence keeps this fixed identity bitset.
        2048 * size_of::<u64>(),
        5462, // Selected BlobChunk typed/raw correspondence stack buffer.
        final_owner,
        size_of::<
            std::cell::RefCell<crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping>,
        >(),
        2 * size_of::<usize>()
            + align_of::<
                std::cell::RefCell<crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping>,
            >()
            - 1,
        connection_header_bytes,
        size_of::<NativeRestoreInputAllocationQuote>(),
        // Both original Prepare/Commit responses can coexist. Include
        // canonical banks, final response owners and bounded DTO/Value
        // transients used by the actual selected response constructor.
        multiply(
            2,
            original_restore_response_requested_bound(selected(maximum_frame as u64)?)?,
        )?,
    ])?;
    // Each baseline nonempty BlobChunk consumes a node-budgeted descriptor.
    // The actual selected path enforces this global bound before appending.
    let custody_layout_bytes = add(
        multiply(
            nodes,
            size_of::<super::restore_inputs::OriginalRestoreInputChunk>(),
        )?,
        super::restore_inputs::original_input_custody_layout(),
    )?;

    Ok(InputGeometry {
        raw_input_bytes,
        historical_backing_bytes,
        reconstruction_lookup_bytes,
        requested_geometry_bytes,
        declared_scratch_and_owner_bytes,
        custody_layout_bytes,
    })
}

#[path = "restore_input_quote/current17.rs"]
mod current17;
#[path = "restore_input_quote/settled.rs"]
mod settled;
