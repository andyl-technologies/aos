//! Conjoins actual Source, SDK and host decoder demand before construction.
//!
//! The earlier passive row funds defining metadata and counting work. The full
//! row independently adds every future owner; native reservations never pay for
//! host copies and no admission number becomes an administrative permission.

use super::super::*;
use super::{
    accounting, construction_data::OriginalSourceRestoredCaptureConstructionData as Row,
    quote_context::OriginalSourceRestoredCaptureQuoteInputs, transport_quote,
};
use crate::node_adapters::cnp::semantic::node::OriginalRestoredSettledNodeHistoryView;
use crate::node_admission::{OriginalRestoredCaptureRequestData, OriginalRestoredCaptureSigningInputs};
use crucible_node_provider::{
    client::{CnpController, OriginalRestoredSettledCaptureProspectiveData},
    reference_packet::service::complete_restore::activation::{
        restoration_activation_retained_native_evidence_counter_scratch_data,
        restoration_activation_retained_native_evidence_data,
    },
    retained_metadata::serialization_storage::original_json_value_storage_extent_data,
};

impl PacketCompleteSemanticSource {
    /// Prices the real borrowed count before allocating output or native work.
    ///
    /// Counting banks are separately reserved by the owning Window from actual
    /// Node/header metadata demand. This row covers their defining traversal,
    /// serializer temporaries and all fixed prospective/construction getters.
    ///
    /// # Errors
    /// Refuses another Source/member, unsupported fields or arithmetic overflow.
    pub(crate) fn original_restored_capture_prequote_storage_data(
        &self,
        controller: &CnpController,
        read_owner: *const (),
        launch: &PacketNative5SourceLaunch,
        raw5: &[u8],
        inputs: &OriginalRestoredCaptureSigningInputs<'_>,
        request: &OriginalRestoredCaptureRequestData<'_>,
        node: &OriginalRestoredSettledNodeHistoryView<'_>,
        maximum: usize,
    ) -> Result<(usize, usize, usize), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if read_owner.is_null()
            || !std::ptr::eq(inputs.source, self)
            || raw5.is_empty()
            || request.maximum_runtime_record_encoded_bytes == 0
            || request.maximum_coordinator_checkpoint_encoded_bytes == 0
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let demand = node.metadata_demand_data()?;
        let banks = self.original_restored_capture_counting_banks_data(node, maximum)?;
        let launch_pass = original_json_value_storage_extent_data(raw5.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let transient = sum(
            &[
                self.original_restored_settled_source17_serialization_transient_data(
                    controller, launch,
                )?,
                demand.historical_serialization_transient_bytes_data(),
                node.original_controller_history_serialization_transient_data(controller)?,
                launch_pass
                    .canonical_pass_requested_bytes()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            ],
            maximum,
        )?;
        let semantic_scratch =
            super::logical::OriginalSourceRestoredSettledSemantic17View::counter_scratch_data()?;
        let scope_scratch = crucible_node_provider::reference_packet::service::complete_restore::activation::
            PacketRestorationActivationScope::original_capture17_retained_metadata_counter_scratch_data();
        let scratch = sum(
            &[
                Self::original_restored_capture_counter_scratch_data(),
                demand.counter_scratch_bytes_data(),
                CnpController::settled_history_counter_scratch_data(),
                super::finalization::FinalizationStorage::counter_scratch_data(),
                launch_pass.declared_counter_scratch_bytes,
                semantic_scratch,
                scope_scratch,
                CnpController::original_restored_settled_capture_counter_scratch_data(),
                Self::original_live_checkpoint17_cache_counter_scratch_data(),
                super::ancestry::OriginalRestoredCaptureAncestry17Data::counter_scratch_data(),
                restoration_activation_retained_native_evidence_counter_scratch_data(),
                Self::original_restored_settled_startup_counter_scratch_data()?,
            ],
            maximum,
        )?;
        sum(&[banks.retained, transient, scratch], maximum)?;
        Ok((banks.retained, transient, scratch))
    }

    /// Quotes complete future work using the actual independently admitted count.
    ///
    /// The quote inputs borrow genuine immutable archive roles and counting
    /// banks funded before this call. The resulting row owns no permission.
    ///
    /// # Errors
    /// Refuses foreign members, changed launch, incomplete current checkpoint,
    /// oversized actual syntax/transport, missing native reserve or short credit.
    pub(crate) fn original_restored_capture_construction_data(
        &self,
        controller: &CnpController,
        read_owner: *const (),
        launch: &PacketNative5SourceLaunch,
        raw5: &[u8],
        inputs: &OriginalRestoredCaptureSigningInputs<'_>,
        request: &OriginalRestoredCaptureRequestData<'_>,
        node: &OriginalRestoredSettledNodeHistoryView<'_>,
        quote: &OriginalSourceRestoredCaptureQuoteInputs<'_>,
        maximum: usize,
    ) -> Result<Row, RuntimeError> {
        self.original_restored_capture_prequote_storage_data(
            controller, read_owner, launch, raw5, inputs, request, node, maximum,
        )?;
        inputs.authenticate_current_data()?;
        self.authenticate_original_restored_settled_source17_launch_data(launch, raw5)?;
        let native = self.original_completed_restored_settled_startup_data()?;
        let validation = self.with_original_completed_restored_settled_startup_data(|storage| {
            storage
                .source_output_validation_data()
                .map_err(|_| RuntimeError::ResourceLimit)
        })?;
        let (prefix, frozen, frontier) = self.with_latest_original_checkpoint17_geometry_data(
            controller,
            inputs.world,
            |current| {
                let facts = restoration_activation_retained_native_evidence_data(
                    current.record_data(),
                    Some(current.underlying_data()),
                )
                .map_err(|_| RuntimeError::ResourceLimit)?;
                let frozen = sum(
                    &[
                        Self::complete_retained_metadata_storage_precredit_data(&facts, maximum)?,
                        NodeRuntime::capture_reference_storage(current.measurement_data())?,
                        NodeRuntime::capture_reference_storage(current.first_observation_data())?,
                        Self::complete_retained_metadata_storage_precredit_data(
                            &current
                                .scope_data()
                                .original_capture17_retained_metadata_data()
                                .map_err(|_| RuntimeError::ResourceLimit)?,
                            maximum,
                        )?,
                    ],
                    maximum,
                )?;
                let prefix = accounting::extent_data(
                    self,
                    controller,
                    launch,
                    inputs,
                    node,
                    quote,
                    current.completed_frontier_data(),
                    request.maximum_coordinator_checkpoint_encoded_bytes,
                    maximum,
                )?;
                Ok((prefix, frozen, current.completed_frontier_data()))
            },
        )?;
        if frontier.get() == 0 || prefix > self.installation().maximum_semantic_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        let sdk = controller
            .original_restored_settled_capture_future_construction_data(
                launch,
                &OriginalRestoredSettledCaptureProspectiveData {
                    capture_id: request.capture_id,
                    cut: request.cut,
                    event_ordinal: request.ordinal,
                    maximum_history_prefix_encoded_bytes: prefix,
                    maximum_runtime_record_encoded_bytes: request
                        .maximum_runtime_record_encoded_bytes,
                },
                maximum,
            )
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let auxiliary = sdk.maximum_auxiliary_originals_data();
        let originals = auxiliary[0]
            .checked_add(auxiliary[1])
            .and_then(|value| value.checked_add(2))
            .ok_or(RuntimeError::ResourceLimit)?;
        if originals
            > usize::try_from(native.maximum_originals.get())
                .map_err(|_| RuntimeError::ResourceLimit)?
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let source = transport_quote::future_storage_data(
            &sdk,
            inputs.world,
            prefix,
            request.maximum_runtime_record_encoded_bytes,
            request.maximum_coordinator_checkpoint_encoded_bytes,
            maximum,
        )?;
        // A final Complete ledger adds one Bridge containing a genuine World,
        // four full content references, two bounded IDs, two U64s and a 32-byte
        // signature. The defining private grammar counter uses borrowed World
        // and maximally escaped closed IDs; no authoritative DTO is fabricated.
        let semantic = accounting::final_semantic_extent_bound_data(
            prefix,
            inputs.world,
            request.capture_id,
            maximum,
        )?;
        if semantic > self.installation().maximum_semantic_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        let output = original_json_value_storage_extent_data(semantic)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        // Final Controller24 is a later cut than the prefix. Its actual same-Node
        // supervisor baseline and the SDK's defining finite encoded delta are
        // funded independently before the first auxiliary upload is assigned.
        let controller_baseline = super::encoding_extent::canonical_encoded_extent_data(
            &node.original_controller_history_data(controller)?,
            maximum,
        )?;
        let finalization = super::finalization::FinalizationStorage::quote_data(
            controller_baseline,
            &sdk,
            quote.ancestry,
            usize::try_from(controller.authority().limits().frame_bytes.get())
                .map_err(|_| RuntimeError::ResourceLimit)?,
            inputs.scope_proof_body.len(),
            maximum,
        )?;
        let materialization =
            super::materialization_storage::CaptureMaterializationStorage::quote_data(
                self,
                &native.output_limits,
                &finalization,
                semantic,
                prefix,
                maximum,
            )?;
        let retained = sum(
            &[
                source.0,
                materialization.retained,
                finalization.retained,
                sdk.retained_requested_bytes_data(),
                validation.retained_requested_bytes_data(),
                frozen,
                quote.ancestry.owned_requested_storage_data(maximum)?,
                // The actual Source argument ledger coexists with the independently
                // cloned SDK-input transport owner, including its two Upload requests.
                sdk.maximum_capture_request_backing_bytes_data()
                    .checked_mul(4)
                    .ok_or(RuntimeError::ResourceLimit)?,
                sdk.maximum_begin_body_backing_bytes_data()
                    .checked_mul(2)
                    .ok_or(RuntimeError::ResourceLimit)?,
                4 * 128,
                output.value_dom_requested_bytes,
                semantic,
                semantic,
                // Final semantic + extracted exact embedded Node have independent
                // canonical byte banks and full content-reference backing.
                2 * ("blake3-256".len() + "cnp.blob.v1".len() + 64)
                    + crucible_node_provider::protocol_snapshot::restored_journal17::RESTORED_SETTLED_SEMANTIC17_MEDIA.len()
                    + "application/json".len(),
                std::mem::size_of::<super::effect::CaptureConstructionOwners>(),
            ],
            maximum,
        )?;
        let transient = sum(
            &[
                source.1,
                materialization.transient,
                // The eventual caller owns this actual executable-link bank
                // throughout its armed read. Fixed stream/guard S is separate.
                self.original_retained_capture17_fresh_link_storage_data()?,
                finalization.transient,
                sdk.maximum_simultaneous_transient_bytes_data(),
                validation.maximum_simultaneous_transient_bytes_data(),
                frozen,
                quote.ancestry.owned_requested_storage_data(maximum)?,
                output
                    .canonical_pass_requested_bytes()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                self.original_restored_settled_source17_serialization_transient_data(
                    controller, launch,
                )?,
            ],
            maximum,
        )?;
        let scratch = sum(
            &[
                source.2,
                materialization.scratch,
                finalization.scratch,
                sdk.counter_scratch_bytes_data(),
                validation.declared_counter_scratch_bytes_data(),
                output.declared_counter_scratch_bytes,
                Self::original_restored_capture_counter_scratch_data(),
            ],
            maximum,
        )?;
        let row = Row {
            process: std::process::id(),
            thread: std::thread::current().id(),
            source: self,
            controller,
            read_owner,
            launch,
            launch_digest: *blake3::hash(raw5).as_bytes(),
            capture_id: *blake3::hash(request.capture_id.as_str().as_bytes()).as_bytes(),
            cut: request.cut,
            ordinal: request.ordinal,
            runtime: request.maximum_runtime_record_encoded_bytes,
            prefix,
            checkpoint: request.maximum_coordinator_checkpoint_encoded_bytes,
            semantic,
            frozen,
            finalization,
            materialization,
            sdk,
            native,
            validation,
            retained,
            transient,
            scratch,
            maximum,
        };
        row.requested_bytes_data()?;
        inputs.authenticate_current_data()?;
        Ok(row)
    }

    /// Reports fixed Source quote/effect and borrowed root frames.
    pub(crate) fn original_restored_capture_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Row>()
            + size_of::<Result<Row, RuntimeError>>()
            + size_of::<OriginalRestoredSettledCaptureProspectiveData<'static>>()
            + size_of::<super::quote_context::OriginalSourceRestoredCaptureQuoteInputs<'static>>()
            + size_of::<[usize; 11]>()
            + size_of::<std::array::IntoIter<usize, 11>>()
            + size_of::<[usize; 5]>()
            + size_of::<std::array::IntoIter<usize, 5>>()
            + size_of::<[usize; 3]>()
            + size_of::<std::array::IntoIter<usize, 3>>()
            + size_of::<&[usize]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Option<usize>>()
            + size_of::<blake3::Hash>()
            + size_of::<[u8; 32]>()
            + size_of::<blake3::Hasher>()
            + size_of::<String>()
            + size_of::<&[u8; 16]>()
            + size_of::<char>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<super::quote_context::OriginalSourceRestoredCaptureCountingBanksData>()
            + size_of::<super::quote_context::OriginalSourceRestoredCaptureEncodingInputs<'static>>(
            )
            + size_of::<[usize; 6]>()
            + size_of::<[usize; 9]>()
            + size_of::<[usize; 13]>()
            + size_of::<
                std::cell::Ref<
                    'static,
                    crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityAliases,
                >,
            >()
            + size_of::<
                Result<
                    std::cell::Ref<
                        'static,
                        crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityAliases,
                    >,
                    std::cell::BorrowError,
                >,
            >()
            + accounting::counter_scratch_data()
            + super::effect::counter_scratch_data()
            + Self::original_retained_capture17_read_counter_scratch_data::<usize>()
    }
}

pub(super) fn sum(values: &[usize], maximum: usize) -> Result<usize, RuntimeError> {
    values.iter().try_fold(0usize, |total, n| {
        total
            .checked_add(*n)
            .filter(|n| *n <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })
}
