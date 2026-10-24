//! Assembles separately derived retained growth and complete encoding phases.
//!
//! These closed obligations originate the same live quote and actual SDK proof
//! planners. They do not replace baseline owners with configured maxima, and
//! they do not issue startup, Capture or whole Source allocation authority.

use super::capture_quote::NativeEndpointCaptureStateData;
use super::*;
use crate::reference_packet::service::capture_allocation::{
    PacketNativeCaptureRetainedGrowth, PacketNativeCaptureTransients,
};
use std::mem::size_of;

pub(super) struct NativeCaptureReportObligationsData {
    pub(super) growth: PacketNativeCaptureRetainedGrowth,
    pub(super) transients: PacketNativeCaptureTransients,
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, next| {
        total
            .checked_add(*next)
            .ok_or(ProviderError::ResourceExhausted(
                "native report phase obligation sum",
            ))
    })
}

fn count(value: usize) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::try_from(value).map_err(|_| {
        ProviderError::ResourceExhausted("native report phase obligation representation")
    })?))
}

impl NativeEndpointCaptureStateData<'_> {
    pub(super) fn report_obligations_data(
        &self,
    ) -> Result<NativeCaptureReportObligationsData, ProviderError> {
        use crate::reference_packet::service::confirmation::{
            PacketNativeAfterConfirmationReceipt, PacketNativeAfterConfirmationRequest,
        };
        let receive = &self.sdk.sdk_data().future_capture_receive;
        // This actual same-Source quote is entered only after the selected
        // startup query has returned. Keep every source/control/candidate owner;
        // partition only its known prefix's exact original storage components.
        let observe_lifetime = self
            .observe_prefix_storage
            .exchange
            .native_original_observe_prepared_lifetime_storage_data(
                &self.observe_preparation,
                receive.maximum_frame_body_bytes,
                self.counter_requested_limit,
            )?;
        let observe_publication = sum(&[
            self.control_growth.publication_retained_bytes,
            observe_lifetime.retained_requested_bytes,
            self.observe_prefix_storage.source_owner_requested_bytes,
            self.candidate_owner.requested_observe_owner_fields_bytes,
        ])?;
        let capture_publication = sum(&[
            self.control_growth.registration_retained_bytes,
            // The selected producer retains the extra original in its fourth
            // owner, plus both actual completed cache bodies/tree/header owners.
            size_of::<Envelope>(),
            crate::reference_packet::control::startup_capture_terminal_cache_storage_data(
                &self.continuation_terminal_shapes.capture_terminal,
            )?,
            self.capture_prefix_storage.requested_bytes()?,
            self.outer_encoding
                .snapshot
                .canonical_output_requested_bytes,
            self.control_growth
                .control_encoding
                .canonical_output_requested_bytes,
            self.continuation_terminal_shapes
                .capture_anchor
                .canonical_output_requested_bytes,
            self.future_capture_request
                .envelope
                .dom_and_canonical_scratch_bytes,
        ])?;
        // The selected confirmation reader restricts Poll before typed decode.
        // Raw read/JSON/Envelope work still uses the same negotiated R. The
        // independently decoded native context and its receipt/response clones
        // are charged from their closed full-frame grammar and concrete types.
        let confirmation_receive = sum(&[
            receive.raw_read_requested_bytes,
            receive.raw_dom_requested_bytes,
            // Independent original, correlation and containment copies. The
            // closed Poll projection owns the full confirmation extension;
            // typed Capture-only validation is deliberately not reused.
            self.continuation_terminal_shapes
                .confirmation_original
                .requested_total()?,
            self.continuation_terminal_shapes
                .confirmation_original
                .requested_total()?,
            self.continuation_terminal_shapes
                .confirmation_original
                .requested_total()?,
            receive.correlation_requested_bytes,
            receive.current_incident_copy_requested_bytes,
            self.future_capture_request.envelope.requested_total()?,
            self.continuation_terminal_shapes
                .capture_terminal
                .requested_total()?,
            2 * 132, // repeated actual Capture request-hash numeric formatter
            size_of::<blake3::Hasher>(),
            size_of::<crate::bodies::PollRequest>(),
            size_of::<RequestBody>(),
            size_of::<PacketNativeAfterConfirmationRequest>(),
            size_of::<PacketNativeAfterConfirmationReceipt>(),
            self.continuation_terminal_shapes
                .confirmation_terminal
                .dom_and_canonical_scratch_bytes,
        ])?;
        let after_confirmation = sum(&[
            confirmation_receive,
            self.confirmation_prefix_storage.requested_bytes()?,
            self.continuation_terminal_shapes
                .confirmation_terminal
                .requested_total()?,
        ])?;
        let observe_encoding = sum(&[
            self.stopped_observe_raw_record.encoding.requested_total()?,
            self.observe_publication_shapes
                .native_receipt
                .requested_total()?,
            self.observe_publication_shapes
                .wrapper_record
                .requested_total()?,
            self.observe_publication_shapes.terminal.requested_total()?,
            self.report_shape.encoding.requested_total()?,
            self.observe_publication_shapes
                .typed_receipt_requested_bytes,
            self.observe_publication_shapes
                .binding_identity_requested_bytes,
            observe_lifetime.encoding_work_requested_bytes()?,
            self.observe_prefix_storage.declared_counter_scratch_bytes,
            self.candidate_owner.serialization_requested_bytes,
        ])?;
        // The same publisher finishes transform/prepare before it reads ACKs.
        // Preserve the actual returned query and both defining counter windows
        // here, matching the separately admitted startup phase projection.
        let observe_acknowledgement = sum(&[
            self.returned_observe_query_requested_bytes,
            observe_lifetime.acknowledgement_work_requested_bytes()?,
            self.observe_prefix_storage.declared_counter_scratch_bytes,
        ])?;
        let observe_encoding = observe_encoding.max(observe_acknowledgement);
        let before_encoding = sum(&[
            self.outer_encoding.native_before.requested_total()?,
            self.outer_encoding.protocol_before.requested_total()?,
            self.outer_encoding.endpoint.requested_total()?,
            self.outer_encoding.snapshot.requested_total()?,
            self.control_growth
                .control_encoding
                .projected_parser_requested_bytes,
            self.continuation_terminal_shapes
                .capture_anchor
                .requested_total()?,
            self.capture_prefix_storage.requested_bytes()?,
        ])?;
        let after_events =
            self.native12_encoding
                .after
                .serialization_events
                .ok_or(ProviderError::Correlation(
                    "native report actual after serializer obligations absent",
                ))?;
        let after_encoding = crate::reference_packet::serialization_storage::closed_event_serialization_storage_data(
            self.native12_encoding.after.maximum_encoded_bytes,
            after_events.maximum_value_nodes,
            after_events.maximum_capacity_records,
            after_events.maximum_serializer_temporary_requested_bytes,
            self.counter_requested_limit,
        )?;
        let after_phase = sum(&[
            after_encoding.requested_total()?,
            confirmation_receive,
            self.confirmation_prefix_storage.requested_bytes()?,
            self.continuation_terminal_shapes
                .confirmation_terminal
                .requested_total()?,
        ])?;
        let scratch = sum(&[
            self.invocation_counter_scratch_bytes,
            size_of::<Self>(),
            crate::reference_packet::control::original_observe_dispatch_scratch_data(),
            size_of::<NativeCaptureReportObligationsData>(),
            crate::connection::OriginalPacketPrefixStorageData::native_original_observe_prepared_lifetime_counter_scratch_data(),
            size_of::<[usize; 3]>(),
            size_of::<Result<usize, ProviderError>>(),
            size_of::<usize>(),
            super::capture_startup::original_startup_capture_endpoint_counter_scratch_data(),
            crate::reference_packet::control::original_startup_capture_counter_scratch_data(),
            crate::reference_packet::service::native_snapshot::native_owned13_snapshot_schema_counter_scratch_data(),
            self.compact_serializer_scratch_bytes,
            crate::connection::NativeCaptureSdkStateQuote::requested_scratch_bytes(),
            self.candidate_owner.declared_counter_scratch_bytes,
            self.native12_encoding.declared_counter_scratch_bytes,
            self.completed_observe_record_encoding
                .declared_counter_scratch_bytes,
        ])?;
        Ok(NativeCaptureReportObligationsData {
            growth: PacketNativeCaptureRetainedGrowth {
                observe_publication_bytes: count(observe_publication)?,
                capture_request_bytes: count(receive.maximum_requested_bytes)?,
                capture_publication_bytes: count(capture_publication)?,
                after_confirmation_bytes: count(after_confirmation)?,
            },
            transients: PacketNativeCaptureTransients {
                observe_encoding_bytes: count(observe_encoding)?,
                model_control_encoding_bytes: count(
                    self.control_growth.model_control_requested_bytes,
                )?,
                native_before_encoding_bytes: count(before_encoding)?,
                native_after_encoding_bytes: count(after_phase)?,
                quote_scratch_bytes: count(scratch)?,
            },
        })
    }
}
