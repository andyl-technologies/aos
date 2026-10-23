//! Joins the real endpoint roots to the unfinished native SDK Capture walk.
//!
//! This producer runs at the actual incoming Observe boundary. Snapshot banks
//! remain the same unused precharged allocations; no Capture cut is bound and
//! no model, Control, report or protocol bytes are copied by this walk.

use super::*;
use crate::client::DeadlineStream;
use crate::connection::NativeCaptureSdkCompletedQuote;
use crate::reference_packet::control::PacketLiveCaptureControlCurrency;
use crate::reference_packet::serialization_storage::NativeControlCaptureEncodingData;
use crate::reference_packet::service::{
    OriginalNativeServiceCaptureContext,
    capture_allocation::PacketNative5CaptureAllocationSelection,
};

/// Holds actual current owner data while the same Observe is prepared.
///
/// Future request, publication and encoding phases are separate terms. In
/// particular, neither snapshot capacity nor this current walk supplies the
/// requested storage of the future proof exchange.
pub(super) struct NativeEndpointCaptureStateData<'a> {
    pub(super) sdk: NativeCaptureSdkCompletedQuote,
    pub(super) currency: PacketLiveCaptureControlCurrency,
    pub(super) observe_hash: crucible_node_format::HashRef,
    pub(super) control_encoding: NativeControlCaptureEncodingData,
    pub(super) control_growth: crate::reference_packet::control::NativeObserveControlGrowthData,
    pub(super) service_inline_bytes: usize,
    pub(super) snapshot_backing_bytes: usize,
    pub(super) incoming_typed_header_bytes: usize,
    // Same closed returned Observe layout as the pre-child startup producer,
    // borrowed from this actual connection's immutable negotiated limits.
    pub(super) returned_observe_query_requested_bytes: usize,
    pub(super) future_capture_request:
        crate::reference_packet::control::NativeProjectedCaptureRequestData,
    pub(super) report_shape: crate::reference_packet::control::NativeCaptureReportProjectionData,
    pub(super) retained_requested_bytes: usize,
    pub(super) compact_serializer_scratch_bytes: usize,
    // Finite refusal ceiling of this admitted counter invocation. It grants
    // no output/model/whole allocation and is never reported as actual usage.
    pub(super) counter_requested_limit: usize,
    pub(super) invocation_counter_scratch_bytes: usize,
    pub(super) observe_publication_shapes:
        crate::reference_packet::control::NativeObservePublicationProjectionData,
    pub(super) stopped_observe_raw_record:
        crate::reference_packet::control::NativeStoppedObserveRecordStorageData<'a>,
    pub(super) candidate_owner: super::capture_candidate::NativeCaptureCandidateOwnerData,
    pub(super) native12_encoding: crate::connection::NativeOwned12CaptureEncodingData,
    pub(super) outer_encoding: super::capture_outer_projection::NativeCaptureOuterProjectionData,
    pub(super) capture_prefix_storage: crate::connection::OriginalContinuationPrefixStorageData,
    pub(super) confirmation_prefix_storage:
        crate::connection::OriginalContinuationPrefixStorageData,
    pub(super) continuation_terminal_shapes:
        crate::reference_packet::control::NativeContinuationTerminalProjectionData,
    // This whole prospective plan is transient through Observe publication.
    // It must be dropped before the completed fourth owner becomes capturable;
    // future Capture/confirmation plans are recomputed under that report.
    pub(super) observe_prefix_storage: crate::connection::OriginalPacketPrefixProjectionStorageData,
    // Fixed scalar DATA from this same complete live prefix. All owning banks
    // remain in observe_prefix_storage and its independent publication rows.
    pub(super) observe_preparation: crate::connection::OriginalNativeObservePreparationStorageData,
    pub(super) completed_observe_record_encoding:
        crate::connection::OriginalPacketCompletedRecordEncodingData,
}

impl PacketEndpoint<DeadlineStream> {
    pub(super) fn quote_original_live_capture_state<'a>(
        &mut self,
        request: &'a Envelope,
        body: &ObserveRequest,
        service: &OriginalNativeServiceCaptureContext<'_>,
        startup: &crate::reference_packet::service::ack_emitter::OriginalNativeReportStartupAllocation,
    ) -> Result<NativeEndpointCaptureStateData<'a>, ProviderError> {
        self.ensure_complete_origin()?;
        if startup.purpose_data()
            != crate::reference_packet::service::report_startup::PacketNativeReportStartupPurpose::OriginalObserve12
        {
            return Err(refused());
        }

        let maximum_serialization_requested_bytes = startup.maximum_requested_bytes()?;
        let compact_serializer_scratch_bytes =
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::requested_serialization_scratch_bytes();
        if compact_serializer_scratch_bytes > maximum_serialization_requested_bytes {
            return Err(exhausted());
        }
        let Self {
            transport,
            native,
            authority,
            policy,
            uploads,
            pins,
            records,
            next_sequence,
            transport_credit: self_transport_credit,
            held,
            complete,
            capture,
            capture_allocation_attempt,
            fresh_restore_attempt,
            pending_capture,
            after_confirmation,
            canonical_ack_boot,
            canonical_ack_admission,
            restore_commit,
            restore_protocol_attempted,
            restore_prepare_admission,
        } = self;
        if !*held
            || request.message != MessageKind::Request
            || request.method != Method::Observe
            || capture_allocation_attempt.is_some()
            || fresh_restore_attempt.is_some()
            || capture.is_some()
            || pending_capture.is_some()
            || after_confirmation.is_some()
            || restore_commit.is_some()
            || *restore_protocol_attempted
            || restore_prepare_admission.is_some()
            || canonical_ack_admission.is_some()
        {
            return Err(refused());
        }
        let Some(Transport::Connected(connection)) = transport.as_mut() else {
            return Err(refused());
        };
        startup.authenticate_compiled_headers(
            connection,
            original_capture_report_quote_layout_data(),
            super::capture_allocation::original_capture_report_owner_layout_data(),
        )?;
        // The exact scope/census counter window is prepaid above before this
        // original Source14 state check or any metadata/SDK/DOM/report work.
        startup.authenticate_original_initial_observation_data(connection, native)?;
        // The SDK checks the actual actor and sealed native codec before any
        // pin/Hello/Control data borrow. Neither those owners nor their numeric
        // facts may replace the genuine installed native admission.
        let returned_observe_query_requested_bytes =
            connection.original_observe_returned_query_storage_data()?;
        let installed = connection.original_native_owned11_admission()?;
        if installed.policy.capture_allocation_selection()
            != Some(PacketNative5CaptureAllocationSelection::OriginalObserve12)
        {
            return Err(refused());
        }
        let boot = canonical_ack_boot.as_ref().ok_or_else(refused)?;
        let context = service.with_original_endpoint_roots(boot, policy);
        context.authenticate_original(connection, uploads)?;
        let invocation = boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("invocation Observe boot borrowed"))?
            .requires_invocation_codec_data()?;
        let invocation_counter_scratch_bytes = if invocation {
            let additional = original_invocation_capture_report_additional_scratch_data();
            startup.authenticate_compiled_headers(
                connection,
                checked_sum(&[original_capture_report_quote_layout_data(), additional])?,
                super::capture_allocation::original_capture_report_owner_layout_data(),
            )?;
            additional
        } else {
            0
        };

        let complete = complete.as_mut().ok_or_else(refused)?;
        complete.authenticate_live_capture_quote(native)?;
        let before = complete.before.as_mut().ok_or_else(refused)?;
        let after = complete.after.as_mut().ok_or_else(refused)?;
        let mut sdk =
            connection.quote_original_native_capture_sdk_state(before, after, uploads, &context)?;
        let currency = {
            let (roots, observer) = sdk.native_metadata_mut();
            startup.observe_unique_capture_metadata(connection, roots, observer)?;
            // This is a separate independently owned ConnectionAuthority clone
            // in the endpoint. Its Strings are separate even when its Arc
            // payloads also occur through the connection/service roots.
            authority.observe_unique_capture_metadata(roots, observer)?;
            complete
                .hello
                .observe_unique_capture_metadata(roots, observer)?;
            observer.vector::<OperationContentPin>(pins.capacity())?;
            for pin in pins.iter() {
                pin.observe_unique_capture_metadata(uploads, roots, observer)?;
            }
            observer.vector::<ExchangeRecord>(records.capacity())?;
            for record in records.iter() {
                record.observe_unique_capture_metadata(connection, roots, observer)?;
            }
            // The received Envelope and boxed typed Observe are actual live
            // roots outside the Connection. CorrelationGuard owns a distinct
            // Envelope clone, already covered by the SDK walk.
            observer.observe(request)?;
            let ObserveRequest {
                binding_hash,
                owner_generation,
                after_observation_sequence,
                maximum_items,
                extensions,
            } = body;
            observer.observe(binding_hash)?;
            observer.observe(owner_generation)?;
            observer.observe(after_observation_sequence)?;
            observer.observe(maximum_items)?;
            observer.observe(extensions)?;
            native.observe_original_live_capture_metadata(roots, observer)?
        };
        // Serialization quotes borrow the real stopped model and Control.
        // Their separate temporary observer must finish before SDK association
        // revalidation acquires any registrar/service loan.
        let control_encoding =
            native.quote_original_live_capture_encoding(maximum_serialization_requested_bytes)?;
        let sdk = sdk.finish_original(connection, uploads, &context)?;
        let future_capture_request = native.quote_original_next_capture_request(
            request,
            sdk.sdk_data()
                .future_capture_receive
                .maximum_frame_body_bytes,
            maximum_serialization_requested_bytes,
        )?;
        let snapshot_backing_bytes = sdk
            .sdk_data()
            .before
            .allocation
            .allocated_bytes
            .checked_add(sdk.sdk_data().after.allocation.allocated_bytes)
            .ok_or_else(exhausted)?;
        let stopped_observe_raw_record = native.quote_original_stopped_observe_record(
            request,
            maximum_serialization_requested_bytes,
        )?;
        let report_shape = native.quote_original_capture_report_shape(
            crate::reference_packet::control::NativeCaptureReportObservationContext {
                original: request,
                observed: body,
                currency: &currency,
                metadata: &complete.metadata_birth_facts.ok_or_else(refused)?,
                endpoint_records_before: records.len(),
                provider_next_sequence_before: *next_sequence,
            },
            maximum_serialization_requested_bytes,
        )?;
        let observe_hash = {
            // This loan authenticates the sole same-actor original and exact
            // canonical literal correspondence, then hashes those retained
            // bytes. The frame-bank borrow ends before any reservation/write.
            let original_body =
                connection.original_report_query_body_data(request, *next_sequence)?;
            crucible_node_format::canonical::hash(
                crate::reference_packet::service::capture_allocation::NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN,
                &original_body,
            )?
        };
        let continuation_terminal_shapes = native.quote_original_continuation_terminal_shapes(
            request,
            &currency,
            &future_capture_request,
            maximum_serialization_requested_bytes,
        )?;
        let observe_publication_shapes = native.quote_original_observe_publication_shapes(
            request,
            &currency,
            maximum_serialization_requested_bytes,
        )?;
        let control_growth = native.quote_original_observe_control_growth(
            crate::reference_packet::control::NativeObserveControlGrowthInput {
                original: request,
                currency: &currency,
                current: &control_encoding,
                raw: &stopped_observe_raw_record.encoding,
                publication: &observe_publication_shapes,
                report: &report_shape,
                capture: &future_capture_request,
                maximum: maximum_serialization_requested_bytes,
            },
        )?;
        let (observe_prefix_storage, observe_preparation, completed_observe_record_encoding) = {
            let mut original_fields = crate::retained_metadata::MetadataObserver::new();
            original_fields.observe(request)?;
            let original =
                crate::reference_packet::serialization_storage::actual_serialization_storage_data(
                    request,
                    original_fields.finish(),
                    maximum_serialization_requested_bytes,
                )?;
            // These extents come from the real raw-record serializer and closed
            // receipt/report field counters. No future body or reference is
            // allocated merely to obtain the prospective prefix allowance.
            let objects = [
                crate::connection::OriginalContinuationContentExtent {
                    maximum_payload_bytes: stopped_observe_raw_record.encoding.maximum_encoded_bytes,
                    media_type: "application/json",
                },
                crate::connection::OriginalContinuationContentExtent {
                    maximum_payload_bytes: observe_publication_shapes.wrapper_record.maximum_encoded_bytes,
                    media_type: "application/json",
                },
                crate::connection::OriginalContinuationContentExtent {
                    maximum_payload_bytes: report_shape.encoding.maximum_encoded_bytes,
                    media_type: crate::reference_packet::service::capture_allocation::PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
                },
            ];
            if objects[2].maximum_payload_bytes
                > crate::reference_packet::service::capture_allocation::MAXIMUM_NATIVE_CAPTURE_ALLOCATION_REPORT_BYTES
            {
                return Err(exhausted());
            }
            let quoted = connection.quote_original_packet_prefix_projection_storage_data(
                *next_sequence,
                request,
                crate::connection::OriginalPacketPrefixProjectionInput {
                    terminal: &observe_publication_shapes.terminal,
                    original: &original,
                    objects: &objects,
                    maximum_requested_bytes: maximum_serialization_requested_bytes,
                },
            )?;
            // Native history precedes this suffix and remains charged. The SDK
            // independently checks its same original frame/descriptor banks.
            let preparation =
                connection.quote_original_native_observe_preparation_storage_data(&quoted)?;
            let record = quoted.completed_record_encoding_data(connection)?;
            quoted
                .exchange
                .preflight_transport_credit_data(*self_transport_credit)?;
            (quoted, preparation, record)
        };
        let candidate_owner = super::capture_candidate::quote_original_candidate_owner(
            connection,
            uploads,
            &context,
            native,
            request,
            &sdk,
            &currency,
            &report_shape,
            &future_capture_request,
            &complete.metadata_birth_facts.ok_or_else(refused)?,
            maximum_serialization_requested_bytes,
        )?;
        let current_storage = &sdk.sdk_data().original_storage;
        let before_suffix = crate::connection::NativeOwned12CaptureSuffixData {
            maximum_retained_bytes: checked_sum(&[
                current_storage.retained_bytes,
                observe_prefix_storage.exchange.outgoing_framed_bytes,
                completed_observe_record_encoding.maximum_completed_incoming_framed_bytes,
                future_capture_request.envelope.maximum_encoded_bytes,
                4,
            ])?,
            maximum_incoming_frames: checked_sum(&[
                current_storage.incoming_frames,
                observe_prefix_storage.exchange.requests,
                1,
            ])?,
            maximum_outgoing_frames: checked_sum(&[
                current_storage.outgoing_frames,
                observe_prefix_storage.exchange.frames,
            ])?,
        };
        // Before depends only on the completed original Observe suffix and the
        // sole restricted next Capture. No provisional after bound is created.
        let native12_before = connection.quote_original_native_owned12_capture_before_encoding(
            before,
            after,
            uploads,
            &context,
            crate::connection::NativeOwned12CaptureEncodingPlan {
                sdk: &sdk,
                candidate: &candidate_owner,
                original_observe: request,
                first_observe_response: *next_sequence,
                maximum_requested_bytes: maximum_serialization_requested_bytes,
            },
            before_suffix,
        )?;
        // The actual live boot selects the new DATA grammar only after the
        // concrete installer authenticates its full outer13 schema.
        let startup_codec = context.requires_original_native_startup_codec(connection, uploads)?;
        let outer_edition = if invocation {
            policy.authenticate_invocation_capture_snapshot_definition()?;
            super::capture_outer_projection::NativeCaptureOuterEdition::Invocation14
        } else if startup_codec {
            policy.authenticate_startup_capture_snapshot_definition()?;
            super::capture_outer_projection::NativeCaptureOuterEdition::Startup13
        } else {
            super::capture_outer_projection::NativeCaptureOuterEdition::Allocation12
        };
        let outer_encoding = super::capture_outer_projection::quote_original_outer12_projection(
            super::capture_outer_projection::NativeCaptureOuterProjectionInput {
                edition: outer_edition,
                state: complete,
                records,
                record_capacity: records.capacity(),
                pins,
                pin_capacity: pins.capacity(),
                uploads,
                observed_fields: sdk.retained_metadata(),
                before: &native12_before,
                observe_record: &completed_observe_record_encoding,
                control: &control_growth,
                capture: &future_capture_request,
                maximum_requested_bytes: maximum_serialization_requested_bytes,
            },
        )?;
        let capture_objects = [
            crate::connection::OriginalContinuationContentExtent {
                maximum_payload_bytes: outer_encoding.snapshot.maximum_encoded_bytes,
                media_type: "application/json",
            },
            crate::connection::OriginalContinuationContentExtent {
                maximum_payload_bytes: continuation_terminal_shapes
                    .capture_anchor
                    .maximum_encoded_bytes,
                media_type: "application/json",
            },
            crate::connection::OriginalContinuationContentExtent {
                maximum_payload_bytes: control_growth.maximum_control_encoded_bytes,
                media_type: "application/json",
            },
        ];
        let capture_prefix_storage = connection.quote_original_continuation_prefix_storage_data(
            *next_sequence,
            request,
            crate::connection::OriginalContinuationPrefixStorageInput {
                kind: crate::connection::OriginalContinuationPrefixKind::Capture,
                original: &future_capture_request.envelope,
                terminal: &continuation_terminal_shapes.capture_terminal,
                objects: &capture_objects,
                maximum_requested_bytes: maximum_serialization_requested_bytes,
            },
        )?;
        let capture_completed_incoming = connection
            .quote_original_continuation_completed_incoming_data(
                &capture_prefix_storage,
                maximum_serialization_requested_bytes,
            )?;
        let after_suffix = crate::connection::NativeOwned12CaptureSuffixData {
            maximum_retained_bytes: checked_sum(&[
                before_suffix.maximum_retained_bytes,
                capture_prefix_storage.exchange.outgoing_framed_bytes,
                capture_completed_incoming,
            ])?,
            maximum_incoming_frames: checked_sum(&[
                before_suffix.maximum_incoming_frames,
                capture_prefix_storage.exchange.requests,
            ])?,
            maximum_outgoing_frames: checked_sum(&[
                before_suffix.maximum_outgoing_frames,
                capture_prefix_storage.exchange.frames,
            ])?,
        };
        let before = complete.before.as_mut().ok_or_else(refused)?;
        let after = complete.after.as_mut().ok_or_else(refused)?;
        // Final pair recounts the same actual current roots and Observe cut.
        // The after suffix is now derived from the real outer12/Control/anchor
        // encoders and complete Capture prefix, before any semantic effect.
        let native12_encoding = connection.quote_original_native_owned12_capture_encoding(
            before,
            after,
            uploads,
            &context,
            crate::connection::NativeOwned12CaptureEncodingPlan {
                sdk: &sdk,
                candidate: &candidate_owner,
                original_observe: request,
                first_observe_response: *next_sequence,
                maximum_requested_bytes: maximum_serialization_requested_bytes,
            },
            before_suffix,
            after_suffix,
        )?;
        if native12_before.before != native12_encoding.before {
            return Err(refused());
        }
        let confirmation_objects = [crate::connection::OriginalContinuationContentExtent {
            maximum_payload_bytes: native12_encoding.after.maximum_encoded_bytes,
            media_type: "application/json",
        }];
        let confirmation_prefix_storage = connection
            .quote_original_continuation_prefix_storage_data(
                *next_sequence,
                request,
                crate::connection::OriginalContinuationPrefixStorageInput {
                    kind: crate::connection::OriginalContinuationPrefixKind::AfterConfirmation,
                    original: &continuation_terminal_shapes.confirmation_original,
                    terminal: &continuation_terminal_shapes.confirmation_terminal,
                    objects: &confirmation_objects,
                    maximum_requested_bytes: maximum_serialization_requested_bytes,
                },
            )?;
        capture_prefix_storage.preflight_transport_credit_data()?;
        confirmation_prefix_storage.preflight_transport_credit_data()?;
        if checked_sum(&[
            *self_transport_credit,
            observe_prefix_storage.exchange.new_transport_credit_bytes,
            capture_prefix_storage.exchange.new_transport_credit_bytes,
            confirmation_prefix_storage
                .exchange
                .new_transport_credit_bytes,
        ])? > crate::reference_packet::continuation_transport::MAXIMUM_CAPTURE_TRANSPORT_BYTES
        {
            return Err(exhausted());
        }
        let retained_requested_bytes =
            crate::retained_metadata::requested_metadata_backing_storage_data(
                &sdk.retained_metadata(),
            )?
            .checked_add(snapshot_backing_bytes)
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    super::super::service::PacketSourceService,
                >())
            })
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Envelope>()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RequestBody>()))
            .ok_or_else(exhausted)?;
        let incoming_typed_header_bytes = std::mem::size_of::<Envelope>()
            .checked_add(std::mem::size_of::<RequestBody>())
            .ok_or_else(exhausted)?;
        complete.authenticate_live_capture_quote(native)?;
        self.ensure_complete_origin()?;
        Ok(NativeEndpointCaptureStateData {
            sdk,
            currency,
            observe_hash,
            control_encoding,
            control_growth,
            // The actual enclosing service includes inline Endpoint/Control
            // fields and pointers. Independently allocated Bootstrap payload
            // and all shared root headers are in the structured service walk.
            service_inline_bytes: std::mem::size_of::<super::super::service::PacketSourceService>(),
            snapshot_backing_bytes,
            incoming_typed_header_bytes,
            returned_observe_query_requested_bytes,
            future_capture_request,
            report_shape,
            retained_requested_bytes,
            compact_serializer_scratch_bytes,
            counter_requested_limit: maximum_serialization_requested_bytes,
            invocation_counter_scratch_bytes,
            stopped_observe_raw_record,
            observe_publication_shapes,
            continuation_terminal_shapes,
            candidate_owner,
            native12_encoding,
            outer_encoding,
            capture_prefix_storage,
            confirmation_prefix_storage,
            observe_prefix_storage,
            observe_preparation,
            completed_observe_record_encoding,
        })
    }
}

fn checked_sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, next| {
        total.checked_add(*next).ok_or_else(exhausted)
    })
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native Observe allocation current endpoint differs")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native Observe allocation actual owner layout")
}

/// Names the real transient quote's inline fields, including numeric subplans.
pub(crate) fn original_capture_report_quote_layout_data() -> usize {
    // The live block retains all three fixed numeric outputs before building
    // its final quote. Their referenced owning banks remain independently priced.
    let preparation_views = std::mem::size_of::<(
        crate::connection::OriginalPacketPrefixProjectionStorageData,
        crate::connection::OriginalNativeObservePreparationStorageData,
        crate::connection::OriginalPacketCompletedRecordEncodingData,
    )>() + std::mem::size_of::<[usize; 6]>()
        + std::mem::size_of::<std::array::IntoIter<usize, 6>>()
        + std::mem::size_of::<Option<usize>>()
        + std::mem::size_of::<usize>()
        + crate::reference_packet::service::ack_emitter::original_native_report_startup_scope_layout_data();
    [
        std::mem::size_of::<NativeEndpointCaptureStateData<'static>>(),
        preparation_views,
        // Startup authenticates this complete counter window before any live
        // per-frame projection; returning DATA grants no publication right.
        crate::connection::OriginalPacketPrefixStorageData::native_original_observe_prepared_lifetime_counter_scratch_data(),
        super::capture_startup::original_startup_capture_endpoint_counter_scratch_data(),
        crate::reference_packet::control::original_startup_capture_counter_scratch_data(),
        crate::reference_packet::service::native_snapshot::native_owned13_snapshot_schema_counter_scratch_data(),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .unwrap_or(usize::MAX)
}

/// Names only the new original-purpose writer views before the selected quote.
pub(crate) fn original_invocation_capture_report_additional_scratch_data() -> usize {
    [
        super::capture_invocation::original_invocation_capture_endpoint_counter_scratch_data(),
        crate::reference_packet::service::OriginalNativeCaptureContext::invocation_additional_counter_scratch_data(),
        crate::connection::original_native_invocation_history_counter_scratch_data(),
        crate::reference_packet::service::native_snapshot::native_owned14_snapshot_schema_counter_scratch_data(),
        std::mem::size_of::<Result<bool, ProviderError>>(),
        std::mem::size_of::<std::cell::Ref<'static, crate::reference_packet::service::ack_emitter::NativeAckBoot>>(),
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .unwrap_or(usize::MAX)
}
