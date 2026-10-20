//! Publishes selected Observe data under the same admitted startup origin.
//!
//! The retained preparation precedes raw/report/reply construction. Control
//! keeps its actual produced reply before transformation; this endpoint keeps
//! partial canonical banks and the SDK/currency owners through refusal/unwind.
//! A published Report remains data: full Capture and cold class gates are
//! independent, and the next original is restricted before typed decoding.

use super::*;
use crate::client::DeadlineStream;
use crate::reference_packet::control::{
    NativeStoppedObserveRecordStorageData, PacketLiveCaptureControlCurrency,
};
use crate::reference_packet::serialization_storage::encode_original_precharged_serialization_into;
use crate::reference_packet::service::capture_allocation::*;
use crate::reference_packet::service::report_startup::{
    PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY, PacketNativeReportStartupAllocationRow,
};
use capture_allocation::NativeCaptureAllocationOwner;

pub(super) struct NativeCaptureAllocationPreparation {
    creator: u32,
    thread: std::thread::ThreadId,
    original: Envelope,
    sdk: NativeCaptureSdkCompletedQuote,
    currency: PacketLiveCaptureControlCurrency,
    report: Option<PacketNativeCaptureAllocationReport>,
    reference: Option<ContentRef>,
    raw: Vec<u8>,
    wrapper: Vec<u8>,
    superseded_receipt: Option<(ContentRef, Vec<u8>)>,
}

pub(super) enum NativeCaptureAllocationAttempt {
    Preparing(NativeCaptureAllocationPreparation),
    Published(NativeCaptureAllocationOwner),
    // Only a callback-free, allocation-free ownership move uses this phase.
    // Every borrowing/serialization entry refuses it.
    Transitioning,
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native original allocation publication owner differs")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native original allocation publication storage")
}

fn count(bytes: usize) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::try_from(bytes).map_err(|_| exhausted())?))
}

impl NativeCaptureAllocationAttempt {
    pub(super) fn published(&self) -> Result<&NativeCaptureAllocationOwner, ProviderError> {
        match self {
            Self::Published(owner) => Ok(owner),
            _ => Err(refused()),
        }
    }

    pub(super) fn published_mut(
        &mut self,
    ) -> Result<&mut NativeCaptureAllocationOwner, ProviderError> {
        match self {
            Self::Published(owner) => Ok(owner),
            _ => Err(refused()),
        }
    }

    fn complete_publication(&mut self) -> Result<(), ProviderError> {
        let Self::Preparing(prepared) = self else {
            return Err(refused());
        };
        if prepared.report.is_none() || prepared.reference.is_none() {
            return Err(refused());
        }
        let previous = std::mem::replace(self, Self::Transitioning);
        match previous {
            Self::Preparing(NativeCaptureAllocationPreparation {
                creator,
                thread,
                original,
                sdk,
                currency,
                report: Some(report),
                reference: Some(reference),
                raw,
                wrapper: _,
                superseded_receipt: _,
            }) => {
                *self = Self::Published(NativeCaptureAllocationOwner {
                    creator,
                    thread,
                    original_observe: original,
                    sdk,
                    currency,
                    report,
                    report_reference: reference,
                    encoded_report: raw,
                    capture: None,
                });
                Ok(())
            }
            previous => {
                *self = previous;
                Err(refused())
            }
        }
    }
}

fn protocol_allocation(
    allocation: &crate::protocol_snapshot::ProtocolSnapshotAllocationFacts,
    current_encoded_extent: usize,
) -> Result<PacketNativeCaptureProtocolAllocation, ProviderError> {
    let literal = allocation.literal.as_ref().ok_or_else(refused)?;
    Ok(PacketNativeCaptureProtocolAllocation {
        encoded_capacity: count(allocation.encoded_capacity)?,
        literal_and_descriptor_bytes: count(literal.allocated_bytes)?,
        current_encoded_bytes: count(current_encoded_extent)?,
    })
}

fn replace_measurement(
    reply: &mut super::super::control::PacketControlReply,
    reference: &ContentRef,
) -> Result<(), ProviderError> {
    // This is the same private stopped producer's closed result, not decoded
    // caller JSON. Keep its raw inventory and every other field unchanged.
    let replacement =
        serde_json::to_value(reference).map_err(crucible_node_format::ContractError::from)?;
    let observations = reply
        .body
        .get_mut("result")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|result| result.get_mut("observations"))
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(refused)?;
    let [batch] = observations.as_mut_slice() else {
        return Err(refused());
    };
    let measurement = batch
        .as_object_mut()
        .and_then(|batch| batch.get_mut("measurement_ref"))
        .ok_or_else(refused)?;
    *measurement = replacement;
    Ok(())
}

impl PacketEndpoint<DeadlineStream> {
    pub(super) fn receive_original_capture_allocation_next(
        &mut self,
        service: &super::super::service::OriginalNativeServiceCaptureContext<'_>,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        self.ensure_complete_origin()?;
        let attempt = self
            .capture_allocation_attempt
            .as_deref()
            .ok_or_else(refused)?;
        let owner = attempt.published()?;
        owner.authenticate_native(&self.native)?;
        let boot = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
        let context = service.with_original_endpoint_roots(boot, &self.policy);
        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(refused());
        };
        if let Some(flight) = self.capture.as_ref() {
            if !flight.complete {
                return Err(refused());
            }
            let terminal = flight
                .prefix
                .as_ref()
                .and_then(|prefix| prefix.records().last())
                .ok_or_else(refused)?;
            connection.receive_original_native_confirmation_after_capture(
                &owner.sdk,
                flight.reservation.request(),
                terminal,
                &self.uploads,
                &context,
            )
        } else {
            connection.receive_original_native_capture_after_quote(
                &owner.sdk,
                &self.uploads,
                &context,
            )
        }
    }

    pub(super) fn publish_original_capture_allocation_observe(
        &mut self,
        original: Envelope,
        observed: &ObserveRequest,
        context: &super::super::service::OriginalNativeServiceCaptureContext<'_>,
        startup: &super::super::service::ack_emitter::OriginalNativeReportStartupAllocation,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        let quote =
            self.quote_original_live_capture_state(&original, observed, context, startup)?;
        let obligations = quote.report_obligations_data()?;
        let actual = PacketNativeReportStartupAllocationRow {
            raw_report_capacity: count(PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY)?,
            retained_growth_bytes: obligations.growth.observe_publication_bytes,
            maximum_simultaneous_transient_bytes: obligations.transients.observe_encoding_bytes,
            declared_counter_scratch_bytes: obligations.transients.quote_scratch_bytes,
        };
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        // This is the actual Source-issued purpose/boot/ACK origin. Numeric
        // growth, current baseline owners or unused startup maxima grant none.
        startup.authenticate_actual_data(connection, &actual)?;
        // The report allowance covers added publication, not baseline native
        // construction. Keep this actual consumer closed until189 provides
        // its separate genuine owner; the transformation below remains typed
        // and exercised independently without synthesizing such authority.
        startup.authenticate_complete_native_baseline(connection)?;

        let metadata = self
            .complete
            .as_ref()
            .and_then(|state| state.metadata_birth_facts)
            .ok_or_else(refused)?;
        let first = self.next_sequence;
        let records_before = self.records.len();
        let capture_quote::NativeEndpointCaptureStateData {
            sdk,
            currency,
            observe_hash,
            retained_requested_bytes,
            report_shape,
            stopped_observe_raw_record,
            observe_publication_shapes,
            observe_prefix_storage,
            completed_observe_record_encoding,
            ..
        } = quote;
        let raw_encoding = stopped_observe_raw_record.into_encoding_data();
        // Moving this actual incoming original ends its previous borrowed quote;
        // no extra Envelope clone is manufactured for ownership convenience.
        self.capture_allocation_attempt = Some(Box::new(
            NativeCaptureAllocationAttempt::Preparing(NativeCaptureAllocationPreparation {
                creator: std::process::id(),
                thread: std::thread::current().id(),
                original,
                sdk,
                currency,
                report: None,
                reference: None,
                raw: Vec::new(),
                wrapper: Vec::new(),
                superseded_receipt: None,
            }),
        ));
        let Self {
            native,
            transport,
            authority,
            next_sequence,
            transport_credit,
            capture_allocation_attempt,
            ..
        } = self;
        let Some(attempt) = capture_allocation_attempt.as_deref_mut() else {
            return Err(refused());
        };
        let NativeCaptureAllocationAttempt::Preparing(prepared) = attempt else {
            return Err(refused());
        };
        prepared
            .raw
            .try_reserve_exact(PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY)
            .map_err(|_| exhausted())?;
        if prepared.raw.capacity() != PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY {
            return Err(exhausted());
        }
        prepared
            .wrapper
            .try_reserve_exact(
                observe_publication_shapes
                    .wrapper_record
                    .maximum_encoded_bytes,
            )
            .map_err(|_| exhausted())?;
        let NativeCaptureAllocationPreparation {
            original,
            sdk,
            currency,
            report,
            reference,
            raw,
            wrapper,
            superseded_receipt,
            ..
        } = prepared;
        let original = &*original;
        let sdk = &*sdk;
        let currency = &*currency;
        let admitted_raw = NativeStoppedObserveRecordStorageData::borrow_original_encoding_data(
            original,
            raw_encoding,
        );
        let mut observe_hash = Some(observe_hash);
        let mut transform =
            |reply: &mut super::super::control::PacketControlReply,
             receipt: &crate::reference_packet::control::ProducedOriginalObserveReceipt|
             -> Result<(), ProviderError> {
                if report.is_some() || reference.is_some() || reply.evidence.len() != 2 {
                    return Err(refused());
                }
                let hash = observe_hash.take().ok_or_else(refused)?;
                let scope =
                    receipt.original_allocation_scope(currency, hash, records_before, first)?;
                let (edges, roots) = sdk.shared_counts();
                *report = Some(PacketNativeCaptureAllocationReport {
                    schema: PACKET_NATIVE_CAPTURE_ALLOCATION_REPORT.into(),
                    scope,
                    before: protocol_allocation(
                        &sdk.sdk_data().before.allocation,
                        sdk.sdk_data().before.current_encoded_extent,
                    )?,
                    after: protocol_allocation(
                        &sdk.sdk_data().after.allocation,
                        sdk.sdk_data().after.current_encoded_extent,
                    )?,
                    metadata_banks: metadata,
                    retained_requested_bytes: count(retained_requested_bytes)?,
                    shared_edges: count(edges)?,
                    unique_roots: count(roots)?,
                    growth: obligations.growth,
                    transients: obligations.transients,
                });
                let retained_report = report.as_ref().ok_or_else(refused)?;
                retained_report.validate_data()?;
                encode_original_precharged_serialization_into(
                    retained_report,
                    &report_shape.encoding,
                    raw,
                )?;
                *reference = Some(crucible_node_format::canonical::content_ref(
                    raw,
                    PACKET_NATIVE_CAPTURE_ALLOCATION_MEDIA,
                )?);
                let report_reference = reference.as_ref().ok_or_else(refused)?;
                let record = receipt.borrowed_allocation_record_view(
                    original,
                    currency,
                    report_reference,
                )?;
                encode_original_precharged_serialization_into(
                    &record,
                    &observe_publication_shapes.wrapper_record,
                    wrapper,
                )?;
                let wrapper_reference =
                    crucible_node_format::canonical::content_ref(wrapper, "application/json")?;
                replace_measurement(reply, &wrapper_reference)?;
                reply
                    .evidence
                    .try_reserve_exact(1)
                    .map_err(|_| exhausted())?;
                *superseded_receipt = Some(std::mem::replace(
                    &mut reply.evidence[1],
                    (wrapper_reference, std::mem::take(wrapper)),
                ));
                reply.evidence.push((report_reference.clone(), raw.clone()));
                prefix::prepare_with_projection_storage_data(
                    transport,
                    next_sequence,
                    transport_credit,
                    authority,
                    original,
                    reply,
                    &observe_prefix_storage,
                )
            };
        native.dispatch_original_capture_allocation_observe(
            original,
            currency,
            &admitted_raw,
            &mut transform,
        )?;
        drop(transform);
        drop(admitted_raw);
        let Some(Transport::Prepared(exchange, acknowledgements)) = self.transport.as_mut() else {
            return Err(refused());
        };
        exchange.publish(&mut |request, reply| acknowledgements.validate(request, reply))?;
        let Some(Transport::Prepared(exchange, _)) = self.transport.take() else {
            return Err(refused());
        };
        let (connection, record) = exchange.into_parts();
        self.records.push(record);
        self.transport = Some(Transport::Connected(connection));
        // All actual prefix/source owners are already back in the retained
        // endpoint before a postpublication correspondence check can refuse.
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        completed_observe_record_encoding.authenticate_completed_original(
            connection,
            self.records.last().ok_or_else(refused)?,
        )?;
        let Some(attempt) = self.capture_allocation_attempt.as_deref_mut() else {
            return Err(refused());
        };
        let NativeCaptureAllocationAttempt::Preparing(prepared) = attempt else {
            return Err(refused());
        };
        prepared
            .currency
            .authenticate_completed_observe(&self.native)?;
        let boot = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
        let actual_context = context.with_original_endpoint_roots(boot, &self.policy);
        prepared
            .sdk
            .authenticate_current(connection, &self.uploads, &actual_context)?;
        startup.authenticate_current(connection)?;
        attempt.complete_publication()?;
        attempt.published()?.authenticate_native(&self.native)?;
        self.held = false;
        Ok(())
    }
}
