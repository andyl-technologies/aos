//! Runs selected startup Capture with its retained original Report and owners.
//!
//! Each construction phase is counted against the same immutable Report before
//! new copies exist. Original reservations, component banks and prepared prefix
//! move into endpoint slots before publication. Refusal/unwind leaves held=true
//! and retains the actual partial owners; completion needs the actual after14.

use super::capture::{CaptureFlight, PendingCapture, bounded};
use super::capture_allocation::OriginalNativeCaptureAllocationOwned12;
use super::capture_outer_projection::BorrowedOriginalPins;
use super::*;
use crate::client::{DeadlineStream, ExchangeDeadline};
use crate::protocol_snapshot::{ProtocolCaptureCut, Sequence};
use crate::reference_packet::continuation_transport::PacketCapturePrefix;
use crate::reference_packet::serialization_storage::{
    NativeSerializationStorageData, actual_serialization_storage_data,
    encode_original_precharged_serialization,
};
use crucible_node_format::{Extensions, U64, canonical};
use serde::Serialize;
use std::mem::size_of;

fn refused() -> ProviderError {
    ProviderError::Correlation("native startup Capture original publication differs")
}
fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native startup Capture complete phase")
}
fn limit(value: U64) -> Result<usize, ProviderError> {
    usize::try_from(value.get()).map_err(|_| exhausted())
}
fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |sum, next| {
        sum.checked_add(*next).ok_or_else(exhausted)
    })
}

#[derive(Serialize)]
struct StartupOuterView<'a, P, E> {
    schema: &'static str,
    capture_request: &'a Envelope,
    capture: &'a CaptureArguments,
    control_reference: &'a ContentRef,
    control: &'a serde_json::Value,
    protocol: &'a P,
    endpoint: &'a E,
}

pub(super) fn original_startup_capture_endpoint_counter_scratch_data() -> usize {
    [
        size_of::<StartupOuterView<'static, (), ()>>(),
        size_of::<[NativeSerializationStorageData; 8]>(),
        size_of::<crate::connection::OriginalContinuationPrefixStorageData>(),
        size_of::<crate::connection::NativeOwned14AfterProtocolCapacityFacts>(),
        crate::reference_packet::control::original_startup_capture_counter_scratch_data(),
        crate::reference_packet::service::OriginalNativeCaptureContext::startup_protocol_counter_scratch_data(),
        crate::reference_packet::service::native_snapshot::native_owned13_snapshot_schema_counter_scratch_data(),
        crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::requested_serialization_scratch_bytes(),
    ].into_iter().try_fold(0usize, usize::checked_add).unwrap_or(usize::MAX)
}

impl PacketEndpoint<DeadlineStream> {
    pub(super) fn capture_original_startup14(
        &mut self,
        request: &Envelope,
        service: &super::super::service::OriginalNativeServiceCaptureContext<'_>,
        deadline: &ExchangeDeadline,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        if self.restore_protocol_attempted
            || self.restore_prepare_admission.is_some()
            || self.capture.is_some()
            || self.pending_capture.is_some()
        {
            return Err(refused());
        }
        self.held = true;
        let owner = self
            .capture_allocation_attempt
            .as_deref()
            .ok_or_else(refused)?
            .published()?;
        let scratch = original_startup_capture_endpoint_counter_scratch_data();
        if scratch > limit(owner.report.transients.quote_scratch_bytes)? {
            return Err(exhausted());
        }
        owner.authenticate_native(&self.native)?;
        if owner.capture.is_some() {
            return Err(refused());
        }
        self.policy
            .authenticate_startup_capture_snapshot_definition()?;
        deadline.remaining()?;
        let boot = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
        let context = service.with_original_endpoint_roots(boot, &self.policy);
        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(refused());
        };
        connection.authenticate_startup_capture_original_data(
            request,
            &owner.sdk,
            &self.uploads,
            &context,
        )?;
        let report = &owner.report;
        let registration = self.native.quote_startup_capture_registration(
            request,
            &owner.original_observe,
            &owner.currency,
            report,
            limit(self.authority.limits().frame_bytes)?,
        )?;
        let terminal_shapes = self.native.quote_startup_capture_terminal_shapes(
            &owner.original_observe,
            &owner.currency,
            &registration.projected,
            limit(report.transients.native_before_encoding_bytes)?,
        )?;
        let state = self.complete.as_mut().ok_or_else(refused)?;
        if !matches!(
            state.profile,
            Some(super::super::service::PacketNative5CaptureProfile::OwnedProtocol11 { .. })
        ) || state.metadata_limits.is_none()
            || state.metadata_birth_facts.is_none()
        {
            return Err(refused());
        }
        let maximum = bounded(
            state.storage.snapshot_bytes.get(),
            "startup snapshot encoded ceiling",
        )?;
        let control_maximum = bounded(
            state.storage.control_snapshot_bytes.get(),
            "startup Control6 encoded ceiling",
        )?;
        let phase = limit(report.transients.native_before_encoding_bytes)?;
        // The raw full reference and all view/counter headers are fixed owners,
        // independently charged before their first allocation/borrow.
        let reference_fields = "blake3-256".len()
            + "cnp.blob.v1".len()
            + 64
            + "application/json".len()
            + size_of::<ContentRef>();
        if sum(&[reference_fields, scratch])? > phase {
            return Err(exhausted());
        }

        let owner = self
            .capture_allocation_attempt
            .as_deref_mut()
            .ok_or_else(refused)?
            .published_mut()?;
        // This exact raw original remains in the private fourth owner even if a
        // later counter, reservation or component refuses. Its independent clone
        // was included in registration_retained_bytes before this assignment.
        owner.capture = Some(request.clone());
        owner.authenticate_native(&self.native)?;
        let before = state.before.as_ref().ok_or_else(refused)?;
        state.authenticate_original_metadata_cut(&self.native, before, true)?;
        let allocation =
            OriginalNativeCaptureAllocationOwned12::borrow_original(owner, &self.native)?;
        connection.capture_original_native_owned14(
            state.before.as_mut().ok_or_else(refused)?,
            &self.uploads,
            ProtocolCaptureCut::NativeIncomingCapture,
            &context,
            &allocation,
        )?;

        self.pending_capture = Some(PendingCapture {
            protocol_before: None,
            reservation: None,
            component: None,
        });
        connection.take_native_protocol_snapshot_into(
            &mut state.before,
            &mut self
                .pending_capture
                .as_mut()
                .ok_or_else(refused)?
                .protocol_before,
            ProtocolCaptureCut::NativeIncomingCapture,
        )?;
        let reservation = self.native.reserve_startup_capture(
            request,
            &owner.currency,
            &owner.report,
            &registration,
        )?;
        self.pending_capture
            .as_mut()
            .ok_or_else(refused)?
            .reservation = Some(reservation);
        let reservation = self
            .pending_capture
            .as_ref()
            .and_then(|pending| pending.reservation.as_ref())
            .ok_or_else(refused)?;
        let (component, control_encoding) = self.native.capture_reserved_startup_control(
            reservation,
            &owner.currency,
            &owner.report,
            control_maximum,
        )?;
        self.pending_capture.as_mut().ok_or_else(refused)?.component = Some(component);
        let pending = self.pending_capture.as_ref().ok_or_else(refused)?;
        let before = pending.protocol_before.as_ref().ok_or_else(refused)?;
        let reservation = pending.reservation.as_ref().ok_or_else(refused)?;
        let component = pending.component.as_ref().ok_or_else(refused)?;
        let protocol_reference = canonical::content_ref(before.bytes(), "application/json")?;
        let protocol_view = (
            "source-private.native-before-protocol/13",
            &protocol_reference,
            before.original_allocation_facts()?.encoded_capacity,
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(before.bytes()),
        );
        let protocol_encoding =
            actual_serialization_storage_data(&protocol_view, Default::default(), phase)?;
        let endpoint_view = (
            "source-owned.packet-native-endpoint-state/13",
            &state.storage,
            &state.profile,
            state.metadata_limits,
            state.metadata_birth_facts,
            state.hello.protocol_view(),
            "same-original-native-protocol-service-context/14",
            Sequence(|| {
                self.records
                    .iter()
                    .map(ExchangeRecord::original_protocol_view)
            }),
            self.records.capacity(),
            BorrowedOriginalPins {
                pins: &self.pins,
                uploads: &self.uploads,
            },
            self.pins.capacity(),
            self.next_sequence,
            self.transport_credit,
            self.held,
            (
                "source-private.native-capture-allocation-owner-reference/13",
                &owner.report_reference,
            ),
        );
        let endpoint_encoding =
            actual_serialization_storage_data(&endpoint_view, Default::default(), phase)?;
        if sum(&[
            protocol_encoding.requested_total()?,
            endpoint_encoding.requested_total()?,
            control_encoding.projected_parser_requested_bytes,
        ])? > phase
        {
            return Err(exhausted());
        }
        // These are separate independent child DOMs. Their typed counters were
        // admitted before parsing/encoding; neither input bytes nor wire credit
        // substitutes for the child allocation layouts.
        let control = canonical::parse_json(component.snapshot().bytes(), control_maximum)?;
        let view = StartupOuterView {
            schema: "source-owned.packet-native-continuation/13",
            capture_request: request,
            capture: reservation.arguments(),
            control_reference: component.snapshot().reference(),
            control: &control,
            protocol: &protocol_view,
            endpoint: &endpoint_view,
        };
        let snapshot_encoding =
            actual_serialization_storage_data(&view, Default::default(), phase)?;
        let simultaneous_before = sum(&[
            protocol_encoding.requested_total()?,
            endpoint_encoding.requested_total()?,
            control_encoding.projected_parser_requested_bytes,
            snapshot_encoding.requested_total()?,
            terminal_shapes.capture_anchor.requested_total()?,
            registration.inventory.requested_total()?,
        ])?;
        if simultaneous_before > phase || snapshot_encoding.maximum_encoded_bytes > maximum {
            return Err(exhausted());
        }
        let objects = [
            crate::connection::OriginalContinuationContentExtent {
                maximum_payload_bytes: snapshot_encoding.maximum_encoded_bytes,
                media_type: "application/json",
            },
            crate::connection::OriginalContinuationContentExtent {
                maximum_payload_bytes: component.anchor().1.len(),
                media_type: "application/json",
            },
            crate::connection::OriginalContinuationContentExtent {
                maximum_payload_bytes: component.snapshot().bytes().len(),
                media_type: "application/json",
            },
        ];
        let storage = connection.quote_original_current_continuation_prefix_storage_data(
            request,
            crate::connection::OriginalContinuationPrefixStorageInput {
                kind: crate::connection::OriginalContinuationPrefixKind::Capture,
                terminal: &terminal_shapes.capture_terminal,
                original: &registration.projected.envelope,
                objects: &objects,
                maximum_requested_bytes: phase,
            },
        )?;
        if sum(&[simultaneous_before, storage.requested_bytes()?])? > phase {
            return Err(exhausted());
        }
        let retained_base = sum(&[
            registration.registration_retained_bytes,
            snapshot_encoding.canonical_output_requested_bytes,
            component.retained_anchor_capacity_data(),
            component.snapshot().retained_encoded_capacity_data(),
            storage.requested_bytes()?,
        ])?;
        if retained_base > limit(owner.report.growth.capture_publication_bytes)? {
            return Err(exhausted());
        }
        let bytes = encode_original_precharged_serialization(&view, &snapshot_encoding)?;
        let reference = canonical::content_ref(&bytes, "application/json")?;
        // No service/registrar view is retained across registration or transport.

        let pending = self.pending_capture.take().ok_or_else(refused)?;
        let PendingCapture {
            protocol_before: Some(protocol_before),
            reservation: Some(reservation),
            component: Some(component),
        } = pending
        else {
            self.pending_capture = Some(pending);
            return Err(refused());
        };
        self.capture = Some(CaptureFlight {
            reservation,
            component,
            protocol_before,
            after_capacity: None,
            owned11_after_capacity: None,
            startup14_after_capacity: None,
            protocol_after: None,
            prefix: None,
            snapshot: (reference, bytes),
            complete: false,
        });
        let flight = self.capture.as_mut().ok_or_else(refused)?;
        let reply = self.native.original_startup_capture_reply(
            &flight.reservation,
            &flight.component,
            &flight.snapshot.0,
            &owner.currency,
            &owner.report,
            retained_base,
        )?;
        if sum(&[retained_base, reply.cache_retained_bytes])?
            > limit(owner.report.growth.capture_publication_bytes)?
        {
            return Err(exhausted());
        }
        storage.authenticate_response_original_clone_data(connection, request)?;
        let mut response = request.clone();
        response.message = MessageKind::Response;
        response.extensions = Extensions::new();
        response.sequence = U64::new(self.next_sequence);
        response.body = reply.body().clone();
        let (anchor, anchor_bytes) = flight.component.anchor();
        storage.authenticate_actual_inputs(
            connection,
            &response,
            &[
                (&flight.snapshot.0, flight.snapshot.1.as_slice()),
                (anchor, anchor_bytes),
                (
                    flight.component.snapshot().reference(),
                    flight.component.snapshot().bytes(),
                ),
            ],
        )?;
        let Some(Transport::Connected(connection)) = self.transport.take() else {
            return Err(refused());
        };
        flight.prefix = Some(PacketCapturePrefix::new(connection));
        let prefix = flight.prefix.as_mut().ok_or_else(refused)?;
        prefix.prepare_complete_with_storage_data(
            response,
            flight.snapshot.clone(),
            (anchor.clone(), anchor_bytes.to_vec()),
            (
                flight.component.snapshot().reference().clone(),
                flight.component.snapshot().bytes().to_vec(),
            ),
            &storage,
        )?;
        let after = state.after.as_ref().ok_or_else(refused)?;
        state.authenticate_original_metadata_cut(&self.native, after, false)?;
        let allocation =
            OriginalNativeCaptureAllocationOwned12::borrow_original(owner, &self.native)?;
        flight.startup14_after_capacity = Some(prefix.preflight_owned14_after_protocol_capacity(
            state.after.as_mut().ok_or_else(refused)?,
            &self.uploads,
            &context,
            &allocation,
            &storage,
            phase,
        )?);

        let retained_transport_credit = self
            .transport_credit
            .checked_add(prefix.charged_bytes())
            .filter(|bytes| {
                *bytes <= super::super::continuation_transport::MAXIMUM_CAPTURE_TRANSPORT_BYTES
            })
            .ok_or_else(exhausted)?;
        self.native.settle_startup_capture(
            &flight.reservation,
            &flight.component,
            &flight.snapshot.0,
            &owner.currency,
            &owner.report,
            reply,
        )?;
        prefix.publish_with_storage_data(&storage)?;
        self.next_sequence = prefix.next_sequence();
        self.transport_credit = retained_transport_credit;
        self.transport = Some(Transport::Connected(prefix.take_completed_connection()?));
        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(refused());
        };
        let after = state.after.as_ref().ok_or_else(refused)?;
        state.authenticate_original_metadata_cut(&self.native, after, false)?;
        let allocation =
            OriginalNativeCaptureAllocationOwned12::borrow_original(owner, &self.native)?;
        connection.capture_original_native_owned14(
            state.after.as_mut().ok_or_else(refused)?,
            &self.uploads,
            ProtocolCaptureCut::HostSettled,
            &context,
            &allocation,
        )?;

        connection.take_native_protocol_snapshot_into(
            &mut state.after,
            &mut flight.protocol_after,
            ProtocolCaptureCut::HostSettled,
        )?;
        let after = flight.protocol_after.as_ref().ok_or_else(refused)?;
        let admitted = flight
            .startup14_after_capacity
            .as_ref()
            .ok_or_else(refused)?;
        if after.bytes().len() > admitted.maximum_after_encoded_bytes
            || admitted.maximum_after_encoded_bytes > admitted.reserved_after_encoded_bytes
            || after.original_allocation_facts()?.maximum_encoded_bytes
                != admitted.reserved_after_encoded_bytes
        {
            return Err(refused());
        }
        deadline.remaining()?;
        flight.complete = true;
        self.held = false;
        Ok(())
    }
}
