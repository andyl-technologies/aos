//! Drives the closed native owned-eleven Capture on genuine service custody.
//!
//! Both original reservations are reconciled with Control before encoding. The
//! SDK records actual metadata in those same banks; the after bound is admitted
//! before any proof or terminal publication. An issued terminal still leaves the
//! flight unresolved until the actual settled after owner has been retained.

use super::super::continuation_transport::PacketCapturePrefix;
use super::capture::{CaptureFlight, PendingCapture, bounded, preflight_transport_credit};
use super::*;
use crate::client::{DeadlineStream, ExchangeDeadline};
use crate::protocol_snapshot::{ProtocolCaptureCut, Sequence};
use crucible_node_format::{Extensions, U64, canonical};

impl PacketEndpoint<DeadlineStream> {
    pub(super) fn capture_original_owned11(
        &mut self,
        request: &Envelope,
        service: &super::super::service::OriginalNativeServiceCaptureContext<'_>,
        deadline: &ExchangeDeadline,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        if self.capture_allocation_attempt.is_some() {
            let invocation = self
                .canonical_ack_boot
                .as_ref()
                .ok_or(ProviderError::Correlation("Capture original boot absent"))?
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("Capture original boot borrowed"))?
                .requires_invocation_codec_data()?;
            return if invocation {
                self.capture_original_invocation15(request, service, deadline)
            } else {
                self.capture_original_startup14(request, service, deadline)
            };
        }

        if self.restore_protocol_attempted
            || self.restore_prepare_admission.is_some()
            || self.fresh_restore_attempt.is_some()
        {
            return Err(ProviderError::Correlation(
                "native capture restore attempt roots unresolved",
            ));
        }
        self.policy.authenticate_owned11_snapshot_definition()?;
        deadline.remaining()?;
        let boot = self
            .canonical_ack_boot
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native whole11 actual endpoint boot absent",
            ))?;
        let roots = service.with_original_endpoint_roots(boot, &self.policy);
        if self.capture.is_some() || self.pending_capture.is_some() {
            return Err(ProviderError::Conflict("native5 Capture already attempted"));
        }
        let state = self.complete.as_mut().ok_or(ProviderError::Correlation(
            "native5 Capture requires original complete service",
        ))?;
        if !matches!(
            state.profile,
            Some(super::super::service::PacketNative5CaptureProfile::OwnedProtocol11 { .. })
        ) || state.metadata_limits.is_none()
            || state.metadata_birth_facts.is_none()
        {
            return Err(ProviderError::Correlation(
                "native whole11 actual born banks absent",
            ));
        }
        let maximum = bounded(
            state.storage.snapshot_bytes.get(),
            "native5 whole snapshot bound",
        )?;
        let control_maximum = bounded(
            state.storage.control_snapshot_bytes.get(),
            "native5 control snapshot bound",
        )?;
        // This validates the SAME request and current model without inserting it.
        // The pending registration's complete control extent is conservatively
        // charged before native lifetime IDs or any output cursor changes.
        let control_bound = self
            .native
            .preflight_original_capture(request, control_maximum)?;
        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(ProviderError::Conflict(
                "native5 original connection unavailable",
            ));
        };
        let before = state.before.as_ref().ok_or(ProviderError::Conflict(
            "native5 original precharged snapshot absent",
        ))?;
        state.authenticate_original_metadata_cut(&self.native, before, true)?;
        let before = state.before.as_mut().ok_or(ProviderError::Conflict(
            "native5 original precharged snapshot absent",
        ))?;
        connection.capture_original_native_owned11(
            before,
            &self.uploads,
            ProtocolCaptureCut::NativeIncomingCapture,
            &roots,
        )?;
        // The endpoint owns the result slot before the SDK transfers the same
        // original reservation. Refusal retains both slots without renewal.
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
                .ok_or(ProviderError::Conflict(
                    "native5 pending Capture result slot absent",
                ))?
                .protocol_before,
            ProtocolCaptureCut::NativeIncomingCapture,
        )?;
        let pending = self
            .pending_capture
            .as_ref()
            .ok_or(ProviderError::Conflict(
                "native5 pending Capture owner absent",
            ))?;
        let protocol_before = pending
            .protocol_before
            .as_ref()
            .ok_or(ProviderError::Conflict(
                "native5 original Capture protocol owner absent",
            ))?;
        // Preserve original SDK field order and alias-view bytes. Re-parsing
        // this body as a Value would canonicalize a different byte identity.
        let protocol_reference =
            canonical::content_ref(protocol_before.bytes(), "application/json")?;
        let protocol_capacity = protocol_before
            .original_allocation_facts()?
            .encoded_capacity;
        let protocol_view = (
            "source-private.native-before-protocol/11",
            &protocol_reference,
            protocol_capacity,
            crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(
                protocol_before.bytes(),
            ),
        );
        let protocol_extent = serialized_credit(&protocol_view, maximum)?;
        // The compact strings and Value are separate bounded snapshot scratch;
        // their simultaneous backing must be covered by the source geometry.
        let protocol = serde_json::to_value(&protocol_view)
            .map_err(crucible_node_format::ContractError::from)?;
        let metadata = {
            // The same before protocol leaf contains the full selected service
            // registrar. This edge names that original retained root, rather
            // than allocating or reconstructing a second registrar owner.
            let negotiation = "same-original-native-protocol-service-context/11";
            let pins = self
                .pins
                .iter()
                .map(|pin| pin.original_protocol_view(&self.uploads))
                .collect::<Result<Vec<_>, _>>()?;
            let view = (
                "source-owned.packet-native-endpoint-state/11",
                state.storage.clone(),
                &state.profile,
                state.metadata_limits,
                state.metadata_birth_facts,
                state.hello.protocol_view(),
                negotiation,
                Sequence(|| {
                    self.records
                        .iter()
                        .map(ExchangeRecord::original_protocol_view)
                }),
                self.records.capacity(),
                &pins,
                self.pins.capacity(),
                self.next_sequence,
                self.transport_credit,
                self.held,
            );
            let metadata_extent = serialized_credit(&view, maximum)?;
            let request_extent = serialized_credit(request, 65_536)?;
            let whole_bound = metadata_extent
                .checked_add(control_bound)
                .and_then(|total| total.checked_add(protocol_extent))
                .and_then(|total| {
                    request_extent
                        .checked_mul(2)
                        .and_then(|request| total.checked_add(request))
                })
                .and_then(|total| total.checked_add(8192))
                .filter(|total| *total <= maximum)
                .ok_or(ProviderError::ResourceExhausted(
                    "native5 complete pending snapshot credit",
                ))?;
            preflight_transport_credit(
                whole_bound,
                control_bound,
                &self.authority,
                self.transport_credit,
            )?;
            serde_json::to_value(&view).map_err(crucible_node_format::ContractError::from)?
        };
        // The registration mutex held by negotiation has been dropped. No
        // protocol registration/publication occurs while that view is retained.
        let reservation = self.native.reserve_original_capture(request)?;
        self.pending_capture
            .as_mut()
            .ok_or(ProviderError::Conflict(
                "native5 pending Capture owner absent",
            ))?
            .reservation = Some(reservation);
        let pending = self
            .pending_capture
            .as_ref()
            .ok_or(ProviderError::Conflict(
                "native5 pending Capture owner absent",
            ))?;
        let reservation = pending.reservation.as_ref().ok_or(ProviderError::Conflict(
            "native5 retained Capture reservation absent",
        ))?;
        let component = self
            .native
            .capture_reserved_control(reservation, control_maximum)?;
        self.pending_capture
            .as_mut()
            .ok_or(ProviderError::Conflict(
                "native5 pending Capture owner absent",
            ))?
            .component = Some(component);
        let pending = self
            .pending_capture
            .as_ref()
            .ok_or(ProviderError::Conflict(
                "native5 pending Capture owner absent",
            ))?;
        let reservation = pending.reservation.as_ref().ok_or(ProviderError::Conflict(
            "native5 retained Capture reservation absent",
        ))?;
        let component = pending.component.as_ref().ok_or(ProviderError::Conflict(
            "native5 retained Capture component absent",
        ))?;
        let control = canonical::parse_json(component.snapshot().bytes(), control_maximum)?;
        let body = serde_json::json!({
            "schema": "source-owned.packet-native-continuation/11",
            "capture_request": request,
            "capture": reservation.arguments(),
            "control_reference": component.snapshot().reference(),
            "control": control,
            "protocol": protocol,
            "endpoint": metadata,
        });
        serialized_credit(&body, maximum)?;
        let bytes = canonical::canonical_json(&body)?;
        if bytes.len() > maximum {
            return Err(ProviderError::ResourceExhausted(
                "native5 canonical whole snapshot credit",
            ));
        }
        let reference = canonical::content_ref(&bytes, "application/json")?;
        let pending = self.pending_capture.take().ok_or(ProviderError::Conflict(
            "native5 pending Capture owner absent",
        ))?;
        let PendingCapture {
            protocol_before: Some(protocol_before),
            reservation: Some(reservation),
            component: Some(component),
        } = pending
        else {
            self.pending_capture = Some(pending);
            return Err(ProviderError::Conflict(
                "native5 incomplete original Capture owner",
            ));
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
        let flight = self.capture.as_mut().ok_or(ProviderError::Conflict(
            "native5 original capture disappeared",
        ))?;
        let reply = self.native.original_capture_reply(
            &flight.reservation,
            &flight.component,
            &flight.snapshot.0,
        )?;
        let mut response = request.clone();
        response.message = MessageKind::Response;
        response.extensions = Extensions::new();
        response.sequence = U64::new(self.next_sequence);
        response.body = reply.body.clone();
        let Some(Transport::Connected(connection)) = self.transport.take() else {
            return Err(ProviderError::Conflict(
                "native5 capture connection disappeared",
            ));
        };
        // Store the entire owner before any verifier/supervisor callback can
        // unwind. An incomplete window and every unsent suffix remain retained.
        flight.prefix = Some(PacketCapturePrefix::new(connection));
        let prefix = flight.prefix.as_mut().ok_or(ProviderError::Conflict(
            "native5 original capture prefix absent",
        ))?;
        let (anchor, anchor_bytes) = flight.component.anchor();
        prefix.prepare_complete(
            response,
            flight.snapshot.clone(),
            (anchor.clone(), anchor_bytes.to_vec()),
            (
                flight.component.snapshot().reference().clone(),
                flight.component.snapshot().bytes().to_vec(),
            ),
        )?;
        let after = state.after.as_ref().ok_or(ProviderError::Conflict(
            "native5 original after snapshot bank absent",
        ))?;
        state.authenticate_original_metadata_cut(&self.native, after, false)?;
        let after = state.after.as_mut().ok_or(ProviderError::Conflict(
            "native5 original after snapshot bank absent",
        ))?;
        flight.owned11_after_capacity =
            Some(prefix.preflight_owned11_after_protocol_capacity(after, &self.uploads, &roots)?);
        let retained_transport_credit = self
            .transport_credit
            .checked_add(prefix.charged_bytes())
            .filter(|bytes| {
                *bytes <= super::super::continuation_transport::MAXIMUM_CAPTURE_TRANSPORT_BYTES
            })
            .ok_or(ProviderError::ResourceExhausted(
                "native5 retained capture transport credit",
            ))?;
        self.native.settle_original_capture(
            &flight.reservation,
            &flight.component,
            &flight.snapshot.0,
            &reply,
        )?;
        prefix.publish()?;
        self.next_sequence = prefix.next_sequence();
        self.transport_credit = retained_transport_credit;
        self.transport = Some(Transport::Connected(prefix.take_completed_connection()?));
        // Publication can already be visible to the host. A later refusal keeps
        // this flight unresolved; Completed alone never proves after issuance.
        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(ProviderError::Conflict(
                "native5 after original connection absent",
            ));
        };
        let after = state.after.as_ref().ok_or(ProviderError::Conflict(
            "native5 original after snapshot bank absent",
        ))?;
        state.authenticate_original_metadata_cut(&self.native, after, false)?;
        let after = state.after.as_mut().ok_or(ProviderError::Conflict(
            "native5 original after snapshot bank absent",
        ))?;
        connection.capture_original_native_owned11(
            after,
            &self.uploads,
            ProtocolCaptureCut::HostSettled,
            &roots,
        )?;
        connection.take_native_protocol_snapshot_into(
            &mut state.after,
            &mut flight.protocol_after,
            ProtocolCaptureCut::HostSettled,
        )?;
        let after = flight
            .protocol_after
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native owned11 after owner absent",
            ))?;
        let capacity = flight
            .owned11_after_capacity
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native owned11 after admission absent",
            ))?;
        if after.bytes().len() > capacity.maximum_after_encoded_bytes
            || capacity.maximum_after_encoded_bytes > capacity.reserved_after_encoded_bytes
            || after.original_allocation_facts()?.maximum_encoded_bytes
                != capacity.reserved_after_encoded_bytes
        {
            return Err(ProviderError::Correlation(
                "native owned11 actual after exceeds admitted bank",
            ));
        }
        deadline.remaining()?;
        flight.complete = true;
        self.held = false;
        Ok(())
    }
}
