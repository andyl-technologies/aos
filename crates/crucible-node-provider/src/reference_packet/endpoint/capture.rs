//! Retains one native Capture and its actual connection through every proof window.
//!
//! The pending snapshot and independent anchor are exported once. Publication
//! completion is retained locally; it does not construct an installed capture or
//! authorize a fresh native owner. The source adapter separately joins original
//! host custody, effect-receipt closure, its opaque ticket and whole-world budget.

use super::super::continuation_transport::PacketCapturePrefix;
use super::super::control::{PacketOriginalCaptureComponent, PacketOriginalCaptureReservation};
use super::*;
use crate::client::ExchangeDeadline;
use crate::handshake::Handshake;
use crate::protocol_snapshot::{OriginalProtocolSnapshot, ProtocolCaptureCut, Sequence};
use crucible_node_contract::{Extensions, U64, canonical};

pub(super) struct CaptureFlight<S: ProviderStream> {
    reservation: PacketOriginalCaptureReservation,
    component: PacketOriginalCaptureComponent,
    protocol_before: OriginalProtocolSnapshot,
    prefix: Option<PacketCapturePrefix<S>>,
    snapshot: (ContentRef, Vec<u8>),
    complete: bool,
}

impl<S: ProviderStream> PacketEndpoint<S> {
    pub(super) fn capture_original(
        &mut self,
        request: &Envelope,
        handshake: &Handshake,
        deadline: &ExchangeDeadline,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        if self.capture.is_some() {
            return Err(ProviderError::Conflict("native5 Capture already attempted"));
        }
        let state = self.complete.as_mut().ok_or(ProviderError::Correlation(
            "native5 Capture requires original complete service",
        ))?;
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
        let before = state.before.as_mut().ok_or(ProviderError::Conflict(
            "native5 original precharged snapshot absent",
        ))?;
        connection.capture_native_protocol_state_with_blobs(
            before,
            ProtocolCaptureCut::NativeIncomingCapture,
            deadline,
            &self.uploads,
        )?;
        let protocol_before = connection.take_native_protocol_snapshot(
            &mut state.before,
            ProtocolCaptureCut::NativeIncomingCapture,
        )?;
        let protocol = canonical::parse_json(protocol_before.bytes(), maximum)?;
        let metadata = {
            let negotiation = handshake.original_negotiation_view(&self.authority)?;
            let pins = self
                .pins
                .iter()
                .map(|pin| pin.original_protocol_view(&self.uploads))
                .collect::<Result<Vec<_>, _>>()?;
            let view = (
                "source-owned.packet-native-endpoint-state/5",
                state.storage.clone(),
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
                .and_then(|total| total.checked_add(protocol_before.bytes().len()))
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
            preflight_transport_credit(whole_bound, &self.authority, self.transport_credit)?;
            serde_json::to_value(&view).map_err(crucible_node_contract::ContractError::from)?
        };
        // The registration mutex held by negotiation has been dropped. No
        // protocol registration/publication occurs while that view is retained.
        let reservation = self.native.reserve_original_capture(request)?;
        let component = self
            .native
            .capture_reserved_control(&reservation, control_maximum)?;
        let control = canonical::parse_json(component.snapshot().bytes(), control_maximum)?;
        let body = serde_json::json!({
            "schema": "source-owned.packet-native-continuation/5",
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
        self.capture = Some(CaptureFlight {
            reservation,
            component,
            protocol_before,
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
        prefix.prepare(
            response,
            flight.snapshot.clone(),
            (anchor.clone(), anchor_bytes.to_vec()),
        )?;
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
        flight.complete = true;
        self.held = false;
        Ok(())
    }

    /// Borrows bytes from a successfully published same-original native Capture.
    ///
    /// This is transport/component evidence only. It cannot replace the source
    /// adapter's complete host journal, effect closure, ticket or installed seal.
    ///
    /// # Errors
    /// Refuses foreign creator/thread or absent/incomplete original publication.
    pub fn original_capture_snapshot(&self) -> Result<(&ContentRef, &[u8]), ProviderError> {
        self.ensure_complete_origin()?;
        let flight = self
            .capture
            .as_ref()
            .filter(|flight| flight.complete)
            .ok_or(ProviderError::Conflict(
                "native5 original Capture publication incomplete",
            ))?;
        if flight.protocol_before.cut() != ProtocolCaptureCut::NativeIncomingCapture {
            return Err(ProviderError::Correlation(
                "native5 original Capture protocol cut changed",
            ));
        }
        Ok((&flight.snapshot.0, &flight.snapshot.1))
    }
}

fn bounded(value: u64, reason: &'static str) -> Result<usize, ProviderError> {
    usize::try_from(value).map_err(|_| ProviderError::ResourceExhausted(reason))
}

fn preflight_transport_credit(
    snapshot: usize,
    authority: &ConnectionAuthority,
    retained: usize,
) -> Result<(), ProviderError> {
    let chunk = bounded(
        authority.limits().blob_chunk_bytes.get(),
        "native5 prefix chunk",
    )?;
    let frame = bounded(authority.limits().frame_bytes.get(), "native5 prefix frame")?;
    if chunk == 0 || frame == 0 {
        return Err(ProviderError::ResourceExhausted(
            "native5 prefix positive bounds",
        ));
    }
    let count = snapshot
        .div_ceil(chunk)
        .checked_add(8192usize.div_ceil(chunk))
        .and_then(|count| count.checked_add(5))
        .filter(|count| *count <= 4096)
        .ok_or(ProviderError::ResourceExhausted(
            "native5 prefix whole frame count",
        ))?;
    count
        .checked_mul(frame)
        .and_then(|bytes| bytes.checked_mul(5))
        .and_then(|bytes| bytes.checked_add(retained))
        .filter(|bytes| {
            *bytes <= super::super::continuation_transport::MAXIMUM_CAPTURE_TRANSPORT_BYTES
        })
        .ok_or(ProviderError::ResourceExhausted(
            "native5 prefix before registration credit",
        ))?;
    Ok(())
}
