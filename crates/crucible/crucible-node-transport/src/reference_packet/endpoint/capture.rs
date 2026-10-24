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
use crucible_node_format::{Extensions, U64, canonical};

pub(super) struct PendingCapture {
    pub(super) protocol_before: Option<OriginalProtocolSnapshot>,
    pub(super) reservation: Option<PacketOriginalCaptureReservation>,
    pub(super) component: Option<PacketOriginalCaptureComponent>,
}

pub(super) struct CaptureFlight<S: ProviderStream> {
    pub(super) reservation: PacketOriginalCaptureReservation,
    pub(super) component: PacketOriginalCaptureComponent,
    pub(super) protocol_before: OriginalProtocolSnapshot,
    pub(super) after_capacity: Option<crate::protocol_snapshot::Native5AfterProtocolCapacityFacts>,
    pub(super) owned11_after_capacity:
        Option<crate::connection::NativeOwned11AfterProtocolCapacityFacts>,
    pub(super) startup14_after_capacity:
        Option<crate::connection::NativeOwned14AfterProtocolCapacityFacts>,
    pub(super) protocol_after: Option<OriginalProtocolSnapshot>,
    pub(super) prefix: Option<PacketCapturePrefix<S>>,
    pub(super) snapshot: (ContentRef, Vec<u8>),
    pub(super) complete: bool,
}

impl<S: ProviderStream> PacketEndpoint<S> {
    pub(super) fn capture_original(
        &mut self,
        request: &Envelope,
        handshake: &Handshake,
        deadline: &ExchangeDeadline,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        if self.capture.is_some() || self.pending_capture.is_some() {
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
        let before = state.before.as_ref().ok_or(ProviderError::Conflict(
            "native5 original precharged snapshot absent",
        ))?;
        state.authenticate_original_metadata_cut(&self.native, before, true)?;
        let before = state.before.as_mut().ok_or(ProviderError::Conflict(
            "native5 original precharged snapshot absent",
        ))?;
        connection.capture_native_protocol_state_with_blobs(
            before,
            ProtocolCaptureCut::NativeIncomingCapture,
            deadline,
            &self.uploads,
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
        let protocol_extent = protocol_before.bytes().len();
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
                &state.profile,
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
        flight.after_capacity =
            Some(prefix.preflight_after_protocol_capacity(after, &self.uploads)?);
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
        connection.capture_native_protocol_state_with_blobs(
            after,
            ProtocolCaptureCut::HostSettled,
            deadline,
            &self.uploads,
        )?;
        connection.take_native_protocol_snapshot_into(
            &mut state.after,
            &mut flight.protocol_after,
            ProtocolCaptureCut::HostSettled,
        )?;
        flight.complete = true;
        self.held = false;
        Ok(())
    }

    /// Borrows the actual issued after-suffix snapshot and its prior capacity bound.
    ///
    /// This is an original local owner loan, not a source settlement or archive
    /// ticket. A remote Completed result cannot substitute for this issuance.
    ///
    /// # Errors
    /// Refuses foreign origin, an unresolved flight, absent after issuance or a
    /// wrong actual cut. The retained owner is never reconstructed from counts.
    pub fn original_capture_after_protocol(
        &self,
    ) -> Result<
        (
            &OriginalProtocolSnapshot,
            &crate::protocol_snapshot::Native5AfterProtocolCapacityFacts,
        ),
        ProviderError,
    > {
        self.ensure_complete_origin()?;
        let flight = self
            .capture
            .as_ref()
            .filter(|flight| flight.complete)
            .ok_or(ProviderError::Correlation(
                "native5 after issuance unresolved",
            ))?;
        let after = flight
            .protocol_after
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native5 original after owner absent",
            ))?;
        if after.cut() != ProtocolCaptureCut::HostSettled {
            return Err(ProviderError::Correlation(
                "native5 original after cut changed",
            ));
        }
        let capacity = flight
            .after_capacity
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "native5 original after admission absent",
            ))?;
        Ok((after, capacity))
    }

    /// Authenticates the actual terminal frame of a complete original Capture.
    ///
    /// Every prefix original must match the literal frame bank of the same
    /// returned connection. The returned read loan excludes transport mutation;
    /// callers drop it before I/O. This is physical evidence only and cannot
    /// issue a source settlement, archive ticket or fresh installation.
    ///
    /// # Errors
    /// Refuses wrong origin, incomplete publication, changed actual frame bytes,
    /// unavailable original connection, unsettled correlations, changed Capture
    /// scope or a terminal result that does not name all three retained objects.
    pub fn original_capture_terminal(
        &self,
    ) -> Result<crate::connection::OriginalSentFrameView<'_>, ProviderError> {
        self.ensure_complete_origin()?;
        let flight = self
            .capture
            .as_ref()
            .filter(|flight| flight.complete)
            .ok_or(ProviderError::Correlation(
                "native5 Capture not physically complete",
            ))?;
        let prefix = flight
            .prefix
            .as_ref()
            .filter(|prefix| prefix.is_complete())
            .ok_or(ProviderError::Correlation(
                "native5 Capture prefix incomplete",
            ))?;
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(ProviderError::Correlation(
                "native5 original Capture connection absent",
            ));
        };
        connection.authenticate_native5_capture_antecedent(&flight.protocol_before)?;
        for record in prefix.records() {
            for index in 0..record.originals().len() {
                let original = record.original_sent_frame(connection, index)?;
                let _literal = original.literal();
            }
        }
        let record = prefix.records().last().ok_or(ProviderError::Correlation(
            "native5 Capture terminal window absent",
        ))?;
        let index = record
            .originals()
            .len()
            .checked_sub(1)
            .ok_or(ProviderError::Correlation(
                "native5 Capture terminal frame absent",
            ))?;
        let terminal = record.original_sent_frame(connection, index)?;
        let response = terminal.original();
        let request = flight.reservation.request();
        if response.message != MessageKind::Response
            || response.method != request.method
            || response.request_id != request.request_id
            || response.operation_id != request.operation_id
            || response.node_id != request.node_id
            || response.capture_owner_id != request.capture_owner_id
            || response.execution_owner_id != request.execution_owner_id
            || !response.extensions.is_empty()
        {
            return Err(ProviderError::Correlation(
                "native5 actual Capture terminal scope changed",
            ));
        }
        // The complete original body is already retained and schema-checked.
        // Compare borrowed fields instead of allocating a second response DTO.
        let body = &response.body;
        let result = body
            .get("result")
            .and_then(serde_json::Value::as_object)
            .ok_or(ProviderError::Correlation("native5 Capture result absent"))?;
        let owners = result
            .get("owner_state_refs")
            .and_then(serde_json::Value::as_array)
            .ok_or(ProviderError::Correlation(
                "native5 Capture owner objects absent",
            ))?;
        if body.len() != 4
            || body.get("status").and_then(serde_json::Value::as_str) != Some("completed")
            || body
                .get("operation_state")
                .and_then(serde_json::Value::as_str)
                != Some("completed")
            || !body
                .get("extensions")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|extensions| extensions.is_empty())
            || result.len() != 3
            || owners.len() != 1
            || !same_borrowed_reference(result.get("capture_manifest"), &flight.snapshot.0)
            || !same_borrowed_reference(owners.first(), flight.component.snapshot().reference())
            || !same_borrowed_reference(
                result.get("unchanged_cut_receipt"),
                flight.component.anchor().0,
            )
        {
            return Err(ProviderError::Correlation(
                "native5 Capture terminal retained object tuple changed",
            ));
        }
        Ok(terminal)
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

pub(super) fn bounded(value: u64, reason: &'static str) -> Result<usize, ProviderError> {
    usize::try_from(value).map_err(|_| ProviderError::ResourceExhausted(reason))
}

pub(super) fn preflight_transport_credit(
    snapshot: usize,
    control: usize,
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
        .and_then(|count| count.checked_add(control.div_ceil(chunk)))
        .and_then(|count| count.checked_add(7))
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

// Full typed-reference comparison borrows the already retained closed JSON.
fn same_borrowed_reference(value: Option<&serde_json::Value>, reference: &ContentRef) -> bool {
    let Some(object) = value.and_then(serde_json::Value::as_object) else {
        return false;
    };
    let Some(hash) = object.get("hash").and_then(serde_json::Value::as_object) else {
        return false;
    };
    object.len() == 3
        && hash.len() == 3
        && hash.get("algorithm").and_then(serde_json::Value::as_str)
            == Some(reference.hash.algorithm.as_str())
        && hash.get("domain").and_then(serde_json::Value::as_str)
            == Some(reference.hash.domain.as_str())
        && hash.get("digest").and_then(serde_json::Value::as_str)
            == Some(reference.hash.digest.as_str())
        && object.get("media_type").and_then(serde_json::Value::as_str)
            == Some(reference.media_type.as_str())
        && object
            .get("length")
            .and_then(serde_json::Value::as_str)
            .and_then(|length| length.parse::<u64>().ok())
            == Some(reference.length.get())
}
