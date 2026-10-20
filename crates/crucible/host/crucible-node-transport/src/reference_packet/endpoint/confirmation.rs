//! Validates confirmation against actual retained Capture and after issuance.
//!
//! This selected route does not call baseline Control.poll. The original native
//! Capture outcome and after owner remain in the endpoint across every refusal.

use super::*;
use crate::reference_packet::service::confirmation::{
    PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION, PacketNativeAfterConfirmationReceipt,
    PacketNativeAfterConfirmationRequest,
};
use crucible_node_format::{ContractError, Extensions, U64, canonical};

impl<S: ProviderStream> PacketEndpoint<S> {
    fn validate_original_after_confirmation(
        &self,
        poll: &Envelope,
        context: &PacketNativeAfterConfirmationRequest,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        context.validate_data()?;
        let flight = self
            .capture
            .as_ref()
            .filter(|flight| flight.complete)
            .ok_or(ProviderError::Correlation(
                "after confirmation requires issued Capture",
            ))?;
        let after = flight
            .protocol_after
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "after confirmation original after owner absent",
            ))?;
        let actual_after = after.original_allocation_facts()?;
        if self.complete.as_ref().is_some_and(|state| {
            matches!(
                state.profile,
                Some(super::super::service::PacketNative5CaptureProfile::OwnedProtocol11 { .. })
            )
        }) {
            if let Some(capacity) = flight.startup14_after_capacity.as_ref() {
                if after.bytes().len() > capacity.maximum_after_encoded_bytes
                    || capacity.maximum_after_encoded_bytes > capacity.reserved_after_encoded_bytes
                    || actual_after.maximum_encoded_bytes != capacity.reserved_after_encoded_bytes
                {
                    return Err(ProviderError::Correlation(
                        "startup after confirmation actual bank differs",
                    ));
                }
            } else {
                let capacity =
                    flight
                        .owned11_after_capacity
                        .as_ref()
                        .ok_or(ProviderError::Correlation(
                            "after confirmation owned11 original admission absent",
                        ))?;
                if after.bytes().len() > capacity.maximum_after_encoded_bytes
                    || capacity.maximum_after_encoded_bytes > capacity.reserved_after_encoded_bytes
                    || actual_after.maximum_encoded_bytes != capacity.reserved_after_encoded_bytes
                {
                    return Err(ProviderError::Correlation(
                        "after confirmation owned11 actual bank differs",
                    ));
                }
            }
        }
        let capture = flight.reservation.request();
        if poll.method != Method::Poll
            || poll.message != MessageKind::Request
            || poll.operation_id != capture.operation_id
            || poll.capture_owner_id != capture.capture_owner_id
            || poll.node_id != capture.node_id
            || poll.execution_owner_id.0.is_some()
            || poll.session_id != capture.session_id
            || poll.incarnation_id != capture.incarnation_id
            || poll.request_id.0.is_none()
            || poll.request_id == capture.request_id
            || context.capture_request_id
                != *capture
                    .request_id
                    .0
                    .as_ref()
                    .ok_or(ProviderError::Correlation(
                        "after original Capture ID absent",
                    ))?
            || context.capture_operation_id
                != *capture
                    .operation_id
                    .0
                    .as_ref()
                    .ok_or(ProviderError::Correlation(
                        "after original Capture operation absent",
                    ))?
            || context.capture_request_hash
                != if let Some(attempt) = self.capture_allocation_attempt.as_deref() {
                    let owner = attempt.published()?;
                    self.native.startup_capture_request_hash_data(
                        capture,
                        &owner.currency,
                        &owner.report,
                    )?
                } else {
                    capture.request_hash(RequestOrigin::Controller)?
                }
            || context.native_snapshot_ref != flight.snapshot.0
            || context.native_control_ref != *flight.component.snapshot().reference()
            || context.native_anchor_ref != *flight.component.anchor().0
        {
            return Err(ProviderError::Correlation(
                "after confirmation original Capture conjunction",
            ));
        }
        let prefix = flight.prefix.as_ref().ok_or(ProviderError::Correlation(
            "after confirmation original Capture prefix absent",
        ))?;
        let last = prefix.records().last().ok_or(ProviderError::Correlation(
            "after confirmation actual terminal record absent",
        ))?;
        let index = last
            .originals()
            .len()
            .checked_sub(1)
            .ok_or(ProviderError::Correlation(
                "after confirmation actual terminal frame absent",
            ))?;
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(ProviderError::Correlation(
                "after confirmation original connection absent",
            ));
        };
        // The selected SDK pending-Poll predicate separately authenticates the
        // exact after boundary plus new incoming request. This physical loan
        // checks the SAME original terminal bytes without claiming settled cut.
        let terminal = last.original_sent_frame(connection, index)?;
        if context.capture_terminal_sequence != terminal.original().sequence
            || context.capture_terminal_hash
                != canonical::json_hash(
                    "source-owned.packet-native-capture-terminal/5",
                    terminal.original(),
                )?
        {
            return Err(ProviderError::Correlation(
                "after confirmation actual terminal changed",
            ));
        }
        Ok(())
    }
}

use crate::reference_packet::continuation_transport::PacketAfterConfirmationPrefix;
pub(super) struct AfterConfirmation<S: ProviderStream> {
    request: Envelope,
    context: Option<PacketNativeAfterConfirmationRequest>,
    receipt: Option<PacketNativeAfterConfirmationReceipt>,
    response: Option<Envelope>,
    prefix: Option<PacketAfterConfirmationPrefix<S>>,
    complete: bool,
}

impl<S: ProviderStream> PacketEndpoint<S> {
    pub(super) fn confirm_original_after(
        &mut self,
        request: Envelope,
    ) -> Result<(), ProviderError> {
        self.ensure_complete_origin()?;
        if self.after_confirmation.is_some() {
            return Err(ProviderError::Conflict(
                "after confirmation already attempted",
            ));
        }
        self.after_confirmation = Some(AfterConfirmation {
            request,
            context: None,
            receipt: None,
            response: None,
            prefix: None,
            complete: false,
        });
        let original = &self
            .after_confirmation
            .as_ref()
            .ok_or(ProviderError::Conflict(
                "after confirmation original owner absent",
            ))?
            .request;
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(ProviderError::Conflict(
                "after original connected transport absent",
            ));
        };
        connection.authenticate_native5_confirmation_poll(original)?;
        let quoted_storage = if self.capture_allocation_attempt.is_some() {
            Some(self.quote_startup_confirmation_publication(original)?)
        } else {
            None
        };

        let context = original
            .extensions
            .get(PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION)
            .ok_or(ProviderError::Correlation(
                "after confirmation context absent",
            ))?;
        // Selected SDK borrowed grammar/extent admission has already happened
        // before this single retained typed decode. The original envelope stays
        // in the attempt slot on parse/refusal/unwind.
        let context: PacketNativeAfterConfirmationRequest =
            serde::Deserialize::deserialize(context).map_err(ContractError::from)?;
        self.validate_original_after_confirmation(original, &context)?;
        self.after_confirmation
            .as_mut()
            .ok_or(ProviderError::Conflict("after confirmation slot absent"))?
            .context = Some(context);
        let flight = self
            .capture
            .as_ref()
            .filter(|flight| flight.complete)
            .ok_or(ProviderError::Correlation(
                "after confirmation Capture unresolved",
            ))?;
        let after = flight
            .protocol_after
            .as_ref()
            .ok_or(ProviderError::Correlation("after original snapshot absent"))?;
        let facts = after.original_allocation_facts()?;
        let after_ref = canonical::content_ref(after.bytes(), "application/json")?;
        let terminal = flight
            .prefix
            .as_ref()
            .and_then(|prefix| prefix.records().last())
            .and_then(|record| record.originals().last())
            .ok_or(ProviderError::Correlation("after actual terminal absent"))?;
        let result = PollResult {
            operation_id: flight
                .reservation
                .request()
                .operation_id
                .0
                .as_ref()
                .ok_or(ProviderError::Correlation("after Capture operation absent"))?
                .clone(),
            operation_state: OperationState::Completed,
            outcome: Nullable(Some(terminal.body.clone())),
            observations: Vec::new(),
            next_observation_sequence: U64::new(0),
        };
        let mut response = self
            .after_confirmation
            .as_ref()
            .ok_or(ProviderError::Conflict("after confirmation slot absent"))?
            .request
            .clone();
        response.message = MessageKind::Response;
        response.sequence = U64::new(self.next_sequence);
        response.body = prefix::completed(result)?;
        // The typed context moves exactly once into the retained receipt.
        let context = self
            .after_confirmation
            .as_mut()
            .ok_or(ProviderError::Conflict("after confirmation slot absent"))?
            .context
            .take()
            .ok_or(ProviderError::Conflict("after confirmation context absent"))?;
        self.after_confirmation
            .as_mut()
            .ok_or(ProviderError::Conflict("after confirmation slot absent"))?
            .receipt = Some(PacketNativeAfterConfirmationReceipt {
            schema: "source-owned.packet-native-after-confirmation-receipt/5".into(),
            capture: context,
            native_after_ref: after_ref,
            native_after_capacity: U64::new(facts.encoded_capacity as u64),
        });
        let receipt = self
            .after_confirmation
            .as_ref()
            .and_then(|slot| slot.receipt.as_ref())
            .ok_or(ProviderError::Conflict("after confirmation receipt absent"))?;
        response.extensions = Extensions::from([(
            PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION.into(),
            serde_json::to_value(receipt).map_err(ContractError::from)?,
        )]);
        self.after_confirmation
            .as_mut()
            .ok_or(ProviderError::Conflict("after confirmation slot absent"))?
            .response = Some(response);
        let original = self
            .after_confirmation
            .as_ref()
            .ok_or(ProviderError::Conflict("after original attempt absent"))?;
        let response = original
            .response
            .as_ref()
            .ok_or(ProviderError::Conflict("after original response absent"))?;
        let chunk = usize::try_from(self.authority.limits().blob_chunk_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("after original chunk bound"))?
            .min(4096);
        if chunk == 0 {
            return Err(ProviderError::ResourceExhausted("after zero chunk"));
        }
        let requests = after.bytes().len().div_ceil(chunk).checked_add(2).ok_or(
            ProviderError::ResourceExhausted("after exact request population"),
        )?;
        let maximum_frame = usize::try_from(self.authority.limits().frame_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("after original frame bound"))?;
        let framed = maximum_frame
            .checked_add(4)
            .ok_or(ProviderError::ResourceExhausted(
                "after original frame header bound",
            ))?;
        let raw = requests
            .checked_mul(framed)
            .ok_or(ProviderError::ResourceExhausted("after raw ACK wholebound"))?;
        let sent = super::super::continuation_transport::outgoing_confirmation_extent(
            &self.authority,
            response,
            &original
                .receipt
                .as_ref()
                .ok_or(ProviderError::Conflict("after receipt absent"))?
                .native_after_ref,
            after.bytes().len(),
        )?;
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(ProviderError::Conflict(
                "after original connected transport absent",
            ));
        };
        // Exact outgoing extents and full worst-case raw ACK extents precede payload copies.
        // Exact full planned frame/ID admission follows before registration.
        connection.preflight_confirmation_publication(
            &original.request,
            requests + 1,
            sent,
            requests,
            raw,
        )?;
        let response = self
            .after_confirmation
            .as_mut()
            .ok_or(ProviderError::Conflict("after original attempt absent"))?
            .response
            .take()
            .ok_or(ProviderError::Conflict("after original response absent"))?;
        let Some(Transport::Connected(connection)) = self.transport.take() else {
            return Err(ProviderError::Conflict(
                "after original connection disappeared",
            ));
        };
        self.after_confirmation
            .as_mut()
            .ok_or(ProviderError::Conflict("after original attempt absent"))?
            .prefix = Some(PacketAfterConfirmationPrefix::new(connection));
        let original = self
            .after_confirmation
            .as_mut()
            .ok_or(ProviderError::Conflict("after original attempt absent"))?;
        let receipt = original
            .receipt
            .as_ref()
            .ok_or(ProviderError::Conflict("after original receipt absent"))?;
        let prefix = original
            .prefix
            .as_mut()
            .ok_or(ProviderError::Conflict("after original prefix absent"))?;
        if let Some(storage) = quoted_storage.as_ref() {
            prefix.prepare_with_storage_data(
                &original.request,
                response,
                receipt,
                (&receipt.native_after_ref, after.bytes()),
                storage,
            )?;
        } else {
            prefix.prepare(
                &original.request,
                response,
                receipt,
                (&receipt.native_after_ref, after.bytes()),
                facts.maximum_encoded_bytes,
            )?;
        }
        let charged = self
            .transport_credit
            .checked_add(prefix.charged_bytes())
            .filter(|n| *n <= super::super::continuation_transport::MAXIMUM_CAPTURE_TRANSPORT_BYTES)
            .ok_or(ProviderError::ResourceExhausted(
                "after whole retained transport credit",
            ))?;
        if let Some(storage) = quoted_storage.as_ref() {
            prefix.publish_with_storage_data(storage)?;
        } else {
            prefix.publish()?;
        }
        self.next_sequence = prefix.next_sequence();
        self.transport_credit = charged;
        self.transport = Some(Transport::Connected(prefix.take_completed_connection()?));
        original.complete = true;
        self.held = false;
        Ok(())
    }
}

impl<S: ProviderStream> PacketEndpoint<S> {
    /// Borrows the retained actual fourth-body confirmation and full suffix.
    ///
    /// # Errors
    /// Refuses foreign origin, unresolved publication, missing typed receipt or
    /// different current original transport. This physical view grants no source
    /// settlement, archive, fresh association or Ready authority.
    pub fn original_after_confirmation(
        &self,
    ) -> Result<(&PacketNativeAfterConfirmationReceipt, &[ExchangeRecord]), ProviderError> {
        self.ensure_complete_origin()?;
        let original = self
            .after_confirmation
            .as_ref()
            .filter(|slot| slot.complete)
            .ok_or(ProviderError::Correlation("after confirmation unresolved"))?;
        let receipt = original.receipt.as_ref().ok_or(ProviderError::Correlation(
            "after confirmation retained receipt absent",
        ))?;
        let prefix = original.prefix.as_ref().ok_or(ProviderError::Correlation(
            "after confirmation actual prefix absent",
        ))?;
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(ProviderError::Correlation(
                "after confirmation original connection absent",
            ));
        };
        for record in prefix.records() {
            for index in 0..record.originals().len() {
                record.original_sent_frame(connection, index)?;
            }
        }
        // Receipt syntax is already fixed; source still validates complete exact
        // incoming ACK originals/literals and the historical after-boundary suffix.
        Ok((receipt, prefix.records()))
    }
}
