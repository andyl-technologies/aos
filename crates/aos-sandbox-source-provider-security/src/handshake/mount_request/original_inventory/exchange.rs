//! Exact reservation confirmation, carrier acceptance and retaining receive.

use super::*;

impl CurrentRootMountSourceProviderSessionV1 {
    /// Confirms actual Q1 and moves its preparation into retained send custody.
    ///
    /// # Errors
    /// Rejects stale or substituted actual readback; retains every input/output owner.
    #[doc(hidden)]
    pub fn confirm_original_inventory_v6(
        &mut self,
        writer: &Writer<'_>,
        original: Original<'_>,
        actual: &OriginalInventoryProtectedReadbackV6,
        preparation: &mut OriginalInventoryPreparationV6,
        send: &mut Option<OriginalInventorySendV6>,
    ) -> Result<(), SourceProviderSecurityError> {
        let result = (|| {
            self.revalidate_original_inventory_continuation_v6(writer, original)?;
            if preparation.failed.get()
                || preparation.confirmed
                || send.is_some()
                || preparation.root != original.2.attempt()
            {
                return Err(invalid());
            }

            writer.validate_readback(actual).map_err(|_| invalid())?;
            let draft = preparation.draft.as_ref().ok_or_else(invalid)?;
            if actual.root_attempt() != preparation.root || actual.query_attempt() != draft.attempt_id {
                return Err(invalid());
            }
            let graph = actual.graph().map_err(|_| invalid())?;
            let attempt = graph
                .legacy()
                .provider_attempts
                .get(&draft.attempt_id)
                .ok_or_else(invalid)?;
            let attempt_key = msa::provider_attempt_key(attempt.attempt_id);
            let head_key = msa::provider_head_key(
                attempt.scope.holder_authority_id,
                attempt.scope.provider_authority_id,
            );
            let attempt_bytes = graph.canonical_records().get(&attempt_key).ok_or_else(invalid)?.clone();
            let head_bytes = graph.canonical_records().get(&head_key).ok_or_else(invalid)?.clone();
            let snapshot = writer.snapshot().map_err(|_| invalid())?;
            let prepared = preparation.prepared.as_ref().ok_or_else(invalid)?;
            prepared.validate_protected_reservation(
                writer,
                &snapshot,
                &attempt_key,
                &attempt_bytes,
                &head_key,
                &head_bytes,
            )?;
            if prepared.native_currentness.is_some()
                || prepared.outcome.native_outcome.is_some()
                || prepared.outcome.deadline_policy != OutcomeDeadlinePolicyV2::Fresh
                || prepared.outcome.deadline_seconds > original.0.deadline_seconds {
                return Err(invalid());
            }
            self.revalidate_original_inventory_continuation_v6(writer, original)?;
            writer.validate_snapshot(&snapshot).map_err(|_| invalid())?;

            let session_id = attempt.session_id;
            let query = attempt.attempt_id;
            let prepared = preparation.prepared.take().ok_or_else(invalid)?;
            *send = Some(OriginalInventorySendV6 {
                root: preparation.root,
                query,
                reservation: Some(prepared.bind_reserved(
                    snapshot,
                    attempt_key,
                    attempt_bytes,
                    head_key,
                    head_bytes,
                    session_id,
                    query,
                )),
                recovery: None,
                sent: None,
                attempted: false,
                carrier_accepted: false,
                failed: Cell::new(false),
            });
            preparation.confirmed = true;
            writer.validate_readback(actual).map_err(|_| invalid())?;
            self.revalidate_original_inventory_continuation_v6(writer, original)
        })();
        if result.is_err() {
            preparation.failed.set(true);
            if let Some(send) = send.as_ref() {
                send.failed.set(true);
            }
            self.fail_query_v6(original);
        }
        result
    }

    /// Sends exact Query bytes while retaining possible-send debt before postchecks.
    ///
    /// # Errors
    /// Rejects reentry or stale custody; Accepted is never returned to a retry lane.
    #[doc(hidden)]
    pub fn send_original_inventory_v6(
        &mut self,
        writer: &Writer<'_>,
        original: Original<'_>,
        send: &mut OriginalInventorySendV6,
    ) -> Result<bool, SourceProviderSecurityError> {
        let result = (|| {
            self.revalidate_original_inventory_continuation_v6(writer, original)?;
            if send.failed.get()
                || send.carrier_accepted
                || send.sent.is_some()
                || send.root != original.2.attempt()
            {
                return Err(invalid());
            }

            let snapshot = writer.snapshot().map_err(|_| invalid())?;
            let reservation = match send.reservation.take() {
                Some(reservation) => reservation,
                None => send.recovery.take().ok_or_else(invalid)?.reservation,
            };
            send.attempted = true;
            let mut boundary = None;
            let mut post_valid = false;
            let outcome = self.send_reserved_mount_request_with_boundary_v6(
                writer,
                reservation,
                |owner, _, observed| {
                    boundary = Some(observed);
                    // Acceptance cannot be undone by fallible postchecks.
                    if observed == ProviderSendBoundaryV6::Accepted {
                        send.carrier_accepted = true;
                    }

                    writer.validate_snapshot(&snapshot).map_err(|_| invalid())?;
                    owner.revalidate_original_inventory_continuation_v6(writer, original)?;
                    post_valid = true;
                    Ok(())
                },
            );
            match outcome {
                Ok(sent) => {
                    send.sent = Some(sent);
                    self.revalidate_original_inventory_continuation_v6(writer, original)?;
                    Ok(true)
                }
                Err(recovery) => {
                    send.recovery = Some(recovery);
                    if boundary == Some(ProviderSendBoundaryV6::Retryable) && post_valid {
                        Ok(false)
                    } else {
                        Err(invalid())
                    }
                }
            }
        })();
        if result.is_err() {
            send.failed.set(true);
            self.fail_query_v6(original);
        }
        result
    }

    /// Parks one actual Query packet before framing, execution or signature checks.
    ///
    /// # Errors
    /// Retains malformed and wrong-FD packets and irrevocably closes effect authority.
    #[doc(hidden)]
    pub fn advance_original_inventory_receive_v6(
        &mut self,
        writer: &Writer<'_>,
        original: Original<'_>,
        send: &OriginalInventorySendV6,
        slot: &mut Option<OriginalInventoryReceivedOutcomeV6>,
    ) -> Result<bool, SourceProviderSecurityError> {
        let result = (|| {
            self.revalidate_original_inventory_continuation_v6(writer, original)?;
            let snapshot = writer.snapshot().map_err(|_| invalid())?;
            let sent = self.require_query_sent_v6(writer, original, send)?;
            if slot.is_some() {
                return Err(invalid());
            }

            let mut packet = None;
            let capture = self.carrier.receive_original_retaining_v5(&mut packet);
            if let Some(packet) = packet {
                *slot = Some(OriginalInventoryReceivedOutcomeV6 {
                    root: send.root,
                    query: send.query,
                    received: packet,
                    verified: None,
                    failed: Cell::new(false),
                });
            }
            match capture {
                Err(CarrierFailureV1::Retryable) if slot.is_none() => {
                    writer.validate_snapshot(&snapshot).map_err(|_| invalid())?;
                    self.revalidate_original_inventory_continuation_v6(writer, original)?;
                    return Ok(false);
                }
                Err(_) => return Err(invalid()),
                Ok(_) => {}
            }
            let token = slot.as_mut().ok_or_else(invalid)?;
            let bound = token.received.bound().ok_or_else(invalid)?;
            bound.execution.revalidate(self.carrier.socket().peer())?;
            if !bound.descriptors.is_empty()
                || !bound.execution.has_same_execution(&self.provider_execution)
            {
                return Err(invalid());
            }

            token.verified = Some(self.verify_provider_outcome_bytes_v2(
                None,
                &sent.outcome,
                bound.payload.clone(),
                None,
            )?);
            writer.validate_snapshot(&snapshot).map_err(|_| invalid())?;
            self.revalidate_original_inventory_received_v6(writer, original, send, token)?;
            Ok(true)
        })();
        if result.is_err() {
            send.failed.set(true);
            if let Some(token) = slot.as_ref() {
                token.failed.set(true);
            }
            self.fail_query_v6(original);
        }
        result
    }
}
