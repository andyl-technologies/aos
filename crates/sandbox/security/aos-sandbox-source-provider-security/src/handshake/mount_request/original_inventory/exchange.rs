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
        let mut boundary = QueryBoundaryV6::new(self, original, (preparation, send));
        boundary.run(|session, progress| {
            let (preparation, send) = progress;
            let preparation = &mut **preparation;
            let send = &mut **send;

            session.revalidate_original_inventory_continuation_v6(writer, original)?;
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
            session.revalidate_original_inventory_continuation_v6(writer, original)?;
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
                observed_boundary: None,
                carrier_accepted: false,
                failed: Cell::new(false),
            });
            preparation.confirmed = true;
            writer.validate_readback(actual).map_err(|_| invalid())?;
            session.revalidate_original_inventory_continuation_v6(writer, original)
        })
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
        let mut boundary = QueryBoundaryV6::new(self, original, send);
        boundary.run(|session, progress| {
            let send = &mut **progress;

            session.revalidate_original_inventory_continuation_v6(writer, original)?;
            if send.failed.get()
                || send.carrier_accepted
                || send.observed_boundary == Some(ProviderSendBoundaryV6::Accepted)
                || send.sent.is_some()
                || send.root != original.2.attempt()
            {
                return Err(invalid());
            }

            let snapshot = writer.snapshot().map_err(|_| invalid())?;
            if send.reservation.is_some() == send.recovery.is_some() {
                return Err(invalid());
            }
            let reservation = send.reservation
                .as_ref()
                .or_else(|| send.recovery.as_ref().map(|recovery| &recovery.reservation))
                .ok_or_else(invalid)?;
            if reservation.prepared.native_currentness.is_some()
                || reservation.prepared.outcome.native_outcome.is_some()
            {
                return Err(invalid());
            }

            send.attempted = true;
            let carrier_accepted = &mut send.carrier_accepted;
            let observed_boundary = &mut send.observed_boundary;
            let mut post_valid = false;
            let outcome = session.send_borrowed_mount_request_v6(
                writer,
                reservation,
                |owner, _, observed| {
                    *observed_boundary = Some(observed);
                    // Acceptance cannot be undone by fallible postchecks.
                    if observed == ProviderSendBoundaryV6::Accepted {
                        *carrier_accepted = true;
                    }

                    writer.validate_snapshot(&snapshot).map_err(|_| invalid())?;
                    owner.revalidate_original_inventory_continuation_v6(writer, original)?;
                    post_valid = true;
                    Ok(())
                },
            );

            match outcome {
                Ok(_) => {
                    // The exact reservation stayed parked across all I/O and
                    // callback checks. Successful conversion only moves fields.
                    if let Some(reservation) = send.reservation.take() {
                        park_query_sent(send, reservation);
                    } else if let Some(recovery) = send.recovery.take() {
                        park_query_sent(send, recovery.reservation);
                    }

                    session.revalidate_original_inventory_continuation_v6(writer, original)?;
                    Ok(true)
                }
                Err(_) => {
                    if send.observed_boundary == Some(ProviderSendBoundaryV6::Retryable)
                        && post_valid
                    {
                        Ok(false)
                    } else {
                        Err(invalid())
                    }
                }
            }
        })
    }

    /// Parks one actual Query packet before framing, execution or signature checks.
    ///
    /// # Errors
    /// Retains successfully typed packets, including bad framing and wrong FDs,
    /// and irrevocably closes effect authority. Rejected raw ancillary messages
    /// retain the existing fatal-close policy rather than creating typed custody.
    #[doc(hidden)]
    pub fn advance_original_inventory_receive_v6(
        &mut self,
        writer: &Writer<'_>,
        original: Original<'_>,
        send: &OriginalInventorySendV6,
        slot: &mut Option<OriginalInventoryReceivedOutcomeV6>,
    ) -> Result<bool, SourceProviderSecurityError> {
        let mut boundary = QueryBoundaryV6::new(self, original, (send, slot));
        boundary.run(|session, progress| {
            let (send, slot) = progress;
            let send = &**send;
            let slot = &mut **slot;

            session.revalidate_original_inventory_continuation_v6(writer, original)?;
            let snapshot = writer.snapshot().map_err(|_| invalid())?;
            let sent = session.require_query_sent_v6(writer, original, send)?;
            if slot.is_none() {
                *slot = Some(OriginalInventoryReceivedOutcomeV6 {
                    root: send.root,
                    query: send.query,
                    received: None,
                    verified: None,
                    failed: Cell::new(false),
                });
            }

            let token = slot.as_mut().ok_or_else(invalid)?;
            if token.failed.get()
                || token.root != send.root
                || token.query != send.query
                || token.received.is_some()
                || token.verified.is_some()
            {
                return Err(invalid());
            }

            let capture = session.carrier.receive_original_retaining_v5(&mut token.received);
            match capture {
                Err(CarrierFailureV1::Retryable) if token.received.is_none() => {
                    writer.validate_snapshot(&snapshot).map_err(|_| invalid())?;
                    session.revalidate_original_inventory_continuation_v6(writer, original)?;
                    return Ok(false);
                }
                Err(_) => return Err(invalid()),
                Ok(_) => {}
            }

            let bound = token.received
                .as_ref()
                .and_then(|record| record.bound())
                .ok_or_else(invalid)?;
            bound.execution.revalidate(session.carrier.socket().peer())?;
            if !bound.descriptors.is_empty()
                || !bound.execution.has_same_execution(&session.provider_execution)
            {
                return Err(invalid());
            }

            token.verified = Some(session.verify_provider_outcome_bytes_v2(
                None,
                &sent.outcome,
                bound.payload.clone(),
                None,
            )?);
            writer.validate_snapshot(&snapshot).map_err(|_| invalid())?;
            session.revalidate_original_inventory_received_v6(writer, original, send, token)?;
            Ok(true)
        })
    }
}

/// Moves a checked ordinary Query reservation without callbacks or allocations.
fn park_query_sent(
    send: &mut OriginalInventorySendV6,
    reservation: ReservedMountProviderRequestV2,
) {
    let ReservedMountProviderRequestV2 { prepared, .. } = reservation;
    send.sent = Some(SentMountProviderRequestV2 {
        projection: prepared.projection,
        outcome: prepared.outcome,
    });
}
