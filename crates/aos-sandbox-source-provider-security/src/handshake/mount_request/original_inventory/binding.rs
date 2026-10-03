//! Exact packet-to-owner binding without reminting the first verifier anchor.

use super::*;
use msa::native_held_completion::{
    validate_native_root_graph_v2, validate_original_inventory_transition_v6,
};
use sha2::Digest as _;

impl CurrentRootMountSourceProviderSessionV1 {
    pub(super) fn require_query_sent_v6<'sent>(
        &mut self,
        writer: &Writer<'_>,
        original: Original<'_>,
        send: &'sent OriginalInventorySendV6,
    ) -> Result<&'sent SentMountProviderRequestV2, SourceProviderSecurityError> {
        if send.failed.get() || !send.carrier_accepted || send.root != original.2.attempt() {
            return Err(invalid());
        }
        let sent = send.sent.as_ref().ok_or_else(invalid)?;
        let authorization = &sent.outcome;
        let graph = writer.current_graph().map_err(|_| invalid())?;
        let attempt = graph
            .legacy()
            .provider_attempts
            .get(&send.query)
            .ok_or_else(invalid)?;
        let session = graph
            .legacy()
            .provider_sessions
            .get(&attempt.session_id)
            .ok_or_else(invalid)?;
        self.revalidate()?;
        let authentication_time = query_authentication_time_v6(
            session.authenticated_at_seconds,
            super::super::current_unix_seconds()?,
        )?;
        let current = capture_session_projection(self, authentication_time)?;
        if authorization.method != SourceProviderMethod::Inventory
            || authorization.native_outcome.is_some()
            || authorization.deadline_policy != OutcomeDeadlinePolicyV2::Fresh
            || authorization.historical_session.is_some()
            || authorization.mount_attempt_id != Some(send.query)
            || authorization.mount_session_id != Some(attempt.session_id)
            || authorization.session_binding != self.session.binding()
            || authorization.signed_request.to_canonical_bytes() != attempt.signed_request
            || authorization.signed_request_digest.as_bytes() != &attempt.signed_request_digest
            || authorization.inventory_correlations != attempt.inventory_correlations
            || authorization.request_sequence != attempt.request_sequence
            || authorization.expected_response_sequence != attempt.request_sequence
            || authorization.deadline_seconds > original.0.deadline_seconds
            || super::super::current_unix_seconds()? >= authorization.deadline_seconds
            || authorization.provider_outcome_signer != current.ordered_signers[3].signer
            || authorization.provider_outcome_public_key != current.ordered_signers[3].public_key
            || !stored_mount_session_matches_projection(session, &current)
            || !stored_mount_session_matches_projection(session, &sent.projection.session)
            || attempt.method != msa::ProviderMethodV2::Inventory
            || attempt.owner != msa::ProviderQueryOwnerV2::Inventory
            || send.root == send.query
        {
            return Err(invalid());
        }
        Ok(sent)
    }

    /// Rechecks retained zero-FD receipt custody without producing another anchor.
    ///
    /// # Errors
    /// Rejects failed/substituted packets, changed Session material or original currentness.
    #[doc(hidden)]
    pub fn revalidate_original_inventory_received_v6(
        &mut self,
        writer: &Writer<'_>,
        original: Original<'_>,
        send: &OriginalInventorySendV6,
        token: &OriginalInventoryReceivedOutcomeV6,
    ) -> Result<(), SourceProviderSecurityError> {
        let mut boundary = QueryBoundaryV6::new(self, original, (send, token));
        boundary.run(|session, progress| {
            let (send, token) = progress;
            let send = &**send;
            let token = &**token;

            session.revalidate_original_inventory_continuation_v6(writer, original)?;
            let snapshot = writer.snapshot().map_err(|_| invalid())?;
            let sent = session.require_query_sent_v6(writer, original, send)?;
            let verified = token.verified_inventory().ok_or_else(invalid)?;
            let record = token.received
                .as_ref()
                .and_then(|record| record.bound())
                .ok_or_else(invalid)?;
            let anchor = verified.verification_anchor;
            let response_digest = aos_sandbox_source_provider_protocol::provider_response_artifact_digest_v1(
                SourceProviderMethod::Inventory,
                &record.payload,
            );
            if token.root != send.root
                || token.query != send.query
                || !record.descriptors.is_empty()
                || !record.execution.has_same_execution(&session.provider_execution)
                || verified.method != SourceProviderMethod::Inventory
                || verified.native_outcome.is_some()
                || verified.canonical_response != record.payload
                || verified.session_binding != sent.outcome.session_binding
                || verified.response_sequence != sent.outcome.expected_response_sequence
                || anchor.verification_started_seconds < 0
                || anchor.verification_completed_seconds < anchor.verification_started_seconds
                || anchor.verification_completed_seconds >= sent.outcome.deadline_seconds
                || anchor.kernel_boot_id != sent.outcome.kernel_boot_id
                || anchor.trusted_clock_evidence_digest != *sent.outcome.trusted_clock_evidence_digest.as_bytes()
                || msa::outcome_verification_anchor_digest_v2(
                    &anchor,
                    sent.outcome.mount_session_id.ok_or_else(invalid)?,
                    send.query,
                    sent.outcome.request_sequence,
                    sent.outcome.expected_response_sequence,
                    *response_digest.as_bytes(),
                ) != anchor.anchor_digest
            {
                return Err(invalid());
            }

            record.execution.revalidate(session.carrier.socket().peer())?;
            writer.validate_snapshot(&snapshot).map_err(|_| invalid())?;
            session.revalidate_original_inventory_continuation_v6(writer, original)
        })
    }

    /// Binds prospective ordinary Q2/H bytes to the first actual verified packet.
    ///
    /// # Errors
    /// Rejects another signed response, anchor, owner, transaction or full-graph edge.
    #[doc(hidden)]
    pub fn validate_original_inventory_prospective_v6(
        &mut self,
        writer: &Writer<'_>,
        original: Original<'_>,
        send: &OriginalInventorySendV6,
        token: &OriginalInventoryReceivedOutcomeV6,
        owners: &JournalTransaction,
    ) -> Result<(), SourceProviderSecurityError> {
        let mut boundary = QueryBoundaryV6::new(self, original, (send, token));
        boundary.run(|session, progress| {
            let (send, token) = progress;
            let send = &**send;
            let token = &**token;

            session.revalidate_original_inventory_received_v6(writer, original, send, token)?;
            let snapshot = writer.snapshot().map_err(|_| invalid())?;
            let before = writer.current_graph().map_err(|_| invalid())?;
            let mut rows = before.canonical_records().clone();
            let mut keys = BTreeSet::new();
            for record in owners.records() {
                if record.namespace()
                    != aos_sandbox::journal::RecordNamespace::MountSourceAcquisition
                    || !keys.insert(record.key().to_vec())
                {
                    return Err(invalid());
                }
                rows.insert(
                    record.key().to_vec(),
                    record.value().ok_or_else(invalid)?.to_vec(),
                );
            }

            let after = validate_native_root_graph_v2(
                rows.iter().map(|(key, value)| (key.as_slice(), value.as_slice())),
            )
            .map_err(|_| invalid())?;
            validate_original_inventory_transition_v6(
                &before,
                &after,
                send.root,
                send.query,
                *owners.id(),
            )
            .map_err(|_| invalid())?;
            require_consumed_packet(&after, send.query, token)?;
            writer.validate_snapshot(&snapshot).map_err(|_| invalid())?;
            session.revalidate_original_inventory_received_v6(writer, original, send, token)
        })
    }

    /// Binds actual current Q2 readback to retained packet and first verifier anchor.
    ///
    /// # Errors
    /// Rejects stale/substituted physical state or packet-to-owner mismatch.
    #[doc(hidden)]
    pub fn validate_original_inventory_readback_v6(
        &mut self,
        writer: &Writer<'_>,
        original: Original<'_>,
        send: &OriginalInventorySendV6,
        token: &OriginalInventoryReceivedOutcomeV6,
        actual: &OriginalInventoryProtectedReadbackV6,
    ) -> Result<(), SourceProviderSecurityError> {
        let mut boundary = QueryBoundaryV6::new(self, original, (send, token));
        boundary.run(|session, progress| {
            let (send, token) = progress;
            let send = &**send;
            let token = &**token;

            session.revalidate_original_inventory_received_v6(writer, original, send, token)?;
            writer.validate_readback(actual).map_err(|_| invalid())?;
            if actual.root_attempt() != send.root || actual.query_attempt() != send.query {
                return Err(invalid());
            }
            require_consumed_packet(actual.graph().map_err(|_| invalid())?, send.query, token)?;
            writer.validate_readback(actual).map_err(|_| invalid())?;
            session.revalidate_original_inventory_received_v6(writer, original, send, token)
        })
    }
}

fn require_consumed_packet(
    graph: &msa::native_held_completion::RootNativeHeldGraphV2,
    query: [u8; 32],
    token: &OriginalInventoryReceivedOutcomeV6,
) -> Result<(), SourceProviderSecurityError> {
    let attempt = graph
        .legacy()
        .provider_attempts
        .get(&query)
        .ok_or_else(invalid)?;
    let verified = token.verified_inventory().ok_or_else(invalid)?;
    let response = decode_inventory_response(verified.canonical_response()).map_err(|_| invalid())?;
    let msa::ProviderAttemptStateV2::DispositionConsumed {
        response_sequence,
        verification_anchor,
        status,
        signed_status,
        signed_status_digest,
        signed_result,
        signed_result_digest,
    } = &attempt.state
    else {
        return Err(invalid());
    };
    let expected_status = match verified.status() {
        SourceProviderStatus::Complete => msa::ProviderStatusV2::Complete,
        SourceProviderStatus::Pending => msa::ProviderStatusV2::Pending,
        SourceProviderStatus::Rejected => msa::ProviderStatusV2::Rejected,
        SourceProviderStatus::Unavailable => msa::ProviderStatusV2::Unavailable,
    };
    let status_bytes = response.signed_status().to_canonical_bytes();
    let result_bytes = response.signed_inventory().map_or(&[][..], |bytes| bytes);
    let status_digest: [u8; 32] = Sha256::digest(&status_bytes).into();
    // The pure whole graph also authenticates each canonical digest/domain.
    if attempt.revision != 2
        || *response_sequence != verified.response_sequence
        || *verification_anchor != verified.verification_anchor
        || *status != expected_status
        || signed_status != &status_bytes
        || signed_result.as_slice() != result_bytes
        || *signed_status_digest != status_digest
        || *signed_result_digest != *verified.result_digest.as_bytes()
    {
        return Err(invalid());
    }
    Ok(())
}
