//! Retains finite closed64/39/42/43 histories through the existing archive engine.
//!
//! The existing AOSBSH01/AOSBST01 families store each new signed request under
//! its own request ID. Full immutable prefixes preserve negative outcomes too;
//! neither a terminal archive nor a missing row establishes a live owner or
//! absence of a later operation. Root separately reads the complete lineage.

use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
};
use aos_sandbox_protocol::authenticated_session::historical_method::historical_terminal_observation_v2;
use aos_sandbox_protocol::execution_availability::ExecutionAvailabilityPhaseV2;
use aos_sandbox_protocol::host_execution_availability::HostExecutionAvailabilityProposalV2;
use aos_sandbox_protocol::host_execution_no_apply::BeforeArgumentNoApplySourceDataV2;

use super::*;

fn is_closed_request(
    request: &AuthenticatedBrokerMethodRequestV1,
) -> Result<bool, BrokerSessionSecurityError> {
    if request.method() == BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 {
        let original = request
            .execution_availability_data_v2()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if original.phase() != ExecutionAvailabilityPhaseV2::AcceptedBind {
            return Ok(false);
        }
        let source = BeforeArgumentNoApplySourceDataV2::decode_canonical(
            original.canonical_accepted_source(),
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let proposal =
            HostExecutionAvailabilityProposalV2::decode_canonical(original.canonical_proposal())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        proposal
            .require_accepted_source(source)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if source.fields().create_operation != request.request_id() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        return Ok(true);
    }
    Ok(
        (request.method() == BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
            && request
                .host_before_argument_no_apply_data_v2()
                .is_some_and(|original| !original.is_query()))
            || request.host_held_no_apply_settlement_data_v2().is_some()
            || request
                .host_no_apply_current_lease_query_data_v2()
                .is_some(),
    )
}

impl ProtectedBrokerSessionJournalV1 {
    pub(in crate::recovery::journal) fn closed_host_prepared_request_id_v2(
        &self,
        stored: &StoredProtocolHistoryV1,
    ) -> Result<Option<[u8; 16]>, BrokerSessionSecurityError> {
        if stored.protocol != BrokerSessionProtocolV1::Host
            || stored.endpoint != BrokerSessionDurableEndpointV1::Client
        {
            return Ok(None);
        }
        let history = stored.history_model()?;
        let head = history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if head.phase() != BrokerSessionDurablePhaseV1::RequestPrepared {
            return Ok(None);
        }
        if !matches!(
            head.method(),
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
                | BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
                | BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2
        ) {
            return Ok(None);
        }
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        let index = history
            .records()
            .len()
            .checked_sub(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let (request, _) =
            historical_client_request(history.records(), index, checkpoint, &transcript)?;
        Ok(is_closed_request(&request)?.then(|| request.request_id()))
    }

    pub(in crate::recovery::journal) fn read_closed_host_terminal_archive_v2(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        let Some(stored) = self.read_host_terminal_archive_stored_v2(request_id)? else {
            return Ok(None);
        };
        let Some(outcome) = self.closed_host_terminal_outcome_v2(&stored)? else {
            return Ok(None);
        };
        if outcome.request().request_id() != request_id {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(Some(stored))
    }

    fn read_host_terminal_archive_stored_v2(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        let value = {
            let mut authority = self.schema_authority_v3()?;
            authority
                .get(&host_terminal_archive_key(request_id))
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .map(<[u8]>::to_vec)
        };
        let Some(value) = self.schema_retain_value_v3(value)? else {
            return Ok(None);
        };
        let bytes = open_history_archive_frame(request_id, &value, MAGIC, DOMAIN)?;
        let stored =
            self.schema_decode_stored_v3(&protocol_key(BrokerSessionProtocolV1::Host), bytes)?;
        Ok(Some(stored))
    }

    fn closed_host_terminal_outcome_v2(
        &mut self,
        stored: &StoredProtocolHistoryV1,
    ) -> Result<Option<AuthenticatedBrokerMethodOutcomeV1>, BrokerSessionSecurityError> {
        if stored.protocol != BrokerSessionProtocolV1::Host
            || stored.endpoint != BrokerSessionDurableEndpointV1::Client
        {
            return Ok(None);
        }
        let history = stored.history_model()?;
        let head = history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if head.phase() != BrokerSessionDurablePhaseV1::Terminal {
            return Ok(None);
        }
        if !matches!(
            head.method(),
            BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
                | BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
                | BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
                | BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2
        ) {
            return Ok(None);
        }
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        let index = history
            .records()
            .len()
            .checked_sub(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let outcome =
            historical_terminal_observation_v2(history.records(), index, checkpoint, &transcript)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if !is_closed_request(outcome.request())? {
            return Ok(None);
        }
        if stored.stable_endpoint_identity
            != self.stable_endpoint_identity(BrokerSessionProtocolV1::Host)?
            || self.endpoint.historical_context(checkpoint.context())? != *checkpoint.context()
            || stored.endpoint_publication
                != self
                    .historical_endpoint_publication(BrokerSessionProtocolV1::Host, &transcript)?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let original = self
            .read_host_argument_archive(outcome.request().request_id())?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let original_checkpoint = original
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let original_transcript = original_checkpoint.verify()?;
        let original_history = original.history_model()?;
        let original_index = original_history
            .records()
            .len()
            .checked_sub(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let (request, _) = historical_client_request(
            original_history.records(),
            original_index,
            original_checkpoint,
            &original_transcript,
        )?;
        if request.canonical_packet() != outcome.request().canonical_packet() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if let Some(early) = outcome.request().host_before_argument_no_apply_data_v2() {
            let source = early.source();
            let accepted = self
                .read_host_terminal_archive_stored_v2(source.fields().create_operation)?
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let accepted_history = accepted.history_model()?;
            // Require the finite64 predecessor before following any semantic
            // association. A hostile39 cycle cannot recurse through archives.
            let accepted_head = accepted_history
                .head()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            if accepted_head.method()
                != BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
                || accepted_head.request_id() != source.fields().create_operation
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let accepted_outcome = self
                .closed_host_terminal_outcome_v2(&accepted)?
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let bind = accepted_outcome
                .request()
                .execution_availability_data_v2()
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            if bind.canonical_accepted_source() != source.encode_canonical()
                || !successful_terminal(
                    accepted_history
                        .head()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?,
                )?
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            // Only the existing canonical helper supplies common H/T on success.
            if successful_terminal(head)? {
                aos_sandbox_protocol::host_execution_no_apply::closed_host_terminal_archive_data_v2(&outcome)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            }
        }
        Ok(Some(outcome))
    }

    pub(in crate::recovery::journal) fn prepare_closed_host_terminal_archive_v2(
        &mut self,
        stored: &StoredProtocolHistoryV1,
    ) -> Result<Option<JournalRecord>, BrokerSessionSecurityError> {
        let Some(outcome) = self.closed_host_terminal_outcome_v2(stored)? else {
            return Ok(None);
        };
        let request_id = outcome.request().request_id();
        if self.validate_host_terminal_archives()? == MAXIMUM_HOST_TERMINAL_ARCHIVES {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        // Test the actual shared family, so a legacy collision also refuses.
        let exists = {
            let mut authority = self.schema_authority_v3()?;
            authority
                .get(&host_terminal_archive_key(request_id))
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .is_some()
        };
        if exists {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let frame = encode_history_archive_frame(request_id, &stored.encode()?, MAGIC, DOMAIN)?;
        Ok(Some(JournalRecord::put(
            RecordNamespace::BrokerSessionTraffic,
            host_terminal_archive_key(request_id),
            frame,
        )))
    }
}

impl crate::recovery::ProtectedBrokerSessionOwnerV1 {
    // The caller retains this actual cold Session's installed schema payer and
    // native originals. Target comes from the same genuine07e Source borrower;
    // the returned comparison tuple cannot construct a live lease or owner.
    pub(crate) fn select_execution_no_apply_cleanup_history_v2(
        &mut self,
        target: aos_sandbox_core::OperationId,
    ) -> Result<(
        aos_sandbox_protocol::host_execution_no_apply::ClosedHostTerminalArchiveDataV2,
        aos_sandbox_protocol::host_execution_availability::observation::HostExecutionAvailabilityObservationV2,
    ), BrokerSessionSecurityError>{
        self.journal
            .select_execution_no_apply_cleanup_history_v2(target)
    }
}

impl ProtectedBrokerSessionJournalV1 {
    fn select_execution_no_apply_cleanup_history_v2(
        &mut self,
        target: aos_sandbox_core::OperationId,
    ) -> Result<(
        aos_sandbox_protocol::host_execution_no_apply::ClosedHostTerminalArchiveDataV2,
        aos_sandbox_protocol::host_execution_availability::observation::HostExecutionAvailabilityObservationV2,
    ), BrokerSessionSecurityError>{
        use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
        use aos_sandbox_protocol::host_execution_availability::observation::HostExecutionAvailabilityObservationV2;

        let ids = self.bounded_host_archive_request_ids(
            BrokerSessionJournalKeyKind::HostTerminalSessionArchive,
            MAXIMUM_HOST_TERMINAL_ARCHIVES,
        )?;
        let mut selected = None;
        for request_id in ids {
            let scope = self.schema_scope_v3();
            let result = (|| {
                let stored = self
                    .read_host_terminal_archive_stored_v2(request_id)?
                    .ok_or(BrokerSessionSecurityError::Currentness)?;
                let Some(outcome) = self.closed_host_terminal_outcome_v2(&stored)? else {
                    return Ok(None);
                };
                let Some(request) = outcome.request().host_before_argument_no_apply_data_v2()
                else {
                    return Ok(None);
                };
                if request.source().fields().create_operation != *target.as_bytes()
                    || !matches!(
                        outcome.result(),
                        AuthenticatedBrokerMethodResultV1::Success { .. }
                    )
                {
                    return Ok(None);
                }
                let terminal = aos_sandbox_protocol::host_execution_no_apply::closed_host_terminal_archive_data_v2(&outcome)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                // The same closed39 reader already required the exact signed64
                // predecessor. Reborrow its sole decoder to extract the actual
                // observed368 bytes, preserving the existing schema payer.
                let accepted = self
                    .read_host_terminal_archive_stored_v2(*target.as_bytes())?
                    .ok_or(BrokerSessionSecurityError::Currentness)?;
                let accepted = self
                    .closed_host_terminal_outcome_v2(&accepted)?
                    .ok_or(BrokerSessionSecurityError::Currentness)?;
                let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } =
                    accepted.result()
                else {
                    return Err(BrokerSessionSecurityError::Currentness);
                };
                let bytes = aos_sandbox_protocol::execution_availability::decode_execution_availability_response_v2(exact_body)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                let availability = HostExecutionAvailabilityObservationV2::decode_canonical(&bytes)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                if availability.fields().phase != ExecutionAvailabilityPhaseV2::AcceptedBind
                    || availability.fields().bound_source_digest
                        != *request.source().digest().as_bytes()
                {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                Ok(Some((terminal, availability)))
            })();
            self.schema_complete_scope_v3(scope, &result);
            if let Some(found) = result? {
                if selected.is_some() {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                selected = Some(found);
            }
        }
        selected.ok_or(BrokerSessionSecurityError::Currentness)
    }
}
