//! Same-owner Storage Session continuity and terminal comparisons.
//!
//! These private seams borrow the actual held Journal and Broker endpoint.
//! They neither reopen a pathname nor create another writer or role instance.

use super::*;
use aos_sandbox_broker_session_protocol::{BrokerSessionPeerBindingV1, BrokerSessionProtectedBindingsV1};

mod execution_availability;

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn dispose_storage_positive_replays_v3(&mut self) {
        self.journal.session_replays.dispose_positive();
    }

    pub(crate) fn retained_storage_root_v1() -> &'static str {
        fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageBroker).journal_root
    }

    pub(crate) fn retained_storage_journal_v1(&self) -> Result<&Journal, BrokerSessionSecurityError> {
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageBroker);
        let owner = &self.journal;
        if owner.owner != JournalOwnerV1::RootBroker
            || owner.endpoint.role() != BrokerSessionDurableEndpointV1::Broker
            || owner.endpoint.protected_protocol_and_node().0 != BrokerSessionProtocolV1::Storage
            || owner.directory != Path::new(fixed.journal_root)
            || owner.name != PROTECTED_SESSION_JOURNAL
            || !owner.storage_receiving_open.as_ref().is_some_and(|open|
                matches!(open.native_settlement, Some(Ok(()))))
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        owner.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn compare_retained_storage_terminal_v1(
        &mut self,
        terminal: &ProtectedBrokerOutcomeCommittedAdvancementV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.compare_retained_storage_currentness_v1(&terminal.currentness_owner, peer, None)
    }

    pub(crate) fn compare_retained_storage_terminal_owner_v1(
        &mut self,
        terminal: &super::super::RetainedStorageTerminalV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.compare_retained_storage_currentness_v1(&terminal.currentness_owner, peer, None)
    }

    pub(crate) fn compare_retained_storage_replay_v1(
        &mut self,
        replay: &super::super::ProtectedBrokerOutcomeReplayV1,
        peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.compare_retained_storage_currentness_v1(&replay.currentness_owner, peer, None)
    }

    pub(crate) fn compare_storage_terminal_receiving_v3(&mut self,
        terminal: &ProtectedBrokerOutcomeCommittedAdvancementV1, peer: &ConnectionPeerIdentity,
        receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.compare_retained_storage_currentness_v1(&terminal.currentness_owner, peer, Some(receiving))
    }

    pub(crate) fn compare_storage_terminal_owner_receiving_v3(&mut self,
        terminal: &super::super::RetainedStorageTerminalV1, peer: &ConnectionPeerIdentity,
        receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.compare_retained_storage_currentness_v1(&terminal.currentness_owner, peer, Some(receiving))
    }

    pub(crate) fn compare_storage_replay_receiving_v3(&mut self,
        replay: &super::super::ProtectedBrokerOutcomeReplayV1, peer: &ConnectionPeerIdentity,
        receiving: &mut dyn StorageFloorFinancialSourceV2,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.compare_retained_storage_currentness_v1(&replay.currentness_owner, peer, Some(receiving))
    }

    fn compare_retained_storage_currentness_v1(
        &mut self,
        current: &super::super::ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
        receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.retained_storage_journal_v1()?;
        if self.journal.storage_receiving_open.as_ref()
            .and_then(|staged| staged.retired_transcript.as_ref())
            .is_some_and(|retired| retired.phase != RetiredStorageTranscriptPhaseV1::Consumed)
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if current.request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || current.transcript.protocol() != BrokerSessionProtocolV1::Storage
            || current.transcript.audience()
                != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        match receiving {
            Some(source) => self.journal.validate_storage_outcome_receiving_v3(current, peer, source),
            None => self.journal.validate_broker_outcome(current, peer),
        }
    }

    // The closed continuation constructor first checks the same original fixed
    // Broker owner. This private projection borrows that endpoint in place;
    // it cannot transfer or clone it out of the retained Journal/floor owner.
    pub(crate) fn retained_storage_broker_v1(&self) -> &ProtectedBrokerSessionBrokerV1 {
        match &self.journal.endpoint {
            ProtectedEndpointV1::Broker(endpoint) => endpoint,
            ProtectedEndpointV1::Client(_) => std::process::abort(),
        }
    }

    pub(crate) fn retained_storage_broker_mut_v1(&mut self) -> &mut ProtectedBrokerSessionBrokerV1 {
        match &mut self.journal.endpoint {
            ProtectedEndpointV1::Broker(endpoint) => endpoint,
            ProtectedEndpointV1::Client(_) => std::process::abort(),
        }
    }
}

pub(crate) struct RetainedStorageOwnerPostV1 {
    original: Result<(), BrokerSessionSecurityError>,
    floor: Result<(), BrokerSessionSecurityError>,
    endpoint: Result<(), BrokerSessionSecurityError>,
}

impl RetainedStorageOwnerPostV1 {
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_ref().err()
            .or_else(|| self.floor.as_ref().err())
            .or_else(|| self.endpoint.as_ref().err())
            .map(|error| error as &dyn std::error::Error)
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn observe_retained_storage_owner_v1(&mut self) -> RetainedStorageOwnerPostV1 {
        self.observe_retained_storage_owner_receiving_v3(None)
    }

    pub(crate) fn observe_retained_storage_owner_receiving_v3(&mut self,
        receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> RetainedStorageOwnerPostV1 {
        // Native's independent same-original observation checks the actual
        // held writer names. These Security posts keep the original floor and
        // protected endpoint current even when poll adopts no new transport.
        let original = self.retained_storage_journal_v1().map(|_| ());
        let floor = self.journal.require_floor_current_with_storage_receiving_v2(receiving);
        let endpoint = self.journal.endpoint.revalidate();
        RetainedStorageOwnerPostV1 { original, floor, endpoint }
    }
}

impl BrokerMainOpenV1 {
    pub(crate) fn retained_storage_handshake_demand_v1() -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let bytes = (3 * std::mem::size_of::<
            crate::production_service::ProductionOriginalStorageLifecycleSessionV1,
        >()) as u64;
        storage_receiving_demand::fixed_security_demand()?.checked_add(
            ResourceVector::ZERO.with(D::MemoryBytes, bytes),
        ).map_err(|_| BrokerSessionSecurityError::Currentness)
    }
}

use super::retired_storage_transcript::{
    RetiredStorageFirstRequestV1, RetiredStorageTranscriptPhaseV1, RetiredStorageTranscriptV1,
};

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn park_retired_storage_transcript_v1(
        &mut self,
        terminal: ProtectedBrokerOutcomeCommittedAdvancementV1,
        checkpoint: HistoricalSessionCheckpointV1,
    ) {
        self.park_retired_storage_currentness_v1(terminal.currentness_owner, checkpoint);
    }

    pub(crate) fn park_retired_storage_terminal_owner_v1(
        &mut self,
        terminal: super::super::RetainedStorageTerminalV1,
        checkpoint: HistoricalSessionCheckpointV1,
    ) {
        self.park_retired_storage_currentness_v1(terminal.currentness_owner, checkpoint);
    }

    fn park_retired_storage_currentness_v1(
        &mut self,
        original: super::super::ProtectedBrokerOutcomeCurrentnessOwnerV1,
        checkpoint: HistoricalSessionCheckpointV1,
    ) {
        // This final move is called only after exact terminal, floor, native,
        // same-socket End and all independent posts passed. The enclosing
        // Session consumes its original transport immediately after this move.
        let staged = match self.journal.storage_receiving_open.as_mut() {
            Some(staged) => staged,
            None => std::process::abort(),
        };
        if staged.retired_transcript.as_ref().is_some_and(|old|
            old.phase != RetiredStorageTranscriptPhaseV1::Consumed)
        {
            std::process::abort();
        }
        staged.retired_transcript = Some(RetiredStorageTranscriptV1 {
            endpoint: BrokerSessionDurableEndpointV1::Broker,
            protected_generation: original.protected_generation,
            protected_head: original.protected_head,
            protected_bindings: original.protected_bindings,
            peer_binding: original.peer_binding,
            session_binding: original.transcript.session_binding(),
            checkpoint,
            first_request: None,
            phase: RetiredStorageTranscriptPhaseV1::Pending,
        });
        // Successful terminal/control copies are now actually disposed. Full
        // signed request/outcome bytes remain in this SAME Journal authority;
        // no persistent-history credit or new request admission follows here.
    }
}

impl ProtectedBrokerSessionJournalV1 {
    pub(super) fn require_retired_storage_rollover_v1(
        &mut self,
        current: &StoredProtocolHistoryV1,
        history: &BrokerSessionDurableHistoryV1,
        next: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<bool, BrokerSessionSecurityError> {
        let retired = match self.endpoint.role() {
            BrokerSessionDurableEndpointV1::Client => self.client_retired_transcript.as_ref(),
            BrokerSessionDurableEndpointV1::Broker => self.storage_receiving_open.as_ref()
                .and_then(|opening| opening.retired_transcript.as_ref()),
        };
        let Some(retired) = retired else { return Ok(false); };
        if retired.phase == RetiredStorageTranscriptPhaseV1::Consumed {
            return Ok(false);
        }
        match retired.endpoint {
            BrokerSessionDurableEndpointV1::Broker => {
                self.retained_storage_broker_recipe_v1()?;
            }
            BrokerSessionDurableEndpointV1::Client => {
                self.retained_storage_client_recipe_v1()?;
            }
        }
        // Revalidate historical protected policy/key provenance on this actual
        // endpoint. This does not authenticate a new request as the old peer.
        let historical = self.endpoint.historical_context(retired.checkpoint.context())?;
        if &historical != retired.checkpoint.context() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        retired.require_exact_predecessor(current, history, next)?;
        Ok(true)
    }

    pub(super) fn bind_retired_storage_request_v1(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let retired = self.retired_storage_transcript_mut_v1()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if retired.phase != RetiredStorageTranscriptPhaseV1::Pending
            || retired.first_request.is_some()
            || request.direction() != request_direction_for_endpoint(retired.endpoint)
            || request.session_binding() == retired.session_binding
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        retired.first_request = Some(RetiredStorageFirstRequestV1 {
            signed_digest: request.signed_request_digest(),
            request_id: request.request_id(),
            session_binding: request.session_binding(),
            client_sequence: request.client_sequence(),
        });
        Ok(())
    }

    pub(super) fn require_retired_storage_initial_request_v1(
        &self,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let Some(retired) = self.retired_storage_transcript_v1()
        else {
            return Ok(());
        };
        if retired.phase == RetiredStorageTranscriptPhaseV1::Consumed {
            return Ok(());
        }
        if retired.phase != RetiredStorageTranscriptPhaseV1::Pending
            || !retired.first_request.as_ref().is_some_and(|first| first.matches(request))
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

    pub(super) fn mark_retired_storage_rollover_attempted_v1(&mut self) {
        let retired = match self.retired_storage_transcript_mut_v1()
        {
            Some(retired) if retired.phase == RetiredStorageTranscriptPhaseV1::Pending => retired,
            _ => std::process::abort(),
        };
        retired.phase = RetiredStorageTranscriptPhaseV1::Attempted;
    }

    pub(super) fn mark_retired_storage_rollover_consumed_v1(
        &mut self,
        recovery: &ProtectedBrokerSessionInitializationRecoveryV1,
    ) {
        if let Some(retired) = self.retired_storage_transcript_mut_v1()
        {
            if retired.matches_completed_initialization(recovery) {
                // Only the shared exact CAS/readback success reaches this cut.
                // The original checkpoint stays owned here. The protected
                // Journal retains its immutable old frames; ambiguity leaves
                // this predecessor Attempted beside the exact recovery target.
                retired.phase = RetiredStorageTranscriptPhaseV1::Consumed;
            }
        }
    }
}

#[cfg(test)]
#[path = "storage_session_continuation/rollover_tests.rs"]
mod rollover_tests;

// Actual Client consumers borrow this SAME held owner. These helpers neither
// reopen a name nor admit resources, sign a request or create a Session.
impl ProtectedBrokerSessionJournalV1 {
    pub(super) fn retained_storage_client_recipe_v1(&self) -> Result<(), BrokerSessionSecurityError> {
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient);
        if !matches!(self.owner, JournalOwnerV1::ServiceClient(_))
            || self.directory != Path::new(fixed.journal_root)
            || self.name != PROTECTED_SESSION_JOURNAL
            || self.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || self.endpoint.protected_protocol_and_node().0 != BrokerSessionProtocolV1::Storage
            || self.limits != protected_session_journal_limits()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn retained_storage_client_journal_v1(&self) -> Result<&Journal, BrokerSessionSecurityError> {
        self.journal.retained_storage_client_recipe_v1()?;
        self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn retained_storage_client_journal_mut_v3(&mut self) -> Result<&mut Journal, BrokerSessionSecurityError> {
        self.journal.retained_storage_client_recipe_v1()?;
        self.journal.journal.as_mut().ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn retained_storage_client_stored_v1(&self)
        -> Result<&[u8], BrokerSessionSecurityError>
    {
        self.retained_storage_client_journal_v1()?;
        self.journal.storage_prepare_current_stored()
    }

    pub(crate) fn retained_storage_client_endpoint_v1(&self) -> &ProtectedBrokerSessionClientV1 {
        match &self.journal.endpoint {
            ProtectedEndpointV1::Client(endpoint) => endpoint,
            ProtectedEndpointV1::Broker(_) => std::process::abort(),
        }
    }

    pub(crate) fn retained_storage_client_endpoint_mut_v1(&mut self) -> &mut ProtectedBrokerSessionClientV1 {
        match &mut self.journal.endpoint {
            ProtectedEndpointV1::Client(endpoint) => endpoint,
            ProtectedEndpointV1::Broker(_) => std::process::abort(),
        }
    }
}
