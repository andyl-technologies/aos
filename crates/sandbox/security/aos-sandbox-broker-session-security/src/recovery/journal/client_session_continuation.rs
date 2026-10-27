//! Captures the actual held Client terminal for positive same-owner rollover.
//!
//! The genuine J turn pays held-history/model geometry before this existing
//! canonical replay engine runs. Captured typed owners remain here through all
//! independent posts. These comparison originals grant no method/effect authority.

use super::*;
use super::request_current::RetainedRequestOriginalsV1;
use crate::recovery::{ReopenCurrentOriginalsV1, TerminalSemanticsOriginalsV1};
use aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointVerifyCaptureV1;
use aos_sandbox_broker_session_protocol::{BrokerSessionPeerBindingV1, BrokerSessionProtectedBindingsV1};
use super::retired_storage_transcript::{
    RetiredStorageTranscriptPhaseV1, RetiredStorageTranscriptV1,
};

impl ProtectedBrokerSessionJournalV1 {
    pub(super) fn retired_storage_transcript_v1(&self) -> Option<&RetiredStorageTranscriptV1> {
        match self.endpoint.role() {
            BrokerSessionDurableEndpointV1::Client => self.client_retired_transcript.as_ref(),
            BrokerSessionDurableEndpointV1::Broker => self.storage_receiving_open.as_ref()
                .and_then(|opening| opening.retired_transcript.as_ref()),
        }
    }

    pub(super) fn retired_storage_transcript_mut_v1(&mut self) -> Option<&mut RetiredStorageTranscriptV1> {
        match self.endpoint.role() {
            BrokerSessionDurableEndpointV1::Client => self.client_retired_transcript.as_mut(),
            BrokerSessionDurableEndpointV1::Broker => self.storage_receiving_open.as_mut()
                .and_then(|opening| opening.retired_transcript.as_mut()),
        }
    }

    pub(super) fn retained_storage_broker_recipe_v1(&self) -> Result<(), BrokerSessionSecurityError> {
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageBroker);
        if self.owner != JournalOwnerV1::RootBroker
            || self.directory != Path::new(fixed.journal_root)
            || self.name != PROTECTED_SESSION_JOURNAL
            || self.endpoint.role() != BrokerSessionDurableEndpointV1::Broker
            || !self.storage_receiving_open.as_ref().is_some_and(|staged|
                matches!(staged.native_settlement, Some(Ok(()))))
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }

}


#[derive(Default)]
pub(crate) struct RetainedStorageClientTerminalOriginalV1 {
    recipe: Option<Result<(), BrokerSessionSecurityError>>,
    checkpoint_verification: HistoricalSessionCheckpointVerifyCaptureV1,
    context: CurrentContextOriginalsV1,
    peer: CurrentPeerOriginalsV1,
    storage_present: Option<Result<bool, BrokerSessionSecurityError>>,
    absence_before: StoredReadOriginalsV1,
    absence_after: StoredReadOriginalsV1,
    replay: ReopenCurrentOriginalsV1,
    request: RetainedRequestOriginalsV1,
    outcome: TerminalSemanticsOriginalsV1,
    after_peer: CurrentPeerOriginalsV1,
    comparison: Option<Result<(), BrokerSessionSecurityError>>,
    protected: Option<Result<BrokerSessionProtectedBindingsV1, BrokerSessionSecurityError>>,
    coordinates: Option<(u64, [u8; 32], BrokerSessionProtectedBindingsV1, BrokerSessionPeerBindingV1)>,
}

impl RetainedStorageClientTerminalOriginalV1 {
    pub(crate) fn retained_endpoint_open_files_v1() -> Option<usize> {
        CurrentPeerOriginalsV1::retained_endpoint_open_files_v1()?.checked_mul(2)
    }

    pub(crate) fn receiving_partial_footprint_v1() -> Option<(usize, usize)> {
        let (replay_bytes, replay_cells) = crate::recovery::retained_current_replay_footprint_v1()?;
        let (context_bytes, context_cells) = CurrentContextOriginalsV1::receiving_footprint_v1()?;
        let (peer_bytes, peer_cells) = CurrentPeerOriginalsV1::receiving_footprint_v1()?;
        let (terminal_bytes, terminal_cells) = TerminalSemanticsOriginalsV1::receiving_footprint_v1()?;
        let (request_bytes, request_cells) = RetainedRequestOriginalsV1::receiving_footprint_v1()?;
        let absent_bytes = StoredReadOriginalsV1::receiving_fixed_backing_bytes_v1()?.checked_mul(2)?
            .checked_add(StoredReadOriginalsV1::construction_bytes_v1()?)?;
        let absent_cells = StoredReadOriginalsV1::receiving_metadata_cells_v1()?.checked_mul(2)?;
        // Actual presence selects exactly one branch. Positive checkpoint
        // verification precedes and remains resident beside either branch.
        let bytes = replay_bytes.max(absent_bytes)
            .checked_add(HistoricalSessionCheckpointVerifyCaptureV1::construction_bytes_v1())?
            .checked_add(context_bytes)?
            .checked_add(peer_bytes.checked_mul(2)?)?
            .checked_add(terminal_bytes)?
            .checked_add(request_bytes)?;
        let cells = replay_cells.max(absent_cells)
            .checked_add(HistoricalSessionCheckpointVerifyCaptureV1::receiving_metadata_cells_v1()?)?
            // Fourteen outer Terminal destinations are distinct from
            // their embedded helper field/control censuses.
            .checked_add(14)?
            .checked_add(context_cells)?
            .checked_add(peer_cells.checked_mul(2)?)?
            .checked_add(terminal_cells)?
            .checked_add(request_cells)?;
        Some((bytes, cells))
    }

    pub(crate) fn observe_once(
        &mut self,
        owner: &mut ProtectedBrokerSessionOwnerV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        checkpoint: &HistoricalSessionCheckpointV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.recipe.is_some() { return Err(BrokerSessionSecurityError::Currentness); }
        let journal = &mut owner.journal;
        self.recipe = Some((|| {
            journal.retained_storage_client_recipe_v1()?;
            checkpoint.verify_retaining(&mut self.checkpoint_verification)?;
            if transcript.protocol() != BrokerSessionProtocolV1::Storage
                || transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
                || self.checkpoint_verification.transcript() != Some(transcript)
                || journal.client_retired_transcript.as_ref().is_some_and(|retired|
                    retired.phase != RetiredStorageTranscriptPhaseV1::Consumed)
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Ok(())
        })());
        if !matches!(self.recipe, Some(Ok(()))) { return Err(BrokerSessionSecurityError::Currentness); }

        self.context.observe_once(journal, transcript)?;
        let context = self.context.value().ok_or(BrokerSessionSecurityError::Currentness)?;
        self.peer.observe_once(journal, transcript, connection_peer)?;
        let peer = self.peer.value().ok_or(BrokerSessionSecurityError::Currentness)?;
        // HELLO precedes the first request. Such an actual Session may have no
        // Storage traffic row at all; no fictitious initialized row is made.
        self.storage_present = Some(journal.journal.as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)
            .map(|native| native.get(RecordNamespace::BrokerSessionTraffic,
                &protocol_key(BrokerSessionProtocolV1::Storage)).is_some()));
        if matches!(self.storage_present, Some(Ok(false))) {
            self.absence_before.observe_optional_once(journal)?;
            if !self.absence_before.is_absent() {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            self.absence_after.observe_optional_once(journal)?;
            if !self.absence_after.is_absent() {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let _ = self.after_peer.observe_once(journal, transcript, connection_peer);
            self.comparison = Some((|| {
                let after_peer = self.after_peer.value()
                    .ok_or(BrokerSessionSecurityError::Currentness)?;
                if !self.absence_before.is_absent()
                    || !self.absence_after.is_absent()
                    || journal.client_retired_transcript.is_some()
                    || peer.binding(BrokerSessionDurableEndpointV1::Client, transcript, context)?
                        != after_peer.binding(BrokerSessionDurableEndpointV1::Client, transcript, context)?
                {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                Ok(())
            })());
            return if matches!(self.comparison, Some(Ok(()))) { Ok(()) }
                else { Err(BrokerSessionSecurityError::Currentness) };
        }
        if !matches!(self.storage_present, Some(Ok(true))) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        // The same existing canonical history/traffic/readback engine supplies
        // every row and exact current protected coordinates. No second parser.
        self.replay.observe_once(journal, transcript, context, peer)?;
        let (history, traffic, _) = self.replay.values()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let credentials = connection_peer.credentials();
        let peer_data = aos_sandbox_protocol::PeerCredentials {
            uid: credentials.uid(), gid: credentials.gid(), pid: Some(credentials.pid().get()),
        };
        let policy = aos_sandbox_protocol::PeerPolicy {
            uid: credentials.uid(), gid: Some(credentials.gid()), audience: context.audience(),
        };
        self.request.observe_once(history, transcript, context, peer_data, policy,
            AuthenticatedBrokerRequestDirectionV1::ClientSend)?;
        let request = self.request.value().ok_or(BrokerSessionSecurityError::Currentness)?;
        self.outcome.observe_once(history, request, transcript, context, traffic)?;
        self.protected = self.replay.values()
            .map(|(_, _, current)| current.protected_bindings(checkpoint.context()));
        let _ = self.after_peer.observe_once(journal, transcript, connection_peer);
        self.comparison = Some((|| {
            let (_, traffic, current) = self.replay.values()
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let head = history.head().map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let peer_binding = peer.binding(BrokerSessionDurableEndpointV1::Client, transcript, context)?;
            let after_peer = self.after_peer.value()
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            if head.endpoint() != BrokerSessionDurableEndpointV1::Client
                || head.phase() != BrokerSessionDurablePhaseV1::Terminal
                || traffic.has_outstanding_request()
                || current.current_head != history.head_commitment()
                || head.peer_binding() != peer_binding
                || after_peer.binding(BrokerSessionDurableEndpointV1::Client, transcript, context)? != peer_binding
                || !request_matches_head(request, head, AuthenticatedBrokerRequestDirectionV1::ClientSend)
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let protected = self.protected.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or(BrokerSessionSecurityError::Currentness)?;
            self.coordinates = Some((current.generation, current.current_head, protected, head.peer_binding()));
            Ok(())
        })());
        if matches!(self.comparison, Some(Ok(()))) { Ok(()) }
        else { Err(BrokerSessionSecurityError::Currentness) }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.checkpoint_verification.failure().map(|cause| cause as _)
            .or_else(|| error(&self.recipe)).or_else(|| self.context.failure())
            .or_else(|| self.peer.failure())
            .or_else(|| error(&self.storage_present))
            .or_else(|| self.absence_before.failure()).or_else(|| self.absence_after.failure())
            .or_else(|| self.replay.failure()).or_else(|| self.request.failure())
            .or_else(|| self.outcome.failure()).or_else(|| error(&self.protected))
            .or_else(|| self.after_peer.failure())
            .or_else(|| error(&self.comparison))
    }

    // Sole actual positive disposal consumer calls this after all fallible
    // terminal/Native/End/floor/endpoint/peer posts, while the same Journal and
    // checkpoint remain owned. It cannot be invoked with historical DATA.
    pub(crate) fn into_retired_predecessor(
        self,
        checkpoint: HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Option<RetiredStorageTranscriptV1> {
        if !matches!(self.comparison, Some(Ok(()))) { std::process::abort(); }
        if matches!(self.storage_present, Some(Ok(false))) {
            if !self.absence_before.is_absent()
                || !self.absence_after.is_absent()
            {
                std::process::abort();
            }
            // All positive End/native/subject posts precede this move. There
            // is no old traffic head to replace and therefore no retired-head
            // authority to install. The SAME held Journal still has absence;
            // its first new request uses the unchanged exact-absence CAS.
            drop(checkpoint);
            return None;
        }
        let (generation, head, protected_bindings, peer_binding) = match self.coordinates {
            Some(coordinates) => coordinates,
            None => std::process::abort(),
        };
        Some(RetiredStorageTranscriptV1 {
            endpoint: BrokerSessionDurableEndpointV1::Client,
            protected_generation: generation,
            protected_head: head,
            protected_bindings,
            peer_binding,
            session_binding: transcript.session_binding(),
            checkpoint, first_request: None, phase: RetiredStorageTranscriptPhaseV1::Pending,
        })
    }
}

fn error<T>(result: &Option<Result<T, BrokerSessionSecurityError>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

/// Owns the independent retained Client floor/endpoint/peer observations.
pub(crate) struct RetainedStorageClientOwnerPostV1 {
    recipe: Result<(), BrokerSessionSecurityError>,
    floor: Result<(), BrokerSessionSecurityError>,
    endpoint: Result<(), BrokerSessionSecurityError>,
    endpoint_native: crate::endpoint::RetainedEndpointRevalidationOriginalV1,
    peer: CurrentPeerOriginalsV1,
}

impl RetainedStorageClientOwnerPostV1 {
    pub(crate) fn retained_endpoint_open_files_v1() -> Option<usize> {
        let one = usize::try_from(crate::endpoint::RetainedEndpointRevalidationOriginalV1::receiving_demand_v1()?
            .get(aos_sandbox_model::ResourceDimension::OpenFiles)).ok()?;
        CurrentPeerOriginalsV1::retained_endpoint_open_files_v1()?.checked_add(one)
    }

    pub(crate) fn receiving_peer_footprint_v1() -> Option<(usize, usize)> {
        let (bytes, cells) = CurrentPeerOriginalsV1::receiving_footprint_v1()?;
        // Recipe, floor, endpoint and the embedded peer destination coexist.
        let endpoint_bytes = usize::try_from(
            crate::endpoint::RetainedEndpointRevalidationOriginalV1::receiving_demand_v1()?
                .get(aos_sandbox_model::ResourceDimension::MemoryBytes)).ok()?;
        Some((bytes.checked_add(endpoint_bytes)?, cells.checked_add(4)?))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.recipe.as_ref().err().map(|cause| cause as &dyn std::error::Error)
            .or_else(|| self.floor.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.endpoint_native.failure())
            .or_else(|| self.endpoint.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.peer.failure())
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn execution_availability_client_journal_v2(&self) -> Result<&Journal, BrokerSessionSecurityError> {
        self.journal.retained_execution_client_recipe_v2()?;
        self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn execution_availability_client_stored_v2(&self) -> Result<&[u8], BrokerSessionSecurityError> {
        self.execution_availability_client_journal_v2()?
            .get(RecordNamespace::BrokerSessionTraffic,
                &protocol_key(self.journal.endpoint.protected_protocol_and_node().0))
            .ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn observe_execution_availability_client_owner_v2(&mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1, peer: &ConnectionPeerIdentity,
    ) -> RetainedStorageClientOwnerPostV1 {
        self.observe_retained_client_owner_inner_v1(transcript, peer, RetainedClientPostPurposeV1::Execution)
    }

    pub(crate) fn compare_execution_availability_predecessor_v2(&mut self,
        currentness: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity,
        originals: &mut OutcomeCurrentOriginalsV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.journal.retained_execution_client_recipe_v2()?;
        require_execution_availability_terminal_v2(currentness)?;
        originals.observe_execution_once_v1(&mut self.journal, currentness, peer)
    }

    pub(crate) fn observe_retained_storage_client_owner_v1(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> RetainedStorageClientOwnerPostV1 {
        self.observe_retained_client_owner_inner_v1(transcript, connection_peer,
            RetainedClientPostPurposeV1::Storage)
    }

    pub(crate) fn observe_retained_resource_client_owner_v2(
        &mut self, transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> RetainedStorageClientOwnerPostV1 {
        self.observe_retained_client_owner_inner_v1(transcript, connection_peer,
            RetainedClientPostPurposeV1::StartResource)
    }

    pub(crate) fn observe_retained_delete_network_client_owner_v4(
        &mut self, transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity,
    ) -> RetainedStorageClientOwnerPostV1 {
        self.observe_retained_client_owner_inner_v1(transcript, peer, RetainedClientPostPurposeV1::DeleteNetwork)
    }

    pub(crate) fn observe_retained_delete_mount_client_owner_v4(
        &mut self, transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity,
    ) -> RetainedStorageClientOwnerPostV1 {
        self.observe_retained_client_owner_inner_v1(transcript, peer, RetainedClientPostPurposeV1::DeleteMount)
    }

    pub(crate) fn observe_catalog_maintenance_client_owner_v2(
        &mut self, transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> RetainedStorageClientOwnerPostV1 {
        self.observe_retained_client_owner_inner_v1(transcript, connection_peer,
            RetainedClientPostPurposeV1::CatalogMaintenance)
    }

    fn observe_retained_client_owner_inner_v1(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        purpose: RetainedClientPostPurposeV1,
    ) -> RetainedStorageClientOwnerPostV1 {
        let recipe = purpose.require_recipe(&self.journal, transcript);
        let floor = self.journal.require_floor_current();
        let mut endpoint_native = crate::endpoint::RetainedEndpointRevalidationOriginalV1::default();
        let endpoint = self.journal.endpoint.revalidate_into_v1(&mut endpoint_native);
        let mut peer = CurrentPeerOriginalsV1::default();
        let _ = peer.observe_once(&mut self.journal, transcript, connection_peer);
        RetainedStorageClientOwnerPostV1 { recipe, floor, endpoint, endpoint_native, peer }
    }

    pub(crate) fn observe_retained_storage_client_failed_entry_v1(&mut self)
        -> RetainedStorageClientOwnerPostV1
    {
        let recipe = self.journal.retained_storage_client_recipe_v1();
        let floor = self.journal.require_floor_current();
        let mut endpoint_native = crate::endpoint::RetainedEndpointRevalidationOriginalV1::default();
        let endpoint = self.journal.endpoint.revalidate_into_v1(&mut endpoint_native);
        RetainedStorageClientOwnerPostV1 {
            recipe, floor, endpoint, endpoint_native, peer: CurrentPeerOriginalsV1::default(),
        }
    }

    pub(crate) fn retained_storage_client_failure_for_v1<'cause>(
        &'cause self,
        error: &'cause BrokerSessionSecurityError,
    ) -> &'cause (dyn std::error::Error + 'static) {
        self.retained_revalidation_failure_for(error)
            .or_else(|| self.retained_storage_floor_revalidation_failure_for(error))
            .unwrap_or(error)
    }


    pub(crate) fn park_retired_storage_client_transcript_v1(
        &mut self,
        terminal: RetainedStorageClientTerminalOriginalV1,
        checkpoint: HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) {
        if self.journal.retained_storage_client_recipe_v1().is_err()
            || self.journal.client_retired_transcript.as_ref().is_some_and(|previous|
                previous.phase != RetiredStorageTranscriptPhaseV1::Consumed)
        {
            std::process::abort();
        }
        self.journal.client_retired_transcript = terminal.into_retired_predecessor(checkpoint, transcript);
    }
}


// The same native observation engine serves the old Storage continuation and
// the closed Controller execution clients. No caller path or purpose is a grant.
#[derive(Clone, Copy)]
enum RetainedClientPostPurposeV1 { Storage, Execution, FixedService, StartResource, CatalogMaintenance, DeleteNetwork, DeleteMount }

impl ProtectedBrokerOutcomeCommittedAdvancementV1 {
    pub(crate) fn maintenance_storage_client_originals_v3(
        &self,
        inventory: bool,
    ) -> Result<
        (
            &AuthenticatedBrokerMethodOutcomeV1,
            &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        ),
        BrokerSessionSecurityError,
    > {
        let method = if inventory {
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
        } else {
            BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT
        };
        // The same complete Storage lifecycle profile, directions, signed
        // request/outcome method and original currentness owner are checked by
        // the existing engine. This distinct caller creates no Start owner.
        self.provisioning_client_originals_engine_v4(method, true, false)
    }
}

impl RetainedClientPostPurposeV1 {
    fn require_recipe(self, journal: &ProtectedBrokerSessionJournalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1) -> Result<(), BrokerSessionSecurityError>
    {
        if matches!(self, Self::Storage) { return journal.retained_storage_client_recipe_v1(); }
        if matches!(self, Self::FixedService) { return journal.fixed_service_server_recipe_v4(transcript); }
        if matches!(self, Self::Execution) {
            if journal.endpoint.protected_protocol_and_node().0 != transcript.protocol() {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            return journal.retained_execution_client_recipe_v2();
        }
        if matches!(self, Self::DeleteNetwork)
            && (transcript.protocol() != BrokerSessionProtocolV1::Network
                || transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
                || !transcript.negotiated_methods().contains(&BrokerMethod::BROKER_METHOD_NETWORK_APPLY)) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if matches!(self, Self::DeleteMount)
            && (transcript.protocol() != BrokerSessionProtocolV1::Mount
                || transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
                || !transcript.negotiated_methods().contains(&BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1)) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if matches!(self, Self::CatalogMaintenance)
            && (transcript.protocol() != BrokerSessionProtocolV1::Host
                || !transcript.negotiated_methods().contains(&BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG)) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if matches!(self, Self::StartResource)
            && !aos_sandbox_broker_session_protocol::profile::is_start_resource_transcript_v2(transcript) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        if matches!(self, Self::StartResource) && transcript.protocol() == BrokerSessionProtocolV1::Storage {
            // Reuse the same held Storage floor/endpoint engine. No new fixed
            // ServiceClient recipe or Storage Session is constructed here.
            return journal.retained_storage_client_recipe_v1();
        }
        let role = match transcript.protocol() {
            BrokerSessionProtocolV1::Host => ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient,
            BrokerSessionProtocolV1::Storage => ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
            BrokerSessionProtocolV1::Network if matches!(self, Self::StartResource | Self::DeleteNetwork) => ProtectedBrokerSessionFixedEndpointV1::ControllerNetworkClient,
            BrokerSessionProtocolV1::Mount if matches!(self, Self::StartResource | Self::DeleteMount) => ProtectedBrokerSessionFixedEndpointV1::ControllerMountClient,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        if !matches!(journal.owner, JournalOwnerV1::ServiceClient(_))
            || journal.directory != Path::new(fixed_endpoint(role).journal_root)
            || journal.name != PROTECTED_SESSION_JOURNAL
            || journal.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || journal.endpoint.protected_protocol_and_node().0 != transcript.protocol()
            || journal.limits != protected_session_journal_limits()
        { return Err(BrokerSessionSecurityError::Currentness); }
        Ok(())
    }
}

impl ProtectedBrokerSessionJournalV1 {
    // This is the existing Execution physical recipe shared by both client
    // endpoints. The genuine C18 loan separately binds actual64/65 purpose,
    // current transcript/socket, native first clock and financial ownership.
    fn retained_execution_client_recipe_v2(&self) -> Result<(), BrokerSessionSecurityError> {
        let role = match self.endpoint.protected_protocol_and_node().0 {
            BrokerSessionProtocolV1::Host => ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient,
            BrokerSessionProtocolV1::Storage => ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        if !matches!(self.owner, JournalOwnerV1::ServiceClient(_))
            || self.directory != Path::new(fixed_endpoint(role).journal_root)
            || self.name != PROTECTED_SESSION_JOURNAL
            || self.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || self.limits != protected_session_journal_limits()
        { return Err(BrokerSessionSecurityError::Currentness); }
        Ok(())
    }
}

fn require_execution_availability_terminal_v2(owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1)
    -> Result<(), BrokerSessionSecurityError>
{
    let method = match owner.transcript.protocol() {
        BrokerSessionProtocolV1::Host => BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2,
        BrokerSessionProtocolV1::Storage => BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2,
        _ => return Err(BrokerSessionSecurityError::Currentness),
    };
    if owner.transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        || !owner.transcript.negotiated_methods().contains(&method)
        || owner.request.method() != method || owner.outcome.method() != method
        || owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
        || owner.outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || owner.request.authorization().is_some() || owner.request.execution_availability_data_v2().is_none()
    { return Err(BrokerSessionSecurityError::Currentness); }
    Ok(())
}

impl ProtectedBrokerOutcomeCommittedAdvancementV1 {
    pub(crate) fn execution_availability_client_originals_v2(&self)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError>
    {
        require_execution_availability_terminal_v2(&self.currentness_owner)?;
        Ok((&self.currentness_owner.outcome, &self.currentness_owner))
    }
}

/// Retains one prearmed negative-capable post of the same execution Session.
///
/// Prearming only captures comparison DATA. The real C18 caller pays its fixed
/// native geometry before arming and keeps the socket, writer and transcript
/// resident through completion. No result here authorizes an effect.
#[derive(Default)]
pub struct ExecutionClientPostOriginalV1 {
    binding: Option<ExecutionClientPostBindingV1>,
    arm: Option<Result<(), BrokerSessionSecurityError>>,
    comparison: Option<Result<(), BrokerSessionSecurityError>>,
    post: Option<RetainedStorageClientOwnerPostV1>,
    terminal_before: [OutcomeCurrentOriginalsV1; 2],
    terminal_before_used: usize,
    terminal_after: OutcomeCurrentOriginalsV1,
    covered_by_terminal: bool,
    finished: bool,
    closed: Option<BrokerSessionSecurityError>,
}

struct ExecutionClientPostBindingV1 {
    journal: aos_sandbox_controller_domain::journal::JournalAuthorityComparisonStampV1,
    socket: std::os::fd::RawFd,
    transcript: [u8; 32],
}

impl ExecutionClientPostOriginalV1 {
    /// Describes the actual retained native post without funding or admission.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let (peer_bytes, _) = RetainedStorageClientOwnerPostV1::receiving_peer_footprint_v1()?;
        let endpoint = crate::endpoint::endpoint_revalidation_footprint_v1()?;
        let floor = crate::recovery::floor_revalidation_footprint_v1()?;
        let (terminal_bytes, _) = OutcomeCurrentOriginalsV1::receiving_footprint_v1()?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(terminal_bytes.checked_mul(3)?)?
            .checked_add(peer_bytes)?
            .checked_add(endpoint.inline_bytes)?.checked_add(endpoint.heap_bytes)?
            .checked_add(floor.inline_bytes)?.checked_add(floor.heap_bytes)?;
        let files = endpoint.file_descriptors.checked_add(floor.file_descriptors)?
            .checked_add(RetainedStorageClientOwnerPostV1::retained_endpoint_open_files_v1()?
                .max(OutcomeCurrentOriginalsV1::retained_endpoint_open_files_v1()?))?;
        // Native Result/control carriers have no namespace entry charge.
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?))
    }

    /// Borrows the original refusal before its later independently owed post.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.arm.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _)
            .or_else(|| self.comparison.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _))
            .or_else(|| self.terminal_before.iter().find_map(OutcomeCurrentOriginalsV1::failure))
            .or_else(|| self.terminal_after.failure())
            .or_else(|| self.post.as_ref().and_then(|v| v.failure()))
            .or_else(|| self.closed.as_ref().map(|e| e as _))
    }

    /// Borrows the actual entered terminal-before validator cause.
    #[must_use]
    pub fn terminal_before_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.terminal_before.iter().find_map(OutcomeCurrentOriginalsV1::failure)
    }

    /// Borrows the distinct entered terminal-after validator cause.
    #[must_use]
    pub fn terminal_after_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.terminal_after.failure()
    }

    pub(super) fn observe_terminal_before_v1(&mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        let original = self.terminal_before.get_mut(self.terminal_before_used)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        self.terminal_before_used = self.terminal_before_used.checked_add(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        original.observe_execution_once_v1(journal, owner, peer)
    }

    pub(in crate::recovery) fn observe_terminal_after_v1(&mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        let binding = self.binding.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        let native = journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        if !self.covered_by_terminal || self.finished || self.closed.is_some()
            || binding.transcript != owner.transcript.session_binding()
            || !native.matches_authority_comparison_stamp_v1(&binding.journal)
        { return Err(BrokerSessionSecurityError::Currentness); }
        self.terminal_after.observe_execution_once_v1(journal, owner, peer)
    }

    pub(super) fn cover_terminal_once_v1(&mut self, journal: &ProtectedBrokerSessionJournalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1, socket: std::os::fd::RawFd)
        -> Result<(), BrokerSessionSecurityError>
    {
        let binding = self.binding.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        let native = journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        if self.finished || self.terminal_before_used >= self.terminal_before.len()
            || self.terminal_before.iter().any(|original| original.failure().is_some())
            || !matches!(self.arm, Some(Ok(())))
            || self.closed.is_some() || binding.socket != socket
            || binding.transcript != transcript.session_binding()
            || !native.matches_authority_comparison_stamp_v1(&binding.journal)
        { return Err(BrokerSessionSecurityError::Currentness); }
        RetainedClientPostPurposeV1::Execution.require_recipe(journal, transcript)?;
        self.covered_by_terminal = true;
        Ok(())
    }

    pub(super) fn require_binding_v1(&self, owner: &ProtectedBrokerSessionOwnerV1,
        transcript: &VerifiedBrokerSessionTranscriptV1, socket: std::os::fd::RawFd)
        -> Result<(), BrokerSessionSecurityError>
    {
        let binding = self.binding.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        let journal = owner.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
        if !matches!(self.arm, Some(Ok(()))) || self.finished || self.closed.is_some()
            || binding.socket != socket || binding.transcript != transcript.session_binding()
            || !journal.matches_authority_comparison_stamp_v1(&binding.journal)
        { return Err(BrokerSessionSecurityError::Currentness); }
        RetainedClientPostPurposeV1::Execution.require_recipe(&owner.journal, transcript)
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    /// Arms the same native post from the actual Session's borrowed socket.
    pub(crate) fn arm_execution_client_socket_post_v1(
        &self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        socket: Option<std::os::fd::BorrowedFd<'_>>,
        original: &mut ExecutionClientPostOriginalV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        use std::os::fd::AsRawFd;

        let socket = socket.ok_or(BrokerSessionSecurityError::Currentness)?;
        self.arm_execution_client_post_v1(transcript, socket.as_raw_fd(), original)
    }

    /// Runs the owed post even when the actual Session socket has closed.
    pub(crate) fn finish_execution_client_socket_post_v1(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity,
        socket: Option<std::os::fd::BorrowedFd<'_>>,
        original: &mut ExecutionClientPostOriginalV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        use std::os::fd::AsRawFd;

        // A closed socket is comparison DATA; the armed post remains owed.
        let socket = socket.map(|socket| socket.as_raw_fd()).unwrap_or(-1);
        self.finish_execution_client_post_v1(transcript, peer, socket, original)
    }

    fn arm_execution_client_post_v1(&self,
        transcript: &VerifiedBrokerSessionTranscriptV1, socket: std::os::fd::RawFd,
        original: &mut ExecutionClientPostOriginalV1) -> Result<(), BrokerSessionSecurityError>
    {
        if original.arm.is_some() || original.closed.is_some() {
            original.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        original.arm = Some((|| {
            RetainedClientPostPurposeV1::Execution.require_recipe(&self.journal, transcript)?;
            let journal = self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
            original.binding = Some(ExecutionClientPostBindingV1 {
                journal: journal.authority_comparison_stamp_v1(), socket,
                transcript: transcript.session_binding(),
            });
            Ok(())
        })());
        if matches!(original.arm, Some(Ok(()))) { Ok(()) }
        else { Err(BrokerSessionSecurityError::Currentness) }
    }

    fn finish_execution_client_post_v1(&mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1, peer: &ConnectionPeerIdentity,
        socket: std::os::fd::RawFd, original: &mut ExecutionClientPostOriginalV1)
        -> Result<(), BrokerSessionSecurityError>
    {
        if original.finished || original.arm.is_none() {
            original.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        original.comparison = Some(original.require_binding_v1(self, transcript, socket));
        // A reached complete validator owns its own prepaid independent after.
        // Otherwise the original early-entry interval still owes this native post.
        if !original.covered_by_terminal {
            original.post = Some(self.observe_retained_client_owner_inner_v1(
                transcript, peer, RetainedClientPostPurposeV1::Execution));
        }
        original.finished = true;
        if original.failure().is_none() { Ok(()) }
        else { Err(BrokerSessionSecurityError::Currentness) }
    }
}

#[cfg(test)]
mod execution_post_tests {
    use super::*;
    use super::super::lifecycle_test_fixture::LifecycleTerminalFixture;
    use std::os::fd::AsRawFd;

    #[test]
    fn prearmed_post_survives_owner_move_and_runs_after_an_early_refusal() {
        let fixture = LifecycleTerminalFixture::new();
        let transcript = fixture.currentness.as_ref().unwrap().transcript.clone();
        let socket = fixture.socket.as_fd().unwrap().as_raw_fd();
        let mut owner = ProtectedBrokerSessionOwnerV1 { journal: fixture.journal };
        // Only the fixed-recipe comparison locator changes. The fixture keeps
        // its real temporary native writer, signed endpoints and kernel peer.
        owner.journal.directory = PathBuf::from(fixed_endpoint(
            ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient).journal_root);
        let mut original = ExecutionClientPostOriginalV1::default();
        owner.arm_execution_client_post_v1(&transcript, socket, &mut original).unwrap();

        let mut moved_owner = Box::new(owner);
        LifecycleTerminalFixture::replace_client_key(&fixture.client_path);
        assert!(moved_owner.finish_execution_client_post_v1(
            &transcript, fixture.socket.peer(), socket, &mut original).is_err());

        assert!(matches!(original.comparison, Some(Ok(()))));
        let post = original.post.as_ref().unwrap();
        assert!(post.endpoint.is_err());
        assert!(post.peer.failure().is_some());
        // The changed held key refuses before the fresh directory is opened.
        // Both complete held-manifest reads must still survive that refusal.
        assert_eq!(post.endpoint_native.retained_file_count_v1(), 0);
        let (first, repeated) = post.endpoint_native.retained_manifest_pair_v1().unwrap();
        assert!(!first.is_empty());
        assert_eq!(first, repeated);
        let retained = first.as_ptr();
        assert!(original.failure().is_some());
        assert!(moved_owner.arm_execution_client_post_v1(
            &transcript, socket, &mut original).is_err());
        assert_eq!(original.post.as_ref().unwrap().endpoint_native
            .retained_manifest_pair_v1().unwrap().0.as_ptr(), retained);
    }

    #[test]
    fn replaced_journal_refuses_the_stamp_but_does_not_suppress_the_owed_post() {
        let fixture = LifecycleTerminalFixture::new();
        let transcript = fixture.currentness.as_ref().unwrap().transcript.clone();
        let socket = fixture.socket.as_fd().unwrap().as_raw_fd();
        let mut owner = ProtectedBrokerSessionOwnerV1 { journal: fixture.journal };
        owner.journal.directory = PathBuf::from(fixed_endpoint(
            ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient).journal_root);
        let mut original = ExecutionClientPostOriginalV1::default();
        owner.arm_execution_client_post_v1(&transcript, socket, &mut original).unwrap();
        let replacement = LifecycleTerminalFixture::new();
        owner.journal.journal = replacement.journal.journal;

        assert!(owner.finish_execution_client_post_v1(
            &transcript, fixture.socket.peer(), socket, &mut original).is_err());

        assert!(matches!(original.comparison, Some(Err(_))));
        assert!(original.post.is_some());
        assert!(original.finished);
    }
}

/// Retains both native Session bookends of one enrolled fixed-service request.
///
/// The same floor, endpoint and CurrentPeer engines serve each independently
/// prearmed destination. The passive stamp survives moves of the real Journal
/// and refuses compaction/replacement. No request, role or effect is admitted
/// by this comparison owner.
#[derive(Default)]
pub(crate) struct FixedServiceSessionPostOriginalV4 {
    binding: Option<ExecutionClientPostBindingV1>,
    arm: Option<Result<(), BrokerSessionSecurityError>>,
    comparison: Option<Result<(), BrokerSessionSecurityError>>,
    before: Option<RetainedStorageClientOwnerPostV1>,
    after: Option<RetainedStorageClientOwnerPostV1>,
    finished: bool,
    closed: Option<BrokerSessionSecurityError>,
}

impl FixedServiceSessionPostOriginalV4 {
    pub(crate) fn receiving_demand_v4() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let (post, _) = RetainedStorageClientOwnerPostV1::receiving_peer_footprint_v1()?;
        let endpoint = crate::endpoint::endpoint_revalidation_footprint_v1()?;
        let floor = crate::recovery::floor_revalidation_footprint_v1()?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(post.checked_mul(2)?)?
            .checked_add(endpoint.inline_bytes.checked_add(endpoint.heap_bytes)?.checked_mul(2)?)?
            .checked_add(floor.inline_bytes.checked_add(floor.heap_bytes)?.checked_mul(2)?)?;
        let files = endpoint.file_descriptors.checked_add(floor.file_descriptors)?
            .checked_add(RetainedStorageClientOwnerPostV1::retained_endpoint_open_files_v1()?)?
            .checked_mul(2)?;
        Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?)
            .with(D::OpenFiles, u64::try_from(files).ok()?))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.arm.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.before.as_ref().and_then(RetainedStorageClientOwnerPostV1::failure))
            .or_else(|| self.comparison.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.after.as_ref().and_then(RetainedStorageClientOwnerPostV1::failure))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn before_complete_v4(&self) -> bool {
        matches!(self.arm, Some(Ok(()))) && self.before.as_ref().is_some_and(|post| post.failure().is_none())
            && !self.finished && self.closed.is_none()
    }

    pub(crate) fn complete_v4(&self) -> bool {
        self.finished && self.after.is_some() && self.failure().is_none()
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn begin_fixed_service_session_post_v4(
        &mut self, transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity, socket: std::os::fd::RawFd,
        original: &mut FixedServiceSessionPostOriginalV4,
    ) -> Result<(), BrokerSessionSecurityError> {
        if original.arm.is_some() || original.closed.is_some() {
            original.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        original.arm = Some((|| {
            self.journal.fixed_service_server_recipe_v4(transcript)?;
            let journal = self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
            original.binding = Some(ExecutionClientPostBindingV1 {
                journal: journal.authority_comparison_stamp_v1(), socket,
                transcript: transcript.session_binding(),
            });
            Ok(())
        })());
        if !matches!(original.arm, Some(Ok(()))) { return Err(BrokerSessionSecurityError::Currentness); }
        // The after destination is already paid and armed before this first
        // native call; a refusing before never suppresses its later sibling.
        original.before = Some(self.observe_retained_client_owner_inner_v1(
            transcript, peer, RetainedClientPostPurposeV1::FixedService));
        if original.before_complete_v4() { Ok(()) }
        else { Err(BrokerSessionSecurityError::Currentness) }
    }

    pub(crate) fn finish_fixed_service_session_post_v4(
        &mut self, transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity, socket: std::os::fd::RawFd,
        original: &mut FixedServiceSessionPostOriginalV4,
    ) -> Result<(), BrokerSessionSecurityError> {
        if original.finished || !matches!(original.arm, Some(Ok(()))) {
            original.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        original.comparison = Some((|| {
            let binding = original.binding.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
            let journal = self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
            if binding.socket != socket || binding.transcript != transcript.session_binding()
                || !journal.matches_authority_comparison_stamp_v1(&binding.journal)
            { return Err(BrokerSessionSecurityError::Currentness); }
            self.journal.fixed_service_server_recipe_v4(transcript)
        })());
        original.after = Some(self.observe_retained_client_owner_inner_v1(
            transcript, peer, RetainedClientPostPurposeV1::FixedService));
        original.finished = true;
        if original.complete_v4() { Ok(()) } else { Err(BrokerSessionSecurityError::Currentness) }
    }
}


/// Retains both actual terminal validators beside the same committed response.
#[derive(Default)]
pub(crate) struct FixedServiceTerminalCurrentOriginalV4 {
    before: OutcomeCurrentOriginalsV1,
    after: OutcomeCurrentOriginalsV1,
}

impl FixedServiceTerminalCurrentOriginalV4 {
    pub(crate) fn receiving_demand_v4() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let (bytes, _) = OutcomeCurrentOriginalsV1::receiving_footprint_v1()?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes.checked_mul(2)?).ok()?)
            .with(D::OpenFiles, u64::try_from(OutcomeCurrentOriginalsV1::retained_endpoint_open_files_v1()?.checked_mul(2)?).ok()?))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.before.failure().or_else(|| self.after.failure())
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn fixed_service_outcome_demand_v4(
        &self, extent: &aos_sandbox_controller_domain::journal::ProtectedJournalPreopenReplayExtentV1,
        transcript: &VerifiedBrokerSessionTranscriptV1, request: &AuthenticatedBrokerMethodRequestV1, body: &[u8],
    ) -> Result<aos_sandbox_model::ResourceVector, BrokerSessionSecurityError> {
        self.journal.fixed_service_server_recipe_v4(transcript)?;
        let key = protocol_key(transcript.protocol());
        let stored = self.journal.journal.as_ref()
            .and_then(|journal| journal.get(RecordNamespace::BrokerSessionTraffic, &key))
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        storage_session_schema_demand::outcome_demand(extent, stored, request.canonical_packet(), body)
            .map_err(Into::into)
    }

    pub(crate) fn observe_fixed_service_terminal_v4(
        &mut self, transcript: &VerifiedBrokerSessionTranscriptV1,
        committed: &ProtectedBrokerOutcomeCommittedAdvancementV1, peer: &ConnectionPeerIdentity,
        original: &mut FixedServiceTerminalCurrentOriginalV4, after: bool,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.journal.fixed_service_server_recipe_v4(transcript)?;
        if !matches!(committed.method(),
            BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1
            | BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
            | BrokerMethod::BROKER_METHOD_NETWORK_PREPARE_V2
            | BrokerMethod::BROKER_METHOD_NETWORK_APPLY
            | BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES)
            || committed.session_binding() != transcript.session_binding()
        { return Err(BrokerSessionSecurityError::Currentness); }
        let destination = if after { &mut original.after } else { &mut original.before };
        destination.observe_execution_once_v1(&mut self.journal, &committed.currentness_owner, peer)
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn execution_no_apply_client_journal_v2(&self) -> Result<&Journal, BrokerSessionSecurityError> {
        if self.journal.endpoint.protected_protocol_and_node().0 != BrokerSessionProtocolV1::Host {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.execution_availability_client_journal_v2()
    }

    pub(crate) fn execution_no_apply_client_stored_v2(&self) -> Result<&[u8], BrokerSessionSecurityError> {
        self.execution_no_apply_client_journal_v2()?;
        self.execution_availability_client_stored_v2()
    }

    pub(crate) fn compare_execution_no_apply_predecessor_v2(&mut self,
        currentness: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity,
        originals: &mut OutcomeCurrentOriginalsV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.execution_no_apply_client_journal_v2()?;
        require_execution_no_apply_terminal_v2(currentness)?;
        originals.observe_execution_once_v1(&mut self.journal, currentness, peer)
    }
}

fn require_execution_no_apply_terminal_v2(owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1)
    -> Result<(), BrokerSessionSecurityError>
{
    let request = &owner.request;
    let method = request.method();
    let finite = match method {
        BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY => request.host_before_argument_no_apply_data_v2()
            .is_some_and(|original| !original.is_query()),
        BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2 => request.host_held_no_apply_settlement_data_v2().is_some(),
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 => request.host_no_apply_current_lease_query_data_v2().is_some(),
        _ => false,
    };
    if !finite || owner.transcript.protocol() != BrokerSessionProtocolV1::Host
        || owner.transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        || !owner.transcript.negotiated_methods().contains(&method)
        || owner.outcome.method() != method
        || request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
        || owner.outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || request.authorization().is_some() {
        return Err(BrokerSessionSecurityError::Currentness);
    }
    Ok(())
}

impl ProtectedBrokerOutcomeCommittedAdvancementV1 {
    pub(crate) fn execution_no_apply_client_originals_v2(&self)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError>
    {
        require_execution_no_apply_terminal_v2(&self.currentness_owner)?;
        Ok((&self.currentness_owner.outcome, &self.currentness_owner))
    }
}
