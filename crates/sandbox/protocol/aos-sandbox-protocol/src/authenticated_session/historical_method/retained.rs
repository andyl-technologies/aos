//! Keeps the sole historical method engine's reached Storage and Network DATA.

use super::*;
use std::error::Error;

use aos_sandbox_broker_session_protocol::{HistoricalTrafficReplayCaptureV1,
    BrokerSessionReplayEvidenceV1, verify_historical_traffic_records_retaining_v1};
use aos_sandbox_broker_session_protocol::projection::{
    CanonicalBrokerRequestDecodeCaptureV1, CanonicalBrokerRequestEnvelopeV1,
    CanonicalBrokerResponseDecodeCaptureV1, CanonicalBrokerResponseEnvelopeV1,
    BrokerSessionProjectionError, decode_canonical_request_retaining_v1,
    decode_canonical_response_retaining_v1,
};
use super::super::all_methods::{AuthenticatedBrokerMethodErrorV1,
    request_capture::AuthenticatedBrokerMethodRequestCaptureV1,
    outcome_capture::{AuthenticatedBrokerMethodOutcomeCaptureV1,
        admit_client_received_outcome_retaining_v1}};

type RequestValue = (AuthenticatedBrokerMethodRequestV1, Box<BrokerSessionTrafficStateV1>);

struct HistoricalMethodCaptureV2 {
    prefix: HistoricalTrafficReplayCaptureV1,
    prior: Option<Result<BrokerSessionTrafficStateV1,
        aos_sandbox_broker_session_protocol::HistoricalTrafficReplayErrorV1>>,
    canonical_request_capture: CanonicalBrokerRequestDecodeCaptureV1,
    canonical_request: Option<Result<CanonicalBrokerRequestEnvelopeV1, BrokerSessionProjectionError>>,
    bindings: Option<Result<super::super::all_methods::AuthenticatedBrokerSemanticBindingsV1,
        AuthenticatedBrokerMethodErrorV1>>,
    request_capture: AuthenticatedBrokerMethodRequestCaptureV1,
    request: Option<RequestValue>,
    request_replay: Option<BrokerSessionReplayEvidenceV1>,
    request_result: Option<Result<(), HistoricalMethodReplayErrorV1>>,
    canonical_outcome_capture: CanonicalBrokerResponseDecodeCaptureV1,
    canonical_outcome: Option<Result<CanonicalBrokerResponseEnvelopeV1, BrokerSessionProjectionError>>,
    outcome_capture: AuthenticatedBrokerMethodOutcomeCaptureV1,
    outcome: Option<Result<AuthenticatedBrokerMethodOutcomeV1, HistoricalMethodReplayErrorV1>>,
    outcome_replay: Option<BrokerSessionReplayEvidenceV1>,
    validation: Option<Result<(), HistoricalMethodReplayErrorV1>>,
    closed: Option<HistoricalMethodReplayErrorV1>,
}

impl Default for HistoricalMethodCaptureV2 {
    fn default() -> Self {
        Self { prefix: Default::default(), prior: None,
            canonical_request_capture: Default::default(), canonical_request: None,
            bindings: None, request_capture: Default::default(), request: None, request_replay: None, request_result: None,
            canonical_outcome_capture: Default::default(), canonical_outcome: None,
            outcome_capture: Default::default(), outcome: None, outcome_replay: None, validation: None, closed: None }
    }
}

impl HistoricalMethodCaptureV2 {
    /// Replays one terminal Storage method through the original history engine.
    ///
    /// # Errors
    /// Retains malformed companions, prefix, signature, method, body, result
    /// and semantic-link refusals. Reentry never replaces reached originals.
    fn observe_once_v1(&mut self, records: &[BrokerSessionDurableRecordV1],
        terminal_index: usize, purpose: HistoricalMethodPurposeV2, checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        if self.validation.is_some() || self.request_result.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(HistoricalMethodReplayErrorV1::Invalid);
            return Err(HistoricalMethodReplayErrorV1::Invalid);
        }
        self.validation = Some(self.observe_terminal_inner(records, terminal_index, purpose, checkpoint, transcript));
        self.require_complete()
    }

    fn observe_terminal_inner(&mut self, records: &[BrokerSessionDurableRecordV1],
        terminal_index: usize, purpose: HistoricalMethodPurposeV2, checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        let (request_index, terminal) = terminal_request_v1(records, terminal_index)?;
        self.observe_request_once(records, request_index, purpose, checkpoint, transcript)?;
        let packet = terminal.outcome_packet().ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
        decode_canonical_response_retaining_v1(packet, &mut self.canonical_outcome_capture)
            .map_err(|_|HistoricalMethodReplayErrorV1::Invalid)?;
        self.canonical_outcome = Some(self.canonical_outcome_capture.take_model_once());
        let canonical = self.canonical_outcome.as_ref().and_then(|result|result.as_ref().ok())
            .ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
        let (request, pending) = self.request.as_ref()
            .ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
        let admission = admit_client_received_outcome_retaining_v1(pending, request, packet, None,
            canonical.message().descriptors.len(), checkpoint.context(), &mut self.outcome_capture)
            .and_then(|()| self.outcome_capture.take_admission_once());
        self.outcome = Some(match admission {
            Ok(AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. }) => Ok(outcome),
            Ok(AuthenticatedBrokerMethodOutcomeAdmissionV1::ExactReplay(replay)) => {
                self.outcome_replay = Some(replay);
                Err(HistoricalMethodReplayErrorV1::Invalid)
            }
            Err(_) => Err(HistoricalMethodReplayErrorV1::Invalid),
        });
        let outcome = self.outcome.as_ref().and_then(|result|result.as_ref().ok())
            .ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
        require_terminal_outcome_v1(outcome, terminal, true)?;
        Ok(())
    }

    fn observe_request_once(&mut self, records: &[BrokerSessionDurableRecordV1],
        request_index: usize, purpose: HistoricalMethodPurposeV2, checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        if self.request_result.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(HistoricalMethodReplayErrorV1::Invalid);
            return Err(HistoricalMethodReplayErrorV1::Invalid);
        }
        self.request_result = Some(self.observe_request_inner(records, request_index, purpose, checkpoint, transcript));
        self.request_result.as_ref().copied().ok_or(HistoricalMethodReplayErrorV1::Invalid)?
    }

    fn observe_request_inner(&mut self, records: &[BrokerSessionDurableRecordV1],
        request_index: usize, purpose: HistoricalMethodPurposeV2, checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        let prepared = records.get(request_index).ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
        if prepared.phase() != BrokerSessionDurablePhaseV1::RequestPrepared {
            return Err(HistoricalMethodReplayErrorV1::Invalid);
        }
        verify_historical_traffic_records_retaining_v1(&records[..request_index], transcript,
            checkpoint.context(), &mut self.prefix).map_err(|_|HistoricalMethodReplayErrorV1::Invalid)?;
        self.prior = Some(self.prefix.take_traffic_once());
        decode_canonical_request_retaining_v1(prepared.request_packet(), &mut self.canonical_request_capture)
            .map_err(|_|HistoricalMethodReplayErrorV1::Invalid)?;
        self.canonical_request = Some(self.canonical_request_capture.take_model_once());
        let canonical = self.canonical_request.as_ref().and_then(|result|result.as_ref().ok())
            .ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
        let method = canonical.signed_artifact().method();
        if !purpose.accepts(method) {
            return Err(HistoricalMethodReplayErrorV1::Invalid);
        }
        self.bindings = Some(authenticated_semantic_bindings_from_envelope_v1(canonical.message(), method));
        let bindings = *self.bindings.as_ref().and_then(|result|result.as_ref().ok())
            .ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
        let peer = checkpoint.peer();
        let policy = crate::PeerPolicy { uid: peer.uid, gid: Some(peer.gid), audience: checkpoint.context().audience() };
        // This is the actual durable companion's historical parse coordinate,
        // never a fresh clock, deadline renewal or current dispatch authority.
        let retained_time = prepared.request_companion().deadline_boottime_nanoseconds()
            .checked_sub(1).ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
        let prior = self.prior.as_ref().and_then(|result|result.as_ref().ok())
            .ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
        let admission = self.request_capture.capture_once_v1(AuthenticatedBrokerRequestDirectionV1::ClientSend,
            prior, prepared.request_packet(), None, canonical.message().descriptors.len(), peer,
            policy, retained_time, bindings, checkpoint.context())
            .and_then(|()|self.request_capture.take_admission_once_v1());
        let (request, pending) = match admission {
            Ok(AuthenticatedBrokerMethodRequestAdmissionV1::New { request, next_traffic }) => (request, next_traffic),
            Ok(AuthenticatedBrokerMethodRequestAdmissionV1::ExactReplay(replay)) => {
                self.request_replay = Some(replay);
                return Err(HistoricalMethodReplayErrorV1::Invalid);
            }
            Err(_) => return Err(HistoricalMethodReplayErrorV1::Invalid),
        };
        // Park the complete request before even a pure final comparison can
        // refuse it; the caller's failure keeps the whole reached model.
        self.request = Some((request, pending));
        let (request, _) = self.request.as_ref().ok_or(HistoricalMethodReplayErrorV1::Invalid)?;
        if !request_matches_head(&request, prepared, AuthenticatedBrokerRequestDirectionV1::ClientSend)
            || request.semantic_commitment() != prepared.request_semantic_binding() {
            return Err(HistoricalMethodReplayErrorV1::Invalid);
        }
        Ok(())
    }

    fn require_complete(&self) -> Result<(), HistoricalMethodReplayErrorV1> {
        if self.closed.is_none() && matches!(self.validation, Some(Ok(()))) {
            Ok(())
        } else { Err(HistoricalMethodReplayErrorV1::Invalid) }
    }

    /// Borrows the exact complete historical request without current authority.
    #[must_use]
    fn request_v1(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> {
        self.require_complete().ok()?;
        self.request.as_ref().map(|(request, _)|request)
    }

    /// Borrows the exact complete successful historical outcome.
    #[must_use]
    fn outcome_v1(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        self.require_complete().ok()?;
        self.outcome.as_ref()?.as_ref().ok()
    }

    /// Borrows the same decoded Apply response retained by outcome admission.
    #[must_use]
    fn storage_apply_v1(&self) -> Option<&aos_sandbox_api::aos::sandbox::local::v1::StorageResult> {
        self.require_complete().ok()?;
        self.outcome_capture.retained_storage_apply_response_data_v1()
    }

    /// Borrows the same decoded Inventory response retained by admission.
    #[must_use]
    fn inventory_v1(&self) -> Option<&(crate::storage_inventory::ValidatedStorageInventory,
        aos_sandbox_api::aos::sandbox::local::v1::InventoryStorageResourcesResponse)> {
        self.require_complete().ok()?;
        self.outcome_capture.retained_storage_inventory_response_data_v1()
    }

    /// Borrows the earliest retained reached cause without new decoding or IO.
    #[must_use]
    fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.prefix.cause()
            .or_else(|| self.prior.as_ref()?.as_ref().err().map(|cause|cause as _))
            .or_else(|| self.canonical_request_capture.failure().map(|cause|cause as _))
            .or_else(|| self.canonical_request.as_ref()?.as_ref().err().map(|cause|cause as _))
            .or_else(|| self.bindings.as_ref()?.as_ref().err().map(|cause|cause as _))
            .or_else(|| self.request_capture.cause())
            .or_else(|| self.request_result.as_ref()?.as_ref().err().map(|cause|cause as _))
            .or_else(|| self.canonical_outcome_capture.failure().map(|cause|cause as _))
            .or_else(|| self.canonical_outcome.as_ref()?.as_ref().err().map(|cause|cause as _))
            .or_else(|| self.outcome_capture.cause())
            .or_else(|| self.outcome.as_ref()?.as_ref().err().map(|cause|cause as _))
            .or_else(|| self.validation.as_ref()?.as_ref().err().map(|cause|cause as _))
            .or_else(|| self.closed.as_ref().map(|cause|cause as _))
    }

}

#[derive(Clone, Copy)]
enum HistoricalMethodPurposeV2 { Storage, Network, Mount, StorageGuestRoot, Host, DeleteNetwork, DeleteHost, HostCurrentNoApply, HostHeldNoApplyAck }

impl HistoricalMethodPurposeV2 {
    fn accepts(self, method: aos_sandbox_broker_session_protocol::hello_message::BrokerMethod) -> bool {
        use aos_sandbox_broker_session_protocol::hello_message::BrokerMethod as M;
        match self {
            Self::DeleteNetwork => method == M::BROKER_METHOD_NETWORK_APPLY,
            Self::DeleteHost => method == M::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
            Self::Storage => matches!(method, M::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                | M::BROKER_METHOD_STORAGE_APPLY | M::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES),
            Self::Network => matches!(method, M::BROKER_METHOD_NETWORK_PREPARE_V2
                | M::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES),
            Self::Mount => matches!(method, M::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1
                | M::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS),
            Self::Host => matches!(method, M::BROKER_METHOD_HOST_APPLY_RUNTIME
                | M::BROKER_METHOD_HOST_INVENTORY_RUNTIME),
            Self::HostCurrentNoApply => method == M::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2,
            Self::HostHeldNoApplyAck => method == M::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2,
            Self::StorageGuestRoot => matches!(method, M::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT
                | M::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES),
        }
    }
}

/// Retains one historical signed Storage exchange without live authority.
///
/// Only PrepareCatalog, Apply and Inventory18 enter the shared retained engine.
/// All bytes come from the caller's verified stored history. This owner creates
/// no Session, clock, lease, resend or dispatch permit.
#[doc(hidden)]
#[derive(Default)]
pub struct HistoricalStorageMethodCaptureV1 { original: HistoricalMethodCaptureV2 }

impl HistoricalStorageMethodCaptureV1 {
    /// Constructs inert historical DATA destinations.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Replays one terminal Storage method through the sole historical engine.
    ///
    /// # Errors
    /// Retains malformed prefix, packet, signature, method and semantic refusals.
    pub fn observe_once_v1(&mut self, records: &[BrokerSessionDurableRecordV1],
        terminal_index: usize, checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        self.original.observe_once_v1(records, terminal_index,
            HistoricalMethodPurposeV2::Storage, checkpoint, transcript)
    }

    /// Borrows the exact successful historical request as DATA.
    #[must_use]
    pub fn request_v1(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> { self.original.request_v1() }

    /// Borrows the exact successful historical outcome as DATA.
    #[must_use]
    pub fn outcome_v1(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> { self.original.outcome_v1() }

    /// Borrows the same successful Prepare26 model retained by outcome admission.
    ///
    /// Historical DATA supplies no current catalog or effect permission.
    #[must_use]
    pub fn storage_preparation_response_data_v3(&self)
        -> Option<&aos_sandbox_api::aos::sandbox::local::v1::PrepareStorageCatalogResponse>
    {
        self.original.require_complete().ok()?;
        self.original.outcome_capture.retained_storage_preparation_response_data_v3()
    }

    /// Borrows the same retained decoded Apply response.
    #[must_use]
    pub fn storage_apply_v1(&self) -> Option<&aos_sandbox_api::aos::sandbox::local::v1::StorageResult> {
        self.original.storage_apply_v1()
    }

    /// Borrows the same retained decoded Inventory18 response.
    #[must_use]
    pub fn inventory_v1(&self) -> Option<&(crate::storage_inventory::ValidatedStorageInventory,
        aos_sandbox_api::aos::sandbox::local::v1::InventoryStorageResourcesResponse)> {
        self.original.inventory_v1()
    }

    /// Borrows the earliest retained cause without decoding or IO.
    #[must_use]
    pub fn failure_v1(&self) -> Option<&(dyn Error + 'static)> { self.original.failure_v1() }
}

/// Retains historical Destroy9 or HostInventory3 through the sole method engine.
///
/// This historical adapter creates no native or live Session authority. The
/// caller separately proves the actual receipt COMMIT, current native custody,
/// unchanged D and all independently owed posts before authorizing cleanup.
#[doc(hidden)]
#[derive(Default)]
pub struct HistoricalDeleteCleanupMethodCaptureV4 { original: HistoricalMethodCaptureV2 }

impl HistoricalDeleteCleanupMethodCaptureV4 {
    /// Replays only a successful signed Destroy9 terminal from verified history.
    ///
    /// # Errors
    /// Retains malformed prefix, signature, request, result or reentry refusal.
    /// Refuses other method9 actions even when their historical signatures verify.
    pub fn observe_network_destroy_once_v4(&mut self, records: &[BrokerSessionDurableRecordV1],
        terminal_index: usize, checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        self.original.observe_once_v1(records, terminal_index,
            HistoricalMethodPurposeV2::DeleteNetwork, checkpoint, transcript)?;
        if self.original.request_v1().and_then(|request| request.network_destroy_data_v4()).is_none()
            || self.original.outcome_capture.retained_network_destroy_response_data_v4().is_none() {
            self.original.closed.get_or_insert(HistoricalMethodReplayErrorV1::Invalid);
            return Err(HistoricalMethodReplayErrorV1::Invalid);
        }
        Ok(())
    }

    /// Replays only a successful authenticated HostInventory3 terminal.
    ///
    /// # Errors
    /// Retains malformed prefix, signature, request, result or reentry refusal.
    /// A decoded scope remains DATA until the genuine native caller qualifies it.
    pub fn observe_host_inventory_once_v4(&mut self, records: &[BrokerSessionDurableRecordV1],
        terminal_index: usize, checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        self.original.observe_once_v1(records, terminal_index,
            HistoricalMethodPurposeV2::DeleteHost, checkpoint, transcript)
    }

    /// Replays only the signed Mount62 namespace Reap terminal through the same engine.
    ///
    /// # Errors
    /// Retains malformed history, another action or an outcome other than Released.
    pub fn observe_mount_reap_once_v4(&mut self, records: &[BrokerSessionDurableRecordV1],
        terminal_index: usize, checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        self.original.observe_once_v1(records, terminal_index,
            HistoricalMethodPurposeV2::Mount, checkpoint, transcript)?;
        if self.original.request_v1().is_none_or(|request| request.method()
            != aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1)
            || self.original.request_v1().and_then(|request| request.mount_attachment_anchor_data_v2())
                .is_none_or(|request| request.action()
                    != aos_sandbox_api::aos::sandbox::local::v1::AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_REAP)
            || self.original.outcome_capture.retained_mount_namespace_result_data_v2()
                .is_none_or(|value| value.lifecycle()
                    != aos_sandbox_api::aos::sandbox::local::v1::AttachmentAnchorLifecycleV1::ATTACHMENT_ANCHOR_LIFECYCLE_V1_RELEASED) {
            self.original.closed.get_or_insert(HistoricalMethodReplayErrorV1::Invalid);
            return Err(HistoricalMethodReplayErrorV1::Invalid);
        }
        Ok(())
    }

    /// Replays only signed destructive Storage7 through the same canonical engine.
    ///
    /// # Errors
    /// Retains malformed history, another method or a failed canonical result.
    pub fn observe_storage_destroy_once_v4(&mut self, records: &[BrokerSessionDurableRecordV1],
        terminal_index: usize, checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        self.original.observe_once_v1(records, terminal_index,
            HistoricalMethodPurposeV2::Storage, checkpoint, transcript)?;
        if self.original.request_v1().is_none_or(|request| request.method()
            != aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_STORAGE_APPLY)
            || self.original.request_v1().and_then(|request| request.storage_apply_data_v1())
                .is_none_or(|request| !matches!(request.operation(), crate::semantics::StorageOperation::Destroy { .. }))
            || self.original.storage_apply_v1().is_none() {
            self.original.closed.get_or_insert(HistoricalMethodReplayErrorV1::Invalid);
            return Err(HistoricalMethodReplayErrorV1::Invalid);
        }
        Ok(())
    }

    /// Borrows the sole authenticated terminal as historical comparison DATA.
    #[must_use]
    pub fn outcome_v4(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        self.original.outcome_v1()
    }

    /// Borrows the sole-decoded complete Host inventory after historical validation.
    #[must_use]
    pub fn host_inventory_v4(&self) -> Option<&aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse> {
        self.original.require_complete().ok()?;
        self.original.outcome_capture.retained_host_inventory_data_v2()
    }

    /// Borrows the earliest actual historical refusal while its owner stays held.
    #[must_use]
    pub fn failure_v4(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure_v1()
    }
}

/// Retains historical Network63 or Inventory19 DATA through the same engine.
///
/// This verifies signed historical packets only. Current namespace identity,
/// protected Session pins and final Root policy comparisons remain separately
/// owned and funded by the actual Root resource server.
#[doc(hidden)]
#[derive(Default)]
pub struct HistoricalStartResourceMethodCaptureV2 { original: HistoricalMethodCaptureV2 }

impl HistoricalStartResourceMethodCaptureV2 {
    /// Replays a terminal held42 outcome through the sole retained method engine.
    ///
    /// The native Root consumer independently requires the exact Acknowledge
    /// command, own floor and actual terminal Controller cut. This is DATA.
    ///
    /// # Errors
    /// Retains malformed prefixes, signatures, semantic links and reentry.
    pub fn observe_host_held_no_apply_ack_once_v2(&mut self,
        records: &[BrokerSessionDurableRecordV1], terminal_index: usize,
        checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        self.original.observe_once_v1(records, terminal_index,
            HistoricalMethodPurposeV2::HostHeldNoApplyAck, checkpoint, transcript)
    }

    /// Replays only the explicit current Host43 lease read through the same engine.
    ///
    /// The result is historical DATA. A genuine Root native reader, its own
    /// paid fresh nonce and the retained Host lease remain independently required.
    ///
    /// # Errors
    /// Retains malformed prefixes, signatures, canonical bodies and semantic
    /// links, and rejects every other method or repeated observation.
    pub fn observe_host_current_no_apply_once_v2(&mut self,
        records: &[BrokerSessionDurableRecordV1], terminal_index: usize,
        checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        self.original.observe_once_v1(records, terminal_index,
            HistoricalMethodPurposeV2::HostCurrentNoApply, checkpoint, transcript)
    }

    /// Replays one terminal Host1 or Inventory3 through the sole retained engine.
    ///
    /// # Errors
    /// Retains malformed prefixes, packet signatures and semantic bindings;
    /// refuses all other methods and repeated observation.
    pub fn observe_host_once_v2(&mut self, records: &[BrokerSessionDurableRecordV1],
        terminal_index: usize, checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        self.original.observe_once_v1(records, terminal_index,
            HistoricalMethodPurposeV2::Host, checkpoint, transcript)
    }

    /// Borrows the same Host1 model retained by authenticated request admission.
    #[must_use]
    pub fn host_apply_request_v2(&self) -> Option<&crate::ValidatedRuntimeRequest> {
        self.original.require_complete().ok()?;
        self.original.request_capture.retained_host_apply_runtime_data_v2()
    }

    /// Borrows the actual Host1 receipt retained by the sole outcome decoder.
    #[must_use]
    pub fn host_apply_observation_v2(&self)
        -> Option<&aos_sandbox_api::aos::sandbox::local::v1::RuntimeObservation> {
        self.original.require_complete().ok()?;
        self.original.outcome_capture.retained_host_apply_observation_data_v2()
    }

    /// Borrows the actual complete Inventory3 retained by outcome admission.
    #[must_use]
    pub fn host_inventory_v2(&self)
        -> Option<&aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse> {
        self.original.require_complete().ok()?;
        self.original.outcome_capture.retained_host_inventory_data_v2()
    }

    /// Constructs inert historical DATA destinations.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Replays one terminal Network63 or Inventory19 exchange.
    ///
    /// # Errors
    /// Retains malformed companions, prefix, signatures and semantic refusals;
    /// all other methods and any reentry are rejected.
    pub fn observe_network_once_v2(&mut self, records: &[BrokerSessionDurableRecordV1],
        terminal_index: usize, checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        self.original.observe_once_v1(records, terminal_index,
            HistoricalMethodPurposeV2::Network, checkpoint, transcript)
    }

    /// Replays one terminal Mount62 or Inventory16 through the same engine.
    ///
    /// # Errors
    /// Retains malformed prefix, packet, signature and semantic refusals and
    /// rejects every other method or repeated observation.
    pub fn observe_mount_once_v2(&mut self, records: &[BrokerSessionDurableRecordV1],
        terminal_index: usize, checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        self.original.observe_once_v1(records, terminal_index,
            HistoricalMethodPurposeV2::Mount, checkpoint, transcript)
    }

    /// Replays one terminal Storage31 or Inventory18 through the same engine.
    ///
    /// # Errors
    /// Retains prefix, packet, signature and semantic failures and refuses
    /// every other method or a repeated observation.
    pub fn observe_storage_once_v2(&mut self, records: &[BrokerSessionDurableRecordV1],
        terminal_index: usize, checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        self.original.observe_once_v1(records, terminal_index,
            HistoricalMethodPurposeV2::StorageGuestRoot, checkpoint, transcript)
    }

    /// Borrows the sole signed method31 response retained by admission.
    #[must_use]
    pub fn storage_guest_root_response_v2(&self)
        -> Option<&crate::semantics::storage_guest_root::StorageGuestRootResponseDataV2>
    {
        self.original.require_complete().ok()?;
        self.original.outcome_capture.retained_storage_guest_root_response_data_v2()
    }

    /// Borrows the same complete Inventory18 retained by admission.
    #[must_use]
    pub fn storage_inventory_response_v2(&self)
        -> Option<&crate::ValidatedStorageInventory>
    {
        self.original.inventory_v1().map(|inventory| &inventory.0)
    }

    /// Borrows the sole Mount62 decoder's complete resource DATA.
    #[must_use]
    pub fn mount_response_v2(&self) -> Option<&crate::mount_attachment_anchor::ValidatedAttachmentAnchorResourceV1> {
        self.original.require_complete().ok()?;
        self.original.outcome_capture.retained_mount_namespace_result_data_v2()
    }

    /// Borrows the sole Inventory16 decoder's complete model DATA.
    #[must_use]
    pub fn mount_inventory_v2(&self) -> Option<&crate::ValidatedDestinationSlotInventory> {
        self.original.require_complete().ok()?;
        self.original.outcome_capture.retained_mount_namespace_inventory_data_v2()
    }

    /// Borrows the exact successful historical request as DATA.
    #[must_use]
    pub fn request_v2(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> { self.original.request_v1() }

    /// Borrows the exact successful historical outcome as DATA.
    #[must_use]
    pub fn outcome_v2(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> { self.original.outcome_v1() }

    /// Borrows the same Network63 response retained by outcome admission.
    #[must_use]
    pub fn prepare_response_v2(&self) -> Option<&aos_sandbox_api::aos::sandbox::local::v1::NetworkResult> {
        self.original.require_complete().ok()?;
        self.original.outcome_capture.retained_network_prepare_response_data_v4()
    }

    /// Borrows the same complete Inventory19 model retained by admission.
    #[must_use]
    pub fn inventory_response_v2(&self) -> Option<&crate::ValidatedNetworkInventory> {
        self.original.require_complete().ok()?;
        self.original.outcome_capture.retained_network_inventory_response_data_v4()
    }

    /// Borrows the earliest retained cause without decoding or IO.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> { self.original.failure_v1() }
}

/// Retains exact historical method31 or Inventory18 DATA through the same engine.
///
/// This purpose is distinct from the original Create Apply/Inventory pair.
/// Its output lends no Session, dispatch permission, currentness or lease.
#[doc(hidden)]
#[derive(Default)]
pub struct HistoricalStorageGuestRootMethodCaptureV2 {
    original: HistoricalMethodCaptureV2,
}

impl HistoricalStorageGuestRootMethodCaptureV2 {
    /// Creates inert destinations without observing traffic or native state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replays one successful method31 or Inventory18 terminal exchange.
    ///
    /// # Errors
    /// Retains malformed historical prefixes, packets, signatures and semantic
    /// joins, rejects other methods, and refuses any repeated observation.
    pub fn observe_once_v2(
        &mut self,
        records: &[BrokerSessionDurableRecordV1],
        terminal_index: usize,
        checkpoint: &HistoricalSessionCheckpointV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalMethodReplayErrorV1> {
        self.original.observe_once_v1(records, terminal_index,
            HistoricalMethodPurposeV2::StorageGuestRoot, checkpoint, transcript)
    }

    /// Borrows the exact authenticated request as historical comparison DATA.
    #[must_use]
    pub fn request_v2(&self) -> Option<&AuthenticatedBrokerMethodRequestV1> {
        self.original.request_v1()
    }

    /// Borrows the whole successful authenticated outcome and its original body.
    #[must_use]
    pub fn outcome_v2(&self) -> Option<&AuthenticatedBrokerMethodOutcomeV1> {
        self.original.outcome_v1()
    }

    /// Borrows the same decoded Inventory18 retained by the original admission.
    #[must_use]
    pub fn inventory_v2(&self) -> Option<&(crate::storage_inventory::ValidatedStorageInventory,
        aos_sandbox_api::aos::sandbox::local::v1::InventoryStorageResourcesResponse)>
    {
        self.original.inventory_v1()
    }

    /// Borrows the sole signed method31 response retained by admission.
    #[must_use]
    pub fn storage_guest_root_response_v2(&self)
        -> Option<&crate::semantics::storage_guest_root::StorageGuestRootResponseDataV2>
    {
        self.original.require_complete().ok()?;
        self.original.outcome_capture.retained_storage_guest_root_response_data_v2()
    }

    /// Borrows the selected retained failure without decoding or native IO.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure_v1()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_historical_purposes_keep_their_exact_method_rosters() {
        use aos_sandbox_broker_session_protocol::hello_message::BrokerMethod as M;
        assert!(HistoricalMethodPurposeV2::DeleteNetwork.accepts(M::BROKER_METHOD_NETWORK_APPLY));
        assert!(HistoricalMethodPurposeV2::DeleteHost.accepts(M::BROKER_METHOD_HOST_INVENTORY_RUNTIME));
        for method in [M::BROKER_METHOD_NETWORK_PREPARE_V2,
            M::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
            M::BROKER_METHOD_STORAGE_APPLY, M::BROKER_METHOD_HOST_APPLY_RUNTIME] {
            assert!(!HistoricalMethodPurposeV2::DeleteNetwork.accepts(method));
            assert!(!HistoricalMethodPurposeV2::DeleteHost.accepts(method));
        }
        assert!(!HistoricalMethodPurposeV2::DeleteHost.accepts(M::BROKER_METHOD_NETWORK_APPLY));
        assert!(!HistoricalMethodPurposeV2::DeleteNetwork.accepts(M::BROKER_METHOD_HOST_INVENTORY_RUNTIME));
    }

    #[test]
    fn fixed_historical_rosters_do_not_admit_each_others_methods() {
        use aos_sandbox_broker_session_protocol::hello_message::BrokerMethod as M;
        assert!(HistoricalMethodPurposeV2::HostCurrentNoApply.accepts(
            M::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2));
        for method in [M::BROKER_METHOD_HOST_TERMINAL_NO_APPLY,
            M::BROKER_METHOD_HOST_QUERY_NO_APPLY,
            M::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2,
            M::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2,
            M::BROKER_METHOD_HOST_APPLY_RUNTIME] {
            assert!(!HistoricalMethodPurposeV2::HostCurrentNoApply.accepts(method));
        }
        for method in [M::BROKER_METHOD_STORAGE_PREPARE_CATALOG,
            M::BROKER_METHOD_STORAGE_APPLY, M::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES] {
            assert!(HistoricalMethodPurposeV2::Storage.accepts(method));
            assert!(!HistoricalMethodPurposeV2::Network.accepts(method));
        }
        for method in [M::BROKER_METHOD_NETWORK_PREPARE_V2, M::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES] {
            assert!(HistoricalMethodPurposeV2::Network.accepts(method));
            assert!(!HistoricalMethodPurposeV2::Storage.accepts(method));
        }
        for method in [M::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1,
            M::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS] {
            assert!(HistoricalMethodPurposeV2::Mount.accepts(method));
            assert!(!HistoricalMethodPurposeV2::Storage.accepts(method));
            assert!(!HistoricalMethodPurposeV2::Network.accepts(method));
            assert!(!HistoricalMethodPurposeV2::StorageGuestRoot.accepts(method));
        }
        for method in [M::BROKER_METHOD_HOST_APPLY_RUNTIME, M::BROKER_METHOD_HOST_INVENTORY_RUNTIME] {
            assert!(HistoricalMethodPurposeV2::Host.accepts(method));
            assert!(!HistoricalMethodPurposeV2::Network.accepts(method));
            assert!(!HistoricalMethodPurposeV2::Mount.accepts(method));
            assert!(!HistoricalMethodPurposeV2::StorageGuestRoot.accepts(method));
        }
        for method in [M::BROKER_METHOD_HOST_OBSERVE_RUNTIME,
            M::BROKER_METHOD_HOST_PUBLISH_CATALOG, M::BROKER_METHOD_HOST_APPLY_EXECUTION] {
            assert!(!HistoricalMethodPurposeV2::Host.accepts(method));
        }
        assert!(!HistoricalMethodPurposeV2::Mount.accepts(M::BROKER_METHOD_NETWORK_PREPARE_V2));
        assert!(!HistoricalMethodPurposeV2::Network.accepts(M::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1));
    }
}
