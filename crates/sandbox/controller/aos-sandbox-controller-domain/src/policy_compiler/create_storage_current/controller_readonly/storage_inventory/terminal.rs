//! Verifies Prepare against the original Inventory and independently read terminal.
//!
//! The authenticated method engine remains the sole request/outcome validator.
//! The Session map and physical coordinates come from Root's actual held native
//! reader. Controller receipt fields only select equality comparisons.

use buffa::Message as _;
use sha2::{Digest as _, Sha256};
use aos_sandbox_api::aos::sandbox::local::v1::PrepareStorageCatalogResponse;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    continuation::SignedPreparationBundleDataV1,
    outcome::{ControllerOutcomeBodyDataV1, OutcomeBundleDataV1},
    controller_use::ControllerSessionReservedBodyDataV1,
};
use super::*;
use super::super::native_read::RootFixedNativeReadbackV1;

pub(crate) struct RootVerifiedSessionTerminalV1 {
    stored: StoredBrokerSessionHistoryV1,
    context: ProtectedBrokerSessionVerificationContextV1,
    transcript: VerifiedBrokerSessionTranscriptV1,
    history: BrokerSessionDurableHistoryV1,
    traffic: BrokerSessionTrafficStateV1,
    request: AuthenticatedBrokerMethodRequestV1,
    outcome: AuthenticatedBrokerMethodOutcomeV1,
    response: PrepareStorageCatalogResponse,
    actual: ControllerOutcomeBodyDataV1,
}

impl RootCurrentStorageInventoryV1 {
    pub(crate) fn verify_prepare_terminal_v1(&self, native: RootFixedNativeReadbackV1<'_>,
        bundle: OutcomeBundleDataV1<'_>, signed: SignedPreparationBundleDataV1<'_>,
        request_id: [u8; 16], cutoff: u64, original: ReadyBundleDataV1<'_>,
        sample: RawPairedClockSample, controller: PeerCredentials,
        recorded: ControllerOutcomeBodyDataV1, request_recorded: ControllerSessionReservedBodyDataV1,
    ) -> Result<RootVerifiedSessionTerminalV1, Error> {
        self.require_complete()?;
        self.require_live_at_v1(sample)?;
        let initial = self.result.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Changed)?;
        initial.verify_prepare_terminal_with_request_time_v1(native, bundle, signed, request_id,
            cutoff, original, sample, controller, recorded, request_recorded, sample.boottime_nanoseconds())
    }
}

impl InventoryValues {
    pub(in crate::policy_compiler) fn verify_historical_prepare_terminal_v1(&self,
        native: RootFixedNativeReadbackV1<'_>, bundle: OutcomeBundleDataV1<'_>,
        signed: SignedPreparationBundleDataV1<'_>, request_id: [u8; 16], cutoff: u64,
        original: ReadyBundleDataV1<'_>, sample: RawPairedClockSample, controller: PeerCredentials,
        recorded: ControllerOutcomeBodyDataV1, request_recorded: ControllerSessionReservedBodyDataV1,
    ) -> Result<RootVerifiedSessionTerminalV1, Error> {
        self.verify_prepare_terminal_with_request_time_v1(native, bundle, signed, request_id,
            cutoff, original, sample, controller, recorded, request_recorded, sample.boottime_nanoseconds())
    }

    fn verify_prepare_terminal_with_request_time_v1(&self,
        native: RootFixedNativeReadbackV1<'_>, bundle: OutcomeBundleDataV1<'_>,
        signed: SignedPreparationBundleDataV1<'_>, request_id: [u8; 16], cutoff: u64,
        original: ReadyBundleDataV1<'_>, sample: RawPairedClockSample, controller: PeerCredentials,
        recorded: ControllerOutcomeBodyDataV1, request_recorded: ControllerSessionReservedBodyDataV1,
        request_time: u64,
    ) -> Result<RootVerifiedSessionTerminalV1, Error> {
        let initial = self;
        verify_storage_history_roster_v2(native.state, &initial.manifest,
            initial.manifest.node_id(), sample.host_boot_id())?;
        let key = (aos_sandbox_model::RecordNamespace::BrokerSessionTraffic,
            canonical_protocol_key_v1(BrokerSessionProtocolV1::Storage));
        let encoded = native.state.get(&key).ok_or(Changed)?;
        let stored = StoredBrokerSessionHistoryV1::decode(&key.1, encoded)?;
        if stored.stable_endpoint_identity != initial.stored.stable_endpoint_identity
            || stored.endpoint_publication != initial.stored.endpoint_publication
            || stored.checkpoint != initial.stored.checkpoint
            || stored.generation <= initial.stored.generation
        { return Err(Box::new(Changed)); }
        let (context, transcript, history, traffic) = verify_session_v1(&initial.manifest, &stored,
            original.storage_client_hello, original.storage_broker_hello,
            initial.manifest.node_id(), sample.host_boot_id(),
            BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG, bundle.request, bundle.outcome)?;
        // Exactly the previously accepted Inventory prefix and one Prepare pair
        // must remain. A different valid history cannot replace this original.
        let prefix = initial.history.records();
        if history.records().len() != prefix.len().checked_add(2).ok_or(Changed)?
            || history.records().get(..prefix.len()) != Some(prefix)
        { return Err(Box::new(Changed)); }
        let (request, pending) = match prepare_client_sent_authenticated_broker_method_request_v1(
            &initial.traffic, bundle.request, None, 0, controller,
            PeerPolicy { uid: controller.uid, gid: Some(controller.gid),
                audience: Audience::AUDIENCE_NODE_CONTROLLER },
            request_time, AuthenticatedBrokerSemanticBindingsV1::new(None, None), &context,
        )? {
            AuthenticatedBrokerMethodRequestAdmissionV1::New { request, next_traffic } => (request, next_traffic),
            _ => return Err(Box::new(Changed)),
        };
        let marked = native.marked_transaction.ok_or(Changed)?;
        let reserved_raw = marked.records().iter().find(|row| row.namespace()
            == aos_sandbox_model::RecordNamespace::BrokerSessionTraffic && row.key() == key.1.as_slice())
            .and_then(|row| row.value()).ok_or(Changed)?;
        let reserved_stored = StoredBrokerSessionHistoryV1::decode(&key.1, reserved_raw)?;
        let reserved_history = reserved_stored.history_model()?;
        let reserved_head = reserved_history.head()?;
        if request_recorded.names != native.names
            || request_recorded.session_binding != transcript.session_binding()
            || request_recorded.request_id != request.request_id()
            || request_recorded.signed_request != request.signed_request_digest()
            || request_recorded.client_sequence != request.client_sequence()
            || request_recorded.generation != reserved_stored.generation
            || reserved_stored.generation <= initial.stored.generation
            || stored.generation <= reserved_stored.generation
            || request_recorded.head != reserved_stored.current_head
            || request_recorded.revision != reserved_head.revision()
            || request_recorded.commitment != reserved_head.commitment()?
            || reserved_stored.stable_endpoint_identity != initial.stored.stable_endpoint_identity
            || reserved_stored.endpoint_publication != initial.stored.endpoint_publication
            || reserved_stored.checkpoint != initial.stored.checkpoint
            || reserved_history.records().len() != prefix.len().checked_add(1).ok_or(Changed)?
            || reserved_history.records() != &history.records()[..history.records().len() - 1]
            || reserved_head.request_packet() != bundle.request
            || reserved_head.outcome_packet().is_some()
        { return Err(Box::new(Changed)); }
        let head = history.head()?;
        let authorization = request.authorization().ok_or(Changed)?;
        if request.method() != BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
            || request.request_id() != request_id || request.exact_body() != signed.request_body
            || request.deadline_boottime_nanoseconds() > cutoff
            || request.semantic_commitment() != head.request_semantic_binding()
            || authorization.broker_plan() != signed.plan
            || authorization.broker_plan_signature() != signed.signature
            || authorization.ownership_lease() != original.ownership_lease
            || authorization.ownership_lease_signature() != original.ownership_signature
        { return Err(Box::new(Changed)); }
        let outcome = match admit_client_received_authenticated_broker_method_outcome_v1(
            &pending, &request, bundle.outcome, None, 0, &context,
        )? {
            AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, next_traffic }
                if next_traffic.as_ref() == &traffic => outcome,
            _ => return Err(Box::new(Changed)),
        };
        if outcome.semantic_commitment() != head.outcome_semantic_binding() {
            return Err(Box::new(Changed));
        }
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result()
            else { return Err(Box::new(Changed)); };
        // Admission above already runs the canonical Storage response validator.
        // This decode only borrows its accepted non-authorizing receipt bytes.
        let response = PrepareStorageCatalogResponse::decode_from_slice(exact_body)?;
        let actual = ControllerOutcomeBodyDataV1 {
            signed_bound: recorded.signed_bound, use_admitted: recorded.use_admitted,
            use_claim: recorded.use_claim,
            request_packet: Sha256::digest(bundle.request).into(),
            outcome_packet: Sha256::digest(bundle.outcome).into(),
            signed_request: request.signed_request_digest(),
            prepared_receipt: aos_sandbox_protocol::semantics::storage_prepare::storage_prepared_receipt_digest_v1(
                &response.non_authorizing_receipt),
            session_names: native.names, session_after_next: native.next, session_after_end: native.end,
            session_head: stored.current_head, session_generation: stored.generation,
            session_revision: head.revision(), session_commitment: head.commitment()?, request_id,
        };
        if actual != recorded { return Err(Box::new(Changed)); }
        Ok(RootVerifiedSessionTerminalV1 { stored, context, transcript, history,
            traffic, request, outcome, response, actual })
    }
}

impl RootVerifiedSessionTerminalV1 {
    pub(crate) fn require_live_at_v1(&self, sample: RawPairedClockSample) -> Result<(), JournalError> {
        if sample.host_boot_id() != self.context.boot_id()
            || sample.boottime_nanoseconds() >= self.request.deadline_boottime_nanoseconds()
            || sample.boottime_nanoseconds() >= self.response.preparation_expires_boottime_nanoseconds
        { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    pub(in crate::policy_compiler) fn require_same_session_successor_data_v1(&self,
        stored: &StoredBrokerSessionHistoryV1, names: aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1,
    ) -> Result<(), JournalError> {
        if names != self.actual.session_names || stored.protocol != self.stored.protocol
            || stored.endpoint != self.stored.endpoint
            || stored.generation <= self.stored.generation
            || stored.stable_endpoint_identity != self.stored.stable_endpoint_identity
            || stored.endpoint_publication != self.stored.endpoint_publication
        { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    pub(in crate::policy_compiler) fn prepared_response_v1(&self) -> &PrepareStorageCatalogResponse {
        &self.response
    }

    pub(crate) fn actual_v1(&self) -> ControllerOutcomeBodyDataV1 { self.actual }

    pub(crate) fn prepared_receipt_v1(&self) -> &[u8] { &self.response.non_authorizing_receipt }
}
