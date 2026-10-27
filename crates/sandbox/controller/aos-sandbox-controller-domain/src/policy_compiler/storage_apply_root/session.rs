//! Authenticates final Apply and fresh Inventory from the actual Session file.
//!
//! The reader supplies the current complete stored history. The same local
//! manifest/context, signed transcript, traffic machine and method captures
//! verify it; incoming final bytes provide no packet, key or Session authority.

use aos_sandbox_protocol::domain_ledger::readonly::FixedJournalReadbackDataV1 as RootFixedNativeReadbackV1;

use std::error::Error;
use std::mem::size_of;
use aos_sandbox_model::{BrokerPlanExpectation, DecodeLimits, RawPairedClockSample,
    ResourceDimension as D, ResourceVector, VerifiedBrokerPlan};
use aos_sandbox_model::format::decode_signature;
use aos_sandbox_broker_session_protocol::{BrokerSessionProtocolV1, BrokerSessionDurablePhaseV1,
    BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1,
    ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    verify_historical_traffic_records_v1};
use aos_sandbox_broker_session_protocol::hello_message::{BrokerMethod, Audience};
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use aos_sandbox_protocol::authenticated_session::{all_methods::{
    AuthenticatedBrokerMethodOutcomeAdmissionV1, AuthenticatedBrokerMethodOutcomeV1,
    AuthenticatedBrokerMethodRequestAdmissionV1, AuthenticatedBrokerRequestDirectionV1,
    request_capture::AuthenticatedBrokerMethodRequestCaptureV1 as RequestCapture,
    outcome_capture::{AuthenticatedBrokerMethodOutcomeCaptureV1 as OutcomeCapture,
        admit_client_received_outcome_retaining_v1}, AuthenticatedBrokerSemanticBindingsV1,
    authenticated_catalog_generation_binding_v1,
}, stored_history::{StoredBrokerSessionHistoryV1, canonical_protocol_key_v1,
    StoredBrokerSessionHistoryDecodeCaptureV1}};
use crate::journal::{JournalError, RecordNamespace};
use crate::policy_compiler::create_storage_current::controller_readonly::{RootProspectiveStorageApplyPlanV1,
    storage_inventory::{RootCurrentStorageInventoryV1,
        verify_session_for_purpose_v1, RootHistoricalSessionPurposeV1}};
use crate::policy_compiler::provisioning_current::apply_inputs::RootApplyInputsOriginalV1;

type Cause = Box<dyn Error>;
type SessionValuesV1 = (ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1);

pub(in crate::policy_compiler) struct RootApplyFinalSessionOriginalV1 {
    stored: StoredBrokerSessionHistoryDecodeCaptureV1,
    verified: Option<Result<SessionValuesV1, Cause>>,
    apply_request: RequestCapture,
    apply_outcome: OutcomeCapture,
    inventory_request: RequestCapture,
    inventory_outcome: OutcomeCapture,
    signature: Option<Result<aos_sandbox_model::model::Signature, aos_sandbox_model::format::CanonicalCborError>>,
    verified_plan: Option<Result<VerifiedBrokerPlan, aos_sandbox_model::BrokerPlanVerificationError>>,
    result: Option<Result<(), Cause>>,
    closed: bool,
}

impl RootApplyFinalSessionOriginalV1 {
    pub(super) fn new() -> Self {
        Self { stored: Default::default(), verified: None, apply_request: RequestCapture::new(),
            apply_outcome: OutcomeCapture::new(), inventory_request: RequestCapture::new(), inventory_outcome: OutcomeCapture::new(),
            signature: None, verified_plan: None, result: None, closed: false }
    }

    // This full addition is joined to final StorageSemantic before replay or
    // constructing this capsule. Two complete signed exchanges coexist; the
    // shared method suppliers price their actual captured prefix, plus Apply's
    // two workspace semantic passes and this actual fixed/constructor layout.
    pub(in crate::policy_compiler) fn receiving_demand_v1(actual_prefix_bytes: usize) -> Result<ResourceVector, JournalError> {
        let one = RootCurrentStorageInventoryV1::additional_demand_v1(actual_prefix_bytes)?;
        let workspace = RequestCapture::storage_apply_additional_receiving_demand_v1(actual_prefix_bytes)
            .ok_or(JournalError::JournalTooLarge)?;
        let bytes = size_of::<Self>().checked_mul(3).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        one.checked_add(one).and_then(|demand| demand.checked_add(workspace))
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(super) fn observe_once_v1(&mut self, native: RootFixedNativeReadbackV1<'_>,
        inputs: &RootApplyInputsOriginalV1, issued: &RootProspectiveStorageApplyPlanV1,
        controller: PeerCredentials, sample: RawPairedClockSample, cutoff: u64,
    ) -> Result<(), JournalError> {
        if self.result.is_some() { self.closed = true; return Err(JournalError::ProtectedBoundary); }
        self.result = Some(self.observe_inner_v1(native, inputs, issued, controller, sample, cutoff));
        self.require_complete_v1()
    }

    fn observe_inner_v1(&mut self, native: RootFixedNativeReadbackV1<'_>,
        inputs: &RootApplyInputsOriginalV1, issued: &RootProspectiveStorageApplyPlanV1,
        controller: PeerCredentials, sample: RawPairedClockSample, cutoff: u64,
    ) -> Result<(), Cause> {
        crate::policy_compiler::create_storage_current::controller_readonly::storage_inventory::
            verify_storage_history_roster_v2(native.state, inputs.storage_manifest_data_v1()?,
                inputs.storage_manifest_data_v1()?.node_id(), sample.host_boot_id())?;
        let key = canonical_protocol_key_v1(BrokerSessionProtocolV1::Storage);
        let bytes = native.state.get(&(RecordNamespace::BrokerSessionTraffic, key.clone()))
            .ok_or(JournalError::ProtectedBoundary)?;
        StoredBrokerSessionHistoryV1::decode_retaining(&key, bytes, &mut self.stored)?;
        let stored = self.stored.stored().ok_or(JournalError::ProtectedBoundary)?;
        inputs.require_same_session_successor_data_v1(stored, native.names)?;
        let history = stored.history_model()?;
        let head = history.head()?;
        if head.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let checkpoint = stored.checkpoint.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let manifest = inputs.manifest_v1()?.manifest();
        self.verified = Some(verify_session_for_purpose_v1(inputs.storage_manifest_data_v1()?, stored,
            checkpoint.client_hello_bytes(), checkpoint.broker_hello_bytes(), *manifest.node().as_bytes(), sample.host_boot_id(),
            head.method(), head.request_packet(), head.outcome_packet().ok_or(JournalError::ProtectedBoundary)?,
            RootHistoricalSessionPurposeV1::Apply));
        let (context, transcript, history, _) = self.verified.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let mut applies = history.records().iter().enumerate().filter(|(_, record)|
            record.phase() == BrokerSessionDurablePhaseV1::Terminal
                && record.method() == BrokerMethod::BROKER_METHOD_STORAGE_APPLY);
        let (index, apply) = applies.next().ok_or(JournalError::ProtectedBoundary)?;
        if applies.next().is_some() || index == 0 || index.checked_add(3) != Some(history.records().len())
            || history.records()[..index - 1].iter().any(|record|
                record.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let before_apply = verify_historical_traffic_records_v1(&history.records()[..index - 1], transcript, context)?;
        let response = inputs.prepared_response_v1()?;
        let catalog: [u8;32] = response.catalog_digest.as_slice().try_into().map_err(|_| JournalError::ProtectedBoundary)?;
        let peer_policy = PeerPolicy { uid: controller.uid, gid: Some(controller.gid), audience: Audience::AUDIENCE_NODE_CONTROLLER };
        self.apply_request.capture_once_v1(AuthenticatedBrokerRequestDirectionV1::ClientSend,
            &before_apply, apply.request_packet(), None, 0, controller, peer_policy,
            sample.boottime_nanoseconds(), AuthenticatedBrokerSemanticBindingsV1::new(
                Some(crate::policy_compiler::storage_apply_root::session::catalog_binding_data_v1(response.catalog_generation, catalog)?), None), context)?;
        let (request, pending) = request_data_v1(&self.apply_request)?;
        let authorization = request.authorization().ok_or(JournalError::ProtectedBoundary)?;
        let prepared = issued.preparation_data_v1();
        if request.catalog_binding() != Some(authenticated_catalog_generation_binding_v1(response.catalog_generation, catalog))
            || authorization.broker_plan() != prepared.canonical_plan()
            || authorization.ownership_lease() != inputs.lease_v1()?.canonical_lease()
            || authorization.ownership_lease_signature() != inputs.lease_v1()?.canonical_signature()
            || request.deadline_boottime_nanoseconds() > cutoff
        { return Err(JournalError::ProtectedBoundary.into()); }
        self.signature = Some(decode_signature(authorization.broker_plan_signature(), DecodeLimits::default()));
        let signature = self.signature.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
        if signature.statement() != prepared.signing_request().statement() { return Err(JournalError::ProtectedBoundary.into()); }
        let expected = issued.plan_data_v1();
        self.verified_plan = Some(aos_sandbox_model::verify_broker_plan(prepared.canonical_plan(), signature,
            issued.anchor_v1(), BrokerPlanExpectation { audience: expected.audience(), protocol: expected.protocol(),
                protocol_version: expected.protocol_version(), assignment: expected.assignment(), node: expected.node(),
                now_seconds: sample.wall_seconds() }, DecodeLimits::default()));
        let verified_plan = self.verified_plan.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let grant = expected.grants().first().ok_or(JournalError::ProtectedBoundary)?;
        let semantics = request.storage_apply_data_v1().ok_or(JournalError::ProtectedBoundary)?;
        verified_plan.match_request(aos_sandbox_model::BrokerPlanRequest {
            verb: grant.verb(), target: grant.target(), argument_commitment: semantics.argument_commitment(),
            request_bytes: u32::try_from(request.exact_body().len()).map_err(|_| JournalError::ProtectedBoundary)?,
            descriptor_count: 0,
        })?;
        admit_client_received_outcome_retaining_v1(pending, request,
            apply.outcome_packet().ok_or(JournalError::ProtectedBoundary)?, None, 0, context, &mut self.apply_outcome)?;
        let before_inventory = verify_historical_traffic_records_v1(&history.records()[..=index], transcript, context)?;
        let inventory = history.head()?;
        self.inventory_request.capture_once_v1(AuthenticatedBrokerRequestDirectionV1::ClientSend,
            &before_inventory, inventory.request_packet(), None, 0, controller, peer_policy,
            sample.boottime_nanoseconds(), AuthenticatedBrokerSemanticBindingsV1::new(None, None), context)?;
        let (request, pending) = request_data_v1(&self.inventory_request)?;
        if request.deadline_boottime_nanoseconds() > cutoff { return Err(JournalError::ProtectedBoundary.into()); }
        admit_client_received_outcome_retaining_v1(pending, request,
            inventory.outcome_packet().ok_or(JournalError::ProtectedBoundary)?, None, 0, context, &mut self.inventory_outcome)?;
        self.apply_outcome.storage_apply_response_data_v1().ok_or(JournalError::ProtectedBoundary)?;
        self.inventory_outcome.storage_inventory_response_data_v1().ok_or(JournalError::ProtectedBoundary)?;
        Ok(())
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), JournalError> {
        if !self.closed && matches!(self.result, Some(Ok(()))) && self.failure().is_none() { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(super) fn apply_v1(&self) -> Result<&AuthenticatedBrokerMethodOutcomeV1, JournalError> {
        self.require_complete_v1()?;
        outcome_data_v1(&self.apply_outcome)
    }

    pub(super) fn inventory_v1(&self) -> Result<&AuthenticatedBrokerMethodOutcomeV1, JournalError> {
        self.require_complete_v1()?;
        outcome_data_v1(&self.inventory_outcome)
    }

    pub(super) fn apply_response_v1(&self) -> Result<&aos_sandbox_api::aos::sandbox::local::v1::StorageResult, JournalError> {
        self.require_complete_v1()?;
        self.apply_outcome.storage_apply_response_data_v1().ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn inventory_model_v1(&self) -> Result<&aos_sandbox_protocol::storage_inventory::ValidatedStorageInventory, JournalError> {
        self.require_complete_v1()?;
        self.inventory_outcome.storage_inventory_response_data_v1().map(|pair| &pair.0).ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.stored.failure().map(|cause| cause as _)
            .or_else(|| self.verified.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.apply_request.cause()).or_else(|| self.signature.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.verified_plan.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.apply_outcome.cause()).or_else(|| self.inventory_request.cause())
            .or_else(|| self.inventory_outcome.cause()).or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
    }
}

fn request_data_v1(capture: &RequestCapture)
    -> Result<(&aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
        &BrokerSessionTrafficStateV1), JournalError>
{
    match capture.value() {
        Some(AuthenticatedBrokerMethodRequestAdmissionV1::New { request, next_traffic }) => Ok((request, next_traffic)),
        _ => Err(JournalError::ProtectedBoundary),
    }
}

fn outcome_data_v1(capture: &OutcomeCapture) -> Result<&AuthenticatedBrokerMethodOutcomeV1, JournalError> {
    match capture.value() {
        Some(AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, .. }) => Ok(outcome),
        _ => Err(JournalError::ProtectedBoundary),
    }
}

fn catalog_binding_data_v1(generation: u64, digest: [u8;32])
    -> Result<aos_sandbox_protocol::semantics::CatalogBindingV1, aos_sandbox_protocol::semantics::StorageSemanticsError>
{
    aos_sandbox_protocol::semantics::CatalogBindingV1::from_publisher(generation,
        aos_sandbox_model::ObjectDigest::from_bytes(digest))
}
