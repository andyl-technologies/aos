//! Checks historical Storage input under Root's independently installed manifest.
//!
//! These models are comparison DATA. The actual accepted Controller identity
//! supplies request-validation parameters; no Storage peer, live Session or
//! receiving grant is reconstructed from the checkpoint or signed packets.

use std::error::Error as StdError;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionDurableHistoryV1,
    BrokerSessionDurablePhaseV1, BrokerSessionProtocolV1, BrokerSessionTrafficStateV1,
    ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    verify_historical_traffic_records_v1,
};
use aos_sandbox_broker_session_protocol::manifest::{BrokerSessionManifestV1,
    BrokerSessionManifestAudienceV1};
use aos_sandbox_broker_session_protocol::hello_message::{Audience, BrokerMethod};
use aos_sandbox_core::{CanonicalAssignmentManifestV1, OperationId, RawPairedClockSample,
    ResourceDimension as D, ResourceVector, ObjectDigest};
use aos_sandbox_core::model::{LimitDimension, LimitValue};
use aos_sandbox_policy::CompiledPolicyCandidateV1;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy};
use aos_sandbox_protocol::authenticated_session::{
    all_methods::{AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerMethodRequestAdmissionV1,
        AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodOutcomeAdmissionV1,
        AuthenticatedBrokerMethodResultV1, AuthenticatedBrokerSemanticBindingsV1,
        prepare_client_sent_authenticated_broker_method_request_v1,
        admit_client_received_authenticated_broker_method_outcome_v1},
    stored_history::{StoredBrokerSessionHistoryV1, canonical_protocol_key_v1},
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1, ready::ReadyBundleDataV1,
    controller_intent::ControllerIntentBodyDataV1,
};
use aos_sandbox_protocol::semantics::{CatalogBindingV1, ProtectedStorageCreatePreparationV1};
use aos_sandbox_protocol::storage_inventory::{ValidatedStorageInventory,
    decode_storage_resource_inventory_response_with_model};
use crate::journal::JournalError;
use crate::public_api_session::{RootCurrentStorageManifestCustodyV1, RootCurrentBrokerPlanCredentialCustodyV1};
use super::use_plan::RootProspectiveStorageUsePlanV1;
use super::session_extent::RootStorageSessionExtentV1;

mod terminal;
mod history_roster;
pub(in crate::policy_compiler) use history_roster::verify_storage_history_roster_v2;
pub(crate) use terminal::RootVerifiedSessionTerminalV1;

type Error = Box<dyn StdError>;

#[derive(Debug, thiserror::Error)]
#[error("the independently pinned Storage Inventory or proposed Storage model changed")]
struct Changed;

pub(crate) struct RootCurrentStorageInventoryV1 {
    credentials: RootCurrentStorageManifestCustodyV1,
    plan_credentials: RootCurrentBrokerPlanCredentialCustodyV1,
    session_extent: RootStorageSessionExtentV1,
    plan_capture: Option<Result<(), ()>>,
    plan_post: Option<Result<(), ()>>,
    prepared: Option<Result<RootProspectiveStorageUsePlanV1, Error>>,
    result: Option<Result<InventoryValues, Error>>,
    capture: Option<Result<(), ()>>,
    post: Option<Result<(), ()>>,
    entered: bool,
    closed: bool,
}

pub(in crate::policy_compiler) struct InventoryValues {
    manifest: BrokerSessionManifestV1,
    context: ProtectedBrokerSessionVerificationContextV1,
    transcript: VerifiedBrokerSessionTranscriptV1,
    stored: StoredBrokerSessionHistoryV1,
    history: BrokerSessionDurableHistoryV1,
    traffic: BrokerSessionTrafficStateV1,
    request: AuthenticatedBrokerMethodRequestV1,
    outcome: AuthenticatedBrokerMethodOutcomeV1,
    inventory: ValidatedStorageInventory,
    proposed: ProtectedStorageCreatePreparationV1,
}

impl Default for RootCurrentStorageInventoryV1 {
    fn default() -> Self {
        Self { credentials: RootCurrentStorageManifestCustodyV1::new(),
            plan_credentials: RootCurrentBrokerPlanCredentialCustodyV1::new(),
            session_extent: Default::default(),
            plan_capture: None, plan_post: None, prepared: None, result: None,
            capture: None, post: None, entered: false, closed: false }
    }
}

impl RootCurrentStorageInventoryV1 {
    pub(super) fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        // The three local trust-policy parses share the existing bounded Core
        // decoder. Its existing fixed public credential ceiling is admitted
        // before capture; no B-supplied policy or key becomes local trust.
        let carrier = aos_sandbox_core::format::TrustPolicyDecodeCaptureV1::
            receiving_carrier_bytes_v1(64 * 1024).and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| bytes.checked_add(16 * 64 * 1024))
            .ok_or(JournalError::JournalTooLarge)?;
        let carrier = u64::try_from(carrier).map_err(|_| JournalError::JournalTooLarge)?;
        let session = RootStorageSessionExtentV1::fixed_demand_v1()?;
        RootCurrentStorageManifestCustodyV1::dominant_demand()
            .ok_or(JournalError::JournalTooLarge)?
            .checked_add(RootCurrentBrokerPlanCredentialCustodyV1::dominant_demand()
                .ok_or(JournalError::JournalTooLarge)?)
            .and_then(|value| value.checked_add(session))
            .and_then(|value| value.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, carrier).with(D::OutputBytes, carrier)))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn encoded_width_v1(bundle: ReadyBundleDataV1<'_>) -> Result<usize, JournalError> {
        [bundle.storage_client_hello, bundle.storage_broker_hello,
            bundle.storage_inventory_request, bundle.storage_inventory_response,
            bundle.storage_inventory_checkpoint, bundle.ownership_claim,
            bundle.ownership_lease, bundle.ownership_signature,
            bundle.ownership_receipt, bundle.ownership_receipt_signature].into_iter()
            .try_fold(920usize, |sum, bytes| sum.checked_add(bytes.len()))
            .ok_or(JournalError::JournalTooLarge)
    }

    pub(crate) fn additional_demand_v1(p: usize) -> Result<ResourceVector, JournalError> {
        use aos_sandbox_protocol::authenticated_session::all_methods::{
            request_capture::AuthenticatedBrokerMethodRequestCaptureV1,
            outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1,
        };
        let request = AuthenticatedBrokerMethodRequestCaptureV1::dynamic_receiving_demand_v1(p)
            .ok_or(JournalError::JournalTooLarge)?;
        let outcome = AuthenticatedBrokerMethodOutcomeCaptureV1::dynamic_receiving_demand_v1(p)
            .ok_or(JournalError::JournalTooLarge)?;
        // Shared method recipes cover the two hostile protobuf/model frontiers.
        // Sixteen additional raw planes cover stored/checkpoint/history, HELLO,
        // context/transcript, replay and retained canonical replacements. Pure
        // temporaries use this dominant peak and the existing decoder backstops.
        let bytes = u64::try_from(p).ok().and_then(|p| p.checked_mul(16))
            .and_then(|p| p.checked_add(256 * 1024)).ok_or(JournalError::JournalTooLarge)?;
        let roster = history_roster::receiving_demand_v2(p)?;
        request.checked_add(outcome)
            .and_then(|value| value.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, bytes).with(D::OutputBytes, bytes)))
            .and_then(|value| value.checked_add(roster))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn observe_once(&mut self, bundle: ReadyBundleDataV1<'_>,
        assignment: &CanonicalAssignmentManifestV1, candidate: &CompiledPolicyCandidateV1,
        sample: RawPairedClockSample, controller: PeerCredentials,
        lease: &aos_sandbox_ownership_protocol::SignedOwnershipLease,
        policy_expires: i64, root_cutoff: u64,
    ) {
        if self.entered { self.closed = true; return; }
        self.entered = true;
        self.capture = Some(self.credentials.capture_once());
        if matches!(self.capture, Some(Ok(()))) {
            self.plan_capture = Some(self.plan_credentials.capture_once());
        }
        if matches!(self.plan_capture, Some(Ok(()))) {
            self.session_extent.capture_once(controller.uid);
        }
        if self.session_extent.require_captured_v1().is_ok() {
            self.result = Some((|| {
                let bytes = self.credentials.bytes().ok_or(Changed)?;
                verify_inventory(bytes, bundle, assignment, candidate, sample, controller)
            })());
        }
        if let Some(Ok(values)) = &self.result {
            self.prepared = Some((|| {
                let public = self.plan_credentials.bytes().ok_or(Changed)?;
                let intent = RecordEnvelopeV1::decode(bundle.intent_record,
                    KeyV1::new(bundle.lane, OwnerV1::Controller, 1)?,
                    PhaseV1::new(OwnerV1::Controller, 1)?)?;
                let intent = ControllerIntentBodyDataV1::decode(intent.body())?;
                RootProspectiveStorageUsePlanV1::prepare_once(public, &values.proposed,
                    candidate, lease, sample, intent.identity.cutoff.min(root_cutoff), policy_expires)
            })());
        }
    }

    // This independent post remains owed after either entered primary outcome.
    pub(super) fn finish_post_once(&mut self) {
        if self.capture.is_some() && self.post.is_none() {
            self.post = Some(self.credentials.recheck_once());
        }
        if self.plan_capture.is_some() && self.plan_post.is_none() {
            self.plan_post = Some(self.plan_credentials.recheck_once());
        }
        self.session_extent.finish_post_once();
    }

    pub(super) fn require_complete(&self) -> Result<(), JournalError> {
        if !self.closed && matches!(self.result, Some(Ok(_)))
            && matches!(self.post, Some(Ok(()))) && self.credentials.failure().is_none()
            && matches!(self.plan_post, Some(Ok(()))) && self.plan_credentials.failure().is_none()
            && matches!(self.prepared, Some(Ok(_)))
            && self.session_extent.extent_v1().is_ok()
        { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    }

    pub(super) fn require_live_at_v1(&self, sample: RawPairedClockSample)
        -> Result<(), JournalError>
    {
        let values = self.result.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let prepared = self.prepared.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if sample.wall_seconds() >= prepared.plan_data_v1().expires_seconds()
            || values.context.boot_id() != sample.host_boot_id()
            || sample.boottime_nanoseconds() >= values.request.deadline_boottime_nanoseconds()
        { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.credentials.capture_failure().map(|cause| cause as _)
            .or_else(|| self.plan_credentials.capture_failure().map(|cause| cause as _))
            .or_else(|| self.session_extent.failure())
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.prepared.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
    }

    pub(super) fn post_failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.credentials.post_failure().map(|cause| cause as _)
            .or_else(|| self.plan_credentials.post_failure().map(|cause| cause as _))
            .or_else(|| self.session_extent.post_failure())
    }

    pub(super) fn session_extent_v1(&self)
        -> Result<&crate::journal::ProtectedJournalPreopenReplayExtentV1, JournalError>
    {
        self.require_complete()?;
        self.session_extent.extent_v1()
    }

    pub(super) fn protected_preparation_v1(&self) -> Result<&ProtectedStorageCreatePreparationV1, JournalError> {
        self.require_complete()?;
        self.result.as_ref().and_then(|result| result.as_ref().ok())
            .map(|values| &values.proposed).ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn prospective_plan_v1(&self) -> Result<&RootProspectiveStorageUsePlanV1, JournalError> {
        self.require_complete()?;
        self.prepared.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }
}

fn verify_inventory(manifest_bytes: &[u8], bundle: ReadyBundleDataV1<'_>,
    assignment: &CanonicalAssignmentManifestV1, candidate: &CompiledPolicyCandidateV1,
    sample: RawPairedClockSample, controller: PeerCredentials,
) -> Result<InventoryValues, Error> {
    verify_inventory_with_request_time_v1(manifest_bytes, bundle, assignment,
        sample, controller, candidate.portable().policy().limits(), sample.boottime_nanoseconds())
}

// Historical transport deadlines are not new method permission. The actual
// fresh Apply owner first joins its held Root6 original and real C9/Session cut;
// it independently checks the original Prepare response and current lease.
pub(in crate::policy_compiler) fn verify_historical_inventory_v1(manifest_bytes: &[u8],
    bundle: ReadyBundleDataV1<'_>, assignment: &CanonicalAssignmentManifestV1,
    resources: &aos_sandbox_core::model::ResourceProfile, sample: RawPairedClockSample, controller: PeerCredentials,
) -> Result<InventoryValues, Error> {
    verify_inventory_with_request_time_v1(manifest_bytes, bundle, assignment,
        sample, controller, resources, sample.boottime_nanoseconds())
}

fn verify_inventory_with_request_time_v1(manifest_bytes: &[u8], bundle: ReadyBundleDataV1<'_>,
    assignment: &CanonicalAssignmentManifestV1, sample: RawPairedClockSample, controller: PeerCredentials,
    resources: &aos_sandbox_core::model::ResourceProfile, request_time: u64,
) -> Result<InventoryValues, Error> {
    let manifest = BrokerSessionManifestV1::decode(manifest_bytes)?;
    let stored = StoredBrokerSessionHistoryV1::decode(
        &canonical_protocol_key_v1(BrokerSessionProtocolV1::Storage),
        bundle.storage_inventory_checkpoint,
    )?;
    let (context, transcript, history, traffic) = verify_session_v1(&manifest, &stored,
        bundle.storage_client_hello, bundle.storage_broker_hello,
        *assignment.manifest().node().as_bytes(), sample.host_boot_id(),
        BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
        bundle.storage_inventory_request, bundle.storage_inventory_response)?;
    let head = history.head()?;
    // The fresh narrow Session's Inventory is its first request. Hidden earlier
    // traffic must fail the same sequence machine below, not disappear behind
    // the caller-selected terminal record.
    let initial = BrokerSessionTrafficStateV1::from_provisional_transcript(transcript.clone())?;
    let (request, pending) = match prepare_client_sent_authenticated_broker_method_request_v1(
        &initial, bundle.storage_inventory_request, None, 0, controller,
        PeerPolicy { uid: controller.uid, gid: Some(controller.gid),
            audience: Audience::AUDIENCE_NODE_CONTROLLER },
        request_time, AuthenticatedBrokerSemanticBindingsV1::new(None, None), &context,
    )? {
        AuthenticatedBrokerMethodRequestAdmissionV1::New { request, next_traffic } => (request, next_traffic),
        _ => return Err(Box::new(Changed)),
    };
    if request.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
        || request.authorization().is_some()
        || request.semantic_commitment() != head.request_semantic_binding()
    { return Err(Box::new(Changed)); }
    let outcome = match admit_client_received_authenticated_broker_method_outcome_v1(
        &pending, &request, bundle.storage_inventory_response, None, 0, &context,
    )? {
        AuthenticatedBrokerMethodOutcomeAdmissionV1::New { outcome, next_traffic }
            if next_traffic.as_ref() == &traffic => outcome,
        _ => return Err(Box::new(Changed)),
    };
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result()
        else { return Err(Box::new(Changed)); };
    let (inventory, model) = decode_storage_resource_inventory_response_with_model(
        exact_body, request.maximum_response_bytes(),
    )?;
    if inventory.kernel_boot_id() != &sample.host_boot_id()
    { return Err(Box::new(Changed)); }
    let catalog: [u8; 32] = model.lifecycle_catalog_head.as_slice().try_into()?;
    let binding = CatalogBindingV1::from_publisher(model.lifecycle_catalog_generation,
        ObjectDigest::from_bytes(catalog))?;
    let intent = RecordEnvelopeV1::decode(bundle.intent_record,
        KeyV1::new(bundle.lane, OwnerV1::Controller, 1)?,
        PhaseV1::new(OwnerV1::Controller, 1)?)?;
    let intent = ControllerIntentBodyDataV1::decode(intent.body())?;
    if request.deadline_boottime_nanoseconds() != intent.identity.cutoff {
        return Err(Box::new(Changed));
    }
    let quota = resources.limits().iter()
        .find(|limit| limit.dimension() == LimitDimension::Bytes).ok_or(Changed)?;
    let LimitValue::Bounded(quota) = quota.value() else { return Err(Box::new(Changed)); };
    let reservation = assignment.manifest().reservations().get(D::StorageBytes);
    let proposed = ProtectedStorageCreatePreparationV1::from_protected_inputs(
        assignment.broker_assignment()?, OperationId::from_bytes(intent.identity.operation),
        quota, reservation, binding, binding, intent.identity.cutoff,
    )?;
    if proposed.canonical_bytes() != bundle.proposed_storage { return Err(Box::new(Changed)); }
    Ok(InventoryValues { manifest, context, transcript, stored, history, traffic,
        request, outcome, inventory, proposed })
}

impl InventoryValues {
    pub(in crate::policy_compiler) fn storage_manifest_data_v1(&self) -> &BrokerSessionManifestV1 { &self.manifest }

    pub(in crate::policy_compiler) fn protected_preparation_v1(&self) -> &ProtectedStorageCreatePreparationV1 {
        &self.proposed
    }
}

fn verify_session_v1(manifest: &BrokerSessionManifestV1,
    stored: &StoredBrokerSessionHistoryV1, client_hello: &[u8], broker_hello: &[u8],
    node: [u8; 16], boot: [u8; 16], method: BrokerMethod, request: &[u8], outcome: &[u8],
) -> Result<(ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1), Error>
{
    verify_session_for_purpose_v1(manifest, stored, client_hello, broker_hello, node, boot,
        method, request, outcome, RootHistoricalSessionPurposeV1::Preparation)
}

#[derive(Clone, Copy)]
pub(in crate::policy_compiler) enum RootHistoricalSessionPurposeV1 {
    Preparation,
    DeletePreparation,
    Apply,
    OperatorRecoverInventory,
    MaintenanceStorageInventory,
    StartNetwork,
    StartMount,
    StartHost,
    ExecutionNoApplyCurrentLease,
    ExecutionNoApplyCleanupLease,
    ExecutionNoApplyHistory,
    DeleteInventory(BrokerSessionProtocolV1, BrokerMethod),
    DeleteNetworkDestroy,
    DeleteHostTerminal,
    DeleteMountReap,
    DeleteStorageDestroy,
}

pub(in crate::policy_compiler) fn verify_session_for_purpose_v1(manifest: &BrokerSessionManifestV1,
    stored: &StoredBrokerSessionHistoryV1, client_hello: &[u8], broker_hello: &[u8],
    node: [u8;16], boot: [u8;16], method: BrokerMethod, request: &[u8], outcome: &[u8],
    purpose: RootHistoricalSessionPurposeV1,
) -> Result<(ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1), Error>
{
    verify_session_inner_v2(manifest, stored, client_hello, broker_hello, node, boot,
        method, SessionHeadSelectionV2::Exact(request, outcome), purpose, None)
}

pub(in crate::policy_compiler) fn verify_start_resource_session_retaining_v2(
    kind: crate::policy_compiler::host_launch_root::kind::ResourceKindV2,
    manifest: &BrokerSessionManifestV1, stored: &StoredBrokerSessionHistoryV1,
    client_hello: &[u8], broker_hello: &[u8], node: [u8;16], boot: [u8;16],
    request: &[u8], outcome: &[u8],
    checkpoint_capture: &mut aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointVerifyCaptureV1,
    traffic_capture: &mut aos_sandbox_broker_session_protocol::HistoricalTrafficReplayCaptureV1,
) -> Result<(ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1), Error> {
    verify_session_inner_v2(manifest, stored, client_hello, broker_hello, node, boot,
        kind.inventory_method_v2(), SessionHeadSelectionV2::Exact(request, outcome),
        match kind {
            crate::policy_compiler::host_launch_root::kind::ResourceKindV2::Host => RootHistoricalSessionPurposeV1::StartHost,
            crate::policy_compiler::host_launch_root::kind::ResourceKindV2::Network => RootHistoricalSessionPurposeV1::StartNetwork,
            crate::policy_compiler::host_launch_root::kind::ResourceKindV2::Mount => RootHistoricalSessionPurposeV1::StartMount,
            crate::policy_compiler::host_launch_root::kind::ResourceKindV2::StorageGuestRoot => RootHistoricalSessionPurposeV1::Apply,
        }, Some((checkpoint_capture, traffic_capture)))
}

// Selection is private to these fixed Root readers. CurrentInventory never
// accepts a caller packet or bypasses full checkpoint/profile/traffic replay.
enum SessionHeadSelectionV2<'packet> {
    Exact(&'packet [u8], &'packet [u8]),
    CurrentInventory,
    HistoricalPrefix,
}

pub(in crate::policy_compiler) fn verify_current_start_resource_inventory_retaining_v2(
    kind: crate::policy_compiler::host_launch_root::kind::ResourceKindV2,
    manifest: &BrokerSessionManifestV1, stored: &StoredBrokerSessionHistoryV1,
    client_hello: &[u8], broker_hello: &[u8], node: [u8;16], boot: [u8;16],
    checkpoint_capture: &mut aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointVerifyCaptureV1,
    traffic_capture: &mut aos_sandbox_broker_session_protocol::HistoricalTrafficReplayCaptureV1,
) -> Result<(ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1), Error> {
    use crate::policy_compiler::host_launch_root::kind::ResourceKindV2;
    let purpose = match kind {
        ResourceKindV2::Mount => RootHistoricalSessionPurposeV1::StartMount,
        ResourceKindV2::Network => RootHistoricalSessionPurposeV1::StartNetwork,
        ResourceKindV2::StorageGuestRoot | ResourceKindV2::Host => return Err(Box::new(Changed)),
    };
    verify_session_inner_v2(manifest, stored, client_hello, broker_hello, node, boot,
        kind.inventory_method_v2(), SessionHeadSelectionV2::CurrentInventory,
        purpose, Some((checkpoint_capture, traffic_capture)))
}

/// Verifies Maintenance's actual Storage18 cut through the shared verifier.
///
/// This closed entrance authenticates the full ordinary Storage lifecycle
/// profile. It does not broaden Start's current-inventory purpose or grant31.
pub(in crate::policy_compiler) fn verify_current_maintenance_storage_inventory_retaining_v2(
    manifest: &BrokerSessionManifestV1, stored: &StoredBrokerSessionHistoryV1,
    client_hello: &[u8], broker_hello: &[u8], node: [u8;16], boot: [u8;16],
    checkpoint_capture: &mut aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointVerifyCaptureV1,
    traffic_capture: &mut aos_sandbox_broker_session_protocol::HistoricalTrafficReplayCaptureV1,
) -> Result<(ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1), Error> {
    verify_session_inner_v2(manifest, stored, client_hello, broker_hello, node, boot,
        BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
        SessionHeadSelectionV2::CurrentInventory,
        RootHistoricalSessionPurposeV1::MaintenanceStorageInventory,
        Some((checkpoint_capture, traffic_capture)))
}

/// Verifies exact final Storage31/fresh18 packet DATA for the closed Maintenance purpose.
pub(in crate::policy_compiler) fn verify_maintenance_storage_session_retaining_v3(
    manifest: &BrokerSessionManifestV1, stored: &StoredBrokerSessionHistoryV1,
    client_hello: &[u8], broker_hello: &[u8], node: [u8;16], boot: [u8;16],
    request: &[u8], outcome: &[u8],
    checkpoint_capture: &mut aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointVerifyCaptureV1,
    traffic_capture: &mut aos_sandbox_broker_session_protocol::HistoricalTrafficReplayCaptureV1,
) -> Result<(ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1), Error> {
    verify_session_inner_v2(manifest, stored, client_hello, broker_hello, node, boot,
        BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
        SessionHeadSelectionV2::Exact(request, outcome),
        RootHistoricalSessionPurposeV1::MaintenanceStorageInventory,
        Some((checkpoint_capture, traffic_capture)))
}

/// Verifies the actual current Host43 head through the sole Session engine.
///
/// The paid Root reader supplies the native journal. This closed purpose
/// verifies the complete ordinary Controller Host profile and Execution
/// continuation methods; it does not adopt the three-method Start profile.
pub(in crate::policy_compiler) fn verify_current_execution_no_apply_session_retaining_v2(
    manifest: &BrokerSessionManifestV1, stored: &StoredBrokerSessionHistoryV1,
    client_hello: &[u8], broker_hello: &[u8], node: [u8;16], boot: [u8;16],
    checkpoint_capture: &mut aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointVerifyCaptureV1,
    traffic_capture: &mut aos_sandbox_broker_session_protocol::HistoricalTrafficReplayCaptureV1,
) -> Result<(ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1), Error> {
    verify_session_inner_v2(manifest, stored, client_hello, broker_hello, node, boot,
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2,
        SessionHeadSelectionV2::CurrentInventory,
        RootHistoricalSessionPurposeV1::ExecutionNoApplyCurrentLease,
        Some((checkpoint_capture, traffic_capture)))
}

/// Verifies a finite Host history prefix without claiming its head completed.
/// Current manifest pins independently authenticate all historical signatures;
/// a pending request remains pending and can never prove the absence of Seal.
pub(in crate::policy_compiler) fn verify_execution_host_history_retaining_v2(
    manifest: &BrokerSessionManifestV1, stored: &StoredBrokerSessionHistoryV1,
    node: [u8;16], boot: [u8;16],
    checkpoint_capture: &mut aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointVerifyCaptureV1,
    traffic_capture: &mut aos_sandbox_broker_session_protocol::HistoricalTrafficReplayCaptureV1,
) -> Result<(ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1), Error> {
    let checkpoint = stored.checkpoint.as_ref().ok_or(Changed)?;
    verify_session_inner_v2(manifest, stored, checkpoint.client_hello_bytes(),
        checkpoint.broker_hello_bytes(), node, boot, BrokerMethod::BROKER_METHOD_UNSPECIFIED,
        SessionHeadSelectionV2::HistoricalPrefix, RootHistoricalSessionPurposeV1::ExecutionNoApplyHistory,
        Some((checkpoint_capture, traffic_capture)))
}

/// Verifies current43 only on the distinct fresh42/43 cleanup Session.
pub(in crate::policy_compiler) fn verify_current_execution_no_apply_cleanup_session_retaining_v2(
    manifest: &BrokerSessionManifestV1, stored: &StoredBrokerSessionHistoryV1,
    node: [u8;16], boot: [u8;16],
    checkpoint_capture: &mut aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointVerifyCaptureV1,
    traffic_capture: &mut aos_sandbox_broker_session_protocol::HistoricalTrafficReplayCaptureV1,
) -> Result<(ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1), Error> {
    let checkpoint = stored.checkpoint.as_ref().ok_or(Changed)?;
    verify_session_inner_v2(manifest, stored, checkpoint.client_hello_bytes(),
        checkpoint.broker_hello_bytes(), node, boot,
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2,
        SessionHeadSelectionV2::CurrentInventory, RootHistoricalSessionPurposeV1::ExecutionNoApplyCleanupLease,
        Some((checkpoint_capture, traffic_capture)))
}

fn verify_session_inner_v2(manifest: &BrokerSessionManifestV1,
    stored: &StoredBrokerSessionHistoryV1, client_hello: &[u8], broker_hello: &[u8],
    node: [u8;16], boot: [u8;16], method: BrokerMethod, expected: SessionHeadSelectionV2<'_>,
    purpose: RootHistoricalSessionPurposeV1,
    mut retained: Option<(&mut aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointVerifyCaptureV1,
        &mut aos_sandbox_broker_session_protocol::HistoricalTrafficReplayCaptureV1)>,
) -> Result<(ProtectedBrokerSessionVerificationContextV1, VerifiedBrokerSessionTranscriptV1,
    BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1), Error>
{
    let checkpoint = stored.checkpoint.as_ref().ok_or(Changed)?;
    let protocol = match purpose {
        RootHistoricalSessionPurposeV1::Preparation | RootHistoricalSessionPurposeV1::DeletePreparation | RootHistoricalSessionPurposeV1::Apply
            | RootHistoricalSessionPurposeV1::OperatorRecoverInventory
            | RootHistoricalSessionPurposeV1::MaintenanceStorageInventory => BrokerSessionProtocolV1::Storage,
        RootHistoricalSessionPurposeV1::StartHost
            | RootHistoricalSessionPurposeV1::ExecutionNoApplyCurrentLease
            | RootHistoricalSessionPurposeV1::ExecutionNoApplyCleanupLease
            | RootHistoricalSessionPurposeV1::ExecutionNoApplyHistory => BrokerSessionProtocolV1::Host,
        RootHistoricalSessionPurposeV1::StartNetwork => BrokerSessionProtocolV1::Network,
        RootHistoricalSessionPurposeV1::StartMount => BrokerSessionProtocolV1::Mount,
        RootHistoricalSessionPurposeV1::DeleteInventory(protocol, _) => protocol,
        RootHistoricalSessionPurposeV1::DeleteNetworkDestroy => BrokerSessionProtocolV1::Network,
        RootHistoricalSessionPurposeV1::DeleteHostTerminal => BrokerSessionProtocolV1::Host,
        RootHistoricalSessionPurposeV1::DeleteMountReap => BrokerSessionProtocolV1::Mount,
        RootHistoricalSessionPurposeV1::DeleteStorageDestroy => BrokerSessionProtocolV1::Storage,
    };
    if stored.protocol != protocol
        || stored.endpoint != BrokerSessionDurableEndpointV1::Client
        || checkpoint.client_hello_bytes() != client_hello
        || checkpoint.broker_hello_bytes() != broker_hello
    { return Err(Box::new(Changed)); }
    // Only the local protected manifest supplies keys/current policy. Historical
    // process claims are comparison DATA only after both signatures verify.
    let context = local_context_for_protocol_v2(manifest, checkpoint.context(),
        node, boot, protocol)?;
    let transcript = match retained.as_mut() {
        Some((capture, _)) => {
            checkpoint.verify_retaining(capture)?;
            capture.take_transcript_once()?
        }
        None => checkpoint.verify()?,
    };
    let correct_profile = match purpose {
        RootHistoricalSessionPurposeV1::DeleteMountReap =>
            transcript.protocol() == BrokerSessionProtocolV1::Mount
                && transcript.audience() == Audience::AUDIENCE_NODE_CONTROLLER
                && method == BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1
                && transcript.negotiated_methods().contains(&method),
        RootHistoricalSessionPurposeV1::DeleteStorageDestroy =>
            method == BrokerMethod::BROKER_METHOD_STORAGE_APPLY
                && aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(&transcript),
        RootHistoricalSessionPurposeV1::DeleteNetworkDestroy =>
            transcript.protocol() == BrokerSessionProtocolV1::Network
                && transcript.audience() == Audience::AUDIENCE_NODE_CONTROLLER
                && method == BrokerMethod::BROKER_METHOD_NETWORK_APPLY
                && transcript.negotiated_methods().contains(&method),
        RootHistoricalSessionPurposeV1::DeleteHostTerminal =>
            transcript.protocol() == BrokerSessionProtocolV1::Host
                && transcript.audience() == Audience::AUDIENCE_NODE_CONTROLLER
                && method == BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
                && transcript.negotiated_methods().contains(&method),
        RootHistoricalSessionPurposeV1::Preparation =>
            aos_sandbox_broker_session_protocol::profile::is_storage_preparation_transcript_v1(&transcript),
        RootHistoricalSessionPurposeV1::DeletePreparation =>
            method == BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG
                && aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(&transcript),
        RootHistoricalSessionPurposeV1::Apply =>
            aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(&transcript),
        RootHistoricalSessionPurposeV1::MaintenanceStorageInventory =>
            method == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                && aos_sandbox_broker_session_protocol::profile::is_storage_lifecycle_transcript_v2(&transcript),
        RootHistoricalSessionPurposeV1::OperatorRecoverInventory =>
            method == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
                && aos_sandbox_broker_session_protocol::profile::is_storage_operator_recover_transcript_v1(&transcript),
        RootHistoricalSessionPurposeV1::StartHost =>
            method == BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME
                && aos_sandbox_broker_session_protocol::profile::is_start_host_catalog_launch_transcript_v2(&transcript),
        RootHistoricalSessionPurposeV1::ExecutionNoApplyCurrentLease => {
            let ordinary = aos_sandbox_broker_session_protocol::profile::
                authenticated_broker_methods_for_role_v1(BrokerSessionProtocolV1::Host,
                    Audience::AUDIENCE_NODE_CONTROLLER);
            let execution = [BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2,
                BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2,
                BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2,
                BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY,
                BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2,
                BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2];
            method == BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2
                && transcript.protocol() == BrokerSessionProtocolV1::Host
                && transcript.audience() == Audience::AUDIENCE_NODE_CONTROLLER
                && ordinary.iter().chain(execution.iter()).all(|required|
                    transcript.required_methods().contains(required)
                        && transcript.negotiated_methods().contains(required))
        }
        RootHistoricalSessionPurposeV1::ExecutionNoApplyCleanupLease =>
            method == BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2
                && aos_sandbox_broker_session_protocol::profile::
                    is_host_no_apply_cleanup_transcript_v1(&transcript),
        RootHistoricalSessionPurposeV1::ExecutionNoApplyHistory => {
            let ordinary = aos_sandbox_broker_session_protocol::profile::
                authenticated_broker_methods_for_role_v1(BrokerSessionProtocolV1::Host,
                    Audience::AUDIENCE_NODE_CONTROLLER);
            transcript.protocol() == BrokerSessionProtocolV1::Host
                && transcript.audience() == Audience::AUDIENCE_NODE_CONTROLLER
                && (ordinary.iter().all(|required|
                    transcript.required_methods().contains(required)
                        && transcript.negotiated_methods().contains(required))
                    || aos_sandbox_broker_session_protocol::profile::
                        is_start_host_catalog_launch_transcript_v2(&transcript)
                    || aos_sandbox_broker_session_protocol::profile::
                        is_host_no_apply_cleanup_transcript_v1(&transcript)
                    || aos_sandbox_broker_session_protocol::profile::
                        is_host_stop_cleanup_transcript_v1(&transcript))
        }
        RootHistoricalSessionPurposeV1::StartNetwork =>
            method == BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES
                && (aos_sandbox_broker_session_protocol::profile::is_network_preparation_transcript_v2(&transcript)
                    || aos_sandbox_broker_session_protocol::profile::is_network_service_transcript_v5(&transcript)),
        RootHistoricalSessionPurposeV1::StartMount =>
            method == BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS
                && aos_sandbox_broker_session_protocol::profile::is_mount_attachment_anchor_transcript_v4(&transcript),
        RootHistoricalSessionPurposeV1::DeleteInventory(protocol, inventory) => {
            transcript.protocol() == protocol && transcript.audience() == Audience::AUDIENCE_NODE_CONTROLLER
                && method == inventory && transcript.required_methods().contains(&inventory)
                && transcript.negotiated_methods().contains(&inventory)
        }
    };
    if !correct_profile { return Err(Box::new(Changed)); }
    let history = stored.history_model()?;
    let head = history.head()?;
    let historical_prefix = matches!(&expected, SessionHeadSelectionV2::HistoricalPrefix);
    if !historical_prefix && (head.phase() != BrokerSessionDurablePhaseV1::Terminal
        || head.method() != method
        || match expected {
            SessionHeadSelectionV2::Exact(request, outcome) =>
                head.request_packet() != request || head.outcome_packet() != Some(outcome),
            SessionHeadSelectionV2::CurrentInventory => head.outcome_packet().is_none(),
            SessionHeadSelectionV2::HistoricalPrefix => false,
        }
        ) || history.head_commitment() != stored.current_head
    { return Err(Box::new(Changed)); }
    let traffic = match retained.as_mut() {
        Some((_, capture)) => {
            aos_sandbox_broker_session_protocol::verify_historical_traffic_records_retaining_v1(
                history.records(), &transcript, &context, capture)?;
            capture.take_traffic_once()?
        }
        None => verify_historical_traffic_records_v1(history.records(), &transcript, &context)?,
    };
    if !historical_prefix && traffic.has_outstanding_request() { return Err(Box::new(Changed)); }
    Ok((context, transcript, history, traffic))
}

fn local_context_v1(manifest: &BrokerSessionManifestV1,
    historical: &ProtectedBrokerSessionVerificationContextV1,
    node: [u8; 16], boot: [u8; 16],
) -> Result<ProtectedBrokerSessionVerificationContextV1, Error> {
    local_context_for_protocol_v2(manifest, historical, node, boot, BrokerSessionProtocolV1::Storage)
}

fn local_context_for_protocol_v2(manifest: &BrokerSessionManifestV1,
    historical: &ProtectedBrokerSessionVerificationContextV1,
    node: [u8; 16], boot: [u8; 16], protocol: BrokerSessionProtocolV1,
) -> Result<ProtectedBrokerSessionVerificationContextV1, Error> {
    manifest.require_all_active()?;
    if manifest.protocol() != protocol
        || manifest.audience() != BrokerSessionManifestAudienceV1::NodeController
        || manifest.node_id() != node
    { return Err(Box::new(Changed)); }
    let local = manifest.verification_context(boot,
        historical.client_process(), historical.broker_process())?;
    if &local != historical { return Err(Box::new(Changed)); }
    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_broker_session_protocol::{BrokerSessionKeyUsageV1 as Usage,
        BrokerSessionSignerReferenceV1};
    use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestKeyPinV1;
    use ed25519_dalek::SigningKey;

    fn manifest(key_offset: u8, revoked: bool) -> BrokerSessionManifestV1 {
        let usages = [Usage::ClientHello, Usage::BrokerHello, Usage::ClientRecord, Usage::BrokerOutcome];
        let keys = std::array::from_fn(|index| {
            let key = SigningKey::from_bytes(&[key_offset + index as u8; 32]);
            let signer = BrokerSessionSignerReferenceV1::for_signing_key(
                [10 + index as u8; 16], 1, [20 + index as u8; 32],
                [30 + index as u8; 16], 1, usages[index], &key,
            ).unwrap();
            BrokerSessionManifestKeyPinV1::new(signer, key.verifying_key().to_bytes(),
                1, 1, revoked && index == 3, None).unwrap()
        });
        BrokerSessionManifestV1::new(BrokerSessionProtocolV1::Storage,
            BrokerSessionManifestAudienceV1::NodeController, 1, 0,
            [1; 16], [2; 16], 1, [3; 32], 1, [4; 32], 1, [5; 32], [6; 16], keys).unwrap()
    }

    #[test]
    fn historical_keys_cannot_replace_roots_independently_pinned_keys() {
        let local = manifest(40, false);
        let same = local.verification_context([7; 16], [8; 16], [9; 16]).unwrap();
        let other = manifest(50, false).verification_context([7; 16], [8; 16], [9; 16]).unwrap();

        assert_eq!(local_context_v1(&local, &same, [6; 16], [7; 16]).unwrap(), same);
        assert!(local_context_v1(&local, &other, [6; 16], [7; 16]).is_err());
        assert!(local_context_v1(&local, &same, [10; 16], [7; 16]).is_err());
        assert!(local_context_v1(&local, &same, [6; 16], [11; 16]).is_err());
    }

    #[test]
    fn local_revocation_refuses_even_when_historical_context_was_active() {
        let active = manifest(40, false);
        let historical = active.verification_context([7; 16], [8; 16], [9; 16]).unwrap();
        let revoked = manifest(40, true);

        assert!(local_context_v1(&revoked, &historical, [6; 16], [7; 16]).is_err());
        assert_eq!(active.encode().len(), 920);
    }
}
