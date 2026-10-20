//! Joins Apply's original Ready and prepared outcome to Root-owned native inputs.
//!
//! New closed R stages pay fixed credentials, their actual captured typed
//! extent, and B's exact quartet/manifest before the existing decoders grow.
//! Only this listener's actual retained Root6 association permits historical
//! Inventory/Prepare interpretation. A new Apply always needs current verified
//! Ownership, fresh compiled policy and its unchanged original temporal bound.

use std::error::Error;
use std::mem::size_of;
use aos_sandbox_core::{CanonicalAssignmentManifestV1, DecodeLimits, RawPairedClockSample,
    ResourceDimension as D, ResourceVector};
use aos_sandbox_core::format::assignment_capture::CanonicalAssignmentDecodeCaptureV1;
use aos_sandbox_ownership_protocol::{SignedOwnershipLease, response_verification::{
    OwnershipClaimDecodeCaptureV1, OwnershipResponseVerifyCaptureV1}, trusted_policy::{
    OwnershipTrustConfigurationCaptureV1}};
use aos_sandbox_policy::CompiledPolicyCandidateV1;
use aos_sandbox_protocol::{PeerCredentials, semantics::ProtectedStorageCreatePreparationV1};
use aos_sandbox_protocol::domain_ledger::{create_storage_history::{
    ready::ReadyBundleDataV1, controller_intent::ControllerIntentBodyDataV1,
    controller_use::{ControllerSignedBodyDataV1, ControllerSessionReservedBodyDataV1},
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1},
    outcome::{OutcomeBundleDataV1, ControllerOutcomeBodyDataV1, RootClosedBodyDataV1,
        HandoffRetainedBodyDataV1}, KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
}, provisioning_root::storage_apply::{StorageApplyQueryDataV1, StorageApplySubjectDataV1},
    resource_bank::{AccountHead, AccountKind, is_head_entry}};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::{JournalError, RecordNamespace};
use crate::normal_root::{RootApplyStageReceivingV1, RootPolicyAcceptedFlightV1};
use crate::public_api_session::{RootCurrentOwnershipCredentialCustodyV1,
    RootCurrentStorageManifestCustodyV1, RootCurrentBrokerPlanCredentialCustodyV1};
use crate::policy_compiler::create_storage_current::{bundle_ownership::{
    planned_assignment_v1, require_claim_data_v1, require_manifest_data_v1,
    ownership_bundle_typed_demand_v1}, controller_readonly::{
    storage_inventory::{InventoryValues, verify_historical_inventory_v1, RootVerifiedSessionTerminalV1},
}};
use super::{RootContinuationClockGateV1, RootContinuationHorizonDataV1};
use super::apply_readonly::RootApplyReadonlyContextV1;

type Cause = Box<dyn Error>;

struct NativeV1 {
    trust_files: RootCurrentOwnershipCredentialCustodyV1,
    trust: OwnershipTrustConfigurationCaptureV1,
    manifest: Option<Box<CanonicalAssignmentDecodeCaptureV1>>,
    claim: Option<Box<OwnershipClaimDecodeCaptureV1>>,
    response: Option<Box<OwnershipResponseVerifyCaptureV1>>,
    storage_files: RootCurrentStorageManifestCustodyV1,
    plan_files: RootCurrentBrokerPlanCredentialCustodyV1,
    clock: RootContinuationClockGateV1,
    trust_capture: Option<Result<(), ()>>,
    storage_capture: Option<Result<(), ()>>,
    plan_capture: Option<Result<(), ()>>,
    trust_post: Option<Result<(), ()>>,
    storage_post: Option<Result<(), ()>>,
    plan_post: Option<Result<(), ()>>,
    inventory: Option<Result<InventoryValues, Cause>>,
    terminal: Option<Result<RootVerifiedSessionTerminalV1, Cause>>,
    trust_typed: Option<Result<(), Cause>>,
    bundle_typed: Option<Result<(), Cause>>,
    storage_entry: Option<Result<(), Cause>>,
    storage_verified: Option<Result<(), Cause>>,
}

impl NativeV1 {
    fn new(horizon: RootContinuationHorizonDataV1) -> Self {
        Self { trust_files: RootCurrentOwnershipCredentialCustodyV1::new(),
            trust: OwnershipTrustConfigurationCaptureV1::new(), manifest: None, claim: None, response: None,
            storage_files: RootCurrentStorageManifestCustodyV1::new(),
            plan_files: RootCurrentBrokerPlanCredentialCustodyV1::new(),
            clock: RootContinuationClockGateV1::new(horizon), trust_capture: None,
            storage_capture: None, plan_capture: None, trust_post: None, storage_post: None, plan_post: None,
            inventory: None, terminal: None, trust_typed: None, bundle_typed: None,
            storage_entry: None, storage_verified: None }
    }

    fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let bytes = size_of::<Self>().checked_mul(2).and_then(|bytes|
            bytes.checked_add(2 * size_of::<RootApplyInputsOriginalV1>()))
            .and_then(|bytes| super::ownership_trust::receiving_frame_bytes_v2()
                .and_then(|frame| bytes.checked_add(frame)))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        RootCurrentOwnershipCredentialCustodyV1::dominant_demand().ok_or(JournalError::JournalTooLarge)?
            .checked_add(RootContinuationClockGateV1::receiving_demand_v1()?)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    fn prepare_trust_once_v1(&mut self, stage: &mut RootApplyStageReceivingV1<'_, '_>) -> Result<(), Cause> {
        super::ownership_trust::prepare_once_v2(
            super::ownership_trust::RootOwnershipTrustReceivingV2::Apply(stage),
            &mut self.clock, &mut self.trust_files, &mut self.trust,
            &mut self.trust_capture,
        )
    }

    fn verify_bundle_once_v1(&mut self, stage: &mut RootApplyStageReceivingV1<'_, '_>,
        bundle: ReadyBundleDataV1<'_>) -> Result<(), Cause>
    {
        let planned = planned_assignment_v1(bundle)?;
        let verifier = self.trust.verifier().ok_or(JournalError::ProtectedBoundary)?;
        stage.admit_apply_bundle_typed_once_v1(demand(ownership_bundle_typed_demand_v1(
            bundle, planned.manifest.len(), verifier)?))?;
        let sample = self.clock.check_next_once_v1()?;
        self.manifest = Some(Box::new(CanonicalAssignmentDecodeCaptureV1::new()));
        self.claim = Some(Box::new(OwnershipClaimDecodeCaptureV1::new()));
        self.response = Some(Box::new(OwnershipResponseVerifyCaptureV1::new()));
        self.manifest.as_mut().ok_or(JournalError::ProtectedBoundary)?
            .decode_once_v1(planned.manifest, DecodeLimits::default())?;
        self.claim.as_mut().ok_or(JournalError::ProtectedBoundary)?.decode_once_v1(bundle.ownership_claim)?;
        let claim = self.claim.as_ref().and_then(|claim| claim.value()).ok_or(JournalError::ProtectedBoundary)?;
        let manifest = self.manifest.as_ref().and_then(|manifest| manifest.value()).ok_or(JournalError::ProtectedBoundary)?;
        let intent = RecordEnvelopeV1::decode(bundle.intent_record, KeyV1::new(bundle.lane, OwnerV1::Controller, 1)?,
            PhaseV1::new(OwnerV1::Controller, 1)?)?;
        let intent = ControllerIntentBodyDataV1::decode(intent.body())?;
        let node = stage.enrolled_node_v1()?;
        require_claim_data_v1(claim, intent.identity.operation, intent.identity.sandbox, node, planned.manifest)?;
        require_manifest_data_v1(manifest, claim, intent.identity.project, &planned, bundle.specification)?;
        verifier.verify_response_bytes_retaining_v1(claim, bundle.ownership_lease, bundle.ownership_signature,
            bundle.ownership_receipt, bundle.ownership_receipt_signature, &sample,
            self.response.as_mut().ok_or(JournalError::ProtectedBoundary)?)?;
        Ok(())
    }

    fn prepare_storage_inputs_once_v1(&mut self, stage: &mut RootApplyStageReceivingV1<'_, '_>,
        subject: StorageApplySubjectDataV1<'_>) -> Result<(), Cause>
    {
        let encoded = subject.encoded_bytes_v1()?;
        let decode = crate::policy_compiler::create_storage_current::controller_readonly::storage_inventory::
            RootCurrentStorageInventoryV1::additional_demand_v1(encoded)?;
        let fixed = RootCurrentStorageManifestCustodyV1::dominant_demand().ok_or(JournalError::JournalTooLarge)?
            .checked_add(RootCurrentBrokerPlanCredentialCustodyV1::dominant_demand().ok_or(JournalError::JournalTooLarge)?)?;
        // The shared public-trust decoder bounds its canonical policy model.
        let trust = aos_sandbox_core::format::TrustPolicyDecodeCaptureV1::receiving_carrier_bytes_v1(64 * 1024)
            .and_then(|bytes| bytes.checked_mul(3)).and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let complete = fixed.checked_add(decode)?.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, trust).with(D::OutputBytes, trust))?;
        stage.admit_apply_storage_inputs_once_v1(demand(complete))?;
        self.clock.check_next_once_v1()?;
        self.storage_capture = Some(self.storage_files.capture_once());
        self.plan_capture = Some(self.plan_files.capture_once());
        if !matches!(self.storage_capture, Some(Ok(()))) || !matches!(self.plan_capture, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    fn finish_posts_once_v1(&mut self) {
        if self.trust_capture.is_some() { self.trust_post = Some(self.trust_files.recheck_once()); }
        if self.storage_capture.is_some() { self.storage_post = Some(self.storage_files.recheck_once()); }
        if self.plan_capture.is_some() { self.plan_post = Some(self.plan_files.recheck_once()); }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.trust_files.capture_failure().map(|cause| cause as _)
            .or_else(|| self.clock.failure()).or_else(|| boxed(&self.trust_typed))
            .or_else(|| self.trust.failure()).or_else(|| boxed(&self.bundle_typed))
            .or_else(|| self.manifest.as_ref().and_then(|manifest| manifest.cause()))
            .or_else(|| self.claim.as_ref().and_then(|claim| claim.failure()).map(|cause| cause as _))
            .or_else(|| self.response.as_ref().and_then(|response| response.cause()))
            .or_else(|| boxed(&self.storage_entry))
            .or_else(|| self.storage_files.capture_failure().map(|cause| cause as _))
            .or_else(|| self.plan_files.capture_failure().map(|cause| cause as _))
            .or_else(|| boxed(&self.inventory)).or_else(|| boxed(&self.terminal)).or_else(|| boxed(&self.storage_verified))
            .or_else(|| self.trust_files.post_failure().map(|cause| cause as _))
            .or_else(|| self.storage_files.post_failure().map(|cause| cause as _))
            .or_else(|| self.plan_files.post_failure().map(|cause| cause as _))
    }
}

/// Retains the actual fixed Root trust and typed original ownership response.
pub(crate) struct RootApplyInputsOriginalV1 {
    fixed: Option<Result<(), Cause>>,
    native: Option<Box<NativeV1>>,
    closed: bool,
}

impl RootApplyInputsOriginalV1 {
    pub(crate) fn new() -> Self { Self { fixed: None, native: None, closed: false } }

    pub(crate) fn prepare_once_v1(&mut self, stage: &mut RootApplyStageReceivingV1<'_, '_>,
        horizon: RootContinuationHorizonDataV1, bundle: ReadyBundleDataV1<'_>,
        policy_interval_demand: ResourceVector) -> Result<(), JournalError>
    {
        if self.fixed.is_some() { self.closed = true; return Err(JournalError::ProtectedBoundary); }
        self.fixed = Some((|| { stage.admit_apply_trust_fixed_once_v1(demand(NativeV1::fixed_demand_v1()?.checked_add(policy_interval_demand)?))?; Ok(()) })());
        if !matches!(self.fixed, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        self.native = Some(Box::new(NativeV1::new(horizon)));
        let native = self.native.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        native.trust_typed = Some(native.prepare_trust_once_v1(stage));
        if !matches!(native.trust_typed, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        native.bundle_typed = Some(native.verify_bundle_once_v1(stage, bundle));
        self.manifest_v1().map(|_| ())
    }

    pub(crate) fn prepare_storage_inputs_once_v1(&mut self, stage: &mut RootApplyStageReceivingV1<'_, '_>,
        subject: StorageApplySubjectDataV1<'_>) -> Result<(), JournalError>
    {
        let native = self.native.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        if native.storage_entry.is_some() { self.closed = true; return Err(JournalError::ProtectedBoundary); }
        native.storage_entry = Some(native.prepare_storage_inputs_once_v1(stage, subject));
        if matches!(native.storage_entry, Some(Ok(()))) { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn manifest_v1(&self) -> Result<&CanonicalAssignmentManifestV1, JournalError> {
        let native = self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if self.closed || !matches!(native.bundle_typed, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        native.manifest.as_ref().and_then(|value| value.value()).ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn lease_v1(&self) -> Result<&SignedOwnershipLease, JournalError> {
        self.manifest_v1()?;
        self.native.as_ref().and_then(|native| native.response.as_ref()).and_then(|response| response.value())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn verify_storage_once_v1(&mut self, flight: &RootPolicyAcceptedFlightV1<'_, '_>,
        readonly: &RootApplyReadonlyContextV1, subject: StorageApplySubjectDataV1<'_>,
        query: StorageApplyQueryDataV1, controller: PeerCredentials,
        controller_partition: (ResourceVector, ResourceVector, ResourceVector),
    ) -> Result<(), JournalError>
    {
        let native = self.native.as_mut().ok_or(JournalError::ProtectedBoundary)?;
        if native.storage_verified.is_some() { self.closed = true; return Err(JournalError::ProtectedBoundary); }
        native.storage_verified = Some((|| {
            flight.require_apply_storage_closed_v1(subject.root_closed)?;
            let sample = native.clock.check_next_once_v1()?;
            if readonly.controller_position_v1()? != (query.controller_next, query.controller_end) {
                return Err(JournalError::ProtectedBoundary.into());
            }
            let bundle = ReadyBundleDataV1::decode(subject.ready)?;
            let state = readonly.controller_state_v1()?;
            require_controller_original_v1(state, subject, query, bundle, controller_partition,
                *native.manifest.as_ref().and_then(|value| value.value()).ok_or(JournalError::ProtectedBoundary)?
                    .manifest().node().as_bytes())?;
            let assignment = native.manifest.as_ref().and_then(|value| value.value()).ok_or(JournalError::ProtectedBoundary)?;
            let specification = aos_sandbox_core::decode_sandbox_spec(bundle.specification, DecodeLimits::default())?;
            native.inventory = Some(verify_historical_inventory_v1(
                native.storage_files.bytes().ok_or(JournalError::ProtectedBoundary)?, bundle,
                assignment, specification.resource_profile(), sample, controller));
            let inventory = native.inventory.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
            let session = readonly.session_v1()?;

            let signed = record_v1(state, bundle.lane, 6, 5)?;
            let signed = ControllerSignedBodyDataV1::decode(signed.body(), bundle.lane, signed.body().len())?;
            let signed = signed.bundle_data_v1(bundle.lane, signed.bundle.len())?;
            let reserved = ControllerSessionReservedBodyDataV1::decode(record_v1(state, bundle.lane, 8, 7)?.body())?;
            let outcome = ControllerOutcomeBodyDataV1::decode(record_v1(state, bundle.lane, 9, 8)?.body())?;
            native.terminal = Some(inventory.verify_historical_prepare_terminal_v1(session,
                OutcomeBundleDataV1 { request: subject.prepare_request, outcome: subject.prepare_outcome },
                signed, reserved.request_id, query.original_cutoff_ns, bundle, sample, controller, outcome, reserved));
            let terminal = native.terminal.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
            terminal.require_live_at_v1(sample)?;
            Ok(())
        })());
        if matches!(native.storage_verified, Some(Ok(()))) { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn preparation_cutoff_v1(&self) -> Result<u64, JournalError> {
        let native = self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if self.closed || !matches!(native.storage_verified, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        Ok(native.terminal.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?
            .prepared_response_v1().preparation_expires_boottime_nanoseconds)
    }

    pub(crate) fn proposed_v1(&self) -> Result<&ProtectedStorageCreatePreparationV1, JournalError> {
        let native = self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if self.closed || !matches!(native.storage_verified, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary); }
        Ok(native.inventory.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?.protected_preparation_v1())
    }

    pub(crate) fn prepared_response_v1(&self)
        -> Result<&aos_proto::aos::sandbox::local::v1::PrepareStorageCatalogResponse, JournalError>
    {
        self.proposed_v1()?;
        Ok(self.native.as_ref().and_then(|native| native.terminal.as_ref()).and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?.prepared_response_v1())
    }

    pub(crate) fn storage_manifest_data_v1(&self)
        -> Result<&aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestV1, JournalError>
    {
        self.proposed_v1()?;
        Ok(self.native.as_ref().and_then(|native| native.inventory.as_ref()).and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?.storage_manifest_data_v1())
    }

    pub(crate) fn require_same_session_successor_data_v1(&self,
        stored: &aos_sandbox_protocol::authenticated_session::stored_history::StoredBrokerSessionHistoryV1,
        names: aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1,
    ) -> Result<(), JournalError> {
        self.proposed_v1()?;
        self.native.as_ref().and_then(|native| native.terminal.as_ref()).and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?.require_same_session_successor_data_v1(stored, names)
    }

    pub(crate) fn public_plan_inputs_v1(&self) -> Result<(&[u8], &[u8], &[u8]), JournalError> {
        self.proposed_v1()?;
        self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?.plan_files.bytes()
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn require_complete_at_v1(&self, sample: RawPairedClockSample) -> Result<(), JournalError> {
        self.proposed_v1()?;
        let native = self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        if !matches!(native.trust_post, Some(Ok(()))) || !matches!(native.storage_post, Some(Ok(())))
            || !matches!(native.plan_post, Some(Ok(()))) || self.failure().is_some()
        { return Err(JournalError::ProtectedBoundary); }
        native.clock.require_final_sample_v1(sample)
    }

    pub(crate) fn finish_posts_once_v1(&mut self) {
        if let Some(native) = &mut self.native { native.finish_posts_once_v1(); }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        boxed(&self.fixed).or_else(|| self.native.as_ref().and_then(|native| native.failure()))
            .or_else(|| self.closed.then_some(&CLOSED as _))
    }
}

fn require_controller_original_v1(state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    subject: StorageApplySubjectDataV1<'_>, query: StorageApplyQueryDataV1,
    bundle: ReadyBundleDataV1<'_>, partition: (ResourceVector, ResourceVector, ResourceVector), node: [u8; 16]) -> Result<(), Cause>
{
    let indexed = aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyBodyDataV1::
        decode(record_v1(state, bundle.lane, 3, 2)?.body())?;
    if indexed != aos_sandbox_protocol::domain_ledger::create_storage_history::ready::InputsReadyBodyDataV1::
        from_bundle(subject.ready)?
    { return Err(JournalError::ProtectedBoundary.into()); }
    let intent = record_v1(state, bundle.lane, 1, 1)?;
    if intent.body() != RecordEnvelopeV1::decode(bundle.intent_record,
        KeyV1::new(bundle.lane, OwnerV1::Controller, 1)?, PhaseV1::new(OwnerV1::Controller, 1)?)?.body()
    { return Err(JournalError::ProtectedBoundary.into()); }
    if record_v1(state, bundle.lane, 2, 12)?.body() !=
        RecordEnvelopeV1::decode(bundle.assignment_planned, KeyV1::new(bundle.lane, OwnerV1::Controller, 2)?,
            PhaseV1::new(OwnerV1::Controller, 12)?)?.body()
    { return Err(JournalError::ProtectedBoundary.into()); }
    let intent = ControllerIntentBodyDataV1::decode(intent.body())?;
    if intent.identity.boot != query.original_boot || intent.identity.started != query.original_boottime_ns
        || intent.identity.cutoff != query.original_cutoff_ns
    { return Err(JournalError::ProtectedBoundary.into()); }
    require_controller_bank_head_data_v2(state, subject.controller_account, partition, node)?;
    let root = ContinuationNativeReceiptDataV1::decode(subject.root_closed, bundle.lane, ContinuationKindV1::Closed)?;
    let root = RootClosedBodyDataV1::decode(root.record_data(bundle.lane, ContinuationKindV1::Closed)?.body())?;
    let handoff = record_v1(state, bundle.lane, 10, 9)?;
    let body = HandoffRetainedBodyDataV1::decode(handoff.body())?;
    if root.handoff_retained != handoff.checksum() || root.source_released != body.source_released
        || root.cache_released != body.cache_released || root.committed_use_claim != body.committed_use_claim
    { return Err(JournalError::ProtectedBoundary.into()); }
    Ok(())
}

fn record_v1(state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    lane: [u8; 16], revision: u64, phase: u8) -> Result<RecordEnvelopeV1<'_>, Cause>
{
    let key = KeyV1::new(lane, OwnerV1::Controller, revision)?;
    let raw = state.get(&(RecordNamespace::CreateStorageHistory, key.encode().to_vec()))
        .ok_or(JournalError::ProtectedBoundary)?;
    Ok(RecordEnvelopeV1::decode(raw, key, PhaseV1::new(OwnerV1::Controller, phase)?)?)
}
fn demand(value: ResourceVector) -> RootContinuationDemandV1 { RootContinuationDemandV1::from_demand_v1(value) }
fn boxed<T>(value: &Option<Result<T, Cause>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause.as_ref())
}
const CLOSED: JournalError = JournalError::ProtectedBoundary;

// Both concrete purposes select actual current C and their same enrolled Root
// partition before this comparison. The bytes do not choose an account/payer.
pub(crate) fn require_controller_bank_head_data_v2(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    account_bytes: &[u8],
    partition: (ResourceVector, ResourceVector, ResourceVector),
    node: [u8; 16],
) -> Result<(), Cause> {
    let account = AccountHead::decode(account_bytes)?;
    let enrollment = account.native_fields().enrollment;
    if aos_sandbox_protocol::domain_ledger::resource_bank::validate(state)? != Some(enrollment) {
        return Err(JournalError::ProtectedBoundary.into());
    }
    let row = aos_sandbox_protocol::domain_ledger::resource_bank::recipient_incarnation(state, enrollment)?
        .ok_or(JournalError::ProtectedBoundary)?;
    if row.generation() != 0 || account.recorded_baseline() != partition.0
        || row.normal_precharge_v1() != partition.1 || row.recovery_reserve_v1() != partition.2
        || row.charged_baseline_v1()? != partition.1
    { return Err(JournalError::ProtectedBoundary.into()); }
    if account.native_fields().kind != AccountKind::Controller
        || account.native_fields().enrollment.native_fields().node != node
        || !state.iter().any(|((namespace, key), bytes)| is_head_entry(*namespace, key) && bytes.as_slice() == account_bytes)
    { return Err(JournalError::ProtectedBoundary.into()); }
    Ok(())
}
