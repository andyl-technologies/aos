//! Checks historical Storage input under Root's independently installed manifest.
//!
//! This private native owner retains the actual independent fixed credentials,
//! Session reader and both native post results beside its protected-built
//! Inventory and plan. Only the containing finite Root context drives capture;
//! public DATA cannot construct or substitute a completed native owner.

use crate::CompiledPolicyCandidateV1;
use crate::native::readonly::error::RootReadonlyErrorV1 as JournalError;
use aos_sandbox_broker::systemd_credentials::{
    RootCurrentStorageManifestCustodyV1, RootCurrentBrokerPlanCredentialCustodyV1,
};
use crate::root_use_plan_data::RootProspectiveStorageUsePlanV1;
use crate::native::readonly::RootFixedNativeReadOriginalsV1 as RootStorageSessionExtentV1;
use crate::native::readonly::RootFixedNativeReadbackV1;
mod resource_kind;
use resource_kind::ResourceKindV2 as RootStorageResourceKindV2;

aos_sandbox_protocol::define_root_storage_session_data_v1!(pub(crate));

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
        let carrier = aos_sandbox_model::format::TrustPolicyDecodeCaptureV1::
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
        -> Result<&crate::native::readonly::preopen_geometry::ProtectedJournalPreopenReplayExtentV1, JournalError>
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

