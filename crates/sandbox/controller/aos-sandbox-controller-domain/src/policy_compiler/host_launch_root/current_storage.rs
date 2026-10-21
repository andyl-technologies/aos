//! Joins signed method31 and fresh18 to the same completed creation workspace.
//!
//! The actual resource server joins this supplier into its paid typed-request
//! stage before construction. It lends the existing completed historical owner
//! and actual same-native Session readback; this module decodes no second full
//! history and opens no journal. Outer native and policy posts remain mandatory.

use aos_sandbox_protocol::domain_ledger::readonly::FixedJournalReadbackDataV1 as RootFixedNativeReadbackV1;

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker_session_protocol::BrokerSessionDurablePhaseV1;
use aos_sandbox_broker_session_protocol::hello_message::BrokerMethod;
use aos_sandbox_model::{
    BrokerPlanExpectation, DecodeLimits,
    RawPairedClockSample, ResourceDimension as D, ResourceVector, VerifiedBrokerPlan,
};
use aos_sandbox_ownership_protocol::SignedOwnershipLease;
use aos_sandbox_protocol::ProtocolValidationError;
use aos_sandbox_protocol::authenticated_session::{
    all_methods::{request_capture::AuthenticatedBrokerMethodRequestCaptureV1 as RequestCapture,
        outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1 as OutcomeCapture},
    historical_method::HistoricalStorageGuestRootMethodCaptureV2 as MethodCapture,
};
use aos_sandbox_protocol::authorization_artifact::start_resource_plan::{
    StartResourcePlanPreparationDataV1,
    compare_historical_start_storage_guest_root_plan_v2,
    start_storage_guest_root_normalization_receiving_demand_v2,
};
use aos_sandbox_protocol::semantics::storage_guest_root::{
    CanonicalStorageGuestRootArgumentsV1 as Arguments,
    StorageGuestRootCurrentPublicationDataV2 as Current,
    StorageGuestRootResponseDataV2,
};
use aos_sandbox_protocol::storage_inventory::ValidatedStorageInventory;

use crate::journal::JournalError;
use aos_sandbox_policy::root_trust_data::RootBrokerPlanPublicTrustDataV1;
use crate::policy_compiler::provisioning_current::StartAssignmentCompilationDataV2;
use super::history::RootHostHistoricalCreateOriginalV2;

type Cause = Box<dyn Error>;

pub(in crate::policy_compiler) struct RootCurrentStoragePublicationOriginalV2 {
    publication: MethodCapture,
    inventory: MethodCapture,
    arguments: Option<Result<Arguments, ProtocolValidationError>>,
    response: Option<Result<StorageGuestRootResponseDataV2, ProtocolValidationError>>,
    signature: Option<Result<aos_sandbox_model::model::Signature,
        aos_sandbox_model::format::CanonicalCborError>>,
    normalization: Option<Result<StartResourcePlanPreparationDataV1, Cause>>,
    plan: Option<Result<VerifiedBrokerPlan, aos_sandbox_model::BrokerPlanVerificationError>>,
    result: Option<Result<(), Cause>>,
    reentered: bool,
}

impl RootCurrentStoragePublicationOriginalV2 {
    pub(in crate::policy_compiler) fn new() -> Self {
        Self {
            publication: MethodCapture::new(),
            inventory: MethodCapture::new(),
            arguments: None,
            response: None,
            signature: None,
            normalization: None,
            plan: None,
            result: None,
            reentered: false,
        }
    }

    // Native Session/schema names belong to the already admitted reader. This
    // supplier covers only these additional retained method/model/crypto planes.
    pub(in crate::policy_compiler) fn receiving_demand_v2(
        prefix: usize,
        lease: &SignedOwnershipLease,
        public: &RootBrokerPlanPublicTrustDataV1,
    ) -> Result<ResourceVector, JournalError> {
        let request = RequestCapture::dynamic_receiving_demand_v1(prefix)
            .ok_or(JournalError::JournalTooLarge)?;
        let outcome = OutcomeCapture::controller_inventory_dynamic_receiving_demand_v1(
            BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES, prefix,
        ).ok_or(JournalError::JournalTooLarge)?;
        let limits = DecodeLimits::default();
        let normalization = start_storage_guest_root_normalization_receiving_demand_v2(
            prefix.min(aos_sandbox_protocol::MAXIMUM_REQUEST_BYTES),
            prefix.min(limits.maximum_bytes), prefix.min(limits.maximum_bytes),
            lease, &public.authority,
        ).ok_or(JournalError::JournalTooLarge)?;
        let fixed = size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(Arguments::deadline_free_request_receiving_bytes_v2()?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let model = request.checked_add(outcome)?;
        let workspace = crate::cold_launch_publication::completion::
            create_workspace_comparison_receiving_demand_v1()
            .ok_or(JournalError::JournalTooLarge)?;
        model.checked_add(model)?.checked_add(normalization)?.checked_add(workspace)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed))
            .map_err(JournalError::ReceivingAccounting)
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::policy_compiler) fn observe_once_v2(
        &mut self,
        native: RootFixedNativeReadbackV1<'_>,
        historical: &RootHostHistoricalCreateOriginalV2,
        compiled: &StartAssignmentCompilationDataV2,
        lease: &SignedOwnershipLease,
        public: &RootBrokerPlanPublicTrustDataV1,
        sample: RawPairedClockSample,
        cutoff: u64,
        policy_expires: i64,
    ) -> Result<(), JournalError> {
        if self.result.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some(self.observe_inner_v2(
            native, historical, compiled, lease, public, sample, cutoff, policy_expires,
        ));
        self.require_complete_v2()
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_inner_v2(
        &mut self,
        native: RootFixedNativeReadbackV1<'_>,
        historical: &RootHostHistoricalCreateOriginalV2,
        compiled: &StartAssignmentCompilationDataV2,
        lease: &SignedOwnershipLease,
        public: &RootBrokerPlanPublicTrustDataV1,
        sample: RawPairedClockSample,
        cutoff: u64,
        policy_expires: i64,
    ) -> Result<(), Cause> {
        let manifest = compiled.manifest_v2();
        let parent = compiled.source_v2().operation_v2();
        let verified = historical.current_storage_history_v2(&native)?;
        let records = verified.history.records();
        let mut publications = records.iter().enumerate().filter(|(_, record)|
            record.phase() == BrokerSessionDurablePhaseV1::Terminal
                && record.method() == BrokerMethod::BROKER_METHOD_STORAGE_POPULATE_GUEST_ROOT
                && record.request_id() == parent.into_bytes());
        let (index, _) = publications.next().ok_or(JournalError::ProtectedBoundary)?;
        if publications.next().is_some() || index == 0
            || index.checked_add(2).is_none_or(|after| after >= records.len())
            || records[index + 1..].iter().any(|record|
                record.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES)
            || records.last().is_none_or(|record|
                record.phase() != BrokerSessionDurablePhaseV1::Terminal)
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.publication.observe_once_v2(records, index, verified.checkpoint, verified.transcript)?;
        self.inventory.observe_once_v2(records, records.len() - 1,
            verified.checkpoint, verified.transcript)?;
        let request = self.publication.request_v2().ok_or(JournalError::ProtectedBoundary)?;
        let inventory_request = self.inventory.request_v2().ok_or(JournalError::ProtectedBoundary)?;
        let original_cutoff = compiled.source_v2().native_origin_data_v2().cutoff_v1();
        if sample.boottime_nanoseconds() >= cutoff
            || cutoff > original_cutoff
            || inventory_request.deadline_boottime_nanoseconds() > original_cutoff
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let inventory = &self.inventory.inventory_v2().ok_or(JournalError::ProtectedBoundary)?.0;
        let (handle, creation_operation) = historical.creation_workspace_selectors_v2()?;
        self.arguments = Some(Arguments::from_protected_assignment(
            manifest.broker_assignment()?, parent.into_bytes(), handle, creation_operation,
        ));
        let arguments = self.arguments.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.response = Some(Ok(*self.publication.storage_guest_root_response_v2()
            .ok_or(JournalError::ProtectedBoundary)?));
        let response = self.response.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        require_current_storage_publication_data_v2(historical, manifest, arguments,
            response, inventory, lease, &parent.into_bytes())?;
        let authorization = request.authorization().ok_or(JournalError::ProtectedBoundary)?;
        if authorization.ownership_lease() != lease.canonical_lease()
            || authorization.ownership_lease_signature() != lease.canonical_signature()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.signature = Some(aos_sandbox_model::format::decode_signature(
            authorization.broker_plan_signature(), DecodeLimits::default(),
        ));
        let signature = self.signature.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let statement = aos_sandbox_model::format::encode_signature_statement(signature.statement());
        let body = arguments.deadline_free_request_body_v2(parent.into_bytes())?;
        // The earlier signed31 deadline remains historical comparison data.
        // This later Root flight cannot renew or substitute that deadline.
        let original_deadline = request.deadline_boottime_nanoseconds();
        if original_deadline > original_cutoff {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.normalization = Some(compare_historical_start_storage_guest_root_plan_v2(
            &body, arguments, manifest, manifest.manifest().policy().digest(), lease,
            original_deadline, policy_expires, public.authority.clone(), public.revocation_scope,
            authorization.broker_plan(), &statement,
        ).map_err(|cause| cause as Cause));
        let normalized = self.normalization.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if request.exact_body() != normalized.request_body.as_slice()
            || signature.statement() != normalized.preparation.signing_request().statement()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let expected = normalized.preparation.plan_data_v1();
        self.plan = Some(aos_sandbox_model::verify_broker_plan(
            normalized.preparation.canonical_plan(), signature, &public.anchor,
            BrokerPlanExpectation {
                audience: expected.audience(), protocol: expected.protocol(),
                protocol_version: expected.protocol_version(), assignment: expected.assignment(),
                node: expected.node(),
                // Cryptographic historical validation only; this owner never
                // lends the verified old plan as a current-use permission.
                now_seconds: expected.issued_seconds(),
            }, DecodeLimits::default(),
        ));
        if !matches!(self.plan, Some(Ok(_))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    pub(in crate::policy_compiler) fn require_complete_v2(&self) -> Result<(), JournalError> {
        if !self.reentered && matches!(self.result, Some(Ok(()))) && self.failure().is_none() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(in crate::policy_compiler) fn current_publication_v2(&self) -> Result<&Current, JournalError> {
        self.require_complete_v2()?;
        self.response.as_ref().and_then(|value| value.as_ref().ok())
            .map(StorageGuestRootResponseDataV2::current_publication_v2)
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(in crate::policy_compiler) fn inventory_v2(&self) -> Result<&ValidatedStorageInventory, JournalError> {
        self.require_complete_v2()?;
        self.inventory.inventory_v2().map(|inventory| &inventory.0)
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(in crate::policy_compiler) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.publication.failure_v2().or_else(|| self.inventory.failure_v2())
            .or_else(|| error(&self.arguments)).or_else(|| error(&self.response))
            .or_else(|| error(&self.signature))
            .or_else(|| self.normalization.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| error(&self.plan))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}

// Both actual Root consumers already hold authenticated native Session models.
// This pure relation does not manufacture their provenance or current scope.
pub(super) fn require_current_storage_publication_data_v2(
    historical: &RootHostHistoricalCreateOriginalV2,
    manifest: &aos_sandbox_model::CanonicalAssignmentManifestV1,
    arguments: &Arguments,
    response: &StorageGuestRootResponseDataV2,
    inventory: &ValidatedStorageInventory,
    lease: &SignedOwnershipLease,
    request_id: &[u8; 16],
) -> Result<(), Cause> {
    historical.require_current_workspace_inventory_v2(inventory)?;
    let workspace = selected_current_storage_workspace_data_v2(manifest, inventory)?;
    require_current_storage_workspace_publication_data_v2(
        workspace, manifest, arguments, response, lease, request_id)
}

// Selection and the current304 relation are shared DATA recipes. Start keeps
// its historical Create conjunction above; Maintenance separately authenticates
// its actual current reservation/assignment and signed native Inventory cut.
pub(in crate::policy_compiler) fn selected_current_storage_workspace_data_v2<'inventory>(
    manifest: &aos_sandbox_model::CanonicalAssignmentManifestV1,
    inventory: &'inventory ValidatedStorageInventory,
) -> Result<&'inventory aos_sandbox_protocol::storage_inventory::ValidatedStorageWorkspace, Cause> {
    let mut workspaces = inventory.workspaces().iter().filter(|workspace|
        workspace.fence().sandbox_id() == manifest.manifest().sandbox().as_bytes());
    let workspace = workspaces.next().ok_or(JournalError::ProtectedBoundary)?;
    if workspaces.next().is_some() {
        return Err(JournalError::ProtectedBoundary.into());
    }
    Ok(workspace)
}

pub(in crate::policy_compiler) fn require_current_storage_workspace_publication_data_v2(
    workspace: &aos_sandbox_protocol::storage_inventory::ValidatedStorageWorkspace,
    manifest: &aos_sandbox_model::CanonicalAssignmentManifestV1,
    arguments: &Arguments,
    response: &StorageGuestRootResponseDataV2,
    lease: &SignedOwnershipLease,
    request_id: &[u8; 16],
) -> Result<(), Cause> {
    let current = workspace.current_guest_root_publication_v2()
        .ok_or(JournalError::ProtectedBoundary)?;
    current.require_workspace_v2(workspace)?;
    current.require_request_data_v2(response.proof_v1(), arguments, request_id)?;
    if current != response.current_publication_v2()
        || current.current_assignment_v2()? != manifest.broker_assignment()?
        || current.ownership_lease_digest_v2() != lease.digest().as_bytes()
    {
        return Err(JournalError::ProtectedBoundary.into());
    }
    Ok(())
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

const CLOSED: JournalError = JournalError::ProtectedBoundary;
