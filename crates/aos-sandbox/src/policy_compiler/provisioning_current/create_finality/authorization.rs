//! Recomputes the new Recover admission against Root's own complete C read.
//!
//! Stored observation bytes select comparison inputs only. The actual Root
//! stage pays this owner before model construction, retains its independent
//! native C interval, and obtains node/image DATA from its genuine enrollment.
//! No decoded row constructs a current decision, peer, receiver or CAS lender.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_core::{
    CapabilityId, ChannelBinding, OperationId, PrincipalId, ProjectId, ResourceDimension as D,
    ResourceVector,
};
use aos_sandbox_protocol::domain_ledger::{
    provisioning_root::finality_recover::{
        CreateFinalityObservationAdmissionDataV1 as Admission, FinalityRecoverQueryDataV1,
        finality_admission_commitment_v1,
    },
    resource_bank,
};

use crate::controller_resource_reservation::OperatorCreateRecoveryRequestDataV1;
use crate::journal::{Journal, JournalError, RecordNamespace};
use aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::public_operation::{
    metadata_complete_admission_receiving_bytes_v1, metadata_complete_admission_transaction_v1,
    require_metadata_complete_admission_rows_v1,
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

type Cause = Box<dyn Error>;

/// Selects an immutable new Recover admission, without carrying its permission.
#[derive(Clone, Copy)]
pub(crate) struct RootRecoveryAdmissionReferenceDataV2 {
    pub(crate) key: [u8; aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::OBSERVATION_ADMISSION_KEY_BYTES_V1],
    pub(crate) commitment: [u8; 32],
    pub(crate) original: aos_sandbox_core::RawPairedClockSample,
    pub(crate) cutoff: u64,
    pub(crate) wall_expiry: i64,
}

impl From<FinalityRecoverQueryDataV1> for RootRecoveryAdmissionReferenceDataV2 {
    fn from(query: FinalityRecoverQueryDataV1) -> Self {
        Self {
            key: query.admission_key,
            commitment: query.admission,
            original: query.original,
            cutoff: query.cutoff,
            wall_expiry: query.wall_expiry,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Purpose {
    CreateFinality,
    StopCleanup,
    ExecutionNoApply,
}

/// Retains only parsed current authorization and historical-target comparisons.
pub(crate) struct CreateFinalityAuthorizationOriginalV1 {
    purpose: Purpose,
    request: Option<Result<OperatorCreateRecoveryRequestDataV1, Cause>>,
    authorization: Option<Result<(), Cause>>,
    admission: Option<Result<JournalTransaction, Cause>>,
    result: Option<Result<OperationId, Cause>>,
    reentered: bool,
}

impl CreateFinalityAuthorizationOriginalV1 {
    pub(crate) fn new() -> Self {
        Self::new_for_purpose_v2(Purpose::CreateFinality)
    }

    pub(crate) fn new_execution_no_apply_v2() -> Self {
        Self::new_for_purpose_v2(Purpose::ExecutionNoApply)
    }

    pub(crate) fn new_stop_cleanup_v2() -> Self {
        Self::new_for_purpose_v2(Purpose::StopCleanup)
    }

    fn new_for_purpose_v2(purpose: Purpose) -> Self {
        Self {
            purpose,
            request: None,
            authorization: None,
            admission: None,
            result: None,
            reentered: false,
        }
    }

    /// Measures actual authority/request graphs before any decoder is entered.
    pub(crate) fn receiving_demand_v1(
        controller: &Journal,
        query: FinalityRecoverQueryDataV1,
    ) -> Result<ResourceVector, Cause> {
        Self::receiving_recovery_demand_v2(controller, query.into())
    }

    pub(crate) fn receiving_recovery_demand_v2(
        controller: &Journal,
        reference: RootRecoveryAdmissionReferenceDataV2,
    ) -> Result<ResourceVector, Cause> {
        let admission = admission_v1(controller, reference)?;
        let models = OperatorCreateRecoveryRequestDataV1::receiving_bytes_v1(
            controller,
            admission.canonical_request,
        )?;
        // The actual idempotency bytes are inside this encoded request. Its
        // complete encoded width bounds that one field before semantic decode.
        let candidate = metadata_complete_admission_receiving_bytes_v1(
            admission.encoded_bytes_v1()?,
            admission.canonical_request.len(),
        )
        .ok_or(JournalError::JournalTooLarge)?;
        let models = models
            .checked_add(candidate)
            .ok_or(JournalError::JournalTooLarge)?;
        let models = u64::try_from(models).map_err(|_| JournalError::JournalTooLarge)?;
        let carrier = size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let entries = crate::publisher_admin::authorization_namespace_entries_v1(controller)
            .and_then(|entries| u64::try_from(entries).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        Ok(ResourceVector::ZERO
            .with(
                D::MemoryBytes,
                models
                    .checked_add(carrier)
                    .ok_or(JournalError::JournalTooLarge)?,
            )
            .with(D::MetadataEntries, entries))
    }

    /// Compares the exact immutable observation and actual current scope.
    pub(crate) fn observe_once_v1(
        &mut self,
        controller: &Journal,
        query: FinalityRecoverQueryDataV1,
        node: [u8; 16],
        partition: (ResourceVector, ResourceVector, ResourceVector),
    ) -> Result<(), JournalError> {
        if self.purpose != Purpose::CreateFinality {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.observe_recovery_once_v2(controller, query.into(), node, partition)
    }

    /// Recomputes actual kind3 capability and all four protected admission rows.
    pub(crate) fn observe_execution_no_apply_once_v2(
        &mut self,
        controller: &Journal,
        reference: RootRecoveryAdmissionReferenceDataV2,
        node: [u8; 16],
        partition: (ResourceVector, ResourceVector, ResourceVector),
    ) -> Result<(), JournalError> {
        if self.purpose != Purpose::ExecutionNoApply {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.observe_recovery_once_v2(controller, reference, node, partition)
    }

    /// Rechecks a distinct Stop cleanup on the same actual current-cap engine.
    pub(crate) fn observe_stop_cleanup_once_v2(
        &mut self,
        controller: &Journal,
        reference: RootRecoveryAdmissionReferenceDataV2,
        node: [u8; 16],
        partition: (ResourceVector, ResourceVector, ResourceVector),
    ) -> Result<(), JournalError> {
        if self.purpose != Purpose::StopCleanup {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.observe_recovery_once_v2(controller, reference, node, partition)
    }

    fn observe_recovery_once_v2(
        &mut self,
        controller: &Journal,
        reference: RootRecoveryAdmissionReferenceDataV2,
        node: [u8; 16],
        partition: (ResourceVector, ResourceVector, ResourceVector),
    ) -> Result<(), JournalError> {
        if self.result.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some(self.observe_inner_v1(controller, reference, node, partition));
        self.target_v1().map(|_| ())
    }

    fn observe_inner_v1(
        &mut self,
        controller: &Journal,
        reference: RootRecoveryAdmissionReferenceDataV2,
        node: [u8; 16],
        (baseline, normal, recovery): (ResourceVector, ResourceVector, ResourceVector),
    ) -> Result<OperationId, Cause> {
        let admission = admission_v1(controller, reference)?;
        let state = controller.historical_read_view_v1().materialized_state_v1();
        let enrollment = resource_bank::validate(state)?.ok_or(JournalError::ProtectedBoundary)?;
        let recipient = resource_bank::recipient_incarnation(state, enrollment)?
            .ok_or(JournalError::ProtectedBoundary)?;
        let identity = enrollment.native_fields();
        if admission.node != node
            || identity.node != node
            || identity.boot != admission.original.host_boot_id()
            || recipient.generation() == 0
            || (recipient.generation() > 1 && recipient.prepaid_range_v2().is_none())
            || recipient.normal_precharge_v1() != normal
            || recipient.recovery_reserve_v1() != recovery
            || normal.checked_add(recovery)? != baseline
            || recipient.charged_baseline_v1()? != baseline
        {
            return Err(JournalError::ProtectedBoundary.into());
        }

        self.request = Some(
            match self.purpose {
                Purpose::CreateFinality => {
                    OperatorCreateRecoveryRequestDataV1::decode_for_project_v1(
                        controller,
                        ProjectId::from_bytes(admission.project),
                        admission.canonical_request,
                    )
                }
                Purpose::ExecutionNoApply => {
                    OperatorCreateRecoveryRequestDataV1::decode_execution_no_apply_for_project_v1(
                        controller,
                        ProjectId::from_bytes(admission.project),
                        aos_sandbox_core::NodeId::from_bytes(node),
                        admission.canonical_request,
                    )
                }
                Purpose::StopCleanup => {
                    OperatorCreateRecoveryRequestDataV1::decode_stop_cleanup_for_project_v1(
                        controller,
                        ProjectId::from_bytes(admission.project),
                        aos_sandbox_core::NodeId::from_bytes(node),
                        admission.canonical_request,
                    )
                }
            }
            .map_err(|cause| Box::new(cause) as Cause),
        );
        let request = self
            .request
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let (canonical, request, target) = request.observation_input_v1();
        if target.as_bytes() != &admission.target
            || canonical != admission.canonical_request
            || Admission::idempotency_digest_v1(admission.holder, request.idempotency_key())
                != admission.idempotency_digest
        {
            return Err(JournalError::ProtectedBoundary.into());
        }

        self.authorization = Some((|| {
            let (revision, expires) = crate::cli_model::authorization_adapter::
                compare_create_recovery_authorization_from_records_v1(
                    crate::publisher_admin::PublisherReadDataV2::from_journal_v2(controller),
                    request, ProjectId::from_bytes(admission.project),
                    PrincipalId::from_bytes(admission.holder),
                    CapabilityId::from_bytes(admission.capability),
                    ChannelBinding::new(admission.channel), admission.original,
                )?;
            if revision.digest().as_bytes() != &admission.authorization_revision
                || expires != admission.wall_expiry
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
            Ok(())
        })());
        if !matches!(self.authorization, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.admission = Some(
            match self.purpose {
                Purpose::CreateFinality => metadata_complete_admission_transaction_v1(admission, request.idempotency_key()),
                Purpose::ExecutionNoApply => aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::public_operation::execution_no_apply_admission_transaction_v1(admission, request.idempotency_key()),
                Purpose::StopCleanup => aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::public_operation::stop_cleanup_admission_transaction_v1(admission, request.idempotency_key()),
            }
                .map_err(|cause| Box::new(cause) as Cause),
        );
        let candidate = self
            .admission
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        require_metadata_complete_admission_rows_v1(candidate, state)?;
        Ok(target)
    }

    pub(crate) fn target_v1(&self) -> Result<OperationId, JournalError> {
        if self.reentered || self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Lends only this original's independently rechecked finite parsed scope.
    pub(crate) fn execution_no_apply_request_v2(
        &self,
    ) -> Result<&OperatorCreateRecoveryRequestDataV1, JournalError> {
        self.target_v1()?;
        if self.purpose != Purpose::ExecutionNoApply {
            return Err(JournalError::ProtectedBoundary);
        }
        self.request
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Lends the positively rechecked finite Stop cleanup scope.
    pub(crate) fn stop_cleanup_request_v2(
        &self,
    ) -> Result<&OperatorCreateRecoveryRequestDataV1, JournalError> {
        self.target_v1()?;
        if self.purpose != Purpose::StopCleanup {
            return Err(JournalError::ProtectedBoundary);
        }
        self.request
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.request
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| &**cause)
            .or_else(|| {
                self.authorization
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| &**cause)
            })
            .or_else(|| {
                self.admission
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| &**cause)
            })
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| &**cause))
    }
}

// Both native payment geometry and the entered model owner borrow this one
// canonical framing check. Native integrity/currentness remains the caller's.
fn admission_v1(
    controller: &Journal,
    reference: RootRecoveryAdmissionReferenceDataV2,
) -> Result<Admission<'_>, JournalError> {
    let raw = controller
        .get(RecordNamespace::OperatorRecovery, &reference.key)
        .ok_or(JournalError::ProtectedBoundary)?;
    let admission = Admission::decode_v1(raw).map_err(|_| JournalError::ProtectedBoundary)?;
    if admission.key_v1() != reference.key
        || finality_admission_commitment_v1(raw) != reference.commitment
        || admission.original != reference.original
        || admission.cutoff != reference.cutoff
        || admission.wall_expiry != reference.wall_expiry
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(admission)
}
