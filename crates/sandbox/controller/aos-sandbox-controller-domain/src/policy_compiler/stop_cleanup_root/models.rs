//! Joins Root's current Recover, protected target, Source dispatch and Host cut.
//!
//! The caller retains its actual nine native readers and financial interval.
//! The model stage pays before any graph grows. Completed values remain
//! comparison DATA until the enclosing native issuer also completes every
//! independent currentness, credential, peer and clock obligation.

use sha2::Digest as _;
use std::{error::Error, mem::size_of};

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector, SandboxId};
use aos_sandbox_ownership_protocol::response_verification::OwnershipResponseVerifyCaptureV1;
use aos_sandbox_protocol::{
    LiveHostRuntimeEnvelopeDataV2,
    domain_ledger::provisioning_root::finality_recover::{
        CreateFinalityObservationAdmissionDataV1 as Admission,
        public_operation::public_controller_request_digest_v1,
    },
};

use crate::{
    journal::JournalError,
    lifecycle::{LifecycleHistoricalReadOriginalV1, retained_lifecycle_replay_receiving_demand_v1},
    policy_compiler::{
        continuation_policy::RootStopCleanupPolicyOriginalV1,
        execution_no_apply_root::HostHistoryOriginalV2,
        provisioning_current::{
            create_finality::authorization::CreateFinalityAuthorizationOriginalV1 as Authorization,
            current_cleanup_assignment::{
                CurrentCleanupAssignmentDataV2, current_cleanup_assignment_receiving_demand_v2,
                current_cleanup_assignment_rows_data_v2,
            },
            finality_readonly::RootCreateFinalityReadonlyOriginalV1,
        },
    },
};

use super::{SelectionData, inventory, trust::Trust};

type Cause = Box<dyn Error>;

pub(super) struct Models {
    authorization: Authorization,
    source: LifecycleHistoricalReadOriginalV1,
    host: HostHistoryOriginalV2,
    assignment: Option<Result<CurrentCleanupAssignmentDataV2, Cause>>,
    old_stop: Option<
        Result<LiveHostRuntimeEnvelopeDataV2, aos_sandbox_protocol::ProtocolValidationError>,
    >,
    lease: OwnershipResponseVerifyCaptureV1,
    lease_result:
        Option<Result<(), aos_sandbox_ownership_protocol::OwnershipLeaseAcquisitionError>>,
    selected: Option<Result<(inventory::Selection, [u8; 16]), JournalError>>,
    body: Option<Result<(), Cause>>,
    repeated: Option<JournalError>,
    recovery: Option<inventory::RecoveryData>,
    project: Option<aos_sandbox_model::ProjectId>,
}

impl Models {
    pub(super) fn new() -> Self {
        Self {
            authorization: Authorization::new_stop_cleanup_v2(),
            source: LifecycleHistoricalReadOriginalV1::new(),
            host: HostHistoryOriginalV2::new(),
            assignment: None,
            old_stop: None,
            lease: OwnershipResponseVerifyCaptureV1::new(),
            lease_result: None,
            selected: None,
            body: None,
            repeated: None,
            recovery: None,
            project: None,
        }
    }

    pub(super) fn receiving_demand(
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
        trust: &Trust,
        _policy: &RootStopCleanupPolicyOriginalV1,
        selection: SelectionData,
    ) -> Result<ResourceVector, Cause> {
        let (controller, source) = readonly.journals_v1()?;
        let auth = Authorization::receiving_recovery_demand_v2(controller, selection.admission)?;
        let source_models = retained_lifecycle_replay_receiving_demand_v1(source.all_records())
            .ok_or(JournalError::JournalTooLarge)?;
        let source_bytes = source.all_records().try_fold(0_usize, |sum, (_, key, value)| {
            sum.checked_add(key.len())?.checked_add(value.len())
        }).ok_or(JournalError::JournalTooLarge)?;
        // Rebuilding the selected canonical Stop envelope is another actual
        // decode beside full Source and Host history. The method-owned request
        // supplier bounds that separate format plane from this same captured
        // A7 extent, before its generated protobuf or template can grow.
        let old_stop = aos_sandbox_protocol::authenticated_session::all_methods::request_capture::
            AuthenticatedBrokerMethodRequestCaptureV1::dynamic_receiving_demand_v1(source_bytes)
                .ok_or(JournalError::JournalTooLarge)?;
        let controller_bytes = controller
            .all_records()
            .try_fold(0_usize, |sum, (_, key, value)| {
                sum.checked_add(key.len())?.checked_add(value.len())
            })
            .ok_or(JournalError::JournalTooLarge)?;
        let state = controller.historical_read_view_v1().materialized_state_v1();
        let current = current_cleanup_assignment_receiving_demand_v2(state)
            .ok_or(JournalError::JournalTooLarge)?;
        let lease = trust
            .ownership()?
            .response_receiving_dynamic_bytes_v2(controller_bytes)
            .ok_or(JournalError::JournalTooLarge)?;
        let fixed = size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(3 * size_of::<CurrentCleanupAssignmentDataV2>()))
            .and_then(|bytes| bytes.checked_add(lease))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        let mut demand = auth
            .checked_add(current)?
            .checked_add(source_models)?
            // The two selected A7 auxiliary payload planes coexist with the
            // full Source projection. Their total actual bytes are bounded by
            // the same Source prefix; one further full canonical model quote
            // dominates that distinct pair without replacing the projection.
            .checked_add(source_models)?
            .checked_add(old_stop)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, fixed))?;
        let native = readonly.session_v1()?;
        let prefix = usize::try_from(native.end)?;
        demand = demand.checked_add(HostHistoryOriginalV2::receiving_demand(
            prefix,
            native.state.len(),
        )?)?;
        Ok(demand)
    }

    pub(super) fn observe_once(
        &mut self,
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
        trust: &Trust,
        selection: SelectionData,
        sample: RawPairedClockSample,
        node: [u8; 16],
        controller_identity: (u32, u32),
        partition: (ResourceVector, ResourceVector, ResourceVector),
    ) -> Result<(), JournalError> {
        if self.body.is_some() {
            self.repeated.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.body = Some(self.observe_inner(
            readonly,
            trust,
            selection,
            sample,
            node,
            controller_identity,
            partition,
        ));
        self.require_complete()
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_inner(
        &mut self,
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
        trust: &Trust,
        selection: SelectionData,
        sample: RawPairedClockSample,
        node: [u8; 16],
        controller_identity: (u32, u32),
        partition: (ResourceVector, ResourceVector, ResourceVector),
    ) -> Result<(), Cause> {
        self.authorization.observe_stop_cleanup_once_v2(
            readonly.controller_v1()?,
            selection.admission,
            node,
            partition,
        )?;
        self.host.observe_once(
            &readonly.session_v1()?,
            trust.manifest()?,
            controller_identity,
        )?;

        let (controller, source) = readonly.journals_v1()?;
        let request = self.authorization.stop_cleanup_request_v2()?;
        let target = request
            .stop_cleanup_target_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.source.observe_once_v1(source, target.operation_v1())?;
        self.source.select_stop_dispatch_once_v1()?;
        let parent = target.source_parent_data_v1(controller, &self.source)?;
        let dispatch = self.source.stop_dispatch_data_v1()?;
        if parent.digest().as_bytes() != &selection.source_parent
            || dispatch.operation() != target.operation_v1()
        {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        self.host.observe_stop_dispatch_once_v1(dispatch)?;
        self.old_stop = Some(
            aos_sandbox_protocol::decode_canonical_live_host_stop_envelope_data_v4(
                self.host.stop_dispatch_request_v1()?.exact_body(),
            ),
        );
        let old_stop = positive(&self.old_stop)?;
        let old_fence = old_stop.template_v1().fence();
        let bound = target.binding_v1().manifest();
        let current = bound.manifest();
        if old_fence.sandbox_id() != current.sandbox().as_bytes()
            || old_fence.incarnation_id() != current.incarnation().as_bytes()
            || old_fence.assignment_epoch() != current.epoch().get()
            || old_fence.assignment_digest() != bound.digest().as_bytes()
            || old_fence.desired_generation() != target.desired_generation_v1()
        {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }

        self.assignment = Some(
            current_cleanup_assignment_rows_data_v2(
                controller.historical_read_view_v1().rows_data_v2(),
                SandboxId::from_bytes(*old_fence.sandbox_id()),
            )
            .map_err(|cause| cause as Cause),
        );
        let assignment = positive(&self.assignment)?;
        if assignment.binding.manifest().canonical_bytes() != bound.canonical_bytes() {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        let lease = &assignment.recovered_lease;
        self.lease_result = Some(trust.ownership()?.verify_response_bytes_retaining_v1(
            assignment.gate.claim(),
            lease.canonical_lease(),
            lease.canonical_signature(),
            lease.canonical_receipt(),
            lease.canonical_receipt_signature(),
            &sample,
            &mut self.lease,
        ));
        positive(&self.lease_result)?;
        let verified = self.lease.value().ok_or(JournalError::ProtectedBoundary)?;
        if verified.digest() != assignment.binding.lease_digest()
            || verified.generation() != assignment.binding.lease_generation()
            || verified.node().as_bytes() != &node
        {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }

        let raw = controller
            .get(
                crate::RecordNamespace::OperatorRecovery,
                &selection.admission.key,
            )
            .ok_or(JournalError::ProtectedBoundary)?;
        let admission = Admission::decode_v1(raw)?;
        let digest = public_controller_request_digest_v1(
            admission.request_scope,
            admission.holder,
            admission.project,
            admission.canonical_request,
        );
        self.recovery = Some(inventory::RecoveryData {
            recovery: admission.operation,
            cleanup: selection.cleanup,
            request: digest,
            revision: admission.authorization_revision,
            cutoff: admission.cutoff,
        });
        self.project = Some(aos_sandbox_model::ProjectId::from_bytes(admission.project));
        let (outcome, inventory, boot) = self.host.stop_cleanup_inventory_v1()?;
        let actual = outcome.request();
        if actual.request_id() != selection.host_query
            || actual.session_binding() != selection.host_session
            || <[u8; 32]>::from(sha2::Sha256::digest(actual.canonical_packet()))
                != selection.host_request
            || <[u8; 32]>::from(sha2::Sha256::digest(outcome.canonical_packet()))
                != selection.host_outcome
            || actual.authorization().is_some()
            || boot != sample.host_boot_id()
            || outcome_body_digest(outcome)? != selection.host_body
        {
            return Err(JournalError::StaleAuthoritySnapshot.into());
        }
        self.selected = Some(inventory::select(
            inventory,
            inventory::QueryData {
                request: actual.request_id(),
                boot,
                recipient: None,
                first: selection.first.boottime_nanoseconds(),
                cutoff: actual.deadline_boottime_nanoseconds(),
                observed: sample,
            },
            inventory::RecoveryData {
                recovery: admission.operation,
                cleanup: selection.cleanup,
                request: digest,
                revision: admission.authorization_revision,
                cutoff: admission.cutoff,
            },
            bound,
            target.desired_generation_v1(),
            dispatch.sdk_request_data_v1(),
        ));
        positive(&self.selected)?;
        Ok(())
    }

    pub(super) fn require_complete(&self) -> Result<(), JournalError> {
        if matches!(self.body, Some(Ok(()))) && self.failure().is_none() {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    pub(super) fn selected(&self) -> Result<(inventory::Selection, [u8; 16]), JournalError> {
        self.require_complete()?;
        positive(&self.selected).copied()
    }

    pub(super) fn assignment(&self) -> Result<&CurrentCleanupAssignmentDataV2, JournalError> {
        self.require_complete()?;
        positive(&self.assignment)
    }

    pub(super) fn lease(
        &self,
    ) -> Result<&aos_sandbox_ownership_protocol::SignedOwnershipLease, JournalError> {
        self.require_complete()?;
        self.lease.value().ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn desired_generation(&self) -> Result<u64, JournalError> {
        self.require_complete()?;
        self.authorization
            .stop_cleanup_request_v2()?
            .stop_cleanup_target_v1()
            .map(|target| target.desired_generation_v1())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn recovery_v1(&self) -> Result<inventory::RecoveryData, JournalError> {
        self.require_complete()?;
        self.recovery.ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn project_v1(&self) -> Result<aos_sandbox_model::ProjectId, JournalError> {
        self.require_complete()?;
        self.project.ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn dispatch_v1(
        &self,
    ) -> Result<
        &aos_sandbox_protocol::domain_ledger::stop_dispatch::LifecycleStopDispatchDataV1,
        JournalError,
    > {
        self.require_complete()?;
        self.source.stop_dispatch_data_v1()
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.authorization
            .failure()
            .or_else(|| self.source.failure())
            .or_else(|| self.host.failure())
            .or_else(|| {
                self.assignment
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.old_stop
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.lease.cause())
            .or_else(|| {
                self.lease_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.selected
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.body
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| self.repeated.as_ref().map(|cause| cause as _))
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

fn outcome_body_digest(
    outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
) -> Result<[u8; 32], JournalError> {
    use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return Err(JournalError::ProtectedBoundary);
    };
    Ok(sha2::Sha256::digest(exact_body).into())
}
