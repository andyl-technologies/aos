//! Issues Apply7 from the actual completed post26 cut on the same retained D.
//!
//! Eight independent debits fund the existing policy, trust, assignment/lease,
//! plan, draft, signature, policy-confirmation and approval engines. This owner
//! neither constructs a signer nor executes or reports physical destruction.

use super::*;
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use aos_sandbox_core::ResourceVector;
mod continuation;
pub(crate) use continuation::RootDeleteResourceContinuationV4;
use aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3 as Purpose;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootDeleteApplyIssuerPhaseV3 {
    Policy,
    Trust,
    Assignment,
    Preparation,
    Draft,
    Signature,
    Confirmation,
    Approval,
}

impl RootDeleteApplyIssuerPhaseV3 {
    pub(crate) const fn index_v3(self) -> usize { self as usize }
}

pub(crate) enum ApplyStageOwnerV3<'scope> {
    Policy(&'scope RootDeleteResourcePolicyOriginalV2),
    Inputs(&'scope RootDeleteResourcePolicyOriginalV2, &'scope RootDeleteCleanupInputsOriginalV2),
    Preparation(&'scope RootDeleteResourcePreparationOriginalV2),
    Draft(&'scope RootDeleteResourcePreparationOriginalV2, &'scope RootDeleteResourceDraftOriginalV2),
    Signature(&'scope RootDeleteResourceDraftOriginalV2, &'scope RootDeleteResourceSignatureOriginalV2),
    Confirmation(&'scope RootDeleteResourceSignatureOriginalV2, &'scope RootDeleteResourcePolicyOriginalV2),
    Approval(&'scope RootDeleteResourceSignatureOriginalV2, &'scope RootDeleteResourcePolicyOriginalV2,
        &'scope RootDeletePreparatoryApprovalOriginalV3),
}

impl ApplyStageOwnerV3<'_> {
    pub(crate) fn receiving_v3(self)
        -> Result<(RootDeleteApplyIssuerPhaseV3, ResourceVector), ResourceReservationErrorV1>
    {
        use RootDeleteApplyIssuerPhaseV3 as P;
        let invalid = |_| ResourceReservationErrorV1::Conflict;
        Ok(match self {
            Self::Policy(owner) => (P::Policy, owner.receiving_demand_v2()?),
            Self::Inputs(policy, owner) => {
                policy.verified_sources_v2().map_err(invalid)?;
                let phase = match owner.admission_phase_v2()? {
                    CleanupInputsPhaseV2::Trust => P::Trust,
                    CleanupInputsPhaseV2::Assignment => P::Assignment,
                };
                (phase, owner.receiving_demand_v2()?)
            }
            Self::Preparation(owner) => (P::Preparation, owner.receiving_demand_v2()?),
            Self::Draft(prepared, owner) => {
                prepared.preparation_data_v2().map_err(invalid)?;
                (P::Draft, owner.receiving_demand_v2()?)
            }
            Self::Signature(draft, owner) => {
                draft.require_completed_v2().map_err(invalid)?;
                (P::Signature, owner.receiving_demand_v2()?)
            }
            Self::Confirmation(signature, owner) => {
                signature.require_completed_v2().map_err(invalid)?;
                (P::Confirmation, owner.receiving_demand_v2()?)
            }
            Self::Approval(signature, confirmation, owner) => {
                signature.require_completed_v2().map_err(invalid)?;
                confirmation.require_confirmation_complete_v3().map_err(invalid)?;
                (P::Approval, owner.receiving_demand_v3()?)
            }
        })
    }
}

#[derive(Clone, Copy)]
enum First { Policy, Inputs, Spec, Preparation, Draft, Signature, Confirmation, Approval, Primary, Reentry }

#[derive(Default)]
pub(super) struct RootDeleteApplyIssuerOriginalV3 {
    purpose: Option<Purpose>,
    policy: RootDeleteResourcePolicyOriginalV2,
    policy_result: Option<Result<(), RootDeleteErrorV1>>,
    inputs: RootDeleteCleanupInputsOriginalV2,
    inputs_result: Option<Result<(), RootDeleteErrorV1>>,
    spec: RootDeleteMountSpecOriginalV4,
    spec_result: Option<Result<(), RootDeleteErrorV1>>,
    preparation: RootDeleteResourcePreparationOriginalV2,
    preparation_result: Option<Result<(), RootDeleteErrorV1>>,
    draft: RootDeleteResourceDraftOriginalV2,
    draft_result: Option<Result<(), RootDeleteErrorV1>>,
    signature: RootDeleteResourceSignatureOriginalV2,
    signature_result: Option<Result<(), RootDeleteErrorV1>>,
    confirmation: RootDeleteResourcePolicyOriginalV2,
    confirmation_result: Option<Result<(), RootDeleteErrorV1>>,
    approval: RootDeletePreparatoryApprovalOriginalV3,
    approval_result: Option<Result<(), RootDeleteErrorV1>>,
    primary: Option<Result<(), Box<dyn StdError>>>,
    first: Option<First>,
    entered: bool,
    closed: Option<RootDeleteErrorV1>,
}

impl RootDeleteApplyIssuerOriginalV3 {
    pub(super) fn issue_once_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &mut UnixStream, challenge: &RootDeleteChallengeOriginalsV1,
        policy: &crate::policy_compiler::RootCurrentPolicyInputDataV1<'_>,
        graph: &RootDeleteGraphObjectsOriginalV2, comparison: &RootDeleteGraphComparisonOriginalV2,
        initial: &initial_inventory::RootDeleteInitialInventoryOriginalV2,
        fresh: &RootDeleteFreshInventoryOriginalV2, selected: &RootDeleteResourceSelectionOriginalV2,
        current: &RootDeletePreparationCurrentOriginalV3, earlier: &RootDeleteResourcePolicyOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.issue_inner_v4(flight, original, challenge, policy, graph, comparison,
            initial, fresh, selected, RootDeleteResourceContinuationV4::apply_v4(current), earlier)
    }

    pub(super) fn issue_network_once_v4(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &mut UnixStream, challenge: &RootDeleteChallengeOriginalsV1,
        policy: &crate::policy_compiler::RootCurrentPolicyInputDataV1<'_>,
        graph: &RootDeleteGraphObjectsOriginalV2, comparison: &RootDeleteGraphComparisonOriginalV2,
        initial: &initial_inventory::RootDeleteInitialInventoryOriginalV2,
        fresh: &RootDeleteFreshInventoryOriginalV2, selected: &RootDeleteResourceSelectionOriginalV2,
        current: &RootDeletePreparationCurrentOriginalV3, apply: &RootDeleteApplyIssuerOriginalV3,
    ) -> Result<(), RootDeleteErrorV1> {
        fresh.require_inputs_complete_v2()?;
        self.issue_inner_v4(flight, original, challenge, policy, graph, comparison,
            initial, fresh, selected, RootDeleteResourceContinuationV4::network_v4(
                current, apply, &fresh.controller, comparison), &apply.confirmation)
    }

    pub(super) fn issue_mount_once_v4(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &mut UnixStream, challenge: &RootDeleteChallengeOriginalsV1,
        policy: &crate::policy_compiler::RootCurrentPolicyInputDataV1<'_>,
        graph: &RootDeleteGraphObjectsOriginalV2, comparison: &RootDeleteGraphComparisonOriginalV2,
        initial: &initial_inventory::RootDeleteInitialInventoryOriginalV2,
        fresh: &RootDeleteFreshInventoryOriginalV2, selected: &RootDeleteResourceSelectionOriginalV2,
        current: &RootDeletePreparationCurrentOriginalV3, network: &RootDeleteApplyIssuerOriginalV3,
        cleanup: &RootDeleteCleanupCurrentOriginalV4,
    ) -> Result<(), RootDeleteErrorV1> {
        fresh.require_inputs_complete_v2()?;
        self.issue_inner_v4(flight, original, challenge, policy, graph, comparison,
            initial, fresh, selected, RootDeleteResourceContinuationV4::mount_v4(
                current, network, cleanup, &fresh.controller, comparison, &fresh.cache), &network.confirmation)
    }

    fn issue_inner_v4(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &mut UnixStream, challenge: &RootDeleteChallengeOriginalsV1,
        policy: &crate::policy_compiler::RootCurrentPolicyInputDataV1<'_>,
        graph: &RootDeleteGraphObjectsOriginalV2, comparison: &RootDeleteGraphComparisonOriginalV2,
        initial: &initial_inventory::RootDeleteInitialInventoryOriginalV2,
        fresh: &RootDeleteFreshInventoryOriginalV2, selected: &RootDeleteResourceSelectionOriginalV2,
        current: RootDeleteResourceContinuationV4<'_>, earlier: &RootDeleteResourcePolicyOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.purpose = Some(current.purpose_v4());
        self.primary = Some((|| {
            current.require_completed_v3()?;
            self.policy_result = Some(self.policy.observe_apply_once_v3(flight, challenge, graph,
                comparison, policy, current, earlier));
            if !matches!(self.policy_result, Some(Ok(()))) {
                self.first = Some(First::Policy); return Err(RootDeleteErrorV1::Opening.into());
            }
            self.inputs_result = Some(self.inputs.observe_apply_once_v3(flight, challenge, &self.policy,
                current, comparison));
            if !matches!(self.inputs_result, Some(Ok(()))) {
                self.first = Some(First::Inputs); return Err(RootDeleteErrorV1::Opening.into());
            }
            if current.purpose_v4() == Purpose::MountReap62 {
                self.spec_result = Some(self.spec.observe_once_v4(flight,
                    super::mount_spec::MountSpecInputsV4 { challenge, current,
                        assignment: &self.inputs, policy: &self.policy, cache: current.mount_cache_v4()? }));
                if !matches!(self.spec_result, Some(Ok(()))) {
                    self.first = Some(First::Spec); return Err(RootDeleteErrorV1::Opening.into());
                }
            }
            self.preparation_result = Some(self.preparation.prepare_apply_once_v3(flight, challenge,
                &self.policy, &self.inputs, selected, current,
                (current.purpose_v4() == Purpose::MountReap62).then_some(&self.spec)));
            if !matches!(self.preparation_result, Some(Ok(()))) {
                self.first = Some(First::Preparation); return Err(RootDeleteErrorV1::Opening.into());
            }
            self.draft_result = Some(self.draft.send_apply_once_v3(flight, original, challenge,
                &self.policy, &self.inputs, &self.preparation, fresh, current));
            if !matches!(self.draft_result, Some(Ok(()))) {
                self.first = Some(First::Draft); return Err(RootDeleteErrorV1::Opening.into());
            }
            self.signature_result = Some(self.signature.receive_apply_once_v3(flight, original,
                challenge, &mut self.policy, &self.inputs, &self.preparation, &self.draft, current));
            if !matches!(self.signature_result, Some(Ok(()))) {
                self.first = Some(First::Signature); return Err(RootDeleteErrorV1::Opening.into());
            }
            self.confirmation_result = Some(self.confirmation.confirm_apply_once_v3(flight, challenge,
                graph, comparison, policy, &self.signature, current, &self.policy));
            if !matches!(self.confirmation_result, Some(Ok(()))) {
                self.first = Some(First::Confirmation); return Err(RootDeleteErrorV1::Opening.into());
            }
            self.approval_result = Some(self.approval.send_apply_once_v3(flight, original, challenge,
                initial, fresh, &self.inputs, &self.preparation, &self.draft, &self.signature,
                &self.confirmation, current));
            if !matches!(self.approval_result, Some(Ok(()))) {
                self.first = Some(First::Approval); return Err(RootDeleteErrorV1::Opening.into());
            }
            Ok(())
        })());
        if self.primary.as_ref().is_some_and(Result::is_err) { self.first.get_or_insert(First::Primary); }
        // Capture may have succeeded before a later model/draft failed. Its
        // original credential posts remain owed independently on every exit.
        self.policy.finish_credentials_if_owed_v2();
        if self.first.is_none() && self.policy.failure().is_some() { self.first = Some(First::Policy); }
        self.require_completed_v3()
    }

    pub(super) fn require_completed_v3(&self) -> Result<(), RootDeleteErrorV1> {
        if self.first.is_none() && matches!(self.primary, Some(Ok(()))) {
            self.approval.require_completed_v3()
        } else { Err(RootDeleteErrorV1::Original) }
    }

    pub(super) fn cleanup_network_approval_v4(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::delete_root::final_inventory::DeleteRootPreparatoryApprovalDataV3, RootDeleteErrorV1> {
        self.completed_approval_for_v4(Purpose::Network9)
    }

    pub(super) fn completed_approval_for_v4(&self, purpose: Purpose)
        -> Result<aos_sandbox_protocol::domain_ledger::delete_root::final_inventory::DeleteRootPreparatoryApprovalDataV3, RootDeleteErrorV1> {
        self.require_completed_v3()?;
        if self.purpose != Some(purpose) { return Err(RootDeleteErrorV1::Original); }
        self.approval.completed_data_v4(purpose)
    }

    pub(super) fn require_cleanup_sample_v4(&self, sample: aos_sandbox_core::RawPairedClockSample)
        -> Result<(), Box<dyn StdError>> {
        self.completed_approval_for_v4(self.purpose.ok_or(RootDeleteErrorV1::Original)?)?
            .clock.validate_later_sample(sample)?;
        let sources = self.confirmation.verified_sources_v2()?;
        let lease = self.inputs.lease_v2()?;
        let plan = self.preparation.preparation_data_v2()?.preparation_v2().plan_data_v1();
        if sample.wall_seconds() >= sources.0.head().expires_at()
            || sample.wall_seconds() >= sources.1.expires_at()
            || sample.wall_seconds() >= lease.authority_expires_seconds()
            || sample.wall_seconds() >= plan.expires_seconds() {
            return Err(RootDeleteErrorV1::Original.into());
        }
        Ok(())
    }

    pub(super) fn compare_cleanup_network_outcome_v4(&self,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        proof: aos_sandbox_protocol::domain_ledger::delete_root::cleanup_current::DeleteRootCleanupTerminalDataV4,
        cutoff: u64,
    ) -> Result<(), Box<dyn StdError>> {
        self.cleanup_network_approval_v4()?;
        self.compare_completed_resource_outcome_v4(outcome, proof, cutoff)
    }

    pub(super) fn compare_completed_resource_outcome_v4(&self,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
        proof: aos_sandbox_protocol::domain_ledger::delete_root::cleanup_current::DeleteRootCleanupTerminalDataV4,
        cutoff: u64,
    ) -> Result<(), Box<dyn StdError>> {
        let purpose = self.purpose.ok_or(RootDeleteErrorV1::Original)?;
        self.completed_approval_for_v4(purpose)?;
        let prepared = self.preparation.preparation_data_v2()?;
        let request = outcome.request();
        let authorization = request.authorization().ok_or(RootDeleteErrorV1::Original)?;
        let signature = self.signature.signed_data_v3()?;
        let lease = self.inputs.lease_v2()?;
        let body = aos_sandbox_protocol::dispatch_template::inject_deadline(prepared.deadline_free_body_v2(), cutoff)?;
        let correct_action = match purpose {
            Purpose::Network9 => request.network_destroy_data_v4().is_some(),
            Purpose::MountReap62 => request.mount_attachment_anchor_data_v2().is_some_and(|request|
                request.action() == aos_proto::aos::sandbox::local::v1::AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_REAP),
            Purpose::Apply7 => request.storage_apply_data_v1().is_some_and(|request|
                matches!(request.operation(), aos_sandbox_protocol::semantics::StorageOperation::Destroy { .. })),
            Purpose::Preparation26 => false,
        };
        if !correct_action || request.method() != prepared.method_v2()
            || request.exact_body() != body || request.deadline_boottime_nanoseconds() != cutoff
            || authorization.broker_plan() != prepared.preparation_v2().canonical_plan()
            || authorization.broker_plan_signature() != signature.canonical_signature
            || authorization.ownership_lease() != lease.canonical_lease()
            || authorization.ownership_lease_signature() != lease.canonical_signature()
            || request.signed_request_digest() != proof.request
            || blake3::hash(outcome.canonical_packet()).as_bytes() != &proof.outcome {
            return Err(RootDeleteErrorV1::Original.into());
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        match self.first? {
            First::Policy => self.policy.failure().or_else(|| cause(&self.policy_result)),
            First::Inputs => self.inputs.failure().or_else(|| cause(&self.inputs_result)),
            First::Spec => self.spec.failure().or_else(|| cause(&self.spec_result)),
            First::Preparation => self.preparation.failure().or_else(|| cause(&self.preparation_result)),
            First::Draft => self.draft.failure().or_else(|| cause(&self.draft_result)),
            First::Signature => self.signature.failure_with_policy_v2(&self.policy)
                .or_else(|| cause(&self.signature_result)),
            First::Confirmation => self.confirmation.failure().or_else(|| cause(&self.confirmation_result)),
            First::Approval => self.approval.failure().or_else(|| cause(&self.approval_result)),
            First::Primary => self.primary.as_ref()?.as_ref().err().map(|cause| cause.as_ref()),
            First::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }

    pub(super) fn funding_failed_v3(&self) -> bool {
        match self.first {
            Some(First::Policy) => self.policy.funding_failed_v2(),
            Some(First::Inputs) => self.inputs.funding_failed_v2(),
            Some(First::Spec) => self.spec.funding_failed_v4(),
            Some(First::Preparation) => self.preparation.funding_failed_v2(),
            Some(First::Draft) => self.draft.funding_failed_v2(),
            Some(First::Signature) => self.signature.funding_failed_v2(),
            Some(First::Confirmation) => self.confirmation.funding_failed_v2(),
            Some(First::Approval) => self.approval.funding_failed_v3(),
            _ => false,
        }
    }

    pub(super) fn property_failure_view_v3(&self) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            First::Policy => self.policy.property_failure_view_v2(),
            First::Spec => self.spec.property_failure_view_v4(),
            First::Preparation => self.preparation.property_failure_view_v2(),
            First::Draft => self.draft.property_failure_view_v2(),
            First::Signature => self.signature.property_failure_view_v2(),
            First::Confirmation => self.confirmation.property_failure_view_v2(),
            First::Approval => self.approval.property_failure_view_v3(),
            _ => None,
        }
    }
}
