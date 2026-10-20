//! Joins current cleanup assignment and live lease through the sole decoders.
//!
//! This owner reads only its genuine D peers' held native/full C and Root
//! credential originals. All source-bound decoder/crypto/compiler work is paid
//! on the same R before growth. Publication bytes never become Native authority.

use std::error::Error;
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_ownership_protocol::response_verification::OwnershipResponseVerifyCaptureV1;
use aos_sandbox_ownership_protocol::trusted_policy::{OwnershipTrustConfigurationCaptureV1,
    OwnershipTrustConfigurationClosedV1, verifier_from_protected_policy_retaining_v1};
use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::journal::JournalError;
use crate::normal_root::RootPolicyAcceptedFlightV1;
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1,
    create_storage_current::controller_readonly::public_trust::RootBrokerPlanPublicTrustDataV1,
    provisioning_current::{current_compiler_complete_receiving_demand_v1, compile_parentless_current_v1}};
use super::{RootDeleteErrorV1, RootDeleteChallengeOriginalsV1, RootDeleteControllerCurrentOriginalV1,
    RootDeleteResourcePolicyOriginalV2, RootDeleteGraphComparisonOriginalV2};

type Cause = Box<dyn Error>;
type Candidate = (aos_sandbox_policy::PolicyCompilerInputV1, aos_sandbox_policy::CompiledPolicyCandidateV1);

#[derive(Clone, Copy)]
enum AssignmentInputV3<'scope> {
    Initial(&'scope RootDeleteControllerCurrentOriginalV1),
    CompletedPreparation(super::RootDeleteResourceContinuationV4<'scope>),
}

impl<'scope> AssignmentInputV3<'scope> {
    fn rows(self) -> Result<aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'scope>, JournalError> {
        match self {
            Self::Initial(owner) => owner.current_assignment_rows_v2(),
            Self::CompletedPreparation(owner) => owner.current_assignment_rows_v3(),
        }
    }

    fn state(self) -> Result<&'scope std::collections::BTreeMap<(crate::journal::RecordNamespace, Vec<u8>), Vec<u8>>, JournalError> {
        match self {
            Self::Initial(owner) => owner.current_assignment_state_v2(),
            Self::CompletedPreparation(owner) => owner.current_assignment_state_v3(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum CleanupInputsPhaseV2 { Trust, Assignment }

#[derive(Clone, Copy)]
enum First { Geometry(usize), Funding(usize), OwnershipTrust, BrokerTrust, Clock, Selection,
    Lease, Compiler, Node, Comparison, Reentry }

use crate::policy_compiler::provisioning_current::current_cleanup_assignment::{
    CurrentCleanupAssignmentDataV2 as AssignmentValuesV2, current_cleanup_assignment_rows_data_v2,
};

#[derive(Default)]
pub(crate) struct RootDeleteCleanupInputsOriginalV2 {
    phase: Option<CleanupInputsPhaseV2>,
    demand: [Option<Result<ResourceVector, JournalError>>; 2],
    funding: [Option<Result<(), ResourceReservationErrorV1>>; 2],
    ownership: OwnershipTrustConfigurationCaptureV1,
    ownership_result: Option<Result<(), OwnershipTrustConfigurationClosedV1>>,
    broker: Option<Result<RootBrokerPlanPublicTrustDataV1, Cause>>,
    clock: RetainedKernelPairedClockAttemptV1,
    sample: Option<Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    time: Option<Result<(), JournalError>>,
    selection: Option<Result<AssignmentValuesV2, Cause>>,
    response: OwnershipResponseVerifyCaptureV1,
    lease: Option<Result<(), aos_sandbox_ownership_protocol::OwnershipLeaseAcquisitionError>>,
    compiler: Option<Result<Candidate, Cause>>,
    node: Option<Result<[u8; 16], crate::normal_root::NormalRootStartupErrorV1>>,
    comparison: Option<Result<(), JournalError>>,
    first: Option<First>,
    entered: bool,
    complete: bool,
    closed: Option<RootDeleteErrorV1>,
}

impl RootDeleteCleanupInputsOriginalV2 {
    pub(crate) fn admission_phase_v2(&self) -> Result<CleanupInputsPhaseV2, ResourceReservationErrorV1> {
        let phase = self.phase.ok_or(ResourceReservationErrorV1::Conflict)?;
        let index = match phase { CleanupInputsPhaseV2::Trust => 0, CleanupInputsPhaseV2::Assignment => 1 };
        if !self.entered || self.first.is_some() || self.funding[index].is_some()
            || !matches!(self.demand[index], Some(Ok(_))) { return Err(ResourceReservationErrorV1::Conflict); }
        Ok(phase)
    }

    pub(crate) fn receiving_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let index = match self.admission_phase_v2()? { CleanupInputsPhaseV2::Trust => 0, CleanupInputsPhaseV2::Assignment => 1 };
        self.demand[index].as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn observe_once_v2(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, policy: &RootDeleteResourcePolicyOriginalV2,
        controller: &RootDeleteControllerCurrentOriginalV1, graph: &RootDeleteGraphComparisonOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.observe_inner_v3(flight, challenge, policy, AssignmentInputV3::Initial(controller), graph)
    }

    pub(super) fn observe_apply_once_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, policy: &RootDeleteResourcePolicyOriginalV2,
        current: super::RootDeleteResourceContinuationV4<'_>, graph: &RootDeleteGraphComparisonOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.observe_inner_v3(flight, challenge, policy, AssignmentInputV3::CompletedPreparation(current), graph)
    }

    fn observe_inner_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, policy: &RootDeleteResourcePolicyOriginalV2,
        controller: AssignmentInputV3<'_>, graph: &RootDeleteGraphComparisonOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.phase = Some(CleanupInputsPhaseV2::Trust);
        self.demand[0] = Some((|| {
            let (ownership, public) = policy.ownership_public_inputs_v2().map_err(|_| JournalError::ProtectedBoundary)?;
            if public.len() != 32 { return Err(JournalError::ProtectedBoundary); }
            let broker = policy.broker_plan_public_inputs_v2().map_err(|_| JournalError::ProtectedBoundary)?;
            let bytes = OwnershipTrustConfigurationCaptureV1::receiving_memory_bytes_v1(ownership.len())
                .and_then(|bytes| bytes.checked_add(RootBrokerPlanPublicTrustDataV1::receiving_memory_bytes_v2(broker)?))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>().checked_mul(3)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
        })());
        if !matches!(self.demand[0], Some(Ok(_))) { self.first = Some(First::Geometry(0)); return Err(RootDeleteErrorV1::Opening); }
        self.funding[0] = Some(self.admit_input_once_v3(flight, policy, controller, graph));
        if !matches!(self.funding[0], Some(Ok(()))) { self.first = Some(First::Funding(0)); return Err(RootDeleteErrorV1::Opening); }
        let (ownership, public) = policy.ownership_public_inputs_v2()?;
        let public: [u8; 32] = public.try_into().map_err(|_| RootDeleteErrorV1::Opening)?;
        self.ownership_result = Some(verifier_from_protected_policy_retaining_v1(
            ownership.to_vec(), public, aos_sandbox_core::DecodeLimits::default(), &mut self.ownership));
        if !matches!(self.ownership_result, Some(Ok(()))) { self.first = Some(First::OwnershipTrust); return Err(RootDeleteErrorV1::Opening); }
        self.broker = Some(RootBrokerPlanPublicTrustDataV1::from_fixed_public_data_v1(policy.broker_plan_public_inputs_v2()?));
        if !matches!(self.broker, Some(Ok(_))) { self.first = Some(First::BrokerTrust); return Err(RootDeleteErrorV1::Opening); }
        self.phase = Some(CleanupInputsPhaseV2::Assignment);
        self.demand[1] = Some((|| {
            let state = controller.state()?;
            let bytes = state.iter().try_fold(0usize, |total, ((_, key), value)| total.checked_add(key.len())?.checked_add(value.len()))
                .ok_or(JournalError::JournalTooLarge)?;
            let verifier = self.ownership.verifier().ok_or(JournalError::ProtectedBoundary)?;
            let verification = verifier.response_receiving_dynamic_bytes_v2(bytes).ok_or(JournalError::JournalTooLarge)?;
            let clock = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1().ok_or(JournalError::JournalTooLarge)?;
            let extra = verification.checked_add(clock)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<AssignmentValuesV2>().checked_mul(3)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
            current_compiler_complete_receiving_demand_v1(u64::try_from(bytes).map_err(|_| JournalError::JournalTooLarge)?,
                state, policy.verified_sources_v2().map_err(|_| JournalError::ProtectedBoundary)?)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, extra)
                    .with(D::OpenFiles, RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64))
                .map_err(|_| JournalError::JournalTooLarge)
        })());
        if !matches!(self.demand[1], Some(Ok(_))) { self.first = Some(First::Geometry(1)); return Err(RootDeleteErrorV1::Opening); }
        self.funding[1] = Some(self.admit_input_once_v3(flight, policy, controller, graph));
        if !matches!(self.funding[1], Some(Ok(()))) { self.first = Some(First::Funding(1)); return Err(RootDeleteErrorV1::Opening); }
        self.sample = Some(self.clock.observe_once(None));
        self.time = Some((|| {
            let sample = *positive(&self.sample)?;
            policy.completed_clock_v2().map_err(|_| JournalError::ProtectedBoundary)?
                .validate_later_sample(sample).map_err(|_| JournalError::ProtectedBoundary)?;
            challenge.require_current_clock_v1(sample)?;
            let signed = policy.verified_sources_v2().map_err(|_| JournalError::ProtectedBoundary)?;
            if sample.wall_seconds() >= signed.0.head().expires_at()
                || sample.wall_seconds() >= signed.1.expires_at() {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        if !matches!(self.time, Some(Ok(()))) { self.first = Some(First::Clock); return Err(RootDeleteErrorV1::Opening); }
        self.selection = Some((|| {
            let rows = controller.rows()?;
            let sandbox = graph.selected_root_v2()?;
            current_cleanup_assignment_rows_data_v2(rows, sandbox).map_err(|error| error as Cause)
        })());
        if !matches!(self.selection, Some(Ok(_))) { self.first = Some(First::Selection); return Err(RootDeleteErrorV1::Opening); }
        let selected = self.selection.as_ref().and_then(|value| value.as_ref().ok()).ok_or(RootDeleteErrorV1::Original)?;
        let recovered = &selected.recovered_lease;
        let sample = *positive(&self.sample).map_err(|_| RootDeleteErrorV1::Opening)?;
        self.lease = Some(self.ownership.verifier().ok_or(RootDeleteErrorV1::Original)?
            .verify_response_bytes_retaining_v1(selected.gate.claim(), recovered.canonical_lease(),
                recovered.canonical_signature(), recovered.canonical_receipt(), recovered.canonical_receipt_signature(),
                &sample, &mut self.response));
        if !matches!(self.lease, Some(Ok(()))) { self.first = Some(First::Lease); return Err(RootDeleteErrorV1::Opening); }
        self.compiler = Some((|| {
            let manifest = selected.binding.manifest().manifest();
            let signed = policy.verified_sources_v2()?;
            if manifest.project() != signed.0.head().project() { return Err(JournalError::ProtectedBoundary.into()); }
            compile_parentless_current_v1(signed, manifest.project(), manifest.sandbox(), signed.0.cache_domain()).map_err(|cause| cause as Cause)
        })());
        if !matches!(self.compiler, Some(Ok(_))) { self.first = Some(First::Compiler); return Err(RootDeleteErrorV1::Opening); }
        self.node = Some(flight.delete_cleanup_enrolled_node_v2());
        if !matches!(self.node, Some(Ok(_))) { self.first = Some(First::Node); return Err(RootDeleteErrorV1::Opening); }
        self.comparison = Some((|| {
            let lease = self.response.value().ok_or(JournalError::ProtectedBoundary)?;
            let candidate = &self.compiler.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?.1;
            if selected.binding.manifest().manifest().node().as_bytes() != positive(&self.node)?
                || selected.binding.manifest().manifest().policy() != candidate.portable().policy_descriptor()
                || selected.binding.lease_digest() != lease.digest()
                || selected.binding.lease_generation() != lease.generation() {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        })());
        if !matches!(self.comparison, Some(Ok(()))) { self.first = Some(First::Comparison); return Err(RootDeleteErrorV1::Opening); }
        self.complete = true;
        Ok(())
    }

    fn admit_input_once_v3(&self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        policy: &RootDeleteResourcePolicyOriginalV2, controller: AssignmentInputV3<'_>,
        graph: &RootDeleteGraphComparisonOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        match controller {
            AssignmentInputV3::Initial(controller) =>
                flight.admit_delete_cleanup_inputs_once_v2(policy, controller, graph, self),
            AssignmentInputV3::CompletedPreparation(current) =>
                flight.admit_delete_resource_continuation_once_v4(current,
                    super::apply_issuer::ApplyStageOwnerV3::Inputs(policy, self)),
        }
    }

    pub(crate) fn require_completed_v2(&self) -> Result<(), RootDeleteErrorV1> {
        if self.complete && self.first.is_none() && matches!(self.comparison, Some(Ok(()))) { Ok(()) }
        else { Err(RootDeleteErrorV1::Original) }
    }

    pub(super) fn manifest_v2(&self)
        -> Result<&aos_sandbox_core::CanonicalAssignmentManifestV1, RootDeleteErrorV1>
    {
        self.require_completed_v2()?;
        Ok(self.selection.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(RootDeleteErrorV1::Original)?.binding.manifest())
    }

    pub(super) fn lease_v2(&self)
        -> Result<&aos_sandbox_ownership_protocol::SignedOwnershipLease, RootDeleteErrorV1>
    {
        self.require_completed_v2()?;
        self.response.value().ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn broker_trust_v2(&self) -> Result<&RootBrokerPlanPublicTrustDataV1, RootDeleteErrorV1> {
        self.require_completed_v2()?;
        self.broker.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn policy_digest_v2(&self) -> Result<aos_sandbox_core::ObjectDigest, RootDeleteErrorV1> {
        self.require_completed_v2()?;
        self.compiler.as_ref().and_then(|value| value.as_ref().ok())
            .map(|(_, candidate)| candidate.portable().policy_descriptor().digest())
            .ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn completed_clock_v2(&self) -> Result<RawPairedClockSample, RootDeleteErrorV1> {
        self.require_completed_v2()?;
        self.sample.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn funding_failed_v2(&self) -> bool { matches!(self.first, Some(First::Funding(_))) }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Geometry(index) => cause(&self.demand[index]),
            First::Funding(index) => cause(&self.funding[index]),
            First::OwnershipTrust => self.ownership.failure().or_else(|| cause(&self.ownership_result)),
            First::BrokerTrust => boxed(&self.broker),
            First::Clock => self.clock.failure().or_else(|| cause(&self.sample)).or_else(|| cause(&self.time)),
            First::Selection => boxed(&self.selection),
            First::Lease => self.response.cause().or_else(|| cause(&self.lease)),
            First::Compiler => boxed(&self.compiler),
            First::Node => cause(&self.node),
            First::Comparison => cause(&self.comparison),
            First::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}
fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
fn boxed<T>(value: &Option<Result<T, Cause>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause.as_ref())
}
