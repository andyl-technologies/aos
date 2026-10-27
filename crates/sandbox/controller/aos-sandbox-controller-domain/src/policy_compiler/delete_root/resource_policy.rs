//! Retains Delete's current signed policy pair on its actual accepted D flight.
//!
//! The graph and six-owner readers must already have completed. This interval
//! uses the sole serving-writer verifier, prearms its own Root/C and four writer
//! destinations before capture, and always runs independent after observations.
//! No result here signs a resource plan or permits a destructive effect.

use std::error::Error;
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::{RootCurrentPolicyInputDataV1, RetainedKernelPairedClockAttemptV1};
use crate::policy_compiler::continuation_policy::{RootDeletePolicyOriginalV2, RootContinuationPolicyErrorV1};
use crate::policy_compiler::root_signed_sources::RootSignedProjectSourcesV1;
use super::{RootDeleteChallengeOriginalsV1, RootDeleteErrorV1,
    RootDeleteGraphObjectsOriginalV2, RootDeleteGraphComparisonOriginalV2};

#[derive(Clone, Copy)]
enum First { Geometry, Funding, Arm, ClockBefore, Before, PolicyBegin, Verification,
    Project, Credentials, PolicyAfter, After, ClockAfter, Reentry }

#[derive(Clone, Copy)]
enum Purpose<'scope> {
    Initial,
    Confirmation { signature: &'scope super::RootDeleteResourceSignatureOriginalV2,
        earlier: &'scope RootDeleteResourcePolicyOriginalV2 },
}

#[derive(Default)]
pub(crate) struct RootDeleteResourcePolicyOriginalV2 {
    demand: Option<Result<ResourceVector, NormalRootStartupErrorV1>>,
    credentials: Option<Box<CredentialCapturesV2>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    policy: RootDeletePolicyOriginalV2,
    policy_begin: Option<Result<(), RootContinuationPolicyErrorV1>>,
    verified: Option<Result<(), RootContinuationPolicyErrorV1>>,
    project: Option<Result<(), JournalError>>,
    policy_after: Option<Result<(), RootContinuationPolicyErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clocks: [RetainedKernelPairedClockAttemptV1; 2],
    samples: [Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>; 2],
    times: [Option<Result<(), JournalError>>; 2],
    entered: bool,
    complete: bool,
    confirmation_complete: bool,
    first: Option<First>,
    closed: Option<RootDeleteErrorV1>,
}

impl RootDeleteResourcePolicyOriginalV2 {
    pub(crate) fn receiving_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.entered || self.funding.is_some() || self.first.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.demand.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn observe_once_v2(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, graph: &RootDeleteGraphObjectsOriginalV2,
        comparison: &RootDeleteGraphComparisonOriginalV2, inputs: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        self.observe_inner_v2(flight, challenge, graph, comparison, inputs, Purpose::Initial, None)
    }

    pub(super) fn confirm_once_v2(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, graph: &RootDeleteGraphObjectsOriginalV2,
        comparison: &RootDeleteGraphComparisonOriginalV2, inputs: &RootCurrentPolicyInputDataV1<'_>,
        signature: &super::RootDeleteResourceSignatureOriginalV2,
        earlier: &RootDeleteResourcePolicyOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.observe_inner_v2(flight, challenge, graph, comparison, inputs,
            Purpose::Confirmation { signature, earlier }, None)
    }

    pub(super) fn observe_apply_once_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, graph: &RootDeleteGraphObjectsOriginalV2,
        comparison: &RootDeleteGraphComparisonOriginalV2, inputs: &RootCurrentPolicyInputDataV1<'_>,
        current: super::RootDeleteResourceContinuationV4<'_>,
        earlier: &RootDeleteResourcePolicyOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.observe_inner_v2(flight, challenge, graph, comparison, inputs, Purpose::Initial,
            Some((current, earlier)))
    }

    pub(super) fn confirm_apply_once_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, graph: &RootDeleteGraphObjectsOriginalV2,
        comparison: &RootDeleteGraphComparisonOriginalV2, inputs: &RootCurrentPolicyInputDataV1<'_>,
        signature: &super::RootDeleteResourceSignatureOriginalV2,
        current: super::RootDeleteResourceContinuationV4<'_>,
        earlier: &RootDeleteResourcePolicyOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.observe_inner_v2(flight, challenge, graph, comparison, inputs,
            Purpose::Confirmation { signature, earlier }, Some((current, earlier)))
    }

    fn observe_inner_v2(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, graph: &RootDeleteGraphObjectsOriginalV2,
        comparison: &RootDeleteGraphComparisonOriginalV2, inputs: &RootCurrentPolicyInputDataV1<'_>,
        purpose: Purpose<'_>,
        apply: Option<(super::RootDeleteResourceContinuationV4<'_>, &RootDeleteResourcePolicyOriginalV2)>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.demand = Some((|| {
            let policy = flight.delete_policy_receiving_demand_v2()?;
            let credentials = match purpose {
                Purpose::Initial => CredentialCapturesV2::receiving_demand_v2()
                    .map_err(|_| NormalRootStartupErrorV1::Service)?,
                Purpose::Confirmation { .. } => ResourceVector::ZERO,
            };
            let native = RootDeleteChunkPostsV1::fixed_demand_v1()
                .map_err(|_| NormalRootStartupErrorV1::Service)?;
            let bytes = std::mem::size_of::<Self>().checked_mul(3)
                .and_then(|bytes| bytes.checked_add(
                    RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?.checked_mul(2)?))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(NormalRootStartupErrorV1::Service)?;
            let pairs = u64::try_from(RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
                .map_err(|_| NormalRootStartupErrorV1::Service)?.checked_mul(2)
                .ok_or(NormalRootStartupErrorV1::Service)?;
            policy.checked_add(credentials).and_then(|demand| demand.checked_add(native))
                .and_then(|demand| demand.checked_add(
                ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OpenFiles, pairs)))
                .map_err(|_| NormalRootStartupErrorV1::Service)
        })());
        if !matches!(self.demand, Some(Ok(_))) {
            self.first = Some(First::Geometry);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.funding = Some(match (purpose, apply) {
            (Purpose::Initial, None) => flight.admit_delete_resource_policy_once_v2(graph, comparison, self),
            (Purpose::Confirmation { signature, .. }, None) =>
                flight.admit_delete_resource_policy_confirmation_once_v2(signature, self),
            (Purpose::Initial, Some((current, _))) => flight.admit_delete_resource_continuation_once_v4(current,
                super::apply_issuer::ApplyStageOwnerV3::Policy(self)),
            (Purpose::Confirmation { signature, .. }, Some((current, _))) =>
                flight.admit_delete_resource_continuation_once_v4(current,
                    super::apply_issuer::ApplyStageOwnerV3::Confirmation(signature, self)),
        });
        if !matches!(self.funding, Some(Ok(()))) {
            self.first = Some(First::Funding);
            return Err(RootDeleteErrorV1::Opening);
        }
        if matches!(purpose, Purpose::Initial) {
            self.credentials = Some(Box::new(CredentialCapturesV2::new_v2()));
        }
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) {
            self.first = Some(First::Arm);
        } else {
            self.samples[0] = Some(self.clocks[0].observe_once(None));
            self.times[0] = Some((|| {
                let sample = *positive(&self.samples[0])?;
                challenge.require_current_clock_v1(sample)?;
                if let Some((current, _)) = apply {
                    current.completed_clock_v3().map_err(|_| JournalError::ProtectedBoundary)?
                        .validate_later_sample(sample).map_err(|_| JournalError::ProtectedBoundary)?;
                }
                if let Purpose::Confirmation { signature, .. } = purpose {
                    signature.completed_clock_v2().map_err(|_| JournalError::ProtectedBoundary)?
                        .validate_later_sample(sample).map_err(|_| JournalError::ProtectedBoundary)?;
                }
                Ok(())
            })());
            if !matches!(self.times[0], Some(Ok(()))) { self.first = Some(First::ClockBefore); }
            self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
            if !matches!(self.before, Some(Ok(()))) { self.first.get_or_insert(First::Before); }
            if self.first.is_none() && matches!(purpose, Purpose::Initial) {
                if self.credentials.as_mut().is_none_or(|credentials| credentials.capture_once_v2().is_err()) {
                    self.first = Some(First::Credentials);
                }
            }
            if self.first.is_none() {
                self.policy_begin = Some(flight.begin_delete_policy_once_v2(&mut self.policy));
                if !matches!(self.policy_begin, Some(Ok(()))) { self.first = Some(First::PolicyBegin); }
            }
            if self.first.is_none() {
                self.verified = Some(match positive(&self.samples[0]) {
                    Ok(sample) => flight.verify_delete_policy_sources_once_v2(&mut self.policy, inputs, *sample),
                    Err(_) => Err(RootContinuationPolicyErrorV1::Closed),
                });
                if !matches!(self.verified, Some(Ok(()))) { self.first = Some(First::Verification); }
            }
            if self.first.is_none() {
                self.project = Some((|| {
                    let sources = self.policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
                    let graph = graph.verified_graph_v2().map_err(|_| JournalError::ProtectedBoundary)?;
                    if sources.0.head().project() != graph.project { return Err(JournalError::ProtectedBoundary); }
                    if let Some((_, earlier)) = apply {
                        let prior = earlier.verified_sources_v2().map_err(|_| JournalError::ProtectedBoundary)?;
                        // Apply retains the accepted horizon and exact source
                        // pair; a newly valid policy cannot renew this D.
                        if sources.0.head() != prior.0.head() || sources.1 != prior.1 {
                            return Err(JournalError::ProtectedBoundary);
                        }
                    }
                    if let Purpose::Confirmation { signature, earlier } = purpose {
                        signature.require_completed_v2().map_err(|_| JournalError::ProtectedBoundary)?;
                        let prior = earlier.verified_sources_v2().map_err(|_| JournalError::ProtectedBoundary)?;
                        // These exact signed packet/input commitments cover all
                        // deployment and project inputs, including signer pins.
                        if sources.0.head() != prior.0.head() || sources.1 != prior.1 {
                            return Err(JournalError::ProtectedBoundary);
                        }
                    }
                    Ok(())
                })());
                if !matches!(self.project, Some(Ok(()))) { self.first = Some(First::Project); }
            }
        }
        // These are already-priced destinations. Every reached pair and Root/C
        // interval finishes independently of semantic or financial refusal.
        if self.policy_begin.is_some() {
            self.policy_after = Some(flight.finish_delete_policy_once_v2(&mut self.policy));
            if !matches!(self.policy_after, Some(Ok(()))) { self.first.get_or_insert(First::PolicyAfter); }
        }
        self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
        if !matches!(self.after, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        self.samples[1] = Some(self.clocks[1].observe_once(None));
        self.times[1] = Some((|| {
            let before = *positive(&self.samples[0])?;
            let after = *positive(&self.samples[1])?;
            before.validate_later_sample(after).map_err(|_| JournalError::ProtectedBoundary)?;
            challenge.require_current_clock_v1(after)?;
            if let Some(sources) = self.policy.verified_v1() {
                if after.wall_seconds() >= sources.0.head().expires_at()
                    || after.wall_seconds() >= sources.1.expires_at() {
                    return Err(JournalError::ProtectedBoundary);
                }
            }
            Ok(())
        })());
        if !matches!(self.times[1], Some(Ok(()))) { self.first.get_or_insert(First::ClockAfter); }
        self.complete = self.first.is_none() && matches!(self.project, Some(Ok(())))
            && matches!(self.policy_after, Some(Ok(()))) && matches!(self.after, Some(Ok(())))
            && matches!(self.times[1], Some(Ok(())));
        self.confirmation_complete = self.complete && matches!(purpose, Purpose::Confirmation { .. });
        self.verified_sources_v2().map(|_| ())
    }

    pub(crate) fn require_confirmation_complete_v3(&self) -> Result<(), RootDeleteErrorV1> {
        if !self.confirmation_complete { return Err(RootDeleteErrorV1::Original); }
        self.verified_sources_v2().map(|_| ())
    }

    pub(crate) fn verified_sources_v2(&self) -> Result<&RootSignedProjectSourcesV1, RootDeleteErrorV1> {
        if !self.complete || self.first.is_some() { return Err(RootDeleteErrorV1::Original); }
        self.policy.require_complete_v1().map_err(|_| RootDeleteErrorV1::Original)?;
        self.policy.verified_v1().ok_or(RootDeleteErrorV1::Original)
    }

    // The same credential originals span later plan/signature work. Final
    // readbacks are owed once even after a failed resource-model or wire stage.
    pub(super) fn finish_credentials_if_owed_v2(&mut self) {
        if let Some(credentials) = self.credentials.as_mut() {
            credentials.finish_once_v2();
            if credentials.failure().is_some() { self.first.get_or_insert(First::Credentials); }
        }
    }

    pub(super) fn require_credentials_complete_v2(&self) -> Result<(), RootDeleteErrorV1> {
        self.verified_sources_v2()?;
        let credentials = self.credentials.as_ref().ok_or(RootDeleteErrorV1::Original)?;
        if credentials.first.is_none() && credentials.posts.iter().all(|post| matches!(post, Some(Ok(())))) {
            Ok(())
        } else { Err(RootDeleteErrorV1::Original) }
    }

    pub(super) fn ownership_public_inputs_v2(&self) -> Result<(&[u8], &[u8]), RootDeleteErrorV1> {
        self.verified_sources_v2()?;
        self.credentials.as_ref().ok_or(RootDeleteErrorV1::Original)?
            .ownership.bytes().ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn broker_plan_public_inputs_v2(&self) -> Result<(&[u8], &[u8], &[u8]), RootDeleteErrorV1> {
        self.verified_sources_v2()?;
        self.credentials.as_ref().ok_or(RootDeleteErrorV1::Original)?
            .plan.bytes().ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn completed_clock_v2(&self) -> Result<RawPairedClockSample, RootDeleteErrorV1> {
        self.verified_sources_v2()?;
        positive(&self.samples[1]).copied().map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn funding_failed_v2(&self) -> bool {
        matches!(self.first, Some(First::Funding))
            || (matches!(self.first, Some(First::Arm | First::Before)) && self.posts.funding_failed_v1())
    }

    pub(super) fn property_failure_view_v2(&self)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        if matches!(self.first, Some(First::Arm | First::Before | First::After)) {
            self.posts.property_failure_view_v1(self.failure()?)
        } else { None }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Geometry => cause(&self.demand),
            First::Funding => cause(&self.funding),
            First::Arm | First::Before => self.posts.before_failure_v1()
                .or_else(|| cause(&self.arm)).or_else(|| cause(&self.before)),
            First::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            First::ClockBefore => self.clocks[0].failure().or_else(|| cause(&self.samples[0])).or_else(|| cause(&self.times[0])),
            First::PolicyBegin | First::Verification | First::PolicyAfter => self.policy.failure()
                .or_else(|| cause(&self.policy_begin)).or_else(|| cause(&self.verified)).or_else(|| cause(&self.policy_after)),
            First::Project => cause(&self.project),
            First::Credentials => self.credentials.as_ref().and_then(|credentials| credentials.failure()),
            First::ClockAfter => self.clocks[1].failure().or_else(|| cause(&self.samples[1])).or_else(|| cause(&self.times[1])),
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

// These are the existing fixed Root credential native engines. The complete
// boxed carrier and both negative prefixes are funded before construction.
struct CredentialCapturesV2 {
    ownership: crate::public_api_session::RootCurrentOwnershipCredentialCustodyV1,
    plan: crate::public_api_session::RootCurrentBrokerPlanCredentialCustodyV1,
    captures: [Option<Result<(), ()>>; 2],
    posts: [Option<Result<(), ()>>; 2],
    first: Option<usize>,
}

impl CredentialCapturesV2 {
    fn new_v2() -> Self {
        Self {
            ownership: crate::public_api_session::RootCurrentOwnershipCredentialCustodyV1::new(),
            plan: crate::public_api_session::RootCurrentBrokerPlanCredentialCustodyV1::new(),
            captures: [None, None], posts: [None, None], first: None,
        }
    }

    fn receiving_demand_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bytes = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        crate::public_api_session::RootCurrentOwnershipCredentialCustodyV1::dominant_demand()
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .checked_add(crate::public_api_session::RootCurrentBrokerPlanCredentialCustodyV1::dominant_demand()
                .ok_or(ResourceReservationErrorV1::Conflict)?)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)).map_err(Into::into)
    }

    fn capture_once_v2(&mut self) -> Result<(), RootDeleteErrorV1> {
        self.captures[0] = Some(self.ownership.capture_once());
        if !matches!(self.captures[0], Some(Ok(()))) {
            self.first = Some(0);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.captures[1] = Some(self.plan.capture_once());
        if !matches!(self.captures[1], Some(Ok(()))) {
            self.first = Some(1);
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    fn finish_once_v2(&mut self) {
        if self.captures[0].is_some() && self.posts[0].is_none() {
            self.posts[0] = Some(self.ownership.recheck_once());
            if !matches!(self.posts[0], Some(Ok(()))) { self.first.get_or_insert(2); }
        }
        if self.captures[1].is_some() && self.posts[1].is_none() {
            self.posts[1] = Some(self.plan.recheck_once());
            if !matches!(self.posts[1], Some(Ok(()))) { self.first.get_or_insert(3); }
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            0 => self.ownership.capture_failure().map(|cause| cause as _),
            1 => self.plan.capture_failure().map(|cause| cause as _),
            2 => self.ownership.post_failure().map(|cause| cause as _),
            3 => self.plan.post_failure().map(|cause| cause as _),
            _ => None,
        }
    }
}
