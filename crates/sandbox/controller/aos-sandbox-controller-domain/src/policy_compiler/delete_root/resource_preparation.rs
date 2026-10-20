//! Prepares the exact unsigned26 cleanup plan on the same retained D/R owner.
//!
//! Current Root inputs, current verified lease and the actual fresh workspace
//! selection precede this interval. Canonical construction is prepaid before
//! any model growth. All Root/C/native clock posts run independently. The plan
//! remains unsigned DATA until the genuine Controller signer and Root's later
//! signed-plan comparison complete; this owner cannot accept or destroy.

use std::error::Error;
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::authorization_artifact::delete_resource_plan::{
    DeleteResourcePlanPreparationDataV2, prepare_delete_resource_plan_v2,
};
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use super::{RootDeleteChallengeOriginalsV1, RootDeleteCleanupInputsOriginalV2, RootDeleteErrorV1,
    RootDeleteResourcePolicyOriginalV2, RootDeleteResourceSelectionOriginalV2};

type Cause = Box<dyn Error>;
use aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3 as Purpose;

#[derive(Clone, Copy)]
enum First { Geometry, Funding, Arm, BeforeClock, Before, Preparation, After, AfterClock, Reentry }

#[derive(Default)]
pub(crate) struct RootDeleteResourcePreparationOriginalV2 {
    purpose: Option<Purpose>,
    demand: Option<Result<ResourceVector, Cause>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clocks: [RetainedKernelPairedClockAttemptV1; 2],
    samples: [Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>; 2],
    times: [Option<Result<(), JournalError>>; 2],
    preparation: Option<Result<DeleteResourcePlanPreparationDataV2, Cause>>,
    first: Option<First>,
    entered: bool,
    complete: bool,
    closed: Option<RootDeleteErrorV1>,
}

impl RootDeleteResourcePreparationOriginalV2 {
    pub(crate) fn receiving_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.entered || self.funding.is_some() || self.first.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.demand.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn prepare_once_v2(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, policy: &RootDeleteResourcePolicyOriginalV2,
        inputs: &RootDeleteCleanupInputsOriginalV2, selected: &RootDeleteResourceSelectionOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.prepare_inner_v3(flight, challenge, policy, inputs, selected, None, None)
    }

    pub(super) fn prepare_apply_once_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, policy: &RootDeleteResourcePolicyOriginalV2,
        inputs: &RootDeleteCleanupInputsOriginalV2, selected: &RootDeleteResourceSelectionOriginalV2,
        current: super::RootDeleteResourceContinuationV4<'_>,
        spec: Option<&super::mount_spec::RootDeleteMountSpecOriginalV4>,
    ) -> Result<(), RootDeleteErrorV1> {
        self.prepare_inner_v3(flight, challenge, policy, inputs, selected, Some(current), spec)
    }

    fn prepare_inner_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, policy: &RootDeleteResourcePolicyOriginalV2,
        inputs: &RootDeleteCleanupInputsOriginalV2, selected: &RootDeleteResourceSelectionOriginalV2,
        current: Option<super::RootDeleteResourceContinuationV4<'_>>,
        spec: Option<&super::mount_spec::RootDeleteMountSpecOriginalV4>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.purpose = Some(current.map_or(Purpose::Preparation26, |current| current.purpose_v4()));
        self.demand = Some((|| {
            let invalid = || JournalError::JournalTooLarge;
            let trust = inputs.broker_trust_v2().map_err(|_| JournalError::ProtectedBoundary)?;
            let lease = inputs.lease_v2().map_err(|_| JournalError::ProtectedBoundary)?;
            let model = if self.purpose == Some(Purpose::MountReap62) {
                let descriptor = inputs.manifest_v2()?.manifest().sandbox_spec();
                let (bytes, _) = spec.ok_or(RootDeleteErrorV1::Original)?.completed_spec_v4(descriptor)?;
                DeleteResourcePlanPreparationDataV2::mount_receiving_demand_v4(&trust.authority,
                    lease.signer(), bytes.len(), descriptor.media_type().as_str().len())
            } else { DeleteResourcePlanPreparationDataV2::receiving_demand_v2(&trust.authority, lease.signer()) }
                .ok_or_else(invalid)?;
            let memory = std::mem::size_of::<Self>().checked_mul(3)
                .and_then(|bytes| bytes.checked_add(RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?.checked_mul(2)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
            Ok(model.checked_add(RootDeleteChunkPostsV1::fixed_demand_v1()?)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory)
                    .with(D::OpenFiles, 2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64))?)
        })());
        if !matches!(self.demand, Some(Ok(_))) { self.first = Some(First::Geometry); return Err(RootDeleteErrorV1::Opening); }
        self.funding = Some(match current {
            None => flight.admit_delete_resource_preparation_once_v2(inputs, selected, self),
            Some(current) => flight.admit_delete_resource_continuation_once_v4(current,
                super::apply_issuer::ApplyStageOwnerV3::Preparation(self)),
        });
        if !matches!(self.funding, Some(Ok(()))) { self.first = Some(First::Funding); return Err(RootDeleteErrorV1::Opening); }
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) { self.first = Some(First::Arm); return Err(RootDeleteErrorV1::Opening); }
        self.samples[0] = Some(self.clocks[0].observe_once(None));
        self.times[0] = Some(self.require_time_v2(challenge, policy, inputs, 0));
        self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
        if !matches!(self.times[0], Some(Ok(()))) { self.first = Some(First::BeforeClock); }
        if !matches!(self.before, Some(Ok(()))) { self.first.get_or_insert(First::Before); }
        if self.first.is_none() {
            self.preparation = Some((|| {
                if self.purpose == Some(Purpose::MountReap62) {
                    let current = current.ok_or(RootDeleteErrorV1::Original)?;
                    let spec = spec.ok_or(RootDeleteErrorV1::Original)?;
                    spec.completed_clock_v4()?.validate_later_sample(*positive(&self.samples[0])?)?;
                    let request = current.mount_request_v4(inputs, spec, challenge)?;
                    let trust = inputs.broker_trust_v2()?;
                    let signed = policy.verified_sources_v2()?;
                    let policy_expires = signed.0.head().expires_at().min(signed.1.expires_at());
                    return aos_sandbox_protocol::authorization_artifact::delete_resource_plan::prepare_delete_mount_reap_plan_v4(
                        &request, aos_sandbox_model::OperationId::from_bytes(challenge.source_query_v1()?.operation),
                        inputs.policy_digest_v2()?, inputs.lease_v2()?, *positive(&self.samples[0])?,
                        challenge.current_cutoff_v1()?, policy_expires, trust.authority.clone(), trust.revocation_scope)
                        .map_err(|cause| cause as Cause);
                }
                let mut selection = selected.selected_v2()?;
                if let Some(current) = current {
                    current.completed_clock_v3()?.validate_later_sample(*positive(&self.samples[0])?)?;
                    selection = current.selection_v4(selection, inputs, challenge)?;
                }
                let trust = inputs.broker_trust_v2()?;
                let signed = policy.verified_sources_v2()?;
                let policy_expires = signed.0.head().expires_at().min(signed.1.expires_at());
                prepare_delete_resource_plan_v2(selection.request, selection.assignment,
                    selection.operation, selection.request_id, inputs.policy_digest_v2()?, inputs.lease_v2()?,
                    *positive(&self.samples[0])?, challenge.current_cutoff_v1()?, policy_expires,
                    trust.authority.clone(), trust.revocation_scope).map_err(|cause| cause as Cause)
            })());
            if !matches!(self.preparation, Some(Ok(_))) { self.first = Some(First::Preparation); }
        }
        // Both observations were prepaid before native entry, and remain owed
        // when canonical construction or either earlier observation refuses.
        self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
        if !matches!(self.after, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        self.samples[1] = Some(self.clocks[1].observe_once(None));
        self.times[1] = Some(self.require_time_v2(challenge, policy, inputs, 1));
        if !matches!(self.times[1], Some(Ok(()))) { self.first.get_or_insert(First::AfterClock); }
        if self.first.is_some() { return Err(RootDeleteErrorV1::Opening); }
        self.complete = true;
        Ok(())
    }

    fn require_time_v2(&self, challenge: &RootDeleteChallengeOriginalsV1,
        policy: &RootDeleteResourcePolicyOriginalV2, inputs: &RootDeleteCleanupInputsOriginalV2, index: usize,
    ) -> Result<(), JournalError> {
        let sample = *positive(&self.samples[index])?;
        let prior = if index == 0 { inputs.completed_clock_v2().map_err(|_| JournalError::ProtectedBoundary)? }
            else { *positive(&self.samples[0])? };
        prior.validate_later_sample(sample).map_err(|_| JournalError::ProtectedBoundary)?;
        challenge.require_current_clock_v1(sample)?;
        let signed = policy.verified_sources_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        let lease = inputs.lease_v2().map_err(|_| JournalError::ProtectedBoundary)?;
        if sample.wall_seconds() >= signed.0.head().expires_at()
            || sample.wall_seconds() >= signed.1.expires_at()
            || sample.wall_seconds() >= lease.authority_expires_seconds() {
            return Err(JournalError::ProtectedBoundary);
        }
        if index == 1 {
            if let Some(Ok(preparation)) = &self.preparation {
                if sample.wall_seconds() >= preparation.preparation_v2().plan_data_v1().expires_seconds() {
                    return Err(JournalError::ProtectedBoundary);
                }
            }
        }
        Ok(())
    }

    pub(super) fn purpose_v3(&self) -> Result<Purpose, RootDeleteErrorV1> {
        self.preparation_data_v2()?;
        self.purpose.ok_or(RootDeleteErrorV1::Original)
    }

    pub(crate) fn preparation_data_v2(&self) -> Result<&DeleteResourcePlanPreparationDataV2, RootDeleteErrorV1> {
        if !self.complete || self.first.is_some() || self.closed.is_some() { return Err(RootDeleteErrorV1::Original); }
        self.preparation.as_ref().and_then(|value| value.as_ref().ok()).ok_or(RootDeleteErrorV1::Original)
    }

    pub(super) fn completed_clock_v2(&self) -> Result<RawPairedClockSample, RootDeleteErrorV1> {
        self.preparation_data_v2()?;
        positive(&self.samples[1]).copied().map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn funding_failed_v2(&self) -> bool {
        matches!(self.first, Some(First::Funding))
            || matches!(self.first, Some(First::Arm | First::Before)) && self.posts.funding_failed_v1()
    }

    pub(super) fn property_failure_view_v2(&self)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        if matches!(self.first, Some(First::Arm | First::Before | First::After)) {
            self.posts.property_failure_view_v1(self.failure()?)
        } else { None }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Geometry => self.demand.as_ref().and_then(|r| r.as_ref().err()).map(|e| e.as_ref()), First::Funding => cause(&self.funding),
            First::Arm | First::Before => self.posts.before_failure_v1()
                .or_else(|| cause(&self.arm)).or_else(|| cause(&self.before)),
            First::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            First::BeforeClock => self.clocks[0].failure().or_else(|| cause(&self.samples[0])).or_else(|| cause(&self.times[0])),
            First::AfterClock => self.clocks[1].failure().or_else(|| cause(&self.samples[1])).or_else(|| cause(&self.times[1])),
            First::Preparation => self.preparation.as_ref()?.as_ref().err().map(|cause| cause.as_ref()),
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
