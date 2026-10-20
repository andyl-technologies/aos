//! Sends the exact unsigned cleanup draft while retaining the same D socket.
//!
//! The real preparation and completed fresh-six owners supply every byte.
//! Payment precedes output allocation and native entry. Root/C and paired
//! bookends remain independent even after encoding/write failure. Success is
//! only a physically sent draft; no signed plan, public acceptance, permission
//! or final D disposition is produced here.

use std::{error::Error, os::unix::net::UnixStream};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::{
    DeleteRootResourceContextDataV2, DeleteRootResourceDraftDataV2,
    DeleteRootResourceWireErrorV2, DELETE_ROOT_RESOURCE_CONTEXT_BYTES_V2,
};
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use crate::policy_compiler::bounded_stream_io::{SliceDeadlineStreamIoV1, DeadlineStreamDirectionV1};
use super::{RootDeleteChallengeOriginalsV1, RootDeleteCleanupInputsOriginalV2, RootDeleteErrorV1,
    RootDeleteResourcePolicyOriginalV2, RootDeleteResourcePreparationOriginalV2, RootDeleteFreshInventoryOriginalV2};

type Cause = Box<dyn Error>;


#[derive(Clone, Copy)]
enum First { Geometry, Funding, Arm, BeforeClock, Before, Encoding, Send, After, AfterClock, Reentry }

pub(crate) struct RootDeleteResourceDraftOriginalV2 {
    demand: Option<Result<ResourceVector, Cause>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clocks: [RetainedKernelPairedClockAttemptV1; 2],
    samples: [Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>; 2],
    times: [Option<Result<(), JournalError>>; 2],
    context: [u8; DELETE_ROOT_RESOURCE_CONTEXT_BYTES_V2],
    encoding: Option<Result<Vec<u8>, Cause>>,
    digest: Option<Result<[u8; 32], DeleteRootResourceWireErrorV2>>,
    io: SliceDeadlineStreamIoV1,
    sent: Option<Result<(), JournalError>>,
    first: Option<First>,
    entered: bool,
    complete: bool,
    closed: Option<RootDeleteErrorV1>,
}

impl Default for RootDeleteResourceDraftOriginalV2 {
    fn default() -> Self {
        Self {
            demand: None, funding: None, posts: Default::default(), arm: None, before: None, after: None,
            clocks: std::array::from_fn(|_| Default::default()), samples: std::array::from_fn(|_| None),
            times: std::array::from_fn(|_| None), context: [0; DELETE_ROOT_RESOURCE_CONTEXT_BYTES_V2],
            encoding: None, digest: None, io: Default::default(), sent: None,
            first: None, entered: false, complete: false, closed: None,
        }
    }
}

impl RootDeleteResourceDraftOriginalV2 {
    pub(crate) fn receiving_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.entered || self.funding.is_some() || self.first.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.demand.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn send_once_v2(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &mut UnixStream, challenge: &RootDeleteChallengeOriginalsV1,
        policy: &RootDeleteResourcePolicyOriginalV2, inputs: &RootDeleteCleanupInputsOriginalV2,
        prepared: &RootDeleteResourcePreparationOriginalV2, fresh: &RootDeleteFreshInventoryOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.send_inner_v3(flight, original, challenge, policy, inputs, prepared, fresh, None)
    }

    pub(super) fn send_apply_once_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &mut UnixStream, challenge: &RootDeleteChallengeOriginalsV1,
        policy: &RootDeleteResourcePolicyOriginalV2, inputs: &RootDeleteCleanupInputsOriginalV2,
        prepared: &RootDeleteResourcePreparationOriginalV2, fresh: &RootDeleteFreshInventoryOriginalV2,
        current: super::RootDeleteResourceContinuationV4<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        self.send_inner_v3(flight, original, challenge, policy, inputs, prepared, fresh, Some(current))
    }

    fn send_inner_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &mut UnixStream, challenge: &RootDeleteChallengeOriginalsV1,
        policy: &RootDeleteResourcePolicyOriginalV2, inputs: &RootDeleteCleanupInputsOriginalV2,
        prepared: &RootDeleteResourcePreparationOriginalV2, fresh: &RootDeleteFreshInventoryOriginalV2,
        current: Option<super::RootDeleteResourceContinuationV4<'_>>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.demand = Some((|| {
            let invalid = || JournalError::JournalTooLarge;
            let prepared = prepared.preparation_data_v2().map_err(|_| JournalError::ProtectedBoundary)?;
            let length = DeleteRootResourceDraftDataV2::preparation_encoded_bytes_v2(prepared).map_err(|_| invalid())?;
            let memory = DeleteRootResourceDraftDataV2::preparation_receiving_memory_bytes_v2(prepared)
                .map_err(|_| invalid())?.checked_add(std::mem::size_of::<Self>().checked_mul(3).ok_or_else(invalid)?)
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<[
                    u8; aos_sandbox_protocol::domain_ledger::delete_root::final_inventory::DELETE_ROOT_FRESH_FRAME_BYTES_V2]>()
                    .checked_mul(3)?))
                .and_then(|bytes| bytes.checked_add(RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?.checked_mul(2)?))
                .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
            let traffic = u64::try_from(length).map_err(|_| invalid())?;
            Ok(RootDeleteChunkPostsV1::fixed_demand_v1()?.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, memory).with(D::NetworkBytes, traffic).with(D::OutputBytes, traffic)
                .with(D::OpenFiles, 2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64))?)
        })());
        if !matches!(self.demand, Some(Ok(_))) { self.first = Some(First::Geometry); return Err(RootDeleteErrorV1::Opening); }
        self.funding = Some(match current {
            None => flight.admit_delete_resource_draft_once_v2(prepared, fresh, self),
            Some(current) => flight.admit_delete_resource_continuation_once_v4(current,
                super::apply_issuer::ApplyStageOwnerV3::Draft(prepared, self)),
        });
        if !matches!(self.funding, Some(Ok(()))) { self.first = Some(First::Funding); return Err(RootDeleteErrorV1::Opening); }
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) { self.first = Some(First::Arm); return Err(RootDeleteErrorV1::Opening); }
        self.samples[0] = Some(self.clocks[0].observe_once(None));
        self.times[0] = Some(self.require_time_v2(challenge, policy, inputs, prepared, 0));
        self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
        if !matches!(self.times[0], Some(Ok(()))) { self.first = Some(First::BeforeClock); }
        if !matches!(self.before, Some(Ok(()))) { self.first.get_or_insert(First::Before); }
        if self.first.is_none() {
            self.encoding = Some((|| {
                let frame = fresh.completed_frame_data_v2()?;
                let signed = policy.verified_sources_v2()?;
                self.context = DeleteRootResourceContextDataV2 { open: frame.open, challenge: frame.challenge,
                    frame: match current { None => frame.digest_v2()?,
                        Some(current) => current.frame_commitment_v4()? }, fresh_six: aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::fresh_six_cut_data_v2(&frame.owners)?,
                    lease: *inputs.lease_v2()?.digest().as_bytes(),
                    policy_expires_seconds: signed.0.head().expires_at().min(signed.1.expires_at()),
                    clock: *positive(&self.samples[0])? }.encode_for_purpose_v3(prepared.purpose_v3()?)?;
                let view = self.view_v2(prepared)?;
                let length = view.encoded_bytes_for_purpose_v3(prepared.purpose_v3()?)?;
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(length)?;
                bytes.resize(length, 0);
                view.encode_range_for_purpose_v3(0, &mut bytes, prepared.purpose_v3()?)?;
                Ok(bytes)
            })());
            if !matches!(self.encoding, Some(Ok(_))) { self.first = Some(First::Encoding); }
        }
        if self.first.is_none() {
            self.digest = Some(self.view_v2(prepared).map_err(|_| DeleteRootResourceWireErrorV2::Context(
                aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootWireErrorV2::Association))
                .and_then(|view| view.digest_for_purpose_v3(prepared.purpose_v3().map_err(|_| DeleteRootResourceWireErrorV2::Context(
                    aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootWireErrorV2::Association))?)));
            if !matches!(self.digest, Some(Ok(_))) { self.first = Some(First::Encoding); }
        }
        if self.first.is_none() {
            self.sent = Some((|| {
                let bytes = self.encoding.as_mut().and_then(|value| value.as_mut().ok())
                    .ok_or(JournalError::ProtectedBoundary)?;
                self.io.run_once(original, bytes, challenge.current_cutoff_v1()
                    .map_err(|_| JournalError::ProtectedBoundary)?, DeadlineStreamDirectionV1::Write)
                    .map_err(|_| JournalError::ProtectedBoundary)
            })());
            if !matches!(self.sent, Some(Ok(()))) { self.first = Some(First::Send); }
        }
        self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
        if !matches!(self.after, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        self.samples[1] = Some(self.clocks[1].observe_once(None));
        self.times[1] = Some(self.require_time_v2(challenge, policy, inputs, prepared, 1));
        if !matches!(self.times[1], Some(Ok(()))) { self.first.get_or_insert(First::AfterClock); }
        if self.first.is_some() { return Err(RootDeleteErrorV1::Opening); }
        self.complete = true;
        Ok(())
    }

    fn view_v2<'view>(&'view self, prepared: &'view RootDeleteResourcePreparationOriginalV2)
        -> Result<DeleteRootResourceDraftDataV2<'view>, RootDeleteErrorV1> {
        let prepared = prepared.preparation_data_v2()?;
        Ok(DeleteRootResourceDraftDataV2 { context: &self.context,
            canonical_plan: prepared.preparation_v2().canonical_plan(),
            canonical_statement: prepared.preparation_v2().signing_request().canonical_statement(),
            deadline_free_body: prepared.deadline_free_body_v2() })
    }

    fn require_time_v2(&self, challenge: &RootDeleteChallengeOriginalsV1,
        policy: &RootDeleteResourcePolicyOriginalV2, inputs: &RootDeleteCleanupInputsOriginalV2,
        prepared: &RootDeleteResourcePreparationOriginalV2, index: usize,
    ) -> Result<(), JournalError> {
        let invalid = || JournalError::ProtectedBoundary;
        let sample = *positive(&self.samples[index])?;
        let prior = if index == 0 { prepared.completed_clock_v2().map_err(|_| invalid())? }
            else { *positive(&self.samples[0])? };
        prior.validate_later_sample(sample).map_err(|_| invalid())?;
        challenge.require_current_clock_v1(sample)?;
        let signed = policy.verified_sources_v2().map_err(|_| invalid())?;
        let plan = prepared.preparation_data_v2().map_err(|_| invalid())?.preparation_v2().plan_data_v1();
        if sample.wall_seconds() >= signed.0.head().expires_at() || sample.wall_seconds() >= signed.1.expires_at()
            || sample.wall_seconds() >= inputs.lease_v2().map_err(|_| invalid())?.authority_expires_seconds()
            || sample.wall_seconds() >= plan.expires_seconds() { return Err(invalid()); }
        Ok(())
    }

    pub(super) fn completed_clock_v2(&self) -> Result<RawPairedClockSample, RootDeleteErrorV1> {
        self.require_completed_v2()?;
        positive(&self.samples[1]).copied().map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(crate) fn require_completed_v2(&self) -> Result<(), RootDeleteErrorV1> {
        if self.complete && self.first.is_none() && self.closed.is_none()
            && matches!(self.sent, Some(Ok(()))) && matches!(self.digest, Some(Ok(_))) { Ok(()) }
        else { Err(RootDeleteErrorV1::Original) }
    }

    pub(super) fn draft_data_v2<'view>(&'view self, prepared: &'view RootDeleteResourcePreparationOriginalV2)
        -> Result<DeleteRootResourceDraftDataV2<'view>, RootDeleteErrorV1> {
        self.require_completed_v2()?;
        self.view_v2(prepared)
    }

    pub(super) fn funding_failed_v2(&self) -> bool {
        matches!(self.first, Some(First::Funding))
            || matches!(self.first, Some(First::Arm | First::Before)) && self.posts.funding_failed_v1()
    }

    pub(super) fn property_failure_view_v2(&self) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        if matches!(self.first, Some(First::Arm | First::Before | First::After)) {
            self.posts.property_failure_view_v1(self.failure()?)
        } else { None }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Geometry => self.demand.as_ref().and_then(|r| r.as_ref().err()).map(|e| e.as_ref()), First::Funding => cause(&self.funding),
            First::Arm | First::Before => self.posts.before_failure_v1().or_else(|| cause(&self.arm)).or_else(|| cause(&self.before)),
            First::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            First::BeforeClock => self.clocks[0].failure().or_else(|| cause(&self.samples[0])).or_else(|| cause(&self.times[0])),
            First::AfterClock => self.clocks[1].failure().or_else(|| cause(&self.samples[1])).or_else(|| cause(&self.times[1])),
            First::Encoding => self.encoding.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause.as_ref())
                .or_else(|| cause(&self.digest)),
            First::Send => self.io.failure().or_else(|| cause(&self.sent)),
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
