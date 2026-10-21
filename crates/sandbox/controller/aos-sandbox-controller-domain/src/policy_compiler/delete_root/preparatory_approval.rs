//! Issues the exact preparatory192 only after real late Root native comparisons.
//!
//! The same D remains occupied afterward. This frame accepts the concrete
//! signed non-destructive catalog preparation and its residual cleanup debt;
//! it never reports destruction or final disposition. Actual Root/C native
//! posts precede the frame, and separately paid post-write time stays owed.

use super::*;
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::delete_root::{final_inventory::{
    DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3, DeleteRootPreparatoryApprovalDataV3},
    initial_inventory::DeleteRootInitialAckDataV3, transport::DeleteRootChallengeDataV2};
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;

type Cause = Box<dyn StdError>;

#[derive(Clone, Copy)]
enum ApprovalFirst { Geometry, Funding, Arm, BeforeClock, Before, After,
    ComparisonClock, Encoding, Send, SendClock, Reentry }

pub(crate) struct RootDeletePreparatoryApprovalOriginalV3 {
    demand: Option<Result<ResourceVector, Cause>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clocks: [RetainedKernelPairedClockAttemptV1; 3],
    samples: [Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>; 3],
    times: [Option<Result<(), Cause>>; 3],
    encoding: Option<Result<[u8; DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3], Cause>>,
    response: [u8; DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3],
    io: FixedDeadlineStreamIoV1<DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3>,
    sent: Option<Result<(), Cause>>,
    entered: bool,
    complete: bool,
    first: Option<ApprovalFirst>,
    closed: Option<RootDeleteErrorV1>,
}

impl Default for RootDeletePreparatoryApprovalOriginalV3 {
    fn default() -> Self {
        Self { demand: None, funding: None, posts: Default::default(), arm: None, before: None, after: None,
            clocks: std::array::from_fn(|_| Default::default()), samples: std::array::from_fn(|_| None),
            times: std::array::from_fn(|_| None), encoding: None,
            response: [0; DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3], io: Default::default(), sent: None,
            entered: false, complete: false, first: None, closed: None }
    }
}

impl RootDeletePreparatoryApprovalOriginalV3 {
    pub(crate) fn receiving_demand_v3(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.entered || self.funding.is_some() || self.first.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        self.demand.as_ref().and_then(|r| r.as_ref().ok()).copied().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn send_once_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &mut UnixStream, challenge: &RootDeleteChallengeOriginalsV1,
        initial: &initial_inventory::RootDeleteInitialInventoryOriginalV2,
        fresh: &RootDeleteFreshInventoryOriginalV2, inputs: &RootDeleteCleanupInputsOriginalV2,
        prepared: &RootDeleteResourcePreparationOriginalV2, draft: &RootDeleteResourceDraftOriginalV2,
        signature: &RootDeleteResourceSignatureOriginalV2, confirmation: &RootDeleteResourcePolicyOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.send_inner_v3(flight, original, challenge, initial, fresh, inputs, prepared,
            draft, signature, confirmation, None)
    }

    pub(super) fn send_apply_once_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &mut UnixStream, challenge: &RootDeleteChallengeOriginalsV1,
        initial: &initial_inventory::RootDeleteInitialInventoryOriginalV2,
        fresh: &RootDeleteFreshInventoryOriginalV2, inputs: &RootDeleteCleanupInputsOriginalV2,
        prepared: &RootDeleteResourcePreparationOriginalV2, draft: &RootDeleteResourceDraftOriginalV2,
        signature: &RootDeleteResourceSignatureOriginalV2, confirmation: &RootDeleteResourcePolicyOriginalV2,
        current: super::RootDeleteResourceContinuationV4<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        self.send_inner_v3(flight, original, challenge, initial, fresh, inputs, prepared,
            draft, signature, confirmation, Some(current))
    }

    fn send_inner_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &mut UnixStream, challenge: &RootDeleteChallengeOriginalsV1,
        initial: &initial_inventory::RootDeleteInitialInventoryOriginalV2,
        fresh: &RootDeleteFreshInventoryOriginalV2, inputs: &RootDeleteCleanupInputsOriginalV2,
        prepared: &RootDeleteResourcePreparationOriginalV2, draft: &RootDeleteResourceDraftOriginalV2,
        signature: &RootDeleteResourceSignatureOriginalV2, confirmation: &RootDeleteResourcePolicyOriginalV2,
        current: Option<super::RootDeleteResourceContinuationV4<'_>>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(ApprovalFirst::Reentry); self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.demand = Some((|| {
            signature.require_completed_v2()?;
            confirmation.require_confirmation_complete_v3()?;
            let bytes = std::mem::size_of::<Self>().checked_mul(3)
                .and_then(|n| n.checked_add(std::mem::size_of::<DeleteRootPreparatoryApprovalDataV3>().checked_mul(3)?))
                .and_then(|n| n.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(3)?))
                .and_then(|n| n.checked_add(RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?.checked_mul(3)?))
                .and_then(|n| u64::try_from(n).ok()).ok_or(JournalError::JournalTooLarge)?;
            let names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
                .and_then(|n| n.checked_mul(3)).and_then(|n| u64::try_from(n).ok()).ok_or(JournalError::JournalTooLarge)?;
            Ok(RootDeleteChunkPostsV1::fixed_demand_v1()?.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, bytes).with(D::MetadataEntries, names)
                .with(D::OpenFiles, 3 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64)
                .with(D::NetworkBytes, DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3 as u64)
                .with(D::OutputBytes, DELETE_ROOT_PREPARATORY_APPROVAL_BYTES_V3 as u64))?)
        })());
        if !matches!(self.demand, Some(Ok(_))) { self.first = Some(ApprovalFirst::Geometry); return Err(RootDeleteErrorV1::Opening); }
        self.funding = Some(match current {
            None => flight.admit_delete_preparatory_approval_once_v3(signature, confirmation, self),
            Some(current) => flight.admit_delete_resource_continuation_once_v4(current,
                super::apply_issuer::ApplyStageOwnerV3::Approval(signature, confirmation, self)),
        });
        if !matches!(self.funding, Some(Ok(()))) { self.first = Some(ApprovalFirst::Funding); return Err(RootDeleteErrorV1::Opening); }
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) { self.first = Some(ApprovalFirst::Arm); }
        self.sample_once_v3(0, challenge, confirmation, inputs, prepared);
        if !matches!(self.times[0], Some(Ok(()))) { self.first.get_or_insert(ApprovalFirst::BeforeClock); }
        self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
        if !matches!(self.before, Some(Ok(()))) { self.first.get_or_insert(ApprovalFirst::Before); }
        // No approval bytes exist until both actual native peer/C posts pass.
        self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
        if !matches!(self.after, Some(Ok(()))) { self.first.get_or_insert(ApprovalFirst::After); }
        self.sample_once_v3(1, challenge, confirmation, inputs, prepared);
        if !matches!(self.times[1], Some(Ok(()))) { self.first.get_or_insert(ApprovalFirst::ComparisonClock); }
        if self.first.is_none() {
            self.encoding = Some((|| {
                let frame = fresh.completed_frame_data_v2()?;
                let draft = draft.draft_data_v2(prepared)?;
                let signed = signature.signed_data_v3()?;
                let purpose = prepared.purpose_v3()?;
                let approval = DeleteRootPreparatoryApprovalDataV3 { open: frame.open,
                    challenge: frame.challenge, frame: match current {
                        None => frame.digest_v2()?,
                        Some(current) => current.frame_commitment_v4()?,
                    },
                    preparation: signed.acceptance_commitment_for_purpose_v3(draft, purpose)?,
                    clock: *positive(&self.samples[1])? };
                let held = DeleteRootChallengeDataV2::decode_v2(challenge.challenge_bytes_v1()?)?;
                let initial = DeleteRootInitialAckDataV3::decode_v3(initial.completed_ack_bytes_v2()?)?;
                match current {
                    None => approval.require_exchange_v3(frame, held, initial, draft, signed)?,
                    Some(current) => {
                        current.require_approval_v4(approval, frame, held, initial, draft, signed)?;
                    }
                }
                Ok(approval.encode_for_purpose_v3(purpose)?)
            })());
            match self.encoding.as_ref().and_then(|r| r.as_ref().ok()) {
                Some(bytes) => self.response = *bytes,
                None => self.first = Some(ApprovalFirst::Encoding),
            }
        }
        if self.first.is_none() {
            self.sent = Some((|| {
                let cutoff = challenge.current_cutoff_v1()?;
                self.io.run_once(original, &mut self.response, cutoff,
                    aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1::Write)?;
                Ok(())
            })());
            if !matches!(self.sent, Some(Ok(()))) { self.first = Some(ApprovalFirst::Send); }
        }
        // This separately funded final sample is owed after every entered path.
        self.sample_once_v3(2, challenge, confirmation, inputs, prepared);
        if !matches!(self.times[2], Some(Ok(()))) { self.first.get_or_insert(ApprovalFirst::SendClock); }
        self.complete = self.first.is_none() && matches!(self.sent, Some(Ok(()))) && self.io.completed_exact();
        if self.complete { Ok(()) } else { Err(RootDeleteErrorV1::Opening) }
    }

    fn sample_once_v3(&mut self, index: usize, challenge: &RootDeleteChallengeOriginalsV1,
        confirmation: &RootDeleteResourcePolicyOriginalV2, inputs: &RootDeleteCleanupInputsOriginalV2,
        prepared: &RootDeleteResourcePreparationOriginalV2,
    ) {
        self.samples[index] = Some(self.clocks[index].observe_once(None));
        self.times[index] = Some((|| {
            let sample = *positive(&self.samples[index])?;
            let prior = if index == 0 { confirmation.completed_clock_v2()? }
                else { *positive(&self.samples[index - 1])? };
            prior.validate_later_sample(sample)?;
            challenge.require_current_clock_v1(sample)?;
            let policy = confirmation.verified_sources_v2()?;
            let lease = inputs.lease_v2()?;
            let plan = prepared.preparation_data_v2()?.preparation_v2().plan_data_v1();
            if sample.wall_seconds() >= policy.0.head().expires_at()
                || sample.wall_seconds() >= policy.1.expires_at()
                || sample.wall_seconds() >= lease.authority_expires_seconds()
                || sample.wall_seconds() >= plan.expires_seconds() { return Err(JournalError::StaleAuthoritySnapshot.into()); }
            Ok(())
        })());
    }

    pub(crate) fn require_completed_v3(&self) -> Result<(), RootDeleteErrorV1> {
        if self.complete && self.first.is_none() && self.closed.is_none() && self.io.completed_exact()
            && matches!(self.sent, Some(Ok(()))) && matches!(self.times[2], Some(Ok(()))) { Ok(()) }
        else { Err(RootDeleteErrorV1::Original) }
    }

    pub(super) fn completed_clock_v3(&self) -> Result<RawPairedClockSample, RootDeleteErrorV1> {
        self.require_completed_v3()?;
        positive(&self.samples[2]).copied().map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn completed_data_v4(&self,
        purpose: aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3,
    ) -> Result<DeleteRootPreparatoryApprovalDataV3, RootDeleteErrorV1> {
        self.require_completed_v3()?;
        DeleteRootPreparatoryApprovalDataV3::decode_for_purpose_v3(
            positive(&self.encoding).map_err(|_| RootDeleteErrorV1::Original)?, purpose)
            .map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn funding_failed_v3(&self) -> bool {
        matches!(self.first, Some(ApprovalFirst::Funding))
            || matches!(self.first, Some(ApprovalFirst::Arm | ApprovalFirst::Before)) && self.posts.funding_failed_v1()
    }

    pub(super) fn property_failure_view_v3(&self) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        if matches!(self.first, Some(ApprovalFirst::Arm | ApprovalFirst::Before | ApprovalFirst::After)) {
            self.posts.property_failure_view_v1(self.failure()?)
        } else { None }
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        match self.first? {
            ApprovalFirst::Geometry => self.demand.as_ref()?.as_ref().err().map(|e| e.as_ref()),
            ApprovalFirst::Funding => cause(&self.funding),
            ApprovalFirst::Arm | ApprovalFirst::Before => self.posts.before_failure_v1().or_else(|| cause(&self.arm)).or_else(|| cause(&self.before)),
            ApprovalFirst::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            ApprovalFirst::BeforeClock => self.clocks[0].failure().or_else(|| cause(&self.samples[0])).or_else(|| self.times[0].as_ref()?.as_ref().err().map(|e| e.as_ref())),
            ApprovalFirst::ComparisonClock => self.clocks[1].failure().or_else(|| cause(&self.samples[1])).or_else(|| self.times[1].as_ref()?.as_ref().err().map(|e| e.as_ref())),
            ApprovalFirst::SendClock => self.clocks[2].failure().or_else(|| cause(&self.samples[2])).or_else(|| self.times[2].as_ref()?.as_ref().err().map(|e| e.as_ref())),
            ApprovalFirst::Encoding => self.encoding.as_ref()?.as_ref().err().map(|e| e.as_ref()),
            ApprovalFirst::Send => self.io.failure().or_else(|| self.sent.as_ref()?.as_ref().err().map(|e| e.as_ref())),
            ApprovalFirst::Reentry => self.closed.as_ref().map(|e| e as _),
        }
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value.as_ref().and_then(|r| r.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}
