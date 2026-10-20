//! Verifies the returned concrete cleanup signature on the same retained D.
//!
//! This original reads the exact finite signed reply with the existing strict
//! D receiver, compares Root's own unsigned draft and canonical statement, and
//! invokes the sole broker-plan verifier under Root's actual fixed trust. Its
//! successful result is an internal completed comparison, not acceptance192 or
//! permission to destroy. All credential and native afters remain independent.

use std::{error::Error, os::unix::net::UnixStream};
use aos_sandbox_model::{BrokerPlanExpectation, DecodeLimits, RawPairedClockSample,
    ResourceDimension as D, ResourceVector, VerifiedBrokerPlan};
use aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::{
    DeleteRootResourceSignedDataV2, DeleteRootResourceWireErrorV2,
    DELETE_ROOT_RESOURCE_SIGNED_HEADER_BYTES_V2,
};
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1,
    root_subject_chunk::RootSubjectChunkReceivingV1};
use super::{RootDeleteChallengeOriginalsV1, RootDeleteCleanupInputsOriginalV2,
    RootDeleteResourceDraftOriginalV2, RootDeleteResourcePreparationOriginalV2,
    RootDeleteResourcePolicyOriginalV2, RootDeleteErrorV1,
    body::message::RootDeleteMessageReceivingV2};

type Cause = Box<dyn Error>;

#[derive(Clone, Copy)]
enum First { Geometry, Funding, Arm, BeforeClock, Before, Header, Extent,
    Payload, Copy, Association, Signature, Verification, Body, Credentials, After, AfterClock, Reentry }

#[derive(Default)]
pub(crate) struct RootDeleteResourceSignatureOriginalV2 {
    demand: Option<Result<ResourceVector, Cause>>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    clocks: [RetainedKernelPairedClockAttemptV1; 2],
    samples: [Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>; 2],
    times: [Option<Result<(), JournalError>>; 2],
    header: RootDeleteMessageReceivingV2,
    header_result: Option<Result<(), RootDeleteErrorV1>>,
    extent: Option<Result<usize, DeleteRootResourceWireErrorV2>>,
    payload: RootDeleteMessageReceivingV2,
    payload_result: Option<Result<(), RootDeleteErrorV1>>,
    copy: Option<Result<(), std::collections::TryReserveError>>,
    bytes: Vec<u8>,
    purpose: Option<aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3>,
    association: Option<Result<(), Cause>>,
    signature: Option<Result<aos_sandbox_model::model::Signature, aos_sandbox_model::format::CanonicalCborError>>,
    verification: Option<Result<VerifiedBrokerPlan, aos_sandbox_model::BrokerPlanVerificationError>>,
    body: Option<Result<(), Cause>>,
    credentials: Option<Result<(), RootDeleteErrorV1>>,
    first: Option<First>,
    entered: bool,
    complete: bool,
    closed: Option<RootDeleteErrorV1>,
}

impl RootDeleteResourceSignatureOriginalV2 {
    pub(crate) fn receiving_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if !self.entered || self.funding.is_some() || self.first.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.demand.as_ref().and_then(|r| r.as_ref().ok()).copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn receive_once_v2(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream, challenge: &RootDeleteChallengeOriginalsV1,
        policy: &mut RootDeleteResourcePolicyOriginalV2, inputs: &RootDeleteCleanupInputsOriginalV2,
        prepared: &RootDeleteResourcePreparationOriginalV2, draft: &RootDeleteResourceDraftOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        self.receive_inner_v3(flight, original, challenge, policy, inputs, prepared, draft, None)
    }

    pub(super) fn receive_apply_once_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream, challenge: &RootDeleteChallengeOriginalsV1,
        policy: &mut RootDeleteResourcePolicyOriginalV2, inputs: &RootDeleteCleanupInputsOriginalV2,
        prepared: &RootDeleteResourcePreparationOriginalV2, draft: &RootDeleteResourceDraftOriginalV2,
        current: super::RootDeleteResourceContinuationV4<'_>,
    ) -> Result<(), RootDeleteErrorV1> {
        self.receive_inner_v3(flight, original, challenge, policy, inputs, prepared, draft, Some(current))
    }

    fn receive_inner_v3(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream, challenge: &RootDeleteChallengeOriginalsV1,
        policy: &mut RootDeleteResourcePolicyOriginalV2, inputs: &RootDeleteCleanupInputsOriginalV2,
        prepared: &RootDeleteResourcePreparationOriginalV2, draft: &RootDeleteResourceDraftOriginalV2,
        current: Option<super::RootDeleteResourceContinuationV4<'_>>,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.purpose = Some(prepared.purpose_v3()?);
        self.demand = Some((|| {
            let invalid = || JournalError::JournalTooLarge;
            draft.require_completed_v2().map_err(|_| JournalError::ProtectedBoundary)?;
            let preparation = prepared.preparation_data_v2().map_err(|_| JournalError::ProtectedBoundary)?;
            let maximum = DeleteRootResourceSignedDataV2::maximum_encoded_bytes_v2().map_err(|_| invalid())?;
            let artifacts = preparation.preparation_v2().canonical_plan().len()
                .checked_add(maximum).ok_or_else(invalid)?;
            let verification = inputs.broker_trust_v2().map_err(|_| JournalError::ProtectedBoundary)?
                .anchor.verification_receiving_bytes_v1(artifacts).ok_or_else(invalid)?;
            let memory = std::mem::size_of::<Self>().checked_mul(3)
                .and_then(|n| n.checked_add(maximum.checked_mul(3)?))
                .and_then(|n| n.checked_add(verification))
                .and_then(|n| n.checked_add(RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?.checked_mul(2)?))
                .and_then(|n| u64::try_from(n).ok()).ok_or_else(invalid)?;
            // Both actual message owners and all their native failure prefixes
            // coexist. Each uses the same compiled D strict-chunk supplier.
            let messages = RootSubjectChunkReceivingV1::delete_receiving_demand_v1()?
                .checked_add(RootSubjectChunkReceivingV1::delete_receiving_demand_v1()?)?;
            let fixed = messages.checked_add(RootDeleteChunkPostsV1::fixed_demand_v1()?)?;
            Ok(fixed.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory)
                .with(D::NetworkBytes, u64::try_from(maximum).map_err(|_| invalid())?)
                .with(D::OpenFiles, 2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64))?)
        })());
        if !matches!(self.demand, Some(Ok(_))) { self.first = Some(First::Geometry); return Err(RootDeleteErrorV1::Opening); }
        self.funding = Some(match current {
            None => flight.admit_delete_resource_signature_once_v2(draft, self),
            Some(current) => flight.admit_delete_resource_continuation_once_v4(current,
                super::apply_issuer::ApplyStageOwnerV3::Signature(draft, self)),
        });
        if !matches!(self.funding, Some(Ok(()))) { self.first = Some(First::Funding); return Err(RootDeleteErrorV1::Opening); }
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        if !matches!(self.arm, Some(Ok(()))) { self.first = Some(First::Arm); return Err(RootDeleteErrorV1::Opening); }
        self.samples[0] = Some(self.clocks[0].observe_once(None));
        self.times[0] = Some(self.require_time_v2(challenge, policy, inputs, prepared, draft, 0));
        self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
        if !matches!(self.times[0], Some(Ok(()))) { self.first = Some(First::BeforeClock); }
        if !matches!(self.before, Some(Ok(()))) { self.first.get_or_insert(First::Before); }
        self.body = Some((|| {
            if self.first.is_none() {
                self.header_result = Some(self.header.receive_continuation_once_v2(flight, original,
                    challenge, DELETE_ROOT_RESOURCE_SIGNED_HEADER_BYTES_V2));
                if !matches!(self.header_result, Some(Ok(()))) { self.first = Some(First::Header); }
            }
            if self.first.is_none() {
                self.extent = Some(self.header.bytes_v2().map_err(|_| DeleteRootResourceWireErrorV2::Context(
                    aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootWireErrorV2::Association))
                    .and_then(|bytes| DeleteRootResourceSignedDataV2::declared_bytes_for_purpose_v3(bytes, prepared.purpose_v3().map_err(|_| DeleteRootResourceWireErrorV2::Context(
                        aos_sandbox_protocol::domain_ledger::delete_root::transport::DeleteRootWireErrorV2::Association))?)));
                if !matches!(self.extent, Some(Ok(_))) { self.first = Some(First::Extent); }
            }
            if self.first.is_none() {
                let length = positive(&self.extent)?.checked_sub(DELETE_ROOT_RESOURCE_SIGNED_HEADER_BYTES_V2)
                    .ok_or(JournalError::ProtectedBoundary)?;
                self.payload_result = Some(self.payload.receive_continuation_once_v2(flight, original, challenge, length));
                if !matches!(self.payload_result, Some(Ok(()))) { self.first = Some(First::Payload); }
            }
            if self.first.is_none() {
                self.copy = Some(self.bytes.try_reserve_exact(*positive(&self.extent)?));
                if matches!(self.copy, Some(Ok(()))) {
                    self.bytes.extend_from_slice(self.header.bytes_v2()?);
                    self.bytes.extend_from_slice(self.payload.bytes_v2()?);
                } else { self.first = Some(First::Copy); }
            }
            if self.first.is_none() {
                self.association = Some((|| {
                    let signed = DeleteRootResourceSignedDataV2::decode_for_purpose_v3(&self.bytes, self.purpose.ok_or(RootDeleteErrorV1::Original)?)?;
                    signed.require_draft_for_purpose_v3(draft.draft_data_v2(prepared)?, prepared.purpose_v3()?)?;
                    Ok(())
                })());
                if !matches!(self.association, Some(Ok(()))) { self.first = Some(First::Association); }
            }
            if self.first.is_none() {
                let signed = DeleteRootResourceSignedDataV2::decode_for_purpose_v3(&self.bytes, self.purpose.ok_or(RootDeleteErrorV1::Original)?)
                    .map_err(|_| RootDeleteErrorV1::Opening)?;
                self.signature = Some(aos_sandbox_model::format::decode_signature(signed.canonical_signature, DecodeLimits::default()));
                if !matches!(self.signature, Some(Ok(_))) { self.first = Some(First::Signature); }
            }
            if self.first.is_none() {
                self.association = Some((|| {
                    let signature = positive(&self.signature)?;
                    let preparation = prepared.preparation_data_v2()?.preparation_v2();
                    if signature.statement() != preparation.signing_request().statement() {
                        return Err(JournalError::ProtectedBoundary.into());
                    }
                    Ok(())
                })());
                if !matches!(self.association, Some(Ok(()))) { self.first = Some(First::Association); }
            }
            if self.first.is_none() {
                let preparation = prepared.preparation_data_v2()?.preparation_v2();
                let expected = preparation.plan_data_v1();
                self.verification = Some(aos_sandbox_model::verify_broker_plan(preparation.canonical_plan(),
                    positive(&self.signature)?, &inputs.broker_trust_v2()?.anchor,
                    BrokerPlanExpectation { audience: expected.audience(), protocol: expected.protocol(),
                        protocol_version: expected.protocol_version(), assignment: expected.assignment(),
                        node: expected.node(), now_seconds: positive(&self.samples[0])?.wall_seconds() }, DecodeLimits::default()));
                if !matches!(self.verification, Some(Ok(_))) { self.first = Some(First::Verification); }
            }
            Ok(())
        })());
        if !matches!(self.body, Some(Ok(()))) { self.first.get_or_insert(First::Body); }
        // The actual fixed native credentials remain owed through the entire
        // signing comparison, including malformed reply/crypto refusal.
        policy.finish_credentials_if_owed_v2();
        self.credentials = Some(policy.require_credentials_complete_v2());
        if !matches!(self.credentials, Some(Ok(()))) { self.first.get_or_insert(First::Credentials); }
        self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
        if !matches!(self.after, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        self.samples[1] = Some(self.clocks[1].observe_once(None));
        self.times[1] = Some(self.require_time_v2(challenge, policy, inputs, prepared, draft, 1));
        if !matches!(self.times[1], Some(Ok(()))) { self.first.get_or_insert(First::AfterClock); }
        if self.first.is_some() { return Err(RootDeleteErrorV1::Opening); }
        self.complete = true;
        Ok(())
    }

    fn require_time_v2(&self, challenge: &RootDeleteChallengeOriginalsV1,
        policy: &RootDeleteResourcePolicyOriginalV2, inputs: &RootDeleteCleanupInputsOriginalV2,
        prepared: &RootDeleteResourcePreparationOriginalV2, draft: &RootDeleteResourceDraftOriginalV2,
        index: usize,
    ) -> Result<(), JournalError> {
        let invalid = || JournalError::ProtectedBoundary;
        let sample = *positive(&self.samples[index])?;
        let prior = if index == 0 { draft.completed_clock_v2().map_err(|_| invalid())? }
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

    pub(super) fn signed_data_v3(&self) -> Result<DeleteRootResourceSignedDataV2<'_>, RootDeleteErrorV1> {
        self.require_completed_v2()?;
        DeleteRootResourceSignedDataV2::decode_for_purpose_v3(&self.bytes, self.purpose.ok_or(RootDeleteErrorV1::Original)?).map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(super) fn completed_clock_v2(&self) -> Result<RawPairedClockSample, RootDeleteErrorV1> {
        self.require_completed_v2()?;
        positive(&self.samples[1]).copied().map_err(|_| RootDeleteErrorV1::Original)
    }

    pub(crate) fn require_completed_v2(&self) -> Result<(), RootDeleteErrorV1> {
        if self.complete && self.first.is_none() && self.closed.is_none()
            && matches!(self.verification, Some(Ok(_))) && matches!(self.credentials, Some(Ok(()))) { Ok(()) }
        else { Err(RootDeleteErrorV1::Original) }
    }

    pub(super) fn failure_with_policy_v2<'cause>(&'cause self,
        policy: &'cause RootDeleteResourcePolicyOriginalV2,
    ) -> Option<&'cause (dyn Error + 'static)> {
        if matches!(self.first, Some(First::Credentials)) {
            return policy.failure().or_else(|| self.failure());
        }
        self.failure()
    }

    pub(super) fn funding_failed_v2(&self) -> bool {
        matches!(self.first, Some(First::Funding))
            || matches!(self.first, Some(First::Arm | First::Before)) && self.posts.funding_failed_v1()
            || matches!(self.first, Some(First::Header)) && self.header.financial_failure_is_selected_v1()
            || matches!(self.first, Some(First::Payload)) && self.payload.financial_failure_is_selected_v1()
    }

    pub(super) fn property_failure_view_v2(&self) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            First::Header => self.header.property_failure_view_v1(),
            First::Payload => self.payload.property_failure_view_v1(),
            First::Arm | First::Before | First::After => self.posts.property_failure_view_v1(self.failure()?),
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Geometry => self.demand.as_ref().and_then(|r| r.as_ref().err()).map(|e| e.as_ref()), First::Funding => cause(&self.funding),
            First::Arm | First::Before => self.posts.before_failure_v1().or_else(|| cause(&self.arm)).or_else(|| cause(&self.before)),
            First::BeforeClock => self.clocks[0].failure().or_else(|| cause(&self.samples[0])).or_else(|| cause(&self.times[0])),
            First::Header => self.header.failure().or_else(|| cause(&self.header_result)),
            First::Extent => cause(&self.extent),
            First::Payload => self.payload.failure().or_else(|| cause(&self.payload_result)),
            First::Copy => cause(&self.copy),
            First::Association => self.association.as_ref().and_then(|r| r.as_ref().err()).map(|e| e.as_ref()),
            First::Signature => cause(&self.signature), First::Verification => cause(&self.verification),
            First::Body => self.body.as_ref().and_then(|r| r.as_ref().err()).map(|e| e.as_ref()),
            First::Credentials => cause(&self.credentials),
            First::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            First::AfterClock => self.clocks[1].failure().or_else(|| cause(&self.samples[1])).or_else(|| cause(&self.times[1])),
            First::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref().and_then(|r| r.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|e| e as _)
}
