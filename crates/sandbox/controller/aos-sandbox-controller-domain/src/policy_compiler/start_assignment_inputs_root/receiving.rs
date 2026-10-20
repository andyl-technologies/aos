//! Retains current signed-input reads through the actual independent Root posts.
//!
//! This purpose owns no lease, resource plan or signing operation. The same R
//! stage prepays every reached native/decoder destination before construction;
//! only an exact reply, hostile EOF and all native posts permit disposition.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::unix_stream::{
    RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1, SubjectStreamReceiveGeometryV1,
};
use aos_sandbox_protocol::domain_ledger::provisioning_root::start_assignment_inputs::{
    StartAssignmentInputsAdmissionDataV2 as Admission,
    StartAssignmentInputsReplyDataV2 as Reply,
    StartAssignmentInputsSubjectDataV2 as Subject,
    QUERY_BYTES_V2,
};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::{
    RootCurrentPolicyInputDataV1,
    bounded_stream_io::{DeadlineStreamDirectionV1 as Direction, FixedDeadlineStreamIoV1,
        SliceDeadlineStreamIoV1},
    continuation_policy::{RootContinuationPolicyErrorV1, RootStartAssignmentInputsPolicyOriginalV2},
    provisioning_current::{RootContinuationClockGateV1 as Clock,
        finality_readonly::RootCreateFinalityReadonlyOriginalV1 as Readonly},
    root_policy_prelude::RootPolicyPreludeOriginalV1,
    root_subject_chunk::RootSubjectChunkReceivingV1,
};
use super::{models::RootStartAssignmentInputsModelsOriginalV2 as Models,
    opening::RootStartAssignmentInputsOpeningOriginalV2 as Opening};

type Cause = Box<dyn Error>;

#[derive(Clone, Copy)]
enum First {
    Opening,
    Chunk,
    Policy,
    Readonly,
    Models,
    Clock,
    Financial,
    Body,
}

#[derive(Clone, Copy)]
enum PostFirst {
    Readonly,
    Policy,
    Peer,
    Clock,
    Relation,
}

pub(super) struct RootStartAssignmentInputsNativeOriginalV2 {
    first: Option<First>,
    post_first: Option<PostFirst>,
    bytes: [u8; QUERY_BYTES_V2],
    remainder: [u8; QUERY_BYTES_V2 - 32],
    remainder_io: FixedDeadlineStreamIoV1<{ QUERY_BYTES_V2 - 32 }>,
    subject: RetainedSubjectStreamReadV1,
    geometry: Result<SubjectStreamReceiveGeometryV1, SeqpacketError>,
    subject_prepared: Option<Result<(), SubjectStreamReadErrorV1>>,
    reporting: Option<Result<(), SeqpacketError>>,
    chunks: RootSubjectChunkReceivingV1,
    eof: [u8; 1],
    eof_io: FixedDeadlineStreamIoV1<1>,
    clock: Option<Box<Clock>>,
    after_clock: Option<Box<Clock>>,
    after_sample: Option<Result<RawPairedClockSample, JournalError>>,
    policy_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    policy: RootStartAssignmentInputsPolicyOriginalV2,
    policy_begin: Option<Result<(), RootContinuationPolicyErrorV1>>,
    policy_verified: Option<Result<(), RootContinuationPolicyErrorV1>>,
    policy_after: Option<Result<(), RootContinuationPolicyErrorV1>>,
    readonly: Readonly,
    models: Models,
    body: Option<Result<(), Cause>>,
    posts: Option<Result<(), Cause>>,
    response_funding: Option<Result<(), NormalRootStartupErrorV1>>,
    reply: Option<Result<Vec<u8>, Cause>>,
    sent: SliceDeadlineStreamIoV1,
    send: Option<Result<(), Cause>>,
    peer_after: Option<Result<(), NormalRootStartupErrorV1>>,
    peer_disposal: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl RootStartAssignmentInputsNativeOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            first: None,
            post_first: None,
            bytes: [0; QUERY_BYTES_V2],
            remainder: [0; QUERY_BYTES_V2 - 32],
            remainder_io: Default::default(),
            subject: Default::default(),
            geometry: crate::normal_root::RootControllerChunkSubjectSampleV1::receive_geometry_v1(),
            subject_prepared: None,
            reporting: None,
            chunks: Default::default(),
            eof: [0; 1],
            eof_io: Default::default(),
            clock: None,
            after_clock: None,
            after_sample: None,
            policy_funding: None,
            policy: Default::default(),
            policy_begin: None,
            policy_verified: None,
            policy_after: None,
            readonly: Readonly::new(),
            models: Models::new(),
            body: None,
            posts: None,
            response_funding: None,
            reply: None,
            sent: Default::default(),
            send: None,
            peer_after: None,
            peer_disposal: None,
        }
    }

    pub(super) fn fixed_receiving_demand_v2() -> Result<ResourceVector, JournalError> {
        Clock::receiving_demand_v1()?.checked_add(ResourceVector::ZERO.with(D::NetworkBytes, 1))
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(super) fn run_once_v2(&mut self, opening: &mut Opening,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
        inputs: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), JournalError> {
        self.body = Some(self.receive_inner_v2(opening, root, inputs));
        if matches!(self.body, Some(Err(_))) {
            self.first = Some(if opening.failure().is_some() { First::Opening }
                else if self.chunks.failure_with_buffer(&self.subject).is_some() { First::Chunk }
                else if self.funding_failed_v2() && root.flight.failure().is_some() { First::Financial }
                else if self.policy.failure().is_some() { First::Policy }
                else if self.readonly.failure().is_some() { First::Readonly }
                else if self.models.failure().is_some() { First::Models }
                else if self.clock.as_ref().and_then(|clock| clock.failure()).is_some() { First::Clock }
                else { First::Body });
        }
        self.finish_posts_once_v2(opening, root.flight);
        self.require_models_complete_v2()?;
        self.send = Some(self.send_reply_once_v2(opening, root));
        if !matches!(self.send, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.peer_disposal = Some(root.flight.settle_start_assignment_inputs_controller_peer_positive_once_v2());
        self.require_disposed_complete_v2()
    }

    fn receive_inner_v2(&mut self, opening: &mut Opening,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
        inputs: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Cause> {
        self.bytes[..32].copy_from_slice(root.native.prefix_bytes_v1());
        self.remainder_io.run_once(&mut root.original, &mut self.remainder,
            root.native.cutoff_v1()?, Direction::Read)?;
        self.bytes[32..].copy_from_slice(&self.remainder);
        root.native.finish_opening_if_owed_v1()?;
        opening.observe_query_once_v1(&self.bytes)?;
        self.clock = Some(Box::new(Clock::new(opening.horizon_v1()?)));
        self.after_clock = Some(Box::new(Clock::new(opening.horizon_v1()?)));
        {
            let mut stage = root.flight.start_assignment_inputs_stage_receiving_v2()?;
            opening.admit_subject_once_v1(&mut stage, size_of::<Self>())?;
        }
        self.reporting = Some(root.flight.enable_start_assignment_inputs_subject_reporting_once_v2());
        if !matches!(self.reporting, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
        let query = opening.query_v1()?;
        self.subject_prepared = Some(self.subject.prepare_exact_once(
            usize::try_from(query.subject_bytes).map_err(|_| JournalError::JournalTooLarge)?,
        ));
        if !matches!(self.subject_prepared, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
        self.chunks.receive_start_assignment_inputs_exact_v2(root.flight, &root.original,
            &mut self.subject, self.geometry.as_ref().map_err(|_| JournalError::ProtectedBoundary)?, opening)?;
        let subject = Subject::decode_v2(self.subject.bytes())?;
        if subject.digest_v2()? != query.subject_digest { return Err(JournalError::ProtectedBoundary.into()); }
        self.eof_io.run_once(&mut root.original, &mut self.eof,
            opening.current_cutoff_v1()?, Direction::Eof)?;

        let required = root.flight.start_assignment_inputs_policy_receiving_demand_v2()?;
        self.policy_funding = Some(root.flight.start_assignment_inputs_stage_receiving_v2()?
            .admit_start_assignment_inputs_policy_fixed_once_v2(RootContinuationDemandV1::from_demand_v1(required)));
        if !matches!(self.policy_funding, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
        self.policy_begin = Some(root.flight.begin_start_assignment_inputs_policy_once_v2(&mut self.policy));
        if !matches!(self.policy_begin, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
        let sample = self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.check_next_once_v1()?;
        opening.require_current_clock_v1(sample)?;
        self.policy_verified = Some(root.flight.verify_start_assignment_inputs_policy_sources_once_v2(
            &mut self.policy, inputs, sample,
        ));
        if !matches!(self.policy_verified, Some(Ok(()))) { return Err(JournalError::ProtectedBoundary.into()); }
        root.flight.start_assignment_inputs_stage_receiving_v2()?
            .admit_start_assignment_inputs_policy_typed_once_v2(RootContinuationDemandV1::from_demand_v1(ResourceVector::ZERO))?;

        self.readonly.observe_start_inputs_once_v2(
            &mut root.flight.start_assignment_inputs_stage_receiving_v2()?,
            self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?,
        )?;
        let sample = self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.check_next_once_v1()?;
        opening.require_current_clock_v1(sample)?;
        self.models.observe_once_v2(&mut root.flight.start_assignment_inputs_stage_receiving_v2()?,
            &mut self.readonly, &self.policy, query, subject, sample)?;
        opening.tighten_start_inputs_once_v2(self.models.current_v2()?, &self.policy)?;
        let horizon = opening.horizon_v1()?;
        self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.narrow_horizon_data_v1(horizon)?;
        self.after_clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.narrow_horizon_data_v1(horizon)?;
        self.prepare_reply_once_v2(opening, root, inputs)?;
        Ok(())
    }
}

impl RootStartAssignmentInputsNativeOriginalV2 {
    pub(super) fn finish_posts_once_v2(&mut self, opening: &Opening,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
    ) {
        if self.posts.is_some() { return; }
        self.readonly.finish_posts_once_v1();
        self.policy_after = Some(flight.finish_start_assignment_inputs_policy_once_v2(&mut self.policy));
        self.peer_after = Some(flight.finish_start_assignment_inputs_controller_peer_posts_once_v2());
        if let Some(clock) = self.after_clock.as_mut() {
            self.after_sample = Some(clock.check_next_once_v1());
        }
        self.posts = Some((|| {
            if self.readonly.require_complete_v1().is_err() {
                self.post_first.get_or_insert(PostFirst::Readonly);
                return Err(JournalError::ProtectedBoundary.into());
            }
            if !matches!(self.policy_after, Some(Ok(()))) || self.policy.require_complete_v1().is_err() {
                self.post_first.get_or_insert(PostFirst::Policy);
                return Err(JournalError::ProtectedBoundary.into());
            }
            if !matches!(self.peer_after, Some(Ok(()))) {
                self.post_first.get_or_insert(PostFirst::Peer);
                return Err(JournalError::ProtectedBoundary.into());
            }
            let sample = match self.after_sample.as_ref().and_then(|value| value.as_ref().ok()) {
                Some(sample) => *sample,
                None => {
                    self.post_first.get_or_insert(PostFirst::Clock);
                    return Err(JournalError::ProtectedBoundary.into());
                }
            };
            if let Err(cause) = opening.require_current_clock_v1(sample) {
                self.post_first.get_or_insert(PostFirst::Relation);
                return Err(cause.into());
            }
            Ok(())
        })());
    }

    fn prepare_reply_once_v2(&mut self, opening: &Opening,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
        inputs: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Cause> {
        let query = opening.query_v1()?;
        let current = self.models.current_v2()?;
        let sample = self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?.check_next_once_v1()?;
        opening.require_current_clock_v1(sample)?;
        let signed = self.policy.verified_v1().ok_or(JournalError::ProtectedBoundary)?;
        let accepted_expires = current.native_origin_data_v2().accepted_v1()
            .original_wall_expiry_v1().ok_or(JournalError::ProtectedBoundary)?;
        let policy_expires = signed.0.head().expires_at().min(signed.1.expires_at())
            .min(current.publisher_v2().expires);
        let admission = Admission {
            root_nonce: opening.root_nonce_v1()?,
            controller_nonce: query.controller_nonce,
            query_digest: query.digest_v2()?,
            original_boot: query.original_boot,
            original_boottime_ns: query.original_boottime_ns,
            original_cutoff_ns: query.original_cutoff_ns,
            observed_wall_seconds: sample.wall_seconds(),
            observed_boottime_ns: sample.boottime_nanoseconds(),
            cutoff_ns: opening.current_cutoff_v1()?,
            policy_expires_seconds: policy_expires,
            accepted_expires_seconds: accepted_expires,
        }.encode_v2()?;
        let (deployment, project) = inputs.raw_signed_input_envelopes_v2()
            .ok_or(JournalError::ProtectedBoundary)?;
        let deployment_bytes = deployment.encoded_bytes_v2()?;
        let project_bytes = project.encoded_bytes_v2()?;
        let reply_bytes = 20_usize.checked_add(admission.len())
            .and_then(|bytes| bytes.checked_add(deployment_bytes))
            .and_then(|bytes| bytes.checked_add(project_bytes)).ok_or(JournalError::JournalTooLarge)?;
        let memory = deployment_bytes.checked_add(project_bytes)
            .and_then(|bytes| bytes.checked_add(reply_bytes)).and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let wire = u64::try_from(reply_bytes).map_err(|_| JournalError::JournalTooLarge)?;
        self.response_funding = Some(root.flight.start_assignment_inputs_stage_receiving_v2()?
            .admit_start_assignment_inputs_response_once_v2(RootContinuationDemandV1::from_demand_v1(
                ResourceVector::ZERO.with(D::MemoryBytes, memory)
                    .with(D::NetworkBytes, wire).with(D::OutputBytes, wire),
            )));
        if !matches!(self.response_funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.reply = Some((|| {
            let mut deployment_encoded = Vec::new();
            deployment_encoded.try_reserve_exact(deployment_bytes)?;
            deployment_encoded.resize(deployment_bytes, 0);
            deployment.encode_range_v2(0, &mut deployment_encoded)?;
            let mut project_encoded = Vec::new();
            project_encoded.try_reserve_exact(project_bytes)?;
            project_encoded.resize(project_bytes, 0);
            project.encode_range_v2(0, &mut project_encoded)?;
            let reply = Reply { admission: &admission, deployment: &deployment_encoded, project: &project_encoded };
            if reply.encoded_bytes_v2()? != reply_bytes {
                return Err(JournalError::ProtectedBoundary.into());
            }
            let mut encoded = Vec::new();
            encoded.try_reserve_exact(reply_bytes)?;
            encoded.resize(reply_bytes, 0);
            reply.encode_range_v2(0, &mut encoded)?;
            Ok(encoded)
        })());
        if matches!(self.reply, Some(Ok(_))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary.into()) }
    }

    fn send_reply_once_v2(&mut self, opening: &Opening,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
    ) -> Result<(), Cause> {
        let reply = self.reply.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        self.sent.run_once(&mut root.original, reply,
            opening.current_cutoff_v1()?, Direction::Write)?;
        Ok(())
    }

    fn require_models_complete_v2(&self) -> Result<(), JournalError> {
        if self.first.is_some() || !matches!(self.body, Some(Ok(())))
            || !matches!(self.posts, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(super) fn require_disposed_complete_v2(&self) -> Result<(), JournalError> {
        self.require_models_complete_v2()?;
        if !matches!(self.send, Some(Ok(()))) || !matches!(self.peer_disposal, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn funding_failed_v2(&self) -> bool {
        matches!(self.policy_funding, Some(Err(_))) || matches!(self.response_funding, Some(Err(_)))
            || self.readonly.selected_funding_failed_v1() || self.models.funding_failed_v2()
    }

    pub(super) fn failure<'held>(&'held self, opening: &'held Opening,
        financial: Option<&'held (dyn Error + 'static)>,
    ) -> Option<&'held (dyn Error + 'static)> {
        if let Some(first) = self.first {
            return match first {
                First::Opening => opening.failure(),
                First::Chunk => self.chunks.failure_with_buffer(&self.subject),
                First::Policy => self.policy.failure(),
                First::Readonly => self.readonly.failure(),
                First::Models => self.models.failure(),
                First::Clock => self.clock.as_ref().and_then(|clock| clock.failure()),
                First::Financial => financial,
                First::Body => self.remainder_io.failure()
                    .or_else(|| cause(&self.reporting))
                    .or_else(|| cause(&self.subject_prepared))
                    .or_else(|| self.geometry.as_ref().err().map(|cause| cause as _))
                    .or_else(|| self.eof_io.failure())
                    .or_else(|| self.subject.failure())
                    .or_else(|| boxed(&self.reply))
                    .or_else(|| boxed(&self.body)),
            };
        }
        match self.post_first {
            Some(PostFirst::Readonly) => self.readonly.failure(),
            Some(PostFirst::Policy) => self.policy.failure(),
            Some(PostFirst::Peer) => cause(&self.peer_after),
            Some(PostFirst::Clock) => self.after_clock.as_ref().and_then(|clock| clock.failure()),
            Some(PostFirst::Relation) => boxed(&self.posts),
            None => boxed(&self.reply).or_else(|| self.sent.failure())
                .or_else(|| boxed(&self.send)).or_else(|| cause(&self.peer_disposal)),
        }
    }
}

fn cause<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn boxed<T>(result: &Option<Result<T, Cause>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause.as_ref())
}
