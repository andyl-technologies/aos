//! Serves the finite Stop cleanup protocol on one continuously held Root flight.
//!
//! Opening, chunk IO, native currentness and final financial disposition use
//! the existing engines. The ordinary Controller signer supplies an effect
//! signature; observation has neither a plan nor signature. Both paths require
//! the real second fresh Host3 before the common post-D confirmation can run.

use std::{
    error::Error,
    mem::size_of,
    os::fd::{AsFd as _, OwnedFd},
};

use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1;
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_linux_descriptors::unix_stream::RetainedUnixStreamAdmissionErrorV1;
use aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1;
use aos_sandbox_protocol::domain_ledger::provisioning_root::{
    execution_no_apply::acquisition::{
        decode_acquisition_raw_pair_data_v2, encode_acquisition_raw_pair_data_v2,
    },
    stop_cleanup::*,
};
use aos_sandbox_protocol::root_policy_completion::StopCleanupObservationDataV1;

use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::controller_resource_reservation::RootStopCleanupStageV1;
use crate::journal::JournalError;
use crate::normal_root::NormalRootStartupErrorV1;
use crate::normal_root::RootControllerChunkSubjectSampleV1;
use crate::normal_root::RootPolicyAcceptedFlightV1;
use crate::normal_root::RootStopCleanupStageReceivingV1;
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use crate::policy_compiler::RootCurrentPolicyInputDataV1;
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use aos_sandbox_broker::bounded_stream_io::FixedDeadlineStreamIoV1;
use aos_sandbox_broker::bounded_stream_io::SliceDeadlineStreamIoV1;
use crate::policy_compiler::provisioning_current::RootContinuationClockGateV1;
use crate::policy_compiler::provisioning_current::RootContinuationHorizonDataV1;
use crate::policy_compiler::provisioning_current::create_finality::authorization::RootRecoveryAdmissionReferenceDataV2;
use crate::policy_compiler::root_policy_prelude::RootPolicyPreludeOriginalV1;
use crate::policy_compiler::root_policy_prelude::RootStopCleanupPreludeV1;
use crate::policy_compiler::root_subject_chunk::RootSubjectChunkReceivingV1;

use super::{RootStopCleanupNativeOriginalV1, SelectionData};

mod dispatch;
mod opening;
pub(crate) use dispatch::RootStopCleanupDispatchOriginalV1;
pub(crate) use opening::RootStopCleanupOpeningOriginalV1;

type Cause = Box<dyn Error>;

#[derive(Clone, Copy)]
enum Phase {
    Opening,
    Stream,
    Subject,
    Inputs,
    Reply,
    Decision,
    Final,
    NativePosts,
    Receipt,
    After,
}

/// Holds the genuine Stop purpose until final inventory and whole disposal.
pub struct RootStopCleanupReceivingV1<'flight, 'listener, 'startup> {
    prelude: RootStopCleanupPreludeV1<'flight, 'listener, 'startup>,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<Native>>,
    body: Option<Result<(), Cause>>,
    peer_post: Option<Result<(), NormalRootStartupErrorV1>>,
    peer_settled: Option<Result<(), NormalRootStartupErrorV1>>,
}

struct Native {
    opening: RootStopCleanupOpeningOriginalV1,
    query: [u8; QUERY_BYTES_V1],
    remainder: [u8; QUERY_BYTES_V1 - 32],
    remainder_io: FixedDeadlineStreamIoV1<{ QUERY_BYTES_V1 - 32 }>,
    stream_duplicate: Option<Result<OwnedFd, rustix::io::Errno>>,
    stream: Option<Result<RetainedUnixStream, RetainedUnixStreamAdmissionErrorV1>>,
    geometry: Result<SubjectStreamReceiveGeometryV1, SeqpacketError>,
    buffers: [RetainedSubjectStreamReadV1; 3],
    chunks: [RootSubjectChunkReceivingV1; 3],
    reporting: Option<Result<(), SeqpacketError>>,
    clock: Option<Box<RootContinuationClockGateV1>>,
    issuer: RootStopCleanupNativeOriginalV1,
    replies: [Option<Vec<u8>>; 4],
    senders: [SliceDeadlineStreamIoV1; 4],
    issued: Option<Result<(), JournalError>>,
    compared: Option<Result<(), JournalError>>,
    final_result: Option<Result<(), JournalError>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<
        Result<RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>,
    >,
    after_binding: Option<Result<(), JournalError>>,
    phase: Phase,
    first: Option<Phase>,
    issuer_failed_in_body: bool,
    clock_failed_in_body: bool,
    posts: bool,
}

/// Prices the fixed transport, exact incoming frame reservoirs and chunk peak.
/// Variable signature/reply representation is paid at its real stage before
/// growth; this supplier contains no fabricated maximum allocation invoice.
pub(crate) fn fixed_receiving_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
    let bad = || ResourceReservationErrorV1::Conflict;
    let geometry = RootControllerChunkSubjectSampleV1::receive_geometry_v1().map_err(|_| bad())?;
    let (raw, files) = geometry.receive_obligations_v1();
    let (stream, stream_files) = RetainedUnixStream::retained_admission_obligations_v1();
    let clock =
        RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1().ok_or_else(bad)?;
    let fixed_incoming = SUBJECT_BYTES_V1.checked_add(20 + 208).ok_or_else(bad)?;
    let fixed_outgoing = 80_usize;
    let fixed_scratch = 648_usize + 456 + 48;
    // Each fixed owner has its constructor, caller and resident planes. The
    // same invoice dominates the shared opening's three-plane request before
    // either Native construction or its lazy sampler enters.
    let bytes = size_of::<Native>()
        .checked_mul(3)
        .and_then(|n| n.checked_add(size_of::<RootStopCleanupOpeningOriginalV1>() * 3))
        .and_then(|n| n.checked_add(size_of::<RootStopCleanupReceivingV1<'_, '_, '_>>() * 3))
        .and_then(|n| n.checked_add(size_of::<RootStopCleanupDispatchOriginalV1>() * 3))
        .and_then(|n| n.checked_add(fixed_incoming.checked_add(fixed_outgoing)?.checked_mul(3)?))
        .and_then(|n| n.checked_add(fixed_scratch.checked_mul(3)?))
        .and_then(|n| n.checked_add(raw))
        .and_then(|n| n.checked_add(stream))
        .and_then(|n| n.checked_add(clock))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(bad)?;
    let files = files
        .checked_add(stream_files)
        .and_then(|value| {
            value.checked_add(RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
        })
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(bad)?;
    let wire = fixed_incoming
        .checked_add(fixed_outgoing)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(bad)?;
    let demand = ResourceVector::ZERO
        .with(D::MemoryBytes, bytes)
        .with(D::OpenFiles, files)
        .with(D::NetworkBytes, wire)
        .with(D::OutputBytes, fixed_outgoing as u64);
    demand
        .checked_add(RootContinuationClockGateV1::receiving_demand_v1().map_err(|_| bad())?)?
        .checked_add(
            RootSubjectChunkReceivingV1::stop_cleanup_receiving_demand_v1().map_err(|_| bad())?,
        )
        .map_err(Into::into)
}

impl<'flight, 'listener, 'startup> RootStopCleanupReceivingV1<'flight, 'listener, 'startup> {
    pub(crate) fn from_prelude(
        prelude: RootStopCleanupPreludeV1<'flight, 'listener, 'startup>,
    ) -> Self {
        Self {
            prelude,
            peer: None,
            native: None,
            body: None,
            peer_post: None,
            peer_settled: None,
        }
    }

    /// Runs the selected held exchange and offers its whole graph to Root.
    ///
    /// # Errors
    /// Retains the first native refusal and every independently owed post.
    pub fn serve_once_v1(
        mut self,
        policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let root = &mut self.prelude.original;
        self.peer = Some(root.flight.admit_stop_cleanup_controller_peer_once_v1());
        if matches!(self.peer, Some(Ok(()))) {
            self.native = Some(Box::new(Native::new()));
            let native = self
                .native
                .as_mut()
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.body = Some(native.run(root, policy));
            if matches!(self.body, Some(Err(_))) {
                native.first.get_or_insert(native.phase);
                // Record temporal cause ownership before owed posts can add
                // a later refusal to their separately retained destinations.
                native.issuer_failed_in_body = native.issuer.failure().is_some();
                native.clock_failed_in_body = native
                    .clock
                    .as_ref()
                    .is_some_and(|clock| clock.failure().is_some());
            }
        }
        let _owed = root.native.finish_opening_if_owed_v1();
        if let Some(native) = self.native.as_mut() {
            native.finish_posts(root.flight);
        }
        self.peer_post = Some(
            root.flight
                .finish_stop_cleanup_controller_peer_posts_once_v1(),
        );
        self.finish_offered()
    }
}

impl Native {
    fn new() -> Self {
        Self {
            opening: Default::default(),
            query: [0; QUERY_BYTES_V1],
            remainder: [0; QUERY_BYTES_V1 - 32],
            remainder_io: Default::default(),
            stream_duplicate: None,
            stream: None,
            geometry: RootControllerChunkSubjectSampleV1::receive_geometry_v1(),
            buffers: std::array::from_fn(|_| RetainedSubjectStreamReadV1::new()),
            chunks: std::array::from_fn(|_| Default::default()),
            reporting: None,
            clock: None,
            issuer: RootStopCleanupNativeOriginalV1::new(),
            replies: std::array::from_fn(|_| None),
            senders: std::array::from_fn(|_| Default::default()),
            issued: None,
            compared: None,
            final_result: None,
            after_clock: Default::default(),
            after_sample: None,
            after_binding: None,
            phase: Phase::Opening,
            first: None,
            issuer_failed_in_body: false,
            clock_failed_in_body: false,
            posts: false,
        }
    }

    fn run(
        &mut self,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
        policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Cause> {
        self.opening
            .admit_query(&mut root.flight.stop_cleanup_stage_receiving_v1()?)?;
        self.query[..32].copy_from_slice(root.native.prefix_bytes_v1());
        self.remainder_io.run_once(
            &mut root.original,
            &mut self.remainder,
            root.native.cutoff_v1()?,
            DeadlineStreamDirectionV1::Read,
        )?;
        self.query[32..].copy_from_slice(&self.remainder);
        root.native.finish_opening_if_owed_v1()?;
        self.opening.observe_query(&self.query)?;
        self.clock = Some(Box::new(RootContinuationClockGateV1::new(
            self.opening.horizon()?,
        )));
        self.phase = Phase::Stream;
        self.stream_duplicate = Some(rustix::io::fcntl_dupfd_cloexec(&root.original, 0));
        match self.stream_duplicate.take() {
            Some(Ok(fd)) => self.stream = Some(RetainedUnixStream::from_owned_retaining_v1(fd)),
            reached => {
                self.stream_duplicate = reached;
                return Err(JournalError::ProtectedBoundary.into());
            }
        }
        positive(&self.stream)?.require_same_endpoint_v1(root.original.as_fd())?;
        self.phase = Phase::Subject;
        self.opening
            .admit_subject(&mut root.flight.stop_cleanup_stage_receiving_v1()?)?;
        self.reporting = Some(root.flight.enable_stop_cleanup_subject_reporting_once_v1());
        positive(&self.reporting)?;
        let query = self.opening.query()?;
        self.receive(root, 0, SUBJECT_BYTES_V1)?;
        let subject = StopCleanupSubjectDataV1::decode_v1(self.buffers[0].bytes())?;
        subject.require_query_v1(query)?;
        let selection = SelectionData {
            admission: RootRecoveryAdmissionReferenceDataV2 {
                key: subject.admission_key.try_into()?,
                commitment: subject.admission.try_into()?,
                original: decode_acquisition_raw_pair_data_v2(subject.recover_original)?,
                cutoff: u64::from_be_bytes(subject.recover_cutoff.try_into()?),
                wall_expiry: i64::from_be_bytes(subject.recover_wall_expiry.try_into()?),
            },
            cleanup: subject.cleanup.try_into()?,
            first: decode_acquisition_raw_pair_data_v2(subject.controller_first)?,
            cutoff: u64::from_be_bytes(subject.cleanup_cutoff.try_into()?),
            source_parent: subject.source_parent.try_into()?,
            host_query: subject.host_query.try_into()?,
            host_session: subject.host_session.try_into()?,
            host_request: subject.host_request.try_into()?,
            host_outcome: subject.host_outcome.try_into()?,
            host_body: subject.host_body.try_into()?,
            query_digest: query.digest_v1()?,
        };
        self.phase = Phase::Inputs;
        self.issued = Some(root.flight.observe_stop_cleanup_inputs_once_v1(
            &mut self.issuer,
            positive(&self.stream)?,
            policy,
            self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?,
            selection,
        ));
        positive(&self.issued)?;
        self.opening.tighten(&self.issuer)?;
        self.clock
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .narrow_wall_expiry_data_v1(self.issuer.policy_expiry_v1()?);
        self.send_decision(root)?;
        self.receive_child_decision(root)?;
        self.phase = Phase::Final;
        self.receive(root, 2, 208)?;
        let final_frame = StopCleanupFinalDataV1::decode_v1(self.buffers[2].bytes())?;
        if final_frame.query_digest != query.digest_v1()? {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.final_result = Some(root.flight.observe_stop_cleanup_final_once_v1(
            &mut self.issuer,
            positive(&self.stream)?,
            self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?,
            (
                final_frame.host_query.try_into()?,
                final_frame.host_session.try_into()?,
                final_frame.host_request.try_into()?,
                final_frame.host_outcome.try_into()?,
                final_frame.host_body.try_into()?,
            ),
        ));
        positive(&self.final_result)?;
        self.send_receipt(root)?;
        Ok(())
    }

    fn receive(
        &mut self,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
        index: usize,
        bytes: usize,
    ) -> Result<(), Cause> {
        if self.buffers[index].bytes().is_empty() {
            self.buffers[index].prepare_exact_once(bytes)?;
        } else {
            self.buffers[index].extend_completed_exact_once(bytes)?;
        }
        self.chunks[index].receive_stop_cleanup_exact_v1(
            root.flight,
            &root.original,
            &mut self.buffers[index],
            self.geometry
                .as_ref()
                .map_err(|_| JournalError::ProtectedBoundary)?,
            &self.opening,
        )?;
        Ok(())
    }

    fn send_decision(
        &mut self,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
    ) -> Result<(), Cause> {
        self.phase = Phase::Reply;
        let query = self.opening.query()?.digest_v1()?;
        let sample = encode_acquisition_raw_pair_data_v2(self.issuer.plan_sample_v1()?);
        let expiry = self.issuer.policy_expiry_v1()?.to_be_bytes();
        let cutoff = self.opening.current_cutoff_v1()?.to_be_bytes();
        let mut observation = [0_u8; 648];
        let kind;
        let decision_bytes = match self.issuer.unsigned_plan_v1()? {
            Some(plan) => {
                let subject = self
                    .issuer
                    .issued_subject_v1()?
                    .ok_or(JournalError::ProtectedBoundary)?
                    .encode_v1();
                let frame = StopCleanupEffectDataV1 {
                    query_digest: &query,
                    subject: &subject,
                    request_body: &plan.request_body,
                    canonical_plan: plan.preparation.canonical_plan(),
                    canonical_statement: plan.preparation.signing_request().canonical_statement(),
                    root_sample: &sample,
                    policy_expiry: &expiry,
                    cutoff: &cutoff,
                };
                let length = frame.encoded_bytes_v1()?;
                let complete = length
                    .checked_mul(3)
                    .and_then(|value| value.checked_add(48 + length))
                    .ok_or(JournalError::JournalTooLarge)?;
                root.flight
                    .stop_cleanup_stage_receiving_v1()?
                    .admit_stop_cleanup_once_v1(
                        RootStopCleanupStageV1::UnsignedReply,
                        RootContinuationDemandV1::from_demand_v1(
                            ResourceVector::ZERO
                                .with(D::MemoryBytes, u64::try_from(complete)?)
                                .with(D::NetworkBytes, u64::try_from(48 + length)?)
                                .with(D::OutputBytes, u64::try_from(48 + length)?),
                        ),
                    )?;
                self.replies[0] = Some(vec![0; length]);
                frame.encode_range_v1(
                    0,
                    self.replies[0]
                        .as_mut()
                        .ok_or(JournalError::ProtectedBoundary)?,
                )?;
                length
            }
            None => {
                let width = match self
                    .issuer
                    .observed_decision_v1()?
                    .ok_or(JournalError::ProtectedBoundary)?
                {
                    StopCleanupObservationDataV1::Historical(row) => {
                        kind = [1_u8];
                        let bytes = row.encode_v7();
                        observation[..bytes.len()].copy_from_slice(&bytes);
                        bytes.len()
                    }
                    StopCleanupObservationDataV1::Cleanup(row) => {
                        kind = [2_u8];
                        observation.copy_from_slice(&row.encode_v1());
                        observation.len()
                    }
                };
                let frame = StopCleanupObservedDataV1 {
                    query_digest: &query,
                    observation_kind: &kind,
                    observation: &observation[..width],
                    root_sample: &sample,
                    policy_expiry: &expiry,
                    cutoff: &cutoff,
                };
                let length = frame.encoded_bytes_v1()?;
                let complete = length
                    .checked_mul(3)
                    .and_then(|value| value.checked_add(48 + length))
                    .ok_or(JournalError::JournalTooLarge)?;
                root.flight
                    .stop_cleanup_stage_receiving_v1()?
                    .admit_stop_cleanup_once_v1(
                        RootStopCleanupStageV1::UnsignedReply,
                        RootContinuationDemandV1::from_demand_v1(
                            ResourceVector::ZERO
                                .with(D::MemoryBytes, u64::try_from(complete)?)
                                .with(D::NetworkBytes, u64::try_from(48 + length)?)
                                .with(D::OutputBytes, u64::try_from(48 + length)?),
                        ),
                    )?;
                self.replies[0] = Some(vec![0; length]);
                frame.encode_range_v1(
                    0,
                    self.replies[0]
                        .as_mut()
                        .ok_or(JournalError::ProtectedBoundary)?,
                )?;
                length
            }
        };
        {
            // The decision and its outer reply remain in distinct original slots.
            let (decision, replies) = self.replies.split_at_mut(1);
            let inner = decision[0]
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?;
            let frame = StopCleanupReplyDataV1 {
                query_digest: &query,
                decision_frame: inner,
            };
            let length = frame.encoded_bytes_v1()?;
            if length != decision_bytes + 48 {
                return Err(JournalError::ProtectedBoundary.into());
            }
            replies[0] = Some(vec![0; length]);
            frame.encode_range_v1(
                0,
                replies[0]
                    .as_mut()
                    .ok_or(JournalError::ProtectedBoundary)?,
            )?;
        }
        self.check_clock()?;
        self.senders[1].run_once(
            &mut root.original,
            self.replies[1]
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?,
            self.opening.current_cutoff_v1()?,
            DeadlineStreamDirectionV1::Write,
        )?;
        Ok(())
    }

    fn receive_child_decision(
        &mut self,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
    ) -> Result<(), Cause> {
        self.phase = Phase::Decision;
        let effect = self.issuer.unsigned_plan_v1()?.is_some();
        self.receive(root, 1, if effect { 20 } else { 16 })?;
        let (total, signature) = if effect {
            let bytes = StopCleanupSignatureDataV1::declared_bytes_v1(self.buffers[1].bytes())?;
            let signature =
                u32::from_be_bytes(self.buffers[1].bytes()[16..20].try_into()?) as usize;
            (bytes, signature)
        } else {
            (
                StopCleanupObservedDecisionDataV1::declared_bytes_v1(self.buffers[1].bytes())?,
                0,
            )
        };
        self.issuer.admit_child_decision_receiving_once_v1(
            &mut root.flight.stop_cleanup_stage_receiving_v1()?,
            total,
            signature,
        )?;
        self.receive(root, 1, total)?;
        let query = self.opening.query()?.digest_v1()?;
        let decision = self.issuer.decision_digest_v1()?;
        let signature = if effect {
            let frame = StopCleanupSignatureDataV1::decode_v1(self.buffers[1].bytes())?;
            if frame.query_digest != query || frame.decision_digest != decision {
                return Err(JournalError::ProtectedBoundary.into());
            }
            Some(frame.canonical_signature)
        } else {
            let frame = StopCleanupObservedDecisionDataV1::decode_v1(self.buffers[1].bytes())?;
            if frame.query_digest != query || frame.decision_digest != decision {
                return Err(JournalError::ProtectedBoundary.into());
            }
            None
        };
        self.compared = Some(self.issuer.observe_signature_once_v1(
            &mut root.flight.stop_cleanup_stage_receiving_v1()?,
            self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?,
            signature,
        ));
        positive(&self.compared)?;
        // A comparison acknowledgement lets the SAME client exchange lend its
        // actual live owner to Host1; it is neither RootDpositive nor a grant DTO.
        let frame = StopCleanupObservedDecisionDataV1 {
            query_digest: &query,
            decision_digest: &decision,
        };
        self.replies[2] = Some(vec![0; frame.encoded_bytes_v1()?]);
        frame.encode_range_v1(
            0,
            self.replies[2]
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?,
        )?;
        self.check_clock()?;
        self.senders[2].run_once(
            &mut root.original,
            self.replies[2]
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?,
            self.opening.current_cutoff_v1()?,
            DeadlineStreamDirectionV1::Write,
        )?;
        Ok(())
    }

    fn send_receipt(
        &mut self,
        root: &mut RootPolicyPreludeOriginalV1<'_, '_, '_>,
    ) -> Result<(), Cause> {
        self.phase = Phase::Receipt;
        let (query, decision, terminal, _) = self.issuer.completion_data_v1()?;
        let cutoff = self.opening.current_cutoff_v1()?.to_be_bytes();
        root.flight
            .stop_cleanup_stage_receiving_v1()?
            .admit_stop_cleanup_once_v1(
                RootStopCleanupStageV1::Receipt,
                RootContinuationDemandV1::from_demand_v1(
                    ResourceVector::ZERO
                        .with(D::MemoryBytes, (3 * RECEIPT_BYTES_V1) as u64)
                        .with(D::NetworkBytes, RECEIPT_BYTES_V1 as u64)
                        .with(D::OutputBytes, RECEIPT_BYTES_V1 as u64),
                ),
            )?;
        let frame = StopCleanupReceiptDataV1 {
            query_digest: &query,
            decision_digest: &decision,
            terminal_host_outcome: &terminal,
            cutoff: &cutoff,
        };
        self.replies[3] = Some(vec![0; frame.encoded_bytes_v1()?]);
        frame.encode_range_v1(
            0,
            self.replies[3]
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?,
        )?;
        self.check_clock()?;
        self.senders[3].run_once(
            &mut root.original,
            self.replies[3]
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?,
            self.opening.current_cutoff_v1()?,
            DeadlineStreamDirectionV1::Write,
        )?;
        Ok(())
    }

    fn check_clock(&mut self) -> Result<(), JournalError> {
        let sample = self
            .clock
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .check_next_once_v1()?;
        self.opening.require_current_clock_v1(sample)
    }

    fn finish_posts(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>) {
        if self.posts {
            return;
        }
        self.posts = true;
        if let (Some(Ok(stream)), Some(clock)) = (&self.stream, &self.clock) {
            flight.finish_stop_cleanup_native_posts_once_v1(&mut self.issuer, stream, clock);
        }
        self.after_sample = Some(self.after_clock.observe_once(None));
        self.after_binding = Some((|| {
            let sample = *positive(&self.after_sample)?;
            self.opening.require_current_clock_v1(sample)?;
            self.clock
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?
                .require_final_sample_v1(sample)
        })());
    }

    fn require_complete(&self) -> Result<(), JournalError> {
        if !self.posts
            || self.first.is_some()
            || self.failure().is_some()
            || !matches!(self.issued, Some(Ok(())))
            || !matches!(self.compared, Some(Ok(())))
            || !matches!(self.final_result, Some(Ok(())))
            || !matches!(self.after_binding, Some(Ok(())))
            || !self.senders[3].completed_exact()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.issuer.require_complete_v1()
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.failure_before().or_else(|| self.failure_after())
    }

    fn failure_before(&self) -> Option<&(dyn Error + 'static)> {
        let clock = || {
            self.clock_failed_in_body
                .then(|| self.clock.as_ref().and_then(|clock| clock.failure()))
                .flatten()
        };
        let issuer = || {
            self.issuer_failed_in_body
                .then(|| self.issuer.failure())
                .flatten()
        };
        let selected = match self.first {
            Some(Phase::Opening) => self
                .opening
                .failure()
                .or_else(|| self.remainder_io.failure()),
            Some(Phase::Stream) => error(&self.stream_duplicate).or_else(|| error(&self.stream)),
            Some(Phase::Subject) => self.chunks[0].failure(),
            Some(Phase::Inputs | Phase::NativePosts) => {
                if self
                    .clock
                    .as_ref()
                    .is_some_and(|gate| self.issuer.external_clock_is_first_v1(gate))
                {
                    clock()
                } else {
                    issuer()
                }
            }
            Some(Phase::Final) => self.chunks[2].failure().or_else(|| {
                if self
                    .clock
                    .as_ref()
                    .is_some_and(|gate| self.issuer.external_clock_is_first_v1(gate))
                {
                    clock()
                } else {
                    issuer()
                }
            }),
            Some(Phase::Reply) => self.senders[1].failure(),
            Some(Phase::Decision) => self.chunks[1]
                .failure()
                .or_else(issuer)
                .or_else(|| self.senders[2].failure()),
            Some(Phase::Receipt) => self.senders[3].failure(),
            Some(Phase::After) | None => None,
        };
        selected.or_else(clock)
    }

    fn failure_after(&self) -> Option<&(dyn Error + 'static)> {
        self.issuer
            .failure()
            .or_else(|| self.clock.as_ref().and_then(|clock| clock.failure()))
            .or_else(|| self.after_clock.failure())
            .or_else(|| error(&self.after_binding))
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

fn error<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
