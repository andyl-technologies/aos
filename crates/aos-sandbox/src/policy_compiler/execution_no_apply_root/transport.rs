//! Serves the finite actual Execution floor-to-ACK programme on the held Root pair.
//!
//! The Root purpose keeps its native stream, Source/R financial owner, policy
//! writers and independent C/Host/Source readers through the floor, final ACK,
//! Root6 succession and the shared post-disposal confirmation. Incoming DATA
//! never constructs a current lease, Controller barrier or positive owner.

use super::{
    RootExecutionNoApplyAckOriginalV2, RootExecutionNoApplyFloorOriginalV2,
    RootExecutionNoApplyHostLeaseOriginalV2, RootExecutionNoApplyHostTrustOriginalV2,
    RootExecutionNoApplyModelsOriginalV2,
};
use crate::{
    controller_resource_reservation::{ResourceReservationErrorV1, RootContinuationDemandV1},
    journal::JournalError,
    normal_root::{
        NormalRootStartupErrorV1, RootControllerChunkSubjectSampleV1, RootPolicyAcceptedFlightV1,
    },
    policy_compiler::{
        RootCurrentPolicyInputDataV1,
        bounded_stream_io::{
            DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1, SliceDeadlineStreamIoV1,
        },
        continuation_policy::RootExecutionNoApplyPolicyOriginalV2,
        provisioning_current::{
            RootContinuationClockGateV1, RootContinuationHorizonDataV1,
            finality_readonly::RootCreateFinalityReadonlyOriginalV1,
        },
        root_policy_prelude::RootExecutionNoApplyPreludeV2,
        root_subject_chunk::RootSubjectChunkReceivingV1,
    },
};
use aos_sandbox_core::{
    ObjectDigest, RawPairedClockSample, ResourceDimension as D, ResourceVector,
};
use aos_sandbox_linux::{
    seqpacket::SeqpacketError,
    unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReceiveGeometryV1},
};
use aos_sandbox_protocol::{
    domain_ledger::{
        create_storage_history::HistoryErrorV1, provisioning_root::execution_no_apply::*,
    },
    host_execution_no_apply::{
        HostExecutionNoApplyRecordV2,
        closed_controller::{
            CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2, CONTROLLER_CREATE_FAILURE_ACK_BYTES_V2,
        },
        current_lease::{
            CurrentHostNoApplyLeaseDataV2, HostNoApplyLeaseScopeV2,
            MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2,
        },
        root_attestation::MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2,
    },
};
use std::os::fd::{AsFd as _, OwnedFd};
use std::{error::Error, mem::size_of};

mod acquisition;
mod dispatch;
use opening::ExchangeQueryV2;
mod opening;
pub(crate) use dispatch::RootExecutionNoApplyDispatchOriginalV2;
pub(crate) use opening::RootExecutionNoApplyOpeningOriginalV2;

type Cause = Box<dyn Error>;

#[derive(Clone, Copy)]
enum Phase {
    Opening,
    Acquisition,
    AcquisitionReply,
    Preliminary,
    Stream,
    Subject,
    Policy,
    Trust,
    NonceSend,
    Current,
    Readonly,
    Models,
    Host,
    Floor,
    FloorSend,
    AckReceive,
    FinalReadonly,
    AckNative,
    FinalBinding,
}

/// Holds one finite Execution purpose selected by its original native prelude.
pub struct RootExecutionNoApplyReceivingV2<'flight, 'listener, 'startup> {
    prelude: RootExecutionNoApplyPreludeV2<'flight, 'listener, 'startup>,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<Native>>,
    body: Option<Result<(), Cause>>,
    peer_post: Option<Result<(), NormalRootStartupErrorV1>>,
    peer_settled: Option<Result<(), NormalRootStartupErrorV1>>,
}

struct Native {
    phase: Phase,
    first: Option<Phase>,
    opening: RootExecutionNoApplyOpeningOriginalV2,
    query: [u8; QUERY_BYTES_V2],
    remainder: [u8; QUERY_BYTES_V2 - 32],
    remainder_io: FixedDeadlineStreamIoV1<{ QUERY_BYTES_V2 - 32 }>,
    acquisition_remainder_io: FixedDeadlineStreamIoV1<64>,
    acquisition: acquisition::AcquisitionTransportV2,
    stream_duplicate: Option<Result<OwnedFd, rustix::io::Errno>>,
    stream: Option<
        Result<
            aos_sandbox_linux::unix_stream::RetainedUnixStream,
            aos_sandbox_linux::unix_stream::RetainedUnixStreamAdmissionErrorV1,
        >,
    >,
    geometry: Result<SubjectStreamReceiveGeometryV1, SeqpacketError>,
    buffers: [RetainedSubjectStreamReadV1; 3],
    chunks: [RootSubjectChunkReceivingV1; 3],
    reporting: Option<Result<(), SeqpacketError>>,
    policy: RootExecutionNoApplyPolicyOriginalV2,
    policy_begin: Option<
        Result<(), crate::policy_compiler::continuation_policy::RootContinuationPolicyErrorV1>,
    >,
    policy_verify: Option<
        Result<(), crate::policy_compiler::continuation_policy::RootContinuationPolicyErrorV1>,
    >,
    policy_post: Option<
        Result<(), crate::policy_compiler::continuation_policy::RootContinuationPolicyErrorV1>,
    >,
    trust: RootExecutionNoApplyHostTrustOriginalV2,
    readonly: RootCreateFinalityReadonlyOriginalV1,
    models: RootExecutionNoApplyModelsOriginalV2,
    host: RootExecutionNoApplyHostLeaseOriginalV2,
    floor: RootExecutionNoApplyFloorOriginalV2,
    floor_entered: bool,
    final_readonly: RootCreateFinalityReadonlyOriginalV1,
    acknowledged: RootExecutionNoApplyAckOriginalV2,
    clock: Option<Box<RootContinuationClockGateV1>>,
    replies: [Option<Vec<u8>>; 2],
    senders: [SliceDeadlineStreamIoV1; 2],
    binding: Option<Result<(), Cause>>,
    native_ack: Option<Result<(), JournalError>>,
    final_binding: Option<Result<(), Cause>>,
    posts: bool,
}

/// Quotes this sealed purpose's actual fixed transport before peer admission.
///
/// This is geometry only. The private Root peer admission pays it on the same
/// genuine R, before constructing any Native or receiving variable fields.
pub(crate) fn fixed_receiving_demand_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
    let bad = || ResourceReservationErrorV1::Conflict;
    let incoming = MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2
        .checked_add(296 + 28)
        .and_then(|n| n.checked_add(28 + 32 + 296))
        .and_then(|n| {
            n.checked_add(
                20 + 32
                    + CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2
                    + CONTROLLER_CREATE_FAILURE_ACK_BYTES_V2,
            )
        })
        .and_then(|n| n.checked_add(aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::acquisition::ACQUISITION_SUBJECT_BYTES_V2))
        .ok_or_else(bad)?;
    let outgoing = MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2
        .checked_add(20 + 64)
        .and_then(|n| n.checked_add(20 + 32 + 32 + 8))
        .and_then(|n| n.checked_add(aos_sandbox_protocol::domain_ledger::provisioning_root::execution_no_apply::acquisition::MAXIMUM_ACQUISITION_REPLY_BYTES_V2))
        .ok_or_else(bad)?;
    let geometry = RootControllerChunkSubjectSampleV1::receive_geometry_v1().map_err(|_| bad())?;
    let (raw, files) = geometry.receive_obligations_v1();
    let (stream_bytes, stream_files) =
        aos_sandbox_linux::unix_stream::RetainedUnixStream::retained_admission_obligations_v1();
    let clock =
        crate::policy_compiler::RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(bad)?;
    let clock_cells =
        crate::policy_compiler::RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(bad)?;
    // Three fixed constructor/envelope planes cover the Native, opening and
    // receiving carriers. Dynamic readonly/model/floor/ACK owners have their
    // own actual stage suppliers; this does not replace or overlap their debt.
    let memory = size_of::<Native>()
        .checked_mul(9)
        .and_then(|n| {
            n.checked_add(size_of::<RootExecutionNoApplyOpeningOriginalV2>().checked_mul(3)?)
        })
        .and_then(|n| {
            n.checked_add(size_of::<RootExecutionNoApplyReceivingV2<'_, '_, '_>>().checked_mul(3)?)
        })
        .and_then(|n| n.checked_add(incoming.checked_add(outgoing)?.checked_mul(2)?))
        .and_then(|n| n.checked_add(raw))
        .and_then(|n| n.checked_add(clock))
        .and_then(|n| n.checked_add(stream_bytes))
        .and_then(|n| n.checked_add(4096 + 3 * size_of::<sha2::Sha256>()))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(bad)?;
    let files = files.checked_add(stream_files).and_then(|n| n.checked_add(crate::policy_compiler::RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1))
        .and_then(|n| u64::try_from(n).ok()).ok_or_else(bad)?;
    let wire = u64::try_from(incoming.checked_add(outgoing).ok_or_else(bad)?).map_err(|_| bad())?;
    let output = u64::try_from(outgoing).map_err(|_| bad())?;
    let native =
        RootSubjectChunkReceivingV1::execution_no_apply_receiving_demand_v2().map_err(|_| bad())?;
    // Each positive chunk disposes its native sample before the next phase;
    // the first failed chunk returns before another of the three can enter.
    Ok(native
        .checked_add(RootContinuationClockGateV1::receiving_demand_v1().map_err(|_| bad())?)?
        .checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, memory)
                .with(D::OpenFiles, files)
                .with(D::MetadataEntries, clock_cells)
                .with(D::NetworkBytes, wire)
                .with(D::OutputBytes, output),
        )?)
}

impl<'flight, 'listener, 'startup> RootExecutionNoApplyReceivingV2<'flight, 'listener, 'startup> {
    pub(crate) fn from_prelude_v2(
        prelude: RootExecutionNoApplyPreludeV2<'flight, 'listener, 'startup>,
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

    /// Serves actual floor-to-ACK while retaining the whole native graph.
    ///
    /// # Errors
    /// Retains real Source/R, peer, currentness, policy, floor, ACK and all owed
    /// posts. Every offered graph uses the same no-shutdown completion kind;
    /// error/EOF can never produce the private post-Dpositive confirmation.
    pub fn serve_once_v2(
        mut self,
        policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), NormalRootStartupErrorV1> {
        let root = &mut self.prelude.original;
        self.peer = Some(
            root.flight
                .admit_execution_no_apply_controller_peer_once_v2(),
        );
        if matches!(self.peer, Some(Ok(()))) {
            // The sealed actual peer invoice included the complete Native,
            // frame reservoirs and shared chunk peak before this allocation.
            self.native = Some(Box::new(Native::new()));
            let native = self
                .native
                .as_mut()
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.body = Some(native.run(root, policy));
            if matches!(self.body, Some(Err(_))) {
                native.first.get_or_insert(native.phase);
            }
        }
        let _opening_after = root.native.finish_opening_if_owed_v1();
        if let Some(native) = self.native.as_mut() {
            native.finish_posts(root.flight);
        }
        self.peer_post = Some(
            root.flight
                .finish_execution_no_apply_controller_peer_posts_once_v2(),
        );
        self.finish_offered_v2()
    }
}

impl Native {
    fn new() -> Self {
        Self {
            phase: Phase::Opening,
            first: None,
            opening: Default::default(),
            query: [0; QUERY_BYTES_V2],
            remainder: [0; QUERY_BYTES_V2 - 32],
            remainder_io: Default::default(),
            acquisition_remainder_io: Default::default(),
            acquisition: acquisition::AcquisitionTransportV2::new(),
            stream_duplicate: None,
            stream: None,
            geometry: RootControllerChunkSubjectSampleV1::receive_geometry_v1(),
            buffers: std::array::from_fn(|_| RetainedSubjectStreamReadV1::new()),
            chunks: std::array::from_fn(|_| Default::default()),
            reporting: None,
            policy: Default::default(),
            policy_begin: None,
            policy_verify: None,
            policy_post: None,
            trust: RootExecutionNoApplyHostTrustOriginalV2::new(),
            readonly: RootCreateFinalityReadonlyOriginalV1::new(),
            models: RootExecutionNoApplyModelsOriginalV2::new(),
            host: RootExecutionNoApplyHostLeaseOriginalV2::new(),
            floor: RootExecutionNoApplyFloorOriginalV2::new(),
            floor_entered: false,
            final_readonly: RootCreateFinalityReadonlyOriginalV1::new(),
            acknowledged: RootExecutionNoApplyAckOriginalV2::new(),
            clock: None,
            replies: [None, None],
            senders: std::array::from_fn(|_| Default::default()),
            binding: None,
            native_ack: None,
            final_binding: None,
            posts: false,
        }
    }

    fn run(
        &mut self,
        root: &mut crate::policy_compiler::root_policy_prelude::RootPolicyPreludeOriginalV1<
            '_,
            '_,
            '_,
        >,
        current_policy: &RootCurrentPolicyInputDataV1<'_>,
    ) -> Result<(), Cause> {
        self.opening
            .admit_query(&mut root.flight.execution_no_apply_stage_receiving_v2()?)?;
        self.query[..32].copy_from_slice(root.native.prefix_bytes_v1());
        let acquisition = self.query.starts_with(b"AOSANQ02");
        if acquisition {
            let remainder: &mut [u8; 64] = (&mut self.remainder[..64]).try_into()?;
            self.acquisition_remainder_io.run_once(
                &mut root.original,
                remainder,
                root.native.cutoff_v1()?,
                DeadlineStreamDirectionV1::Read,
            )?;
            self.query[32..96].copy_from_slice(remainder);
        } else {
            self.remainder_io.run_once(
                &mut root.original,
                &mut self.remainder,
                root.native.cutoff_v1()?,
                DeadlineStreamDirectionV1::Read,
            )?;
            self.query[32..].copy_from_slice(&self.remainder);
        }
        root.native.finish_opening_if_owed_v1()?;
        self.opening
            .observe_query(&self.query[..if acquisition { 96 } else { QUERY_BYTES_V2 }])?;
        self.phase = Phase::Stream;
        self.stream_duplicate = Some(rustix::io::fcntl_dupfd_cloexec(&root.original, 0));
        match self.stream_duplicate.take() {
            Some(Ok(fd)) => {
                self.stream = Some(
                    aos_sandbox_linux::unix_stream::RetainedUnixStream::from_owned_retaining_v1(fd),
                )
            }
            reached => {
                self.stream_duplicate = reached;
                return Err(JournalError::ProtectedBoundary.into());
            }
        }
        positive(&self.stream)?.require_same_endpoint_v1(root.original.as_fd())?;
        self.phase = Phase::Subject;
        self.opening
            .admit_subject(&mut root.flight.execution_no_apply_stage_receiving_v2()?)?;
        self.reporting = Some(
            root.flight
                .enable_execution_no_apply_subject_reporting_once_v2(),
        );
        positive(&self.reporting)?;
        let query = self.opening.query()?;
        match query {
            ExchangeQueryV2::Acquisition(query) => {
                self.receive_acquisition_and_preliminary(root, current_policy, query)?
            }
            ExchangeQueryV2::Active(_) => {
                self.buffers[0].prepare_exact_once(usize::try_from(query.subject_bytes())?)?;
                self.chunks[0].receive_execution_no_apply_exact_v2(
                    root.flight,
                    &root.original,
                    &mut self.buffers[0],
                    self.geometry
                        .as_ref()
                        .map_err(|_| JournalError::ProtectedBoundary)?,
                    &self.opening,
                )?;
            }
        }
        let subject = ExecutionNoApplySubjectDataV2::decode_v2(self.buffers[0].bytes())?;
        let comparison =
            CurrentHostNoApplyLeaseDataV2::decode_canonical(subject.preliminary_lease)?;
        let cut = aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::RootExecutionNoApplyControllerCutDataV2::decode_canonical(subject.controller_cut)?;
        match query {
            ExchangeQueryV2::Active(query) => {
                if subject.digest_v2()? != query.subject_digest
                    || query.controller_next != cut.next()
                    || query.controller_end != cut.end()
                    || comparison.fields().scope != HostNoApplyLeaseScopeV2::Active
                    || query.original_boot != comparison.fields().native_boot
                {
                    return Err(JournalError::ProtectedBoundary.into());
                }
                self.begin_policy(root, current_policy)?;
            }
            ExchangeQueryV2::Acquisition(_) => {
                self.acquisition.require_preliminary(comparison, cut)?
            }
        }
        self.opening.tighten(&self.policy, comparison)?;
        let horizon = self.opening.horizon()?;
        match self.clock.as_mut() {
            Some(clock) => clock.narrow_horizon_data_v1(horizon)?,
            None => self.clock = Some(Box::new(RootContinuationClockGateV1::new(horizon))),
        }
        self.phase = Phase::Trust;
        self.trust.prepare_once_v2(
            &mut root.flight.execution_no_apply_stage_receiving_v2()?,
            self.opening.horizon()?,
            comparison,
        )?;
        let nonce = self.trust.read_nonce_data_v2()?;
        self.phase = Phase::NonceSend;
        self.send_nonce(root, query, nonce)?;
        self.phase = Phase::Current;
        self.receive_current(root, query)?;

        // Only after actual43 completed can the independent current C/Session/
        // Source reader observe its signed nonce relation on this held writer.
        self.phase = Phase::Readonly;
        self.readonly.observe_execution_no_apply_once_v2(
            &mut root.flight.execution_no_apply_stage_receiving_v2()?,
            self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?,
        )?;
        let HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(marker) =
            comparison.fields().marker
        else {
            return Err(JournalError::ProtectedBoundary.into());
        };
        let subject = ExecutionNoApplySubjectDataV2::decode_v2(self.buffers[0].bytes())?;
        let wall = i64::from_be_bytes(subject.wall.try_into()?);
        self.phase = Phase::Models;
        self.models.observe_once_v2(
            &mut root.flight.execution_no_apply_stage_receiving_v2()?,
            &self.readonly,
            &self.policy,
            marker,
            ObjectDigest::from_bytes(comparison.fields().terminal_archive_head),
            ObjectDigest::from_bytes(comparison.fields().signed_terminal_outcome),
            wall,
        )?;
        self.binding = Some((|| {
            let actual = self
                .readonly
                .execution_no_apply_current_data_v2()?
                .global_controller_cut_data_v2()?;
            let (predecessor, successor) = self.models.plan_data_v2()?.row_digests_data_v2();
            if actual != cut
                || rows(predecessor).as_slice() != subject.predecessor
                || rows(successor).as_slice() != subject.successor
                || self.models.plan_data_v2()?.wall_seconds_data_v2() != wall
            {
                return Err(JournalError::ProtectedBoundary.into());
            }
            Ok(())
        })());
        positive(&self.binding)?;
        self.phase = Phase::Host;
        self.host.observe_once_v2(
            &mut root.flight.execution_no_apply_stage_receiving_v2()?,
            &self.readonly,
            &mut self.trust,
        )?;
        let stream = positive(&self.stream)?;
        self.phase = Phase::Floor;
        root.flight.append_execution_no_apply_floor_once_v2(
            &mut self.floor,
            stream,
            &mut self.policy,
            &mut self.readonly,
            &self.models,
            &self.host,
            &mut self.trust,
            &mut self.floor_entered,
            if matches!(query, ExchangeQueryV2::Acquisition(_)) {
                Some(&mut self.acquisition.original)
            } else {
                None
            },
        )?;
        self.phase = Phase::FloorSend;
        self.send_floor(root, query, nonce)?;
        self.phase = Phase::AckReceive;
        self.receive_ack(root, query)?;

        self.phase = Phase::FinalReadonly;
        self.final_readonly
            .observe_execution_no_apply_final_once_v2(
                &mut root.flight.execution_no_apply_stage_receiving_v2()?,
                self.clock.as_mut().ok_or(JournalError::ProtectedBoundary)?,
            )?;
        self.phase = Phase::AckNative;
        self.native_ack = Some(root.flight.certify_execution_no_apply_ack_once_v2(
            &mut self.acknowledged,
            positive(&self.stream)?,
            &mut self.final_readonly,
            &mut self.trust,
            &self.policy,
            &self.floor,
            if matches!(query, ExchangeQueryV2::Acquisition(_)) {
                Some(&mut self.acquisition.original)
            } else {
                None
            },
        ));
        positive(&self.native_ack)?;
        self.phase = Phase::FinalBinding;
        self.final_binding = Some((|| {
            let announced =
                ExecutionNoApplyAcknowledgementDataV2::decode_v2(self.buffers[2].bytes())?;
            let actual = self.acknowledged.acknowledgement_data_v2()?;
            if announced.controller_ack != actual.encode_canonical() || announced.controller_prepare !=
                aos_sandbox_protocol::host_execution_no_apply::root_attestation::RootExecutionNoApplyAttestationDataV2::decode_canonical(
                    self.floor.attestation_bytes_v2()?)?.prepare_data_v2().encode_canonical() {
                return Err(JournalError::ProtectedBoundary.into());
            }
            Ok(())
        })());
        positive(&self.final_binding)?;
        Ok(())
    }

    fn send_nonce(
        &mut self,
        root: &mut crate::policy_compiler::root_policy_prelude::RootPolicyPreludeOriginalV1<
            '_,
            '_,
            '_,
        >,
        query: ExchangeQueryV2,
        nonce: [u8; 32],
    ) -> Result<(), Cause> {
        let digest = query.digest_v2()?;
        let cutoff = query.cutoff().to_be_bytes();
        let frame = ExecutionNoApplyNonceReplyDataV2 {
            query_digest: &digest,
            root_nonce: &nonce,
            original_cutoff: &cutoff,
        };
        let bytes = frame.encoded_bytes_v2()?;
        self.replies[0] = Some(vec![0; bytes]);
        frame.encode_range_v2(
            0,
            self.replies[0]
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?,
        )?;
        self.senders[0].run_once(
            &mut root.original,
            self.replies[0]
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?,
            self.opening.current_cutoff_v1()?,
            DeadlineStreamDirectionV1::Write,
        )?;
        Ok(())
    }

    fn receive_current(
        &mut self,
        root: &mut crate::policy_compiler::root_policy_prelude::RootPolicyPreludeOriginalV1<
            '_,
            '_,
            '_,
        >,
        query: ExchangeQueryV2,
    ) -> Result<(), Cause> {
        self.buffers[1].prepare_exact_once(28)?;
        self.chunks[1].receive_execution_no_apply_exact_v2(
            root.flight,
            &root.original,
            &mut self.buffers[1],
            self.geometry
                .as_ref()
                .map_err(|_| JournalError::ProtectedBoundary)?,
            &self.opening,
        )?;
        let bytes = ExecutionNoApplyCurrentDataV2::declared_bytes_v2(self.buffers[1].bytes())?;
        self.buffers[1].extend_completed_exact_once(bytes)?;
        self.chunks[1].receive_execution_no_apply_exact_v2(
            root.flight,
            &root.original,
            &mut self.buffers[1],
            self.geometry
                .as_ref()
                .map_err(|_| JournalError::ProtectedBoundary)?,
            &self.opening,
        )?;
        let initial = ExecutionNoApplySubjectDataV2::decode_v2(self.buffers[0].bytes())?;
        let current = ExecutionNoApplyCurrentDataV2::decode_v2(self.buffers[1].bytes())?;
        if current.query_digest != query.digest_v2()?
            || current.controller_cut != initial.controller_cut
            || current.wall != initial.wall
            || current.predecessor != initial.predecessor
            || current.successor != initial.successor
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    fn send_floor(
        &mut self,
        root: &mut crate::policy_compiler::root_policy_prelude::RootPolicyPreludeOriginalV1<
            '_,
            '_,
            '_,
        >,
        query: ExchangeQueryV2,
        nonce: [u8; 32],
    ) -> Result<(), Cause> {
        let digest = query.digest_v2()?;
        let frame = ExecutionNoApplyFloorReplyDataV2 {
            query_digest: &digest,
            root_nonce: &nonce,
            attestation: self.floor.attestation_bytes_v2()?,
        };
        let bytes = frame.encoded_bytes_v2()?;
        self.replies[1] = Some(vec![0; bytes]);
        frame.encode_range_v2(
            0,
            self.replies[1]
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?,
        )?;
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

    fn receive_ack(
        &mut self,
        root: &mut crate::policy_compiler::root_policy_prelude::RootPolicyPreludeOriginalV1<
            '_,
            '_,
            '_,
        >,
        query: ExchangeQueryV2,
    ) -> Result<(), Cause> {
        self.buffers[2].prepare_exact_once(20)?;
        self.chunks[2].receive_execution_no_apply_exact_v2(
            root.flight,
            &root.original,
            &mut self.buffers[2],
            self.geometry
                .as_ref()
                .map_err(|_| JournalError::ProtectedBoundary)?,
            &self.opening,
        )?;
        let bytes =
            ExecutionNoApplyAcknowledgementDataV2::declared_bytes_v2(self.buffers[2].bytes())?;
        self.buffers[2].extend_completed_exact_once(bytes)?;
        self.chunks[2].receive_execution_no_apply_exact_v2(
            root.flight,
            &root.original,
            &mut self.buffers[2],
            self.geometry
                .as_ref()
                .map_err(|_| JournalError::ProtectedBoundary)?,
            &self.opening,
        )?;
        let frame = ExecutionNoApplyAcknowledgementDataV2::decode_v2(self.buffers[2].bytes())?;
        if frame.query_digest != query.digest_v2()? {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    fn finish_posts(&mut self, flight: &RootPolicyAcceptedFlightV1<'_, '_>) {
        if self.posts {
            return;
        }
        self.posts = true;
        self.readonly.finish_posts_once_v1();
        if self.readonly.failure().is_some() {
            self.first.get_or_insert(Phase::Readonly);
        }
        self.final_readonly.finish_posts_once_v1();
        if self.final_readonly.failure().is_some() {
            self.first.get_or_insert(Phase::FinalReadonly);
        }
        self.trust.finish_posts_once_v2();
        if self.trust.failure().is_some() {
            self.first.get_or_insert(Phase::Trust);
        }
        if self.policy_begin.is_some() && !self.floor_entered {
            self.policy_post = Some(
                flight.finish_execution_no_apply_policy_without_floor_once_v2(&mut self.policy),
            );
            if self.policy.failure().is_some()
                || self.policy_post.as_ref().is_some_and(Result::is_err)
            {
                self.first.get_or_insert(Phase::Policy);
            }
        }
    }

    fn require_complete(&self) -> Result<(), JournalError> {
        if !self.posts
            || !matches!(self.native_ack, Some(Ok(())))
            || !matches!(self.final_binding, Some(Ok(())))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.acknowledged.require_complete_v2()?;
        self.floor.attestation_bytes_v2()?;
        self.policy
            .require_complete_v1()
            .map_err(|_| JournalError::ProtectedBoundary)?;
        self.final_readonly.require_complete_v1()?;
        if self.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected =
            match self.first? {
                Phase::Opening => self
                    .opening
                    .failure()
                    .or_else(|| self.remainder_io.failure())
                    .or_else(|| self.acquisition_remainder_io.failure()),
                Phase::Acquisition => (if self.clock.as_ref().is_some_and(|clock| {
                    self.acquisition.original.external_clock_is_first_v2(clock)
                }) {
                    self.clock.as_ref().and_then(|clock| clock.failure())
                } else {
                    self.acquisition.original.failure()
                })
                .or_else(|| {
                    self.acquisition
                        .chunk
                        .failure_with_buffer(&self.acquisition.buffer)
                }),
                Phase::AcquisitionReply => self.acquisition.sender.failure(),
                Phase::Preliminary => self.chunks[0].failure_with_buffer(&self.buffers[0]),
                Phase::Stream => error(&self.stream_duplicate).or_else(|| error(&self.stream)),
                Phase::Subject => self
                    .geometry
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
                    .or_else(|| error(&self.reporting))
                    .or_else(|| self.chunks[0].failure_with_buffer(&self.buffers[0])),
                Phase::Policy => self
                    .policy
                    .failure()
                    .or_else(|| error(&self.policy_begin))
                    .or_else(|| error(&self.policy_verify))
                    .or_else(|| error(&self.policy_post)),
                Phase::Trust => self.trust.failure(),
                Phase::NonceSend => self.senders[0].failure(),
                Phase::Current => self.chunks[1].failure_with_buffer(&self.buffers[1]),
                Phase::Readonly => self.readonly.failure(),
                Phase::Models => self.models.failure().or_else(|| boxed_error(&self.binding)),
                Phase::Host => self.host.failure().or_else(|| self.trust.failure()),
                Phase::Floor => self
                    .acquisition
                    .original
                    .failure()
                    .or_else(|| self.floor.failure())
                    .or_else(|| self.trust.failure())
                    .or_else(|| self.readonly.failure())
                    .or_else(|| self.policy.failure()),
                Phase::FloorSend => self.senders[1].failure(),
                Phase::AckReceive => self.chunks[2].failure_with_buffer(&self.buffers[2]),
                Phase::FinalReadonly => self.final_readonly.failure(),
                Phase::AckNative => {
                    if let Some(cause) = self.acquisition.original.failure() {
                        return Some(cause);
                    }
                    let (trust, readers) = self.acknowledged.external_failure_v2();
                    (if trust {
                        self.trust.failure()
                    } else if readers {
                        self.final_readonly.failure()
                    } else {
                        self.acknowledged.failure()
                    })
                    .or_else(|| error(&self.native_ack))
                }
                Phase::FinalBinding => boxed_error(&self.final_binding),
            };
        selected.or_else(|| self.clock.as_ref().and_then(|clock| clock.failure()))
    }
}

fn rows(input: [[u8; 32]; 3]) -> [u8; 96] {
    let mut bytes = [0; 96];
    for (chunk, digest) in bytes.chunks_exact_mut(32).zip(input) {
        chunk.copy_from_slice(&digest);
    }
    bytes
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

fn boxed_error(slot: &Option<Result<(), Cause>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause.as_ref())
}
