//! Retains the actual Execution Root connection through floor, C effects and ACK.
//!
//! Every phase reborrows the same concrete Source/C18 loan. The socket, initial
//! Root subject, original deadline, literal frames and independent owed posts
//! remain resident. A borrowed floor is not a detached attestation capability.

use super::{
    NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1,
    peer_receiving::CreateStorageRootPeerReceivingOriginalsV1,
    resource_stream::{
        self, RootClientControllerContextV2, RootClientFundingV1, RootClientLoanV1,
        RootReplyPurposeV1, RootReplyReceiveV1, RootSubjectDataV1,
    },
    root_connection::ControllerRootConnectionOriginalV1,
    strict_chunk::RootStrictChunkOriginalV1,
};
use crate::{
    controller_execution_operation::ControllerExecutionNoApplyClientLoanV2,
    controller_resource_reservation::ResourceReservationErrorV1,
    policy_compiler::{
        RetainedKernelPairedClockAttemptV1,
        bounded_stream_io::{DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1},
    },
};
use aos_sandbox_broker::bounded_entropy::{EntropyError, RetainedKernelNonceOriginalV1};
use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1};
use aos_sandbox_protocol::{
    domain_ledger::{
        create_storage_history::HistoryErrorV1,
        provisioning_root::{execution_no_apply::*, storage_apply::ApplyRootDataErrorV1},
    },
    host_execution_no_apply::{
        current_lease::CurrentHostNoApplyLeaseDataV2,
        root_attestation::{
            MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2, RootExecutionNoApplyAttestationDataV2,
        },
    },
};
use std::{error::Error, mem::size_of};

mod acquisition;
mod floor;
pub use acquisition::RootExecutionNoApplyClientAcquisitionBorrowV2;
pub use floor::RootExecutionNoApplyClientFloorBorrowV2;

use super::bookend::RootClientBookendV1 as Bookend;

type Cause = Box<dyn Error + Send + Sync>;
// Five actual intervals: opening, floor response, Cprepare, CAS and closing.
const BOOKENDS: usize = 10;

/// Reports an incomplete or refused continuously held Execution Root exchange.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the retained Execution Root exchange is incomplete or refused")]
pub struct RootExecutionNoApplyClientClosedV2;

/// Retains the actual Root socket, frames, native subjects and all owed posts.
#[must_use = "retain the original through actual Root finality and Source disposition"]
pub struct RootExecutionNoApplyClientOriginalV2 {
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    state: Option<Box<Native>>,
    acquisition: Option<Box<acquisition::AcquisitionNativeV2>>,
    complete: ResourceVector,
    observations: usize,
    wire: u64,
    output: u64,
    received_bound: usize,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    funding_original: bool,
    phase: usize,
    pending: Option<usize>,
    first: Option<First>,
    reentry: Option<RootExecutionNoApplyClientClosedV2>,
    validation: Option<Cause>,
}

#[derive(Clone, Copy)]
enum First {
    Entry,
    Body(usize),
    Bookend(usize),
    Funding,
    Unwind,
    Reentry,
    Validation,
    Acquisition,
}

struct Native {
    origin: RawPairedClockSample,
    source_cutoff: u64,
    cutoff: u64,
    preliminary: CurrentHostNoApplyLeaseDataV2,
    preliminary_bytes: Vec<u8>,
    cut: [u8; 96],
    wall: [u8; 8],
    predecessor: [u8; 96],
    successor: [u8; 96],
    entropy: RetainedKernelNonceOriginalV1,
    nonce: Option<Result<[u8; 16], EntropyError>>,
    query: Option<Result<ExecutionNoApplyQueryDataV2, HistoryErrorV1>>,
    query_bytes: [u8; QUERY_BYTES_V2],
    query_digest: [u8; 32],
    root_nonce: [u8; 32],
    connection: ControllerRootConnectionOriginalV1,
    connect: Option<Result<(), HistoryErrorV1>>,
    reporting: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    query_sender: FixedDeadlineStreamIoV1<QUERY_BYTES_V2>,
    query_sent: Option<Result<(), HistoryErrorV1>>,
    eof: FixedDeadlineStreamIoV1<1>,
    eof_byte: [u8; 1],
    ended: Option<Result<(), HistoryErrorV1>>,
    sender: [FixedDeadlineStreamIoV1<4096>; 3],
    sent: [Option<Result<(), HistoryErrorV1>>; 3],
    scratch: [u8; 4096],
    data_failure: Option<ApplyRootDataErrorV1>,
    replies: [Reply; 3],
    confirmation: Option<Result<(), HistoryErrorV1>>,
    sent_ack: Option<aos_sandbox_protocol::host_execution_no_apply::closed_controller::ControllerCreateFailureAckDataV2>,
    bookends: [Bookend; BOOKENDS],
    body: [Option<Result<(), Cause>>; 3],
    prepare_after: Option<Result<(), RootExecutionNoApplyClientClosedV2>>,
    cas_after: Option<Result<(), RootExecutionNoApplyClientClosedV2>>,
}

struct Reply {
    received: RetainedSubjectStreamReadV1,
    preparation: Option<Result<(), SubjectStreamReadErrorV1>>,
    extension: Option<Result<(), SubjectStreamReadErrorV1>>,
    chunk: Option<Box<RootStrictChunkOriginalV1>>,
}

impl Default for RootExecutionNoApplyClientOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl RootExecutionNoApplyClientOriginalV2 {
    /// Constructs only inert destinations, without allocation, admission or IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entry: None,
            state: None,
            acquisition: None,
            complete: ResourceVector::ZERO,
            observations: 0,
            wire: 0,
            output: 0,
            received_bound: 20,
            admission: None,
            funding_original: false,
            phase: 0,
            pending: None,
            first: None,
            reentry: None,
            validation: None,
        }
    }

    fn demand(
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bad = || ResourceReservationErrorV1::Conflict;
        let peer =
            CreateStorageRootPeerReceivingOriginalsV1::execution_no_apply_native_peak_v2(profile)
                .ok_or_else(bad)?;
        let connection =
            ControllerRootConnectionOriginalV1::receiving_demand_v1().ok_or_else(bad)?;
        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| bad())?;
        let (raw, files) = geometry.receive_obligations_v1();
        let clock_bytes = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .and_then(|n| n.checked_mul(BOOKENDS))
            .ok_or_else(bad)?;
        let clock_cells = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|n| n.checked_mul(BOOKENDS))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(bad)?;
        let memory = size_of::<Self>().checked_add(size_of::<Native>())
            .and_then(|n| n.checked_add(size_of::<RootStrictChunkOriginalV1>().checked_mul(2)?))
            .and_then(|n| n.checked_add(size_of::<RootClientFundingV1<'_>>().checked_mul(2)?))
            .and_then(|n| n.checked_add(size_of::<RootReplyReceiveV1<'_>>().checked_mul(2)?))
            .and_then(|n| n.checked_add(raw)).and_then(|n| n.checked_add(clock_bytes))
            .and_then(|n| n.checked_add(RetainedKernelNonceOriginalV1::construction_bytes_v1()?))
            .and_then(|n| n.checked_add(aos_sandbox_protocol::host_execution_no_apply::current_lease::MAXIMUM_CURRENT_HOST_NO_APPLY_LEASE_BYTES_V2))
            .and_then(|n| n.checked_add(MAXIMUM_ROOT_NO_APPLY_ATTESTATION_BYTES_V2.checked_mul(2)?))
            .and_then(|n| n.checked_mul(3)).and_then(|n| u64::try_from(n).ok()).ok_or_else(bad)?;
        let files = BOOKENDS
            .checked_mul(RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1)
            .and_then(|n| n.checked_add(files))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(bad)?;
        Ok(peer.checked_add(connection)?.checked_add(
            ResourceVector::ZERO
                .with(D::MemoryBytes, memory)
                .with(D::OpenFiles, files)
                .with(D::MetadataEntries, clock_cells),
        )?)
    }

    /// Opens the actual fixed Root socket and obtains its separately sampled43 nonce.
    ///
    /// # Errors
    /// Retains funding, entropy, connection, native peer, framing and original-D
    /// failures, and independently drains the already paid opening after-post.
    pub fn begin_once_v2(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        if self.acquisition.is_some() {
            return self.begin_after_acquisition_once_v2(loan);
        }
        if self.entry.is_some() {
            return Err(self.refuse_reentry());
        }
        let profile = loan.root_transport_profile_v2();
        self.entry = Some((|| {
            let (origin, cutoff) = loan.root_original_clock_data_v2()?;
            let preliminary = loan.root_owned_host_lease_data_v2()?;
            let cut = loan.controller_cut_data_v2()?;
            let (wall, predecessor, successor) = loan.controller_rows_data_v2()?;
            self.complete = Self::demand(profile)?;
            let whole = self
                .complete
                .checked_add(resource_stream::peer_traffic_v1(BOOKENDS)?)?;
            let debit = loan.admit_root_transport_complete_v2(whole);
            if debit.is_err() && loan.failure_v2().is_some() {
                self.funding_original = true;
            }
            debit?;
            self.observations = BOOKENDS;
            self.state = Some(Box::new(Native::new(
                origin,
                cutoff,
                preliminary,
                cut.encode_canonical(),
                wall.to_be_bytes(),
                rows(predecessor),
                rows(successor),
            )));
            Ok(())
        })());
        if !matches!(self.entry, Some(Ok(()))) {
            self.first.get_or_insert(First::Entry);
            return Err(RootExecutionNoApplyClientClosedV2);
        }
        self.pending = Some(1);
        let mut guard = OwedAfter {
            owner: self,
            profile,
        };
        let result = guard.owner.open_body(loan, profile);
        guard.owner.record_body(0, result);
        guard.finish();
        drop(guard);
        if self.first.is_none() {
            self.phase = 1;
            Ok(())
        } else {
            Err(RootExecutionNoApplyClientClosedV2)
        }
    }

    fn open_body(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), Cause> {
        let native = self
            .state
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        native.nonce = Some(native.entropy.observe_once());
        let nonce = *positive(&native.nonce)?;
        native.query = Some((|| {
            let subject = native.subject();
            let cut = loan
                .controller_cut_data_v2()
                .map_err(|_| HistoryErrorV1::Malformed)?;
            let query = ExecutionNoApplyQueryDataV2 {
                controller_nonce: nonce,
                original_boot: native.origin.host_boot_id(),
                original_boottime_ns: native.origin.boottime_nanoseconds(),
                original_cutoff_ns: native.source_cutoff,
                subject_bytes: u64::try_from(subject.encoded_bytes_v2()?)
                    .map_err(|_| HistoryErrorV1::Extent)?,
                subject_digest: subject.digest_v2()?,
                controller_next: cut.next(),
                controller_end: cut.end(),
            };
            native.query_bytes = query.encode_v2()?;
            native.query_digest = query.digest_v2()?;
            Ok(query)
        })());
        let query = *positive(&native.query)?;
        let bytes = usize::try_from(query.subject_bytes)?
            .checked_add(QUERY_BYTES_V2)
            .ok_or(HistoryErrorV1::Extent)?;
        self.charge(
            loan,
            bytes.checked_add(20).ok_or(HistoryErrorV1::Extent)?,
            bytes,
        )?;
        let native = self
            .state
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        native.connect = Some(native.connection.connect_once());
        positive(&native.connect)?;
        self.observe_bookend(0, profile, false)?;
        let native = self
            .state
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        native.reporting = Some(native.connection.stream_mut()?.enable_subject_reporting());
        positive(&native.reporting)?;
        native.query_sent = Some(native.query_sender.run_once(
            native.connection.stream_mut()?,
            &mut native.query_bytes,
            native.cutoff,
            DeadlineStreamDirectionV1::Write,
        ));
        positive(&native.query_sent)?;
        let subject = ExecutionNoApplySubjectDataV2 {
            preliminary_lease: &native.preliminary_bytes,
            controller_cut: &native.cut,
            wall: &native.wall,
            predecessor: &native.predecessor,
            successor: &native.successor,
        };
        resource_stream::send_subject_v1(
            RootSubjectDataV1::ExecutionNoApplySubject(subject),
            &mut native.connection,
            &mut native.sender[0],
            &mut native.sent[0],
            &mut native.scratch,
            &mut native.data_failure,
            native.cutoff,
        )
        .map_err(|_| RootExecutionNoApplyClientClosedV2)?;
        self.receive(loan, profile, 0, RootReplyPurposeV1::ExecutionNoApplyNonce)?;
        let native = self
            .state
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        let reply =
            ExecutionNoApplyNonceReplyDataV2::decode_v2(native.replies[0].received.bytes())?;
        if reply.query_digest != native.query_digest
            || reply.original_cutoff != native.source_cutoff.to_be_bytes()
        {
            return Err(HistoryErrorV1::Malformed.into());
        }
        native.root_nonce.copy_from_slice(reply.root_nonce);
        Ok(())
    }

    /// Borrows only the actual completed Root nonce for the same Host43 turn.
    ///
    /// # Errors
    /// Refuses incomplete opening, failed posts or another phase.
    pub fn root_read_nonce_data_v2(&self) -> Result<[u8; 32], RootExecutionNoApplyClientClosedV2> {
        self.require_phase(1)?;
        Ok(self.native()?.root_nonce)
    }

    /// Sends current43 completion on the same Root socket and retains the signed floor.
    ///
    /// # Errors
    /// Refuses changed whole-C/rows, another phase, transport, native peer or
    /// canonical floor association, retaining the independently owed after-post.
    pub fn receive_floor_once_v2(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        self.require_phase(1)?;
        let profile = loan.root_transport_profile_v2();
        self.pending = Some(3);
        let mut guard = OwedAfter {
            owner: self,
            profile,
        };
        let result = guard.owner.floor_body(loan, profile);
        guard.owner.record_body(1, result);
        guard.finish();
        drop(guard);
        if self.first.is_none() {
            self.phase = 2;
            Ok(())
        } else {
            Err(RootExecutionNoApplyClientClosedV2)
        }
    }

    fn floor_body(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), Cause> {
        let lease = self.require_owned_cut(loan)?;
        self.observe_bookend(2, profile, false)?;
        let bytes = {
            let native = self.native()?;
            native.current().encoded_bytes_v2()?
        };
        self.charge(
            loan,
            bytes.checked_add(20).ok_or(HistoryErrorV1::Extent)?,
            bytes,
        )?;
        let native = self
            .state
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        let current = ExecutionNoApplyCurrentDataV2 {
            query_digest: &native.query_digest,
            controller_cut: &native.cut,
            wall: &native.wall,
            predecessor: &native.predecessor,
            successor: &native.successor,
        };
        resource_stream::send_subject_v1(
            RootSubjectDataV1::ExecutionNoApplyCurrent(current),
            &mut native.connection,
            &mut native.sender[1],
            &mut native.sent[1],
            &mut native.scratch,
            &mut native.data_failure,
            native.cutoff,
        )
        .map_err(|_| RootExecutionNoApplyClientClosedV2)?;
        self.receive(loan, profile, 1, RootReplyPurposeV1::ExecutionNoApplyFloor)?;
        let native = self.native()?;
        let reply =
            ExecutionNoApplyFloorReplyDataV2::decode_v2(native.replies[1].received.bytes())?;
        let packet = RootExecutionNoApplyAttestationDataV2::decode_canonical(reply.attestation)?;
        let floor = packet.floor_data_v2();
        if reply.query_digest != native.query_digest
            || reply.root_nonce != native.root_nonce
            || floor.fields().host_lease != lease
            || floor.fields().controller_cut.encode_canonical() != native.cut
            || floor.fields().terminal_wall_seconds.to_be_bytes() != native.wall
            || rows(floor.fields().predecessor_rows) != native.predecessor
            || rows(floor.fields().successor_rows) != native.successor
        {
            return Err(HistoryErrorV1::Malformed.into());
        }
        Ok(())
    }

    fn require_owned_cut(
        &self,
        loan: &ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
    ) -> Result<CurrentHostNoApplyLeaseDataV2, Cause> {
        let native = self.native()?;
        let (origin, cutoff) = loan.root_original_clock_data_v2()?;
        let (wall, predecessor, successor) = loan.controller_rows_data_v2()?;
        if origin != native.origin
            || cutoff != native.source_cutoff
            || loan.controller_cut_data_v2()?.encode_canonical() != native.cut
            || wall.to_be_bytes() != native.wall
            || rows(predecessor) != native.predecessor
            || rows(successor) != native.successor
        {
            return Err(HistoryErrorV1::Malformed.into());
        }
        let lease = loan.root_owned_host_lease_data_v2()?;
        if lease.fields().accepted_source != native.preliminary.fields().accepted_source
            || lease.fields().marker != native.preliminary.fields().marker
            || lease.fields().challenge != native.preliminary.fields().challenge
            || lease.fields().current_session != native.preliminary.fields().current_session
        {
            return Err(HistoryErrorV1::Malformed.into());
        }
        Ok(lease)
    }

    /// Sends the actual Root ACK while retaining its original native connection.
    ///
    /// Final positive completion additionally requires the shared permanent-F
    /// confirmation issued causally after actual transient D disposal. EOF and
    /// an immediate ALIVE sample do not establish that causal boundary.
    ///
    /// # Errors
    /// Refuses incomplete C bookends, a changed floor, malformed DATA, transport
    /// or native Root posts, retaining every reached prefix and owed after.
    pub fn send_acknowledgement_once_v2(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        self.require_phase(4)?;
        let profile = loan.root_transport_profile_v2();
        self.pending = Some(9);
        let mut guard = OwedAfter {
            owner: self,
            profile,
        };
        let result = guard.owner.acknowledgement_body(loan, profile);
        guard.owner.record_body(2, result);
        guard.finish();
        drop(guard);
        if self.first.is_none() {
            self.phase = 5;
            Ok(())
        } else {
            Err(RootExecutionNoApplyClientClosedV2)
        }
    }

    fn acknowledgement_body(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), Cause> {
        // Both records come from actual continuously owned originals. No
        // caller-supplied prepare or ACK bytes can select this final phase.
        let ack = loan.controller_acknowledgement_data_v2()?;
        let bytes = 20_usize
            .checked_add(aos_sandbox_protocol::host_execution_no_apply::closed_controller::CLOSED_CREATE_FAILURE_PREPARE_BYTES_V2)
            .and_then(|n| n.checked_add(aos_sandbox_protocol::host_execution_no_apply::closed_controller::CONTROLLER_CREATE_FAILURE_ACK_BYTES_V2))
            .ok_or(HistoryErrorV1::Extent)?;
        self.charge(
            loan,
            bytes.checked_add(1).ok_or(HistoryErrorV1::Extent)?,
            bytes,
        )?;
        let native = self.native()?;
        let floor_reply =
            ExecutionNoApplyFloorReplyDataV2::decode_v2(native.replies[1].received.bytes())?;
        let packet =
            RootExecutionNoApplyAttestationDataV2::decode_canonical(floor_reply.attestation)?;
        let controller_prepare = packet.prepare_data_v2().encode_canonical();
        let controller_ack = ack.encode_canonical();
        let subject = ExecutionNoApplyAcknowledgementDataV2 {
            query_digest: &native.query_digest,
            controller_prepare: &controller_prepare,
            controller_ack: &controller_ack,
        };
        if subject.encoded_bytes_v2()? != bytes {
            return Err(HistoryErrorV1::Extent.into());
        }
        self.observe_bookend(8, profile, false)?;
        let native = self
            .state
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        native.sent_ack = Some(ack);
        let subject = ExecutionNoApplyAcknowledgementDataV2 {
            query_digest: &native.query_digest,
            controller_prepare: &controller_prepare,
            controller_ack: &controller_ack,
        };
        resource_stream::send_subject_v1(
            RootSubjectDataV1::ExecutionNoApplyAcknowledgement(subject),
            &mut native.connection,
            &mut native.sender[2],
            &mut native.sent[2],
            &mut native.scratch,
            &mut native.data_failure,
            native.cutoff,
        )
        .map_err(|_| RootExecutionNoApplyClientClosedV2)?;
        self.receive_confirmation(loan, profile)?;
        let native = self
            .state
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        native.confirmation = Some(if native.replies[2].received.bytes()
            == aos_sandbox_protocol::root_policy_completion::execution_no_apply_positive_completion_bytes_v2(
                native.query_digest, *ack.root_floor.as_bytes(), ack) {
            Ok(())
        } else { Err(HistoryErrorV1::Malformed) });
        positive(&native.confirmation)?;
        native.ended = Some(native.eof.run_once(
            native.connection.stream_mut()?,
            &mut native.eof_byte,
            native.cutoff,
            DeadlineStreamDirectionV1::Eof,
        ));
        positive(&native.ended)?;
        if !native.eof.completed_exact() {
            return Err(HistoryErrorV1::Malformed.into());
        }
        Ok(())
    }

    /// Requires actual positive Root disposition rather than a sent closing frame.
    ///
    /// # Errors
    /// Refuses incomplete EOF, failed same-process ALIVE/native posts or any
    /// earlier financial, transport or canonical association failure.
    pub fn require_complete_v2(&self) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        self.require_phase(5)?;
        if let Some(acquired) = self.acquisition.as_ref() {
            acquired.require_transferred()?;
        }
        let native = self.native()?;
        if matches!(native.confirmation, Some(Ok(())))
            && matches!(native.ended, Some(Ok(())))
            && native.eof.completed_exact()
            && matches!(native.bookends[9].observed, Some(Ok(())))
        {
            Ok(())
        } else {
            Err(RootExecutionNoApplyClientClosedV2)
        }
    }

    /// Joins actual completed Root disposition to the literal ACK sent by this owner.
    ///
    /// # Errors
    /// Refuses incomplete confirmation/EOF/native posts or any different ACK,
    /// including its operation, floor, prepare, CAS, phase and whole Controller cut.
    pub fn require_completed_controller_acknowledgement_v2(
        &self,
        acknowledgement: &aos_sandbox_protocol::host_execution_no_apply::closed_controller::ControllerCreateFailureAckDataV2,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        self.require_complete_v2()?;
        if self.native()?.sent_ack.as_ref() == Some(acknowledgement) {
            Ok(())
        } else {
            Err(RootExecutionNoApplyClientClosedV2)
        }
    }

    fn charge(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
        wire: usize,
        output: usize,
    ) -> Result<(), Cause> {
        let mut funding = self.funding();
        funding
            .charge_for_v2(
                &mut RootClientLoanV1::ExecutionNoApply(loan),
                RootClientControllerContextV2::ExecutionOwned,
                0,
                wire,
                output,
            )
            .map_err(|_| RootExecutionNoApplyClientClosedV2)?;
        Ok(())
    }

    fn funding(&mut self) -> RootClientFundingV1<'_> {
        RootClientFundingV1 {
            complete: self.complete,
            observations: &mut self.observations,
            wire: &mut self.wire,
            output: &mut self.output,
            received_bound: &mut self.received_bound,
            admission: &mut self.admission,
            funding_original: &mut self.funding_original,
        }
    }

    fn receive(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
        profile: &ProductionControllerNormalRootProfileV1,
        index: usize,
        purpose: RootReplyPurposeV1,
    ) -> Result<(), Cause> {
        let native = self
            .state
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        let reply = &mut native.replies[index];
        let mut receive = RootReplyReceiveV1 {
            connection: &mut native.connection,
            received: &mut reply.received,
            preparation: &mut reply.preparation,
            extension: &mut reply.extension,
            chunk: &mut reply.chunk,
            data_failure: &mut native.data_failure,
            peer_before: &native.bookends[0].peer,
            profile,
            cutoff: native.cutoff,
        };
        let mut funding = RootClientFundingV1 {
            complete: self.complete,
            observations: &mut self.observations,
            wire: &mut self.wire,
            output: &mut self.output,
            received_bound: &mut self.received_bound,
            admission: &mut self.admission,
            funding_original: &mut self.funding_original,
        };
        receive
            .receive_reply_for_v2(
                purpose,
                &mut RootClientLoanV1::ExecutionNoApply(loan),
                RootClientControllerContextV2::ExecutionOwned,
                &mut funding,
            )
            .map_err(|_| RootExecutionNoApplyClientClosedV2)?;
        Ok(())
    }

    fn receive_confirmation(
        &mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'_, '_, '_>,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), Cause> {
        let native = self
            .state
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        let reply = &mut native.replies[2];
        let mut receive = RootReplyReceiveV1 {
            connection: &mut native.connection,
            received: &mut reply.received,
            preparation: &mut reply.preparation,
            extension: &mut reply.extension,
            chunk: &mut reply.chunk,
            data_failure: &mut native.data_failure,
            peer_before: &native.bookends[0].peer,
            profile,
            cutoff: native.cutoff,
        };
        let mut funding = RootClientFundingV1 {
            complete: self.complete,
            observations: &mut self.observations,
            wire: &mut self.wire,
            output: &mut self.output,
            received_bound: &mut self.received_bound,
            admission: &mut self.admission,
            funding_original: &mut self.funding_original,
        };
        receive.receive_fixed_reply_for_v2(aos_sandbox_protocol::root_policy_completion::ROOT_POLICY_POSITIVE_COMPLETION_BYTES_V2,
            &mut RootClientLoanV1::ExecutionNoApply(loan), RootClientControllerContextV2::ExecutionOwned, &mut funding)
            .map_err(|_| RootExecutionNoApplyClientClosedV2)?;
        Ok(())
    }

    fn observe_bookend(
        &mut self,
        index: usize,
        profile: &ProductionControllerNormalRootProfileV1,
        owed: bool,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        let native = self
            .state
            .as_mut()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        if native.bookends[index].sample.is_some() {
            return Err(self.refuse_reentry());
        }
        let result = if index == 0 {
            native.bookends[0].observe_once(profile, native.connection.stream().ok(),
                self.acquisition.as_ref().map(|one| &one.bookends[0]),
                native.origin, native.cutoff, owed)
        } else {
            let (previous, current) = native.bookends.split_at_mut(index);
            let baseline = matches!(previous[0].observed, Some(Ok(()))).then_some(&previous[0]);
            current[0].observe_once(profile, native.connection.stream().ok(), baseline,
                native.origin, native.cutoff, owed)
        };
        if result.is_err() {
            self.first.get_or_insert(First::Bookend(index));
            return Err(RootExecutionNoApplyClientClosedV2);
        }
        Ok(())
    }

    fn drain_owed(
        &mut self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        let index = self
            .pending
            .take()
            .ok_or(RootExecutionNoApplyClientClosedV2)?;
        self.observe_bookend(index, profile, true)
    }

    fn record_body(&mut self, index: usize, result: Result<(), Cause>) {
        if result.is_err() {
            self.first.get_or_insert(First::Body(index));
        }
        if let Some(native) = self.state.as_mut() {
            native.body[index] = Some(result);
        }
    }

    fn native(&self) -> Result<&Native, RootExecutionNoApplyClientClosedV2> {
        self.state
            .as_deref()
            .ok_or(RootExecutionNoApplyClientClosedV2)
    }

    fn require_phase(&self, phase: usize) -> Result<(), RootExecutionNoApplyClientClosedV2> {
        if self.first.is_some() || self.phase != phase || self.pending.is_some() {
            Err(RootExecutionNoApplyClientClosedV2)
        } else {
            Ok(())
        }
    }

    fn refuse_reentry(&mut self) -> RootExecutionNoApplyClientClosedV2 {
        self.reentry
            .get_or_insert(RootExecutionNoApplyClientClosedV2);
        self.first.get_or_insert(First::Reentry);
        RootExecutionNoApplyClientClosedV2
    }

    fn refuse_validation(&mut self, cause: Cause) -> RootExecutionNoApplyClientClosedV2 {
        if self.validation.is_none() {
            self.validation = Some(cause);
        }
        self.first.get_or_insert(First::Validation);
        RootExecutionNoApplyClientClosedV2
    }

    /// Borrows the actual native, financial or retained framing failure.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Entry => error(&self.entry),
            First::Acquisition => self
                .acquisition
                .as_ref()
                .and_then(|native| native.failure()),
            First::Funding => error(&self.admission),
            First::Bookend(index) => {
                let one = &self.state.as_ref()?.bookends[index];
                one.peer
                    .failure()
                    .or_else(|| error(&one.observed))
                    .or_else(|| one.clock.failure())
                    .or_else(|| error(&one.sample))
                    .or_else(|| error(&one.time))
            }
            First::Body(index) => {
                let native = self.state.as_ref()?;
                native
                    .entropy
                    .failure()
                    .or_else(|| error(&self.admission))
                    .or_else(|| native.connection.failure())
                    .or_else(|| error(&native.reporting))
                    .or_else(|| native.query_sender.failure())
                    .or_else(|| native.sender[index].failure())
                    .or_else(|| {
                        if index == 2 {
                            native.eof.failure().or_else(|| error(&native.ended))
                        } else {
                            None
                        }
                    })
                    .or_else(|| {
                        native
                            .replies
                            .iter()
                            .find_map(|r| r.chunk.as_ref().and_then(|c| c.failure(&r.received)))
                    })
                    .or_else(|| {
                        native.body[index]
                            .as_ref()?
                            .as_ref()
                            .err()
                            .map(|cause| &**cause as _)
                    })
            }
            First::Unwind | First::Reentry => self.reentry.as_ref().map(|cause| cause as _),
            First::Validation => self.validation.as_ref().map(|cause| cause.as_ref() as _),
        }
    }

    /// Reports whether the selected refusal belongs to the actual Source/C18 loan.
    #[must_use]
    pub fn original_failure_selected_v2(&self) -> bool {
        self.funding_original
            && matches!(
                self.first,
                Some(First::Entry | First::Body(_) | First::Acquisition)
            )
    }

    /// Borrows the actual completed floor while retaining its native Root original.
    ///
    /// # Errors
    /// Refuses incomplete/failed floor response or changed original C association.
    pub fn borrow_floor_v2<'root, 'turn: 'root>(
        &'root mut self,
        loan: &ControllerExecutionNoApplyClientLoanV2<'turn, '_, '_>,
    ) -> Result<RootExecutionNoApplyClientFloorBorrowV2<'root>, RootExecutionNoApplyClientClosedV2>
    {
        self.require_phase(2)?;
        if let Err(cause) = self.require_owned_cut(loan) {
            return Err(self.refuse_validation(cause));
        }
        Ok(RootExecutionNoApplyClientFloorBorrowV2 {
            profile: loan.root_transport_profile_v2(),
            owner: self,
        })
    }

    /// Borrows the same Root response after genuine Cprepare advanced its native cut.
    ///
    /// # Errors
    /// Refuses a missing Root post or a changed actual prepared-floor owner.
    pub fn borrow_prepared_floor_v2<'root, 'turn: 'root>(
        &'root mut self,
        loan: &mut ControllerExecutionNoApplyClientLoanV2<'turn, '_, '_>,
    ) -> Result<RootExecutionNoApplyClientFloorBorrowV2<'root>, RootExecutionNoApplyClientClosedV2>
    {
        self.require_phase(3)?;
        let native = self.native()?;
        let packet =
            ExecutionNoApplyFloorReplyDataV2::decode_v2(native.replies[1].received.bytes())
                .map_err(|_| RootExecutionNoApplyClientClosedV2)?;
        loan.require_prepared_root_floor_current_v2(packet.attestation)
            .map_err(|_| RootExecutionNoApplyClientClosedV2)?;
        Ok(RootExecutionNoApplyClientFloorBorrowV2 {
            profile: loan.root_transport_profile_v2(),
            owner: self,
        })
    }
}

struct OwedAfter<'owner> {
    owner: &'owner mut RootExecutionNoApplyClientOriginalV2,
    profile: &'owner ProductionControllerNormalRootProfileV1,
}

impl OwedAfter<'_> {
    fn finish(&mut self) {
        let _ = self.owner.drain_owed(self.profile);
    }
}

impl Drop for OwedAfter<'_> {
    fn drop(&mut self) {
        if self.owner.pending.is_some() {
            self.owner
                .reentry
                .get_or_insert(RootExecutionNoApplyClientClosedV2);
            self.owner.first.get_or_insert(First::Unwind);
            let _ = self.owner.drain_owed(self.profile);
        }
    }
}

impl Native {
    fn new(
        origin: RawPairedClockSample,
        cutoff: u64,
        preliminary: CurrentHostNoApplyLeaseDataV2,
        cut: [u8; 96],
        wall: [u8; 8],
        predecessor: [u8; 96],
        successor: [u8; 96],
    ) -> Self {
        Self {
            origin,
            source_cutoff: cutoff,
            cutoff: cutoff.min(preliminary.fields().native_cutoff),
            preliminary,
            preliminary_bytes: preliminary.encode_canonical(),
            cut,
            wall,
            predecessor,
            successor,
            entropy: RetainedKernelNonceOriginalV1::new(),
            nonce: None,
            query: None,
            query_bytes: [0; QUERY_BYTES_V2],
            query_digest: [0; 32],
            root_nonce: [0; 32],
            connection: Default::default(),
            connect: None,
            reporting: None,
            query_sender: Default::default(),
            query_sent: None,
            eof: Default::default(),
            eof_byte: [0],
            ended: None,
            sender: std::array::from_fn(|_| Default::default()),
            sent: std::array::from_fn(|_| None),
            scratch: [0; 4096],
            data_failure: None,
            replies: std::array::from_fn(|_| Reply {
                received: Default::default(),
                preparation: None,
                extension: None,
                chunk: None,
            }),
            confirmation: None,
            sent_ack: None,
            bookends: std::array::from_fn(|_| Bookend::new()),
            body: std::array::from_fn(|_| None),
            prepare_after: None,
            cas_after: None,
        }
    }

    fn subject(&self) -> ExecutionNoApplySubjectDataV2<'_> {
        ExecutionNoApplySubjectDataV2 {
            preliminary_lease: &self.preliminary_bytes,
            controller_cut: &self.cut,
            wall: &self.wall,
            predecessor: &self.predecessor,
            successor: &self.successor,
        }
    }

    fn current(&self) -> ExecutionNoApplyCurrentDataV2<'_> {
        ExecutionNoApplyCurrentDataV2 {
            query_digest: &self.query_digest,
            controller_cut: &self.cut,
            wall: &self.wall,
            predecessor: &self.predecessor,
            successor: &self.successor,
        }
    }
}

fn rows(input: [[u8; 32]; 3]) -> [u8; 96] {
    let mut bytes = [0; 96];
    for (chunk, digest) in bytes.chunks_exact_mut(32).zip(input) {
        chunk.copy_from_slice(&digest);
    }
    bytes
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, HistoryErrorV1> {
    slot.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(HistoryErrorV1::Malformed)
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
