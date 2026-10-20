//! Retains the original Root stream's U-funded continuation destinations.
//!
//! One bounded sender is reused only after the actual upper posts have passed.
//! Each incoming Root phase has its own strict receiver, so an unresolved native
//! prefix is never replaced. Signed and outcome transfers borrow their actual
//! completed producer's bytes; the transport copies only one indexed chunk.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, SubjectStreamReceiveGeometryV1};
use aos_sandbox_protocol::domain_ledger::create_q04_history::CLAIM_CHUNK_BYTES;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    continuation::{SIGNED_PREPARATION_PREFIX_BYTES_V1, SIGNED_BOUND_RECEIPT_BYTES_V1,
        USE_ADMITTED_RECEIPT_BYTES_V1},
    current_proofs::CURRENT_PROOFS_CHALLENGE_FRAME_BYTES_V1,
    outcome::{CONTROLLER_OUTCOME_RECEIPT_BYTES_V1, RELEASE_PROOFS_BYTES_V1,
        ROOT_CLOSED_RECEIPT_BYTES_V1, ROOT_OUTCOME_RECEIPT_BYTES_V1},
    root_open::RootOpenBodyDataV1,
    transport::{CHUNK_HEADER_BYTES, FRAME_HEADER_BYTES, INDEX_BYTES,
        FrameCoordinatesV1, FrameEnvelopeV1, FrameKindV1, TransferIndexV1},
    use_reserved::{USE_CURRENT_PROOFS_BYTES_V1, USE_RESERVED_RECEIPT_BYTES_V1},
};
use aos_sandbox_broker_session_protocol::projection::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES;

use crate::controller_resource_reservation::ResourceReservationErrorV1;
use crate::normal_root::CreateStorageRootPeerReceivingOriginalsV1;
use crate::policy_compiler::bounded_stream_io::{DeadlineStreamDirectionV1, SliceDeadlineStreamIoV1};

use super::subject::RootExactSubjectReceiveV1;

mod reserved_turn;
mod current;
mod signed;
mod outcome;
mod commit_refusal;
mod handoff_refusal;
mod closed;
pub(in crate::controller_resource_reservation::create_intake) use closed::OriginalCreateStorageRootClosedV1;
pub(super) mod releases;
pub(in crate::controller_resource_reservation::create_intake) use outcome::OriginalCreateStorageRootOutcomeV1;
pub(in crate::controller_resource_reservation::create_intake) use signed::OriginalCreateStorageRootSignedBoundV1;
pub(in crate::controller_resource_reservation::create_intake) use current::OriginalCreateStorageRootUseAdmittedV1;

const SEND_BYTES: usize = FRAME_HEADER_BYTES + CHUNK_HEADER_BYTES + CLAIM_CHUNK_BYTES;
const USE_ADMISSION_PREFIX_BYTES: usize = 20;
const OUTCOME_PREFIX_BYTES: usize = 16;

/// Describes the actual Root continuation's byte and observation bounds.
///
/// This is passive cost DATA. It cannot construct Ready, U, a socket, a peer
/// binding or a completed protocol phase. Every actual observation remains
/// charged monotonically against the same real returned U before native work.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateStorageRootUseTailShapeDataV1 {
    /// The concrete carriers, encoded stream traffic and Root PID1 traffic.
    pub receiving: ResourceVector,
    /// The closed maximum number of full Root observations including refusal posts.
    pub root_observations: usize,
    /// Cumulative Controller property reads, not resident intake archive slots.
    ///
    /// Two existing same-C Producer calls each execute two property reads per
    /// Root observation. Positive Producer scopes already settle and dispose.
    pub controller_observer_rows: usize,
}

/// Derives the original Root continuation's complete transport layout DATA.
///
/// The request width is the same normalized nonissuing Prepare width used by
/// both actual U issuers. Root peer and native subject geometry use their fixed
/// installed contracts. This function performs no allocation, IO or admission.
/// Pure controls contribute bytes, never resident namespace metadata entries.
///
/// # Errors
/// Rejects zero width, unrepresentable transfer geometry or checked overflow.
pub fn create_storage_root_use_tail_shape_v1(
    request_shape_bytes: usize,
) -> Result<CreateStorageRootUseTailShapeDataV1, ResourceReservationErrorV1> {
    let invalid = || ResourceReservationErrorV1::Conflict;
    if request_shape_bytes == 0 { return Err(invalid()); }
    let signed = request_shape_bytes.checked_mul(3)
        .and_then(|n| n.checked_add(SIGNED_PREPARATION_PREFIX_BYTES_V1)).ok_or_else(invalid)?;
    let outcome = request_shape_bytes.checked_add(AUTHENTICATED_RESPONSE_MAXIMUM_BYTES)
        .and_then(|n| n.checked_add(OUTCOME_PREFIX_BYTES)).ok_or_else(invalid)?;
    // Invoke the canonical index constructor: the bound is the same finite
    // chunk grammar that the actual sender will use, not a second count rule.
    let signed_index = TransferIndexV1::new(u64::try_from(signed).map_err(|_| invalid())?, [1; 32])
        .map_err(|_| invalid())?;
    let outcome_index = TransferIndexV1::new(u64::try_from(outcome).map_err(|_| invalid())?, [1; 32])
        .map_err(|_| invalid())?;
    let chunks = usize::try_from(signed_index.count()).ok()
        .and_then(|n| n.checked_add(usize::try_from(outcome_index.count()).ok()?)).ok_or_else(invalid)?;
    let admitted = request_shape_bytes.checked_mul(2)
        .and_then(|n| n.checked_add(USE_ADMISSION_PREFIX_BYTES + USE_ADMITTED_RECEIPT_BYTES_V1))
        .and_then(|n| n.checked_add(FRAME_HEADER_BYTES)).ok_or_else(invalid)?;
    let incoming = CURRENT_PROOFS_CHALLENGE_FRAME_BYTES_V1
        .checked_add(admitted)
        .and_then(|n| n.checked_add(FRAME_HEADER_BYTES + SIGNED_BOUND_RECEIPT_BYTES_V1))
        .and_then(|n| n.checked_add(FRAME_HEADER_BYTES + ROOT_OUTCOME_RECEIPT_BYTES_V1))
        .and_then(|n| n.checked_add(FRAME_HEADER_BYTES + ROOT_CLOSED_RECEIPT_BYTES_V1))
        .ok_or_else(invalid)?;
    let outgoing = (FRAME_HEADER_BYTES + USE_RESERVED_RECEIPT_BYTES_V1)
        .checked_add(FRAME_HEADER_BYTES + USE_CURRENT_PROOFS_BYTES_V1)
        .and_then(|n| n.checked_add(FRAME_HEADER_BYTES + CONTROLLER_OUTCOME_RECEIPT_BYTES_V1))
        .and_then(|n| n.checked_add(FRAME_HEADER_BYTES + RELEASE_PROOFS_BYTES_V1))
        .and_then(|n| n.checked_add(2 * (FRAME_HEADER_BYTES + INDEX_BYTES)))
        .and_then(|n| n.checked_add(chunks.checked_mul(FRAME_HEADER_BYTES + CHUNK_HEADER_BYTES)?))
        .and_then(|n| n.checked_add(signed))
        .and_then(|n| n.checked_add(outcome)).ok_or_else(invalid)?;
    // Every successful strict receive consumes at least one actual byte. Each
    // chunk has one subject comparison and one independently owed Root post.
    // Every outgoing frame has before/after observations. Seven incoming phase
    // comparisons (including the extra header and full-frame checks) each owe
    // one post; entry and final refusal have two spare
    // destinations. The second Cache flight adds its two full Root bookends.
    // Four additional observations bookend actual Prepare reservation and
    // its authenticated terminal. Positive disposal never refunds this ceiling.
    // Four real Root samples bookend the two original held releases.
    let sends = chunks.checked_add(6).ok_or_else(invalid)?;
    // Two additional observations bookend the actual Root8 Controller signing.
    let root_observations = incoming.checked_mul(2)
        .and_then(|n| n.checked_add(sends.checked_mul(2)?))
        .and_then(|n| n.checked_add(7 + 2 + 2 + 2 + 4 + 4)).ok_or_else(invalid)?;
    let controller_observer_rows = root_observations.checked_mul(4).ok_or_else(invalid)?;
    let property = root_use_observation_traffic_v1(root_observations)?;
    let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
        .map_err(|_| invalid())?;
    let (native_bytes, native_files) = geometry.receive_obligations_v1();
    // The final proof encoder holds three exact native receipts beside one
    // exact payload before copying into the same existing send scratch.
    let release_carriers = size_of::<([u8; aos_sandbox_protocol::domain_ledger::create_storage_history::outcome::HANDOFF_RETAINED_RECEIPT_BYTES_V1],
        [u8; aos_sandbox_protocol::domain_ledger::create_storage_history::outcome::RELEASED_RECEIPT_BYTES_V1],
        [u8; aos_sandbox_protocol::domain_ledger::create_storage_history::outcome::RELEASED_RECEIPT_BYTES_V1],
        [u8; RELEASE_PROOFS_BYTES_V1])>();
    let bytes = size_of::<RootUseTailOriginalsV1>().checked_mul(2)
        .and_then(|n| n.checked_add(release_carriers.checked_mul(2)?))
        // Full strict receiver buffers stay resident through their phase joins.
        .and_then(|n| n.checked_add(incoming))
        // Failed native receive plus its independently owed destination are
        // additional to those encoded bytes and the still-held Root peer pool.
        .and_then(|n| n.checked_add(native_bytes.checked_mul(2)?))
        .ok_or_else(invalid)?;
    let stream = u64::try_from(incoming.checked_add(outgoing).ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    Ok(CreateStorageRootUseTailShapeDataV1 {
        receiving: ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(D::OpenFiles, u64::try_from(native_files.checked_mul(2).ok_or_else(invalid)?)
                .map_err(|_| invalid())?)
            .with(D::NetworkBytes, stream.checked_add(property.get(D::NetworkBytes)).ok_or_else(invalid)?)
            .with(D::LogBytes, property.get(D::LogBytes)),
        root_observations,
        controller_observer_rows,
    })
}

// The same closed cost projection serves both the finite U ceiling and the
// actual next-frontier debit. The existing same-C Producer owns and retires
// its native peak independently; these cumulative bytes are never refunded.
pub(super) fn root_use_observation_traffic_v1(
    observations: usize,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let invalid = || ResourceReservationErrorV1::Conflict;
    let (root_wire, root_logs) = CreateStorageRootPeerReceivingOriginalsV1::query_traffic_v1(observations)
        .ok_or_else(invalid)?;
    let producer_calls = observations.checked_mul(2).ok_or_else(invalid)?;
    let (controller_wire, controller_logs) = crate::normal_root::ProductionControllerNormalRootProfileV1::
        create_storage_producer_traffic_bound_v1(producer_calls).ok_or_else(invalid)?;
    Ok(ResourceVector::ZERO
        .with(D::NetworkBytes, root_wire.checked_add(controller_wire).ok_or_else(invalid)?)
        .with(D::LogBytes, root_logs.checked_add(controller_logs).ok_or_else(invalid)?))
}

#[derive(Default)]
pub(super) struct RootUseTailOriginalsV1 {
    pub(super) invitation: RootExactSubjectReceiveV1,
    pub(super) admitted: RootExactSubjectReceiveV1,
    pub(super) signed_bound: RootExactSubjectReceiveV1,
    pub(super) outcome_ack: RootExactSubjectReceiveV1,
    pub(super) closed: RootExactSubjectReceiveV1,
    sender: RootTailSendOriginalsV1,
    coordinates: Option<TailCoordinatesV1>,
    signed_index: Option<Result<TransferIndexV1, HistoryErrorV1>>,
    pub(super) signed_turn: signed::RootSignedTurnOriginalsV1,
    outcome_index: Option<Result<TransferIndexV1, HistoryErrorV1>>,
    pub(super) outcome_turn: outcome::RootOutcomeTurnOriginalsV1,
    pub(super) commit_refusal: commit_refusal::RootUseCommitRefusalOriginalsV1,
    pub(super) handoff_refusal: handoff_refusal::RootHandoffRefusalOriginalsV1,
    pub(super) closed_turn: closed::RootClosedTurnOriginalsV1,
    pub(super) releases: releases::RootHeldReleaseTurnOriginalsV1,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<TailFailureV1>,
    attempted: bool,
    entered: bool,
    shape: Option<Result<CreateStorageRootUseTailShapeDataV1, ResourceReservationErrorV1>>,
    fixed: Option<Result<(), ResourceReservationErrorV1>>,
    wire_funding: Option<Result<(), ResourceReservationErrorV1>>,
    wire_used: u64,
    wire_limit: u64,
    reserved_settlement: Option<Result<(), HistoryErrorV1>>,
    invitation_settlement: Option<Result<(), HistoryErrorV1>>,
    invitation_geometry: Option<Result<SubjectStreamReceiveGeometryV1, aos_sandbox_linux::seqpacket::SeqpacketError>>,
    reserved_encoding: Option<Result<[u8; USE_RESERVED_RECEIPT_BYTES_V1], HistoryErrorV1>>,
    invitation_entry_post: Option<Result<(), super::CreateStorageRootExchangeClosedV1>>,
    property_paid: usize,
    property_limit: usize,
    before: Option<Result<(), super::CreateStorageRootExchangeClosedV1>>,
    sent_reserved: Option<Result<(), HistoryErrorV1>>,
    after: Option<Result<(), super::CreateStorageRootExchangeClosedV1>>,
    reserved_complete: bool,
    invitation_decoding: Option<Result<aos_sandbox_protocol::domain_ledger::create_storage_history::current_proofs::CurrentProofsChallengeDataV1, HistoryErrorV1>>,
    invitation_post: Option<Result<(), super::CreateStorageRootExchangeClosedV1>>,
    invitation_complete: bool,
    proofs_entered: bool,
    admitted_cutoff: Option<u64>,
    proofs_before: Option<Result<(), super::CreateStorageRootExchangeClosedV1>>,
    proofs_encoding: Option<Result<[u8; USE_CURRENT_PROOFS_BYTES_V1], HistoryErrorV1>>,
    proofs_sent: Option<Result<(), HistoryErrorV1>>,
    proofs_after: Option<Result<(), super::CreateStorageRootExchangeClosedV1>>,
    proofs_settlement: Option<Result<(), HistoryErrorV1>>,
    proofs_complete: bool,
    admitted_geometry: Option<Result<SubjectStreamReceiveGeometryV1, aos_sandbox_linux::seqpacket::SeqpacketError>>,
    admitted_entry_post: Option<Result<(), super::CreateStorageRootExchangeClosedV1>>,
    admitted_received: Option<Result<(), super::CreateStorageRootExchangeClosedV1>>,
    admitted_body: Option<Result<aos_sandbox_protocol::domain_ledger::create_storage_history::continuation::UseAdmittedBodyDataV1, HistoryErrorV1>>,
    admitted_post: Option<Result<(), super::CreateStorageRootExchangeClosedV1>>,
    admitted_settlement: Option<Result<(), HistoryErrorV1>>,
    admitted_complete: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TailFailureV1 { Geometry, Funding, Before, Send, After, ReservedSettlement, InvitationGeometry, ReceiveInvitation,
    DecodeInvitation, InvitationPost, InvitationSettlement, ProofsBefore,
    ProofsEncoding, ProofsSend, ProofsAfter, ProofsSettlement, AdmittedGeometry,
    AdmittedReceive, AdmittedComparison, AdmittedPost, AdmittedSettlement }

impl RootUseTailOriginalsV1 {
    pub(super) fn started(&self) -> bool { self.attempted }

    pub(super) fn paid_root_observations_v1(&self) -> usize {
        self.property_paid
    }

    pub(super) fn admitted_cutoff_v1(&self) -> Result<u64, ResourceReservationErrorV1> {
        self.admitted_cutoff.ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn second_invitation_complete_v1(&self) -> bool {
        self.invitation_complete
    }

    pub(super) fn mark_use_funding_failure_v1(&mut self) {
        self.first.get_or_insert(TailFailureV1::Funding);
    }

    pub(super) fn proofs_before_is_owed_v1(&self) -> bool {
        self.proofs_entered && self.proofs_before.is_none()
    }

    pub(super) fn proofs_after_is_owed_v1(&self) -> bool {
        self.proofs_entered && self.proofs_after.is_none()
    }

    pub(super) fn admitted_entry_is_owed_v1(&self) -> bool {
        self.proofs_complete && self.wire_funding.is_some() && self.admitted_entry_post.is_none()
    }

    pub(super) fn admitted_comparison_is_owed_v1(&self) -> bool {
        self.admitted_received.is_some() && self.admitted_body.is_some() && self.admitted_post.is_none()
    }

    pub(super) fn funding_failure_is_selected(&self) -> bool {
        self.first == Some(TailFailureV1::Funding)
    }

    pub(super) fn before_is_owed(&self) -> bool { self.entered && self.before.is_none() }

    pub(super) fn after_is_owed(&self) -> bool { self.entered && self.after.is_none() }

    pub(super) fn invitation_entry_post_is_owed(&self) -> bool {
        self.entered && self.reserved_complete && self.wire_funding.is_some()
            && self.invitation_entry_post.is_none()
    }

    pub(super) fn invitation_post_is_owed(&self) -> bool {
        self.entered && self.invitation_decoding.is_some() && self.invitation_post.is_none()
    }

    pub(super) fn failure<'cause>(&'cause self,
        peer: &'cause CreateStorageRootPeerReceivingOriginalsV1,
        property_geometry: &'cause Option<Result<ResourceVector, ResourceReservationErrorV1>>,
        property_funding: &'cause Option<Result<(), ResourceReservationErrorV1>>,
    ) -> Option<&'cause (dyn Error + 'static)> {
        match self.first {
            Some(TailFailureV1::Geometry) => cause(&self.shape),
            Some(TailFailureV1::Funding) => cause(&self.fixed).or_else(|| cause(&self.wire_funding)).or_else(|| cause(property_geometry))
                .or_else(|| cause(property_funding)),
            Some(TailFailureV1::Before) => peer.failure().or_else(|| cause(&self.before)),
            Some(TailFailureV1::Send) => cause(&self.reserved_encoding).or_else(|| self.sender.failure())
                .or_else(|| cause(&self.sent_reserved)),
            Some(TailFailureV1::After) => peer.failure().or_else(|| cause(&self.after)),
            Some(TailFailureV1::ReservedSettlement) => cause(&self.reserved_settlement),
            Some(TailFailureV1::InvitationGeometry) => cause(&self.invitation_geometry),
            Some(TailFailureV1::InvitationSettlement) => cause(&self.invitation_settlement),
            Some(TailFailureV1::ProofsBefore) => peer.failure().or_else(|| cause(&self.proofs_before)),
            Some(TailFailureV1::ProofsEncoding) => cause(&self.proofs_encoding),
            Some(TailFailureV1::ProofsSend) => self.sender.failure().or_else(|| cause(&self.proofs_sent)),
            Some(TailFailureV1::ProofsAfter) => peer.failure().or_else(|| cause(&self.proofs_after)),
            Some(TailFailureV1::ProofsSettlement) => cause(&self.proofs_settlement),
            Some(TailFailureV1::AdmittedGeometry) => cause(&self.admitted_geometry),
            Some(TailFailureV1::AdmittedReceive) => self.admitted.failure(peer),
            Some(TailFailureV1::AdmittedComparison) => cause(&self.admitted_body),
            Some(TailFailureV1::AdmittedPost) => peer.failure().or_else(|| cause(&self.admitted_post)),
            Some(TailFailureV1::AdmittedSettlement) => cause(&self.admitted_settlement),
            Some(TailFailureV1::ReceiveInvitation) => self.invitation.failure(peer),
            Some(TailFailureV1::DecodeInvitation) => cause(&self.invitation_decoding),
            Some(TailFailureV1::InvitationPost) => peer.failure().or_else(|| cause(&self.invitation_post)),
            None => None,
        }
    }
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref().and_then(|v| v.as_ref().err()).map(|cause| cause as _)
}

struct RootTailSendOriginalsV1 {
    bytes: [u8; SEND_BYTES],
    encoding: Option<Result<usize, HistoryErrorV1>>,
    native: Option<SliceDeadlineStreamIoV1>,
}

impl Default for RootTailSendOriginalsV1 {
    fn default() -> Self { Self { bytes: [0; SEND_BYTES], encoding: None, native: None } }
}

impl RootTailSendOriginalsV1 {
    // The genuine Root loan invokes this only after actual same-U admission.
    // Borrowed payloads must come from its completed native/Security owners.
    fn prepare_once(&mut self, coordinates: FrameCoordinatesV1, payload: &[u8])
        -> Result<(), HistoryErrorV1>
    {
        self.prepare_parts_once(coordinates, &[], payload)
    }

    // Both ordinary fixed payloads and indexed chunks use this same single
    // prepaid scratch and frame encoder; no whole signed bundle is copied.
    fn prepare_parts_once(&mut self, coordinates: FrameCoordinatesV1,
        prefix: &[u8], payload: &[u8],
    ) -> Result<(), HistoryErrorV1> {
        if self.encoding.is_some() || self.native.is_some() { return Err(HistoryErrorV1::Correlation); }
        self.encoding = Some((|| {
            let split = FRAME_HEADER_BYTES.checked_add(prefix.len()).ok_or(HistoryErrorV1::Extent)?;
            let length = split.checked_add(payload.len()).ok_or(HistoryErrorV1::Extent)?;
            if length > SEND_BYTES { return Err(HistoryErrorV1::Extent); }
            self.bytes[FRAME_HEADER_BYTES..split].copy_from_slice(prefix);
            self.bytes[split..length].copy_from_slice(payload);
            let header = coordinates.encode_header(&self.bytes[FRAME_HEADER_BYTES..length])?;
            self.bytes[..FRAME_HEADER_BYTES].copy_from_slice(&header);
            Ok(length)
        })());
        positive(&self.encoding).map(|_| ())
    }

    // The existing scratch receives only this indexed range. Both original
    // authenticated packets remain continuously borrowed from their real owner.
    fn prepare_outcome_chunk_once(&mut self, coordinates: FrameCoordinatesV1,
        index: TransferIndexV1, chunk: u32,
        bundle: aos_sandbox_protocol::domain_ledger::create_storage_history::outcome::OutcomeBundleDataV1<'_>,
    ) -> Result<(), HistoryErrorV1> {
        if self.encoding.is_some() || self.native.is_some() { return Err(HistoryErrorV1::Correlation); }
        self.encoding = Some((|| {
            let offset = usize::try_from(chunk).ok().and_then(|n| n.checked_mul(CLAIM_CHUNK_BYTES))
                .ok_or(HistoryErrorV1::Extent)?;
            let total = bundle.encoded_bytes()?;
            let payload_bytes = total.checked_sub(offset).ok_or(HistoryErrorV1::Extent)?.min(CLAIM_CHUNK_BYTES);
            if payload_bytes == 0 { return Err(HistoryErrorV1::Extent); }
            let payload_start = FRAME_HEADER_BYTES + CHUNK_HEADER_BYTES;
            let length = payload_start.checked_add(payload_bytes).ok_or(HistoryErrorV1::Extent)?;
            bundle.encode_range_into_v1(offset, &mut self.bytes[payload_start..length])?;
            let chunk_header = index.encode_chunk_header(chunk, &self.bytes[payload_start..length])?;
            self.bytes[FRAME_HEADER_BYTES..payload_start].copy_from_slice(&chunk_header);
            let frame_header = coordinates.encode_header(&self.bytes[FRAME_HEADER_BYTES..length])?;
            self.bytes[..FRAME_HEADER_BYTES].copy_from_slice(&frame_header);
            Ok(length)
        })());
        positive(&self.encoding).map(|_| ())
    }

    fn send_once(&mut self, stream: &mut RetainedUnixStream, cutoff: u64)
        -> Result<(), HistoryErrorV1>
    {
        let length = *positive(&self.encoding)?;
        if self.native.is_some() { return Err(HistoryErrorV1::Correlation); }
        self.native = Some(Default::default());
        self.native.as_mut().ok_or(HistoryErrorV1::Correlation)?.run_prefix_once(
            stream, &mut self.bytes, length, cutoff, DeadlineStreamDirectionV1::Write,
        )
    }

    // Only the actual outer loan may call this after all independent posts.
    // No bool, parsed receipt or caller-supplied Result can authorize disposal.
    fn dispose_after_posts_once(&mut self) -> Result<(), HistoryErrorV1> {
        let native = self.native.as_ref().ok_or(HistoryErrorV1::Correlation)?;
        if !native.completed_exact() || native.failure().is_some() { return Err(HistoryErrorV1::Correlation); }
        drop(self.native.take());
        self.encoding = None;
        Ok(())
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.encoding.as_ref().and_then(|v| v.as_ref().err()).map(|e| e as _)
            .or_else(|| self.native.as_ref().and_then(SliceDeadlineStreamIoV1::failure))
    }
}

// One monotonically advanced global sequence counts every actual message,
// including both invitations and each indexed chunk. Kind codes are unrelated.
struct TailCoordinatesV1 {
    hello: RootOpenBodyDataV1,
    next: u64,
}

impl TailCoordinatesV1 {
    fn new(hello: RootOpenBodyDataV1, ready: TransferIndexV1) -> Result<Self, HistoryErrorV1> {
        if ready.digest() != hello.open.ready { return Err(HistoryErrorV1::Correlation); }
        Ok(Self { hello, next: u64::from(ready.count()).checked_add(6).ok_or(HistoryErrorV1::Extent)? })
    }

    fn current(&self, kind: FrameKindV1) -> FrameCoordinatesV1 {
        FrameCoordinatesV1 { kind, lane: self.hello.open.lane, sequence: self.next,
            root_nonce: self.hello.root_nonce, controller_nonce: self.hello.open.controller_nonce }
    }

    fn advance_after_posts(&mut self) -> Result<(), HistoryErrorV1> {
        self.next = self.next.checked_add(1).ok_or(HistoryErrorV1::Extent)?;
        Ok(())
    }
}

fn positive<T>(value: &Option<Result<T, HistoryErrorV1>>) -> Result<&T, HistoryErrorV1> {
    value.as_ref().and_then(|v| v.as_ref().ok()).ok_or(HistoryErrorV1::Correlation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    fn coordinates() -> FrameCoordinatesV1 {
        FrameCoordinatesV1 { kind: FrameKindV1::UseReserved, lane: [1; 16],
            sequence: 6, root_nonce: [2; 16], controller_nonce: [3; 16] }
    }

    #[test]
    fn sender_uses_original_deadline_engine_and_canonical_frame_bytes() {
        let (writer, mut reader) = UnixStream::pair().expect("stream pair");
        let fd: OwnedFd = writer.into();
        let mut retained = RetainedUnixStream::from_owned_retaining_v1(fd).expect("original stream");
        let mut sender = RootTailSendOriginalsV1::default();
        let expected = coordinates();
        sender.prepare_once(expected, b"actual retained receipt").expect("prepare");

        sender.send_once(&mut retained, u64::MAX).expect("write");
        let mut bytes = vec![0; FRAME_HEADER_BYTES + b"actual retained receipt".len()];
        reader.read_exact(&mut bytes).expect("same stream read");

        let envelope = FrameEnvelopeV1::decode(&bytes, expected).expect("canonical frame");
        assert_eq!(envelope.payload(), b"actual retained receipt");
        assert!(sender.native.as_ref().is_some_and(SliceDeadlineStreamIoV1::completed_exact));
        assert!(sender.send_once(&mut retained, u64::MAX).is_err());
        // This mechanical test exercises only scratch disposal. The production
        // Root loan must first close its independent native/currentness posts.
        sender.dispose_after_posts_once().expect("positive scratch disposal");
        assert!(sender.native.is_none());
    }

    #[test]
    fn sender_keeps_actual_timeout_refusal_and_disallows_positive_disposal() {
        let (writer, _reader) = UnixStream::pair().expect("stream pair");
        let fd: OwnedFd = writer.into();
        let mut retained = RetainedUnixStream::from_owned_retaining_v1(fd).expect("original stream");
        let mut sender = RootTailSendOriginalsV1::default();
        sender.prepare_once(coordinates(), b"receipt").expect("prepare");

        assert!(sender.send_once(&mut retained, 0).is_err());
        let first = sender.failure().expect("cutoff cause") as *const dyn Error;
        assert!(sender.dispose_after_posts_once().is_err());
        assert!(sender.prepare_once(coordinates(), b"other").is_err());
        assert!(std::ptr::eq(first, sender.failure().expect("same cause")));
        assert!(sender.native.is_some());
    }

    #[test]
    fn concrete_tail_shape_accounts_for_header_and_zero_namespace_controls() {
        let shape = create_storage_root_use_tail_shape_v1(128).expect("bounded shape");

        assert_eq!(shape.receiving.get(D::MetadataEntries), 0);
        assert_eq!(shape.controller_observer_rows, shape.root_observations * 4);
        assert!(shape.receiving.get(D::MemoryBytes) >= (2 * size_of::<RootUseTailOriginalsV1>()) as u64);
        assert_eq!(FRAME_HEADER_BYTES + USE_ADMISSION_PREFIX_BYTES + USE_ADMITTED_RECEIPT_BYTES_V1, 592);
        assert!(create_storage_root_use_tail_shape_v1(usize::MAX).is_err());
        assert!(create_storage_root_use_tail_shape_v1(0).is_err());
    }
}
