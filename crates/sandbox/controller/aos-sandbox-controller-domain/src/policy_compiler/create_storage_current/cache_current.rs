//! Joins the actual independent Root and Controller Cache signer halves.
//!
//! Root begins its own retained signer flight before sending invitation19. The
//! same authenticated Controller sends Phase4; only then does Root finish its
//! independent signer flight and verify the identical packet using its own pin.
//! This component supplies neither U nor complete typed-B/current-cut authority.

use std::error::Error as StdError;
use std::mem::size_of;
use std::os::unix::net::UnixStream;
use std::path::Path;

use aos_sandbox_broker::cache_current_signer_exchange::{
    CacheCurrentSignerExchangeClosedV1 as SignerClosed,
    CacheCurrentSignerExchangeOriginalsV1,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::{
    RetainedSubjectStreamReadV1, SubjectStreamReadErrorV1, SubjectStreamReceiveGeometryV1,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    cache_held::{
        CACHE_HELD_RECEIPT_BYTES_V1, CacheHeldReceiptDataV1,
        current_proof::{
            CacheCurrentProofDataErrorV1, CacheCurrentProofVerifyCaptureV1,
            current_cache_challenge_digest_v1, verify_current_cache_proof_retaining_v1,
        },
    },
    current_proofs::CurrentProofsChallengeDataV1,
    ready::{ReadyBundleDataV1, InputsReadyNativeReceiptDataV1},
    root_open::RootHelloDataV1,
    transport::FRAME_HEADER_BYTES,
    use_authorized::CURRENT_PROOFS_PAYLOAD_BYTES_V1,
};

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{JournalError, ProtectedJournalCurrentnessOriginalsV1};
use crate::normal_root::{
    NormalRootStartupErrorV1, RootControllerChunkSubjectSampleV1, RootPolicyAcceptedFlightV1,
};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use aos_sandbox_broker::bounded_stream_io::FixedDeadlineStreamIoV1;

use super::{
    RootCreateStorageCurrentErrorV1 as Error,
    bundle_ownership::RootCurrentBundleOwnershipStateV1,
    pins::RootCurrentPinsStateV1,
    ready::{RootCurrentReadyStateV1, subject::RootCurrentChunkReceivingV1},
    root_open::{RootCurrentOpenReadbackV1, RootCurrentOpenStateV1},
    source_current::RootCurrentSourceExchangeStateV1,
};
use super::super::{
    root_current_writers::RootCreateStorageCurrentWritersV1,
    protected_owner::{PROTECTED_POLICY_ROOT, POLICY_AUTHORITY_JOURNAL, POLICY_STATE_JOURNAL},
};

use super::use_reserved::{RootCurrentProofTurnV1, RootCurrentUseReservedStateV1};
use super::use_authorized::RootCurrentUseAuthorizedStateV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::{
    UseCurrentProofsDataV1, USE_CURRENT_PROOFS_BYTES_V1,
    UseReservedNativeReceiptDataV1,
};

use aos_sandbox_policy::cache_current_data::{
    PROOFS_FRAME_BYTES, USE_PROOFS_FRAME_BYTES, received_proofs_v1,
    received_use_proofs_v1, require_same_reserved_receipt_v1, require_observed_clock,
};

const HELLO_BYTES: usize = 612;
const INVITATION_BYTES: usize = 248;
type WriterResult = Option<Result<(), JournalError>>;

pub(crate) struct RootCurrentCacheProofStateV1 {
    turn_binding: Option<Result<Option<[u8; 32]>, Error>>,
    framing: Option<Result<(), HistoryErrorV1>>,
    configuration: Option<Result<(u32, u32, u32), NormalRootStartupErrorV1>>,
    hello: [u8; HELLO_BYTES],
    hello_copy: Option<Result<(), HistoryErrorV1>>,
    before: [ProtectedJournalCurrentnessOriginalsV1; 2],
    before_result: [WriterResult; 2],
    before_readback: Option<Result<(), JournalError>>,
    before_clock: RetainedKernelPairedClockAttemptV1,
    before_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_cutoff: Option<Result<(), JournalError>>,
    transport: CacheCurrentSignerExchangeOriginalsV1,
    begin: Option<Result<(), SignerClosed>>,
    invitation: [u8; INVITATION_BYTES],
    invitation_encoding: Option<Result<(), HistoryErrorV1>>,
    invitation_io: FixedDeadlineStreamIoV1<INVITATION_BYTES>,
    sent: Option<Result<(), HistoryErrorV1>>,
    geometry: Result<SubjectStreamReceiveGeometryV1, aos_sandbox_linux::seqpacket::SeqpacketError>,
    received_frame: RetainedSubjectStreamReadV1,
    preparation: Option<Result<(), SubjectStreamReadErrorV1>>,
    chunks: RootCurrentChunkReceivingV1,
    received: Option<Result<(), Error>>,
    proofs_binding: Option<Result<(), HistoryErrorV1>>,
    finish: Option<Result<(), SignerClosed>>,
    packet: Option<Result<(), SignerClosed>>,
    verification: CacheCurrentProofVerifyCaptureV1,
    verified: Option<Result<(), CacheCurrentProofDataErrorV1>>,
    association: Option<Result<(), HistoryErrorV1>>,
    primary: Option<Result<(), Error>>,
    after: [ProtectedJournalCurrentnessOriginalsV1; 2],
    after_result: [WriterResult; 2],
    after_readback: Option<Result<(), JournalError>>,
    peer: Option<Result<(), NormalRootStartupErrorV1>>,
    after_clock: RetainedKernelPairedClockAttemptV1,
    after_sample: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_cutoff: Option<Result<(), JournalError>>,
    interval: Option<Result<(), aos_sandbox_model::OwnershipLeaseVerificationError>>,
    cross_clock: Option<Result<(), HistoryErrorV1>>,
    complete: bool,
    entered: bool,
    closed: Option<Error>,
}

impl RootCurrentCacheProofStateV1 {
    pub(super) fn new() -> Self {
        Self {
            turn_binding: None,
            framing: None,
            configuration: None,
            hello: [0; HELLO_BYTES],
            hello_copy: None,
            before: std::array::from_fn(|_| ProtectedJournalCurrentnessOriginalsV1::new()),
            before_result: [None, None],
            before_readback: None,
            before_clock: Default::default(),
            before_sample: None,
            before_cutoff: None,
            transport: CacheCurrentSignerExchangeOriginalsV1::new(),
            begin: None,
            invitation: [0; INVITATION_BYTES],
            invitation_encoding: None,
            invitation_io: Default::default(),
            sent: None,
            geometry: RootControllerChunkSubjectSampleV1::receive_geometry_v1(),
            received_frame: RetainedSubjectStreamReadV1::new(),
            preparation: None,
            chunks: Default::default(),
            received: None,
            proofs_binding: None,
            finish: None,
            packet: None,
            verification: CacheCurrentProofVerifyCaptureV1::new(),
            verified: None,
            association: None,
            primary: None,
            after: std::array::from_fn(|_| ProtectedJournalCurrentnessOriginalsV1::new()),
            after_result: [None, None],
            after_readback: None,
            peer: None,
            after_clock: Default::default(),
            after_sample: None,
            after_cutoff: None,
            interval: None,
            cross_clock: None,
            complete: false,
            entered: false,
            closed: None,
        }
    }

    pub(crate) fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::JournalTooLarge;
        let (transport_bytes, transport_files, transport_cells) =
            CacheCurrentSignerExchangeOriginalsV1::additional_receiving_shape_v1().ok_or_else(invalid)?;
        let verification = CacheCurrentProofVerifyCaptureV1::receiving_additional_inline_bytes_v1()
            .and_then(|bytes| bytes.checked_add(
                CacheCurrentProofVerifyCaptureV1::receiving_additional_heap_bytes_v1()?,
            ))
            .ok_or_else(invalid)?;
        let bytes = size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(transport_bytes))
            .and_then(|bytes| bytes.checked_add(verification))
            .and_then(|bytes| bytes.checked_add(PROOFS_FRAME_BYTES))
            .and_then(|bytes| bytes.checked_add(
                aos_sandbox_policy::cache_current_data::fixed_framing_receiving_bytes_v1()?))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(
                aos_sandbox_policy::cache_current_data::FRAMING_INTERFACE_CONTROL_BYTES_V1))
            .ok_or_else(invalid)?;
        // Native transport/model providers retain their existing namespace
        // bounds. Pure parent, framing and identity carriers add only bytes.
        let cells = Some(transport_cells)
            .and_then(|cells| cells.checked_add(
                CacheCurrentProofVerifyCaptureV1::receiving_metadata_cells_v1()?,
            ))
            .and_then(|cells| cells.checked_add(
                FixedDeadlineStreamIoV1::<INVITATION_BYTES>::receiving_metadata_cells_v1(),
            ))
            .ok_or_else(invalid)?;
        let mut demand = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| invalid())?)
            .with(D::OpenFiles, u64::try_from(transport_files).map_err(|_| invalid())?)
            .with(D::NetworkBytes, (INVITATION_BYTES + PROOFS_FRAME_BYTES) as u64);
        let chunk_clock = RootCurrentChunkReceivingV1::additional_clock_demand_v1()?;
        demand = demand.checked_add(RootCurrentChunkReceivingV1::additional_receiving_demand_v1()?)
            .and_then(|value| value.checked_add(chunk_clock)).map_err(|_| invalid())?;
        demand = demand.checked_add(ReadyBundleDataV1::fixed_framing_receiving_demand_v1().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        demand = demand.checked_add(root_current_post_backing_demand_v1()?)
            .map_err(|_| invalid())?;
        Ok(demand.with(D::OutputBytes, demand.get(D::MemoryBytes)))
    }

    pub(crate) fn use_fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        // The second turn retains a distinct SAME transport/verification owner.
        // Its larger forwarded frame and actual borrowed codec carriers add
        // bytes; no Rust-field MetadataEntries charge is introduced.
        let extra = (USE_PROOFS_FRAME_BYTES - PROOFS_FRAME_BYTES)
            .checked_add(4 * size_of::<UseCurrentProofsDataV1<'static>>())
            .and_then(|bytes| bytes.checked_add(4 * size_of::<UseReservedNativeReceiptDataV1<'static>>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        Self::fixed_demand_v1()?.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, extra)
            .with(D::NetworkBytes, (USE_PROOFS_FRAME_BYTES - PROOFS_FRAME_BYTES) as u64))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn exchange_once(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        original: &UnixStream,
        root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
        source: &RootCurrentSourceExchangeStateV1,
        pins: &RootCurrentPinsStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1,
    ) -> Result<(), Error> {
        self.exchange_for_turn(flight, writers, original, root, ready, source, pins,
            ownership, RootCurrentProofTurnV1::Initial)
    }

    pub(super) fn exchange_use_once(&mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>, writers: &mut RootCreateStorageCurrentWritersV1,
        original: &UnixStream, root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        source: &RootCurrentSourceExchangeStateV1, pins: &RootCurrentPinsStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1, authorization: &RootCurrentUseAuthorizedStateV1,
        reserved: &RootCurrentUseReservedStateV1,
    ) -> Result<(), Error> {
        self.exchange_for_turn(flight, writers, original, root, ready, source, pins,
            ownership, RootCurrentProofTurnV1::Reserved { authorization, reserved })
    }

    fn exchange_for_turn(&mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>, writers: &mut RootCreateStorageCurrentWritersV1,
        original: &UnixStream, root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        source: &RootCurrentSourceExchangeStateV1, pins: &RootCurrentPinsStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1, turn: RootCurrentProofTurnV1<'_>,
    ) -> Result<(), Error> {
        if self.entered || self.closed.is_some() {
            self.closed.get_or_insert(Error::Original);
            return Err(Error::Original);
        }
        self.entered = true;
        self.primary = Some(self.exchange_inner(
            flight, writers, original, root, ready, source, pins, ownership, turn,
        ));

        // Entry occurs only after the genuine fixed R provision. Every entered
        // primary, including framing/connect/invitation/signature failures,
        // therefore owes the same independent original posts.
        observe_turn_writers(writers, root, turn, &mut self.after, &mut self.after_result,
            &mut self.after_readback);
        self.peer = Some(flight.recheck_current_controller_peer_once());
        self.after_sample = Some(self.after_clock.observe_once(None));
        self.after_cutoff = Some(require_clock(root, source, &self.after_sample));
        if let (Some(Ok(before)), Some(Ok(after))) = (&self.before_sample, &self.after_sample) {
            self.interval = Some(before.validate_later_sample(*after));
            if let Some(body) = self.verification.body() {
                self.cross_clock = Some(require_observed_clock(body.sample, *before, *after));
            }
        }
        self.complete = matches!(self.primary, Some(Ok(())))
            && self.after_result.iter().all(|result| matches!(result, Some(Ok(()))))
            && matches!(self.after_readback, Some(Ok(_)))
            && matches!(self.peer, Some(Ok(())))
            && matches!(self.after_cutoff, Some(Ok(())))
            && matches!(self.interval, Some(Ok(())))
            && matches!(self.cross_clock, Some(Ok(())))
            && self.chunks.native_sample_disposed()
            && self.failure_with_original(flight).is_none();
        if self.complete {
            Ok(())
        } else {
            Err(Error::History)
        }
    }

    fn exchange_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        original: &UnixStream,
        root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1,
        source: &RootCurrentSourceExchangeStateV1,
        pins: &RootCurrentPinsStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1,
        turn: RootCurrentProofTurnV1<'_>,
    ) -> Result<(), Error> {
        ownership.require_complete_v1()?;
        source.require_complete_v1()?;
        self.turn_binding = Some(turn.authorization_checksum_v1(root));
        positive(&self.turn_binding)?;
        let raw = ready.raw_ready_bytes()?;
        let bundle = match ReadyBundleDataV1::borrow_field_framing_data_v1(raw) {
            Ok(bundle) => {
                self.framing = Some(Ok(()));
                bundle
            }
            Err(cause) => {
                self.framing = Some(Err(cause));
                return Err(Error::History);
            }
        };
        self.configuration = Some(
            flight.current_cut_startup().map_err(|_| Error::Original)?
                .current_cache_signer_identity_data_v1(),
        );
        let (uid, gid, socket_gid) = *positive(&self.configuration)?;
        self.hello_copy = Some(ready.original_hello_frame_v1(root, &mut self.hello));
        positive(&self.hello_copy)?;
        let body = root.completed_body()?;
        let hello = RootHelloDataV1::decode(&self.hello, body.open).map_err(|_| Error::History)?;
        let held: &[u8; CACHE_HELD_RECEIPT_BYTES_V1] = bundle.cache_held.try_into()
            .map_err(|_| Error::History)?;
        let cutoff = source.original_cutoff_v1()?;
        observe_turn_writers(writers, root, turn, &mut self.before, &mut self.before_result,
            &mut self.before_readback);
        for result in &self.before_result {
            positive(result)?;
        }
        positive(&self.before_readback)?;
        self.before_sample = Some(self.before_clock.observe_once(None));
        self.before_cutoff = Some(require_clock(root, source, &self.before_sample));
        positive(&self.before_cutoff)?;

        // Actual Root-first begin returns after write+SHUT_WR without reading.
        self.begin = Some(self.transport.begin_root_half_once(
            &self.hello, held, uid, gid, socket_gid, cutoff,
        ));
        positive(&self.begin)?;
        let index = ready.original_transfer_index_v1()?;
        let invitation = CurrentProofsChallengeDataV1 {
            lane: body.open.lane,
            root_open: hello.checksum,
            root_nonce: body.root_nonce,
            ready: body.open.ready,
            challenge: current_cache_challenge_digest_v1(&self.hello, held),
        };
        self.invitation_encoding = Some(match turn {
            RootCurrentProofTurnV1::Initial => invitation.encode_frame(&hello, index),
            RootCurrentProofTurnV1::Reserved { .. } => invitation.encode_use_frame(&hello, index),
        }.map(|bytes| self.invitation = bytes));
        positive(&self.invitation_encoding)?;
        let mut stream = original;
        self.sent = Some(self.invitation_io.run_once(
            &mut stream, &mut self.invitation, cutoff, DeadlineStreamDirectionV1::Write,
        ));
        positive(&self.sent)?;

        self.preparation = Some(self.received_frame.prepare_exact_once(match turn {
            RootCurrentProofTurnV1::Initial => PROOFS_FRAME_BYTES,
            RootCurrentProofTurnV1::Reserved { .. } => USE_PROOFS_FRAME_BYTES,
        }));
        positive(&self.preparation)?;
        let geometry = *self.geometry.as_ref().map_err(|_| Error::History)?;
        self.received = Some(self.chunks.receive_exact_until(
            flight, original, &mut self.received_frame, root, &geometry, cutoff,
        ));
        positive(&self.received)?;
        self.proofs_binding = Some((|| {
            match turn {
                RootCurrentProofTurnV1::Initial => {
                    let proofs = received_proofs_v1(self.received_frame.bytes(), hello, index)?;
                    if proofs.cache_packet.len() != 1064 { return Err(HistoryErrorV1::Extent); }
                    proofs.controller.body(body.open.lane)?.require_bundle(raw)
                }
                RootCurrentProofTurnV1::Reserved { reserved, .. } => {
                    let proofs = received_use_proofs_v1(self.received_frame.bytes(), hello, index)?;
                    let expected = reserved.received_receipt_v1(body.open.lane)
                        .map_err(|_| HistoryErrorV1::Correlation)?;
                    require_same_reserved_receipt_v1(proofs.controller, expected)
                }
            }
        })());
        positive(&self.proofs_binding)?;
        self.finish = Some(self.transport.finish_once());
        positive(&self.finish)?;
        let packet = match self.transport.packet() {
            Ok(packet) => {
                self.packet = Some(Ok(()));
                packet
            }
            Err(cause) => {
                self.packet = Some(Err(cause));
                return Err(Error::History);
            }
        };
        let pin = pins.cache_signer_v1()?;
        self.verified = Some(verify_current_cache_proof_retaining_v1(
            packet, pin.verifying_key(), pin.generation(), &mut self.verification,
        ));
        positive(&self.verified)?;
        self.association = Some((|| {
            let signed = self.verification.body().ok_or(HistoryErrorV1::Correlation)?;
            signed.compare_root_hello_data(hello)?;
            signed.compare_held_data(CacheHeldReceiptDataV1::decode(held, body.open.lane)?)?;
            let forwarded = match turn {
                RootCurrentProofTurnV1::Initial =>
                    received_proofs_v1(self.received_frame.bytes(), hello, index)?.cache_packet,
                RootCurrentProofTurnV1::Reserved { .. } =>
                    received_use_proofs_v1(self.received_frame.bytes(), hello, index)?.cache_packet,
            };
            if forwarded != packet {
                return Err(HistoryErrorV1::Correlation);
            }
            Ok(())
        })());
        positive(&self.association).map(|_| ())
    }

    pub(crate) fn require_use_complete_for_v1(&self, root: &RootCurrentOpenStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
    ) -> Result<(), Error> {
        self.require_complete_v1()?;
        let expected = RootCurrentProofTurnV1::Reserved { authorization, reserved }
            .authorization_checksum_v1(root)?;
        if expected.is_none() || *positive(&self.turn_binding)? != expected {
            return Err(Error::History);
        }
        Ok(())
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if !self.complete || self.closed.is_some() || self.verification.body().is_none() {
            return Err(Error::History);
        }
        Ok(())
    }

    pub(super) fn verified_packet_v1(&self) -> Result<&[u8], Error> {
        self.require_complete_v1()?;
        self.transport.packet().map(|packet| packet.as_slice()).map_err(|_| Error::History)
    }

    pub(super) fn verified_body_v1(&self) -> Result<&aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::current_proof::CacheCurrentProofBodyDataV1, Error> {
        self.require_complete_v1()?;
        self.verification.body().ok_or(Error::History)
    }

    // Controller receipt DATA remains borrowed from its actual authenticated
    // frame. Only the later independent Controller replay can accept it.
    pub(super) fn controller_receipt_v1(&self, root: &RootCurrentOpenStateV1,
        ready: &RootCurrentReadyStateV1) -> Result<InputsReadyNativeReceiptDataV1<'_>, Error>
    {
        self.require_complete_v1()?;
        let body = root.completed_body()?;
        let hello = RootHelloDataV1::decode(&self.hello, body.open).map_err(|_| Error::History)?;
        Ok(received_proofs_v1(self.received_frame.bytes(), hello, ready.original_transfer_index_v1()?)
            .map_err(|_| Error::History)?.controller)
    }

    pub(super) fn current_proofs_payload_v1(&self) -> Result<&[u8; CURRENT_PROOFS_PAYLOAD_BYTES_V1], Error> {
        self.require_complete_v1()?;
        self.received_frame.bytes().get(FRAME_HEADER_BYTES..)
            .and_then(|bytes| bytes.try_into().ok()).ok_or(Error::History)
    }

    pub(crate) fn use_current_proofs_payload_v1(&self)
        -> Result<&[u8; USE_CURRENT_PROOFS_BYTES_V1], Error>
    {
        self.require_complete_v1()?;
        self.received_frame.bytes().get(FRAME_HEADER_BYTES..)
            .and_then(|bytes| bytes.try_into().ok()).ok_or(Error::History)
    }

    pub(super) fn failure_with_original<'a>(&'a self, _flight: &'a RootPolicyAcceptedFlightV1<'_, '_>)
        -> Option<&'a (dyn StdError + 'static)>
    {
        self.geometry.as_ref().err().map(|cause| cause as &(dyn StdError + 'static))
            .or_else(|| cause(&self.turn_binding)).or_else(|| cause(&self.framing)).or_else(|| cause(&self.configuration)).or_else(|| cause(&self.hello_copy))
            .or_else(|| self.before.iter().find_map(|original| original.failure()))
            .or_else(|| self.before_result.iter().find_map(cause)).or_else(|| cause(&self.before_readback))
            .or_else(|| self.before_clock.failure()).or_else(|| cause(&self.before_sample))
            .or_else(|| cause(&self.before_cutoff))
            .or_else(|| if matches!(self.begin, Some(Err(_))) { self.transport.failure().or_else(|| cause(&self.begin)) } else { None })
            .or_else(|| cause(&self.invitation_encoding)).or_else(|| self.invitation_io.failure())
            .or_else(|| cause(&self.sent))
            .or_else(|| {
                if matches!(self.preparation, Some(Err(SubjectStreamReadErrorV1::Retained))) {
                    self.received_frame.failure().or_else(|| cause(&self.preparation))
                } else {
                    cause(&self.preparation)
                }
            })
            .or_else(|| self.chunks.failure_with_buffer(&self.received_frame)).or_else(|| cause(&self.received))
            .or_else(|| cause(&self.proofs_binding))
            .or_else(|| if matches!(self.finish, Some(Err(_))) { self.transport.failure().or_else(|| cause(&self.finish)) } else { None })
            .or_else(|| cause(&self.packet)).or_else(|| self.verification.failure())
            .or_else(|| cause(&self.verified)).or_else(|| cause(&self.association)).or_else(|| cause(&self.primary))
            .or_else(|| self.after.iter().find_map(|original| original.failure()))
            .or_else(|| self.after_result.iter().find_map(cause)).or_else(|| cause(&self.after_readback))
            .or_else(|| cause(&self.peer)).or_else(|| self.after_clock.failure())
            .or_else(|| cause(&self.after_sample)).or_else(|| cause(&self.after_cutoff))
            .or_else(|| cause(&self.interval)).or_else(|| cause(&self.cross_clock))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn observe_turn_writers(writers: &mut RootCreateStorageCurrentWritersV1,
    root: &RootCurrentOpenStateV1, turn: RootCurrentProofTurnV1<'_>,
    originals: &mut [ProtectedJournalCurrentnessOriginalsV1; 2], results: &mut [WriterResult; 2],
    readback: &mut Option<Result<(), JournalError>>)
{
    *readback = Some(match observe_writer_names_v1(writers, originals, results) {
        Ok((authority, policy)) => turn.readback_v1(root, authority, policy),
        Err(cause) => Err(cause),
    });
}

pub(super) fn require_clock(root: &RootCurrentOpenStateV1, source: &RootCurrentSourceExchangeStateV1,
    sample: &Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>) -> Result<(), JournalError>
{
    let now = *positive(sample).map_err(|_| JournalError::ProtectedBoundary)?;
    root.require_clock(now)?;
    let cutoff = source.original_cutoff_v1().map_err(|_| JournalError::ProtectedBoundary)?;
    let source = source.fields_v1().map_err(|_| JournalError::ProtectedBoundary)?;
    if now.boottime_nanoseconds() >= cutoff || now.host_boot_id() != source.boot
        || now.boottime_nanoseconds() < source.boottime_nanoseconds || now.wall_seconds() < source.wall_seconds {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) fn observe_writers(writers: &mut RootCreateStorageCurrentWritersV1, root: &RootCurrentOpenStateV1,
    originals: &mut [ProtectedJournalCurrentnessOriginalsV1; 2], results: &mut [WriterResult; 2],
    readback: &mut Option<Result<RootCurrentOpenReadbackV1, JournalError>>)
{
    *readback = Some(match observe_writer_names_v1(writers, originals, results) {
        Ok((authority, policy)) => root.readback_current(authority, policy),
        Err(cause) => Err(cause),
    });
}

// Both fixed Root cuts run these exact held-writer observations in the old
// order. Their own typed originals select only the subsequent DATA comparison.
pub(super) fn observe_writer_names_v1<'writer>(
    writers: &'writer mut RootCreateStorageCurrentWritersV1,
    originals: &mut [ProtectedJournalCurrentnessOriginalsV1; 2],
    results: &mut [WriterResult; 2],
) -> Result<(&'writer mut crate::journal::Journal, &'writer crate::journal::Journal), JournalError> {
    let (authority, policy) = writers.authority_and_policy()?;
    results[0] = Some(authority.validate_held_owned_at_for_uid_retaining(
        Path::new(PROTECTED_POLICY_ROOT), POLICY_AUTHORITY_JOURNAL, 0, &mut originals[0]));
    results[1] = Some(policy.validate_held_owned_at_for_uid_retaining(
        Path::new(PROTECTED_POLICY_ROOT), POLICY_STATE_JOURNAL, 0, &mut originals[1]));
    Ok((authority, policy))
}

// Both actual Root purposes already pay their own resident/constructor pair
// fields in their whole State. This shared supplier counts the additional raw
// pair backing and all four reached retained writer-name observations exactly.
pub(super) fn root_current_post_backing_demand_v1() -> Result<ResourceVector, JournalError> {
    let invalid = || JournalError::JournalTooLarge;
    let bytes = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
        .and_then(|bytes| bytes.checked_sub(size_of::<RetainedKernelPairedClockAttemptV1>()))
        .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(invalid)?;
    let mut demand = ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| invalid())?)
        .with(D::OpenFiles,
            (2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1) as u64);
    for name in [POLICY_AUTHORITY_JOURNAL, POLICY_STATE_JOURNAL] {
        let names = ProtectedJournalCurrentnessOriginalsV1::fixed_demand_v1(
            Path::new(PROTECTED_POLICY_ROOT), name,
        )?;
        demand = demand.checked_add(names).and_then(|value| value.checked_add(names))
            .map_err(|_| invalid())?;
    }
    Ok(demand)
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, Error> {
    value.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Error::History)
}

fn cause<T, E: StdError + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    value.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}
