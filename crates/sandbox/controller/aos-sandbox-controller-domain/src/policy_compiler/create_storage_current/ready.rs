//! Receives inert indexed Ready bytes under the same genuine Root original.
//!
//! RootOpen is committed before Hello. Strict subject reporting is enabled
//! before Hello can trigger any Controller context. Every successful chunk is
//! bound and copied while resident, independently posted, then actually disposed
//! before reusing the fixed native peak. Raw bytes remain cumulative. Complete
//! typed B validation and current-cut authorization are a subsequent closed stage.

use std::collections::TryReserveError;
use std::error::Error as StdError;
use std::io::{self, Write as _};
use std::os::unix::net::UnixStream;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::RetainedSubjectStreamReadV1;
use aos_sandbox_protocol::domain_ledger::create_q04_history::CLAIM_CHUNK_BYTES;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1,
    ready::ready_commitment_v1,
    transport::{
        CHUNK_HEADER_BYTES, FRAME_HEADER_BYTES, INDEX_BYTES, ChunkEnvelopeV1,
        FrameCoordinatesV1, FrameEnvelopeV1, FrameKindV1, TransferIndexV1,
    },
};

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{JournalError, ProtectedJournalNamesV1};
use crate::normal_root::{
    NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1,
};

use super::root_open::{
    RootCurrentOpenReadbackV1, RootCurrentOpenStateV1, require_authority, require_policy,
};
use super::super::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::super::source_genesis_root::original_root_kernel_pair_v1;
use super::{OriginalRootCreateStorageCurrentAttemptV1, RootCreateStorageCurrentErrorV1 as Error};

pub(super) mod subject;
pub(super) mod indexed;
use subject::RootCurrentChunkReceivingV1;

pub(crate) struct RootCurrentReadyStateV1 {
    geometry: Result<aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1,
        aos_sandbox_linux::seqpacket::SeqpacketError>,
    fixed: Option<Result<(), NormalRootStartupErrorV1>>,
    enabled: Option<Result<(), aos_sandbox_linux::seqpacket::SeqpacketError>>,
    hello_clock: Option<Result<aos_sandbox_model::RawPairedClockSample, SourceGenesisErrorV1>>,
    hello_cutoff: Option<Result<(), JournalError>>,
    hello_header: [u8; FRAME_HEADER_BYTES],
    hello_encoding: Option<Result<(), HistoryErrorV1>>,
    sent: usize,
    send: Option<io::Result<usize>>,
    send_shape: Option<io::Result<()>>,
    index_frame: RetainedSubjectStreamReadV1,
    index: Option<Result<TransferIndexV1, HistoryErrorV1>>,
    variable: Option<Result<(), NormalRootStartupErrorV1>>,
    allocation: Option<Result<(), TryReserveError>>,
    bytes: Vec<u8>,
    frame: Option<RetainedSubjectStreamReadV1>,
    frame_binding: Option<Result<(), HistoryErrorV1>>,
    next_chunk: u32,
    chunks: RootCurrentChunkReceivingV1,
    digest: Option<Result<(), HistoryErrorV1>>,
    authority_names: Option<Result<ProtectedJournalNamesV1, JournalError>>,
    policy_names: Option<Result<ProtectedJournalNamesV1, JournalError>>,
    authority_post: Option<Result<(), JournalError>>,
    policy_post: Option<Result<(), JournalError>>,
    names_binding: Option<Result<(), JournalError>>,
    readback: Option<Result<RootCurrentOpenReadbackV1, JournalError>>,
    peer_post: Option<Result<(), NormalRootStartupErrorV1>>,
    clock: Option<Result<aos_sandbox_model::RawPairedClockSample, SourceGenesisErrorV1>>,
    cutoff: Option<Result<(), JournalError>>,
    transfer: Option<Result<(), Error>>,
    complete: bool,
    closed: bool,
}

impl RootCurrentReadyStateV1 {
    pub(super) fn new() -> Self {
        Self {
            geometry: crate::normal_root::RootControllerChunkSubjectSampleV1::receive_geometry_v1(),
            fixed: None,
            enabled: None,
            hello_clock: None,
            hello_cutoff: None,
            hello_header: [0; FRAME_HEADER_BYTES],
            hello_encoding: None,
            sent: 0,
            send: None,
            send_shape: None,
            index_frame: RetainedSubjectStreamReadV1::new(),
            index: None,
            variable: None,
            allocation: None,
            bytes: Vec::new(),
            frame: None,
            frame_binding: None,
            next_chunk: 0,
            chunks: RootCurrentChunkReceivingV1::default(),
            digest: None,
            authority_names: None,
            policy_names: None,
            authority_post: None,
            policy_post: None,
            names_binding: None,
            readback: None,
            peer_post: None,
            clock: None,
            cutoff: None,
            transfer: None,
            complete: false,
            closed: false,
        }
    }

    pub(super) fn receive_once(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        original: &UnixStream,
        root_open: &RootCurrentOpenStateV1,
    ) -> Result<(), Error> {
        if self.transfer.is_some() || self.closed {
            self.closed = true;
            return Err(Error::Original);
        }
        self.transfer = Some(self.receive_inner(flight, original, root_open));
        // These independent posts run even after index/allocation/native/codec
        // refusal. Earlier lower results stay in the same owner, not a local Err.
        self.finish_posts(flight, writers, root_open);
        self.complete = matches!(self.transfer, Some(Ok(())))
            && matches!(self.names_binding, Some(Ok(())))
            && matches!(self.readback, Some(Ok(_)))
            && matches!(self.peer_post, Some(Ok(())))
            && matches!(self.cutoff, Some(Ok(())))
            && self.failure().is_none();
        if self.complete {
            Ok(())
        } else {
            Err(Error::Ready)
        }
    }

    fn receive_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &UnixStream,
        root_open: &RootCurrentOpenStateV1,
    ) -> Result<(), Error> {
        let geometry = *self.geometry.as_ref().map_err(|_| Error::Ready)?;
        let body = root_open.completed_body()?;
        let record = root_open.committed_record()?;
        let startup = flight.current_cut_startup().map_err(|_| Error::Original)?;
        self.fixed = Some(startup.prepay_create_storage_ready_fixed_once(root_open));
        positive(&self.fixed)?;
        self.enabled = Some(flight.enable_current_subject_reporting_once());
        positive(&self.enabled)?;
        self.hello_clock = Some(original_root_kernel_pair_v1());
        self.hello_cutoff = Some((|| {
            let now = *positive(&self.hello_clock).map_err(|_| JournalError::ProtectedBoundary)?;
            root_open.require_clock(now)
        })());
        positive(&self.hello_cutoff)?;
        self.hello_encoding = Some(FrameCoordinatesV1 {
            kind: FrameKindV1::Hello,
            lane: body.open.lane,
            sequence: 1,
            root_nonce: body.root_nonce,
            controller_nonce: body.open.controller_nonce,
        }.encode_header(record).map(|header| self.hello_header = header));
        positive(&self.hello_encoding)?;
        self.send_hello(original, record)?;

        self.index_frame.prepare_exact_once(FRAME_HEADER_BYTES + INDEX_BYTES)
            .map_err(|_| Error::Ready)?;
        self.chunks.receive_exact(flight, original, &mut self.index_frame, root_open, &geometry)?;
        self.index = Some((|| {
            let frame = FrameEnvelopeV1::decode(self.index_frame.bytes(), FrameCoordinatesV1 {
                kind: FrameKindV1::ReadyIndex,
                lane: body.open.lane,
                sequence: 2,
                root_nonce: body.root_nonce,
                controller_nonce: body.open.controller_nonce,
            })?;
            let index = TransferIndexV1::decode(frame.payload())?;
            if index.digest() != body.open.ready {
                return Err(HistoryErrorV1::Correlation);
            }
            Ok(index)
        })());
        let index = *positive(&self.index)?;
        self.variable = Some(startup.prepay_create_storage_ready_bytes_once(index));
        positive(&self.variable)?;
        indexed::receive_chunks_once_v1(indexed::IndexedReceiveSlotsV1 {
            allocation: &mut self.allocation, bytes: &mut self.bytes,
            frame: &mut self.frame, frame_binding: &mut self.frame_binding,
            next_chunk: &mut self.next_chunk, chunks: &mut self.chunks, digest: &mut self.digest,
        }, flight, original, root_open, &geometry, index,
            indexed::IndexedTransferPurposeDataV1::Ready, 3, body.cutoff)
    }

    fn send_hello(&mut self, original: &UnixStream, record: &[u8]) -> Result<(), Error> {
        let length = FRAME_HEADER_BYTES.checked_add(record.len()).ok_or(Error::Ready)?;
        while self.sent < length {
            let bytes = if self.sent < FRAME_HEADER_BYTES {
                &self.hello_header[self.sent..]
            } else {
                &record[self.sent - FRAME_HEADER_BYTES..]
            };
            self.send = Some((&*original).write(bytes));
            let reached = *positive(&self.send)?;
            if reached == 0 || reached > bytes.len() {
                self.send_shape = Some(Err(io::Error::new(io::ErrorKind::WriteZero,
                    "Root Hello did not reach the original endpoint")));
                return Err(Error::Ready);
            }
            self.sent = self.sent.checked_add(reached).ok_or(Error::Ready)?;
        }
        self.send_shape = Some(Ok(()));
        Ok(())
    }

    fn finish_posts(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1,
        root_open: &RootCurrentOpenStateV1,
    ) {
        match writers.authority_and_policy() {
            Ok((authority, policy)) => {
                self.authority_names = Some(authority.protected_writer_physical_names_v1());
                self.policy_names = Some(policy.protected_writer_physical_names_v1());
                self.names_binding = Some((|| {
                    let body = root_open.completed_body().map_err(|_| JournalError::ProtectedBoundary)?;
                    if *positive(&self.authority_names).map_err(|_| JournalError::ProtectedBoundary)? != body.authority_names
                        || *positive(&self.policy_names).map_err(|_| JournalError::ProtectedBoundary)? != body.policy_names
                    {
                        return Err(JournalError::ProtectedBoundary);
                    }
                    Ok(())
                })());
                self.authority_post = Some(require_authority(authority));
                self.policy_post = Some(require_policy(policy));
                self.readback = Some(root_open.readback_current(authority, policy));
            }
            Err(error) => {
                self.authority_post = Some(Err(error));
                self.policy_post = Some(Err(JournalError::ProtectedBoundary));
            }
        }
        self.peer_post = Some(flight.recheck_current_controller_peer_once());
        self.clock = Some(original_root_kernel_pair_v1());
        self.cutoff = Some((|| {
            let now = *positive(&self.clock).map_err(|_| JournalError::ProtectedBoundary)?;
            root_open.require_clock(now)
        })());
    }

    pub(crate) fn completed_native_descriptor_peak_v1(&self) -> Result<u64, Error> {
        self.raw_ready_bytes()?;
        if !self.index_frame.completed_exact() || self.frame.is_some()
            || !self.chunks.native_sample_disposed()
        {
            return Err(Error::Ready);
        }
        // Every actual received chunk, subject sample and native before/after
        // carrier has been disposed after positive copy and independent posts.
        // Raw Ready buffers stay resident. This is an available sequential FD
        // peak inside the same whole-service R, never traffic or budget refund.
        let geometry = self.geometry.as_ref().map_err(|_| Error::Ready)?;
        u64::try_from(geometry.receive_obligations_v1().1).map_err(|_| Error::Ready)
    }

    pub(crate) fn raw_ready_bytes(&self) -> Result<&[u8], Error> {
        if self.complete && !self.closed && self.failure().is_none() {
            Ok(&self.bytes)
        } else {
            Err(Error::Ready)
        }
    }

    // Copies only the bytes actually sent on this completed original exchange.
    // The same RootOpen owner supplies its unchanged resident record; this does
    // not encode a replacement Hello or accept passed nonce/receipt authority.
    pub(super) fn original_hello_frame_v1(
        &self,
        root: &RootCurrentOpenStateV1,
        output: &mut [u8; 612],
    ) -> Result<(), aos_sandbox_protocol::domain_ledger::create_storage_history::HistoryErrorV1> {
        self.raw_ready_bytes().map_err(|_| HistoryErrorV1::Correlation)?;
        let record = root.committed_record().map_err(|_| HistoryErrorV1::Correlation)?;
        if self.sent != output.len() || record.len() != output.len() - FRAME_HEADER_BYTES
            || !matches!(self.hello_encoding, Some(Ok(())))
        {
            return Err(HistoryErrorV1::Correlation);
        }
        output[..FRAME_HEADER_BYTES].copy_from_slice(&self.hello_header);
        output[FRAME_HEADER_BYTES..].copy_from_slice(record);
        let original = root.completed_body().map_err(|_| HistoryErrorV1::Correlation)?;
        aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootHelloDataV1::decode(
            output, original.open,
        )?;
        Ok(())
    }

    pub(super) fn original_transfer_index_v1(&self) -> Result<TransferIndexV1, Error> {
        self.raw_ready_bytes()?;
        self.index.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(Error::Ready)
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        macro_rules! cause {
            ($slot:expr) => {
                $slot.as_ref().and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn StdError + 'static))
            };
        }
        self.geometry.as_ref().err().map(|cause| cause as &(dyn StdError + 'static))
            .or_else(|| cause!(self.fixed))
            .or_else(|| cause!(self.enabled))
            .or_else(|| cause!(self.hello_clock))
            .or_else(|| cause!(self.hello_cutoff))
            .or_else(|| cause!(self.hello_encoding))
            .or_else(|| cause!(self.send))
            .or_else(|| cause!(self.send_shape))
            .or_else(|| self.index_frame.failure())
            .or_else(|| cause!(self.index))
            .or_else(|| cause!(self.variable))
            .or_else(|| cause!(self.allocation))
            .or_else(|| self.frame.as_ref().and_then(|frame| frame.failure()))
            .or_else(|| self.chunks.failure())
            .or_else(|| cause!(self.frame_binding))
            .or_else(|| cause!(self.digest))
            .or_else(|| cause!(self.transfer))
            .or_else(|| cause!(self.authority_names))
            .or_else(|| cause!(self.policy_names))
            .or_else(|| cause!(self.names_binding))
            .or_else(|| cause!(self.authority_post))
            .or_else(|| cause!(self.policy_post))
            .or_else(|| cause!(self.readback))
            .or_else(|| cause!(self.peer_post))
            .or_else(|| cause!(self.clock))
            .or_else(|| cause!(self.cutoff))
    }
}

impl OriginalRootCreateStorageCurrentAttemptV1<'_, '_, '_> {
    pub(crate) fn ready_fixed_demand() -> Result<ResourceVector, JournalError> {
        let construction = indexed::construction_bytes_v1().ok_or(JournalError::JournalTooLarge)?;
        Self::ready_fixed_base_demand_v1()?.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, construction))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    fn ready_fixed_base_demand_v1() -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::LimitExceeded("fixed Root Ready receiving shape");
        let native = RootCurrentChunkReceivingV1::additional_receiving_demand_v1()?;
        let frames = FRAME_HEADER_BYTES + INDEX_BYTES
            + FRAME_HEADER_BYTES + CHUNK_HEADER_BYTES + CLAIM_CHUNK_BYTES;
        let memory = native.get(D::MemoryBytes)
            .checked_add(frames as u64)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RootCurrentReadyStateV1>() as u64))
            .ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::MetadataEntries, native.get(D::MetadataEntries))
            .with(D::OpenFiles, native.get(D::OpenFiles))
            .with(D::NetworkBytes, (FRAME_HEADER_BYTES + INDEX_BYTES) as u64)
            .with(D::OutputBytes, memory)
            .with(D::LogBytes, 64 * 1024)
            .checked_add(RootCurrentChunkReceivingV1::additional_clock_demand_v1()?)
            .map_err(|_| invalid())?)
    }

    pub(crate) fn ready_encoded_demand(index: TransferIndexV1) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::LimitExceeded("actual Root Ready encoded extent");
        let _ = usize::try_from(index.total()).map_err(|_| invalid())?;
        let memory = index.total().checked_mul(2).ok_or_else(invalid)?;
        let overhead = u64::from(index.count())
            .checked_mul((FRAME_HEADER_BYTES + CHUNK_HEADER_BYTES) as u64).ok_or_else(invalid)?;
        let traffic = index.total().checked_add(overhead).ok_or_else(invalid)?;
        // Only inert encoded storage/copy is admitted here. No typed B decoder,
        // model graph, signing, U or prospective compiler allocation enters.
        Ok(ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::OutputBytes, memory)
            .with(D::NetworkBytes, traffic))
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, Error> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Error::Ready)
}
