//! Receives actual outcome index/chunks and C9 on the same Root connection.
//!
//! Fixed and captured-extent stages of the SAME R precede their growth. This
//! owner uses the existing Ready indexed copy and per-chunk subject engine;
//! failed frames, native steps, actual returned errors and owed posts remain.

use std::collections::TryReserveError;
use std::error::Error as StdError;
use std::os::unix::net::UnixStream;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReceiveGeometryV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{HistoryErrorV1,
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1},
    outcome::{OutcomeBundleDataV1, CONTROLLER_OUTCOME_RECEIPT_BYTES_V1},
    transport::{FRAME_HEADER_BYTES, INDEX_BYTES, CHUNK_HEADER_BYTES, FrameCoordinatesV1,
        FrameEnvelopeV1, FrameKindV1, TransferIndexV1}};
use crate::journal::JournalError;
use crate::normal_root::{RootControllerChunkSubjectSampleV1, RootPolicyAcceptedFlightV1,
    NormalRootStartupErrorV1};
use crate::policy_compiler::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::super::{RootCreateStorageCurrentErrorV1 as Error,
    ready::{RootCurrentReadyStateV1, subject::RootCurrentChunkReceivingV1,
        indexed::{self, IndexedReceiveSlotsV1, IndexedTransferPurposeDataV1}},
    root_open::{RootCurrentOpenStateV1, RootCurrentHistoryPostsV1},
    source_current::RootCurrentSourceExchangeStateV1,
    signed_bound::RootCurrentSignedBoundStateV1,
    use_reserved::RootCurrentUseReservedStateV1};

pub(crate) struct RootOutcomeInputV1 {
    geometry: Result<SubjectStreamReceiveGeometryV1, aos_sandbox_linux::seqpacket::SeqpacketError>,
    before: RootCurrentHistoryPostsV1,
    before_readback: Option<Result<(), JournalError>>,
    before_live: Option<Result<(), JournalError>>,
    maxima: Option<Result<[usize; 2], JournalError>>,
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
    decoded: Option<Result<(), HistoryErrorV1>>,
    recorded: RetainedSubjectStreamReadV1,
    recorded_binding: Option<Result<(), HistoryErrorV1>>,
    primary: Option<Result<(), Error>>,
    after: RootCurrentHistoryPostsV1,
    after_readback: Option<Result<(), JournalError>>,
    after_live: Option<Result<(), JournalError>>,
    interval: Option<Result<(), aos_sandbox_model::OwnershipLeaseVerificationError>>,
    complete: bool,
    closed: bool,
}

impl RootOutcomeInputV1 {
    pub(super) fn new() -> Self {
        Self { geometry: RootControllerChunkSubjectSampleV1::receive_geometry_v1(),
            before: Default::default(), before_readback: None, before_live: None,
            maxima: None, index_frame: RetainedSubjectStreamReadV1::new(), index: None,
            variable: None, allocation: None, bytes: Vec::new(), frame: None,
            frame_binding: None, next_chunk: 0, chunks: Default::default(), digest: None,
            decoded: None, recorded: RetainedSubjectStreamReadV1::new(), recorded_binding: None, primary: None,
            after: Default::default(), after_readback: None, after_live: None,
            interval: None, complete: false, closed: false }
    }

    pub(super) fn maxima_v1(reserved: &RootCurrentUseReservedStateV1) -> Result<[usize; 2], JournalError> {
        let plan = reserved.completed_readonly_v1().and_then(|read| read.prospective_use_plan_v1())
            .map_err(|_| JournalError::ProtectedBoundary)?;
        Ok([plan.request_shape_bytes_v1(),
            aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES])
    }

    pub(super) fn receive_once(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        signed: &RootCurrentSignedBoundStateV1, reserved: &RootCurrentUseReservedStateV1,
        source: &RootCurrentSourceExchangeStateV1,
    ) -> Result<(), Error> {
        if self.primary.is_some() || self.closed { self.closed = true; return Err(Error::Original); }
        self.before.arm_once(flight)?;
        self.after.arm_once(flight)?;
        self.primary = Some(self.receive_inner(flight, writers, original, root, ready,
            signed, reserved, source));
        let body = root.completed_body().ok();
        let origin = root.original_clock_origin_v1().ok();
        self.after.observe_once(flight, writers, body.as_ref(), origin.map(|pair| pair.0), origin.map(|pair| pair.1));
        self.after_readback = Some(match writers.authority_and_policy() {
            Ok((authority, policy)) => signed.readback_current_v1(authority, policy).map(|_| ()),
            Err(cause) => Err(cause),
        });
        self.after_live = Some(self.after.require_complete().and_then(|()| {
            positive(&self.after_readback).map_err(|_| JournalError::ProtectedBoundary)?;
            require_live(root, reserved, source, self.after.sample()?)
        }));
        if let (Ok(before), Ok(after)) = (self.before.sample(), self.after.sample()) {
            self.interval = Some(before.validate_later_sample(after));
        }
        self.complete = matches!(self.primary, Some(Ok(()))) && matches!(self.after_live, Some(Ok(())))
            && matches!(self.interval, Some(Ok(()))) && self.frame.is_none()
            && self.chunks.native_sample_disposed() && self.failure_with_original(flight).is_none();
        self.require_complete_v1()
    }

    fn receive_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        signed: &RootCurrentSignedBoundStateV1, reserved: &RootCurrentUseReservedStateV1,
        source: &RootCurrentSourceExchangeStateV1,
    ) -> Result<(), Error> {
        signed.require_complete_v1()?;
        let body = root.completed_body()?;
        let origin = root.original_clock_origin_v1()?;
        self.before.observe_once(flight, writers, Some(&body), Some(origin.0), Some(origin.1));
        self.before_readback = Some(match writers.authority_and_policy() {
            Ok((authority, policy)) => signed.readback_current_v1(authority, policy).map(|_| ()),
            Err(cause) => Err(cause),
        });
        self.before_live = Some(self.before.require_complete().and_then(|()| {
            positive(&self.before_readback).map_err(|_| JournalError::ProtectedBoundary)?;
            require_live(root, reserved, source, self.before.sample()?)
        }));
        positive(&self.before_live)?;
        self.maxima = Some(Self::maxima_v1(reserved));
        let maxima = *positive(&self.maxima)?;
        let geometry = *self.geometry.as_ref().map_err(|_| Error::History)?;
        let cutoff = source.original_cutoff_v1()?;
        self.index_frame.prepare_exact_once(FRAME_HEADER_BYTES + INDEX_BYTES).map_err(|_| Error::History)?;
        self.chunks.receive_exact_until(flight, original, &mut self.index_frame, root, &geometry, cutoff)?;
        self.index = Some((|| {
            let sequence = 12_u64.checked_add(u64::from(ready.original_transfer_index_v1()
                .map_err(|_| HistoryErrorV1::Correlation)?.count())).and_then(|value| value.checked_add(u64::from(signed.completed_index_v1().ok()?.count())))
                .ok_or(HistoryErrorV1::Extent)?;
            let frame = FrameEnvelopeV1::decode(self.index_frame.bytes(), FrameCoordinatesV1 {
                kind: FrameKindV1::OutcomeIndex, lane: body.open.lane, sequence,
                root_nonce: body.root_nonce, controller_nonce: body.open.controller_nonce,
            })?;
            let index = TransferIndexV1::decode(frame.payload())?;
            let maximum = maxima.into_iter().try_fold(16_usize, |bytes, field|
                bytes.checked_add(field).ok_or(HistoryErrorV1::Extent))?;
            if index.total() > u64::try_from(maximum).map_err(|_| HistoryErrorV1::Extent)? {
                return Err(HistoryErrorV1::Extent);
            }
            Ok(index)
        })());
        let index = *positive(&self.index)?;
        self.variable = Some(flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_outcome_bytes_once(root, signed, reserved, self));
        positive(&self.variable)?;
        let first_sequence = 13_u64.checked_add(u64::from(ready.original_transfer_index_v1()?.count()))
            .and_then(|value| value.checked_add(u64::from(signed.completed_index_v1().ok()?.count())))
            .ok_or(Error::History)?;
        indexed::receive_chunks_once_v1(IndexedReceiveSlotsV1 {
            allocation: &mut self.allocation, bytes: &mut self.bytes,
            frame: &mut self.frame, frame_binding: &mut self.frame_binding,
            next_chunk: &mut self.next_chunk, chunks: &mut self.chunks, digest: &mut self.digest,
        }, flight, original, root, &geometry, index,
            IndexedTransferPurposeDataV1::Outcome { maxima }, first_sequence, cutoff)?;
        self.decoded = Some(OutcomeBundleDataV1::decode(&self.bytes, maxima).map(|_| ()));
        positive(&self.decoded)?;
        self.recorded.prepare_exact_once(FRAME_HEADER_BYTES + CONTROLLER_OUTCOME_RECEIPT_BYTES_V1)
            .map_err(|_| Error::History)?;
        self.chunks.receive_exact_until(flight, original, &mut self.recorded, root, &geometry, cutoff)?;
        self.recorded_binding = Some((|| {
            let sequence = first_sequence.checked_add(u64::from(index.count())).ok_or(HistoryErrorV1::Extent)?;
            let frame = FrameEnvelopeV1::decode(self.recorded.bytes(), FrameCoordinatesV1 {
                kind: FrameKindV1::OutcomeRecorded, lane: body.open.lane, sequence,
                root_nonce: body.root_nonce, controller_nonce: body.open.controller_nonce,
            })?;
            ContinuationNativeReceiptDataV1::decode(frame.payload(), body.open.lane,
                ContinuationKindV1::ControllerOutcomeRecorded).map(|_| ())
        })());
        positive(&self.recorded_binding).map(|_| ())
    }

    pub(crate) fn additional_received_demand_v1(&self, _reserved: &RootCurrentUseReservedStateV1)
        -> Result<ResourceVector, JournalError> {
        let index = *self.index.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let raw = usize::try_from(index.total()).map_err(|_| JournalError::JournalTooLarge)?;
        let models = super::super::controller_readonly::storage_inventory::RootCurrentStorageInventoryV1::additional_demand_v1(raw)?;
        let wire = index.total().checked_add(u64::from(index.count()).checked_mul(
            (FRAME_HEADER_BYTES + CHUNK_HEADER_BYTES) as u64).ok_or(JournalError::JournalTooLarge)?)
            .ok_or(JournalError::JournalTooLarge)?;
        let memory = index.total().checked_mul(4).ok_or(JournalError::JournalTooLarge)?;
        models.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory).with(D::NetworkBytes, wire))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn failed_financial_entry_v1(&self) -> bool {
        matches!(self.variable, Some(Err(_)))
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if self.complete && !self.closed && matches!(self.recorded_binding, Some(Ok(()))) {
            Ok(())
        } else { Err(Error::History) }
    }

    pub(crate) fn completed_bundle_v1(&self) -> Result<OutcomeBundleDataV1<'_>, Error> {
        self.require_complete_v1()?;
        OutcomeBundleDataV1::decode(&self.bytes, *positive(&self.maxima)?).map_err(|_| Error::History)
    }

    pub(crate) fn recorded_receipt_v1(&self, lane: [u8; 16]) -> Result<ContinuationNativeReceiptDataV1<'_>, Error> {
        self.require_complete_v1()?;
        ContinuationNativeReceiptDataV1::decode(&self.recorded.bytes()[FRAME_HEADER_BYTES..], lane,
            ContinuationKindV1::ControllerOutcomeRecorded).map_err(|_| Error::History)
    }

    pub(crate) fn index_v1(&self) -> Result<TransferIndexV1, Error> {
        self.require_complete_v1()?;
        positive(&self.index).copied()
    }

    pub(super) fn failure_with_original<'a>(&'a self, flight: &'a RootPolicyAcceptedFlightV1<'_, '_>)
        -> Option<&'a (dyn StdError + 'static)>
    {
        self.geometry.as_ref().err().map(|cause| cause as &(dyn StdError + 'static))
            .or_else(|| self.before.failure()).or_else(|| cause(&self.before_readback))
            .or_else(|| cause(&self.before_live)).or_else(|| cause(&self.maxima))
            .or_else(|| self.index_frame.failure()).or_else(|| cause(&self.index))
            .or_else(|| if matches!(self.variable, Some(Err(_))) { flight.failure() } else { None })
            .or_else(|| cause(&self.variable)).or_else(|| cause(&self.allocation))
            .or_else(|| self.frame.as_ref().and_then(|frame| frame.failure()))
            .or_else(|| self.chunks.failure()).or_else(|| cause(&self.frame_binding))
            .or_else(|| cause(&self.digest)).or_else(|| cause(&self.decoded))
            .or_else(|| self.recorded.failure()).or_else(|| cause(&self.recorded_binding))
            .or_else(|| cause(&self.primary))
            .or_else(|| self.after.failure()).or_else(|| cause(&self.after_readback))
            .or_else(|| cause(&self.after_live)).or_else(|| cause(&self.interval))
    }
}

fn require_live(root: &RootCurrentOpenStateV1, reserved: &RootCurrentUseReservedStateV1,
    source: &RootCurrentSourceExchangeStateV1, sample: aos_sandbox_model::RawPairedClockSample)
    -> Result<(), JournalError>
{
    root.require_clock(sample)?;
    reserved.completed_readonly_v1().map_err(|_| JournalError::ProtectedBoundary)?.require_live_at_v1(sample)?;
    if sample.boottime_nanoseconds() >= source.original_cutoff_v1().map_err(|_| JournalError::ProtectedBoundary)? {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, Error> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Error::History)
}

fn cause<T, E: StdError + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
