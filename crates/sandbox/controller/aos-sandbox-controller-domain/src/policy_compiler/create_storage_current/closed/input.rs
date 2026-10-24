//! Receives the same authenticated connection's exact final release proofs.
//!
//! Original Held and Root5 owners remain borrowed through independent native
//! readback. Decoding or matching these receipts creates no terminal proof.

use std::error::Error as StdError;
use std::os::unix::net::UnixStream;
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReceiveGeometryV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, OwnerV1, KeyV1, PhaseV1, RecordEnvelopeV1,
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1},
    outcome::{ReleaseProofsDataV1, HandoffRetainedBodyDataV1, RELEASE_PROOFS_BYTES_V1},
    transport::{FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameEnvelopeV1, FrameKindV1},
    ready::ReadyBundleDataV1,
};
use crate::journal::JournalError;
use crate::normal_root::{RootControllerChunkSubjectSampleV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::super::{RootCreateStorageCurrentErrorV1 as Error,
    root_open::{RootCurrentOpenStateV1, RootCurrentHistoryPostsV1},
    ready::{RootCurrentReadyStateV1, subject::RootCurrentChunkReceivingV1},
    outcome::RootCurrentOutcomeStateV1,
    use_reserved::RootCurrentUseReservedStateV1,
    source_current::RootCurrentSourceExchangeStateV1,
    cache_current::RootCurrentCacheProofStateV1};

pub(crate) struct RootReleaseInputV1 {
    geometry: Result<SubjectStreamReceiveGeometryV1, aos_sandbox_linux::seqpacket::SeqpacketError>,
    before: RootCurrentHistoryPostsV1,
    before_readback: Option<Result<(), JournalError>>,
    frame: RetainedSubjectStreamReadV1,
    chunks: RootCurrentChunkReceivingV1,
    framing: Option<Result<(), HistoryErrorV1>>,
    joins: Option<Result<HandoffRetainedBodyDataV1, HistoryErrorV1>>,
    primary: Option<Result<(), Error>>,
    after: RootCurrentHistoryPostsV1,
    after_readback: Option<Result<(), JournalError>>,
    live: Option<Result<(), JournalError>>,
    interval: Option<Result<(), aos_sandbox_model::OwnershipLeaseVerificationError>>,
    complete: bool,
    closed: bool,
}

impl RootReleaseInputV1 {
    pub(super) fn new() -> Self {
        Self { geometry: RootControllerChunkSubjectSampleV1::receive_geometry_v1(),
            before: Default::default(), before_readback: None, frame: Default::default(),
            chunks: Default::default(), framing: None, joins: None, primary: None,
            after: Default::default(), after_readback: None, live: None, interval: None,
            complete: false, closed: false }
    }

    pub(super) fn receive_once(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        outcome: &RootCurrentOutcomeStateV1, reserved: &RootCurrentUseReservedStateV1,
        source: &RootCurrentSourceExchangeStateV1, cache: &RootCurrentCacheProofStateV1,
    ) -> Result<(), Error> {
        if self.primary.is_some() || self.closed { self.closed = true; return Err(Error::Original); }
        self.before.arm_once(flight)?;
        self.after.arm_once(flight)?;
        self.primary = Some(self.receive_inner(flight, writers, original, root, ready, outcome, source, cache));
        let body = root.completed_body().ok();
        let origin = root.original_clock_native_v1().ok();
        self.after.observe_once(flight, writers, body.as_ref(), origin);
        self.after_readback = Some(match writers.authority_and_policy() {
            Ok((authority, policy)) => outcome.readback_current_v1(authority, policy).map(|_| ()),
            Err(cause) => Err(cause),
        });
        self.live = Some((|| {
            self.after.require_complete()?;
            positive(&self.after_readback)?;
            require_live(root, outcome, reserved, source, self.after.sample()?)
        })());
        if let (Ok(before), Ok(after)) = (self.before.sample(), self.after.sample()) {
            self.interval = Some(before.validate_later_sample(after));
        }
        self.complete = matches!(self.primary, Some(Ok(()))) && matches!(self.live, Some(Ok(())))
            && matches!(self.interval, Some(Ok(()))) && self.chunks.native_sample_disposed()
            && self.failure().is_none();
        self.require_complete_v1()
    }

    fn receive_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        outcome: &RootCurrentOutcomeStateV1, source: &RootCurrentSourceExchangeStateV1,
        cache: &RootCurrentCacheProofStateV1,
    ) -> Result<(), Error> {
        outcome.require_complete_v1()?;
        let body = root.completed_body()?;
        let origin = root.original_clock_native_v1()?;
        self.before.observe_once(flight, writers, Some(&body), Some(origin));
        self.before_readback = Some(match writers.authority_and_policy() {
            Ok((authority, policy)) => outcome.readback_current_v1(authority, policy).map(|_| ()),
            Err(cause) => Err(cause),
        });
        self.before.require_complete().map_err(|_| Error::History)?;
        positive(&self.before_readback).map_err(|_| Error::History)?;
        let geometry = *self.geometry.as_ref().map_err(|_| Error::History)?;
        self.frame.prepare_exact_once(FRAME_HEADER_BYTES + RELEASE_PROOFS_BYTES_V1).map_err(|_| Error::History)?;
        self.chunks.receive_exact_until(flight, original, &mut self.frame, root, &geometry, source.original_cutoff_v1()?)?;
        self.framing = Some(FrameEnvelopeV1::decode(self.frame.bytes(), FrameCoordinatesV1 {
            kind: FrameKindV1::ReleaseProofs, lane: body.open.lane,
            sequence: outcome.completed_ack_sequence_v1()?.checked_add(1).ok_or(Error::History)?,
            root_nonce: body.root_nonce, controller_nonce: body.open.controller_nonce,
        }).map(|_| ()));
        positive(&self.framing).map_err(|_| Error::History)?;
        let proof = ReleaseProofsDataV1::decode(&self.frame.bytes()[FRAME_HEADER_BYTES..], body.open.lane)
            .map_err(|_| Error::History)?;
        let original = ReadyBundleDataV1::borrow_field_framing_data_v1(ready.raw_ready_bytes()?)
            .map_err(|_| Error::History)?;
        let source_held = RecordEnvelopeV1::decode(
            aos_sandbox_protocol::domain_ledger::create_storage_history::source_held::SourceHeldReceiptDataV1::
                decode(original.source_held, body.open.lane).map_err(|_| Error::History)?.record,
            KeyV1::new(body.open.lane, OwnerV1::Source, 1).map_err(|_| Error::History)?,
            PhaseV1::new(OwnerV1::Source, 1).map_err(|_| Error::History)?).map_err(|_| Error::History)?;
        let cache_held = cache.verified_body_v1()?.cache_held_checksum;
        if source.fields_v1()?.held_head != source_held.checksum() { return Err(Error::History); }
        let root_outcome = outcome.completed_receipt_v1()?.record_data(body.open.lane, ContinuationKindV1::OutcomeRecorded)
            .map_err(|_| Error::History)?;
        let c9 = outcome.completed_controller_v1()?.outcome_suffix_v1()?.expected_v1()?[3]
            .records().first().and_then(|record| record.value()).ok_or(Error::History)?;
        let c9 = RecordEnvelopeV1::decode(c9, KeyV1::new(body.open.lane, OwnerV1::Controller, 9).map_err(|_| Error::History)?,
            PhaseV1::new(OwnerV1::Controller, 8).map_err(|_| Error::History)?).map_err(|_| Error::History)?;
        self.joins = Some(proof.require_links(body.open.lane, root_outcome.checksum(), c9.checksum(),
            source_held.checksum(), cache_held));
        positive(&self.joins).map(|_| ()).map_err(|_| Error::History)
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if self.complete && !self.closed { Ok(()) } else { Err(Error::History) }
    }

    pub(crate) fn proofs_v1(&self, lane: [u8; 16]) -> Result<ReleaseProofsDataV1<'_>, Error> {
        self.require_complete_v1()?;
        ReleaseProofsDataV1::decode(&self.frame.bytes()[FRAME_HEADER_BYTES..], lane).map_err(|_| Error::History)
    }

    pub(crate) fn controller_receipt_v1(&self, lane: [u8; 16]) -> Result<ContinuationNativeReceiptDataV1<'_>, Error> {
        ContinuationNativeReceiptDataV1::decode(self.proofs_v1(lane)?.controller, lane,
            ContinuationKindV1::HandoffRetained).map_err(|_| Error::History)
    }

    pub(crate) fn handoff_v1(&self) -> Result<HandoffRetainedBodyDataV1, Error> {
        self.require_complete_v1()?;
        positive(&self.joins).copied().map_err(|_| Error::History)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.geometry.as_ref().err().map(|cause| cause as _).or_else(|| self.before.failure())
            .or_else(|| cause(&self.before_readback)).or_else(|| self.frame.failure())
            .or_else(|| self.chunks.failure()).or_else(|| cause(&self.framing)).or_else(|| cause(&self.joins))
            .or_else(|| cause(&self.primary)).or_else(|| self.after.failure())
            .or_else(|| cause(&self.after_readback)).or_else(|| cause(&self.live)).or_else(|| cause(&self.interval))
    }
}

pub(super) fn require_live(root: &RootCurrentOpenStateV1, outcome: &RootCurrentOutcomeStateV1,
    reserved: &RootCurrentUseReservedStateV1, source: &RootCurrentSourceExchangeStateV1,
    sample: aos_sandbox_model::RawPairedClockSample) -> Result<(), JournalError> {
    root.require_clock(sample)?;
    outcome.completed_controller_v1().map_err(|_| JournalError::ProtectedBoundary)?.require_live_at_v1(sample)?;
    outcome.completed_session_v1().map_err(|_| JournalError::ProtectedBoundary)?.require_live_at_v1(sample)?;
    reserved.completed_readonly_v1().map_err(|_| JournalError::ProtectedBoundary)?.require_live_at_v1(sample)?;
    if sample.boottime_nanoseconds() >= source.original_cutoff_v1().map_err(|_| JournalError::ProtectedBoundary)? {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: StdError + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
