//! Retains the exact ReleaseProofs frame from the same owned accepted stream.
//!
//! Parsed proof fields remain comparison DATA until their independent C10,
//! Source and Cache native readers complete. The genuine subject borrower owns
//! all reached receive/copy/clock/disposal results; supplied bytes cannot enter.

use super::super::super::{
    initial_cache::RootInitialCacheProofOriginalV1,
    initial_open::{RootInitialOpenErrorV1, RootInitialOpenPreparedOriginalV1},
    initial_post::RootInitialOpenPostsOriginalV1,
    initial_ready::RootInitialReadyOriginalV1,
    initial_source_exchange::RootInitialSourceExchangeOriginalV1,
    initial_subject::{RootInitialSubjectFrameBorrowV1, RootInitialSubjectOriginalV1},
    owned::RootCurrentAcceptedOriginalsV1,
    writers::RootCurrentWritersOriginalV1,
};
use super::super::outcome::RootUseOutcomeOriginalV1;
use super::super::reserved::RootUseReservedOriginalV1;
use crate::native::startup::RootCurrentWritersPredecessorV1;
use aos_sandbox_broker::receiving::{
    RootObservationErrorV1, RootSelectedControllerSubjectSampleV1, RootSelectedStartupBorrowV1,
    RootUpperMutationGuardV1,
};
use aos_sandbox_model::RawPairedClockSample;
use aos_sandbox_linux::unix_stream::{RetainedSubjectStreamReadV1, SubjectStreamReceiveGeometryV1};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1},
    outcome::{HandoffRetainedBodyDataV1, RELEASE_PROOFS_BYTES_V1, ReleaseProofsDataV1},
    ready::ReadyBundleDataV1,
    transport::{FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameEnvelopeV1, FrameKindV1},
};
use std::error::Error;

type Slot<T, F = RootReleaseInputErrorV1> = Option<Result<T, F>>;

/// Retains an actual final release-frame, correlation or independent post cause.
#[derive(Debug, thiserror::Error)]
pub enum RootReleaseInputErrorV1 {
    /// Retains the original native post, frame subject or original clock refusal.
    #[error(transparent)]
    Open(#[from] RootInitialOpenErrorV1),
    /// Retains canonical release-envelope or exact-link refusal.
    #[error(transparent)]
    Format(#[from] HistoryErrorV1),
    /// The genuine receive/copy/disposal, predecessor or owed post is incomplete.
    #[error("native release input is incomplete")]
    Incomplete,
}
type E = RootReleaseInputErrorV1;

pub(in crate::native::root_current) struct RootReleaseInputOriginalV1 {
    geometry: Result<SubjectStreamReceiveGeometryV1, aos_sandbox_linux::seqpacket::SeqpacketError>,
    before: RootInitialOpenPostsOriginalV1,
    before_arm: Slot<(), RootObservationErrorV1>,
    after_arm: Slot<(), RootObservationErrorV1>,
    before_readback: Slot<(), RootInitialOpenErrorV1>,
    frame: RetainedSubjectStreamReadV1,
    chunks: RootInitialSubjectOriginalV1,
    framing: Slot<(), HistoryErrorV1>,
    joins: Slot<HandoffRetainedBodyDataV1, HistoryErrorV1>,
    primary: Slot<()>,
    after: RootInitialOpenPostsOriginalV1,
    after_readback: Slot<(), RootInitialOpenErrorV1>,
    live: Slot<()>,
    interval: Slot<(), aos_sandbox_model::OwnershipLeaseVerificationError>,
    entered: bool,
    closed: bool,
}

impl RootReleaseInputOriginalV1 {
    pub(in crate::native::root_current) fn new() -> Self {
        Self {
            geometry: RootSelectedControllerSubjectSampleV1::receive_geometry_v1(),
            before: RootInitialOpenPostsOriginalV1::new(),
            before_arm: None,
            after_arm: None,
            before_readback: None,
            frame: RetainedSubjectStreamReadV1::new(),
            chunks: RootInitialSubjectOriginalV1::new(),
            framing: None,
            joins: None,
            primary: None,
            after: RootInitialOpenPostsOriginalV1::new(),
            after_readback: None,
            live: None,
            interval: None,
            entered: false,
            closed: false,
        }
    }

    pub(in crate::native::root_current) fn arm_before_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.before_arm.is_some() {
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.before_arm = Some(self.before.arm_once_v1(predecessor, startup, exclusion));
        if matches!(self.before_arm, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        }
    }

    pub(in crate::native::root_current) fn arm_after_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if !matches!(self.before_arm, Some(Ok(()))) || self.after_arm.is_some() {
            self.closed = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.after_arm = Some(self.after.arm_once_v1(predecessor, startup, exclusion));
        if matches!(self.after_arm, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootObservationErrorV1::Service)
        }
    }

    pub(in crate::native::root_current) fn begin_receive_once_v1(
        &mut self,
        writers: &mut RootCurrentWritersOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        outcome: &RootUseOutcomeOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
    ) -> Result<(), E> {
        if self.entered || self.closed || self.primary.is_some() {
            self.closed = true;
            return Err(E::Incomplete);
        }
        positive(&self.before_arm)?;
        positive(&self.after_arm)?;
        self.entered = true;
        outcome.require_complete_v1().map_err(|_| E::Incomplete)?;
        self.before
            .observe_once_v1(writers, open, &originals.peer, &originals.stream);
        self.before_readback = Some(match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => outcome
                .readback_current_v1(authority, policy)
                .map(|_| ())
                .map_err(|_| RootInitialOpenErrorV1::Boundary),
            Err(error) => Err(RootInitialOpenErrorV1::Root(error)),
        });
        self.before.require_complete_v1()?;
        positive(&self.before_readback)?;
        self.frame
            .prepare_exact_once(FRAME_HEADER_BYTES + RELEASE_PROOFS_BYTES_V1)
            .map_err(|_| E::Incomplete)
    }

    pub(in crate::native::root_current) fn borrow_subject_once_v1<'cut, 'startup>(
        &'cut mut self,
        originals: &'cut mut RootCurrentAcceptedOriginalsV1<'startup>,
        open: &'cut RootInitialOpenPreparedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
    ) -> Result<RootInitialSubjectFrameBorrowV1<'cut, 'startup>, RootInitialOpenErrorV1> {
        if !self.entered || self.primary.is_some() || self.closed {
            return Err(RootInitialOpenErrorV1::Boundary);
        }
        let geometry = *self
            .geometry
            .as_ref()
            .map_err(|_| RootInitialOpenErrorV1::Boundary)?;
        self.chunks
            .borrow_source_frame_v1(&mut self.frame, originals, open, source, geometry)
    }

    pub(in crate::native::root_current) fn decode_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        outcome: &RootUseOutcomeOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
    ) -> Result<(), E> {
        if self.primary.is_some() || self.closed {
            self.closed = true;
            return Err(E::Incomplete);
        }
        let result = self.decode_inner(open, ready, outcome, source, cache);
        self.primary = Some(result);
        positive(&self.primary).map(|_| ())
    }

    fn decode_inner(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        outcome: &RootUseOutcomeOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
    ) -> Result<(), E> {
        if !self.frame.completed_exact() || !self.chunks.disposed_v1() {
            return Err(E::Incomplete);
        }
        let body = open.body_v1()?;
        self.framing = Some(
            FrameEnvelopeV1::decode(
                self.frame.bytes(),
                FrameCoordinatesV1 {
                    kind: FrameKindV1::ReleaseProofs,
                    lane: body.open.lane,
                    sequence: outcome
                        .completed_ack_sequence_v1()
                        .map_err(|_| E::Incomplete)?
                        .checked_add(1)
                        .ok_or(E::Incomplete)?,
                    root_nonce: body.root_nonce,
                    controller_nonce: body.open.controller_nonce,
                },
            )
            .map(|_| ()),
        );
        positive(&self.framing)?;
        let proof =
            ReleaseProofsDataV1::decode(&self.frame.bytes()[FRAME_HEADER_BYTES..], body.open.lane)?;
        let original =
            ReadyBundleDataV1::borrow_field_framing_data_v1(ready.raw_ready_bytes_v1()?)?;
        let source_held=RecordEnvelopeV1::decode(
            aos_sandbox_protocol::domain_ledger::create_storage_history::source_held::SourceHeldReceiptDataV1::decode(original.source_held,body.open.lane)?.record,
            KeyV1::new(body.open.lane,OwnerV1::Source,1)?,PhaseV1::new(OwnerV1::Source,1)?)?;
        let cache_held = cache
            .verified_body_v1()
            .map_err(|_| E::Incomplete)?
            .cache_held_checksum;
        if source.fields_v1().map_err(|_| E::Incomplete)?.held_head != source_held.checksum() {
            return Err(E::Incomplete);
        }
        let root_outcome = outcome
            .completed_receipt_v1()
            .map_err(|_| E::Incomplete)?
            .record_data(body.open.lane, ContinuationKindV1::OutcomeRecorded)?;
        let c9 = outcome
            .completed_controller_v1()
            .map_err(|_| E::Incomplete)?
            .outcome_suffix_v1()
            .map_err(|_| E::Incomplete)?
            .expected_v1()
            .map_err(|_| E::Incomplete)?[3]
            .records()
            .first()
            .and_then(|record| record.value())
            .ok_or(E::Incomplete)?;
        let c9 = RecordEnvelopeV1::decode(
            c9,
            KeyV1::new(body.open.lane, OwnerV1::Controller, 9)?,
            PhaseV1::new(OwnerV1::Controller, 8)?,
        )?;
        self.joins = Some(proof.require_links(
            body.open.lane,
            root_outcome.checksum(),
            c9.checksum(),
            source_held.checksum(),
            cache_held,
        ));
        positive(&self.joins).map(|_| ())
    }

    pub(in crate::native::root_current) fn observe_after_once_v1(
        &mut self,
        writers: &mut RootCurrentWritersOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        open: &RootInitialOpenPreparedOriginalV1,
        outcome: &RootUseOutcomeOriginalV1,
        reserved: &RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
    ) {
        if !self.entered || self.after_readback.is_some() {
            return;
        }
        self.after
            .observe_once_v1(writers, open, &originals.peer, &originals.stream);
        self.after_readback = Some(match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => outcome
                .readback_current_v1(authority, policy)
                .map(|_| ())
                .map_err(|_| RootInitialOpenErrorV1::Boundary),
            Err(error) => Err(RootInitialOpenErrorV1::Root(error)),
        });
        self.live = Some((|| {
            self.after.require_complete_v1()?;
            positive(&self.after_readback)?;
            require_live(open, outcome, reserved, source, self.after.sample_v1()?)
        })());
        if let (Ok(before), Ok(after)) = (self.before.sample_v1(), self.after.sample_v1()) {
            self.interval = Some(before.validate_later_sample(after));
        }
    }

    pub(in crate::native::root_current) fn require_complete_v1(&self) -> Result<(), E> {
        if !self.entered || self.closed || !self.chunks.disposed_v1() {
            return Err(E::Incomplete);
        }
        positive(&self.primary)?;
        positive(&self.live)?;
        positive(&self.interval)?;
        if self.failure_v1().is_some() {
            Err(E::Incomplete)
        } else {
            Ok(())
        }
    }

    pub(in crate::native::root_current) fn proofs_v1(
        &self,
        lane: [u8; 16],
    ) -> Result<ReleaseProofsDataV1<'_>, E> {
        self.require_complete_v1()?;
        ReleaseProofsDataV1::decode(&self.frame.bytes()[FRAME_HEADER_BYTES..], lane)
            .map_err(E::from)
    }

    pub(in crate::native::root_current) fn controller_receipt_v1(
        &self,
        lane: [u8; 16],
    ) -> Result<ContinuationNativeReceiptDataV1<'_>, E> {
        ContinuationNativeReceiptDataV1::decode(
            self.proofs_v1(lane)?.controller,
            lane,
            ContinuationKindV1::HandoffRetained,
        )
        .map_err(E::from)
    }

    pub(in crate::native::root_current) fn handoff_v1(
        &self,
    ) -> Result<HandoffRetainedBodyDataV1, E> {
        self.require_complete_v1()?;
        positive(&self.joins).copied()
    }

    pub(in crate::native::root_current) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry
            .as_ref()
            .err()
            .map(|cause| cause as _)
            .or_else(|| cause(&self.before_arm))
            .or_else(|| cause(&self.after_arm))
            .or_else(|| self.before.failure_v1())
            .or_else(|| cause(&self.before_readback))
            .or_else(|| self.frame.failure())
            .or_else(|| self.chunks.failure_v1(&self.frame))
            .or_else(|| cause(&self.framing))
            .or_else(|| cause(&self.joins))
            .or_else(|| cause(&self.primary))
            .or_else(|| self.after.failure_v1())
            .or_else(|| cause(&self.after_readback))
            .or_else(|| cause(&self.live))
            .or_else(|| cause(&self.interval))
    }
}

fn require_live(
    open: &RootInitialOpenPreparedOriginalV1,
    outcome: &RootUseOutcomeOriginalV1,
    reserved: &RootUseReservedOriginalV1,
    source: &RootInitialSourceExchangeOriginalV1,
    sample: RawPairedClockSample,
) -> Result<(), E> {
    let body = open.body_v1()?;
    open.clock_original_v1()
        .require_current_v1(sample, body.cutoff)
        .map_err(RootInitialOpenErrorV1::from)?;
    outcome
        .require_live_at_v1(sample)
        .map_err(|_| E::Incomplete)?;
    reserved
        .completed_controller_v1()
        .map_err(|_| E::Incomplete)?
        .require_live_at_v1(sample)
        .map_err(|_| E::Incomplete)?;
    if sample.boottime_nanoseconds() >= source.original_cutoff_v1().map_err(|_| E::Incomplete)? {
        return Err(E::Incomplete);
    }
    Ok(())
}
fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or(E::Incomplete)
}
fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()
        .and_then(|value| value.as_ref().err())
        .map(|cause| cause as _)
}
