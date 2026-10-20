//! Records Root6 after independent C10, released Source/Cache and positive U readback.
//!
//! No advancement expectation supplies native readback. The owned read turn
//! checks the original signed Prepare, full Controller suffix and actual stored
//! terminal before the shared Root pair append or Frame16 closure.

use std::error::Error as StdError;
use std::fs::Metadata;
use std::io;
use std::os::unix::net::UnixStream;
use aos_sandbox_core::ResourceVector;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1,
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1},
    outcome::{RootClosedBodyDataV1, ROOT_CLOSED_BODY_BYTES_V1,
        ROOT_CLOSED_RECORD_BYTES_V1, ROOT_CLOSED_RECEIPT_BYTES_V1,
        RELEASE_PROOFS_BYTES_V1},
    transport::{FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameKindV1}};
use crate::journal::{Journal, JournalError, ProtectedJournalPreopenReplayExtentV1};
use crate::normal_root::RootPolicyAcceptedFlightV1;
use crate::policy_compiler::bounded_stream_io::{SliceDeadlineStreamIoV1, DeadlineStreamDirectionV1};
use crate::policy_compiler::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::{RootCreateStorageCurrentErrorV1 as Error,
    bundle_ownership::RootCurrentBundleOwnershipStateV1,
    cache_current::RootCurrentCacheProofStateV1,
    controller_readonly::{RootCurrentControllerReadonlyStateV1,
        native_read::RootFixedNativeReadOriginalsV1},
    history_pair::RootCurrentHistoryPairV1,
    policy_inputs::RootCurrentPolicyInputDataV1,
    ready::{RootCurrentReadyStateV1, subject::RootCurrentChunkReceivingV1},
    root_open::{RootCurrentOpenStateV1, RootCurrentHistoryPostsV1, RootCurrentHistoryPurposeV1},
    signed_bound::RootCurrentSignedBoundStateV1,
    source_current::RootCurrentSourceExchangeStateV1,
    use_authorized::RootCurrentUseAuthorizedStateV1,
    use_reserved::RootCurrentUseReservedStateV1,
    outcome::RootCurrentOutcomeStateV1};

pub(crate) mod input;
pub(crate) mod read;
use read::RootCurrentClosedReadV1;
const FRAME_BYTES: usize = FRAME_HEADER_BYTES + ROOT_CLOSED_RECEIPT_BYTES_V1;
type Readback = crate::journal::create_storage_history::HistoryPairReadbackV1<ROOT_CLOSED_RECORD_BYTES_V1>;

/// Selects one private actual same-R terminal receiving frontier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClosedFinancialStageV1 {
    Fixed, ControllerNative, ControllerSemantic, SourceNative, SourceSemantic, CacheNative, CacheSemantic,
}

impl ClosedFinancialStageV1 {
    pub(crate) const fn index_v1(self) -> usize { self as usize }
}

pub(crate) struct RootCurrentTerminalCompletionV1 {
    actual_receipt: [u8; ROOT_CLOSED_RECEIPT_BYTES_V1],
    actual_identities: [crate::journal::root_construction::RootJournalServingIdentityV1; 2],
}

impl RootCurrentTerminalCompletionV1 {
    /// Checks the sole actual native floor successor of these retained Root6 cuts.
    pub(crate) fn require_execution_floor_successor_v2(&self,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &super::pins::RootCurrentPinsStateV1,
        floor: &crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyFloorOriginalV2,
    ) -> Result<(), JournalError> {
        floor.require_policy_successor_v2(writers, pins, &self.actual_identities)
    }

    /// Advances only the actual identities certified by completed native ACK.
    ///
    /// The original literal Root6 receipt remains unchanged. No decoded ACK,
    /// supplied sequence, replacement Policy or financial allocation can issue
    /// this succession; the genuine verifier retains its independent final
    /// C/Host Session/Source and Root native post results.
    pub(crate) fn certify_execution_no_apply_successor_once_v2(&mut self,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &super::pins::RootCurrentPinsStateV1,
        floor: &crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyFloorOriginalV2,
        acknowledged: &crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyAckOriginalV2,
    ) -> Result<(), JournalError> {
        acknowledged.require_serving_successor_v2(writers, pins, floor, &self.actual_identities)?;
        self.actual_identities = writers.serving_identities_v1()?;
        Ok(())
    }

    pub(crate) fn require_serving_pair_v1(&self, writers: &RootCreateStorageCurrentWritersV1) -> Result<(), Error> {
        writers.require_serving_identities_v1(&self.actual_identities).map_err(|_| Error::Writers)
    }

    // The terminal producer retained these bytes from the actual positive
    // native/send owner. This is a historical association comparison only;
    // a new purpose still owes its own R, cold reads and independent posts.
    pub(crate) fn require_same_receipt_data_v1(&self, encoded: &[u8]) -> Result<(), Error> {
        if encoded == self.actual_receipt { Ok(()) } else { Err(Error::Original) }
    }

}

pub(crate) struct RootCurrentClosedStateV1 {
    read: RootCurrentClosedReadV1,
    body: Option<Result<RootClosedBodyDataV1, HistoryErrorV1>>,
    encoded: Option<Result<[u8; ROOT_CLOSED_BODY_BYTES_V1], HistoryErrorV1>>,
    pair: RootCurrentHistoryPairV1<ROOT_CLOSED_RECORD_BYTES_V1>,
    primary: Option<Result<(), Error>>,
    append_posts: RootCurrentHistoryPostsV1,
    append_live: Option<Result<(), JournalError>>,
    frame: [u8; FRAME_BYTES],
    terminal: Option<RootCurrentTerminalCompletionV1>,
    terminal_error: Option<JournalError>,
    framing: Option<Result<(), HistoryErrorV1>>,
    send: SliceDeadlineStreamIoV1,
    sent: Option<Result<(), HistoryErrorV1>>,
    send_posts: RootCurrentHistoryPostsV1,
    send_readback: Option<Result<Readback, JournalError>>,
    send_metadata: Option<io::Result<Metadata>>,
    send_live: Option<Result<(), JournalError>>,
    complete: bool,
    closed: bool,
}

impl RootCurrentClosedStateV1 {
    pub(super) fn new() -> Self {
        Self { read: RootCurrentClosedReadV1::new(), body: None, encoded: None,
            pair: RootCurrentHistoryPairV1::new(), primary: None,
            append_posts: Default::default(), append_live: None,
            frame: [0; FRAME_BYTES], terminal: None, terminal_error: None, framing: None,
            send: Default::default(), sent: None, send_posts: Default::default(),
            send_readback: None, send_metadata: None, send_live: None,
            complete: false, closed: false }
    }

    pub(crate) fn fixed_receiving_demand_v1(held: &ProtectedJournalPreopenReplayExtentV1,
        outcome: &RootCurrentOutcomeStateV1) -> Result<ResourceVector, JournalError> {
        let end = outcome.completed_receipt_v1().map_err(|_| JournalError::ProtectedBoundary)?.after_end;
        let extent = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(held.limits, end)?;
        let owner = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(FRAME_HEADER_BYTES + RELEASE_PROOFS_BYTES_V1))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let comparison_bytes = 2_usize.checked_mul(3).and_then(|copies| copies.checked_mul(
            aos_sandbox_protocol::domain_ledger::create_storage_history::outcome::RELEASED_RECORD_BYTES_V1
                + aos_sandbox_protocol::domain_ledger::create_storage_history::HEAD_BYTES
                + 2 * aos_sandbox_protocol::domain_ledger::create_storage_history::KEY_BYTES
                + 2 * std::mem::size_of::<crate::journal::JournalRecord>()
                + std::mem::size_of::<crate::journal::JournalTransaction>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let controller = RootCurrentControllerReadonlyStateV1::closed_fixed_demand_v1()?;
        let source = RootFixedNativeReadOriginalsV1::source_release_fixed_demand_v1()?;
        let cache = RootFixedNativeReadOriginalsV1::cache_release_fixed_demand_v1()?;
        let chunks = RootCurrentChunkReceivingV1::additional_receiving_demand_v1()?;
        let clock = RootCurrentChunkReceivingV1::additional_clock_demand_v1()?;
        let post = RootCurrentHistoryPostsV1::additional_receiving_demand_v1()?;
        let identity = RootCreateStorageCurrentWritersV1::serving_identity_demand_v1()?;
        let mut demand = super::geometry::fixed_root_history_append_demand_v1(&extent,
            ROOT_CLOSED_BODY_BYTES_V1, FRAME_BYTES + FRAME_HEADER_BYTES + RELEASE_PROOFS_BYTES_V1,
            usize::try_from(owner).map_err(|_| JournalError::JournalTooLarge)?)?;
        let disposition = super::OriginalRootCreateStorageCurrentAttemptV1::positive_disposition_demand_v1()?;
        let comparisons = ResourceVector::ZERO.with(aos_sandbox_core::ResourceDimension::MemoryBytes, comparison_bytes);
        for extra in [controller, source, cache, chunks, clock, post, post, post, identity, comparisons, disposition] {
            demand = demand.checked_add(extra).map_err(|_| JournalError::JournalTooLarge)?;
        }
        Ok(demand)
    }

    pub(super) fn produce_once(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1, source: &RootCurrentSourceExchangeStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1, policy: &RootCurrentPolicyInputDataV1<'_>,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        signed: &RootCurrentSignedBoundStateV1, outcome: &RootCurrentOutcomeStateV1,
    ) -> Result<(), Error> {
        if self.primary.is_some() || self.closed { self.closed = true; return Err(Error::Original); }
        self.append_posts.arm_once(flight)?;
        self.primary = Some(self.produce_inner(flight, writers, original, root, ready, cache,
            source, ownership, policy, authorization, reserved, signed, outcome));
        let body = root.completed_body().ok();
        let origin = root.original_clock_origin_v1().ok();
        self.append_posts.observe_once(flight, writers, body.as_ref(), origin.map(|pair| pair.0), origin.map(|pair| pair.1));
        self.append_live = Some(self.append_posts.require_complete().and_then(|()|
            self.read.require_live_at_v1(root, reserved, source, outcome, self.append_posts.sample()?)));
        positive(&self.primary).map_err(|_| Error::History)?;
        positive(&self.append_live).map_err(|_| Error::History)?;
        self.framing = Some(self.frame_once(root, outcome));
        positive(&self.framing).map_err(|_| Error::History)?;
        self.send_posts.arm_once(flight)?;
        self.sent = Some(self.send.run_once(&mut &*original, &mut self.frame,
            source.original_cutoff_v1()?, DeadlineStreamDirectionV1::Write));
        self.send_posts.observe_once(flight, writers, body.as_ref(), origin.map(|pair| pair.0), origin.map(|pair| pair.1));
        match writers.authority_and_policy() {
            Ok((authority, policy)) => {
                self.send_readback = Some(self.pair.readback_pair(authority, policy));
                self.send_metadata = Some(authority.held_native_receiving_metadata_v1().0);
            }
            Err(cause) => self.send_readback = Some(Err(cause)),
        }
        self.send_live = Some((|| {
            self.send_posts.require_complete()?;
            self.read.require_live_at_v1(root, reserved, source, outcome, self.send_posts.sample()?)?;
            positive(&self.send_readback)?;
            self.pair.require_end(&self.send_metadata)
        })());
        self.complete = self.send.completed_exact() && matches!(self.send_live, Some(Ok(())))
            && self.failure_with_original(flight).is_none();
        if self.complete {
            match writers.serving_identities_v1() {
                Ok(actual_identities) => {
                    let mut actual_receipt = [0; ROOT_CLOSED_RECEIPT_BYTES_V1];
                    actual_receipt.copy_from_slice(&self.frame[FRAME_HEADER_BYTES..]);
                    self.terminal = Some(RootCurrentTerminalCompletionV1 { actual_identities, actual_receipt });
                }
                Err(cause) => self.terminal_error = Some(cause),
            }
        }
        self.require_complete_v1()
    }

    fn produce_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1, source: &RootCurrentSourceExchangeStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1, policy: &RootCurrentPolicyInputDataV1<'_>,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        signed: &RootCurrentSignedBoundStateV1, outcome: &RootCurrentOutcomeStateV1,
    ) -> Result<(), Error> {
        self.read.observe_once(flight, writers, original, root, ready, source, cache,
            ownership, policy, authorization, reserved, signed, outcome)?;
        let open = root.completed_body()?;
        let proofs = self.read.input.proofs_v1(open.open.lane)?;
        let controller = self.read.input.controller_receipt_v1(open.open.lane)?
            .record_data(open.open.lane, ContinuationKindV1::HandoffRetained).map_err(|_| Error::History)?;
        let source_release = ContinuationNativeReceiptDataV1::decode(proofs.source, open.open.lane,
            ContinuationKindV1::SourceReleased).map_err(|_| Error::History)?
            .record_data(open.open.lane, ContinuationKindV1::SourceReleased).map_err(|_| Error::History)?;
        let cache_release = ContinuationNativeReceiptDataV1::decode(proofs.cache, open.open.lane,
            ContinuationKindV1::CacheReleased).map_err(|_| Error::History)?
            .record_data(open.open.lane, ContinuationKindV1::CacheReleased).map_err(|_| Error::History)?;
        self.body = Some(Ok(RootClosedBodyDataV1 { handoff_retained: controller.checksum(),
            source_released: source_release.checksum(), cache_released: cache_release.checksum(),
            committed_use_claim: self.read.controller_v1()?.closed_suffix_v1()?.committed_claim_v1()? }));
        self.encoded = Some(positive(&self.body).map_err(|_| Error::History)?.encode());
        let previous = outcome.completed_receipt_v1()?.record_data(open.open.lane,
            ContinuationKindV1::OutcomeRecorded).map_err(|_| Error::History)?.checksum();
        self.pair.prepare_once(KeyV1::new(open.open.lane, OwnerV1::Root, 6).map_err(|_| Error::History)?,
            PhaseV1::new(OwnerV1::Root, 6).map_err(|_| Error::History)?, previous, open.open.seed,
            positive(&self.encoded).map_err(|_| Error::History)?).map_err(|_| Error::History)?;
        let purpose = RootCurrentHistoryPurposeV1::Closed { root, outcome, reserved, source, read: &self.read };
        self.pair.prepare_cut_once(root, purpose).map_err(|_| Error::History)?;
        let (authority, policy) = writers.authority_and_policy().map_err(|_| Error::Writers)?;
        self.pair.append_once(flight, original, authority, policy, root, purpose).map_err(|_| Error::History)
    }

    fn frame_once(&mut self, root: &RootCurrentOpenStateV1,
        outcome: &RootCurrentOutcomeStateV1) -> Result<(), HistoryErrorV1> {
        let body = root.completed_body().map_err(|_| HistoryErrorV1::Correlation)?;
        let readback = positive(&self.pair.readback).map_err(|_| HistoryErrorV1::Correlation)?;
        let committed = positive(&self.pair.append).map_err(|_| HistoryErrorV1::Correlation)?;
        let receipt = ContinuationNativeReceiptDataV1 { record: &self.pair.record, latest_head: readback.head,
            names: self.append_posts.authority_names_v1().map_err(|_| HistoryErrorV1::Correlation)?,
            after_next: readback.next, after_end: committed.durable_bytes };
        receipt.encode_into(body.open.lane, ContinuationKindV1::Closed, &mut self.frame[FRAME_HEADER_BYTES..])?;
        let sequence = outcome.completed_ack_sequence_v1().map_err(|_| HistoryErrorV1::Correlation)?
            .checked_add(2).ok_or(HistoryErrorV1::Extent)?;
        let header = FrameCoordinatesV1 { kind: FrameKindV1::Closed,
            lane: body.open.lane, sequence, root_nonce: body.root_nonce,
            controller_nonce: body.open.controller_nonce }.encode_header(&self.frame[FRAME_HEADER_BYTES..])?;
        self.frame[..FRAME_HEADER_BYTES].copy_from_slice(&header);
        Ok(())
    }

    fn receipt_data_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'_>, Error> {
        let readback = positive(&self.pair.readback).map_err(|_| Error::History)?;
        let committed = positive(&self.pair.append).map_err(|_| Error::History)?;
        Ok(ContinuationNativeReceiptDataV1 { record: &self.pair.record, latest_head: readback.head,
            names: self.append_posts.authority_names_v1().map_err(|_| Error::History)?,
            after_next: readback.next, after_end: committed.durable_bytes })
    }

    pub(super) fn failed_financial_entry_v1(&self) -> Option<ClosedFinancialStageV1> {
        self.read.failed_financial_entry_v1()
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if self.complete && !self.closed && self.terminal.is_some() { self.read.require_complete_v1() } else { Err(Error::History) }
    }

    pub(crate) fn completed_receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'_>, Error> {
        self.require_complete_v1()?;
        self.receipt_data_v1()
    }

    pub(crate) fn readback_current_v1(&self, authority: &Journal, policy: &Journal) -> Result<Readback, JournalError> {
        self.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        self.pair.readback_current_v1(authority, policy)
    }

    pub(crate) fn take_terminal_once_v1(&mut self) -> Result<RootCurrentTerminalCompletionV1, Error> {
        self.require_complete_v1()?;
        self.terminal.take().ok_or(Error::Original)
    }

    pub(crate) fn failure_with_original<'a>(&'a self, flight: &'a RootPolicyAcceptedFlightV1<'_, '_>)
        -> Option<&'a (dyn StdError + 'static)> {
        self.read.failure_with_original(flight).or_else(|| cause(&self.body)).or_else(|| cause(&self.encoded))
            .or_else(|| self.pair.failure()).or_else(|| cause(&self.primary))
            .or_else(|| self.append_posts.failure()).or_else(|| cause(&self.append_live))
            .or_else(|| cause(&self.framing)).or_else(|| self.send.failure()).or_else(|| cause(&self.sent))
            .or_else(|| self.send_posts.failure()).or_else(|| cause(&self.send_readback))
            .or_else(|| cause(&self.send_metadata)).or_else(|| cause(&self.send_live))
            .or_else(|| self.terminal_error.as_ref().map(|cause| cause as _))
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: StdError + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
