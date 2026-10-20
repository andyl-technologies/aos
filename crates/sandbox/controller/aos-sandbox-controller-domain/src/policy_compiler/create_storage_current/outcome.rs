//! Records Root5 after independent C9 and actual Storage Session acceptance.
//!
//! No advancement expectation supplies native readback. The owned read turn
//! checks the original signed Prepare, full Controller suffix and actual stored
//! terminal before the shared Root pair append or Frame21 acknowledgment.

use std::error::Error as StdError;
use std::fs::Metadata;
use std::io;
use std::os::unix::net::UnixStream;
use aos_sandbox_model::ResourceVector;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1,
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1},
    outcome::{RootOutcomeBodyDataV1, ROOT_OUTCOME_BODY_BYTES_V1,
        ROOT_OUTCOME_RECORD_BYTES_V1, ROOT_OUTCOME_RECEIPT_BYTES_V1,
        CONTROLLER_OUTCOME_RECEIPT_BYTES_V1},
    transport::{FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameKindV1}};
use crate::journal::{Journal, JournalError, ProtectedJournalPreopenReplayExtentV1};
use crate::normal_root::RootPolicyAcceptedFlightV1;
use crate::policy_compiler::bounded_stream_io::{SliceDeadlineStreamIoV1, DeadlineStreamDirectionV1};
use crate::policy_compiler::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::{RootCreateStorageCurrentErrorV1 as Error,
    bundle_ownership::RootCurrentBundleOwnershipStateV1,
    cache_current::RootCurrentCacheProofStateV1,
    controller_readonly::{RootCurrentControllerReadonlyStateV1,
        storage_inventory::RootVerifiedSessionTerminalV1,
        native_read::RootFixedNativeReadOriginalsV1},
    history_pair::RootCurrentHistoryPairV1,
    policy_inputs::RootCurrentPolicyInputDataV1,
    ready::{RootCurrentReadyStateV1, subject::RootCurrentChunkReceivingV1},
    root_open::{RootCurrentOpenStateV1, RootCurrentHistoryPostsV1, RootCurrentHistoryPurposeV1},
    signed_bound::RootCurrentSignedBoundStateV1,
    source_current::RootCurrentSourceExchangeStateV1,
    use_admitted::RootCurrentUseAdmittedStateV1,
    use_authorized::RootCurrentUseAuthorizedStateV1,
    use_reserved::RootCurrentUseReservedStateV1};

pub(crate) mod input;
pub(crate) mod read;
use read::RootCurrentOutcomeReadV1;
const FRAME_BYTES: usize = FRAME_HEADER_BYTES + ROOT_OUTCOME_RECEIPT_BYTES_V1;
type Readback = crate::journal::create_storage_history::HistoryPairReadbackV1<ROOT_OUTCOME_RECORD_BYTES_V1>;

/// Selects an already-failed original solely for guarded diagnostic borrowing.
#[derive(Clone, Copy)]
pub(crate) enum OutcomeFinancialStageV1 { Fixed, Bytes, ControllerNative, ControllerSemantic, Session }

pub(crate) struct RootCurrentOutcomeStateV1 {
    read: RootCurrentOutcomeReadV1,
    body: Option<Result<RootOutcomeBodyDataV1, HistoryErrorV1>>,
    encoded: Option<Result<[u8; ROOT_OUTCOME_BODY_BYTES_V1], HistoryErrorV1>>,
    pair: RootCurrentHistoryPairV1<ROOT_OUTCOME_RECORD_BYTES_V1>,
    primary: Option<Result<(), Error>>,
    append_posts: RootCurrentHistoryPostsV1,
    append_live: Option<Result<(), JournalError>>,
    frame: [u8; FRAME_BYTES],
    ack_sequence: Option<u64>,
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

impl RootCurrentOutcomeStateV1 {
    pub(super) fn new() -> Self {
        Self { read: RootCurrentOutcomeReadV1::new(), body: None, encoded: None,
            pair: RootCurrentHistoryPairV1::new(), primary: None,
            append_posts: Default::default(), append_live: None,
            frame: [0; FRAME_BYTES], ack_sequence: None, framing: None,
            send: Default::default(), sent: None, send_posts: Default::default(),
            send_readback: None, send_metadata: None, send_live: None,
            complete: false, closed: false }
    }

    pub(crate) fn fixed_receiving_demand_v1(held: &ProtectedJournalPreopenReplayExtentV1,
        signed: &RootCurrentSignedBoundStateV1) -> Result<ResourceVector, JournalError>
    {
        let end = signed.completed_receipt_v1().map_err(|_| JournalError::ProtectedBoundary)?.after_end;
        let extent = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(held.limits, end)?;
        let owner = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<super::failure_view::RootCurrentFailureViewV1<'_>>()))
            .and_then(|bytes| bytes.checked_add(aos_sandbox_protocol::domain_ledger::create_q04_history::CLAIM_CHUNK_BYTES))
            .and_then(|bytes| bytes.checked_add(FRAME_HEADER_BYTES * 3 + CONTROLLER_OUTCOME_RECEIPT_BYTES_V1 + 48))
            .ok_or(JournalError::JournalTooLarge)?;
        let controller = RootCurrentControllerReadonlyStateV1::outcome_fixed_demand_v1()?;
        let session = RootFixedNativeReadOriginalsV1::fixed_demand_v1()?;
        let chunks = RootCurrentChunkReceivingV1::additional_receiving_demand_v1()?;
        let clocks = RootCurrentChunkReceivingV1::additional_clock_demand_v1()?;
        let bookend = RootCurrentHistoryPostsV1::additional_receiving_demand_v1()
            .map_err(|_| JournalError::JournalTooLarge)?;
        super::geometry::fixed_root_history_append_demand_v1(&extent,
            ROOT_OUTCOME_BODY_BYTES_V1, FRAME_BYTES + FRAME_HEADER_BYTES + CONTROLLER_OUTCOME_RECEIPT_BYTES_V1, owner)?
            .checked_add(controller)
            .and_then(|demand| demand.checked_add(session))
            .and_then(|demand| demand.checked_add(chunks))
            .and_then(|demand| demand.checked_add(clocks))
            .and_then(|demand| demand.checked_add(bookend))
            .and_then(|demand| demand.checked_add(bookend))
            .and_then(|demand| demand.checked_add(bookend))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn produce_once(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1, source: &RootCurrentSourceExchangeStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1, policy: &RootCurrentPolicyInputDataV1<'_>,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, signed: &RootCurrentSignedBoundStateV1,
    ) -> Result<(), Error> {
        if self.primary.is_some() || self.closed { self.closed = true; return Err(Error::Original); }
        self.append_posts.arm_once(flight)?;
        self.primary = Some(self.produce_inner(flight, writers, original, root, ready, cache,
            source, ownership, policy, authorization, reserved, admitted, signed));
        let body = root.completed_body().ok();
        let origin = root.original_clock_origin_v1().ok();
        self.append_posts.observe_once(flight, writers, body.as_ref(), origin.map(|pair| pair.0), origin.map(|pair| pair.1));
        self.append_live = Some(self.append_posts.require_complete().and_then(|()|
            self.read.require_live_at_v1(root, reserved, source, self.append_posts.sample()?)));
        positive(&self.primary).map_err(|_| Error::History)?;
        positive(&self.append_live).map_err(|_| Error::History)?;
        self.framing = Some(self.frame_once(root, ready, signed));
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
            self.read.require_live_at_v1(root, reserved, source, self.send_posts.sample()?)?;
            positive(&self.send_readback)?;
            self.pair.require_end(&self.send_metadata)
        })());
        self.complete = self.send.completed_exact() && matches!(self.send_live, Some(Ok(())))
            && self.failure_with_original(flight).is_none();
        self.require_complete_v1()
    }

    fn produce_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1, source: &RootCurrentSourceExchangeStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1, policy: &RootCurrentPolicyInputDataV1<'_>,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, signed: &RootCurrentSignedBoundStateV1,
    ) -> Result<(), Error> {
        self.read.observe_once(flight, writers, original, root, ready, cache, source,
            ownership, policy, authorization, reserved, admitted, signed)?;
        let open = root.completed_body()?;
        let controller = self.read.input.recorded_receipt_v1(open.open.lane)?
            .record_data(open.open.lane, ContinuationKindV1::ControllerOutcomeRecorded).map_err(|_| Error::History)?;
        let terminal = self.read.terminal_v1()?.actual_v1();
        self.body = Some(self.read.input.completed_bundle_v1()?.commitment().map(|bundle|
            RootOutcomeBodyDataV1 { controller_outcome: controller.checksum(),
                prepared_receipt: terminal.prepared_receipt, outcome_bundle: bundle }));
        self.encoded = Some(positive(&self.body).map_err(|_| Error::History)?.encode());
        let previous = signed.completed_receipt_v1()?.record_data(open.open.lane,
            ContinuationKindV1::SignedBound).map_err(|_| Error::History)?.checksum();
        self.pair.prepare_once(KeyV1::new(open.open.lane, OwnerV1::Root, 5).map_err(|_| Error::History)?,
            PhaseV1::new(OwnerV1::Root, 5).map_err(|_| Error::History)?, previous, open.open.seed,
            positive(&self.encoded).map_err(|_| Error::History)?).map_err(|_| Error::History)?;
        let purpose = RootCurrentHistoryPurposeV1::Outcome { root, signed, reserved, source, read: &self.read };
        self.pair.prepare_cut_once(root, purpose).map_err(|_| Error::History)?;
        let (authority, policy) = writers.authority_and_policy().map_err(|_| Error::Writers)?;
        self.pair.append_once(flight, original, authority, policy, root, purpose).map_err(|_| Error::History)
    }

    fn frame_once(&mut self, root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        signed: &RootCurrentSignedBoundStateV1) -> Result<(), HistoryErrorV1> {
        let body = root.completed_body().map_err(|_| HistoryErrorV1::Correlation)?;
        let readback = positive(&self.pair.readback).map_err(|_| HistoryErrorV1::Correlation)?;
        let committed = positive(&self.pair.append).map_err(|_| HistoryErrorV1::Correlation)?;
        let receipt = ContinuationNativeReceiptDataV1 { record: &self.pair.record, latest_head: readback.head,
            names: self.append_posts.authority_names_v1().map_err(|_| HistoryErrorV1::Correlation)?,
            after_next: readback.next, after_end: committed.durable_bytes };
        receipt.encode_into(body.open.lane, ContinuationKindV1::OutcomeRecorded, &mut self.frame[FRAME_HEADER_BYTES..])?;
        let sequence = 14_u64.checked_add(u64::from(ready.original_transfer_index_v1()
            .map_err(|_| HistoryErrorV1::Correlation)?.count()))
            .and_then(|value| value.checked_add(u64::from(signed.completed_index_v1().ok()?.count())))
            .and_then(|value| value.checked_add(u64::from(self.read.input.index_v1().ok()?.count())))
            .ok_or(HistoryErrorV1::Extent)?;
        let header = FrameCoordinatesV1 { kind: FrameKindV1::RootOutcomeRecorded,
            lane: body.open.lane, sequence, root_nonce: body.root_nonce,
            controller_nonce: body.open.controller_nonce }.encode_header(&self.frame[FRAME_HEADER_BYTES..])?;
        self.frame[..FRAME_HEADER_BYTES].copy_from_slice(&header);
        self.ack_sequence = Some(sequence);
        Ok(())
    }

    fn receipt_data_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'_>, Error> {
        let readback = positive(&self.pair.readback).map_err(|_| Error::History)?;
        let committed = positive(&self.pair.append).map_err(|_| Error::History)?;
        Ok(ContinuationNativeReceiptDataV1 { record: &self.pair.record, latest_head: readback.head,
            names: self.append_posts.authority_names_v1().map_err(|_| Error::History)?,
            after_next: readback.next, after_end: committed.durable_bytes })
    }

    pub(super) fn failed_financial_entry_v1(&self) -> Option<OutcomeFinancialStageV1> {
        self.read.failed_financial_entry_v1()
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if self.complete && !self.closed { self.read.require_complete_v1() } else { Err(Error::History) }
    }

    pub(crate) fn completed_receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'_>, Error> {
        self.require_complete_v1()?;
        self.receipt_data_v1()
    }

    pub(crate) fn readback_current_v1(&self, authority: &Journal, policy: &Journal) -> Result<Readback, JournalError> {
        self.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        self.pair.readback_current_v1(authority, policy)
    }

    pub(crate) fn completed_controller_v1(&self) -> Result<&RootCurrentControllerReadonlyStateV1, Error> {
        self.require_complete_v1()?;
        self.read.controller_v1()
    }

    pub(crate) fn completed_session_v1(&self) -> Result<&RootVerifiedSessionTerminalV1, Error> {
        self.require_complete_v1()?;
        self.read.terminal_v1()
    }

    pub(crate) fn completed_ack_sequence_v1(&self) -> Result<u64, Error> {
        self.require_complete_v1()?;
        self.ack_sequence.ok_or(Error::History)
    }

    pub(crate) fn failure_with_original<'a>(&'a self, flight: &'a RootPolicyAcceptedFlightV1<'_, '_>)
        -> Option<&'a (dyn StdError + 'static)> {
        self.read.failure_with_original(flight).or_else(|| cause(&self.body)).or_else(|| cause(&self.encoded))
            .or_else(|| self.pair.failure()).or_else(|| cause(&self.primary))
            .or_else(|| self.append_posts.failure()).or_else(|| cause(&self.append_live))
            .or_else(|| cause(&self.framing)).or_else(|| self.send.failure()).or_else(|| cause(&self.sent))
            .or_else(|| self.send_posts.failure()).or_else(|| cause(&self.send_readback))
            .or_else(|| cause(&self.send_metadata)).or_else(|| cause(&self.send_live))
    }
}

fn positive<T, E>(value: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: StdError + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
