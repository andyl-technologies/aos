//! Commits Root3 from its actual reserved replay and both fresh current proofs.
//!
//! The original unsigned plan and signing statement remain in the SAME fresh
//! readonly compiler preparation. Root sends their complete bytes to Controller;
//! this stage owns no signing key and treats its receipt only as comparison DATA.

use std::collections::TryReserveError;
use std::error::Error as StdError;
use std::fs::Metadata;
use std::io;
use std::os::unix::net::UnixStream;

use aos_sandbox_core::{ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1,
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1,
        UseAdmittedBodyDataV1, UseAdmissionTransferDataV1,
        USE_ADMITTED_BODY_BYTES_V1, USE_ADMITTED_RECORD_BYTES_V1,
        USE_ADMITTED_RECEIPT_BYTES_V1},
    transport::{FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameKindV1},
    use_authorized::source_current_reply_commitment_v1,
    use_reserved::use_current_proofs_commitment_v1,
};
use sha2::{Digest as _, Sha256};
use crate::journal::{Journal, JournalError};
use crate::normal_root::RootPolicyAcceptedFlightV1;
use crate::policy_compiler::bounded_stream_io::{SliceDeadlineStreamIoV1, DeadlineStreamDirectionV1};
use crate::policy_compiler::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::{RootCreateStorageCurrentErrorV1 as Error,
    cache_current::RootCurrentCacheProofStateV1,
    ready::RootCurrentReadyStateV1,
    root_open::{RootCurrentOpenStateV1, RootCurrentHistoryPostsV1, RootCurrentHistoryPurposeV1},
    source_current::RootCurrentSourceExchangeStateV1,
    use_authorized::RootCurrentUseAuthorizedStateV1,
    use_reserved::RootCurrentUseReservedStateV1,
    history_pair::RootCurrentHistoryPairV1};

type Readback = crate::journal::create_storage_history::HistoryPairReadbackV1<USE_ADMITTED_RECORD_BYTES_V1>;

pub(crate) struct RootCurrentUseAdmittedStateV1 {
    body: Option<Result<UseAdmittedBodyDataV1, Error>>,
    encoded: Option<Result<[u8; USE_ADMITTED_BODY_BYTES_V1], HistoryErrorV1>>,
    pair: RootCurrentHistoryPairV1<USE_ADMITTED_RECORD_BYTES_V1>,
    primary: Option<Result<(), Error>>,
    append_posts: RootCurrentHistoryPostsV1,
    append_live: Option<Result<(), JournalError>>,
    receipt: [u8; USE_ADMITTED_RECEIPT_BYTES_V1],
    frame_length: Option<Result<usize, HistoryErrorV1>>,
    allocation: Option<Result<(), TryReserveError>>,
    frame: Vec<u8>,
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

impl RootCurrentUseAdmittedStateV1 {
    pub(super) fn new() -> Self {
        Self { body: None, encoded: None, pair: RootCurrentHistoryPairV1::new(),
            primary: None, append_posts: Default::default(), append_live: None,
            receipt: [0; USE_ADMITTED_RECEIPT_BYTES_V1], frame_length: None,
            allocation: None, frame: Vec::new(), framing: None, send: Default::default(),
            sent: None, send_posts: Default::default(), send_readback: None,
            send_metadata: None, send_live: None, complete: false, closed: false }
    }

    pub(crate) fn frame_bytes_v1(reserved: &RootCurrentUseReservedStateV1) -> Result<usize, JournalError> {
        let prepared = reserved.completed_readonly_v1().and_then(|read| read.prospective_use_plan_v1())
            .map_err(|_| JournalError::ProtectedBoundary)?.preparation_data_v1();
        FRAME_HEADER_BYTES.checked_add(20 + USE_ADMITTED_RECEIPT_BYTES_V1)
            .and_then(|bytes| bytes.checked_add(prepared.canonical_plan().len()))
            .and_then(|bytes| bytes.checked_add(prepared.signing_request().canonical_statement().len()))
            .ok_or(JournalError::JournalTooLarge)
    }

    pub(crate) fn receiving_demand_v1(held: &crate::journal::ProtectedJournalPreopenReplayExtentV1,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1)
        -> Result<ResourceVector, JournalError>
    {
        let extent = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
            held.limits, authorization.completed_receipt_v1().map_err(|_| JournalError::ProtectedBoundary)?.after_end)?;
        let frame = Self::frame_bytes_v1(reserved)?;
        let owner = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(frame.checked_mul(2)?))
            .ok_or(JournalError::JournalTooLarge)?;
        super::geometry::fixed_root_history_append_demand_v1(&extent,
            USE_ADMITTED_BODY_BYTES_V1, frame, owner)
    }

    pub(super) fn produce_once(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        source: &RootCurrentSourceExchangeStateV1, cache: &RootCurrentCacheProofStateV1,
    ) -> Result<(), Error> {
        if self.primary.is_some() || self.closed { self.closed = true; return Err(Error::Original); }
        self.append_posts.arm_once(flight)?;
        self.primary = Some(self.produce_inner(flight, writers, original, root,
            authorization, reserved, source, cache));
        let origin = root.original_clock_origin_v1().ok();
        let body = root.completed_body().ok();
        self.append_posts.observe_once(flight, writers, body.as_ref(),
            origin.map(|pair| pair.0), origin.map(|pair| pair.1));
        self.append_live = Some(self.append_posts.require_complete()
            .and_then(|()| require_live(root, reserved, source, self.append_posts.sample()?)));
        positive(&self.primary).map_err(|_| Error::History)?;
        positive(&self.append_live).map_err(|_| Error::History)?;
        self.framing = Some(self.frame_once(root, ready, reserved));
        positive(&self.framing).map_err(|_| Error::History)?;
        self.send_posts.arm_once(flight)?;
        self.sent = Some(self.send.run_once(&mut &*original, &mut self.frame,
            source.original_cutoff_v1()?, DeadlineStreamDirectionV1::Write));
        self.send_posts.observe_once(flight, writers, body.as_ref(),
            origin.map(|pair| pair.0), origin.map(|pair| pair.1));
        match writers.authority_and_policy() {
            Ok((authority, policy)) => {
                self.send_readback = Some(self.pair.readback_pair(authority, policy));
                self.send_metadata = Some(authority.held_native_receiving_metadata_v1().0);
            }
            Err(cause) => self.send_readback = Some(Err(cause)),
        }
        self.send_live = Some((|| {
            self.send_posts.require_complete()?;
            require_live(root, reserved, source, self.send_posts.sample()?)?;
            positive(&self.send_readback)?;
            self.pair.require_end(&self.send_metadata)
        })());
        self.complete = self.send.completed_exact() && self.failure().is_none()
            && matches!(self.send_live, Some(Ok(())));
        self.require_complete_v1()
    }

    fn produce_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, authorization: &RootCurrentUseAuthorizedStateV1,
        reserved: &RootCurrentUseReservedStateV1, source: &RootCurrentSourceExchangeStateV1,
        cache: &RootCurrentCacheProofStateV1,
    ) -> Result<(), Error> {
        reserved.require_complete_v1()?;
        source.require_use_complete_for_v1(root, authorization, reserved)?;
        cache.require_use_complete_for_v1(root, authorization, reserved)?;
        self.body = Some((|| {
            let lane = root.completed_body()?.open.lane;
            let receipt = reserved.received_receipt_v1(lane)?;
            let held = receipt.body(lane).map_err(|_| Error::History)?;
            let plan = reserved.completed_readonly_v1()?.prospective_use_plan_v1()?.preparation_data_v1();
            Ok(UseAdmittedBodyDataV1 {
                use_reserved: record_checksum(receipt.record, lane, OwnerV1::Controller, 5, 4)?,
                current_proofs: use_current_proofs_commitment_v1(cache.use_current_proofs_payload_v1()?),
                source_current: source_current_reply_commitment_v1(source.verified_packet_v1()?),
                cache_current: Sha256::digest(cache.verified_packet_v1()?).into(),
                use_claim: aos_sandbox_protocol::domain_ledger::resource_bank::Claim::decode(held.claim)
                    .map_err(|_| Error::History)?.native_fields().id,
                unsigned_plan: Sha256::digest(plan.canonical_plan()).into(),
                signing_statement: Sha256::digest(plan.signing_request().canonical_statement()).into(),
            })
        })());
        let body = *positive(&self.body).map_err(|_| Error::History)?;
        self.encoded = Some(body.encode());
        let root_body = root.completed_body()?;
        let previous = record_checksum(authorization.completed_receipt_v1()?.record,
            root_body.open.lane, OwnerV1::Root, 2, 2)?;
        self.pair.prepare_once(KeyV1::new(root_body.open.lane, OwnerV1::Root, 3).map_err(|_| Error::History)?,
            PhaseV1::new(OwnerV1::Root, 3).map_err(|_| Error::History)?, previous,
            root_body.open.seed, positive(&self.encoded).map_err(|_| Error::History)?)
            .map_err(|_| Error::History)?;
        let purpose = RootCurrentHistoryPurposeV1::UseAdmitted { root, authorization, reserved, source, cache };
        self.pair.prepare_cut_once(root, purpose).map_err(|_| Error::History)?;
        let (authority, policy) = writers.authority_and_policy().map_err(|_| Error::Writers)?;
        self.pair.append_once(flight, original, authority, policy, root, purpose).map_err(|_| Error::History)
    }

    fn frame_once(&mut self, root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        reserved: &RootCurrentUseReservedStateV1) -> Result<(), HistoryErrorV1>
    {
        let body = root.completed_body().map_err(|_| HistoryErrorV1::Correlation)?;
        let readback = positive(&self.pair.readback).map_err(|_| HistoryErrorV1::Correlation)?;
        let committed = positive(&self.pair.append).map_err(|_| HistoryErrorV1::Correlation)?;
        let receipt = ContinuationNativeReceiptDataV1 {
            record: &self.pair.record, latest_head: readback.head,
            names: self.append_posts.authority_names_v1().map_err(|_| HistoryErrorV1::Correlation)?,
            after_next: readback.next, after_end: committed.durable_bytes,
        };
        receipt.encode_into(body.open.lane, ContinuationKindV1::UseAdmitted, &mut self.receipt)?;
        let prepared = reserved.completed_readonly_v1().and_then(|read| read.prospective_use_plan_v1())
            .map_err(|_| HistoryErrorV1::Correlation)?.preparation_data_v1();
        let transfer = UseAdmissionTransferDataV1 { receipt: &self.receipt,
            plan: prepared.canonical_plan(), statement: prepared.signing_request().canonical_statement() };
        self.frame_length = Some(transfer.encoded_bytes(body.open.lane)
            .and_then(|bytes| bytes.checked_add(FRAME_HEADER_BYTES).ok_or(HistoryErrorV1::Extent)));
        let length = *positive(&self.frame_length).map_err(|_| HistoryErrorV1::Extent)?;
        self.allocation = Some(self.frame.try_reserve_exact(length));
        positive(&self.allocation).map_err(|_| HistoryErrorV1::Extent)?;
        self.frame.resize(length, 0);
        transfer.encode_into(body.open.lane, &mut self.frame[FRAME_HEADER_BYTES..])?;
        let sequence = u64::from(ready.original_transfer_index_v1().map_err(|_| HistoryErrorV1::Correlation)?.count())
            .checked_add(9).ok_or(HistoryErrorV1::Extent)?;
        let header = FrameCoordinatesV1 { kind: FrameKindV1::UseAdmitted, lane: body.open.lane,
            sequence, root_nonce: body.root_nonce, controller_nonce: body.open.controller_nonce }
            .encode_header(&self.frame[FRAME_HEADER_BYTES..])?;
        self.frame[..FRAME_HEADER_BYTES].copy_from_slice(&header);
        Ok(())
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if self.complete && !self.closed && self.failure().is_none() { Ok(()) } else { Err(Error::History) }
    }

    fn receipt_data_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'_>, HistoryErrorV1> {
        let readback = positive(&self.pair.readback).map_err(|_| HistoryErrorV1::Correlation)?;
        let committed = positive(&self.pair.append).map_err(|_| HistoryErrorV1::Correlation)?;
        Ok(ContinuationNativeReceiptDataV1 { record: &self.pair.record, latest_head: readback.head,
            names: self.append_posts.authority_names_v1().map_err(|_| HistoryErrorV1::Correlation)?,
            after_next: readback.next, after_end: committed.durable_bytes })
    }

    pub(crate) fn completed_receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'_>, Error> {
        self.require_complete_v1()?;
        self.receipt_data_v1().map_err(|_| Error::History)
    }

    pub(crate) fn readback_current_v1(&self, authority: &Journal, policy: &Journal) -> Result<Readback, JournalError> {
        self.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        self.pair.readback_current_v1(authority, policy)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.body).or_else(|| cause(&self.encoded)).or_else(|| self.pair.failure())
            .or_else(|| cause(&self.primary)).or_else(|| self.append_posts.failure())
            .or_else(|| cause(&self.append_live)).or_else(|| cause(&self.frame_length))
            .or_else(|| cause(&self.allocation)).or_else(|| cause(&self.framing))
            .or_else(|| self.send.failure()).or_else(|| cause(&self.sent))
            .or_else(|| self.send_posts.failure()).or_else(|| cause(&self.send_readback))
            .or_else(|| cause(&self.send_metadata)).or_else(|| cause(&self.send_live))
    }
}

fn require_live(root: &RootCurrentOpenStateV1, reserved: &RootCurrentUseReservedStateV1,
    source: &RootCurrentSourceExchangeStateV1, sample: aos_sandbox_core::RawPairedClockSample)
    -> Result<(), JournalError>
{
    root.require_clock(sample)?;
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
    slot.as_ref().and_then(|value| value.as_ref().err()).map(|error| error as _)
}

fn record_checksum(record: &[u8], lane: [u8; 16], owner: OwnerV1,
    revision: u64, phase: u8) -> Result<[u8; 32], Error>
{
    let key = KeyV1::new(lane, owner, revision).map_err(|_| Error::History)?;
    let phase = PhaseV1::new(owner, phase).map_err(|_| Error::History)?;
    Ok(RecordEnvelopeV1::decode(record, key, phase).map_err(|_| Error::History)?.checksum())
}
