//! Binds Root4 only after actual signing bytes and the exact Prepare were verified.
//!
//! The same accepted socket carries the index/chunks. Root retains its original
//! unsigned compiler preparation, actual verified packet and independent posts;
//! the sole shared native history-pair owner performs the Root4 append/readback.

use std::error::Error as StdError;
use std::fs::Metadata;
use std::io;
use std::os::unix::net::UnixStream;
use aos_sandbox_core::ResourceVector;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{HistoryErrorV1,
    KeyV1, OwnerV1, PhaseV1,
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1,
        SignedBoundBodyDataV1, SignedPreparationBundleDataV1,
        SIGNED_BOUND_BODY_BYTES_V1, SIGNED_BOUND_RECORD_BYTES_V1, SIGNED_BOUND_RECEIPT_BYTES_V1},
    transport::{FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameKindV1, TransferIndexV1}};
use sha2::{Digest as _, Sha256};
use crate::journal::{Journal, JournalError, ProtectedJournalPreopenReplayExtentV1};
use crate::normal_root::RootPolicyAcceptedFlightV1;
use crate::policy_compiler::bounded_stream_io::{FixedDeadlineStreamIoV1, DeadlineStreamDirectionV1};
use crate::policy_compiler::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::{RootCreateStorageCurrentErrorV1 as Error,
    bundle_ownership::RootCurrentBundleOwnershipStateV1,
    ready::{RootCurrentReadyStateV1, subject::RootCurrentChunkReceivingV1},
    root_open::{RootCurrentOpenStateV1, RootCurrentHistoryPostsV1, RootCurrentHistoryPurposeV1},
    source_current::RootCurrentSourceExchangeStateV1,
    use_reserved::RootCurrentUseReservedStateV1,
    use_admitted::RootCurrentUseAdmittedStateV1,
    history_pair::RootCurrentHistoryPairV1};

pub(crate) mod input;
mod verification;
use input::RootSignedInputV1;
const FRAME_BYTES: usize = FRAME_HEADER_BYTES + SIGNED_BOUND_RECEIPT_BYTES_V1;
#[derive(Clone, Copy)]
pub(crate) enum SignedControllerFinancialStageV1 {
    Fixed,
    Native,
    Semantic,
}

type Readback = crate::journal::create_storage_history::HistoryPairReadbackV1<SIGNED_BOUND_RECORD_BYTES_V1>;

pub(crate) struct RootCurrentSignedBoundStateV1 {
    input: RootSignedInputV1,
    controller_entry: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    controller: Option<Box<super::controller_readonly::RootCurrentControllerReadonlyStateV1>>,
    body: Option<Result<SignedBoundBodyDataV1, HistoryErrorV1>>,
    encoded: Option<Result<[u8; SIGNED_BOUND_BODY_BYTES_V1], HistoryErrorV1>>,
    pair: RootCurrentHistoryPairV1<SIGNED_BOUND_RECORD_BYTES_V1>,
    primary: Option<Result<(), Error>>,
    append_posts: RootCurrentHistoryPostsV1,
    append_live: Option<Result<(), JournalError>>,
    frame: [u8; FRAME_BYTES],
    framing: Option<Result<(), HistoryErrorV1>>,
    send: FixedDeadlineStreamIoV1<FRAME_BYTES>,
    sent: Option<Result<(), HistoryErrorV1>>,
    send_posts: RootCurrentHistoryPostsV1,
    send_readback: Option<Result<Readback, JournalError>>,
    send_metadata: Option<io::Result<Metadata>>,
    send_live: Option<Result<(), JournalError>>,
    complete: bool,
    closed: bool,
}

impl RootCurrentSignedBoundStateV1 {
    pub(super) fn new() -> Self {
        Self { input: RootSignedInputV1::new(), controller_entry: None, controller: None, body: None, encoded: None,
            pair: RootCurrentHistoryPairV1::new(), primary: None,
            append_posts: Default::default(), append_live: None,
            frame: [0; FRAME_BYTES], framing: None, send: Default::default(), sent: None,
            send_posts: Default::default(), send_readback: None, send_metadata: None,
            send_live: None, complete: false, closed: false }
    }

    pub(crate) fn fixed_receiving_demand_v1(held: &ProtectedJournalPreopenReplayExtentV1,
        admitted: &RootCurrentUseAdmittedStateV1) -> Result<ResourceVector, JournalError>
    {
        let prefix = admitted.completed_receipt_v1().map_err(|_| JournalError::ProtectedBoundary)?.after_end;
        let extent = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(held.limits, prefix)?;
        let chunk = aos_sandbox_protocol::domain_ledger::create_q04_history::CLAIM_CHUNK_BYTES;
        let owner = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(chunk))
            .and_then(|bytes| bytes.checked_add(FRAME_HEADER_BYTES * 2 + 48))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<super::RootCurrentFailureViewV1<'static>>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(usize::try_from(super::ready::indexed::construction_bytes_v1()?).ok()?))
            .ok_or(JournalError::JournalTooLarge)?;
        let base = super::geometry::fixed_root_history_append_demand_v1(&extent,
            SIGNED_BOUND_BODY_BYTES_V1, FRAME_BYTES + FRAME_HEADER_BYTES + 48, owner)?;
        let native = RootCurrentChunkReceivingV1::additional_receiving_demand_v1()?;
        let clock = RootCurrentChunkReceivingV1::additional_clock_demand_v1()?;
        let input_owed = super::root_open::RootCurrentHistoryPostsV1::additional_owed_demand_v1()?;
        let input_owed = input_owed.checked_add(input_owed).map_err(|_| JournalError::JournalTooLarge)?;
        let input_names = super::root_open::history_native_receiving_demand_v1()?;
        let input_clock = super::root_open::history_clock_receiving_demand_v1()?;
        let input_clocks = input_clock.checked_add(input_clock).map_err(|_| JournalError::JournalTooLarge)?;
        base.checked_add(native)
            .and_then(|value| value.checked_add(clock))
            .and_then(|value| value.checked_add(input_names))
            .and_then(|value| value.checked_add(input_clocks))
            .and_then(|value| value.checked_add(input_owed))
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(super) fn produce_once(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, reserved: &RootCurrentUseReservedStateV1,
        source: &RootCurrentSourceExchangeStateV1, ownership: &RootCurrentBundleOwnershipStateV1,
        cache: &super::cache_current::RootCurrentCacheProofStateV1,
        policy_data: &super::policy_inputs::RootCurrentPolicyInputDataV1<'_>,
        authorization: &super::use_authorized::RootCurrentUseAuthorizedStateV1,
    ) -> Result<(), Error> {
        if self.primary.is_some() || self.closed { self.closed = true; return Err(Error::Original); }
        self.append_posts.arm_once(flight)?;
        self.primary = Some(self.produce_inner(flight, writers, original, root, ready,
            admitted, reserved, source, ownership, cache, policy_data, authorization));
        let body = root.completed_body().ok();
        let origin = root.original_clock_origin_v1().ok();
        self.append_posts.observe_once(flight, writers, body.as_ref(), origin.map(|pair| pair.0), origin.map(|pair| pair.1));
        self.append_live = Some(self.append_posts.require_complete()
            .and_then(|()| require_live(root, reserved, source, self.append_posts.sample()?)));
        positive(&self.primary).map_err(|_| Error::History)?;
        positive(&self.append_live).map_err(|_| Error::History)?;
        self.framing = Some(self.frame_once(root, ready));
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
            require_live(root, reserved, source, self.send_posts.sample()?)?;
            positive(&self.send_readback)?;
            self.pair.require_end(&self.send_metadata)
        })());
        self.complete = self.send.completed_exact() && self.failure_with_original(flight).is_none()
            && matches!(self.send_live, Some(Ok(())));
        self.require_complete_v1()
    }

    fn produce_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        admitted: &RootCurrentUseAdmittedStateV1, reserved: &RootCurrentUseReservedStateV1,
        source: &RootCurrentSourceExchangeStateV1, ownership: &RootCurrentBundleOwnershipStateV1,
        cache: &super::cache_current::RootCurrentCacheProofStateV1,
        policy_data: &super::policy_inputs::RootCurrentPolicyInputDataV1<'_>,
        authorization: &super::use_authorized::RootCurrentUseAuthorizedStateV1,
    ) -> Result<(), Error> {
        self.input.receive_once(flight, writers, original, root, ready, admitted, reserved, source, ownership)?;
        self.controller_entry = Some(flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_signed_controller_fixed_once(root, admitted, &self.input));
        positive(&self.controller_entry).map_err(|_| Error::History)?;
        self.controller = Some(Box::new(super::controller_readonly::RootCurrentControllerReadonlyStateV1::new()));
        self.controller.as_mut().ok_or(Error::History)?.capture_signed_once(flight, writers,
            root, ready, cache, source, ownership, policy_data, authorization, reserved, admitted, &self.input)?;
        let bundle = self.input.completed_bundle_v1()?;
        self.body = Some((|| {
            Ok(SignedBoundBodyDataV1 { bundle: bundle.commitment()?,
                bundle_bytes: u64::try_from(bundle.encoded_bytes()?).map_err(|_| HistoryErrorV1::Extent)?,
                request_id: self.input.completed_request_id_v1().map_err(|_| HistoryErrorV1::Correlation)?,
                request_body: Sha256::digest(bundle.request_body).into(), plan: Sha256::digest(bundle.plan).into(),
                signature: Sha256::digest(bundle.signature).into() })
        })());
        self.encoded = Some(positive(&self.body).map_err(|_| Error::History)?.encode());
        let body = root.completed_body()?;
        let previous = admitted.completed_receipt_v1()?.record_data(body.open.lane,
            ContinuationKindV1::UseAdmitted).map_err(|_| Error::History)?.checksum();
        self.pair.prepare_once(KeyV1::new(body.open.lane, OwnerV1::Root, 4).map_err(|_| Error::History)?,
            PhaseV1::new(OwnerV1::Root, 4).map_err(|_| Error::History)?, previous, body.open.seed,
            positive(&self.encoded).map_err(|_| Error::History)?).map_err(|_| Error::History)?;
        let purpose = RootCurrentHistoryPurposeV1::SignedBound { admitted, reserved, source, signed: &self.input };
        self.pair.prepare_cut_once(root, purpose).map_err(|_| Error::History)?;
        let (authority, policy) = writers.authority_and_policy().map_err(|_| Error::Writers)?;
        self.pair.append_once(flight, original, authority, policy, root, purpose).map_err(|_| Error::History)
    }

    fn frame_once(&mut self, root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1)
        -> Result<(), HistoryErrorV1>
    {
        let body = root.completed_body().map_err(|_| HistoryErrorV1::Correlation)?;
        let readback = positive(&self.pair.readback).map_err(|_| HistoryErrorV1::Correlation)?;
        let committed = positive(&self.pair.append).map_err(|_| HistoryErrorV1::Correlation)?;
        let receipt = ContinuationNativeReceiptDataV1 { record: &self.pair.record,
            latest_head: readback.head, names: self.append_posts.authority_names_v1()
                .map_err(|_| HistoryErrorV1::Correlation)?, after_next: readback.next, after_end: committed.durable_bytes };
        receipt.encode_into(body.open.lane, ContinuationKindV1::SignedBound, &mut self.frame[FRAME_HEADER_BYTES..])?;
        let sequence = 11_u64.checked_add(u64::from(ready.original_transfer_index_v1()
            .map_err(|_| HistoryErrorV1::Correlation)?.count()))
            .and_then(|value| value.checked_add(u64::from(self.input.index_v1().ok()?.count())))
            .ok_or(HistoryErrorV1::Extent)?;
        let header = FrameCoordinatesV1 { kind: FrameKindV1::SignedBound, lane: body.open.lane,
            sequence, root_nonce: body.root_nonce, controller_nonce: body.open.controller_nonce }
            .encode_header(&self.frame[FRAME_HEADER_BYTES..])?;
        self.frame[..FRAME_HEADER_BYTES].copy_from_slice(&header);
        Ok(())
    }

    pub(super) fn failed_controller_financial_entry_v1(&self) -> Option<SignedControllerFinancialStageV1> {
        if matches!(self.controller_entry, Some(Err(_))) { Some(SignedControllerFinancialStageV1::Fixed) }
        else { self.controller.as_deref().and_then(|state| state.failed_signed_financial_entry_v1()) }
    }

    pub(super) fn failed_variable_entry_v1(&self) -> bool { self.input.failed_variable_entry_v1() }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if self.complete && !self.closed { self.input.require_complete_v1() }
        else { Err(Error::History) }
    }

    pub(crate) fn completed_bundle_v1(&self) -> Result<SignedPreparationBundleDataV1<'_>, Error> {
        self.require_complete_v1()?;
        self.input.completed_bundle_v1()
    }

    pub(crate) fn completed_request_id_v1(&self) -> Result<[u8; 16], Error> {
        self.require_complete_v1()?;
        self.input.completed_request_id_v1()
    }

    pub(crate) fn verified_plan_v1(&self) -> Result<&aos_sandbox_core::VerifiedBrokerPlan, Error> {
        self.require_complete_v1()?;
        self.input.verified_plan_v1()
    }

    pub(crate) fn completed_index_v1(&self) -> Result<TransferIndexV1, Error> {
        self.require_complete_v1()?;
        self.input.index_v1()
    }

    pub(crate) fn completed_receipt_v1(&self) -> Result<ContinuationNativeReceiptDataV1<'_>, Error> {
        self.require_complete_v1()?;
        let readback = positive(&self.pair.readback).map_err(|_| Error::History)?;
        let committed = positive(&self.pair.append).map_err(|_| Error::History)?;
        Ok(ContinuationNativeReceiptDataV1 { record: &self.pair.record, latest_head: readback.head,
            names: self.append_posts.authority_names_v1().map_err(|_| Error::History)?,
            after_next: readback.next, after_end: committed.durable_bytes })
    }

    pub(crate) fn readback_current_v1(&self, authority: &Journal, policy: &Journal) -> Result<Readback, JournalError> {
        self.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        self.pair.readback_current_v1(authority, policy)
    }

    pub(crate) fn failure_with_original<'a>(&'a self, flight: &'a RootPolicyAcceptedFlightV1<'_, '_>)
        -> Option<&'a (dyn StdError + 'static)>
    {
        self.input.failure_with_original(flight)
            .or_else(|| cause(&self.controller_entry))
            .or_else(|| self.controller.as_ref().and_then(|state| state.failure_with_original(flight)))
            .or_else(|| cause(&self.body))
            .or_else(|| cause(&self.encoded)).or_else(|| self.pair.failure()).or_else(|| cause(&self.primary))
            .or_else(|| self.append_posts.failure()).or_else(|| cause(&self.append_live))
            .or_else(|| cause(&self.framing)).or_else(|| self.send.failure()).or_else(|| cause(&self.sent))
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
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: StdError + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
