//! Receives Frame6 from the same accepted Controller without issuing a proof.
//!
//! A distinct same-R fixed stage prepays this resident owner before construction.
//! The exact received bank/head/row bytes remain comparison DATA. A fresh funded
//! same-file replay must independently observe all six transactions before the
//! enclosing Root continuation can use the reserved cut.

use aos_sandbox_protocol::domain_ledger::create_storage_history::readback::HistoryPairReadbackDataV1;
use std::error::Error as StdError;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HEAD_BYTES, KEY_BYTES, HistoryErrorV1, KeyV1, LatestHeadV1, OwnerV1, PhaseV1,
    RecordCoordinatesV1, RecordEnvelopeV1,
    transport::{FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameEnvelopeV1, FrameKindV1},
    use_reserved::{RootValidatedBodyDataV1,
        UseReservedNativeReceiptDataV1, ROOT_VALIDATED_RECORD_BYTES_V1,
        USE_RESERVED_RECEIPT_BYTES_V1},
};
use crate::journal::{JournalError, JournalTransaction};
use crate::journal::create_storage_history::{prepare_readonly_history_pair_v1};
use crate::normal_root::RootPolicyAcceptedFlightV1;
use aos_sandbox_broker::bounded_stream_io::FixedDeadlineStreamIoV1;
use aos_sandbox_broker::bounded_stream_io::DeadlineStreamDirectionV1;
use crate::policy_compiler::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::super::{RootCreateStorageCurrentErrorV1 as Error,
    cache_current::RootCurrentCacheProofStateV1,
    controller_readonly::RootCurrentControllerReadonlyStateV1,
    ready::RootCurrentReadyStateV1,
    root_open::{RootCurrentOpenStateV1, RootCurrentHistoryPostsV1},
    source_current::RootCurrentSourceExchangeStateV1,
    use_authorized::RootCurrentUseAuthorizedStateV1};

pub(super) const FRAME_BYTES: usize = FRAME_HEADER_BYTES + USE_RESERVED_RECEIPT_BYTES_V1;
type RootReadback = HistoryPairReadbackDataV1<{ aos_sandbox_protocol::domain_ledger::create_storage_history::use_authorized::USE_AUTHORIZED_RECORD_BYTES_V1 }>;

pub(crate) struct RootCurrentUseReservedReceivedV1 {
    endpoint: Option<Result<(), aos_linux_descriptors::Error>>,
    before: RootCurrentHistoryPostsV1,
    before_readback: Option<Result<RootReadback, JournalError>>,
    before_live: Option<Result<(), JournalError>>,
    raw: [u8; FRAME_BYTES],
    io: FixedDeadlineStreamIoV1<FRAME_BYTES>,
    received: Option<Result<(), HistoryErrorV1>>,
    decoded: Option<Result<(), HistoryErrorV1>>,
    validated: Option<Result<JournalTransaction, JournalError>>,
    bank: Option<Result<JournalTransaction, aos_sandbox_protocol::domain_ledger::resource_bank::ResourceBankDataError>>,
    reserved: Option<Result<JournalTransaction, JournalError>>,
    positions: Option<Result<[(u64, u64); 4], JournalError>>,
    primary: Option<Result<(), Error>>,
    after: RootCurrentHistoryPostsV1,
    after_readback: Option<Result<RootReadback, JournalError>>,
    after_live: Option<Result<(), JournalError>>,
    complete: bool,
    closed: bool,
}

impl RootCurrentUseReservedReceivedV1 {
    pub(super) fn new() -> Self {
        Self { endpoint: None, before: Default::default(), before_readback: None,
            before_live: None, raw: [0; FRAME_BYTES], io: Default::default(),
            received: None, decoded: None, validated: None, bank: None, reserved: None,
            positions: None, primary: None, after: Default::default(), after_readback: None,
            after_live: None, complete: false, closed: false }
    }

    pub(crate) fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::{
            USE_RESERVED_RECORD_BYTES_V1, USE_RESERVED_BODY_BYTES_V1};
        use aos_sandbox_protocol::domain_ledger::resource_bank::{ACCOUNT_HEAD_BYTES_V1,
            CLAIM_BYTES_V1, CREATE_STORAGE_USE_BINDING_BYTES_V1};
        let invalid = || JournalError::JournalTooLarge;
        // Both state planes, three actual expected transactions, canonical
        // construction arrays and the fixed deadline reader are prepaid bytes.
        let records = ROOT_VALIDATED_RECORD_BYTES_V1.checked_add(USE_RESERVED_RECORD_BYTES_V1)
            .and_then(|bytes| bytes.checked_add(2 * HEAD_BYTES + 4 * KEY_BYTES))
            .and_then(|bytes| bytes.checked_add(ACCOUNT_HEAD_BYTES_V1 + CLAIM_BYTES_V1
                + CREATE_STORAGE_USE_BINDING_BYTES_V1 + 3 * 17))
            .and_then(|bytes| bytes.checked_add(7 * std::mem::size_of::<crate::journal::JournalRecord>()))
            .ok_or_else(invalid)?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(records.checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(2 * (ROOT_VALIDATED_RECORD_BYTES_V1 + USE_RESERVED_BODY_BYTES_V1)))
            .ok_or_else(invalid)?;
        let owed = RootCurrentHistoryPostsV1::additional_receiving_demand_v1()?;
        ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| invalid())?)
            .with(D::NetworkBytes, FRAME_BYTES as u64).checked_add(owed)
            .and_then(|value| value.checked_add(owed)).map_err(|_| invalid())
    }

    pub(super) fn receive_once(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, authorization: &RootCurrentUseAuthorizedStateV1,
        ready: &RootCurrentReadyStateV1, source: &RootCurrentSourceExchangeStateV1,
        cache: &RootCurrentCacheProofStateV1, first: &RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), Error> {
        if self.primary.is_some() || self.closed { self.closed = true; return Err(Error::Original); }
        self.before.arm_once(flight)?;
        self.after.arm_once(flight)?;
        self.primary = Some(self.receive_inner(flight, writers, original, root,
            authorization, ready, source, cache, first));
        let body = root.completed_body().ok();
        let origin = root.original_clock_native_v1().ok();
        self.after.observe_once(flight, writers, body.as_ref(),
            origin);
        self.after_readback = Some(match writers.authority_and_policy() {
            Ok((authority, policy)) => authorization.readback_current_v1(authority, policy),
            Err(error) => Err(error),
        });
        self.after_live = Some(self.after.require_complete().and_then(|()| {
            self.after_readback.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?;
            require_live(root, source, first, self.after.sample()?)
        }));
        self.complete = self.failure().is_none() && matches!(self.primary, Some(Ok(())))
            && matches!(self.after_live, Some(Ok(())));
        self.require_received_v1()
    }

    fn receive_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, authorization: &RootCurrentUseAuthorizedStateV1,
        ready: &RootCurrentReadyStateV1, source: &RootCurrentSourceExchangeStateV1,
        cache: &RootCurrentCacheProofStateV1, first: &RootCurrentControllerReadonlyStateV1,
    ) -> Result<(), Error> {
        authorization.require_complete_v1()?;
        first.require_complete_v1()?;
        let body = root.completed_body()?;
        let origin = root.original_clock_native_v1()?;
        self.endpoint = Some(flight.current_cut_native().map_err(|_| Error::Original)?
            .require_same_endpoint_v1(original.as_fd()));
        positive(&self.endpoint).map_err(|_| Error::Original)?;
        self.before.observe_once(flight, writers, Some(&body), Some(origin));
        self.before_readback = Some(match writers.authority_and_policy() {
            Ok((authority, policy)) => authorization.readback_current_v1(authority, policy),
            Err(error) => Err(error),
        });
        self.before_live = Some(self.before.require_complete().and_then(|()| {
            positive(&self.before_readback)?;
            require_live(root, source, first, self.before.sample()?)
        }));
        positive(&self.before_live).map_err(|_| Error::History)?;
        self.received = Some(self.io.run_once(&mut &*original, &mut self.raw,
            source.original_cutoff_v1()?, DeadlineStreamDirectionV1::Read));
        positive(&self.received).map_err(|_| Error::History)?;
        self.decoded = Some((|| {
            let sequence = u64::from(ready.original_transfer_index_v1()
                .map_err(|_| HistoryErrorV1::Correlation)?.count())
                .checked_add(6).ok_or(HistoryErrorV1::Extent)?;
            let frame = FrameEnvelopeV1::decode(&self.raw, FrameCoordinatesV1 {
                kind: FrameKindV1::UseReserved, lane: body.open.lane, sequence,
                root_nonce: body.root_nonce, controller_nonce: body.open.controller_nonce,
            })?;
            let receipt = UseReservedNativeReceiptDataV1::decode(frame.payload(), body.open.lane)?;
            receipt.body(body.open.lane)?.require_authorization_v1(body.open.lane,
                authorization.completed_receipt_v1().map_err(|_| HistoryErrorV1::Correlation)?)
        })());
        positive(&self.decoded).map_err(|_| Error::History)?;
        self.prepare_expected(root, authorization, ready, cache)
    }

    fn prepare_expected(&mut self, root: &RootCurrentOpenStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1, ready: &RootCurrentReadyStateV1,
        cache: &RootCurrentCacheProofStateV1) -> Result<(), Error>
    {
        let lane = root.completed_body()?.open.lane;
        let receipt = UseReservedNativeReceiptDataV1::decode(&self.raw[FRAME_HEADER_BYTES..], lane)
            .map_err(|_| Error::History)?;
        let body = receipt.body(lane).map_err(|_| Error::History)?;
        let inputs = cache.controller_receipt_v1(root, ready)?;
        let prior = RecordEnvelopeV1::decode(inputs.record,
            KeyV1::new(lane, OwnerV1::Controller, 3).map_err(|_| Error::History)?,
            PhaseV1::new(OwnerV1::Controller, 2).map_err(|_| Error::History)?)
            .map_err(|_| Error::History)?;
        let encoded = RootValidatedBodyDataV1 { authorization: authorization.completed_receipt_v1()? }
            .encode(lane).map_err(|_| Error::History)?;
        let key = KeyV1::new(lane, OwnerV1::Controller, 4).map_err(|_| Error::History)?;
        let phase = PhaseV1::new(OwnerV1::Controller, 3).map_err(|_| Error::History)?;
        let mut record = [0; ROOT_VALIDATED_RECORD_BYTES_V1];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key, phase, predecessor: prior.checksum(), correlation: prior.coordinates().correlation,
        }, &encoded, &mut record).map_err(|_| Error::History)?;
        let head = LatestHeadV1::new(4, checksum).map_err(|_| Error::History)?.encode();
        self.validated = Some(prepare_readonly_history_pair_v1(key, phase, &record, &head));
        self.bank = Some(body.expected_reserve_transaction_v1());
        self.reserved = Some(prepare_readonly_history_pair_v1(
            KeyV1::new(lane, OwnerV1::Controller, 5).map_err(|_| Error::History)?,
            PhaseV1::new(OwnerV1::Controller, 4).map_err(|_| Error::History)?,
            receipt.record, &receipt.latest_head));
        self.positions = Some((|| {
            if checksum != body.root_validated || inputs.names != receipt.names {
                return Err(JournalError::ProtectedBoundary);
            }
            let first = (inputs.after_next, inputs.after_end);
            let append = crate::journal::encoded_transaction_append_bytes(positive(&self.validated)?)?;
            let second = (first.0.checked_add(4).ok_or(JournalError::SequenceExhausted)?,
                first.1.checked_add(append).ok_or(JournalError::JournalTooLarge)?);
            let append = crate::journal::encoded_transaction_append_bytes(positive(&self.bank)?)?;
            let third = (second.0.checked_add(5).ok_or(JournalError::SequenceExhausted)?,
                second.1.checked_add(append).ok_or(JournalError::JournalTooLarge)?);
            let append = crate::journal::encoded_transaction_append_bytes(positive(&self.reserved)?)?;
            let fourth = (third.0.checked_add(4).ok_or(JournalError::SequenceExhausted)?,
                third.1.checked_add(append).ok_or(JournalError::JournalTooLarge)?);
            if third != (body.after_next, body.after_end)
                || fourth != (receipt.after_next, receipt.after_end)
            { return Err(JournalError::ProtectedBoundary); }
            Ok([first, second, third, fourth])
        })());
        positive(&self.positions).map(|_| ()).map_err(|_| Error::History)
    }

    pub(crate) fn require_received_v1(&self) -> Result<(), Error> {
        if self.complete && !self.closed && self.failure().is_none() { Ok(()) }
        else { Err(Error::History) }
    }

    pub(crate) fn receipt_v1(&self, lane: [u8; 16])
        -> Result<UseReservedNativeReceiptDataV1<'_>, Error>
    {
        self.require_received_v1()?;
        UseReservedNativeReceiptDataV1::decode(&self.raw[FRAME_HEADER_BYTES..], lane).map_err(|_| Error::History)
    }

    pub(crate) fn expected_v1(&self)
        -> Result<[&JournalTransaction; 3], Error>
    {
        self.require_received_v1()?;
        Ok([positive(&self.validated).map_err(|_| Error::History)?,
            positive(&self.bank).map_err(|_| Error::History)?,
            positive(&self.reserved).map_err(|_| Error::History)?])
    }

    pub(crate) fn positions_v1(&self)
        -> Result<[(u64, u64); 4], Error>
    {
        self.require_received_v1()?;
        positive(&self.positions).copied().map_err(|_| Error::History)
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.endpoint).or_else(|| self.before.failure()).or_else(|| cause(&self.before_readback))
            .or_else(|| cause(&self.before_live)).or_else(|| self.io.failure())
            .or_else(|| cause(&self.received)).or_else(|| cause(&self.decoded))
            .or_else(|| cause(&self.validated)).or_else(|| cause(&self.bank))
            .or_else(|| cause(&self.reserved)).or_else(|| cause(&self.positions))
            .or_else(|| cause(&self.primary)).or_else(|| self.after.failure())
            .or_else(|| cause(&self.after_readback)).or_else(|| cause(&self.after_live))
    }
}

fn require_live(root: &RootCurrentOpenStateV1, source: &RootCurrentSourceExchangeStateV1,
    first: &RootCurrentControllerReadonlyStateV1, sample: aos_sandbox_model::RawPairedClockSample)
    -> Result<(), JournalError>
{
    root.require_clock(sample)?;
    first.require_live_at_v1(sample)?;
    if sample.boottime_nanoseconds() >= source.original_cutoff_v1()
        .map_err(|_| JournalError::ProtectedBoundary)? { return Err(JournalError::ProtectedBoundary); }
    Ok(())
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: StdError + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
