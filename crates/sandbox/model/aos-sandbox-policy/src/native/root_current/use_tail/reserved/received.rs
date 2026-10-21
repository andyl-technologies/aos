//! Retains the exact Frame6 and both genuine prearmed history bookends.
//!
//! Bytes and expected bank/history rows are comparison DATA. Only the enclosing
//! reserved owner can complete its distinct captured native and semantic replay.

use std::error::Error;
use std::mem::size_of;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use aos_sandbox_broker::bounded_stream_io::{DeadlineStreamDirectionV1, FixedDeadlineStreamIoV1};
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::receiving::{
    RootObservationErrorV1, RootSelectedStartupBorrowV1, RootUpperMutationGuardV1,
};
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HEAD_BYTES, HistoryErrorV1, KEY_BYTES, KeyV1, LatestHeadV1, OwnerV1, PhaseV1,
    RecordCoordinatesV1, RecordEnvelopeV1,
    readback::HistoryPairReadbackDataV1,
    transport::{FRAME_HEADER_BYTES, FrameCoordinatesV1, FrameEnvelopeV1, FrameKindV1},
    use_authorized::USE_AUTHORIZED_RECORD_BYTES_V1,
    use_reserved::{
        ROOT_VALIDATED_RECORD_BYTES_V1, RootValidatedBodyDataV1, USE_RESERVED_RECEIPT_BYTES_V1,
        UseReservedNativeReceiptDataV1,
    },
};
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};

use super::super::super::initial_cache::RootInitialCacheProofOriginalV1;
use super::super::super::initial_controller::RootInitialControllerReadonlyOriginalV1;
use super::super::super::initial_open::{
    RootInitialOpenErrorV1, RootInitialOpenPreparedOriginalV1,
};
use super::super::super::initial_post::RootInitialOpenPostsOriginalV1;
use super::super::super::initial_ready::RootInitialReadyOriginalV1;
use super::super::super::initial_source_exchange::RootInitialSourceExchangeOriginalV1;
use super::super::super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1;
use super::super::super::owned::RootCurrentAcceptedOriginalsV1;
use super::super::super::writers::RootCurrentWritersOriginalV1;
use super::E;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::readonly::error::RootReadonlyErrorV1 as ReadError;
use crate::native::startup::RootCurrentWritersPredecessorV1;

const FRAME_BYTES: usize = FRAME_HEADER_BYTES + USE_RESERVED_RECEIPT_BYTES_V1;
type Readback = HistoryPairReadbackDataV1<USE_AUTHORIZED_RECORD_BYTES_V1>;

pub(in crate::native::root_current) struct RootUseReservedReceivedOriginalV1 {
    endpoint: Option<Result<(), aos_linux_descriptors::Error>>,
    before: RootInitialOpenPostsOriginalV1,
    before_arm: Option<Result<(), RootObservationErrorV1>>,
    after_arm: Option<Result<(), RootObservationErrorV1>>,
    before_readback: Option<Result<Readback, RootInitialOpenErrorV1>>,
    before_live: Option<Result<(), ReadError>>,
    raw: [u8; FRAME_BYTES],
    io: FixedDeadlineStreamIoV1<FRAME_BYTES>,
    received: Option<Result<(), HistoryErrorV1>>,
    decoded: Option<Result<(), HistoryErrorV1>>,
    validated: Option<Result<JournalTransaction, ReadError>>,
    bank: Option<
        Result<
            JournalTransaction,
            aos_sandbox_protocol::domain_ledger::resource_bank::ResourceBankDataError,
        >,
    >,
    reserved: Option<Result<JournalTransaction, ReadError>>,
    positions: Option<Result<[(u64, u64); 4], ReadError>>,
    primary: Option<Result<(), E>>,
    after: RootInitialOpenPostsOriginalV1,
    after_readback: Option<Result<Readback, RootInitialOpenErrorV1>>,
    after_live: Option<Result<(), ReadError>>,
    reentered: bool,
}

impl RootUseReservedReceivedOriginalV1 {
    pub(in crate::native::root_current) fn new() -> Self {
        Self {
            endpoint: None,
            before: RootInitialOpenPostsOriginalV1::new(),
            before_arm: None,
            after_arm: None,
            before_readback: None,
            before_live: None,
            raw: [0; FRAME_BYTES],
            io: Default::default(),
            received: None,
            decoded: None,
            validated: None,
            bank: None,
            reserved: None,
            positions: None,
            primary: None,
            after: RootInitialOpenPostsOriginalV1::new(),
            after_readback: None,
            after_live: None,
            reentered: false,
        }
    }

    pub(in crate::native::root_current) fn fixed_demand_v1() -> Result<ResourceVector, NativeError>
    {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::{
            USE_RESERVED_BODY_BYTES_V1, USE_RESERVED_RECORD_BYTES_V1,
        };
        use aos_sandbox_protocol::domain_ledger::resource_bank::{
            ACCOUNT_HEAD_BYTES_V1, CLAIM_BYTES_V1, CREATE_STORAGE_USE_BINDING_BYTES_V1,
        };
        let invalid = || NativeError::Mechanical(Mechanical::JournalTooLarge);
        let records = ROOT_VALIDATED_RECORD_BYTES_V1
            .checked_add(USE_RESERVED_RECORD_BYTES_V1)
            .and_then(|bytes| bytes.checked_add(2 * HEAD_BYTES + 4 * KEY_BYTES))
            .and_then(|bytes| {
                bytes.checked_add(
                    ACCOUNT_HEAD_BYTES_V1
                        + CLAIM_BYTES_V1
                        + CREATE_STORAGE_USE_BINDING_BYTES_V1
                        + 3 * 17,
                )
            })
            .and_then(|bytes| bytes.checked_add(7 * size_of::<JournalRecord>()))
            .ok_or_else(invalid)?;
        let memory = size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(records.checked_mul(3)?))
            .and_then(|bytes| {
                bytes.checked_add(2 * (ROOT_VALIDATED_RECORD_BYTES_V1 + USE_RESERVED_BODY_BYTES_V1))
            })
            .ok_or_else(invalid)?;
        let owed = super::super::super::initial_geometry::history_post_demand_v1()?;
        ResourceVector::ZERO
            .with(
                D::MemoryBytes,
                u64::try_from(memory).map_err(|_| invalid())?,
            )
            .with(D::NetworkBytes, FRAME_BYTES as u64)
            .checked_add(owed)
            .and_then(|value| value.checked_add(owed))
            .map_err(|_| invalid())
    }

    pub(in crate::native::root_current) fn arm_before_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.before_arm.is_some() {
            self.reentered = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.before_arm = Some(self.before.arm_once_v1(predecessor, startup, exclusion));
        self.before_arm
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|_| ())
            .ok_or(RootObservationErrorV1::Service)
    }

    pub(in crate::native::root_current) fn arm_after_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.after_arm.is_some() {
            self.reentered = true;
            return Err(RootObservationErrorV1::Service);
        }
        self.before_arm
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(RootObservationErrorV1::Service)?;
        self.after_arm = Some(self.after.arm_once_v1(predecessor, startup, exclusion));
        self.after_arm
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|_| ())
            .ok_or(RootObservationErrorV1::Service)
    }

    pub(in crate::native::root_current) fn receive_once_v1(
        &mut self,
        writers: &mut RootCurrentWritersOriginalV1,
        original: &UnixStream,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &RootInitialUseAuthorizedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
        first: &RootInitialControllerReadonlyOriginalV1,
    ) -> Result<(), E> {
        if self.primary.is_some() || self.reentered {
            self.reentered = true;
            return Err(E::Incomplete);
        }
        self.before_arm
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(E::Incomplete)?;
        self.after_arm
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(E::Incomplete)?;
        self.primary = Some(self.receive_inner_v1(
            writers,
            original,
            originals,
            open,
            authorization,
            ready,
            source,
            cache,
            first,
        ));
        // Both genuine arms preceded entry. Every body refusal still owes the
        // original full names/Root→Controller→Root/ordinary-clock bookend.
        self.after
            .observe_once_v1(writers, open, &originals.peer, &originals.stream);
        self.after_readback = Some(match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => authorization.readback_current_v1(authority, policy),
            Err(error) => Err(RootInitialOpenErrorV1::Root(error)),
        });
        self.after_live = Some(
            self.after
                .require_complete_v1()
                .map_err(|_| ReadError::ProtectedBoundary)
                .and_then(|()| {
                    self.after_readback
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .ok_or(ReadError::ProtectedBoundary)?;
                    require_live_v1(
                        open,
                        source,
                        first,
                        self.after
                            .sample_v1()
                            .map_err(|_| ReadError::ProtectedBoundary)?,
                    )
                }),
        );
        self.require_received_v1()
    }

    fn receive_inner_v1(
        &mut self,
        writers: &mut RootCurrentWritersOriginalV1,
        original: &UnixStream,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &RootInitialUseAuthorizedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
        first: &RootInitialControllerReadonlyOriginalV1,
    ) -> Result<(), E> {
        authorization.require_complete_v1()?;
        first.require_complete_v1()?;
        let body = open.body_v1()?;
        {
            let accepted = self
                .before
                .borrow_for_preparation_v1(&originals.peer, &originals.stream)
                .map_err(|_| E::Incomplete)?;
            self.endpoint = Some(accepted.require_same_endpoint_v1(original.as_fd()));
        }
        self.endpoint
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(E::Incomplete)?;
        self.before
            .observe_once_v1(writers, open, &originals.peer, &originals.stream);
        self.before_readback = Some(match writers.opened_pair_view_v1() {
            Ok((authority, policy)) => authorization.readback_current_v1(authority, policy),
            Err(error) => Err(RootInitialOpenErrorV1::Root(error)),
        });
        self.before_live = Some(
            self.before
                .require_complete_v1()
                .map_err(|_| ReadError::ProtectedBoundary)
                .and_then(|()| {
                    self.before_readback
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .ok_or(ReadError::ProtectedBoundary)?;
                    require_live_v1(
                        open,
                        source,
                        first,
                        self.before
                            .sample_v1()
                            .map_err(|_| ReadError::ProtectedBoundary)?,
                    )
                }),
        );
        self.before_live
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(E::Incomplete)?;
        self.received = Some(self.io.run_once(
            &mut &*original,
            &mut self.raw,
            source.original_cutoff_v1().map_err(|_| E::Incomplete)?,
            DeadlineStreamDirectionV1::Read,
        ));
        self.received
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(E::Incomplete)?;
        self.decoded = Some((|| {
            let sequence = u64::from(
                ready
                    .original_transfer_index_v1()
                    .map_err(|_| HistoryErrorV1::Correlation)?
                    .count(),
            )
            .checked_add(6)
            .ok_or(HistoryErrorV1::Extent)?;
            let frame = FrameEnvelopeV1::decode(
                &self.raw,
                FrameCoordinatesV1 {
                    kind: FrameKindV1::UseReserved,
                    lane: body.open.lane,
                    sequence,
                    root_nonce: body.root_nonce,
                    controller_nonce: body.open.controller_nonce,
                },
            )?;
            let receipt = UseReservedNativeReceiptDataV1::decode(frame.payload(), body.open.lane)?;
            receipt.body(body.open.lane)?.require_authorization_v1(
                body.open.lane,
                authorization
                    .completed_receipt_v1()
                    .map_err(|_| HistoryErrorV1::Correlation)?,
            )
        })());
        self.decoded
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(E::Incomplete)?;
        self.prepare_expected_v1(open, authorization, ready, cache)
    }

    fn prepare_expected_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &RootInitialUseAuthorizedOriginalV1,
        ready: &RootInitialReadyOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
    ) -> Result<(), E> {
        let lane = open.body_v1()?.open.lane;
        let receipt =
            UseReservedNativeReceiptDataV1::decode(&self.raw[FRAME_HEADER_BYTES..], lane)?;
        let body = receipt.body(lane)?;
        let inputs = cache
            .controller_receipt_v1(open, ready)
            .map_err(|_| E::Incomplete)?;
        let prior = RecordEnvelopeV1::decode(
            inputs.record,
            KeyV1::new(lane, OwnerV1::Controller, 3)?,
            PhaseV1::new(OwnerV1::Controller, 2)?,
        )?;
        let encoded = RootValidatedBodyDataV1 {
            authorization: authorization.completed_receipt_v1()?,
        }
        .encode(lane)?;
        let key = KeyV1::new(lane, OwnerV1::Controller, 4)?;
        let phase = PhaseV1::new(OwnerV1::Controller, 3)?;
        let mut record = [0; ROOT_VALIDATED_RECORD_BYTES_V1];
        let checksum = RecordEnvelopeV1::encode_into(
            RecordCoordinatesV1 {
                key,
                phase,
                predecessor: prior.checksum(),
                correlation: prior.coordinates().correlation,
            },
            &encoded,
            &mut record,
        )?;
        let head = LatestHeadV1::new(4, checksum)?.encode();
        self.validated = Some(
            super::super::super::initial_controller::prepare_readonly_pair(
                key, phase, &record, &head,
            ),
        );
        self.bank = Some(body.expected_reserve_transaction_v1());
        self.reserved = Some(
            super::super::super::initial_controller::prepare_readonly_pair(
                KeyV1::new(lane, OwnerV1::Controller, 5)?,
                PhaseV1::new(OwnerV1::Controller, 4)?,
                receipt.record,
                &receipt.latest_head,
            ),
        );
        self.positions = Some((|| {
            if checksum != body.root_validated || inputs.names != receipt.names {
                return Err(ReadError::ProtectedBoundary);
            }
            let first = (inputs.after_next, inputs.after_end);
            let append = append_bytes_v1(positive(&self.validated)?)?;
            let second = (
                first.0.checked_add(4).ok_or_else(sequence)?,
                first
                    .1
                    .checked_add(append)
                    .ok_or(ReadError::JournalTooLarge)?,
            );
            let append = append_bytes_v1(positive(&self.bank)?)?;
            let third = (
                second.0.checked_add(5).ok_or_else(sequence)?,
                second
                    .1
                    .checked_add(append)
                    .ok_or(ReadError::JournalTooLarge)?,
            );
            let append = append_bytes_v1(positive(&self.reserved)?)?;
            let fourth = (
                third.0.checked_add(4).ok_or_else(sequence)?,
                third
                    .1
                    .checked_add(append)
                    .ok_or(ReadError::JournalTooLarge)?,
            );
            if third != (body.after_next, body.after_end)
                || fourth != (receipt.after_next, receipt.after_end)
            {
                return Err(ReadError::ProtectedBoundary);
            }
            Ok([first, second, third, fourth])
        })());
        positive(&self.positions)
            .map(|_| ())
            .map_err(|_| E::Incomplete)
    }

    pub(in crate::native::root_current) fn require_received_v1(&self) -> Result<(), E> {
        if self.reentered
            || !matches!(self.primary, Some(Ok(())))
            || !matches!(self.after_live, Some(Ok(())))
            || self.failure_v1().is_some()
        {
            Err(E::Incomplete)
        } else {
            Ok(())
        }
    }

    pub(in crate::native::root_current) fn receipt_v1(
        &self,
        lane: [u8; 16],
    ) -> Result<UseReservedNativeReceiptDataV1<'_>, E> {
        self.require_received_v1()?;
        Ok(UseReservedNativeReceiptDataV1::decode(
            &self.raw[FRAME_HEADER_BYTES..],
            lane,
        )?)
    }

    pub(in crate::native::root_current) fn expected_v1(
        &self,
    ) -> Result<[&JournalTransaction; 3], E> {
        self.require_received_v1()?;
        Ok([
            positive(&self.validated).map_err(|_| E::Incomplete)?,
            positive(&self.bank).map_err(|_| E::Incomplete)?,
            positive(&self.reserved).map_err(|_| E::Incomplete)?,
        ])
    }

    pub(in crate::native::root_current) fn positions_v1(&self) -> Result<[(u64, u64); 4], E> {
        self.require_received_v1()?;
        positive(&self.positions)
            .copied()
            .map_err(|_| E::Incomplete)
    }

    pub(in crate::native::root_current) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.before_arm)
            .or_else(|| cause(&self.after_arm))
            .or_else(|| cause(&self.endpoint))
            .or_else(|| self.before.failure_v1())
            .or_else(|| cause(&self.before_readback))
            .or_else(|| cause(&self.before_live))
            .or_else(|| self.io.failure())
            .or_else(|| cause(&self.received))
            .or_else(|| cause(&self.decoded))
            .or_else(|| cause(&self.validated))
            .or_else(|| cause(&self.bank))
            .or_else(|| cause(&self.reserved))
            .or_else(|| cause(&self.positions))
            .or_else(|| cause(&self.primary))
            .or_else(|| self.after.failure_v1())
            .or_else(|| cause(&self.after_readback))
            .or_else(|| cause(&self.after_live))
    }
}

fn require_live_v1(
    open: &RootInitialOpenPreparedOriginalV1,
    source: &RootInitialSourceExchangeOriginalV1,
    first: &RootInitialControllerReadonlyOriginalV1,
    sample: RawPairedClockSample,
) -> Result<(), ReadError> {
    let body = open.body_v1().map_err(|_| ReadError::ProtectedBoundary)?;
    open.clock_original_v1()
        .require_current_v1(sample, body.cutoff)
        .map_err(|_| ReadError::ProtectedBoundary)?;
    first.require_live_at_v1(sample)?;
    if sample.boottime_nanoseconds()
        >= source
            .original_cutoff_v1()
            .map_err(|_| ReadError::ProtectedBoundary)?
    {
        return Err(ReadError::ProtectedBoundary);
    }
    Ok(())
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, ReadError> {
    slot.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(ReadError::ProtectedBoundary)
}
fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|error| error as _)
}
fn sequence() -> ReadError {
    ReadError::from(Mechanical::SequenceExhausted)
}
fn append_bytes_v1(tx: &JournalTransaction) -> Result<u64, ReadError> {
    aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes(tx)
        .map_err(|error| ReadError::from(Mechanical::from(error)))
}
