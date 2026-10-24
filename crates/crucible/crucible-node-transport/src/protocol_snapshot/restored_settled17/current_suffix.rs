//! Retains every current suffix attempt and the unchanged nonrenewing ledger.

use super::{
    current_contracts::*,
    current_fixed::*,
    current_ordinary::*,
    current_shared::{CurrentShared17, read_reference17, read_shared_vector17},
};
use crate::{
    ProviderError,
    bodies::{ExactRunArguments, ObserveRequest},
    envelope::Envelope,
    protocol_snapshot::{
        owned11::typed::{Fields, HistoricalType, Ledger, invalid, plain_string, unsigned},
        restored_suffix_history::HistoricalRestoredSuffixLedger,
    },
    reference_packet::service::{ack_emitter::NativeAckBoot, native_startup::*},
    retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind},
};
use serde_json::{Map, Value};
use std::{
    cell::RefCell,
    mem::{align_of, size_of},
    rc::Rc,
};

#[derive(Clone, Copy)]
pub(crate) enum CurrentAttemptStage17 {
    Receiving,
    Raw,
    Typed,
    Authenticated,
    Dispatched,
    Published,
    Failed,
}

pub(crate) struct CurrentSuffixObserve17 {
    pub(crate) ordinal: u64,
    pub(crate) original: Option<Envelope>,
    pub(crate) body: Option<ObserveRequest>,
    pub(crate) terminal: Option<Envelope>,
    pub(crate) stage: CurrentAttemptStage17,
}
impl HistoricalType for CurrentSuffixObserve17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role17(
            fields.named("schema")?,
            "source-private.native-restored-observe-attempt/1",
        )?;
        let ordinal = ledger.read::<u64>(fields.named("ordinal")?, build)?;
        let original = ledger.read::<Option<Envelope>>(fields.named("original")?, build)?;
        let body = <Optional17<CurrentDto17<ObserveRequest>> as CurrentField17>::read(
            fields.named("body")?,
            ledger,
            build,
        )?;
        let terminal = ledger.read::<Option<Envelope>>(fields.named("terminal")?, build)?;
        let raw_stage = fields.named("stage")?;
        if plain_string(raw_stage)? == "authenticated" {
            return Err(invalid());
        }
        let stage = inline17::<CurrentAttemptStage17>(raw_stage, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            ordinal: ordinal.ok_or_else(invalid)?,
            original: original.ok_or_else(invalid)?,
            body: body.ok_or_else(invalid)?,
            terminal: terminal.ok_or_else(invalid)?,
            stage: stage.ok_or_else(invalid)?,
        }))
    }
}

pub(crate) struct CurrentSuffixProducer17 {
    pub(crate) ordinal: u64,
    pub(crate) original: Option<Envelope>,
    pub(crate) body: Option<CurrentOrdinaryBody17>,
    pub(crate) arguments: Option<ExactRunArguments>,
    pub(crate) terminal: Option<Envelope>,
    pub(crate) prepared_reply: Option<Map<String, Value>>,
    pub(crate) stage: CurrentAttemptStage17,
}
impl HistoricalType for CurrentSuffixProducer17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role17(
            fields.named("schema")?,
            "source-private.native-restored-producer-attempt/1",
        )?;
        let ordinal = ledger.read::<u64>(fields.named("ordinal")?, build)?;
        let original = ledger.read::<Option<Envelope>>(fields.named("original")?, build)?;
        let raw = fields.named("body")?;
        let body = if raw == b"null" {
            Some(None)
        } else {
            let mut body = Fields::object(raw)?;
            let (kind, raw) = body.pair()?.ok_or_else(invalid)?;
            let value = read_ordinary17(plain_string(kind)?, raw, ledger, build)?.map(Some);
            body.finish()?;
            value
        };
        let arguments = <Optional17<CurrentDto17<ExactRunArguments>> as CurrentField17>::read(
            fields.named("arguments")?,
            ledger,
            build,
        )?;
        let terminal = ledger.read::<Option<Envelope>>(fields.named("terminal")?, build)?;
        let prepared_reply =
            ledger.read::<Option<Map<String, Value>>>(fields.named("prepared_reply")?, build)?;
        let raw_stage = fields.named("stage")?;
        if plain_string(raw_stage)? == "authenticated" {
            return Err(invalid());
        }
        let stage = inline17::<CurrentAttemptStage17>(raw_stage, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            ordinal: ordinal.ok_or_else(invalid)?,
            original: original.ok_or_else(invalid)?,
            body: body.ok_or_else(invalid)?,
            arguments: arguments.ok_or_else(invalid)?,
            terminal: terminal.ok_or_else(invalid)?,
            prepared_reply: prepared_reply.ok_or_else(invalid)?,
            stage: stage.ok_or_else(invalid)?,
        }))
    }
}

pub(crate) struct CurrentSealedSuffix17 {
    pub(crate) model: [usize; 8],
    pub(crate) launch_digest: FixedCompact17<32>,
    pub(crate) launch_bytes: usize,
    pub(crate) frame_bytes: usize,
    pub(crate) originals: usize,
    pub(crate) reservation: PacketRestoredSuffixReservationData,
    pub(crate) retained: usize,
    pub(crate) transient: usize,
    pub(crate) scratch: usize,
    pub(crate) requested: usize,
}
impl HistoricalType for CurrentSealedSuffix17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role17(
            fields.named("schema")?,
            "source-private.native-restored-suffix-sealed/1",
        )?;
        let model = fixed_usizes17::<8>(fields.named("model")?, ledger, build)?;
        let launch_digest =
            ledger.read::<FixedCompact17<32>>(fields.named("launch_digest")?, build)?;
        let launch_bytes = ledger.read::<usize>(fields.named("launch_bytes")?, build)?;
        let frame_bytes = ledger.read::<usize>(fields.named("frame_bytes")?, build)?;
        let originals = ledger.read::<usize>(fields.named("originals")?, build)?;
        let reservation =
            <CurrentDto17<PacketRestoredSuffixReservationData> as CurrentField17>::read(
                fields.named("reservation")?,
                ledger,
                build,
            )?;
        let retained = ledger.read::<usize>(fields.named("retained")?, build)?;
        let transient = ledger.read::<usize>(fields.named("transient")?, build)?;
        let scratch = ledger.read::<usize>(fields.named("scratch")?, build)?;
        let requested = ledger.read::<usize>(fields.named("requested")?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            model: model.ok_or_else(invalid)?,
            launch_digest: launch_digest.ok_or_else(invalid)?,
            launch_bytes: launch_bytes.ok_or_else(invalid)?,
            frame_bytes: frame_bytes.ok_or_else(invalid)?,
            originals: originals.ok_or_else(invalid)?,
            reservation: reservation.ok_or_else(invalid)?,
            retained: retained.ok_or_else(invalid)?,
            transient: transient.ok_or_else(invalid)?,
            scratch: scratch.ok_or_else(invalid)?,
            requested: requested.ok_or_else(invalid)?,
        }))
    }
}

pub(crate) struct CurrentSuffix17 {
    pub(crate) creator: u32,
    pub(crate) preamble: FixedCompact17<ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES>,
    pub(crate) reservation: PacketRestoredSuffixReservationData,
    pub(crate) ledger: HistoricalRestoredSuffixLedger,
    pub(crate) observe_attempts: Vec<CurrentShared17<CurrentSuffixObserve17>>,
    pub(crate) producer_attempts: Vec<CurrentShared17<CurrentSuffixProducer17>>,
    pub(crate) raw7: FixedCompact17<32>,
    pub(crate) raw7_bytes: usize,
    pub(crate) raw5: FixedCompact17<32>,
    pub(crate) raw5_bytes: usize,
    pub(crate) sealed: Option<CurrentSealedSuffix17>,
    pub(crate) failed: bool,
    pub(crate) first_observation_group: Option<usize>,
    pub(crate) first_observation_record: Option<usize>,
}
impl HistoricalType for CurrentSuffix17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let layout = NativeAckBoot::current_suffix_box_layout17_data();
        if ledger.row_aligned(MetadataRecordKind::Boxed, 1, layout.1)? != layout.0 {
            return Err(invalid());
        }
        let mut fields = Fields::object(input)?;
        role17(
            fields.named("schema")?,
            "source-private.native-current-restored-suffix/17",
        )?;
        let creator_raw = fields.named("creator")?;
        role17(
            fields.named("thread_role")?,
            "same-original-native-thread-history-only",
        )?;
        let preamble_raw = fields.named("preamble")?;
        let reservation_raw = fields.named("reservation")?;
        let ledger_raw = fields.named("ledger")?;
        let observe_raw = fields.named("observe_attempts")?;
        let observe_capacity =
            usize::try_from(unsigned(fields.named("observe_capacity")?)?).map_err(|_| invalid())?;
        let producer_raw = fields.named("producer_attempts")?;
        let producer_capacity = usize::try_from(unsigned(fields.named("producer_capacity")?)?)
            .map_err(|_| invalid())?;
        let raw7_raw = fields.named("raw7")?;
        let raw7_bytes_raw = fields.named("raw7_bytes")?;
        let raw5_raw = fields.named("raw5")?;
        let raw5_bytes_raw = fields.named("raw5_bytes")?;
        let sealed_raw = fields.named("sealed")?;
        let failed_raw = fields.named("failed")?;
        let observation_raw = fields.named("first_observation_role")?;
        let record_raw = fields.named("first_observation_record")?;
        fields.finish()?;

        let creator = ledger.read::<u32>(creator_raw, build)?;
        let raw7_bytes = ledger.read::<usize>(raw7_bytes_raw, build)?;
        let raw5_bytes = ledger.read::<usize>(raw5_bytes_raw, build)?;
        let failed = ledger.read::<bool>(failed_raw, build)?;
        let first_observation_record = ledger.read::<Option<usize>>(record_raw, build)?;
        let observe_attempts = read_shared_vector17::<CurrentSuffixObserve17>(
            observe_raw,
            ledger,
            build,
            MetadataSharedKind::NativeRestoredSuffixObservationAttempt,
            (
                size_of::<RefCell<NativeRestoredSuffixObserveAttempt>>(),
                align_of::<RefCell<NativeRestoredSuffixObserveAttempt>>(),
            ),
            (
                size_of::<Rc<RefCell<NativeRestoredSuffixObserveAttempt>>>(),
                align_of::<Rc<RefCell<NativeRestoredSuffixObserveAttempt>>>(),
            ),
            Some(observe_capacity),
        )?;
        let producer_attempts = read_shared_vector17::<CurrentSuffixProducer17>(
            producer_raw,
            ledger,
            build,
            MetadataSharedKind::NativeRestoredProducerAttempt,
            (
                size_of::<RefCell<NativeRestoredProducerAttempt>>(),
                align_of::<RefCell<NativeRestoredProducerAttempt>>(),
            ),
            (
                size_of::<Rc<RefCell<NativeRestoredProducerAttempt>>>(),
                align_of::<Rc<RefCell<NativeRestoredProducerAttempt>>>(),
            ),
            Some(producer_capacity),
        )?;
        let first_observation_group = if observation_raw == b"null" {
            None
        } else {
            role17(observation_raw, "first_restoration_observation")?;
            Some(read_reference17(
                ledger,
                MetadataSharedKind::NativeRestorationObservationAttempt,
                NativeAckBoot::current_stage_layouts17_data()[2],
            )?)
        };
        let preamble = ledger
            .read::<FixedCompact17<ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES>>(
                preamble_raw,
                build,
            )?;
        let reservation =
            <CurrentDto17<PacketRestoredSuffixReservationData> as CurrentField17>::read(
                reservation_raw,
                ledger,
                build,
            )?;
        let budget = read_ledger17(ledger_raw, ledger, build)?;
        let raw7 = ledger.read::<FixedCompact17<32>>(raw7_raw, build)?;
        let raw5 = ledger.read::<FixedCompact17<32>>(raw5_raw, build)?;
        let sealed = ledger.read::<Option<CurrentSealedSuffix17>>(sealed_raw, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            creator: creator.ok_or_else(invalid)?,
            preamble: preamble.ok_or_else(invalid)?,
            reservation: reservation.ok_or_else(invalid)?,
            ledger: budget.ok_or_else(invalid)?,
            observe_attempts: observe_attempts.ok_or_else(invalid)?,
            producer_attempts: producer_attempts.ok_or_else(invalid)?,
            raw7: raw7.ok_or_else(invalid)?,
            raw7_bytes: raw7_bytes.ok_or_else(invalid)?,
            raw5: raw5.ok_or_else(invalid)?,
            raw5_bytes: raw5_bytes.ok_or_else(invalid)?,
            sealed: sealed.ok_or_else(invalid)?,
            failed: failed.ok_or_else(invalid)?,
            first_observation_group,
            first_observation_record: first_observation_record.ok_or_else(invalid)?,
        }))
    }
}
