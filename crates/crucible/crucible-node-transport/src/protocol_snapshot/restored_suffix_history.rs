//! Reads the distinct restored suffix history family without creating authority.
//!
//! The writer retains real ledger counters and request partials. Historical
//! records cannot construct a live budget, actor, Scope, Capture admission or
//! current World. Old invocation15 and startup14 readers keep their refusals.

use crate::ProviderError;
use crate::bodies::{
    BeginRequest, BlobBeginRequest, BlobChunkRequest, BlobFinishRequest, ExactRunArguments,
    ObserveRequest, PollRequest, RetireRequest,
};
use crate::envelope::{Envelope, Method};
use crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes;
use crate::reference_packet::service::native_startup::PacketRestoredSuffixReservationData;
use crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Names the exact standalone suffix-history component family.
pub const RESTORED_SUFFIX_HISTORY_SCHEMA: &str = "source-private.native-restored-suffix-history/1";
/// Names the separate fixed nonrenewing ledger family.
pub const RESTORED_SUFFIX_LEDGER_SCHEMA: &str = "source-private.native-restored-suffix-ledger/1";

/// Preserves the actual ledger milestone without granting its future transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalRestoredSuffixLedgerStage {
    /// Records no currently open original in the numeric ledger.
    Idle,
    /// Records a spent read which has not admitted an action.
    Ingress,
    /// Records independently spent action work awaiting full publication.
    Action,
    /// Records sticky failure; historical reading cannot refund or reopen it.
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum LedgerSchema {
    #[serde(rename = "source-private.native-restored-suffix-ledger/1")]
    Version1,
}

/// Retains all admitted and spent numeric axes without a live constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalRestoredSuffixLedger {
    schema: LedgerSchema,
    admitted: PacketRestoredSuffixReservationData,
    originals: u64,
    ingress_retained: u64,
    action_retained: u64,
    stage: HistoricalRestoredSuffixLedgerStage,
}

impl HistoricalRestoredSuffixLedger {
    pub(crate) fn from_actual_data(
        admitted: PacketRestoredSuffixReservationData,
        originals: u64,
        ingress_retained: u64,
        action_retained: u64,
        stage: HistoricalRestoredSuffixLedgerStage,
    ) -> Result<Self, ProviderError> {
        let data = Self {
            schema: LedgerSchema::Version1,
            admitted,
            originals,
            ingress_retained,
            action_retained,
            stage,
        };
        data.validate_data()?;
        Ok(data)
    }

    /// Checks every recorded scalar without constructing a spending ledger.
    ///
    /// # Errors
    /// Refuses another family, overdrawn or overflowing independent axes.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        self.admitted.requested_bytes_data()?;
        if self.schema != LedgerSchema::Version1
            || self.originals > self.admitted.maximum_originals.get()
            || self.ingress_retained > self.admitted.ingress.retained_requested_bytes.get()
            || self.action_retained > self.admitted.actions.retained_requested_bytes.get()
            || (self.originals == 0 && (self.ingress_retained != 0 || self.action_retained != 0))
            || (self.originals == 0
                && matches!(
                    self.stage,
                    HistoricalRestoredSuffixLedgerStage::Ingress
                        | HistoricalRestoredSuffixLedgerStage::Action
                ))
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Returns the original reservation as historical DATA only.
    pub const fn admitted_data(&self) -> PacketRestoredSuffixReservationData {
        self.admitted
    }
    /// Returns all spent original slots, including interrupted work.
    pub const fn originals_data(&self) -> u64 {
        self.originals
    }
    /// Returns the actual remaining count without refunding failed slots.
    ///
    /// # Errors
    /// Refuses an invalid or overdrawn historical count.
    pub fn remaining_originals_data(&self) -> Result<u64, ProviderError> {
        self.validate_data()?;
        self.admitted
            .maximum_originals
            .get()
            .checked_sub(self.originals)
            .ok_or_else(invalid)
    }
    /// Returns the independently spent retained ingress axis.
    pub const fn ingress_retained_data(&self) -> u64 {
        self.ingress_retained
    }
    /// Returns the independently spent retained action axis.
    pub const fn action_retained_data(&self) -> u64 {
        self.action_retained
    }
    /// Returns the exact terminal or partial ledger milestone.
    pub const fn stage_data(&self) -> HistoricalRestoredSuffixLedgerStage {
        self.stage
    }
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("restored suffix historical codec differs")
}

/// Retains a method-discriminated Producer typed partial as historical DATA.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalRestoredProducerBody {
    /// Retains the real Begin body, even when its later validation failed.
    Begin(BeginRequest),
    /// Retains the separately decoded Poll body.
    Poll(PollRequest),
    /// Retains the actual Retire body and custody reference.
    Retire(RetireRequest),
    /// Retains the actual current Observe body.
    Observe(ObserveRequest),
    /// Retains the actual upload Begin body.
    BlobBegin(BlobBeginRequest),
    /// Retains a decoded upload chunk independently of its original raw body.
    BlobChunk(BlobChunkRequest),
    /// Retains the actual upload Finish body.
    BlobFinish(BlobFinishRequest),
}

/// Preserves an actual partial/terminal stage without creating live dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalRestoredAttemptStage {
    /// Retains a spent read slot with no parsed original.
    Receiving,
    /// Retains a raw original before typed decode.
    Raw,
    /// Retains typed children before dispatch.
    Typed,
    /// Retains in-progress action history, never a settled success seal.
    Dispatched,
    /// Retains completed publication history, never a renewed ACK right.
    Published,
    /// Retains sticky refusal, failure or interruption.
    Failed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserveAttempt {
    schema: String,
    ordinal: u64,
    original: Option<Envelope>,
    body: Option<ObserveRequest>,
    terminal: Option<Envelope>,
    stage: HistoricalRestoredAttemptStage,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerAttempt {
    schema: String,
    ordinal: u64,
    original: Option<Envelope>,
    body: Option<HistoricalRestoredProducerBody>,
    arguments: Option<ExactRunArguments>,
    terminal: Option<Envelope>,
    prepared_reply: Option<Map<String, Value>>,
    stage: HistoricalRestoredAttemptStage,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedSuffix {
    schema: String,
    model: [usize; 8],
    launch_digest: Value,
    launch_bytes: usize,
    frame_bytes: usize,
    originals: usize,
    reservation: PacketRestoredSuffixReservationData,
    retained: usize,
    transient: usize,
    scratch: usize,
    requested: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuffixHistory {
    schema: String,
    capacities: Vec<(String, usize, usize, usize)>,
    capacity_rows: usize,
    creator: u32,
    thread: String,
    preamble: Value,
    reservation: PacketRestoredSuffixReservationData,
    ledger: HistoricalRestoredSuffixLedger,
    observe_attempts: Vec<ObserveAttempt>,
    observe_capacity: usize,
    producer_attempts: Vec<ProducerAttempt>,
    producer_capacity: usize,
    raw7: Value,
    raw7_bytes: usize,
    raw5: Value,
    raw5_bytes: usize,
    sealed: Option<SealedSuffix>,
    failed: bool,
    first_observation: Option<(String, usize)>,
}

/// Owns an exact historical component and all typed request partials as DATA.
///
/// This owner deliberately has no conversion to a live boot, budget, Weak, Rc
/// identity, Source/Window claim or native permission. The exact original bytes
/// remain retained alongside the inert typed reader result.
pub struct HistoricalRestoredSuffixHistory {
    original: Vec<u8>,
    parsed: Option<Value>,
    data: Option<SuffixHistory>,
}

/// Reports independent new owning decoder phases as DATA, never admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoredSuffixHistoryConstructionData {
    retained: usize,
    transient: usize,
    scratch: usize,
    total: usize,
}

impl RestoredSuffixHistoryConstructionData {
    /// Returns independent raw, typed and historical capacity-owner storage.
    pub const fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }
    /// Returns complete simultaneous parser and verification work.
    pub const fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }
    /// Returns fixed defining reader/result headers.
    pub const fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }
    /// Returns the checked whole construction demand.
    pub const fn requested_bytes_data(&self) -> usize {
        self.total
    }
}

/// Borrows an explicitly bounded component before owning decode is admitted.
pub struct RestoredSuffixHistoryDecodePlan<'a> {
    input: &'a [u8],
    maximum: usize,
    demand: RestoredSuffixHistoryConstructionData,
}

impl<'a> RestoredSuffixHistoryDecodePlan<'a> {
    /// Checks the exact family/roster and bounds independent owning decode work.
    ///
    /// # Errors
    /// Refuses a missing/unknown root, old family, oversized body or checked overflow.
    pub fn validate(
        input: &'a [u8],
        maximum_input: usize,
        maximum_requested: usize,
    ) -> Result<Self, ProviderError> {
        if input.is_empty() || input.len() > maximum_input || maximum_input == 0 {
            return Err(invalid());
        }
        // A distinct closed family is mandatory before any owning decode. The
        // canonical root roster cannot fall back to invocation15 or startup14.
        let mut fields = super::owned11::OriginalOwned11Fields::object(input)?;
        for name in [
            "capacities",
            "capacity_rows",
            "creator",
            "failed",
            "first_observation",
            "ledger",
            "observe_attempts",
            "observe_capacity",
            "preamble",
            "producer_attempts",
            "producer_capacity",
            "raw5",
            "raw5_bytes",
            "raw7",
            "raw7_bytes",
            "reservation",
            "schema",
            "sealed",
            "thread",
        ] {
            let raw = fields.named(name)?;
            if name == "schema"
                && super::owned11::original_owned11_plain_string(raw)?
                    != RESTORED_SUFFIX_HISTORY_SCHEMA
            {
                return Err(invalid());
            }
        }
        fields.finish()?;
        let extent = original_json_value_storage_extent_data(input.len())?;
        // Raw byte preservation, strict DOM parse, typed request/Value children
        // and roundtrip verification are independent simultaneous owners.
        let typed = extent
            .maximum_value_nodes
            .checked_mul(
                std::mem::size_of::<ProducerAttempt>()
                    .checked_add(std::mem::size_of::<ObserveAttempt>())
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)?;
        let retained = input
            .len()
            .checked_add(extent.value_dom_requested_bytes)
            .and_then(|n| n.checked_add(typed))
            .ok_or_else(invalid)?;
        let transient = extent
            .canonical_pass_requested_bytes()?
            .checked_mul(3)
            .and_then(|n| n.checked_add(typed))
            .ok_or_else(invalid)?;
        let scratch = original_restored_suffix_history_counter_scratch_data();
        let total = retained
            .checked_add(transient)
            .and_then(|n| n.checked_add(scratch))
            .ok_or_else(invalid)?;
        let demand = RestoredSuffixHistoryConstructionData {
            retained,
            transient,
            scratch,
            total,
        };
        if total > maximum_requested {
            return Err(invalid());
        }
        Ok(Self {
            input,
            maximum: maximum_input,
            demand,
        })
    }

    /// Returns the full new decoder demand, never a spending grant.
    pub const fn demand_data(&self) -> &RestoredSuffixHistoryConstructionData {
        &self.demand
    }

    /// Retains a partial output before allocating or validating the owning decode.
    ///
    /// The genuine caller separately admits this whole demand. The returned
    /// history cannot activate Capture or a restoration; later correspondence
    /// failure leaves exact raw bytes and any completed typed owner in `output`.
    ///
    /// # Errors
    /// Refuses another output, short admission, malformed/duplicate/unknown keys,
    /// invalid family, contradictory counters/ordinals or incomplete correspondence.
    pub fn reconstruct_into(
        &self,
        admitted: &RestoredSuffixHistoryConstructionData,
        output: &mut Option<HistoricalRestoredSuffixHistory>,
    ) -> Result<(), ProviderError> {
        if output.is_some() || admitted != &self.demand {
            return Err(invalid());
        }
        *output = Some(HistoricalRestoredSuffixHistory {
            original: Vec::new(),
            parsed: None,
            data: None,
        });
        let slot = output.as_mut().ok_or_else(invalid)?;
        slot.original
            .try_reserve_exact(self.input.len())
            .map_err(|_| invalid())?;
        slot.original.extend_from_slice(self.input);
        slot.parsed = Some(crucible_node_format::canonical::parse_json(
            self.input,
            self.maximum,
        )?);
        let value = slot.parsed.as_ref().ok_or_else(invalid)?;
        for key in ["observe_attempts", "producer_attempts"] {
            if value
                .get(key)
                .and_then(Value::as_array)
                .is_none_or(|attempts| attempts.len() > 256)
            {
                return Err(invalid());
            }
        }
        slot.data = Some(
            serde_json::from_value(value.clone())
                .map_err(crucible_node_format::ContractError::from)?,
        );
        slot.authenticate_data()
    }
}

impl HistoricalRestoredSuffixHistory {
    /// Borrows the exact original body; no canonical replacement identity is made.
    pub fn original_bytes_data(&self) -> &[u8] {
        &self.original
    }
    /// Borrows the full original admitted/spent ledger after complete validation.
    ///
    /// # Errors
    /// Refuses a partial or inconsistent historical decode.
    pub fn ledger_data(&self) -> Result<&HistoricalRestoredSuffixLedger, ProviderError> {
        self.authenticate_data()?;
        Ok(&self.data.as_ref().ok_or_else(invalid)?.ledger)
    }
    fn authenticate_data(&self) -> Result<(), ProviderError> {
        let data = self.data.as_ref().ok_or_else(invalid)?;
        data.ledger.validate_data()?;
        if data.schema != RESTORED_SUFFIX_HISTORY_SCHEMA
            || data.creator == 0
            || data.thread != "same-original-thread-history-only"
            || data.reservation != data.ledger.admitted_data()
            || data.capacities.len() != data.capacity_rows
            || data.observe_attempts.len() > data.observe_capacity
            || data.producer_attempts.len() > data.producer_capacity
            || data.observe_capacity > 256
            || data.producer_capacity > 256
            || data.raw7_bytes == 0
            || data.raw5_bytes == 0
            || data
                .first_observation
                .as_ref()
                .is_none_or(|(role, _)| role != "first_restoration_observation")
        {
            return Err(invalid());
        }
        let capacity_value = serde_json::to_value(&data.capacities)
            .map_err(crucible_node_format::ContractError::from)?;
        let capacity_bytes = crucible_node_format::canonical::canonical_json(&capacity_value)?;
        crate::retained_metadata::records::ValidatedMetadataRecords::validate(
            &capacity_bytes,
            data.capacity_rows,
            data.reservation
                .requested_bytes_data()?
                .try_into()
                .map_err(|_| invalid())?,
        )?;
        compact_fixed(&data.raw7, 32)?;
        compact_fixed(&data.raw5, 32)?;
        compact_fixed(&data.preamble, crate::reference_packet::service::native_startup::ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES)?;
        let sealed = data.sealed.as_ref().ok_or_else(invalid)?;
        compact_fixed(&sealed.launch_digest, 32)?;
        let total = sealed.model[..7]
            .iter()
            .try_fold(0usize, |n, term| n.checked_add(*term).ok_or_else(invalid))?;
        if sealed.schema != "source-private.native-restored-suffix-sealed/1"
            || total != sealed.model[7]
            || sealed.reservation != data.reservation
            || sealed.originals
                != usize::try_from(data.reservation.maximum_originals.get())
                    .map_err(|_| invalid())?
            || sealed.launch_bytes == 0
            || sealed.frame_bytes == 0
            || sealed
                .retained
                .checked_add(sealed.transient)
                .and_then(|n| n.checked_add(sealed.scratch))
                != Some(sealed.requested)
        {
            return Err(invalid());
        }
        let mut previous = 0;
        for attempt in &data.observe_attempts {
            if attempt.schema != "source-private.native-restored-observe-attempt/1" {
                return Err(invalid());
            }
            ordinal(attempt.ordinal, &mut previous, data.ledger.originals_data())?;
            attempt_state(
                attempt.stage,
                &attempt.original,
                &attempt.terminal,
                attempt.body.is_some(),
            )?;
            if let Some(original) = &attempt.original {
                if original.method != Method::Observe {
                    return Err(invalid());
                }
                if let Some(body) = &attempt.body {
                    typed_body_matches(original, body)?;
                }
            }
        }
        previous = 0;
        for attempt in &data.producer_attempts {
            if attempt.schema != "source-private.native-restored-producer-attempt/1" {
                return Err(invalid());
            }
            ordinal(attempt.ordinal, &mut previous, data.ledger.originals_data())?;
            attempt_state(
                attempt.stage,
                &attempt.original,
                &attempt.terminal,
                attempt.body.is_some(),
            )?;
            if attempt.stage == HistoricalRestoredAttemptStage::Published
                && attempt.terminal.as_ref().map(|terminal| &terminal.body)
                    != attempt.prepared_reply.as_ref()
            {
                return Err(invalid());
            }
            if let (Some(original), Some(body)) = (&attempt.original, &attempt.body) {
                let method = match body {
                    HistoricalRestoredProducerBody::Begin(_) => Method::Begin,
                    HistoricalRestoredProducerBody::Poll(_) => Method::Poll,
                    HistoricalRestoredProducerBody::Retire(_) => Method::Retire,
                    HistoricalRestoredProducerBody::Observe(_) => Method::Observe,
                    HistoricalRestoredProducerBody::BlobBegin(_) => Method::BlobBegin,
                    HistoricalRestoredProducerBody::BlobChunk(_) => Method::BlobChunk,
                    HistoricalRestoredProducerBody::BlobFinish(_) => Method::BlobFinish,
                };
                if original.method != method
                    || (method != Method::Begin && attempt.arguments.is_some())
                {
                    return Err(invalid());
                }
                match body {
                    HistoricalRestoredProducerBody::Begin(body) => {
                        typed_body_matches(original, body)?;
                        if let Some(arguments) = &attempt.arguments
                            && serde_json::to_value(arguments)
                                .map_err(crucible_node_format::ContractError::from)?
                                != Value::Object(body.arguments.clone())
                        {
                            return Err(invalid());
                        }
                    }
                    HistoricalRestoredProducerBody::Poll(body) => {
                        typed_body_matches(original, body)?
                    }
                    HistoricalRestoredProducerBody::Retire(body) => {
                        typed_body_matches(original, body)?
                    }
                    HistoricalRestoredProducerBody::Observe(body) => {
                        typed_body_matches(original, body)?
                    }
                    HistoricalRestoredProducerBody::BlobBegin(body) => {
                        typed_body_matches(original, body)?
                    }
                    HistoricalRestoredProducerBody::BlobChunk(body) => {
                        typed_body_matches(original, body)?
                    }
                    HistoricalRestoredProducerBody::BlobFinish(body) => {
                        typed_body_matches(original, body)?
                    }
                }
            }
            if data
                .observe_attempts
                .iter()
                .any(|old| old.ordinal == attempt.ordinal)
            {
                return Err(invalid());
            }
        }
        if data.ledger.stage_data() == HistoricalRestoredSuffixLedgerStage::Idle
            && (data
                .observe_attempts
                .len()
                .checked_add(data.producer_attempts.len())
                .ok_or_else(invalid)?
                != usize::try_from(data.ledger.originals_data()).map_err(|_| invalid())?
                || data
                    .observe_attempts
                    .iter()
                    .any(|attempt| attempt.stage != HistoricalRestoredAttemptStage::Published)
                || data
                    .producer_attempts
                    .iter()
                    .any(|attempt| attempt.stage != HistoricalRestoredAttemptStage::Published))
        {
            return Err(invalid());
        }
        // Failure and incomplete ledger phases are retained verbatim; this
        // reader deliberately does not turn them into a settled Capture seal.
        let _ = data.failed;
        Ok(())
    }
}

fn typed_body_matches(original: &Envelope, body: &impl Serialize) -> Result<(), ProviderError> {
    if serde_json::to_value(body).map_err(crucible_node_format::ContractError::from)?
        != Value::Object(original.body.clone())
    {
        return Err(invalid());
    }
    Ok(())
}

fn compact_fixed(value: &Value, expected: usize) -> Result<(), ProviderError> {
    let bytes = crucible_node_format::canonical::canonical_json(value)?;
    if ValidatedCompactBytes::validate(&bytes, bytes.len(), expected)?.decoded_length() != expected
    {
        return Err(invalid());
    }
    Ok(())
}

fn ordinal(actual: u64, previous: &mut u64, maximum: u64) -> Result<(), ProviderError> {
    if actual == 0 || actual <= *previous || actual > maximum {
        return Err(invalid());
    }
    *previous = actual;
    Ok(())
}

fn attempt_state(
    stage: HistoricalRestoredAttemptStage,
    original: &Option<Envelope>,
    terminal: &Option<Envelope>,
    typed: bool,
) -> Result<(), ProviderError> {
    if matches!(
        stage,
        HistoricalRestoredAttemptStage::Raw
            | HistoricalRestoredAttemptStage::Typed
            | HistoricalRestoredAttemptStage::Dispatched
            | HistoricalRestoredAttemptStage::Published
    ) && original.is_none()
        || matches!(
            stage,
            HistoricalRestoredAttemptStage::Typed
                | HistoricalRestoredAttemptStage::Dispatched
                | HistoricalRestoredAttemptStage::Published
        ) && !typed
        || stage == HistoricalRestoredAttemptStage::Published && terminal.is_none()
    {
        return Err(invalid());
    }
    if stage == HistoricalRestoredAttemptStage::Published {
        original
            .as_ref()
            .ok_or_else(invalid)?
            .matches_response(terminal.as_ref().ok_or_else(invalid)?)?;
    }
    Ok(())
}

/// Names fixed reader/partial/result/borrowed-view headers before decoding.
pub fn original_restored_suffix_history_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<HistoricalRestoredSuffixLedger>()
        + size_of::<Result<HistoricalRestoredSuffixLedger, ProviderError>>()
        + size_of::<RestoredSuffixHistoryDecodePlan<'static>>()
        + size_of::<Result<RestoredSuffixHistoryDecodePlan<'static>, ProviderError>>()
        + size_of::<HistoricalRestoredSuffixHistory>()
        + size_of::<Option<HistoricalRestoredSuffixHistory>>()
        + size_of::<SuffixHistory>()
        + size_of::<Result<SuffixHistory, serde_json::Error>>()
        + size_of::<ProducerAttempt>()
        + size_of::<ObserveAttempt>()
        + size_of::<SealedSuffix>()
        + size_of::<RestoredSuffixHistoryConstructionData>()
        + size_of::<Result<RestoredSuffixHistoryConstructionData, ProviderError>>()
        + size_of::<Value>() * 3
        + size_of::<Result<Value, crucible_node_format::ContractError>>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<HistoricalRestoredAttemptStage>()
        + size_of::<HistoricalRestoredProducerBody>()
        + size_of::<std::slice::Iter<'static, ObserveAttempt>>() * 2
        + size_of::<std::slice::Iter<'static, ProducerAttempt>>() * 2
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<
            Result<
                crate::retained_metadata::records::ValidatedMetadataRecords<'static>,
                ProviderError,
            >,
        >()
        + size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>()
        + size_of::<ValidatedCompactBytes<'static>>()
        + size_of::<Result<ValidatedCompactBytes<'static>, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
    use crucible_node_format::U64;

    fn ledger() -> HistoricalRestoredSuffixLedger {
        let row = PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(30),
            maximum_simultaneous_transient_bytes: U64::new(40),
            declared_counter_scratch_bytes: U64::new(50),
        };
        HistoricalRestoredSuffixLedger::from_actual_data(
            PacketRestoredSuffixReservationData {
                maximum_originals: U64::new(3),
                ingress: row,
                actions: row,
            },
            2,
            20,
            10,
            HistoricalRestoredSuffixLedgerStage::Failed,
        )
        .unwrap()
    }

    #[test]
    fn historical_ledger_refuses_wrong_family_unknown_keys_and_overdraw() {
        let original = ledger();
        let mut value = serde_json::to_value(original).unwrap();
        value["originals"] = Value::from(4);
        assert!(
            serde_json::from_value::<HistoricalRestoredSuffixLedger>(value.clone())
                .unwrap()
                .validate_data()
                .is_err()
        );
        value = serde_json::to_value(original).unwrap();
        value["schema"] = Value::from("source-private.native-startup-owner/15");
        assert!(serde_json::from_value::<HistoricalRestoredSuffixLedger>(value).is_err());
        value = serde_json::to_value(original).unwrap();
        value["remaining"] = Value::from(3);
        assert!(serde_json::from_value::<HistoricalRestoredSuffixLedger>(value).is_err());
        assert_eq!(original.remaining_originals_data().unwrap(), 1);
    }

    #[test]
    fn short_decode_credit_refuses_before_creating_an_output_owner() {
        let raw = br#"{"capacities":[],"capacity_rows":0,"creator":1,"failed":true,"first_observation":null,"ledger":null,"observe_attempts":[],"observe_capacity":0,"preamble":null,"producer_attempts":[],"producer_capacity":0,"raw5":null,"raw5_bytes":0,"raw7":null,"raw7_bytes":0,"reservation":null,"schema":"source-private.native-restored-suffix-history/1","sealed":null,"thread":"same-original-thread-history-only"}"#;
        let plan = RestoredSuffixHistoryDecodePlan::validate(raw, 4096, usize::MAX).unwrap();
        let mut short = *plan.demand_data();
        short.total -= 1;
        let mut output = None;
        assert!(plan.reconstruct_into(&short, &mut output).is_err());
        assert!(output.is_none());
        assert!(
            plan.reconstruct_into(plan.demand_data(), &mut output)
                .is_err()
        );
        assert_eq!(output.as_ref().unwrap().original_bytes_data(), raw);
        assert!(output.as_ref().unwrap().ledger_data().is_err());
    }
}
