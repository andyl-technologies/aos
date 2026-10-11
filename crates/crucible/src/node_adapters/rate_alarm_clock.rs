//! Owned rational counter, original alarm requests and exact pending reactions.
//!
//! This model converts shared picoseconds to a separate visible counter. Its
//! immutable rate, epoch and drift never change coordinator time. Native state
//! includes complete original requests and pending/fired alarm bodies; publishing
//! those bodies does not acknowledge their common-runtime receipt.
//!
//! ```json
//! {"format":"crucible.rate-alarm-clock.v1","definition":{"numerator":"1",
//!  "denominator":"1","epoch_ps":"0","epoch_counter":"0","drift_ppb":0},
//!  "position":{"time_ps":"0","microstep":"0","phase":0},
//!  "next_sequence":"0","requests":[],"pending":[],"issued":[]}
//! ```

use std::io::{self, Write};

use crucible_node_contract::{
    Extensions, Id, NodeBinding, Phase, Position, SchemaRef, U64, canonical,
};
use serde::{Deserialize, Serialize, ser::SerializeSeq};

use super::host::failure;
use crate::node_contract::OperationFailure;

#[cfg(test)]
mod tests;

pub(super) type ClockEventKey = (u64, u32, u32);
pub(super) type ClockInputChanges = (Vec<ClockEventKey>, Vec<ClockEventKey>);

/// Bounds the complete original command and pending publication roster.
pub const MAXIMUM_CLOCK_REQUESTS: usize = 64;
/// Bounds the complete selected native continuation before serialization.
pub const MAXIMUM_CLOCK_STATE_BYTES: usize = 64 * 1024;

/// Selects an immutable rational visible counter without granting execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateAlarmClockDefinition {
    /// Selects 1 through one billion counter units per rational interval.
    pub numerator: U64,
    /// Selects a shared-picosecond divisor from 1 through one billion.
    pub denominator: U64,
    /// Sets the immutable shared coordinate of the visible counter epoch.
    pub epoch_ps: U64,
    /// Sets the visible counter reading at the epoch.
    pub epoch_counter: U64,
    /// Selects fixed drift from -999,999,999 through 1,000,000,000 parts per billion.
    pub drift_ppb: i64,
}

impl RateAlarmClockDefinition {
    fn rate(&self) -> Result<(u64, u64), OperationFailure> {
        if self.numerator.get() == 0
            || self.numerator.get() > 1_000_000_000
            || self.denominator.get() == 0
            || self.denominator.get() > 1_000_000_000
            || !(-999_999_999..=1_000_000_000).contains(&self.drift_ppb)
        {
            return Err(failure(
                "rational clock rate or drift is outside selected bounds",
            ));
        }
        let drift = u64::try_from(1_000_000_000i64 + self.drift_ppb)
            .map_err(|_| failure("rational clock drift overflow"))?;
        let numerator = self
            .numerator
            .get()
            .checked_mul(drift)
            .ok_or_else(|| failure("rational clock numerator overflow"))?;
        let denominator = self
            .denominator
            .get()
            .checked_mul(1_000_000_000)
            .ok_or_else(|| failure("rational clock denominator overflow"))?;
        Ok((numerator, denominator))
    }

    /// Computes the visible reading at an exact shared coordinate.
    ///
    /// # Errors
    /// Refuses invalid rates, time before the epoch or counter overflow.
    pub fn reading(&self, time_ps: U64) -> Result<U64, OperationFailure> {
        let (numerator, denominator) = self.rate()?;
        let elapsed = time_ps
            .get()
            .checked_sub(self.epoch_ps.get())
            .ok_or_else(|| failure("clock reading precedes its immutable epoch"))?;
        let units = u128::from(elapsed) * u128::from(numerator) / u128::from(denominator);
        let units = u64::try_from(units).map_err(|_| failure("visible counter overflow"))?;
        self.epoch_counter
            .get()
            .checked_add(units)
            .map(U64::new)
            .ok_or_else(|| failure("visible counter epoch addition overflow"))
    }

    /// Computes the first shared picosecond at which a counter target is reached.
    ///
    /// # Errors
    /// Refuses invalid rates, a target before the epoch or an unrepresentable time.
    pub fn alarm_time(&self, target: U64) -> Result<U64, OperationFailure> {
        let (numerator, denominator) = self.rate()?;
        let delta = target
            .get()
            .checked_sub(self.epoch_counter.get())
            .ok_or_else(|| failure("alarm target precedes the visible epoch"))?;
        let product = u128::from(delta) * u128::from(denominator);
        let quotient = product / u128::from(numerator);
        let rounded = quotient + u128::from(product % u128::from(numerator) != 0);
        let ticks = u64::try_from(rounded).map_err(|_| failure("alarm time overflow"))?;
        self.epoch_ps
            .get()
            .checked_add(ticks)
            .map(U64::new)
            .ok_or_else(|| failure("alarm epoch addition overflow"))
    }
}

/// Names a bounded original counter request independently of its input transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum RateAlarmClockRequest {
    /// Reads the counter at the authentic input reaction coordinate.
    Read {
        /// Names this original request.
        correlation: Id,
    },
    /// Arms one once-only alarm at a future counter target.
    Arm {
        /// Names this original request and alarm.
        correlation: Id,
        /// Selects the visible counter threshold.
        target: U64,
    },
    /// Cancels an existing unfired original alarm.
    Cancel {
        /// Names this original cancellation request.
        correlation: Id,
        /// Names the exact original arm request.
        alarm: Id,
    },
}

impl RateAlarmClockRequest {
    fn correlation(&self) -> &Id {
        match self {
            Self::Read { correlation }
            | Self::Arm { correlation, .. }
            | Self::Cancel { correlation, .. } => correlation,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClockRequestRecord {
    request: RateAlarmClockRequest,
    reaction: Position,
}

/// Retains one exact counter/alarm response without common publication authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateAlarmClockEvent {
    /// Retains the original request or alarm identity.
    pub correlation: Id,
    /// Names the source-owned response kind: reading, armed, canceled, or alarm.
    pub kind: String,
    /// Retains the real native reaction before its later causal publication.
    pub reaction: Position,
    /// Reports the checked visible reading at that reaction.
    pub counter: U64,
    /// Retains one monotone original native FIFO identity.
    pub sequence: U64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    format: String,
    definition: RateAlarmClockDefinition,
    position: Position,
    next_sequence: U64,
    requests: Vec<ClockRequestRecord>,
    pending: Vec<RateAlarmClockEvent>,
    issued: Vec<RateAlarmClockEvent>,
}

/// Owns the complete rational counter and bounded original alarm continuation.
pub struct RateAlarmClock {
    saved: Snapshot,
}

impl RateAlarmClock {
    /// Creates an inactive original model at the shared epoch.
    ///
    /// # Errors
    /// Refuses a nonzero shared epoch, invalid rate/drift or unrepresentable reading.
    pub fn new(definition: RateAlarmClockDefinition) -> Result<Self, OperationFailure> {
        if definition.epoch_ps.get() != 0 {
            return Err(failure("initial clock requires shared epoch zero"));
        }
        definition.reading(0.into())?;
        Ok(Self {
            saved: Snapshot {
                format: "crucible.rate-alarm-clock.v1".into(),
                definition,
                position: Position::new(0.into(), 0.into(), Phase::BoundaryControl),
                next_sequence: 0.into(),
                requests: Vec::new(),
                pending: Vec::new(),
                issued: Vec::new(),
            },
        })
    }

    /// Reopens complete original native state as an inactive data model.
    ///
    /// This validates original request/alarm inventory without supplying source
    /// authentication, a fresh owner, activation, or any runtime permission.
    ///
    /// # Errors
    /// Refuses changed definitions, noncanonical or oversized bytes, incomplete
    /// original inventories and impossible counter/reaction history.
    pub fn from_continuation(
        definition: RateAlarmClockDefinition,
        bytes: &[u8],
    ) -> Result<Self, OperationFailure> {
        let mut model = Self::new(definition)?;
        model.restore(bytes)?;
        Ok(model)
    }

    /// Borrows the original immutable visible-clock definition.
    pub fn definition(&self) -> &RateAlarmClockDefinition {
        &self.saved.definition
    }

    /// Returns the earliest retained alarm reaction without issuing a runtime grant.
    ///
    /// Unseen input may produce an earlier read/arm response. This value alone
    /// therefore does not prove an unconditional output frontier.
    pub fn earliest_alarm(&self) -> Option<Position> {
        self.saved
            .pending
            .iter()
            .filter(|event| event.kind == "alarm")
            .map(|event| event.reaction)
            .min()
    }

    pub(super) fn position(&self) -> Position {
        self.saved.position
    }

    pub(super) fn issued(&self) -> &[RateAlarmClockEvent] {
        &self.saved.issued
    }

    pub(super) fn validate_native(bytes: &[u8]) -> Result<Self, OperationFailure> {
        let value = canonical::parse_json(bytes, MAXIMUM_CLOCK_STATE_BYTES)
            .map_err(|e| failure(&e.to_string()))?;
        let saved: Snapshot = serde_json::from_value(value).map_err(|e| failure(&e.to_string()))?;
        Self::from_continuation(saved.definition, bytes)
    }

    pub(super) fn validate_original_inputs(
        &self,
        inputs: &[(Position, U64, &[u8])],
    ) -> Result<(), OperationFailure> {
        if inputs.len() != self.saved.requests.len() {
            return Err(failure("clock original consumed request count differs"));
        }
        for (record, (delivery, _, bytes)) in self.saved.requests.iter().zip(inputs) {
            if delivery.phase != Phase::Delivery
                || record.reaction
                    != Position::new(delivery.time_ps, delivery.microstep, Phase::Reaction)
                || record.request != Self::decode_request(bytes)?
            {
                return Err(failure(
                    "clock original request/reaction differs from actual consumed input",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn original_parent(
        &self,
        event: &RateAlarmClockEvent,
    ) -> Result<Position, OperationFailure> {
        let record = self
            .saved
            .requests
            .iter()
            .find(|record| record.request.correlation() == &event.correlation)
            .ok_or_else(|| failure("clock original event lacks its actual input request"))?;
        let delivery = Position::new(
            record.reaction.time_ps,
            record.reaction.microstep,
            Phase::Delivery,
        );
        if delivery >= event.reaction {
            return Err(failure(
                "clock event precedes its original full-position input",
            ));
        }
        Ok(delivery)
    }

    pub(super) fn validate_pending_causes(
        &self,
        causes: &std::collections::BTreeMap<(u64, u32, u32), Vec<Position>>,
    ) -> Result<(), OperationFailure> {
        if causes.len() != self.saved.pending.len() {
            return Err(failure("clock pending original causal roster differs"));
        }
        for event in &self.saved.pending {
            let delivery = self.original_parent(event)?;
            if delivery >= event.reaction
                || causes
                    .get(&event_key(event))
                    .is_none_or(|parents| parents.as_slice() != [delivery])
            {
                return Err(failure(
                    "clock pending causal parent is not the original full-position delivery",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn time_ps(&self) -> u64 {
        self.saved.position.time_ps.get()
    }

    pub(super) fn next_position(&self) -> Option<Position> {
        self.saved.pending.iter().map(|event| event.reaction).min()
    }

    pub(super) fn pending_count(&self) -> usize {
        self.saved.pending.len()
    }

    pub(super) fn pending_keys(&self) -> impl Iterator<Item = (u64, u32, u32)> + '_ {
        self.saved.pending.iter().map(event_key)
    }

    pub(super) fn decode_request(bytes: &[u8]) -> Result<RateAlarmClockRequest, OperationFailure> {
        let value = canonical::parse_json(bytes, 512).map_err(|e| failure(&e.to_string()))?;
        let request: RateAlarmClockRequest =
            serde_json::from_value(value).map_err(|e| failure(&e.to_string()))?;
        if encode(&request, 512)? != bytes {
            return Err(failure("clock request is not canonical"));
        }
        Ok(request)
    }

    pub(super) fn consume(
        &mut self,
        at: Position,
        bytes: &[u8],
    ) -> Result<ClockInputChanges, OperationFailure> {
        let request = Self::decode_request(bytes)?;
        if at < self.saved.position
            || at.phase != Phase::Reaction
            || self.saved.requests.len() >= MAXIMUM_CLOCK_REQUESTS
            || self
                .saved
                .requests
                .iter()
                .any(|old| old.request.correlation() == request.correlation())
        {
            return Err(failure(
                "clock original request has stale, duplicate or exhausted custody",
            ));
        }
        let reading = self.saved.definition.reading(at.time_ps)?;
        let mut removed = Vec::new();
        let mut events = vec![("reading", at, reading)];
        match &request {
            RateAlarmClockRequest::Read { .. } => {}
            RateAlarmClockRequest::Arm { target, .. } => {
                if *target <= reading {
                    return Err(failure("clock alarm must name a future counter target"));
                }
                let time = self.saved.definition.alarm_time(*target)?;
                let reaction = Position::new(time, 0.into(), Phase::Reaction);
                if reaction <= at {
                    return Err(failure("clock alarm cannot be backdated"));
                }
                events = vec![
                    ("armed", at, reading),
                    ("alarm", reaction, self.saved.definition.reading(time)?),
                ];
            }
            RateAlarmClockRequest::Cancel { alarm, .. } => {
                let original = self
                    .saved
                    .pending
                    .iter()
                    .find(|event| event.kind == "alarm" && &event.correlation == alarm)
                    .ok_or_else(|| failure("clock cancellation lacks an original pending alarm"))?;
                if original.reaction <= at {
                    return Err(failure(
                        "due clock alarm cannot be canceled after its reaction",
                    ));
                }
                removed.push(event_key(original));
                events = vec![("canceled", at, reading)];
            }
        }
        let total = self
            .saved
            .pending
            .len()
            .checked_add(events.len())
            .and_then(|n| n.checked_sub(removed.len()))
            .ok_or_else(|| failure("clock pending geometry overflow"))?;
        if total > MAXIMUM_CLOCK_REQUESTS
            || self.saved.issued.len() + total > MAXIMUM_CLOCK_REQUESTS * 2
        {
            return Err(failure("clock native alarm/output credit exhausted"));
        }
        let next = self
            .saved
            .next_sequence
            .get()
            .checked_add(events.len() as u64)
            .ok_or_else(|| failure("clock native sequence overflow"))?;
        // Reserve all owned rows before changing the request or alarm inventory.
        self.saved
            .requests
            .try_reserve(1)
            .map_err(|_| failure("clock request retention allocation failed"))?;
        self.saved
            .pending
            .try_reserve(events.len())
            .map_err(|_| failure("clock event retention allocation failed"))?;
        self.saved
            .issued
            .try_reserve(total)
            .map_err(|_| failure("clock original output retention allocation failed"))?;
        let mut additions = Vec::new();
        additions
            .try_reserve_exact(events.len())
            .map_err(|_| failure("clock event credit unavailable"))?;
        for (index, (kind, reaction, counter)) in events.into_iter().enumerate() {
            additions.push(RateAlarmClockEvent {
                correlation: request.correlation().clone(),
                kind: kind.into(),
                reaction,
                counter,
                sequence: (self.saved.next_sequence.get() + index as u64).into(),
            });
        }
        let mut keys = Vec::new();
        keys.try_reserve_exact(additions.len())
            .map_err(|_| failure("clock causal key retention unavailable"))?;
        keys.extend(additions.iter().map(event_key));
        let record = ClockRequestRecord {
            request,
            reaction: at,
        };
        let projected = ProjectedState {
            format: &self.saved.format,
            definition: &self.saved.definition,
            position: at,
            next_sequence: next.into(),
            requests: RequestRows {
                original: &self.saved.requests,
                additional: Some(&record),
            },
            pending: EventRows {
                original: &self.saved.pending,
                omitted: &removed,
                omitted_at: None,
                additional: &additions,
                due: None,
            },
            issued: EventRows::unchanged(&self.saved.issued),
        };
        measure(&projected, MAXIMUM_CLOCK_STATE_BYTES)?;

        self.saved
            .pending
            .retain(|event| !removed.contains(&event_key(event)));
        self.saved.pending.extend(additions);
        self.saved.requests.push(record);
        self.saved.position = at;
        self.saved.next_sequence = next.into();
        Ok((keys, removed))
    }

    pub(super) fn publish(
        &mut self,
        at: Position,
    ) -> Result<Vec<(RateAlarmClockEvent, Vec<u8>)>, OperationFailure> {
        if at < self.saved.position || self.next_position() != Some(at) {
            return Err(failure(
                "clock publication lacks the next original reaction",
            ));
        }
        let mut output = Vec::new();
        let due = self
            .saved
            .pending
            .iter()
            .filter(|event| event.reaction == at)
            .count();
        output
            .try_reserve_exact(due)
            .map_err(|_| failure("clock publication retention failed"))?;
        self.saved
            .issued
            .try_reserve(due)
            .map_err(|_| failure("clock issued retention failed"))?;
        for event in self
            .saved
            .pending
            .iter()
            .filter(|event| event.reaction == at)
        {
            output.push((event.clone(), encode(event, 512)?));
        }
        let projected = ProjectedState {
            format: &self.saved.format,
            definition: &self.saved.definition,
            position: at,
            next_sequence: self.saved.next_sequence,
            requests: RequestRows {
                original: &self.saved.requests,
                additional: None,
            },
            pending: EventRows {
                original: &self.saved.pending,
                omitted: &[],
                omitted_at: Some(at),
                additional: &[],
                due: None,
            },
            issued: EventRows {
                original: &self.saved.issued,
                omitted: &[],
                omitted_at: None,
                additional: &[],
                due: Some((&self.saved.pending, at)),
            },
        };
        measure(&projected, MAXIMUM_CLOCK_STATE_BYTES)?;
        // Complete every fallible output-body copy before changing the FIFO.
        let mut issued = Vec::new();
        issued
            .try_reserve_exact(due)
            .map_err(|_| failure("clock issued copy credit unavailable"))?;
        issued.extend(output.iter().map(|(event, _)| event.clone()));

        self.saved.pending.retain(|event| event.reaction != at);
        self.saved.issued.extend(issued);
        self.saved.position = at;
        Ok(output)
    }

    pub(super) fn park(&mut self, at: Position) -> Result<(), OperationFailure> {
        if at < self.saved.position || self.next_position().is_some_and(|next| next < at) {
            return Err(failure(
                "clock cannot park beyond an unexecuted alarm or response",
            ));
        }
        self.saved.definition.reading(at.time_ps)?;
        measure(
            &ProjectedState {
                format: &self.saved.format,
                definition: &self.saved.definition,
                position: at,
                next_sequence: self.saved.next_sequence,
                requests: RequestRows {
                    original: &self.saved.requests,
                    additional: None,
                },
                pending: EventRows::unchanged(&self.saved.pending),
                issued: EventRows::unchanged(&self.saved.issued),
            },
            MAXIMUM_CLOCK_STATE_BYTES,
        )?;
        self.saved.position = at;
        Ok(())
    }

    pub(super) fn capture(&self) -> Result<Vec<u8>, OperationFailure> {
        encode(&self.saved, MAXIMUM_CLOCK_STATE_BYTES)
    }

    pub(super) fn restore(&mut self, bytes: &[u8]) -> Result<(), OperationFailure> {
        let value = canonical::parse_json(bytes, MAXIMUM_CLOCK_STATE_BYTES)
            .map_err(|e| failure(&e.to_string()))?;
        let saved: Snapshot = serde_json::from_value(value).map_err(|e| failure(&e.to_string()))?;
        if saved.format != "crucible.rate-alarm-clock.v1"
            || saved.definition != self.saved.definition
            || saved.requests.len() > MAXIMUM_CLOCK_REQUESTS
            || saved.pending.len() > MAXIMUM_CLOCK_REQUESTS
            || saved.pending.len() + saved.issued.len() > MAXIMUM_CLOCK_REQUESTS * 2
            || encode(&saved, MAXIMUM_CLOCK_STATE_BYTES)? != bytes
        {
            return Err(failure(
                "clock native continuation format, definition or bounds differ",
            ));
        }
        // Reexecute only inert validation from complete original request records.
        // The restored live model receives this exact saved state only afterwards.
        let mut oracle = Self::new(saved.definition.clone())?;
        for record in &saved.requests {
            while let Some(next) = oracle.next_position()
                && next < record.reaction
            {
                oracle.publish(next)?;
            }
            oracle.consume(record.reaction, &encode(&record.request, 512)?)?;
        }
        while let Some(next) = oracle.next_position()
            && next < saved.position
        {
            oracle.publish(next)?;
        }
        // Equal-cut issued rows determine whether that original reaction was run.
        if oracle.next_position() == Some(saved.position)
            && saved
                .issued
                .iter()
                .any(|event| event.reaction == saved.position)
        {
            oracle.publish(saved.position)?;
        }
        oracle.park(saved.position)?;
        if oracle.saved != saved {
            return Err(failure(
                "clock original request/alarm/issued inventory is incomplete or changed",
            ));
        }
        self.saved = saved;
        Ok(())
    }
}

pub(super) fn event_key(event: &RateAlarmClockEvent) -> (u64, u32, u32) {
    (event.reaction.time_ps.get(), 0, event.sequence.get() as u32)
}

// Borrowed row projections charge complete prospective native geometry before
// a request, publication or administrative park can mutate original state.
#[derive(Serialize)]
struct ProjectedState<'a> {
    format: &'a str,
    definition: &'a RateAlarmClockDefinition,
    position: Position,
    next_sequence: U64,
    requests: RequestRows<'a>,
    pending: EventRows<'a>,
    issued: EventRows<'a>,
}

struct RequestRows<'a> {
    original: &'a [ClockRequestRecord],
    additional: Option<&'a ClockRequestRecord>,
}

impl Serialize for RequestRows<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(
            self.original.len() + usize::from(self.additional.is_some()),
        ))?;
        for row in self.original {
            rows.serialize_element(row)?;
        }
        if let Some(row) = self.additional {
            rows.serialize_element(row)?;
        }
        rows.end()
    }
}

struct EventRows<'a> {
    original: &'a [RateAlarmClockEvent],
    omitted: &'a [(u64, u32, u32)],
    omitted_at: Option<Position>,
    additional: &'a [RateAlarmClockEvent],
    due: Option<(&'a [RateAlarmClockEvent], Position)>,
}

impl<'a> EventRows<'a> {
    fn unchanged(original: &'a [RateAlarmClockEvent]) -> Self {
        Self {
            original,
            omitted: &[],
            omitted_at: None,
            additional: &[],
            due: None,
        }
    }
}

impl Serialize for EventRows<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let retained = self.original.iter().filter(|event| {
            Some(event.reaction) != self.omitted_at && !self.omitted.contains(&event_key(event))
        });
        let due = self
            .due
            .into_iter()
            .flat_map(|(rows, at)| rows.iter().filter(move |event| event.reaction == at));
        let mut rows = serializer.serialize_seq(Some(
            retained.clone().count() + self.additional.len() + due.clone().count(),
        ))?;
        for event in retained.chain(self.additional).chain(due) {
            rows.serialize_element(event)?;
        }
        rows.end()
    }
}

struct EncodingCredit {
    bytes: usize,
    maximum: usize,
}

impl Write for EncodingCredit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("clock encoding credit exceeded"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn measure(value: &impl Serialize, maximum: usize) -> Result<usize, OperationFailure> {
    let mut credit = EncodingCredit { bytes: 0, maximum };
    serde_json::to_writer(&mut credit, value).map_err(|e| failure(&e.to_string()))?;
    Ok(credit.bytes)
}

fn encode(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>, OperationFailure> {
    let measured = measure(value, maximum)?;
    let value = serde_json::to_value(value).map_err(|e| failure(&e.to_string()))?;
    let bytes = canonical::canonical_json(&value).map_err(|e| failure(&e.to_string()))?;
    if bytes.len() != measured {
        return Err(failure("clock canonical geometry changed after precredit"));
    }
    Ok(bytes)
}

/// Defines the selected complete rational-clock native envelope.
pub const RATE_ALARM_CLOCK_SPECIFICATION: &str = "host rate/alarm clock native envelope7: exact unsigned 64-bit rational counter with floor reading/ceiling threshold conversion to shared integer picoseconds; overflow refuses without wrapping; unchanged shared picosecond coordinates; complete original requests, pending and issued alarm/response FIFO; outer original staged inputs, causal parents, operation outcomes and ACKs; alarm data publication conveys no guest interrupt or delivery authority; fixed rate/drift only; no autonomous host time or guest CPU";

/// Returns the distinct source-owned rational-clock continuation schema.
///
/// # Errors
/// Refuses invalid schema or specification content identities.
pub fn host_rate_alarm_clock_schema() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("host/rate-alarm-native-v1").map_err(|e| failure(&e.to_string()))?,
        version: 1,
        definition: canonical::content_ref(RATE_ALARM_CLOCK_SPECIFICATION.as_bytes(), "text/plain")
            .map_err(|e| failure(&e.to_string()))?,
        extensions: Extensions::new(),
    })
}

pub(super) fn selected(binding: &NodeBinding) -> bool {
    host_rate_alarm_clock_schema().is_ok_and(|schema| {
        binding
            .compatibility
            .implementation
            .formats
            .contains(&schema)
    })
}
