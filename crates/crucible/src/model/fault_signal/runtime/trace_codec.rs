//! Allocation-aware canonical codec for standalone resolved-effect traces.

use std::marker::PhantomData;

use serde::de::{IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::*;

const MAX_DEPTH: usize = 128;
const HARD_WORK_ITEMS: u64 = FaultResourceLimits::compiled_maximum().thin_replay_events;
const HARD_RECORDS: u64 = FaultResourceLimits::compiled_maximum().resolved_effect_records;

pub(super) fn encode(
    trace: &ResolvedEffectTrace,
    limits: FaultResourceLimits,
) -> Result<Vec<u8>, FaultRuntimeError> {
    trace.validate(limits)?;
    checkpoint_codec::encode_prefixed(trace, RESOLVED_EFFECT_TRACE_MAGIC, limits)
}

pub(super) fn decode(
    payload: &[u8],
    limits: FaultResourceLimits,
) -> Result<ResolvedEffectTrace, FaultRuntimeError> {
    let wire: TraceWire = ciborium::de::from_reader(payload).map_err(map_decode_error)?;
    let count = u64::try_from(wire.work_items.values.len())
        .map_err(|_| FaultRuntimeError::CountOverflow("thin_replay_events"))?;
    let mut work_items = Vec::new();
    work_items
        .try_reserve_exact(wire.work_items.values.len())
        .map_err(|_| {
            resource(
                "thin_replay_events",
                0,
                count,
                limits.thin_replay_events,
                HARD_WORK_ITEMS,
            )
        })?;
    work_items.extend(
        wire.work_items
            .values
            .into_iter()
            .map(ResolvedReplayWorkItem::from),
    );
    Ok(ResolvedEffectTrace {
        mode: wire.mode,
        work_items,
        cursor: wire.cursor,
    })
}

pub(super) fn preflight(
    payload: &[u8],
    limits: FaultResourceLimits,
) -> Result<(), FaultRuntimeError> {
    let mut cursor = CborCursor::new(payload);
    let fields = cursor.map_len()?;
    let mut records = 0_u64;
    for _ in 0..fields {
        let field = cursor.text()?;
        if field == b"work_items" {
            let work_items = cursor.array_len()?;
            admit(
                "thin_replay_events",
                0,
                work_items,
                limits.thin_replay_events,
                HARD_WORK_ITEMS,
            )?;
            for _ in 0..work_items {
                let item_fields = cursor.map_len()?;
                for _ in 0..item_fields {
                    let item_field = cursor.text()?;
                    if item_field == b"records" {
                        let additional = cursor.array_len()?;
                        admit(
                            "resolved_effect_records",
                            records,
                            additional,
                            limits.resolved_effect_records,
                            HARD_RECORDS,
                        )?;
                        records = records.checked_add(additional).ok_or_else(|| {
                            resource(
                                "resolved_effect_records",
                                records,
                                additional,
                                limits.resolved_effect_records,
                                HARD_RECORDS,
                            )
                        })?;
                        for _ in 0..additional {
                            cursor.skip_value(0)?;
                        }
                    } else {
                        cursor.skip_value(0)?;
                    }
                }
            }
        } else {
            cursor.skip_value(0)?;
        }
    }
    if cursor.offset != payload.len() {
        return Err(FaultRuntimeError::CheckpointEncoding);
    }
    Ok(())
}

trait BoundField {
    const FIELD: &'static str;
    const MAX: u64;
}

struct WorkItemBound;
impl BoundField for WorkItemBound {
    const FIELD: &'static str = "thin_replay_events";
    const MAX: u64 = HARD_WORK_ITEMS;
}

struct RecordBound;
impl BoundField for RecordBound {
    const FIELD: &'static str = "resolved_effect_records";
    const MAX: u64 = HARD_RECORDS;
}

struct BoundedVec<T, F> {
    values: Vec<T>,
    field: PhantomData<F>,
}

impl<'de, T: Deserialize<'de>, F: BoundField> Deserialize<'de> for BoundedVec<T, F> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedVisitor<T, F>(PhantomData<(T, F)>);

        impl<'de, T: Deserialize<'de>, F: BoundField> Visitor<'de> for BoundedVisitor<T, F> {
            type Value = BoundedVec<T, F>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "at most {} {}", F::MAX, F::FIELD)
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let hint = sequence.size_hint().unwrap_or(0);
                let requested = u64::try_from(hint).unwrap_or(u64::MAX);
                if requested > F::MAX {
                    return Err(serde::de::Error::custom(resource_message(
                        F::FIELD,
                        0,
                        requested,
                        F::MAX,
                        F::MAX,
                    )));
                }
                let mut values = Vec::new();
                values.try_reserve_exact(hint.min(1024)).map_err(|_| {
                    serde::de::Error::custom(resource_message(
                        F::FIELD,
                        0,
                        requested.min(1024),
                        F::MAX,
                        F::MAX,
                    ))
                })?;
                loop {
                    let current = u64::try_from(values.len()).unwrap_or(u64::MAX);
                    if current >= F::MAX {
                        if sequence.next_element::<IgnoredAny>()?.is_some() {
                            return Err(serde::de::Error::custom(resource_message(
                                F::FIELD,
                                current,
                                1,
                                F::MAX,
                                F::MAX,
                            )));
                        }
                        break;
                    }
                    if values.len() == values.capacity() {
                        values.try_reserve(1).map_err(|_| {
                            serde::de::Error::custom(resource_message(
                                F::FIELD,
                                current,
                                1,
                                F::MAX,
                                F::MAX,
                            ))
                        })?;
                    }
                    let Some(value) = sequence.next_element()? else {
                        break;
                    };
                    values.push(value);
                }
                Ok(BoundedVec {
                    values,
                    field: PhantomData,
                })
            }
        }

        deserializer.deserialize_seq(BoundedVisitor(PhantomData))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TraceWire {
    mode: FaultReplayMode,
    work_items: BoundedVec<WorkItemWire, WorkItemBound>,
    cursor: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkItemWire {
    coordinate: FaultCoordinate,
    same_coordinate_sequence: u64,
    opportunity: Option<ContentHash>,
    target: Option<ResolvedFaultTarget>,
    operation: Option<FaultOperation>,
    direction: Option<FaultDirection>,
    phase: Option<FaultPhase>,
    network_frame_key: Option<ContentHash>,
    network_producer_direction_key: Option<ContentHash>,
    derivation_fingerprint: ContentHash,
    records: BoundedVec<ResolvedEffectRecord, RecordBound>,
}

impl From<WorkItemWire> for ResolvedReplayWorkItem {
    fn from(value: WorkItemWire) -> Self {
        Self {
            coordinate: value.coordinate,
            same_coordinate_sequence: value.same_coordinate_sequence,
            opportunity: value.opportunity,
            target: value.target,
            operation: value.operation,
            direction: value.direction,
            phase: value.phase,
            network_frame_key: value.network_frame_key,
            network_producer_direction_key: value.network_producer_direction_key,
            derivation_fingerprint: value.derivation_fingerprint,
            records: value.records.values,
        }
    }
}

fn admit(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> Result<(), FaultRuntimeError> {
    let total = current
        .checked_add(requested)
        .ok_or_else(|| resource(field, current, requested, configured, hard))?;
    if total > configured || total > hard {
        return Err(resource(field, current, requested, configured, hard));
    }
    Ok(())
}

fn resource(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> FaultRuntimeError {
    FaultRuntimeError::ResourceLimit(FaultResourceLimitError::Exceeded {
        field,
        current,
        requested,
        configured,
        hard,
    })
}

fn resource_message(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> String {
    format!("crucible-resource-limit|{field}|{current}|{requested}|{configured}|{hard}")
}

fn map_decode_error<T>(error: ciborium::de::Error<T>) -> FaultRuntimeError {
    let ciborium::de::Error::Semantic(_, message) = error else {
        return FaultRuntimeError::CheckpointEncoding;
    };
    let mut fields = message.split('|');
    if fields.next() != Some("crucible-resource-limit") {
        return FaultRuntimeError::CheckpointEncoding;
    }
    let Some(field) = fields.next() else {
        return FaultRuntimeError::CheckpointEncoding;
    };
    let field = match field {
        "thin_replay_events" => "thin_replay_events",
        "resolved_effect_records" => "resolved_effect_records",
        _ => return FaultRuntimeError::CheckpointEncoding,
    };
    let Some(current) = fields.next().and_then(|value| value.parse().ok()) else {
        return FaultRuntimeError::CheckpointEncoding;
    };
    let Some(requested) = fields.next().and_then(|value| value.parse().ok()) else {
        return FaultRuntimeError::CheckpointEncoding;
    };
    let Some(configured) = fields.next().and_then(|value| value.parse().ok()) else {
        return FaultRuntimeError::CheckpointEncoding;
    };
    let Some(hard) = fields.next().and_then(|value| value.parse().ok()) else {
        return FaultRuntimeError::CheckpointEncoding;
    };
    if fields.next().is_some() {
        return FaultRuntimeError::CheckpointEncoding;
    }
    resource(field, current, requested, configured, hard)
}

struct CborCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CborCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn map_len(&mut self) -> Result<u64, FaultRuntimeError> {
        self.container_len(5)
    }

    fn array_len(&mut self) -> Result<u64, FaultRuntimeError> {
        self.container_len(4)
    }

    fn container_len(&mut self, major: u8) -> Result<u64, FaultRuntimeError> {
        let initial = self.byte()?;
        if initial >> 5 != major {
            return Err(FaultRuntimeError::CheckpointEncoding);
        }
        self.argument(initial & 0x1f)
    }

    fn text(&mut self) -> Result<&'a [u8], FaultRuntimeError> {
        let initial = self.byte()?;
        if initial >> 5 != 3 {
            return Err(FaultRuntimeError::CheckpointEncoding);
        }
        let length = self.argument(initial & 0x1f)?;
        self.take(length)
    }

    fn skip_value(&mut self, depth: usize) -> Result<(), FaultRuntimeError> {
        if depth >= MAX_DEPTH {
            return Err(FaultRuntimeError::CheckpointEncoding);
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let argument = self.argument(initial & 0x1f)?;
        match major {
            0 | 1 | 7 => Ok(()),
            2 | 3 => self.take(argument).map(|_| ()),
            4 => {
                for _ in 0..argument {
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            5 => {
                for _ in 0..argument {
                    self.skip_value(depth + 1)?;
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            6 => self.skip_value(depth + 1),
            _ => Err(FaultRuntimeError::CheckpointEncoding),
        }
    }

    fn argument(&mut self, additional: u8) -> Result<u64, FaultRuntimeError> {
        match additional {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => Ok(u64::from(self.byte()?)),
            25 => Ok(u64::from(u16::from_be_bytes(self.array()?))),
            26 => Ok(u64::from(u32::from_be_bytes(self.array()?))),
            27 => Ok(u64::from_be_bytes(self.array()?)),
            _ => Err(FaultRuntimeError::CheckpointEncoding),
        }
    }

    fn byte(&mut self) -> Result<u8, FaultRuntimeError> {
        let value = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or(FaultRuntimeError::CheckpointEncoding)?;
        self.offset += 1;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], FaultRuntimeError> {
        self.take(u64::try_from(N).unwrap_or(u64::MAX))?
            .try_into()
            .map_err(|_| FaultRuntimeError::CheckpointEncoding)
    }

    fn take(&mut self, length: u64) -> Result<&'a [u8], FaultRuntimeError> {
        let length = usize::try_from(length).map_err(|_| FaultRuntimeError::CheckpointEncoding)?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FaultRuntimeError::CheckpointEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(FaultRuntimeError::CheckpointEncoding)?;
        self.offset = end;
        Ok(value)
    }
}
