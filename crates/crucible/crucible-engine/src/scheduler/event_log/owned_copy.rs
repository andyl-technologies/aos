//! Exact structural copies of retained scheduler entries under original admission.
//!
//! The enclosing prefix retains the current account. Strings, byte arrays and
//! B-tree nodes are reserved before their allocations; scalar hashes and clocks
//! are copied directly, without serialization or parser seed banks.

use super::*;
use crate::EngineError;
use crate::owned_decode::{DecodeAdmissionError, charge_array, charge_btree_entry};
use crate::trigger::{
    GuestAssertionDetail, GuestAssertionMarker, GuestMeasurementEvent, GuestMeasurementValue,
    GuestSemanticMarkerDetail, ResolvedMemPlace,
};
pub(crate) use observable::copy_observable as copy_observable_admitted;

mod fault;
mod observable;

pub(crate) fn copy_entries_admitted(
    source: &[SchedulerEventLogEntry],
) -> Result<Vec<SchedulerEventLogEntry>, EngineError> {
    crate::owned_decode::require_current_custody().map_err(admission)?;
    let mut entries = reserve_array(source.len())?;
    for entry in source {
        entries.push(copy_entry_admitted(entry)?);
    }
    Ok(entries)
}

pub(crate) fn copy_entry_admitted(
    value: &SchedulerEventLogEntry,
) -> Result<SchedulerEventLogEntry, EngineError> {
    crate::owned_decode::require_current_custody().map_err(admission)?;
    Ok(SchedulerEventLogEntry {
        sequence: value.sequence,
        at: EventLogTime {
            virtual_time: value.at.virtual_time,
            stamp: EventLogTickStamp {
                node: value.at.stamp.node.as_ref().map(copy_node).transpose()?,
                tick: value.at.stamp.tick,
                retired: value.at.stamp.retired,
            },
        },
        source: match &value.source {
            EventSource::Scenario { event } => EventSource::Scenario {
                event: copy_event(event)?,
            },
            EventSource::Engine => EventSource::Engine,
            EventSource::Node { node } => EventSource::Node {
                node: copy_node(node)?,
            },
            EventSource::Guest { node } => EventSource::Guest {
                node: copy_node(node)?,
            },
            EventSource::Command { command_id } => EventSource::Command {
                command_id: *command_id,
            },
        },
        level: value.level,
        class: value.class,
        event_payload: EventPayload {
            kind: copy_string(&value.event_payload.kind)?,
            attributes: copy_attributes(&value.event_payload.attributes)?,
        },
        payload: copy_payload(&value.payload)?,
        content_hash: value.content_hash,
        provenance: value.provenance,
    })
}

fn copy_payload(value: &SchedulerEventLogPayload) -> Result<SchedulerEventLogPayload, EngineError> {
    use SchedulerEventLogPayload as P;
    Ok(match value {
        P::ResolvedHappening(event) => P::ResolvedHappening(copy_scheduled(event)?),
        P::Decision(decision) => P::Decision(decision.try_clone_admitted()?),
        P::Observable(observation) => P::Observable(observable::copy_observable(observation)?),
        P::EvaluationBoundary(kind) => P::EvaluationBoundary(*kind),
        P::TriggerFired(firing) => P::TriggerFired(firing.try_clone_admitted()?),
        P::TriggerActionApplied(application) => P::TriggerActionApplied(TriggerActionApplication {
            sequence: application.sequence,
            event: copy_event(&application.event)?,
            at: application.at,
            path: copy_vec(&application.path)?,
            action: application.action.try_clone_admitted()?,
        }),
        P::FaultObservation(observation) => {
            P::FaultObservation(fault::copy_observation(observation)?)
        }
        P::Diagnostic(diagnostic) => P::Diagnostic(EventDiagnosticPayload {
            name: copy_string(&diagnostic.name)?,
            level: diagnostic.level,
            details: copy_attributes(&diagnostic.details)?,
        }),
    })
}

pub(in crate::scheduler) fn copy_scheduled(
    value: &ScheduledEvent,
) -> Result<ScheduledEvent, EngineError> {
    Ok(ScheduledEvent {
        key: ScheduledEventKey {
            timeline: SharedTimelineKey {
                virtual_time: value.key.timeline.virtual_time,
                node: copy_scheduler_node(&value.key.timeline.node)?,
                sequence: value.key.timeline.sequence,
            },
            producer: copy_scheduler_node(&value.key.producer)?,
        },
        payload: match &value.payload {
            ScheduledEventPayload::BackendInput(input) => {
                ScheduledEventPayload::BackendInput(BackendInput {
                    node: copy_node(&input.node)?,
                    payload: copy_vec(&input.payload)?,
                })
            }
            ScheduledEventPayload::IoCompletion(completion) => {
                ScheduledEventPayload::IoCompletion(IoCompletion {
                    sub_node: copy_scheduler_node(&completion.sub_node)?,
                    target: copy_node(&completion.target)?,
                    delivery_tick: completion.delivery_tick,
                    source_delivery: completion.source_delivery,
                    payload: copy_vec(&completion.payload)?,
                })
            }
            // Control operations contain only a sequence and a closed unit enum.
            ScheduledEventPayload::Control(operation) => {
                ScheduledEventPayload::Control(operation.clone())
            }
        },
    })
}

fn copy_attributes(
    source: &BTreeMap<String, EventAttributeValue>,
) -> Result<BTreeMap<String, EventAttributeValue>, EngineError> {
    let mut result = BTreeMap::new();
    for (key, value) in source {
        charge_btree_entry::<String, EventAttributeValue>().map_err(admission)?;
        let value = match value {
            EventAttributeValue::Bool(value) => EventAttributeValue::Bool(*value),
            EventAttributeValue::U64(value) => EventAttributeValue::U64(*value),
            EventAttributeValue::U128(value) => EventAttributeValue::U128(*value),
            EventAttributeValue::String(value) => EventAttributeValue::String(copy_string(value)?),
            EventAttributeValue::Bytes(value) => EventAttributeValue::Bytes(copy_vec(value)?),
            EventAttributeValue::Node(value) => EventAttributeValue::Node(copy_node(value)?),
            EventAttributeValue::Event(value) => EventAttributeValue::Event(copy_event(value)?),
            EventAttributeValue::VirtualTime(value) => EventAttributeValue::VirtualTime(*value),
            EventAttributeValue::Icount(value) => EventAttributeValue::Icount(*value),
            EventAttributeValue::Level(value) => EventAttributeValue::Level(*value),
        };
        result.insert(copy_string(key)?, value);
    }
    Ok(result)
}

pub(in crate::scheduler) fn copy_scheduler_node(
    value: &SchedulerNodeId,
) -> Result<SchedulerNodeId, EngineError> {
    Ok(SchedulerNodeId {
        node: copy_node(&value.node)?,
        kind: value.kind,
    })
}

pub(in crate::scheduler) fn copy_node(value: &NodeId) -> Result<NodeId, EngineError> {
    Ok(NodeId {
        name: copy_string(&value.name)?,
    })
}

fn copy_event(value: &EventId) -> Result<EventId, EngineError> {
    Ok(EventId {
        name: copy_string(&value.name)?,
    })
}

fn copy_assertion(value: &AssertionId) -> Result<AssertionId, EngineError> {
    Ok(AssertionId {
        name: copy_string(&value.name)?,
    })
}

pub(in crate::scheduler) fn copy_string(source: &str) -> Result<String, EngineError> {
    charge_array::<u8>(source.len()).map_err(admission)?;
    let mut result = String::new();
    result.try_reserve_exact(source.len()).map_err(allocation)?;
    result.push_str(source);
    Ok(result)
}

pub(in crate::scheduler) fn reserve_array<T>(length: usize) -> Result<Vec<T>, EngineError> {
    charge_array::<T>(length).map_err(admission)?;
    let mut result = Vec::new();
    result.try_reserve_exact(length).map_err(allocation)?;
    Ok(result)
}

pub(in crate::scheduler) fn copy_vec<T: Copy>(source: &[T]) -> Result<Vec<T>, EngineError> {
    let mut result = reserve_array(source.len())?;
    result.extend_from_slice(source);
    Ok(result)
}

fn admission(source: DecodeAdmissionError) -> EngineError {
    EngineError::ArtifactDecodeAdmission { source }
}

fn allocation(source: std::collections::TryReserveError) -> EngineError {
    admission(DecodeAdmissionError::new(source))
}
