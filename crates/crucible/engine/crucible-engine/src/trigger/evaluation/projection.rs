//! Independently owned evaluation facts copied from their retained original prefix.

use super::*;
use crate::owned_decode::{charge_btree_entry, reserve_vec};
use crate::trigger::assertions::owned_storage::{admission, copy_json, copy_string};

pub(super) fn copy_evaluation<O>(
    prefix: &ConditionEventLogPrefix,
    oracle: O,
) -> Result<ConditionEvaluation<O>, EngineError> {
    let _original = prefix._decode_custody.enter();
    let child = crate::owned_decode::require_current_child_budget().map_err(admission)?;
    let _scope = child.enter();
    let mut event_firings = BTreeMap::new();
    for (event, at) in &prefix.event_firings {
        charge_btree_entry::<EventId, VirtualTime>().map_err(admission)?;
        event_firings.insert(
            EventId {
                name: copy_string(&event.name)?,
            },
            *at,
        );
    }
    let mut timer_fires = BTreeMap::new();
    for (timer, at) in &prefix.timer_fires {
        charge_btree_entry::<TimerId, VirtualTime>().map_err(admission)?;
        timer_fires.insert(
            TimerId {
                name: copy_string(&timer.name)?,
            },
            *at,
        );
    }
    let mut observable_events = Vec::new();
    for event in &prefix.observable_events {
        reserve_vec(&mut observable_events, 1).map_err(admission)?;
        observable_events.push(ObservableEvent {
            at: event.at,
            payload: copy_json(&event.payload)?,
        });
    }
    let mut ordering_facts = Vec::new();
    for fact in &prefix.ordering_facts {
        reserve_vec(&mut ordering_facts, 1).map_err(admission)?;
        ordering_facts.push(match fact {
            ObservedOrderingFact::ResolvedHappening {
                sequence,
                at,
                key,
                class,
            } => ObservedOrderingFact::ResolvedHappening {
                sequence: *sequence,
                at: *at,
                key: copy_json(key)?,
                class: *class,
            },
            ObservedOrderingFact::DeliveryOrder {
                sequence,
                at,
                order,
            } => ObservedOrderingFact::DeliveryOrder {
                sequence: *sequence,
                at: *at,
                order: copy_json(order)?,
            },
        });
    }
    child.check().map_err(admission)?;
    Ok(ConditionEvaluation {
        point: prefix.point,
        event_log_offset: prefix.event_log_offset,
        oracle,
        event_firings,
        timer_fires,
        observable_events,
        ordering_facts,
        scheduler_quiescence: None,
        white_box_policies: BTreeMap::new(),
        once_latches: Vec::new(),
        code_points: BTreeMap::new(),
        mem_places: BTreeMap::new(),
        _append_custodies: Vec::new(),
        _array_custodies: Default::default(),
        _decode_custody: child.custody(),
    })
}
