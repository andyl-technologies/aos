//! Independent ownership and exact copies of admitted condition-prefix facts.

use super::*;
use crate::owned_decode::{DecodeCustody, charge_btree_set_entry, reserve_vec};

// Credits describe physical custody, not canonical evaluation facts. An
// independently admitted copy and its source have identical semantic identity.
impl PartialEq for ConditionEventLogPrefix {
    fn eq(&self, other: &Self) -> bool {
        self.point == other.point
            && self.base_sequence == other.base_sequence
            && self.event_log_offset == other.event_log_offset
            && self.prefix_offsets == other.prefix_offsets
            && self.scheduler_entries == other.scheduler_entries
            && self.last_black_box_observation == other.last_black_box_observation
            && self.observable_events == other.observable_events
            && self.black_box_observation_kinds == other.black_box_observation_kinds
            && self.event_firings == other.event_firings
            && self.timer_fires == other.timer_fires
            && self.ordering_facts == other.ordering_facts
    }
}

impl Eq for ConditionEventLogPrefix {}

impl ConditionEventLogPrefix {
    /// Reenters retained original metadata authority for an enclosing copy.
    pub(crate) fn enter_original_decode(&self) -> Option<crate::owned_decode::DecodeScope> {
        self._decode_custody.enter()
    }

    /// Copies a checked prefix under an independent child of its original authority.
    ///
    /// # Errors
    /// Returns the original admission refusal before copying an owned field.
    pub fn try_clone_admitted(&self) -> Result<Self, ConditionEvaluationError> {
        let _original = self._decode_custody.enter();
        let child = crate::owned_decode::require_current_child_budget()
            .map_err(ConditionEvaluationError::OriginalAdmission)?;
        let _scope = child.enter();
        let mut observable_events = Vec::new();
        for event in &self.observable_events {
            reserve_vec(&mut observable_events, 1)
                .map_err(ConditionEvaluationError::OriginalAdmission)?;
            observable_events.push(ObservableEvent {
                at: event.at,
                payload: crate::scheduler::copy_observable_admitted(&event.payload)
                    .map_err(ConditionEvaluationError::from)?,
            });
        }
        let mut ordering_facts = Vec::new();
        for fact in &self.ordering_facts {
            reserve_vec(&mut ordering_facts, 1)
                .map_err(ConditionEvaluationError::OriginalAdmission)?;
            ordering_facts.push(copy_ordering_fact(fact)?);
        }
        let mut black_box_observation_kinds = BTreeSet::new();
        for kind in &self.black_box_observation_kinds {
            charge_btree_set_entry::<BlackBoxObservationKind>()
                .map_err(ConditionEvaluationError::OriginalAdmission)?;
            black_box_observation_kinds.insert(*kind);
        }
        let mut event_firings = BTreeMap::new();
        for (event, at) in &self.event_firings {
            crate::owned_decode::charge_btree_entry::<EventId, VirtualTime>()
                .map_err(ConditionEvaluationError::OriginalAdmission)?;
            event_firings.insert(copy(event)?, *at);
        }
        let mut timer_fires = BTreeMap::new();
        for (timer, at) in &self.timer_fires {
            crate::owned_decode::charge_btree_entry::<TimerId, VirtualTime>()
                .map_err(ConditionEvaluationError::OriginalAdmission)?;
            timer_fires.insert(copy(timer)?, *at);
        }
        let result = Self {
            point: self.point,
            base_sequence: self.base_sequence,
            event_log_offset: self.event_log_offset,
            prefix_offsets: copy_prefix_offsets(&self.prefix_offsets)?,
            scheduler_entries: crate::scheduler::copy_entries_admitted(&self.scheduler_entries)
                .map_err(ConditionEvaluationError::from)?,
            last_black_box_observation: self.last_black_box_observation,
            observable_events,
            black_box_observation_kinds,
            event_firings,
            timer_fires,
            ordering_facts,
            _append_custodies: Vec::new(),
            _array_custodies: Default::default(),
            _decode_custody: child.custody(),
        };
        child
            .check()
            .map_err(ConditionEvaluationError::OriginalAdmission)?;
        Ok(result)
    }
}

pub(in crate::trigger) fn copy<T>(value: &T) -> Result<T, ConditionEvaluationError>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    assertions::owned_storage::copy_json(value).map_err(ConditionEvaluationError::from)
}

fn copy_ordering_fact(
    fact: &ObservedOrderingFact,
) -> Result<ObservedOrderingFact, ConditionEvaluationError> {
    Ok(match fact {
        ObservedOrderingFact::ResolvedHappening {
            sequence,
            at,
            key,
            class,
        } => ObservedOrderingFact::ResolvedHappening {
            sequence: *sequence,
            at: *at,
            key: copy(key)?,
            class: *class,
        },
        ObservedOrderingFact::DeliveryOrder {
            sequence,
            at,
            order,
        } => ObservedOrderingFact::DeliveryOrder {
            sequence: *sequence,
            at: *at,
            order: copy(order)?,
        },
    })
}

pub(in crate::trigger) fn copy_prefix_offsets(
    source: &BTreeMap<u64, EventLogOffset>,
) -> Result<BTreeMap<u64, EventLogOffset>, ConditionEvaluationError> {
    let mut offsets = BTreeMap::new();
    for (sequence, offset) in source {
        crate::owned_decode::charge_btree_entry::<u64, EventLogOffset>()
            .map_err(ConditionEvaluationError::OriginalAdmission)?;
        offsets.insert(*sequence, *offset);
    }
    Ok(offsets)
}

pub(in crate::trigger) fn current_custody() -> Result<DecodeCustody, ConditionEvaluationError> {
    crate::owned_decode::require_current_custody()
        .map_err(ConditionEvaluationError::OriginalAdmission)
}

#[cfg(test)]
mod tests;
